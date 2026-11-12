"""Tamper-evident audit log.

Append-only, hash-chained: each entry's hash covers its own fields AND the prior
entry's hash, so altering, inserting, reordering, or deleting any entry breaks
the chain from that point on and `verify()` pinpoints where. This is the
"immutable audit log" — immutable in the cryptographic, detectable sense, not
because the file can't be edited.

Timestamps are caller-supplied (epoch seconds) so the log is deterministic and
replayable in tests; the live system passes time.time().

Durability contract for a persisted log (``AuditLog.open``):

* An entry is written and fsynced to the file *before* it joins the in-memory
  chain. A failed write raises, rolls the file back to its previous length, and
  leaves the chain untouched, so memory and disk never disagree.
* One writer per file. ``open`` takes an exclusive advisory lock (``flock``) on
  the file for the life of the log; a second opener, in this or another
  process, fails fast with ``AuditLogLockedError`` instead of forking the
  chain. Where advisory locks are unavailable (Windows, some network
  filesystems) the lock is skipped with a warning and single-writer is an
  operational requirement.
* A final line with no terminating newline is a torn write from a crash. It is
  not tampering evidence and is not silently dropped: ``open`` truncates it,
  logs a warning, and appends an ``audit_log_recovered`` entry that records the
  torn bytes on the chain. Any other unparseable line is an integrity failure.
"""

from __future__ import annotations

import errno
import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import asdict, dataclass
from typing import Any, Optional

try:  # POSIX advisory locking; absent on Windows.
    import fcntl
except ImportError:  # pragma: no cover - exercised only on Windows
    fcntl = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64

_O_BINARY = getattr(os, "O_BINARY", 0)


class AuditIntegrityError(Exception):
    """Raised when a persisted audit log fails its hash-chain verification."""


class AuditTornTailError(AuditIntegrityError):
    """The file's final line is incomplete: a write was cut off by a crash.

    ``AuditLog.open`` repairs this (truncate + recorded recovery entry);
    ``AuditLog.from_jsonl``, a read-only loader, reports it.
    """

    def __init__(self, message: str, *, good_length: int, torn: bytes):
        super().__init__(message)
        self.good_length = good_length
        self.torn = torn


class AuditLogLockedError(RuntimeError):
    """Another writer already holds this audit log open."""


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def _read_all(fd: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while True:
        chunk = os.read(fd, 1 << 20)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


#: The audit log names actors, targets and reveal reasons: owner read/write
#: only (F10). Applied at creation and tightened on an existing file.
AUDIT_FILE_MODE = 0o600


def _restrict_mode(fd: int, path: str) -> None:
    """Tighten an existing log to owner-only; best effort (F10).

    ``os.open``'s mode applies only when the file is created. A log created
    by an older release (``0o666`` minus the umask, often ``0o644``) is
    narrowed here so group and other lose read access.
    """
    if not hasattr(os, "fchmod"):  # pragma: no cover - Windows
        return
    try:
        mode = os.fstat(fd).st_mode & 0o777
        if mode & 0o077:
            os.fchmod(fd, AUDIT_FILE_MODE)
            logger.warning("audit log %s was readable beyond its owner (mode %o); "
                           "restricted it to %o", path, mode, AUDIT_FILE_MODE)
    except OSError as exc:
        logger.warning("could not restrict audit log %s to mode %o (%s)",
                       path, AUDIT_FILE_MODE, exc)


def _lock_exclusive(fd: int, path: str) -> None:
    if fcntl is None:  # pragma: no cover - Windows
        logger.warning("advisory file locking is unavailable on this platform; "
                       "run a single VecShield server per audit log (%s)", path)
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        if exc.errno in (errno.EAGAIN, errno.EACCES, errno.EWOULDBLOCK):
            raise AuditLogLockedError(
                f"audit log {path} is already open by another VecShield process "
                "(or another writer in this one). Run a single server per state "
                "directory: stop the other process, or give this one its own "
                "--state-dir."
            ) from exc
        logger.warning("could not lock audit log %s (%s); run a single VecShield "
                       "server per audit log", path, exc)


@dataclass
class AuditEntry:
    seq: int
    timestamp: float
    actor: str
    action: str
    target: str
    details: dict[str, Any]
    prev_hash: str
    hash: str = ""

    def _digest(self) -> str:
        payload = {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "actor": self.actor,
            "action": self.action,
            "target": self.target,
            "details": self.details,
            "prev_hash": self.prev_hash,
        }
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class VerifyResult:
    ok: bool
    entries: int
    first_bad_seq: Optional[int] = None
    reason: str = ""


class AuditLog:
    def __init__(self, entries: Optional[list[AuditEntry]] = None, *,
                 persist_path: Optional[str] = None):
        self._entries: list[AuditEntry] = entries or []
        self._persist_path: Optional[str] = persist_path
        # Serializes append(): the hash chain reads head_hash and appends as one
        # critical section. FastAPI runs sync endpoints in a threadpool and the
        # async job runner adds more concurrency, so concurrent appends would
        # otherwise race on seq/prev_hash and corrupt the chain.
        self._lock = threading.Lock()
        # Locked, held-open descriptor for a log returned by open().
        self._fd: Optional[int] = None
        self._closed = False
        # Length to restore before the next write if rolling back a failed
        # write could not be completed.
        self._rollback_to: Optional[int] = None
        #: Details of any recovery performed by open() (e.g. a torn tail).
        self.recovery_notes: list[dict[str, Any]] = []

    @classmethod
    def open(cls, path: str) -> "AuditLog":
        """Open a durable, write-through audit log as its single writer.

        The file is created if missing and exclusively locked for the life of
        the returned log (``AuditLogLockedError`` if another writer holds it).
        An existing file is loaded and its hash chain verified before use; a
        broken chain or an unparseable complete line raises
        AuditIntegrityError so the service refuses to append to (and thereby
        endorse) tampered compliance evidence, and the file is left as found.
        A torn final line is truncated and recorded as an
        ``audit_log_recovered`` entry (see ``recovery_notes``). New entries are
        fsynced to the file as they are recorded, so the log survives restarts.
        """
        p = os.fspath(path)
        parent = os.path.dirname(p)
        if parent:
            os.makedirs(parent, exist_ok=True)
        fd = os.open(p, os.O_RDWR | os.O_CREAT | os.O_APPEND | _O_BINARY,
                     AUDIT_FILE_MODE)
        log: Optional[AuditLog] = None
        try:
            _restrict_mode(fd, p)
            _lock_exclusive(fd, p)
            entries, torn = _parse_jsonl(_read_all(fd), p)
            log = cls(entries)
            result = log.verify()
            if not result.ok:
                raise AuditIntegrityError(
                    f"audit log at {p} failed integrity check at seq "
                    f"{result.first_bad_seq}: {result.reason}"
                )
            log._persist_path = p
            log._fd = fd
            if torn is not None and not log._accept_unterminated_entry(torn):
                log._recover_torn_tail(torn)
            return log
        except BaseException:
            if log is not None:
                log._fd = None  # never let __del__ close a reused descriptor
            os.close(fd)
            raise

    def _accept_unterminated_entry(self, torn: AuditTornTailError) -> bool:
        """Keep a final entry that is whole and chains correctly but lost only
        its newline; write the newline so later appends start a fresh line."""
        assert self._fd is not None
        try:
            obj = json.loads(torn.torn.decode("utf-8"))
            candidate = AuditEntry(**obj) if isinstance(obj, dict) else None
        except (ValueError, TypeError):
            return False
        if candidate is None:
            return False
        extended = AuditLog(self._entries + [candidate])
        if not extended.verify().ok:
            return False
        _write_all(self._fd, b"\n")
        os.fsync(self._fd)
        self._entries.append(candidate)
        logger.info("audit log %s: final entry seq %d lacked a newline; kept it",
                    self._persist_path, candidate.seq)
        return True

    def _recover_torn_tail(self, torn: AuditTornTailError) -> None:
        assert self._fd is not None
        text = torn.torn.decode("utf-8", errors="replace")
        details = {
            "reason": ("the final line was incomplete (a write interrupted by a "
                       "crash); it was removed from the file and is preserved "
                       "here"),
            "torn_bytes": len(torn.torn),
            "torn_sha256": hashlib.sha256(torn.torn).hexdigest(),
            "torn_tail": text,
            "truncated_at_offset": torn.good_length,
        }
        logger.warning("audit log %s had a torn final line (%d bytes) from an "
                       "interrupted write; truncated it and recorded an "
                       "audit_log_recovered entry", self._persist_path,
                       len(torn.torn))
        os.ftruncate(self._fd, torn.good_length)
        try:
            self.append("system", "audit_log_recovered", "audit_log", details)
        except BaseException:
            # The note could not be written: put the torn bytes back rather
            # than lose them, and let the caller report the failure.
            try:
                _write_all(self._fd, torn.torn)
                os.fsync(self._fd)
            except OSError:
                logger.error("could not restore the torn tail of %s",
                             self._persist_path, exc_info=True)
            raise
        self.recovery_notes.append(details)

    def close(self) -> None:
        """Release the file lock. Further appends to a persisted log fail."""
        with self._lock:
            if self._persist_path is not None:
                self._closed = True
            if self._fd is not None:
                fd, self._fd = self._fd, None
                os.close(fd)

    def __enter__(self) -> "AuditLog":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def __del__(self) -> None:
        fd = getattr(self, "_fd", None)
        if fd is not None:
            try:
                os.close(fd)
            except Exception:  # noqa: BLE001 - finalizer, e.g. at shutdown
                pass

    @property
    def entries(self) -> list[AuditEntry]:
        return list(self._entries)

    @property
    def head_hash(self) -> str:
        return self._entries[-1].hash if self._entries else GENESIS_HASH

    def append(self, actor: str, action: str, target: str,
               details: Optional[dict] = None,
               timestamp: Optional[float] = None) -> AuditEntry:
        with self._lock:
            entry = AuditEntry(
                seq=len(self._entries),
                timestamp=timestamp if timestamp is not None else time.time(),
                actor=actor,
                action=action,
                target=target,
                details=details or {},
                prev_hash=self.head_hash,
            )
            entry.hash = entry._digest()
            if self._persist_path is not None:
                # Durable first: the entry joins the chain only once it is on
                # disk, so a failed write can never leave memory ahead of the
                # file (which a restart would read as a broken chain).
                self._write_durably((json.dumps(entry.to_dict()) + "\n").encode("utf-8"))
            self._entries.append(entry)
            return entry

    def _write_durably(self, data: bytes) -> None:
        if self._closed:
            raise ValueError(f"audit log {self._persist_path} is closed")
        assert self._persist_path is not None
        fd, owned = self._fd, False
        if fd is None:  # constructed with persist_path rather than open()
            fd = os.open(self._persist_path,
                         os.O_WRONLY | os.O_CREAT | os.O_APPEND | _O_BINARY,
                         AUDIT_FILE_MODE)
            owned = True
        try:
            if self._rollback_to is not None:
                os.ftruncate(fd, self._rollback_to)
                self._rollback_to = None
            start = os.lseek(fd, 0, os.SEEK_END)
            try:
                _write_all(fd, data)
                os.fsync(fd)
            except BaseException:
                try:
                    os.ftruncate(fd, start)
                except OSError:
                    self._rollback_to = start
                    logger.error("could not roll back a failed audit write in %s; "
                                 "retrying before the next append",
                                 self._persist_path, exc_info=True)
                raise
        finally:
            if owned:
                os.close(fd)

    def verify(self) -> VerifyResult:
        prev = GENESIS_HASH
        for i, e in enumerate(self._entries):
            if e.seq != i:
                return VerifyResult(False, len(self._entries), i, "sequence break")
            if e.prev_hash != prev:
                return VerifyResult(False, len(self._entries), e.seq,
                                    "prev_hash mismatch (insert/delete/reorder)")
            if e.hash != e._digest():
                return VerifyResult(False, len(self._entries), e.seq,
                                    "content tampered (hash mismatch)")
            prev = e.hash
        return VerifyResult(True, len(self._entries))

    # --- persistence (JSON Lines) ---

    def to_jsonl(self, path: str) -> None:
        with open(path, "w") as f:
            for e in self._entries:
                f.write(json.dumps(e.to_dict()) + "\n")

    @classmethod
    def from_jsonl(cls, path: str) -> "AuditLog":
        """Load a log read-only. Raises AuditIntegrityError (AuditTornTailError
        for an incomplete final line) rather than a parse error."""
        with open(path, "rb") as f:
            data = f.read()
        entries, torn = _parse_jsonl(data, os.fspath(path))
        if torn is not None:
            raise torn
        return cls(entries)


def _parse_jsonl(data: bytes, source: str
                 ) -> tuple[list[AuditEntry], Optional[AuditTornTailError]]:
    """Parse JSON Lines into entries.

    Every newline-terminated line must be a complete entry; anything else is an
    AuditIntegrityError. An unterminated final segment is returned separately
    as a torn tail for the caller to repair or report.
    """
    entries: list[AuditEntry] = []
    end = data.rfind(b"\n") + 1
    complete, tail = data[:end], data[end:]
    for lineno, raw in enumerate(complete.split(b"\n")[:-1], start=1):
        if not raw.strip():
            continue
        try:
            obj = json.loads(raw.decode("utf-8"))
            if not isinstance(obj, dict):
                raise TypeError("not an object")
            entries.append(AuditEntry(**obj))
        except (ValueError, TypeError) as exc:
            raise AuditIntegrityError(
                f"audit log at {source} has an unreadable entry on line "
                f"{lineno}: {exc}") from exc
    torn = None
    if tail:
        torn = AuditTornTailError(
            f"audit log at {source} ends with an incomplete line ({len(tail)} "
            "bytes): a write was interrupted", good_length=end, torn=tail)
    return entries, torn
