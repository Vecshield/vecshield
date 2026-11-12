"""Local accounts and browser sessions for the VecShield console.

A small, self-contained identity store for deployments that have no external
identity provider (improvement plan 1.1, ADR 0002). It follows the other SQLite
stores in the repository: one auto-created file (or ``:memory:``), WAL journal
mode, one lock serializing access, and row-dict reads.

Security properties:

* Passwords are hashed with stdlib ``hashlib.scrypt`` (n=2**14, r=8, p=1, a
  16-byte random salt, 32-byte key) and encoded as
  ``scrypt$n$r$p$salt_b64$hash_b64``. Verification is constant-time, and an
  unknown username still costs one scrypt so response time does not reveal
  which accounts exist.
* Session tokens are 256-bit random values handed to the browser once; only
  their SHA-256 is stored, so a copy of the database cannot be replayed as a
  cookie. Sessions expire after an idle period and at an absolute lifetime.
* Repeated failures lock an account for a period. Password changes, resets
  and disabling an account revoke that account's other sessions.
* The first start creates ``admin`` (role admin) with a bootstrap password that
  must be changed at first sign-in. Accounts are disabled, never deleted, so
  the audit trail stays attributable.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Optional

from vecshield_platform.api.auth import ADMIN, ALL_ROLES

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Policy constants                                                            #
# --------------------------------------------------------------------------- #

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 256
BOOTSTRAP_ADMIN = "admin"
DEFAULT_BOOTSTRAP_PASSWORD = "admin"
INITIAL_PASSWORD_ENV = "VECSHIELD_INITIAL_ADMIN_PASSWORD"

DEFAULT_IDLE_MINUTES = 60.0
DEFAULT_MAX_HOURS = 12.0
DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_LOCKOUT_MINUTES = 15.0
#: last_seen_at is written at most this often, so reads stay cheap.
TOUCH_INTERVAL_S = 60.0

_SCRYPT_N = 2 ** 14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SALT_BYTES = 16
_KEY_BYTES = 32

_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._@-]{1,63}$")

#: Deliberately tiny: the length floor does most of the work, this catches
#: the obvious choices someone makes when forced off ``admin``.
_DENYLIST = frozenset({
    "admin", "administrator", "password", "changeme", "vecshield",
    "letmein", "welcome", "qwerty", "123456789012", "1234567890123",
    "password1234", "password12345", "passwordpassword", "adminadminadmin",
    "administrator1", "changemechangeme", "changeme1234", "vecshield123",
    "vecshield1234", "vecshieldadmin", "qwertyuiop12", "welcome12345",
    "letmeinletmein",
})


# --------------------------------------------------------------------------- #
# Errors                                                                      #
# --------------------------------------------------------------------------- #

class UserStoreError(Exception):
    """Base class for account errors; ``str()`` is safe to show to a caller."""


class PasswordPolicyError(UserStoreError, ValueError):
    """A new password does not meet the policy."""


class InvalidUserError(UserStoreError, ValueError):
    """A username or role set is malformed."""


class UserExistsError(UserStoreError):
    """An account with that username already exists."""


class UserNotFoundError(UserStoreError, KeyError):
    """No account with that username."""

    def __str__(self) -> str:  # KeyError would repr() the message
        return str(self.args[0]) if self.args else "unknown user"


class AccountGuardError(UserStoreError):
    """The change would lock everyone out (last admin) or disable oneself."""


class InvalidCredentialsError(UserStoreError):
    """Wrong username or password, or a disabled account. Deliberately generic."""


class AccountLockedError(UserStoreError):
    """Too many failures; retry after ``retry_after_s`` seconds."""

    def __init__(self, retry_after_s: float):
        self.retry_after_s = max(0.0, float(retry_after_s))
        super().__init__(
            f"too many failed sign-in attempts; try again in {self.retry_minutes} "
            f"minute{'s' if self.retry_minutes != 1 else ''}")

    @property
    def retry_minutes(self) -> int:
        return max(1, int(-(-self.retry_after_s // 60)))


# --------------------------------------------------------------------------- #
# Password hashing                                                            #
# --------------------------------------------------------------------------- #

def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int, dklen: int) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                          dklen=dklen, maxmem=256 * n * r + 1024 * 1024)


def hash_password(password: str) -> str:
    """Return ``scrypt$n$r$p$salt_b64$hash_b64`` for ``password``."""
    salt = secrets.token_bytes(_SALT_BYTES)
    key = _scrypt(password, salt, _SCRYPT_N, _SCRYPT_R, _SCRYPT_P, _KEY_BYTES)
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${_b64e(salt)}${_b64e(key)}"


def verify_password(password: str, encoded: str) -> bool:
    """Constant-time check of ``password`` against an encoded scrypt hash."""
    try:
        scheme, n_s, r_s, p_s, salt_b64, key_b64 = encoded.split("$")
        if scheme != "scrypt":
            return False
        n, r, p = int(n_s), int(r_s), int(p_s)
        # Refuse absurd parameters from a tampered row rather than allocate them.
        if not (2 <= n <= 2 ** 20 and 1 <= r <= 32 and 1 <= p <= 16):
            return False
        salt, expected = _b64d(salt_b64), _b64d(key_b64)
    except (ValueError, TypeError):
        return False
    actual = _scrypt(password, salt, n, r, p, len(expected))
    return hmac.compare_digest(actual, expected)


_DUMMY_HASH: Optional[str] = None
_DUMMY_LOCK = threading.Lock()


def _dummy_verify(password: str) -> None:
    """Spend one scrypt so an unknown user costs what a known one does."""
    global _DUMMY_HASH
    with _DUMMY_LOCK:
        if _DUMMY_HASH is None:
            _DUMMY_HASH = hash_password(secrets.token_urlsafe(16))
        dummy = _DUMMY_HASH
    verify_password(password[:MAX_PASSWORD_LENGTH], dummy)


# --------------------------------------------------------------------------- #
# Validation                                                                  #
# --------------------------------------------------------------------------- #

def normalize_username(raw: object) -> str:
    """Lower-case and validate a username; raises :class:`InvalidUserError`."""
    name = str(raw or "").strip().lower()
    if not _USERNAME_RE.fullmatch(name):
        raise InvalidUserError(
            "username must be 2-64 characters: lowercase letters, digits, and . _ @ -, "
            "starting with a letter or digit")
    return name


def validate_roles(raw: object) -> tuple[str, ...]:
    """Validate a granted-role list; at least one known role is required."""
    if isinstance(raw, str) or not isinstance(raw, (list, tuple, set, frozenset)):
        raise InvalidUserError("roles must be a list")
    roles: set[str] = set()
    for item in raw:
        role = str(item).strip().lower()
        if role not in ALL_ROLES:
            raise InvalidUserError(
                f"unknown role {item!r}; roles are {', '.join(ALL_ROLES)}")
        roles.add(role)
    if not roles:
        raise InvalidUserError("at least one role is required")
    return tuple(sorted(roles))


def check_password_policy(password: object, *, username: str = "") -> None:
    """Raise :class:`PasswordPolicyError` if ``password`` is not acceptable."""
    if not isinstance(password, str):
        raise PasswordPolicyError("password must be text")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(
            f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise PasswordPolicyError(
            f"password must be at most {MAX_PASSWORD_LENGTH} characters")
    lowered = password.strip().lower()
    if username and lowered == username.lower():
        raise PasswordPolicyError("password must not be the username")
    if lowered in _DENYLIST:
        raise PasswordPolicyError("that password is too common; choose another")


def _iso(ts: Optional[float]) -> Optional[str]:
    if ts is None:
        return None
    return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        logger.warning("ignoring %s=%r: not a number", name, raw)
        return default
    return value if value > 0 else default


# --------------------------------------------------------------------------- #
# Records                                                                     #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class User:
    """An account as the API sees it; never carries the password hash."""

    username: str
    roles: tuple[str, ...]
    disabled: bool
    must_change_password: bool
    created_at: float
    created_by: Optional[str]
    updated_at: float
    last_login_at: Optional[float]

    def public_dict(self) -> dict:
        return {
            "username": self.username,
            "roles": list(self.roles),
            "disabled": self.disabled,
            "must_change_password": self.must_change_password,
            "created_at": _iso(self.created_at),
            "created_by": self.created_by,
            "last_login_at": _iso(self.last_login_at),
        }


@dataclass(frozen=True)
class Session:
    """A freshly issued session. ``token`` is the only copy of the secret."""

    token: str
    username: str
    created_at: float
    expires_at: float


_DDL = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS users (
    username             TEXT PRIMARY KEY,
    password_hash        TEXT NOT NULL,
    roles                TEXT NOT NULL,
    disabled             INTEGER NOT NULL DEFAULT 0,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    created_at           REAL NOT NULL,
    created_by           TEXT,
    updated_at           REAL NOT NULL,
    last_login_at        REAL,
    failed_attempts      INTEGER NOT NULL DEFAULT 0,
    locked_until         REAL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_sha256 TEXT PRIMARY KEY,
    username     TEXT NOT NULL REFERENCES users(username),
    created_at   REAL NOT NULL,
    last_seen_at REAL NOT NULL,
    expires_at   REAL NOT NULL,
    user_agent   TEXT
);

CREATE INDEX IF NOT EXISTS ix_sessions_username ON sessions(username);
CREATE INDEX IF NOT EXISTS ix_sessions_expires  ON sessions(expires_at);
"""


def _create_private(path: str) -> None:
    """Create ``path`` owner-only before SQLite opens it, so the file (and the
    WAL/SHM sidecars SQLite derives from it) never exist world-readable."""
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return
    except OSError:
        return  # let sqlite3.connect report a real problem
    os.close(fd)


def bootstrap_pending(db_path: str | Path) -> bool:
    """True when opening a :class:`UserStore` at ``db_path`` would create ``admin``.

    Creates nothing: a missing file is reported as pending without being made,
    so a caller can refuse to start before any account exists.
    """
    path = Path(db_path)
    if not path.exists():
        return True
    conn = sqlite3.connect(str(path))
    try:
        return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
    except sqlite3.OperationalError as e:
        if "no such table" in str(e):
            return True
        raise
    finally:
        conn.close()


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def session_id(token_sha256: str) -> str:
    """The public handle for a session: a hash of its stored hash, truncated."""
    return hashlib.sha256(token_sha256.encode("ascii")).hexdigest()[:16]


def session_id_for_token(token: Optional[str]) -> Optional[str]:
    return session_id(_token_hash(token)) if token else None


def _user(row: sqlite3.Row) -> User:
    try:
        roles = tuple(sorted(r for r in json.loads(row["roles"]) if r in ALL_ROLES))
    except (TypeError, ValueError):
        roles = ()
    return User(
        username=row["username"],
        roles=roles,
        disabled=bool(row["disabled"]),
        must_change_password=bool(row["must_change_password"]),
        created_at=float(row["created_at"]),
        created_by=row["created_by"],
        updated_at=float(row["updated_at"]),
        last_login_at=(float(row["last_login_at"])
                       if row["last_login_at"] is not None else None),
    )


# --------------------------------------------------------------------------- #
# Store                                                                       #
# --------------------------------------------------------------------------- #

class UserStore:
    """Thread-safe SQLite store of local accounts and their sessions."""

    def __init__(
        self,
        db_path: str | Path = ":memory:",
        *,
        clock: Callable[[], float] = time.time,
        idle_minutes: Optional[float] = None,
        max_hours: Optional[float] = None,
        max_attempts: Optional[int] = None,
        lockout_minutes: Optional[float] = None,
        initial_admin_password: Optional[str] = None,
    ):
        self._path = str(db_path)
        self._clock = clock
        self.idle_s = 60.0 * (idle_minutes if idle_minutes is not None else
                              _env_float("VECSHIELD_SESSION_IDLE_MINUTES", DEFAULT_IDLE_MINUTES))
        self.max_s = 3600.0 * (max_hours if max_hours is not None else
                               _env_float("VECSHIELD_SESSION_MAX_HOURS", DEFAULT_MAX_HOURS))
        self.max_attempts = int(max_attempts if max_attempts is not None else
                                _env_float("VECSHIELD_LOGIN_MAX_ATTEMPTS", DEFAULT_MAX_ATTEMPTS))
        self.lockout_s = 60.0 * (lockout_minutes if lockout_minutes is not None else
                                 _env_float("VECSHIELD_LOGIN_LOCKOUT_MINUTES",
                                            DEFAULT_LOCKOUT_MINUTES))
        self._lock = threading.Lock()
        is_file = self._path != ":memory:" and not self._path.startswith("file:")
        if is_file:
            _create_private(self._path)
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_DDL)
        self._conn.commit()
        if is_file:
            # SQLite gives -wal/-shm the database file's mode; tighten any that
            # an older run left readable. Best effort on odd filesystems.
            for suffix in ("", "-wal", "-shm"):
                try:
                    os.chmod(self._path + suffix, 0o600)
                except OSError:
                    pass
        if initial_admin_password is None:
            initial_admin_password = os.environ.get(INITIAL_PASSWORD_ENV) or None
        self._bootstrap_password = initial_admin_password or DEFAULT_BOOTSTRAP_PASSWORD
        self.bootstrapped = self._bootstrap()

    # ------------------------------------------------------------------ #
    # Bootstrap                                                            #
    # ------------------------------------------------------------------ #

    def _bootstrap(self) -> bool:
        """Create the first admin when there are no accounts at all."""
        with self._lock:
            count = self._conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            if count:
                return False
            now = self._clock()
            with self._conn:
                self._conn.execute(
                    "INSERT INTO users (username, password_hash, roles, disabled, "
                    "must_change_password, created_at, created_by, updated_at) "
                    "VALUES (?, ?, ?, 0, 1, ?, ?, ?)",
                    (BOOTSTRAP_ADMIN, hash_password(self._bootstrap_password),
                     json.dumps([ADMIN]), now, "bootstrap", now))
        if self._bootstrap_password == DEFAULT_BOOTSTRAP_PASSWORD:
            logger.warning(
                "created the initial local account 'admin' with the default password "
                "'admin'; it must be changed at first sign-in. Set %s before first "
                "start to choose a different bootstrap password.", INITIAL_PASSWORD_ENV)
        else:
            logger.warning(
                "created the initial local account 'admin' with the password from %s; "
                "it must be changed at first sign-in.", INITIAL_PASSWORD_ENV)
        return True

    def default_admin_password_active(self) -> bool:
        """True while ``admin`` still signs in with the bootstrap default ``admin``.

        Costs one scrypt; intended for a startup warning, not per request.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT password_hash, must_change_password, disabled FROM users "
                "WHERE username = ?", (BOOTSTRAP_ADMIN,)).fetchone()
        if row is None or row["disabled"] or not row["must_change_password"]:
            return False
        return verify_password(DEFAULT_BOOTSTRAP_PASSWORD, row["password_hash"])

    # ------------------------------------------------------------------ #
    # Reads                                                                #
    # ------------------------------------------------------------------ #

    def ping(self) -> None:
        with self._lock:
            self._conn.execute("SELECT 1").fetchone()

    def get_user(self, username: str) -> Optional[User]:
        name = str(username or "").strip().lower()
        with self._lock:
            row = self._conn.execute("SELECT * FROM users WHERE username = ?",
                                     (name,)).fetchone()
        return _user(row) if row is not None else None

    def list_users(self) -> list[User]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM users ORDER BY username").fetchall()
        return [_user(r) for r in rows]

    # ------------------------------------------------------------------ #
    # Sign-in                                                              #
    # ------------------------------------------------------------------ #

    def authenticate(self, username: object, password: object) -> User:
        """Verify credentials. Raises :class:`InvalidCredentialsError` (generic)
        or :class:`AccountLockedError`; returns the user and records the login."""
        pw = password if isinstance(password, str) else ""
        try:
            name = normalize_username(username)
        except InvalidUserError:
            _dummy_verify(pw)
            raise InvalidCredentialsError("invalid username or password") from None
        row = self._reserve_attempt(name)
        if row is None:
            _dummy_verify(pw)
            raise InvalidCredentialsError("invalid username or password")
        ok = len(pw) <= MAX_PASSWORD_LENGTH and verify_password(pw, row["password_hash"])
        if not ok:
            self._record_failure(name)
            raise InvalidCredentialsError("invalid username or password")
        if row["disabled"]:
            # Not a password failure: hand the reserved attempt back.
            self._release_attempt(name)
            raise InvalidCredentialsError("invalid username or password")
        self._record_success(name, login=True)
        user = self.get_user(name)
        assert user is not None
        return user

    # A wrong guess is counted *before* the password is checked, in the same
    # locked transaction that checks the lock. Counting it afterwards let a
    # burst of concurrent guesses all pass the lock check and each run a full
    # password verification before any of them was recorded, so the lockout
    # threshold did not bound the number of guesses. ``failed_attempts`` holds
    # recorded failures plus attempts still being checked.

    def _reserve_attempt(self, name: str) -> Optional[sqlite3.Row]:
        """Claim one attempt against ``name`` or raise :class:`AccountLockedError`.

        Returns the user row (``None`` for an unknown user, which reserves
        nothing). Every reservation must be settled with exactly one of
        :meth:`_record_failure`, :meth:`_record_success` or
        :meth:`_release_attempt`.
        """
        now = self._clock()
        with self._lock, self._conn:
            row = self._conn.execute("SELECT * FROM users WHERE username = ?",
                                     (name,)).fetchone()
            if row is None:
                return None
            locked_until = row["locked_until"]
            if locked_until is not None and float(locked_until) > now:
                raise AccountLockedError(float(locked_until) - now)
            if int(row["failed_attempts"]) >= self.max_attempts:
                # Enough attempts are already recorded or in flight to reach the
                # threshold; this one is refused without checking the password.
                raise AccountLockedError(self.lockout_s)
            self._conn.execute(
                "UPDATE users SET failed_attempts = failed_attempts + 1 "
                "WHERE username = ?", (name,))
        return row

    def _release_attempt(self, name: str) -> None:
        """Hand back a reservation that was not a password failure."""
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE users SET failed_attempts = MAX(failed_attempts - 1, 0) "
                "WHERE username = ?", (name,))

    def _record_failure(self, name: str) -> None:
        """Settle a reserved attempt as a wrong password; lock at the threshold."""
        now = self._clock()
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT failed_attempts, locked_until FROM users WHERE username = ?",
                (name,)).fetchone()
            if row is None:
                return
            attempts = int(row["failed_attempts"])  # already counts this one
            already_locked = (row["locked_until"] is not None
                              and float(row["locked_until"]) > now)
            if attempts >= self.max_attempts and not already_locked:
                self._conn.execute(
                    "UPDATE users SET failed_attempts = 0, locked_until = ? "
                    "WHERE username = ?", (now + self.lockout_s, name))
                logger.warning("local account %r locked after %d failed sign-ins",
                               name, attempts)

    def _record_success(self, name: str, *, login: bool) -> None:
        """Settle a reserved attempt as a correct password.

        Clears the failure count only if the account is not locked at this
        moment: a lock set by concurrent wrong guesses while this password was
        being checked wins, and the correct guess is refused.
        """
        now = self._clock()
        with self._lock, self._conn:
            row = self._conn.execute("SELECT locked_until FROM users WHERE username = ?",
                                     (name,)).fetchone()
            if row is not None and row["locked_until"] is not None \
                    and float(row["locked_until"]) > now:
                raise AccountLockedError(float(row["locked_until"]) - now)
            if login:
                self._conn.execute(
                    "UPDATE users SET failed_attempts = 0, locked_until = NULL, "
                    "last_login_at = ? WHERE username = ?", (now, name))
            else:
                self._conn.execute(
                    "UPDATE users SET failed_attempts = 0, locked_until = NULL "
                    "WHERE username = ?", (name,))

    def is_locked(self, username: str) -> bool:
        with self._lock:
            row = self._conn.execute("SELECT locked_until FROM users WHERE username = ?",
                                     (str(username).lower(),)).fetchone()
        return bool(row and row["locked_until"] is not None
                    and float(row["locked_until"]) > self._clock())

    # ------------------------------------------------------------------ #
    # Sessions                                                             #
    # ------------------------------------------------------------------ #

    def create_session(self, username: str, *, user_agent: Optional[str] = None) -> Session:
        now = self._clock()
        token = secrets.token_urlsafe(32)
        expires = now + self.max_s
        with self._lock, self._conn:
            self._conn.execute(
                "DELETE FROM sessions WHERE expires_at <= ? OR last_seen_at <= ?",
                (now, now - self.idle_s))
            self._conn.execute(
                "INSERT INTO sessions (token_sha256, username, created_at, last_seen_at, "
                "expires_at, user_agent) VALUES (?, ?, ?, ?, ?, ?)",
                (_token_hash(token), username, now, now, expires,
                 (user_agent or "")[:256] or None))
        return Session(token=token, username=username, created_at=now, expires_at=expires)

    def resolve_session(self, token: Optional[str]) -> Optional[User]:
        """Return the enabled user behind a live session token, else ``None``.

        Expired sessions and sessions of disabled users are deleted on sight.
        """
        if not token or len(token) > 512:
            return None
        digest = _token_hash(token)
        now = self._clock()
        with self._lock:
            row = self._conn.execute(
                "SELECT s.last_seen_at, s.expires_at, u.* FROM sessions s "
                "JOIN users u ON u.username = s.username WHERE s.token_sha256 = ?",
                (digest,)).fetchone()
            if row is None:
                return None
            last_seen = float(row["last_seen_at"])
            if (now >= float(row["expires_at"]) or now - last_seen >= self.idle_s
                    or row["disabled"]):
                with self._conn:
                    self._conn.execute("DELETE FROM sessions WHERE token_sha256 = ?",
                                       (digest,))
                return None
            if now - last_seen >= TOUCH_INTERVAL_S:
                with self._conn:
                    self._conn.execute(
                        "UPDATE sessions SET last_seen_at = ? WHERE token_sha256 = ?",
                        (now, digest))
            return _user(row)

    def revoke_session(self, token: Optional[str]) -> None:
        if not token:
            return
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM sessions WHERE token_sha256 = ?",
                               (_token_hash(token),))

    def revoke_user_sessions(self, username: str, *, except_token: Optional[str] = None) -> int:
        keep = _token_hash(except_token) if except_token else ""
        with self._lock, self._conn:
            cur = self._conn.execute(
                "DELETE FROM sessions WHERE username = ? AND token_sha256 != ?",
                (username, keep))
            return cur.rowcount

    def session_count(self, username: str) -> int:
        with self._lock:
            return int(self._conn.execute(
                "SELECT COUNT(*) FROM sessions WHERE username = ?", (username,)).fetchone()[0])

    def list_user_sessions(self, username: str) -> list[dict]:
        """The user's live sessions, newest first, for self-service review.

        Each carries an opaque ``id`` derived from the stored hash; the hash
        itself is the lookup key and never leaves the store.
        """
        now = self._clock()
        with self._lock:
            rows = self._conn.execute(
                "SELECT token_sha256, created_at, last_seen_at, expires_at, user_agent "
                "FROM sessions WHERE username = ? AND expires_at > ? AND last_seen_at > ? "
                "ORDER BY created_at DESC",
                (username, now, now - self.idle_s)).fetchall()
        return [{
            "id": session_id(row["token_sha256"]),
            "created_at": _iso(row["created_at"]),
            "last_seen_at": _iso(row["last_seen_at"]),
            "expires_at": _iso(row["expires_at"]),
            "user_agent": row["user_agent"],
        } for row in rows]

    def revoke_session_by_id(self, username: str, sid: str) -> bool:
        """Revoke one of ``username``'s sessions by its opaque id.

        Only that user's rows are searched, so an id belonging to someone else
        is indistinguishable from an unknown one.
        """
        with self._lock, self._conn:
            rows = self._conn.execute(
                "SELECT token_sha256 FROM sessions WHERE username = ?",
                (username,)).fetchall()
            for row in rows:
                if hmac.compare_digest(session_id(row["token_sha256"]), sid):
                    self._conn.execute("DELETE FROM sessions WHERE token_sha256 = ?",
                                       (row["token_sha256"],))
                    return True
        return False

    # ------------------------------------------------------------------ #
    # Account management                                                   #
    # ------------------------------------------------------------------ #

    def create_user(self, username: object, password: object, roles: Iterable[str],
                    *, created_by: str) -> User:
        name = normalize_username(username)
        granted = validate_roles(roles)
        check_password_policy(password, username=name)
        assert isinstance(password, str)
        encoded = hash_password(password)
        now = self._clock()
        with self._lock, self._conn:
            if self._conn.execute("SELECT 1 FROM users WHERE username = ?",
                                  (name,)).fetchone():
                raise UserExistsError(f"user {name!r} already exists")
            self._conn.execute(
                "INSERT INTO users (username, password_hash, roles, disabled, "
                "must_change_password, created_at, created_by, updated_at) "
                "VALUES (?, ?, ?, 0, 1, ?, ?, ?)",
                (name, encoded, json.dumps(list(granted)), now, created_by, now))
        user = self.get_user(name)
        assert user is not None
        return user

    def update_user(self, username: str, *, roles: Optional[Iterable[str]] = None,
                    disabled: Optional[bool] = None, actor: Optional[str] = None) -> User:
        """Change roles and/or disabled state, refusing to strand the console.

        ``actor`` is the local account making the change (if any); it may not
        disable itself.
        """
        name = str(username or "").strip().lower()
        granted = validate_roles(roles) if roles is not None else None
        now = self._clock()
        with self._lock, self._conn:
            row = self._conn.execute("SELECT * FROM users WHERE username = ?",
                                     (name,)).fetchone()
            if row is None:
                raise UserNotFoundError(f"unknown user {name!r}")
            current = _user(row)
            new_roles = granted if granted is not None else current.roles
            new_disabled = bool(disabled) if disabled is not None else current.disabled
            if new_disabled and not current.disabled and actor and actor == name:
                raise AccountGuardError("you cannot disable your own account")
            was_admin = ADMIN in current.roles and not current.disabled
            stays_admin = ADMIN in new_roles and not new_disabled
            if was_admin and not stays_admin:
                others = 0
                for r in self._conn.execute(
                        "SELECT roles FROM users WHERE disabled = 0 AND username != ?",
                        (name,)).fetchall():
                    try:
                        if ADMIN in json.loads(r["roles"]):
                            others += 1
                    except (TypeError, ValueError):
                        continue
                if others == 0:
                    raise AccountGuardError(
                        "this is the last enabled admin; grant admin to another "
                        "account first")
            self._conn.execute(
                "UPDATE users SET roles = ?, disabled = ?, updated_at = ? WHERE username = ?",
                (json.dumps(list(new_roles)), int(new_disabled), now, name))
            if new_disabled:
                self._conn.execute("DELETE FROM sessions WHERE username = ?", (name,))
        user = self.get_user(name)
        assert user is not None
        return user

    def change_password(self, username: str, current_password: object,
                        new_password: object, *, keep_token: Optional[str] = None) -> User:
        """Self-service change. Wrong ``current_password`` counts as a failed
        sign-in (a stolen session must not be a free password oracle)."""
        name = str(username or "").strip().lower()
        with self._lock:
            existing = self._conn.execute("SELECT disabled FROM users WHERE username = ?",
                                          (name,)).fetchone()
        if existing is None or existing["disabled"]:
            raise UserNotFoundError(f"unknown user {name!r}")
        row = self._reserve_attempt(name)
        if row is None:
            raise UserNotFoundError(f"unknown user {name!r}")
        cur = current_password if isinstance(current_password, str) else ""
        if len(cur) > MAX_PASSWORD_LENGTH or not verify_password(cur, row["password_hash"]):
            self._record_failure(name)
            raise InvalidCredentialsError("current password is incorrect")
        self._record_success(name, login=False)
        check_password_policy(new_password, username=name)
        assert isinstance(new_password, str)
        if hmac.compare_digest(cur.encode("utf-8"), new_password.encode("utf-8")):
            raise PasswordPolicyError("the new password must differ from the current one")
        self._set_password(name, new_password, must_change=False, keep_token=keep_token)
        user = self.get_user(name)
        assert user is not None
        return user

    def reset_password(self, username: str, new_password: object) -> User:
        """Administrative reset: forces a change at next sign-in and signs the
        account out everywhere."""
        name = str(username or "").strip().lower()
        if self.get_user(name) is None:
            raise UserNotFoundError(f"unknown user {name!r}")
        check_password_policy(new_password, username=name)
        assert isinstance(new_password, str)
        self._set_password(name, new_password, must_change=True, keep_token=None)
        user = self.get_user(name)
        assert user is not None
        return user

    def _set_password(self, name: str, password: str, *, must_change: bool,
                      keep_token: Optional[str]) -> None:
        encoded = hash_password(password)
        now = self._clock()
        keep = _token_hash(keep_token) if keep_token else ""
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE users SET password_hash = ?, must_change_password = ?, "
                "failed_attempts = 0, locked_until = NULL, updated_at = ? "
                "WHERE username = ?", (encoded, int(must_change), now, name))
            self._conn.execute(
                "DELETE FROM sessions WHERE username = ? AND token_sha256 != ?",
                (name, keep))

    # ------------------------------------------------------------------ #
    # Lifecycle                                                            #
    # ------------------------------------------------------------------ #

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "UserStore":
        return self

    def __exit__(self, *_) -> None:
        self.close()
