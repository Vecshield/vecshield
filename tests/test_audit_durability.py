"""Durability of the persisted audit chain: failed writes, torn tails, and a
single writer per file.

The on-disk JSON Lines file is the compliance evidence. A write that fails must
leave both the file and the in-memory chain as they were, a crash mid-write
must not brick the service with an unhandled parse error, and two writers must
not fork the chain.
"""

from __future__ import annotations

import errno
import json
import os
import subprocess
import sys
import textwrap

import pytest
from click.testing import CliRunner

from vecshield_platform.compliance import audit as audit_mod
from vecshield_platform.compliance.audit import (
    AuditIntegrityError,
    AuditLog,
    AuditLogLockedError,
    AuditTornTailError,
)

posix_only = pytest.mark.skipif(sys.platform == "win32",
                                reason="advisory locking is POSIX-only")


# --------------------------------------------------------------------------- #
# Write failures                                                              #
# --------------------------------------------------------------------------- #

def test_failed_fsync_raises_and_leaves_file_and_chain_unchanged(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    log = AuditLog.open(str(path))
    try:
        log.append("admin", "store_added", "s1", timestamp=1.0)
        before = path.read_bytes()

        def disk_full(fd):
            raise OSError(errno.ENOSPC, "No space left on device")

        monkeypatch.setattr(os, "fsync", disk_full)
        with pytest.raises(OSError):
            log.append("admin", "erasure_executed", "s1", timestamp=2.0)
        monkeypatch.undo()

        # Neither the chain nor the file recorded an entry that was not durable.
        assert len(log.entries) == 1
        assert path.read_bytes() == before

        log.append("admin", "store_removed", "s1", timestamp=3.0)
        assert [e.seq for e in log.entries] == [0, 1]
        assert log.verify().ok
    finally:
        log.close()
    reopened = AuditLog.open(str(path))
    try:
        assert [e.action for e in reopened.entries] == ["store_added", "store_removed"]
        assert reopened.verify().ok
    finally:
        reopened.close()


def test_partial_write_is_rolled_back(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    log = AuditLog.open(str(path))
    try:
        log.append("admin", "a", "t", timestamp=1.0)
        before = path.read_bytes()
        real = audit_mod._write_all

        def half_then_fail(fd, data):
            real(fd, data[: len(data) // 2])
            raise OSError(errno.EIO, "I/O error")

        monkeypatch.setattr(audit_mod, "_write_all", half_then_fail)
        with pytest.raises(OSError):
            log.append("admin", "b", "t", timestamp=2.0)
        monkeypatch.undo()

        assert path.read_bytes() == before
        assert len(log.entries) == 1
        log.append("admin", "c", "t", timestamp=3.0)
    finally:
        log.close()
    reopened = AuditLog.open(str(path))
    try:
        assert [e.action for e in reopened.entries] == ["a", "c"]
        assert reopened.verify().ok
    finally:
        reopened.close()


# --------------------------------------------------------------------------- #
# Torn tail                                                                   #
# --------------------------------------------------------------------------- #

def _write_log_with_torn_tail(path, torn: str) -> None:
    log = AuditLog.open(str(path))
    try:
        log.append("admin", "a", "t", timestamp=1.0)
        log.append("admin", "b", "t", timestamp=2.0)
    finally:
        log.close()
    with open(path, "a") as f:
        f.write(torn)  # the process died mid-write: no trailing newline


def test_torn_final_line_is_recovered_and_recorded(tmp_path, caplog):
    path = tmp_path / "audit.jsonl"
    torn = '{"seq": 2, "timestamp": 3.0, "act'
    _write_log_with_torn_tail(path, torn)

    with caplog.at_level("WARNING", logger=audit_mod.__name__):
        log = AuditLog.open(str(path))
    try:
        actions = [e.action for e in log.entries]
        assert actions == ["a", "b", "audit_log_recovered"]
        note = log.entries[-1]
        assert note.actor == "system"
        assert note.details["torn_bytes"] == len(torn.encode())
        assert note.details["torn_tail"] == torn
        assert note.details["reason"]
        assert log.verify().ok
        assert "torn" in caplog.text.lower()
    finally:
        log.close()

    # The torn bytes are gone from the file; the recovery note is on the chain.
    lines = path.read_text().splitlines()
    assert len(lines) == 3
    assert json.loads(lines[-1])["action"] == "audit_log_recovered"
    again = AuditLog.open(str(path))
    try:
        assert len(again.entries) == 3 and again.verify().ok
    finally:
        again.close()


def test_from_jsonl_reports_a_torn_tail_as_an_integrity_error(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write_log_with_torn_tail(path, '{"seq": 2, "ti')
    with pytest.raises(AuditTornTailError) as exc:
        AuditLog.from_jsonl(str(path))
    assert isinstance(exc.value, AuditIntegrityError)


@pytest.mark.parametrize("corrupt", [
    "not json at all\n",                   # complete (newline-terminated) garbage
    '{"seq": 2, "unexpected": true}\n',    # valid JSON, not an entry
])
def test_corrupt_complete_line_is_an_integrity_error(tmp_path, corrupt):
    path = tmp_path / "audit.jsonl"
    log = AuditLog.open(str(path))
    log.append("admin", "a", "t", timestamp=1.0)
    log.close()
    with open(path, "a") as f:
        f.write(corrupt)
    with pytest.raises(AuditIntegrityError) as exc:
        AuditLog.open(str(path))
    assert not isinstance(exc.value, AuditTornTailError)
    # The refusal must not have modified the evidence.
    assert path.read_text().endswith(corrupt)


def test_corrupt_middle_line_is_an_integrity_error_not_a_parse_crash(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog.open(str(path))
    log.append("admin", "a", "t", timestamp=1.0)
    log.append("admin", "b", "t", timestamp=2.0)
    log.close()
    lines = path.read_text().splitlines()
    lines.insert(1, '{"seq": 1, "timest')
    path.write_text("\n".join(lines) + "\n")
    with pytest.raises(AuditIntegrityError):
        AuditLog.open(str(path))


# --------------------------------------------------------------------------- #
# Single writer                                                               #
# --------------------------------------------------------------------------- #

@posix_only
def test_second_opener_fails_fast_and_lock_is_released_on_close(tmp_path):
    path = tmp_path / "audit.jsonl"
    first = AuditLog.open(str(path))
    try:
        first.append("admin", "x", "1")
        with pytest.raises(AuditLogLockedError, match="already open"):
            AuditLog.open(str(path))
        first.append("admin", "y", "2")
    finally:
        first.close()
    with AuditLog.open(str(path)) as second:
        second.append("admin", "z", "3")
        assert [e.seq for e in second.entries] == [0, 1, 2]
        assert second.verify().ok


@posix_only
def test_second_process_cannot_open_a_held_audit_log(tmp_path):
    path = tmp_path / "audit.jsonl"
    held = AuditLog.open(str(path))
    try:
        held.append("admin", "x", "1")
        probe = textwrap.dedent(f"""
            from vecshield_platform.compliance.audit import AuditLog, AuditLogLockedError
            try:
                AuditLog.open({str(path)!r}).append("admin", "fork", "2")
            except AuditLogLockedError:
                raise SystemExit(3)
        """)
        proc = subprocess.run([sys.executable, "-c", probe], capture_output=True,
                              text=True, timeout=60)
        assert proc.returncode == 3, proc.stderr
        held.append("admin", "y", "2")
    finally:
        held.close()
    with AuditLog.open(str(path)) as reopened:
        assert [e.action for e in reopened.entries] == ["x", "y"]
        assert reopened.verify().ok


# --------------------------------------------------------------------------- #
# serve startup                                                               #
# --------------------------------------------------------------------------- #

def _serve(tmp_path, monkeypatch):
    import uvicorn

    from vecshield_platform.cli import cli

    started: dict = {}
    monkeypatch.setattr(uvicorn, "run",
                        lambda app, host=None, port=None: started.update(ok=True))
    result = CliRunner().invoke(cli, [
        "serve", "--config", str(tmp_path / "vecshield.json"),
        "--state-dir", str(tmp_path / "state"), "--host", "127.0.0.1", "--no-login",
    ])
    return result, started


def _state_audit(tmp_path):
    audit_dir = tmp_path / "state" / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    return audit_dir / "audit.jsonl"


def test_serve_recovers_a_torn_audit_tail(tmp_path, monkeypatch):
    path = _state_audit(tmp_path)
    _write_log_with_torn_tail(path, '{"seq": 2, "act')
    result, started = _serve(tmp_path, monkeypatch)
    assert result.exit_code == 0, result.output
    assert started == {"ok": True}
    assert "recovered" in result.output.lower()
    assert result.exception is None


def test_serve_reports_a_corrupt_audit_log_without_a_traceback(tmp_path, monkeypatch):
    path = _state_audit(tmp_path)
    path.write_text("not json\n{}\n")
    result, started = _serve(tmp_path, monkeypatch)
    assert result.exit_code == 1
    assert started == {}
    assert "integrity check failed" in result.output
    assert not isinstance(result.exception, json.JSONDecodeError)


@posix_only
def test_serve_refuses_an_audit_log_held_by_another_process(tmp_path, monkeypatch):
    path = _state_audit(tmp_path)
    held = AuditLog.open(str(path))
    try:
        result, started = _serve(tmp_path, monkeypatch)
    finally:
        held.close()
    assert result.exit_code == 1, result.output
    assert started == {}
    assert "already open" in result.output


def test_whole_final_entry_missing_only_its_newline_is_kept(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog.open(str(path))
    log.append("admin", "a", "t", timestamp=1.0)
    log.append("admin", "b", "t", timestamp=2.0)
    log.close()
    path.write_bytes(path.read_bytes().rstrip(b"\n"))

    with AuditLog.open(str(path)) as reopened:
        assert [e.action for e in reopened.entries] == ["a", "b"]
        assert reopened.recovery_notes == []
        reopened.append("admin", "c", "t", timestamp=3.0)
    with AuditLog.open(str(path)) as again:
        assert [e.action for e in again.entries] == ["a", "b", "c"]
        assert again.verify().ok


def test_torn_tail_is_restored_if_the_recovery_note_cannot_be_written(
        tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    torn = '{"seq": 2, "act'
    _write_log_with_torn_tail(path, torn)
    before = path.read_bytes()

    def disk_full(fd):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(os, "fsync", disk_full)
    with pytest.raises(OSError):
        AuditLog.open(str(path))
    monkeypatch.undo()
    assert path.read_bytes() == before
    with AuditLog.open(str(path)) as recovered:
        assert recovered.entries[-1].details["torn_tail"] == torn
