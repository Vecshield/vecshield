"""Tamper-evident audit log tests."""

from __future__ import annotations

import json

import pytest

from vecshield_platform.compliance import AuditIntegrityError, AuditLog


def _seed():
    log = AuditLog()
    log.append("alice", "scan", "store/docs", {"findings": 3}, timestamp=1.0)
    log.append("alice", "erasure", "subject/bob@x.io", {"chunks": 5}, timestamp=2.0)
    log.append("system", "policy_eval", "store/docs", {"violations": 1}, timestamp=3.0)
    return log


def test_clean_chain_verifies():
    log = _seed()
    r = log.verify()
    assert r.ok and r.entries == 3 and r.first_bad_seq is None


def test_chaining_links_entries():
    log = _seed()
    e = log.entries
    assert e[0].prev_hash == "0" * 64
    assert e[1].prev_hash == e[0].hash
    assert e[2].prev_hash == e[1].hash


def test_content_tampering_detected():
    log = _seed()
    log._entries[1].details["chunks"] = 9999  # tamper after the fact
    r = log.verify()
    assert not r.ok and r.first_bad_seq == 1 and "tampered" in r.reason


def test_deletion_breaks_chain():
    log = _seed()
    del log._entries[1]
    log._entries[1].seq = 1  # renumber to hide the gap
    r = log.verify()
    assert not r.ok and r.first_bad_seq == 1  # prev_hash no longer matches


def test_persistence_roundtrip(tmp_path):
    log = _seed()
    p = str(tmp_path / "audit.jsonl")
    log.to_jsonl(p)
    loaded = AuditLog.from_jsonl(p)
    assert loaded.verify().ok
    assert loaded.head_hash == log.head_hash


def test_open_persists_across_restart(tmp_path):
    """A served log must survive a restart (the audit gap fixed in 2026-07)."""
    path = str(tmp_path / "audit.jsonl")
    log = AuditLog.open(path)
    log.append("alice", "scan", "store/docs", {"findings": 3}, timestamp=1.0)
    log.append("dpo", "erasure", "subject/x", {"chunks": 2}, timestamp=2.0)

    # Simulate a process restart: the old writer exits (releasing its lock) and
    # a new one reopens the same path. One writer per file at a time.
    log.close()
    reopened = AuditLog.open(path)
    assert [e.action for e in reopened.entries] == ["scan", "erasure"]
    assert reopened.verify().ok

    # Appends continue the same hash chain and are themselves persisted.
    reopened.append("system", "policy_eval", "store/docs", {}, timestamp=3.0)
    reopened.close()
    again = AuditLog.open(path)
    assert len(again.entries) == 3
    assert again.verify().ok


def test_open_rejects_tampered_log(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog.open(str(path))
    log.append("alice", "scan", "store/docs", {"findings": 3}, timestamp=1.0)
    log.append("alice", "scan", "store/docs", {"findings": 9}, timestamp=2.0)
    log.close()

    lines = path.read_text().splitlines()
    tampered = json.loads(lines[0])
    tampered["details"]["findings"] = 0  # rewrite history
    lines[0] = json.dumps(tampered)
    path.write_text("\n".join(lines) + "\n")

    with pytest.raises(AuditIntegrityError):
        AuditLog.open(str(path))
