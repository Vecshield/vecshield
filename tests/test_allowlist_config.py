"""ConfigStore persistence of allow-list rules and suppressions (1.12c)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from vecshield.models import Severity
from vecshield_platform.api.config_store import ConfigStore
from vecshield_platform.compliance.allowlist import SuppressionError


def _future(days: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def test_add_and_remove_allowlist_rule():
    cfg = ConfigStore()
    r = cfg.add_allowlist_rule(reason="research corpus",
                               category="rag_integrity", collection="kb",
                               owner="alice")
    assert r.id in cfg.allowlist
    cfg.remove_allowlist_rule(r.id)
    assert r.id not in cfg.allowlist


def test_add_unscoped_allowlist_rule_rejected():
    cfg = ConfigStore()
    with pytest.raises(SuppressionError):
        cfg.add_allowlist_rule(reason="oops")  # no scope, no matcher


def test_effective_allowlist_includes_builtins():
    cfg = ConfigStore()
    cfg.add_allowlist_rule(reason="x", category="cve")
    rules = cfg.effective_allowlist()
    assert any(r.source == "builtin" for r in rules)
    assert any(r.source == "custom" for r in rules)
    # Built-ins can be excluded.
    assert all(r.source == "custom"
               for r in cfg.effective_allowlist(include_builtin=False))


def test_add_suppression_validates_and_persists():
    cfg = ConfigStore()
    s = cfg.add_suppression(fingerprint="fp-1", reason="accepted", owner="sec",
                            expires_at=_future(10))
    assert s.id in cfg.suppressions
    assert cfg.active_suppressions()  # not expired


def test_add_suppression_rejects_bad_ttl():
    cfg = ConfigStore()
    with pytest.raises(SuppressionError):
        cfg.add_suppression(fingerprint="fp", reason="r", owner="o",
                            expires_at=_future(-1))
    # Sensitive finding cannot get a long TTL.
    with pytest.raises(SuppressionError):
        cfg.add_suppression(fingerprint="fp", reason="r", owner="o",
                            expires_at=_future(60), category="data_classification",
                            severity=Severity.CRITICAL)


def test_remove_suppression():
    cfg = ConfigStore()
    s = cfg.add_suppression(fingerprint="fp", reason="r", owner="o",
                            expires_at=_future(5))
    cfg.remove_suppression(s.id)
    assert s.id not in cfg.suppressions


def test_persistence_round_trip(tmp_path):
    path = str(tmp_path / "config.json")
    cfg = ConfigStore(path)
    cfg.add_allowlist_rule(reason="research", category="rag_integrity",
                           collection="kb", owner="alice")
    supp = cfg.add_suppression(fingerprint="fp-xyz", reason="accepted",
                               owner="sec", expires_at=_future(20), ticket="J-1")

    reloaded = ConfigStore(path)
    assert len(reloaded.allowlist) == 1
    assert len(reloaded.suppressions) == 1
    r = next(iter(reloaded.allowlist.values()))
    assert r.category == "rag_integrity" and r.collection == "kb"
    s = reloaded.suppressions[supp.id]
    assert s.fingerprint == "fp-xyz" and s.ticket == "J-1"
