"""Tests for allow-list / suppression FP-management (improvement plan 1.12b)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from vecshield.models import Finding, Severity
from vecshield_platform.compliance.allowlist import (
    AllowlistRule,
    Suppression,
    SuppressionError,
    builtin_allowlist,
    default_ttl_days,
    evaluate_suppressions,
    is_sensitive,
    validate_suppression,
)
from vecshield_platform.compliance.fingerprint import fingerprint_finding


def _finding(**kw) -> Finding:
    base = dict(id="find-x", title="t", severity=Severity.MEDIUM,
                category="rag_integrity", store="s", collection="kb",
                evidence={})
    base.update(kw)
    return Finding(**base)


NOW = datetime(2025, 1, 1, tzinfo=timezone.utc)


def _future(days: int) -> str:
    return (NOW + timedelta(days=days)).isoformat()


# --------------------------------------------------------------------------- #
# AllowlistRule                                                                #
# --------------------------------------------------------------------------- #

def test_allowlist_rule_requires_scope_or_matcher():
    with pytest.raises(SuppressionError):
        AllowlistRule(id="bad", reason="too broad")


def test_allowlist_matches_by_scope():
    rule = AllowlistRule(id="r1", reason="research corpus",
                         category="rag_integrity", collection="kb",
                         rule="prompt injection")
    f = _finding(title="Prompt-injection content in 'kb'")
    assert rule.matches(f, fingerprint_finding(f))
    # Different collection -> no match.
    other = _finding(collection="prod", title="Prompt-injection content in 'prod'")
    assert not rule.matches(other, fingerprint_finding(other))
    # Different rule token -> no match.
    anomaly = _finding(title="Anomalous embeddings in 'kb'")
    assert not rule.matches(anomaly, fingerprint_finding(anomaly))


def test_allowlist_matches_by_fingerprint():
    f = _finding()
    fp = fingerprint_finding(f)
    rule = AllowlistRule(id="r2", reason="accepted", fingerprints=(fp,))
    assert rule.matches(f, fp)
    other = _finding(store="s2")
    assert not rule.matches(other, fingerprint_finding(other))


def test_allowlist_matches_by_value_pattern():
    rule = AllowlistRule(id="r3", reason="synthetic",
                         value_patterns=(r"AKIAIOSFODNN7EXAMPLE",))
    hit = _finding(category="data_classification",
                   evidence={"examples": [{"preview": "key AKIAIOSFODNN7EXAMPLE here"}]})
    assert rule.matches(hit, fingerprint_finding(hit))
    miss = _finding(category="data_classification",
                    evidence={"examples": [{"preview": "no secret"}]})
    assert not rule.matches(miss, fingerprint_finding(miss))


def test_allowlist_roundtrip():
    rule = AllowlistRule(id="r", reason="x", category="cve",
                         value_patterns=("foo",), owner="alice")
    assert AllowlistRule.from_dict(rule.to_dict()).to_dict() == rule.to_dict()


# --------------------------------------------------------------------------- #
# Suppression + validation                                                     #
# --------------------------------------------------------------------------- #

def test_suppression_is_active_respects_expiry():
    s = Suppression(fingerprint="fp-1", reason="r", owner="o",
                    expires_at=_future(10))
    assert s.is_active(NOW)
    assert not s.is_active(NOW + timedelta(days=11))


def test_validate_suppression_requires_fields():
    with pytest.raises(SuppressionError):
        validate_suppression(Suppression(fingerprint="", reason="r", owner="o",
                                         expires_at=_future(5)), now=NOW)
    with pytest.raises(SuppressionError):
        validate_suppression(Suppression(fingerprint="fp", reason="", owner="o",
                                         expires_at=_future(5)), now=NOW)
    with pytest.raises(SuppressionError):
        validate_suppression(Suppression(fingerprint="fp", reason="r", owner="",
                                         expires_at=_future(5)), now=NOW)


def test_validate_suppression_rejects_past_and_too_long():
    with pytest.raises(SuppressionError):
        validate_suppression(Suppression(fingerprint="fp", reason="r", owner="o",
                                         expires_at=_future(-1)), now=NOW)
    with pytest.raises(SuppressionError):
        validate_suppression(Suppression(fingerprint="fp", reason="r", owner="o",
                                         expires_at=_future(400)), now=NOW)


def test_validate_suppression_sensitive_ttl_cap():
    supp = Suppression(fingerprint="fp", reason="r", owner="o",
                       expires_at=_future(60))
    # 60d is fine for a non-sensitive MEDIUM finding...
    validate_suppression(supp, category="rag_integrity",
                         severity=Severity.MEDIUM, now=NOW)
    # ...but not for a CRITICAL (sensitive) one.
    with pytest.raises(SuppressionError):
        validate_suppression(supp, category="data_classification",
                             severity=Severity.CRITICAL, now=NOW)


def test_is_sensitive_and_default_ttl():
    assert is_sensitive(severity=Severity.CRITICAL)
    assert is_sensitive(category="data_classification")
    assert not is_sensitive(category="cve", severity=Severity.LOW)
    assert default_ttl_days(Severity.CRITICAL) < default_ttl_days(Severity.LOW)


def test_suppression_roundtrip():
    s = Suppression(fingerprint="fp", reason="r", owner="o",
                    expires_at=_future(5), ticket="JIRA-1")
    assert Suppression.from_dict(s.to_dict()).to_dict() == s.to_dict()


# --------------------------------------------------------------------------- #
# evaluate_suppressions                                                        #
# --------------------------------------------------------------------------- #

def test_evaluate_suppresses_by_fingerprint_and_tags():
    f = _finding()
    fp = fingerprint_finding(f)
    supp = Suppression(fingerprint=fp, reason="accepted risk", owner="sec",
                       expires_at=_future(10))
    res = evaluate_suppressions([f], suppressions=[supp], now=NOW)
    assert res.suppressed == [f] and res.active == []
    assert f.evidence["suppressed"] is True
    assert f.evidence["suppression"]["source"] == "suppression"
    assert f.evidence["suppression"]["owner"] == "sec"


def test_evaluate_expired_suppression_does_not_apply():
    f = _finding()
    supp = Suppression(fingerprint=fingerprint_finding(f), reason="r", owner="o",
                       expires_at=_future(-1))
    res = evaluate_suppressions([f], suppressions=[supp], now=NOW)
    assert res.active == [f]
    assert f.evidence["suppressed"] is False
    assert "suppression" not in f.evidence


def test_evaluate_suppresses_by_allowlist():
    f = _finding(title="Prompt-injection content in 'kb'")
    rule = AllowlistRule(id="r", reason="research corpus",
                         category="rag_integrity", collection="kb")
    res = evaluate_suppressions([f], allowlist=[rule], now=NOW)
    assert res.suppressed == [f]
    assert f.evidence["suppression"]["source"] == "allowlist"


def test_evaluate_reports_over_suppression():
    findings = [_finding(id=f"f{i}", collection="kb") for i in range(4)]
    rule = AllowlistRule(id="r", reason="broad", category="rag_integrity")
    res = evaluate_suppressions(findings, allowlist=[rule], now=NOW,
                                over_threshold=0.5)
    assert res.coverage["rag_integrity"] == 1.0
    assert "rag_integrity" in res.over_suppressed


def test_evaluate_no_rules_keeps_all_active():
    findings = [_finding(id="a"), _finding(id="b", category="cve",
                                           store="deps", collection=None)]
    res = evaluate_suppressions(findings, now=NOW)
    assert len(res.active) == 2 and not res.suppressed
    assert all(f.evidence["suppressed"] is False for f in findings)


# --------------------------------------------------------------------------- #
# Built-in safe defaults                                                       #
# --------------------------------------------------------------------------- #

def test_builtin_allowlist_suppresses_synthetic_pan():
    f = _finding(category="data_classification", collection="c",
                 title="Sensitive data in 'c'",
                 evidence={"examples": [{"preview": "card 4111 1111 1111 1111"}]})
    res = evaluate_suppressions([f], allowlist=builtin_allowlist(), now=NOW)
    assert res.suppressed == [f]
    assert res.suppressed[0].evidence["suppression"]["origin"] == "builtin"


def test_builtin_allowlist_ignores_real_looking_value():
    f = _finding(category="data_classification", collection="c",
                 title="Sensitive data in 'c'",
                 evidence={"examples": [{"preview": "card 4242 4242 4242 4242"}]})
    res = evaluate_suppressions([f], allowlist=builtin_allowlist(), now=NOW)
    assert res.active == [f]
