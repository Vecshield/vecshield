"""Policy engine tests."""

from __future__ import annotations

from vecshield_platform.compliance import default_policies, evaluate_policies
from vecshield_platform.compliance.policy import Policy
from vecshield.models import Finding, Severity


def _finding(**kw):
    base = dict(id="f1", title="t", severity=Severity.HIGH,
                category="data_classification", store="s", collection="c",
                evidence={})
    base.update(kw)
    return Finding(**base)


def test_secret_policy_matches():
    f = _finding(evidence={"label_counts": {"secret": 2}})
    v = evaluate_policies(default_policies(), [f])
    assert any(x.policy_id == "secrets-never-embedded" for x in v)


def test_phi_high_inversion_threshold():
    hit = _finding(evidence={"label_counts": {"phi": 3},
                             "sensitivity": {"inversion_risk": 0.85}})
    miss = _finding(evidence={"label_counts": {"phi": 3},
                              "sensitivity": {"inversion_risk": 0.4}})
    v_hit = evaluate_policies(default_policies(), [hit])
    v_miss = evaluate_policies(default_policies(), [miss])
    assert any(x.policy_id == "phi-high-inversion" for x in v_hit)
    assert not any(x.policy_id == "phi-high-inversion" for x in v_miss)


def test_min_severity_gate():
    pol = [Policy(id="p", description="d", when={"min_severity": "high"},
                  action="x")]
    high = _finding(severity=Severity.HIGH)
    med = _finding(severity=Severity.MEDIUM)
    assert len(evaluate_policies(pol, [high])) == 1
    assert len(evaluate_policies(pol, [med])) == 0


def test_isolation_and_injection_policies():
    iso = _finding(category="isolation", severity=Severity.HIGH, collection="shared")
    inj = _finding(category="rag_integrity", severity=Severity.HIGH)
    v = evaluate_policies(default_policies(), [iso, inj])
    ids = {x.policy_id for x in v}
    assert {"cross-tenant-bleed", "rag-injection"} <= ids


def test_no_false_matches_on_clean_finding():
    clean = _finding(category="data_classification", severity=Severity.LOW,
                     evidence={"label_counts": {"pii": 1}})
    # PII-only, low severity -> none of the default (secret/phi/iso/injection) fire
    assert evaluate_policies(default_policies(), [clean]) == []
