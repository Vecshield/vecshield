"""A DPIA may not report an unmeasured safeguard as a safeguard in place."""

from __future__ import annotations

from vecshield.classify import RegexClassifier
from vecshield_platform.compliance import build_pia_html, generate_pia
from vecshield_platform.orchestrator import run_full_audit

from test_assessment_coverage import MemoryConnector, chunk


def safeguards(pia):
    return {item["control"]: item for item in pia.safeguards}


def test_skipped_checks_leave_safeguards_unassessed_not_satisfied():
    conn = MemoryConnector({"docs": [chunk(1)]})
    result = run_full_audit(conn, classifier=RegexClassifier(),
                            include_integrity=False, include_posture=False)
    pia = generate_pia(result)

    tls = safeguards(pia)["Encryption in transit (TLS)"]
    assert tls["status"] == "not assessed — review required"
    assert tls["open_findings"] == 0
    assert tls["assessed_by"] == "configuration_posture"
    assert tls["reason"]
    assert pia.assessment_complete is False
    assert "Tenant isolation" in pia.unassessed_safeguards
    # Nothing severe was observed, but nothing was measured either.
    assert pia.residual_risk == "unknown"
    assert pia.dpo_action_required is True


def test_partial_classification_does_not_conclude_no_personal_data():
    conn = MemoryConnector({"docs": [chunk(1), chunk(2)]})
    result = run_full_audit(conn, classifier=RegexClassifier(),
                            max_chunks_per_collection=1,
                            include_integrity=False, include_posture=False)
    pia = generate_pia(result)

    assert pia.data_categories == []
    assert "cannot be concluded" in pia.necessity
    assert pia.assessment_complete is False
    assert "Incomplete assessment" in build_pia_html(pia)


def test_observed_gap_outranks_coverage_language():
    conn = MemoryConnector({"docs": [chunk(1, text="Key: AKIAIOSFODNN7EXAMPLE")]},
                           query=True)
    result = run_full_audit(conn, classifier=RegexClassifier(),
                            tenant_field="tenant_id",
                            include_integrity=False, include_posture=False)
    isolation = safeguards(generate_pia(result))["Tenant isolation"]
    # Every chunk was read and none carries a tenant: the check is complete and
    # not applicable, and the row gives that reason rather than a bare pass.
    assert isolation["status"] == "in place / no gap detected"
    assert "isolation is not applicable" in isolation["reason"]
    # Read only in part, the same collection cannot be called either.
    conn.data["docs"].append(chunk(2))
    capped = run_full_audit(conn, classifier=RegexClassifier(), tenant_field="tenant_id",
                            include_integrity=False, include_posture=False,
                            max_chunks_per_collection=1)
    isolation = safeguards(generate_pia(capped))["Tenant isolation"]
    assert isolation["status"] == "partially assessed — review required"


def test_legacy_audit_without_outcomes_is_never_reported_as_clean():
    class LegacyAudit:
        store = "legacy"
        violations: list = []

        def all_findings(self):
            return []

    pia = generate_pia(LegacyAudit())
    assert {item["status"] for item in pia.safeguards} == {"not assessed — review required"}
    assert pia.residual_risk == "unknown"
    assert pia.assessment_complete is False
    assert "in place" not in build_pia_html(pia)
