"""Policies over the store-control findings fire on what the producers emit.

Where it is cheap, the findings come from the real producer (retention
schedule, biometric classifier); otherwise they are built with the producer's
own category constant and the evidence field it writes, so a renamed field
breaks this test rather than silently disarming a policy.
"""

from __future__ import annotations

from datetime import datetime, timezone

from vecshield.models import Collection, Finding, Severity
from vecshield_platform.compliance.policy import default_policies, evaluate_policies
from vecshield_platform.posture.policy import posture_policies

NOW = datetime(2026, 9, 29, tzinfo=timezone.utc)


def _fired(policies, findings):
    return {(v.policy_id, v.action) for v in evaluate_policies(policies, findings)}


def _finding(category, severity, **evidence):
    return Finding(id=f"f-{category}-{severity.value}", title="t", severity=severity,
                   category=category, store="s", collection="c", evidence=evidence)


def _record(chunk_id, *, labels=(), **metadata):
    return {"chunk_id": chunk_id, "labels": set(labels), "detectors": set(),
            "qualifiers": set(), "metadata": metadata}


# ---- retention schedule ----------------------------------------------------

def test_card_data_older_than_the_declared_maximum_asks_for_a_purge():
    from vecshield_platform.scan.retention_schedule import (
        evaluate_retention_schedule, retention_schedule_findings)

    records = [_record("old", labels={"pci"}, created_at="2023-01-01T00:00:00Z"),
               _record("new", labels={"pci"}, created_at="2026-09-01T00:00:00Z")]
    result = evaluate_retention_schedule(
        records, {"rules": [{"category": "pci", "max_age_days": 365,
                             "basis": "Card data policy"}]},
        collection="c", now=NOW)
    findings = retention_schedule_findings("s", "c", result)
    assert findings and findings[0].severity == Severity.HIGH
    assert ("retention-sensitive-over-max", "purge_expired_records") in _fired(
        default_policies(), findings)


def test_low_sensitivity_over_retention_does_not_ask_for_a_purge():
    finding = _finding("retention_schedule", Severity.LOW)
    assert not {p for p, _ in _fired(default_policies(), [finding])
                if p == "retention-sensitive-over-max"}


# ---- biometric templates ---------------------------------------------------

def test_confirmed_face_templates_ask_for_a_review_and_possible_ones_do_not():
    from vecshield_platform.scan.biometric import (
        biometric_findings, detect_biometric_collection)

    confirmed = detect_biometric_collection(
        Collection(name="faces", count=100, dimension=512,
                   embedding_model="insightface/buffalo_l", metadata={}), [])
    findings = biometric_findings("s", "faces", confirmed)
    assert ("biometric-templates-reviewed", "review_biometric_obligations") in _fired(
        default_policies(), findings)

    possible = _finding("biometric_templates", Severity.MEDIUM)
    assert not _fired(default_policies(), [possible])


# ---- superseded versions and poisoning patterns ----------------------------

def test_superseded_sensitive_versions_ask_for_a_purge():
    high = _finding("chunk_versions", Severity.HIGH, sensitive_superseded_chunks=2)
    medium = _finding("chunk_versions", Severity.MEDIUM, sensitive_superseded_chunks=0)
    fired = _fired(default_policies(), [high, medium])
    assert ("superseded-sensitive-chunks", "purge_superseded_chunks") in fired
    assert len([v for v in evaluate_policies(default_policies(), [medium])
                if v.policy_id == "superseded-sensitive-chunks"]) == 0


def test_only_corroborated_poisoning_patterns_ask_for_quarantine():
    corroborated = [_finding("corpus_duplication", Severity.MEDIUM),
                    _finding("retrieval_hubness", Severity.MEDIUM)]
    plain = [_finding("corpus_duplication", Severity.LOW),
             _finding("retrieval_hubness", Severity.LOW),
             _finding("retrieval_hubness", Severity.INFO)]
    violations = [v for v in evaluate_policies(default_policies(), corroborated)
                  if v.policy_id == "poisoning-signals-review"]
    assert len(violations) == 2
    assert {v.action for v in violations} == {"quarantine_chunks"}
    assert not [v for v in evaluate_policies(default_policies(), plain)
                if v.policy_id == "poisoning-signals-review"]


# ---- server vulnerabilities and support status -----------------------------

def test_critical_or_known_exploited_server_vulnerabilities_ask_for_a_patch():
    from vecshield_platform.posture.server_vulns import SERVER_VULNERABILITY

    critical = _finding(SERVER_VULNERABILITY, Severity.CRITICAL, known_exploited=False)
    kev_medium = _finding(SERVER_VULNERABILITY, Severity.MEDIUM, known_exploited=True)
    plain_medium = _finding(SERVER_VULNERABILITY, Severity.MEDIUM, known_exploited=False)
    managed_info = _finding(SERVER_VULNERABILITY, Severity.INFO, managed=True)

    fired = {v.policy_id: v for v in evaluate_policies(posture_policies(), [critical])}
    assert fired["no-critical-server-vulnerabilities"].action == "patch_server"

    kev = [v for v in evaluate_policies(posture_policies(), [kev_medium])]
    assert [(v.policy_id, v.severity) for v in kev] == [
        ("no-known-exploited-server-vulnerabilities", Severity.CRITICAL)]
    assert not evaluate_policies(posture_policies(), [plain_medium, managed_info])


def test_the_kev_policy_reads_the_field_the_producer_writes():
    """server_vulns writes known_exploited on every matched advisory finding."""
    import inspect

    from vecshield_platform.posture import server_vulns

    assert '"known_exploited": bool(kev)' in inspect.getsource(server_vulns._match_finding)


def test_an_end_of_life_release_asks_for_an_upgrade_and_a_warning_does_not():
    from vecshield_platform.posture.server_vulns import SERVER_SUPPORT_STATUS

    eol = _finding(SERVER_SUPPORT_STATUS, Severity.HIGH, status="eol")
    soon = _finding(SERVER_SUPPORT_STATUS, Severity.LOW, status="eol_within_90_days")
    assert ("server-release-supported", "upgrade_supported_release") in _fired(
        posture_policies(), [eol])
    assert not _fired(posture_policies(), [soon])


# ---- model egress and residency --------------------------------------------

def test_high_risk_model_egress_asks_to_declare_or_disable():
    from vecshield_platform.posture.egress import (
        CATEGORY, THIRD_PARTY, flow_severity)

    high, _ = flow_severity(["phi"], klass=THIRD_PARTY, baa_declared=False)
    medium, _ = flow_severity(["pii"], klass=THIRD_PARTY, baa_declared=False)
    assert high == Severity.HIGH and medium == Severity.MEDIUM
    assert ("model-egress-declared", "declare_processor_or_disable_module") in _fired(
        posture_policies(), [_finding(CATEGORY, high)])
    assert not _fired(posture_policies(), [_finding(CATEGORY, medium)])


def test_data_outside_residency_without_adequacy_asks_to_restrict_or_document():
    from vecshield_platform.posture.residency import CATEGORY

    assert ("data-within-residency-policy",
            "restrict_region_or_document_transfer") in _fired(
        posture_policies(), [_finding(CATEGORY, Severity.HIGH)])
    # Partial or conditional adequacy is MEDIUM: reported, not a violation.
    assert not _fired(posture_policies(), [_finding(CATEGORY, Severity.MEDIUM)])


def test_new_policies_are_serialisable_and_one_finding_at_a_time():
    import json

    for policy in default_policies() + posture_policies():
        json.dumps(policy.when)
    finding = _finding("chunk_versions", Severity.HIGH)
    assert len([v for v in evaluate_policies(default_policies(), [finding, finding])
                if v.policy_id == "superseded-sensitive-chunks"]) == 2


# ---- the evidence names producers ask for are explained --------------------

def test_every_evidence_name_a_producer_asks_for_is_in_the_vocabulary():
    from vecshield_platform.compliance.vocabulary import EVIDENCE_TYPES
    from vecshield_platform.posture import egress, residency

    asked = {egress.SUB_PROCESSOR_REGISTER, egress.DATA_PROCESSING_AGREEMENT,
             egress.BUSINESS_ASSOCIATE_AGREEMENT, "model_integration_configuration",
             residency.DATA_RESIDENCY_STATEMENT, residency.TRANSFER_MECHANISM,
             "residency_policy"}
    assert asked <= set(EVIDENCE_TYPES), sorted(asked - set(EVIDENCE_TYPES))
