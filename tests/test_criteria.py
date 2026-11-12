"""Missing evidence never becomes a pass, and only a reviewer concludes."""

from __future__ import annotations

import pytest

from vecshield_platform.compliance.criteria import (
    ADDRESSABLE_DETERMINATION,
    KNOWN_PACK_VERSIONS,
    PACK_VERSION,
    Criterion,
    ReviewerDecision,
    evaluate_criterion,
    evaluate_pack,
    summarize_pack,
)
from vecshield_platform.compliance.packs import (
    CRITERIA,
    HIPAA_NOT_COVERED,
    criteria_for,
    get_criterion,
    hipaa_pack_manifest,
    pack_manifest,
    resolve_criterion_id,
)
from vecshield_platform.coverage import check_outcome

CRITERION = Criterion(
    id="TEST-01", framework="HIPAA", paraphrase="Access is limited.",
    source_ids=["hipaa-164-312-a-1"], technical_checks=["tenant_isolation"],
    manual_evidence=["access_review_record"],
    applicability_questions=["system_handles_ephi"],
    limitations=["A probe samples."])

APPLIES = {"system_handles_ephi": "yes"}
EVIDENCE = {"access_review_record": "accepted"}
PASSED = [check_outcome("tenant_isolation", "s", "docs", outcome="passed", complete=True)]
REVIEWED = ReviewerDecision(reviewer="dpo@example.test", conclusion="satisfied",
                            rationale="Access review covers the period.",
                            decided_at="2026-09-17")


def test_unanswered_applicability_is_not_an_obligation_that_applies():
    result = evaluate_criterion(CRITERION, check_outcomes=PASSED, evidence=EVIDENCE)
    assert result.status == "not_assessed"
    assert result.applicability_status == "requires_confirmation"
    assert result.applicability == {"system_handles_ephi": "requires_confirmation"}


def test_everything_green_still_waits_for_a_reviewer():
    result = evaluate_criterion(CRITERION, check_outcomes=PASSED,
                                applicability_answers=APPLIES, evidence=EVIDENCE)
    assert result.status == "under_review"
    assert result.technical_result == "passed"
    assert result.evidence_sufficiency == "accepted"
    assert result.reviewer is None

    concluded = evaluate_criterion(CRITERION, check_outcomes=PASSED,
                                   applicability_answers=APPLIES, evidence=EVIDENCE,
                                   reviewer_decision=REVIEWED)
    assert concluded.status == "satisfied_for_scope"
    assert concluded.reviewer["reviewer"] == "dpo@example.test"


def test_missing_evidence_is_not_a_pass_however_clean_the_scan():
    result = evaluate_criterion(CRITERION, check_outcomes=PASSED,
                                applicability_answers=APPLIES)
    assert result.status == "evidence_needed"
    assert result.missing_evidence == ["access_review_record"]
    assert result.evidence_sufficiency == "missing"


def test_a_check_that_never_ran_cannot_satisfy_a_criterion():
    for outcomes in ([], [check_outcome("tenant_isolation", "s", outcome="skipped",
                                        reason="No tenant field configured.")]):
        result = evaluate_criterion(CRITERION, check_outcomes=outcomes,
                                    applicability_answers=APPLIES, evidence=EVIDENCE)
        assert result.status == "evidence_needed"
        assert result.technical_result == "not_run"


def test_partial_coverage_is_inconclusive_not_satisfied():
    sampled = [check_outcome("tenant_isolation", "s", "docs", outcome="inconclusive",
                             reason="Only part of the collection was read.", sampled=True)]
    result = evaluate_criterion(CRITERION, check_outcomes=sampled,
                                applicability_answers=APPLIES, evidence=EVIDENCE,
                                reviewer_decision=REVIEWED)
    # A reviewer's sign-off does not upgrade coverage that was never achieved.
    assert result.status == "evidence_needed"
    assert result.technical_result == "inconclusive"
    assert result.technical_coverage == "partial"


def test_an_observed_failure_is_a_gap_without_waiting_for_review():
    failed = [check_outcome("tenant_isolation", "s", "docs", outcome="failed",
                            complete=True, reason="Cross-tenant bleed observed.")]
    result = evaluate_criterion(CRITERION, check_outcomes=failed,
                                applicability_answers=APPLIES, evidence=EVIDENCE)
    assert result.status == "gap_identified"
    assert result.gaps and result.observations[0]["outcome"] == "failed"


def test_scoping_out_a_criterion_requires_a_named_reviewer():
    answers = {"system_handles_ephi": "no"}
    pending = evaluate_criterion(CRITERION, applicability_answers=answers)
    assert pending.status == "not_assessed"
    assert pending.applicability_status == "excluded"

    decided = evaluate_criterion(
        CRITERION, applicability_answers=answers,
        reviewer_decision=ReviewerDecision(
            reviewer="ciso@example.test", conclusion="not_applicable",
            rationale="This store holds no ePHI.", decided_at="2026-09-17"))
    assert decided.status == "not_applicable"
    assert decided.reviewer["rationale"] == "This store holds no ePHI."


def test_a_reviewer_can_record_a_gap_over_a_clean_scan():
    result = evaluate_criterion(
        CRITERION, check_outcomes=PASSED, applicability_answers=APPLIES,
        evidence=EVIDENCE,
        reviewer_decision=ReviewerDecision(
            reviewer="auditor@example.test", conclusion="gap",
            rationale="Access reviews were not performed for Q2.",
            decided_at="2026-09-17"))
    assert result.status == "gap_identified"
    assert "Q2" in result.rationale


def test_rejected_evidence_is_distinguished_from_absent_evidence():
    rejected = evaluate_criterion(CRITERION, check_outcomes=PASSED,
                                  applicability_answers=APPLIES,
                                  evidence={"access_review_record": "rejected"})
    assert rejected.evidence_sufficiency == "rejected"
    assert rejected.status == "evidence_needed"
    submitted = evaluate_criterion(CRITERION, check_outcomes=PASSED,
                                   applicability_answers=APPLIES,
                                   evidence={"access_review_record": "submitted"})
    assert submitted.evidence_sufficiency == "submitted"
    assert submitted.status == "under_review"


def test_unknown_vocabularies_are_rejected_not_coerced():
    with pytest.raises(ValueError):
        evaluate_criterion(CRITERION, applicability_answers={"system_handles_ephi": "probably"})
    with pytest.raises(ValueError):
        evaluate_criterion(CRITERION, applicability_answers=APPLIES,
                           evidence={"access_review_record": "vibes"})


def test_shipped_pack_starts_unassessed_and_claims_no_review():
    manifest = pack_manifest()
    assert manifest["regulatory_review"] is None and manifest["lifecycle"] == "draft"
    assessments = evaluate_pack(CRITERIA)
    summary = summarize_pack(assessments)
    assert summary["by_status"]["not_assessed"] == len(CRITERIA)
    assert summary["awaiting_input"] == len(CRITERIA)
    assert "not a compliance score" in summary["note"]


#: Every check name the engine actually emits, with where it is emitted.
#: A criterion may not cite a check that is not in this set.
#: tests/test_crypto_posture_wiring.py runs the real engines and holds this
#: set to what they emit.
EMITTED_CHECKS = {
    # vecshield_platform/orchestrator.py. "configuration_posture" is only
    # the umbrella recorded when the posture audit is skipped or fails; no
    # criterion may rest on it.
    "training_data_classification", "chunk_boundary", "data_classification",
    "rag_integrity", "tenant_isolation",
    # vecshield_platform/scan/engine.py — read from the pass the scan already
    # makes. `query_result_ceiling` is deliberately absent: it raises no
    # finding and makes no control claim, so no criterion may rest on it.
    "retention_horizon", "embedding_consistency",
    # vecshield_platform/posture/engine.py
    "network_exposure", "transport_encryption", "authentication", "cve",
    "transport_tls_enforcement", "at_rest_encryption", "field_encryption",
    "access_grants", "server_hardening",
    # vecshield_platform/crypto (classification pass and opt-in probes)
    "data_representation", "pan_representation", "retrieval_exposure",
    "direct_identifier_exposure",
    # vecshield_platform/integrity/engine.py
    "prompt_injection", "embedding_anomaly", "provenance",
    # vecshield_platform/compliance/erasure.py
    "erasure_verification",
}


def test_every_shipped_criterion_names_sources_limits_and_real_checks():
    for criterion in CRITERIA:
        record = criterion.to_dict()
        assert record["sources"] and all(s["status"] != "unresolved"
                                         for s in record["sources"])
        assert criterion.limitations
        assert set(criterion.technical_checks) <= EMITTED_CHECKS, criterion.id
        # A criterion with no emitting check must say it is manual-evidence-only
        # rather than quietly citing nothing.
        assert criterion.technical_checks or criterion.manual_evidence_only, criterion.id
        if criterion.manual_evidence_only:
            assert criterion.manual_evidence, criterion.id
        assert criterion.applicability_questions or criterion.framework == "General"


def test_the_emitted_check_catalogue_matches_the_source_it_claims():
    """The allow-list above is only useful if it tracks the real emitters."""
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1] / "vecshield_platform"
    text = "\n".join((root / name).read_text() for name in
                      ("orchestrator.py", "integrity/engine.py",
                       "compliance/erasure.py", "posture/engine.py",
                       "crypto/states.py", "scan/engine.py"))
    for check in EMITTED_CHECKS:
        assert f'"{check}"' in text, f"{check} is not emitted anywhere"


def test_no_criterion_cites_a_source_id_that_does_not_resolve():
    for criterion in CRITERIA:
        assert criterion.source_ids, criterion.id
        for source in criterion.to_dict()["sources"]:
            assert source["title"] != "Unresolved source reference", (
                criterion.id, source["id"])
            assert source["status"] != "unresolved", (criterion.id, source["id"])
            assert source["issuer"] and source["section"] or source["edition"]


def test_pack_lookup_helpers():
    assert get_criterion("GDPR-ERASURE-01").framework == "GDPR"
    assert get_criterion("nope") is None
    assert {c.framework for c in criteria_for("hipaa")} == {"HIPAA"}
    assert criteria_for("Nonexistent") == []


def test_retired_hipaa_ids_still_resolve_to_the_criterion_that_absorbed_them():
    """Stored reviews and exceptions name criterion ids as plain strings."""
    retired_access = "HIPAA-SEC" + "-ACCESS-01"
    assert get_criterion(retired_access).id == "HIPAA-164-312-A1-ACCESS-CONTROL-01"
    assert get_criterion("HIPAA-SEC-EPHI-INVENTORY-01").id == "HIPAA-164-308-A1-RISK-01"
    assert resolve_criterion_id(retired_access) == "HIPAA-164-312-A1-ACCESS-CONTROL-01"
    assert resolve_criterion_id("HIPAA-164-312-B-AUDIT-01") == "HIPAA-164-312-B-AUDIT-01"
    assert resolve_criterion_id("never-existed") is None
    # The pack itself lists current ids only; the retired ones are a lookup
    # alias, not a second criterion.
    assert retired_access not in {c.id for c in CRITERIA}
    assert pack_manifest()["retired_criterion_ids"][retired_access] == (
        "HIPAA-164-312-A1-ACCESS-CONTROL-01")


def test_pack_version_moved_so_old_assessments_are_not_reread_as_new_ones():
    assert PACK_VERSION == "vecshield-vector-store-draft-4"
    assert "vecshield-vector-store-draft-3" in KNOWN_PACK_VERSIONS
    assert PACK_VERSION != KNOWN_PACK_VERSIONS[1]
    assert PACK_VERSION in KNOWN_PACK_VERSIONS
    assert all(c.pack_version == PACK_VERSION for c in CRITERIA)


def test_erasure_verification_becomes_a_structured_check_outcome():
    from vecshield_platform.compliance.erasure import (
        ErasureReport, ErasureVerification, erasure_check_outcome)

    complete = ErasureVerification(
        subject="jane@example.test", generated_at="2026-09-17", ok=True,
        remaining=ErasureReport(subject="jane@example.test",
                                generated_at="2026-09-17",
                                coverage_status="complete"))
    outcome = erasure_check_outcome(complete, store="s")
    assert outcome["check"] == "erasure_verification"
    assert outcome["outcome"] == "passed" and outcome["coverage"]["complete"] is True

    partial = ErasureVerification(
        subject="jane@example.test", generated_at="2026-09-17", ok=True,
        remaining=ErasureReport(subject="jane@example.test",
                                generated_at="2026-09-17",
                                coverage_status="partial"))
    degraded = erasure_check_outcome(partial, store="s")
    assert degraded["outcome"] == "inconclusive"
    assert degraded["coverage"]["complete"] is False
    assert "does not verify deletion" in degraded["reason"]


def api_client(tmp_path):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from vecshield_platform.api import create_app
    from vecshield_platform.api.registry import StoreRegistry
    from vecshield_platform.history import ScanHistory

    registry = StoreRegistry()
    registry.register("prod", "fake", factory=lambda: None)
    history = ScanHistory(tmp_path / "history.db")
    app = create_app(registry=registry, scan_history=history, serve_ui=False)
    return TestClient(app), history, app


def saved_audit(history, *, outcomes):
    from test_assessment_snapshots import audit_result

    result = audit_result()
    result.check_outcomes.extend(outcomes)
    history.save_audit(result, store_id="prod")
    return result.id


def test_criteria_endpoint_publishes_the_pack_and_its_limits(tmp_path):
    client, history, app = api_client(tmp_path)
    try:
        body = client.get("/compliance/criteria").json()
        assert body["pack"]["regulatory_review"] is None
        criterion = next(c for c in body["criteria"]
                         if c["criterion_id"] == "HIPAA-164-312-A1-ACCESS-CONTROL-01")
        assert criterion["sources"][0]["section"] == "45 CFR 164.312(a)(1)"
        assert criterion["aliases"] == ["HIPAA-SEC" + "-ACCESS-01"]
        assert criterion["specification"] == "standard"
        assert criterion["manual_evidence"] and criterion["limitations"]
        assert client.get("/compliance/criteria?framework=GDPR").json()["criteria"]
        assert client.get("/compliance/criteria?framework=NIST").status_code == 404
    finally:
        app.state.jobs.shutdown(wait=False)
        history.close()


def test_criteria_evaluation_reads_a_frozen_audit_and_needs_its_inputs(tmp_path):
    client, history, app = api_client(tmp_path)
    try:
        assert client.post("/stores/prod/criteria").status_code == 409
        audit_id = saved_audit(history, outcomes=[
            check_outcome("tenant_isolation", "fake://observed", "docs",
                          outcome="passed", complete=True),
            check_outcome("configuration_posture", "fake://observed",
                          outcome="passed", complete=True)])

        body = client.post("/stores/prod/criteria", json={"framework": "HIPAA"}).json()
        assert body["audit_id"] == audit_id
        access = next(a for a in body["assessments"]
                      if a["criterion_id"] == "HIPAA-164-312-A1-ACCESS-CONTROL-01")
        assert access["status"] == "not_assessed"

        answered = client.post("/stores/prod/criteria", json={
            "audit_id": audit_id, "framework": "HIPAA",
            "applicability": {"covered_entity_or_business_associate": "yes",
                              "system_handles_ephi": "yes"},
            "evidence": {"authorized_access_policy": "accepted",
                         "access_review_record": "accepted"},
        }).json()
        access = next(a for a in answered["assessments"]
                      if a["criterion_id"] == "HIPAA-164-312-A1-ACCESS-CONTROL-01")
        assert access["status"] == "under_review"
        # Two HIPAA criteria rest on exactly these two artifacts and these two
        # checks: technical access control, and access management. Both reach a
        # reviewer; neither concludes without one.
        assert answered["summary"]["by_status"]["under_review"] == 2
        assert {a["criterion_id"] for a in answered["assessments"]
                if a["status"] == "under_review"} == {
            "HIPAA-164-312-A1-ACCESS-CONTROL-01",
            "HIPAA-164-308-A4-ACCESS-MGMT-01"}

        concluded = client.post("/stores/prod/criteria", json={
            "audit_id": audit_id, "framework": "HIPAA",
            "applicability": {"covered_entity_or_business_associate": "yes",
                              "system_handles_ephi": "yes"},
            "evidence": {"authorized_access_policy": "accepted",
                         "access_review_record": "accepted"},
            "reviewer_decisions": {"HIPAA-164-312-A1-ACCESS-CONTROL-01": {
                "reviewer": "dpo@example.test", "conclusion": "satisfied",
                "rationale": "Reviewed for Q3.", "decided_at": "2026-09-17"}},
        }).json()
        access = next(a for a in concluded["assessments"]
                      if a["criterion_id"] == "HIPAA-164-312-A1-ACCESS-CONTROL-01")
        assert access["status"] == "satisfied_for_scope"
        assert access["reviewer"]["reviewer"] == "dpo@example.test"
    finally:
        app.state.jobs.shutdown(wait=False)
        history.close()


def test_criteria_evaluation_rejects_bad_inputs_and_foreign_audits(tmp_path):
    client, history, app = api_client(tmp_path)
    try:
        audit_id = saved_audit(history, outcomes=[])
        assert client.post("/stores/prod/criteria",
                           json={"audit_id": "missing"}).status_code == 404
        assert client.post("/stores/prod/criteria", json={
            "applicability": {"system_handles_ephi": "maybe"}}).status_code == 422
        assert client.post("/stores/prod/criteria", json={
            "audit_id": audit_id,
            "reviewer_decisions": {"HIPAA-164-312-A1-ACCESS-CONTROL-01": {"reviewer": "x"}},
        }).status_code == 422
        assert client.post("/stores/nope/criteria").status_code == 404
    finally:
        app.state.jobs.shutdown(wait=False)
        history.close()


# ---------------------------------------------------------------------------
# Addressable implementation specifications (45 CFR 164.306(d))
# ---------------------------------------------------------------------------

ADDRESSABLE = Criterion(
    id="TEST-ADDRESSABLE-01", framework="HIPAA",
    specification="addressable", specification_basis="45 CFR 164.306(d)",
    paraphrase="ePHI at rest is encrypted.",
    source_ids=["hipaa-164-312-a-2-iv", "hipaa-164-306-d"],
    technical_checks=["configuration_posture"],
    manual_evidence=["encryption_at_rest_statement"],
    applicability_questions=["system_handles_ephi"],
    limitations=["Posture reads the endpoint, not the disk."])

REQUIRED = Criterion(
    id="TEST-REQUIRED-01", framework="HIPAA",
    specification="required", specification_basis="45 CFR 164.306(d)",
    paraphrase="ePHI is disposed of when no longer needed.",
    source_ids=["hipaa-164-310-d-2-i"],
    technical_checks=["configuration_posture"],
    manual_evidence=["encryption_at_rest_statement"],
    applicability_questions=["system_handles_ephi"],
    limitations=["Live index only."])

FAILED_POSTURE = [check_outcome("configuration_posture", "s", outcome="failed",
                                complete=True)]
PASSED_POSTURE = [check_outcome("configuration_posture", "s", outcome="passed",
                                complete=True)]
SUPPLIED = {"encryption_at_rest_statement": "accepted"}
DETERMINED = dict(SUPPLIED, **{ADDRESSABLE_DETERMINATION: "accepted"})


def test_addressable_control_missing_and_undocumented_is_a_gap_naming_306d():
    result = evaluate_criterion(
        ADDRESSABLE, check_outcomes=FAILED_POSTURE,
        applicability_answers={"system_handles_ephi": "yes"}, evidence=SUPPLIED)
    assert result.status == "gap_identified"
    assert result.specification == "addressable"
    assert result.addressable_determination == "missing"
    assert "164.306(d)" in result.rationale
    assert "not mean optional" in result.rationale
    assert result.gaps


def test_addressable_control_missing_but_determined_reads_as_assessed():
    result = evaluate_criterion(
        ADDRESSABLE, check_outcomes=FAILED_POSTURE,
        applicability_answers={"system_handles_ephi": "yes"}, evidence=DETERMINED)
    # Explained, not excused: it still goes to a reviewer, and the observation
    # is still recorded.
    assert result.status == "under_review"
    assert result.addressable_determination == "accepted"
    assert result.technical_result == "failed"
    assert any("addressable" in g for g in result.gaps)
    assert "equivalent" in result.rationale

    concluded = evaluate_criterion(
        ADDRESSABLE, check_outcomes=FAILED_POSTURE,
        applicability_answers={"system_handles_ephi": "yes"}, evidence=DETERMINED,
        reviewer_decision=REVIEWED)
    assert concluded.status == "satisfied_for_scope"


def test_addressable_with_no_check_result_says_what_is_missing():
    result = evaluate_criterion(
        ADDRESSABLE, applicability_answers={"system_handles_ephi": "yes"},
        evidence=SUPPLIED)
    assert result.status == "evidence_needed"
    assert "164.306(d)" in result.rationale

    determined = evaluate_criterion(
        ADDRESSABLE, applicability_answers={"system_handles_ephi": "yes"},
        evidence=DETERMINED)
    assert determined.status == "under_review"


def test_a_determination_cannot_excuse_a_required_specification():
    """Only addressable specifications read a determination. Required ones do not."""
    result = evaluate_criterion(
        REQUIRED, check_outcomes=FAILED_POSTURE,
        applicability_answers={"system_handles_ephi": "yes"}, evidence=DETERMINED)
    assert result.status == "gap_identified"
    assert result.addressable_determination is None
    assert "164.306(d)" not in result.rationale


def test_specification_none_behaves_exactly_as_before():
    """The original criterion has no specification; nothing about it changes."""
    assert CRITERION.specification is None
    failed = [check_outcome("tenant_isolation", "s", "docs", outcome="failed",
                            complete=True)]
    result = evaluate_criterion(
        CRITERION, check_outcomes=failed, applicability_answers=APPLIES,
        evidence=dict(EVIDENCE, **{ADDRESSABLE_DETERMINATION: "accepted"}))
    assert result.status == "gap_identified"
    assert result.addressable_determination is None
    assert result.rationale == ("A check for this criterion failed within the "
                                "observed scope.")
    assert result.gaps == ["A technical check for this criterion observed a failure."]


def test_a_criterion_must_either_name_a_check_or_declare_itself_manual():
    with pytest.raises(ValueError):
        Criterion(id="X", framework="HIPAA", paraphrase="p",
                  source_ids=["hipaa-164-312-b"])
    with pytest.raises(ValueError):
        Criterion(id="X", framework="HIPAA", paraphrase="p",
                  source_ids=["hipaa-164-312-b"], manual_evidence_only=True,
                  manual_evidence=["x"], technical_checks=["data_classification"])
    with pytest.raises(ValueError):
        Criterion(id="X", framework="HIPAA", paraphrase="p",
                  source_ids=["hipaa-164-312-b"], manual_evidence_only=True)
    with pytest.raises(ValueError):
        Criterion(id="X", framework="HIPAA", paraphrase="p",
                  source_ids=["hipaa-164-312-b"],
                  technical_checks=["data_classification"],
                  specification="mandatory-ish")


def test_a_manual_evidence_only_criterion_is_not_stuck_on_missing_coverage():
    audit = get_criterion("HIPAA-164-312-B-AUDIT-01")
    assert audit.manual_evidence_only and not audit.technical_checks
    applies = {"covered_entity_or_business_associate": "yes",
               "system_handles_ephi": "yes"}
    evidence = {name: "accepted" for name in audit.manual_evidence}

    waiting = evaluate_criterion(audit, applicability_answers=applies,
                                 evidence=evidence)
    assert waiting.status == "under_review"
    assert waiting.technical_coverage == "not_applicable"
    assert "No check in this product observes this obligation" in waiting.rationale

    # Missing artifacts still block it, and a reviewer still decides.
    assert evaluate_criterion(audit, applicability_answers=applies,
                              evidence={}).status == "evidence_needed"
    assert evaluate_criterion(audit, applicability_answers=applies,
                              evidence=evidence,
                              reviewer_decision=REVIEWED
                              ).status == "satisfied_for_scope"


# ---------------------------------------------------------------------------
# The HIPAA pack's shape and its stated coverage boundary
# ---------------------------------------------------------------------------

EXPECTED_HIPAA_IDS = [
    "HIPAA-164-308-A1-RISK-01",
    "HIPAA-164-308-A4-ACCESS-MGMT-01",
    "HIPAA-164-308-A6-INCIDENT-01",
    "HIPAA-164-308-A8-EVALUATION-01",
    "HIPAA-164-308-B1-BAA-01",
    "HIPAA-164-310-D2-DISPOSAL-01",
    "HIPAA-164-312-A1-ACCESS-CONTROL-01",
    "HIPAA-164-312-A2IV-ENCRYPTION-01",
    "HIPAA-164-312-B-AUDIT-01",
    "HIPAA-164-312-C1-INTEGRITY-01",
    "HIPAA-164-312-D-AUTHN-01",
    "HIPAA-164-312-E1-TRANSMISSION-01",
    "HIPAA-164-312-E2II-ENCRYPTION-01",
    "HIPAA-164-316-B1-DOCUMENTATION-01",
    "HIPAA-164-502-B-MIN-NECESSARY-01",
    "HIPAA-164-514-B-DEIDENT-01",
    "HIPAA-164-524-ACCESS-01",
    "HIPAA-164-402-BREACH-ASSESS-01",
]


def test_the_hipaa_criterion_ids_are_the_published_set():
    """Demo scenarios and docs are written against this list."""
    assert sorted(c.id for c in criteria_for("HIPAA")) == sorted(EXPECTED_HIPAA_IDS)


def test_every_hipaa_criterion_records_how_its_obligation_is_written():
    for criterion in criteria_for("HIPAA"):
        if criterion.id == "HIPAA-164-402-BREACH-ASSESS-01":
            # §164.402 is a definitions section, not a standard.
            assert criterion.specification is None
            continue
        assert criterion.specification in ("standard", "required", "addressable"), (
            criterion.id)
        # Security Rule criteria cite the provision that draws the line;
        # Privacy and Breach Rule ones do not, because it does not reach them.
        if criterion.specification == "addressable":
            assert criterion.specification_basis == "45 CFR 164.306(d)", criterion.id
            assert "hipaa-164-306-d" in criterion.source_ids, criterion.id


def test_the_hipaa_manifest_says_what_it_does_not_cover():
    manifest = hipaa_pack_manifest()
    assert manifest["regulatory_review"] is None and manifest["lifecycle"] == "draft"
    assert manifest["criteria"] == len(EXPECTED_HIPAA_IDS)
    assert manifest["by_specification"]["addressable"] == [
        "HIPAA-164-308-A4-ACCESS-MGMT-01", "HIPAA-164-312-A2IV-ENCRYPTION-01",
        "HIPAA-164-312-E2II-ENCRYPTION-01"]
    topics = " ".join(e["topic"] + e["reason"] for e in manifest["not_covered"])
    for absent in ("clearance", "Physical", "Contingency", "60-day",
                   "Sanction", "training", "Accounting of disclosures"):
        assert absent in topics, absent
    assert "164.410" in " ".join(e["section"] for e in manifest["not_covered"])
    # §164.528 is named as out of scope rather than shipped as a criterion
    # nothing observes.
    assert not any("528" in c.id for c in criteria_for("HIPAA"))
    assert "164.528" in " ".join(e["section"] for e in HIPAA_NOT_COVERED)


def test_the_hipaa_manifest_reports_no_score_and_no_percentage():
    import json

    blob = json.dumps(hipaa_pack_manifest([{"store_id": "s", "kind": "pinecone"}]))
    assert "%" not in blob
    assert "score" not in blob.lower()
    assert "percent" not in blob.lower()


def test_the_baa_criterion_is_grounded_in_the_connector_estate():
    manifest = hipaa_pack_manifest([
        {"store_id": "clinical-rag", "kind": "pinecone"},
        {"store_id": "notes-index", "kind": "azure_search"},
        {"store_id": "self-hosted", "kind": "qdrant"},
        {"store_id": "mystery", "kind": "not-a-connector"},
    ])
    exposure = manifest["business_associates"]
    assert exposure["vendors_requiring_a_baa"] == [
        "Microsoft (Azure AI Search)", "Pinecone"]
    assert [e["store_id"] for e in exposure["operator_not_established"]] == [
        "self-hosted"]
    assert [e["store_id"] for e in exposure["unrecognised_kinds"]] == ["mystery"]
    # No estate supplied means no claim about vendors at all.
    assert "business_associates" not in hipaa_pack_manifest()


def test_evidence_filed_under_a_retired_criterion_id_is_not_orphaned(tmp_path):
    """The console demo seeded reviews and an exception under the old ids."""
    from vecshield_platform.evidence import (
        EvidenceArtifact, EvidenceReview, RiskException,
        transition_artifact, transition_review)

    client, history, app = api_client(tmp_path)
    retired = "HIPAA-SEC" + "-ACCESS-01"
    current = "HIPAA-164-312-A1-ACCESS-CONTROL-01"
    try:
        audit_id = saved_audit(history, outcomes=[
            check_outcome("tenant_isolation", "fake://observed", "docs",
                          outcome="passed", complete=True),
            check_outcome("configuration_posture", "fake://observed",
                          outcome="passed", complete=True)])
        for artifact_id, requirement in (("ev-policy", "authorized_access_policy"),
                                         ("ev-review", "access_review_record")):
            artifact = EvidenceArtifact(
                id=artifact_id, title=requirement, content_hash="0" * 64,
                collected_at="2026-09-01", scope="prod",
                period_start="2026-07-01", period_end="2026-09-30")
            for state in ("integrity_checked", "available"):
                artifact = transition_artifact(artifact, to_state=state,
                                               actor="demo@example.test")
            history.save_artifact(artifact)
            review = EvidenceReview(id=f"rev-{artifact_id}", artifact_id=artifact_id,
                                    criterion_id=retired, requirement=requirement,
                                    scope="prod", period="2026-Q3")
            review = transition_review(review, to_state="submitted",
                                       reviewer="demo@example.test")
            review = transition_review(review, to_state="accepted",
                                       reviewer="dpo@example.test",
                                       reason="Covers the period.")
            history.save_review(review)
        history.save_exception(RiskException(
            id="exc-old", criterion_id=retired, scope="prod",
            rationale="Interim cover.", requested_by="alex@example.test",
            expires_at="2027-01-01"))

        body = client.post("/stores/prod/criteria", json={
            "audit_id": audit_id, "framework": "HIPAA",
            "applicability": {"covered_entity_or_business_associate": "yes",
                              "system_handles_ephi": "yes"}}).json()
        access = next(a for a in body["assessments"]
                      if a["criterion_id"] == current)
        # The reviews filed under the retired id still satisfy the artifacts,
        # and the exception still attaches.
        assert access["evidence_sufficiency"] == "accepted"
        assert access["status"] == "under_review"
        assert {r["criterion_id"] for r in access["evidence_reviews"]} == {current}
        # Asserted as a set: /stores/{id}/criteria fetches exceptions twice
        # (scope=store_id plus scope=""), and the empty scope is falsy so the
        # second call filters nothing and returns everything. That duplication
        # is a pre-existing bug in this endpoint, unrelated to the retired id.
        assert {e["id"] for e in access["exceptions"]} == {"exc-old"}
    finally:
        app.state.jobs.shutdown(wait=False)
        history.close()
