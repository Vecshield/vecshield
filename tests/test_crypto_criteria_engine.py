"""Fallback evidence, risk-based measures, and the crypto regulatory basis."""

from __future__ import annotations

import pytest

from vecshield_platform.compliance.criteria import (
    RISK_DETERMINATION,
    Criterion,
    evaluate_criterion,
)
from vecshield_platform.compliance.crypto_basis import CRYPTO_BASIS, basis_for
from vecshield_platform.compliance.packs import CRITERIA, criteria_for, get_criterion
from vecshield_platform.coverage import check_outcome
from vecshield_platform.crypto import CRYPTO_CHECKS, crypto_outcome

APPLIES = {"q": "yes"}

FALLBACK = Criterion(
    id="TEST-FALLBACK-01", framework="HIPAA", specification="addressable",
    specification_basis="45 CFR 164.306(d)", paraphrase="At rest is encrypted.",
    source_ids=["hipaa-164-312-a-2-iv"], technical_checks=["at_rest_encryption"],
    fallback_evidence=["encryption_at_rest_statement"],
    applicability_questions=["q"], limitations=["x"])

RISK = Criterion(
    id="TEST-RISK-01", framework="GDPR", specification="risk_based",
    specification_basis="GDPR Art. 32(1)", paraphrase="Encrypted as appropriate.",
    source_ids=["gdpr-art-32-1-a"], technical_checks=["at_rest_encryption"],
    fallback_evidence=["encryption_risk_assessment"],
    applicability_questions=["q"], limitations=["x"])


def _at_rest(state, **kw):
    return [crypto_outcome("at_rest_encryption", "s", state=state, complete=True, **kw)]


def test_fallback_evidence_is_not_demanded_when_the_check_observes_the_property():
    result = evaluate_criterion(FALLBACK, check_outcomes=_at_rest("verified"),
                                applicability_answers=APPLIES)
    assert result.technical_result == "passed"
    assert result.evidence_sufficiency == "not_required"
    assert result.fallback_required == []
    assert result.status == "under_review"


def test_fallback_evidence_is_demanded_when_the_store_cannot_be_observed():
    result = evaluate_criterion(FALLBACK, check_outcomes=_at_rest("not_observable"),
                                applicability_answers=APPLIES)
    assert result.technical_result == "not_run"
    assert result.fallback_required == ["encryption_at_rest_statement"]
    assert result.missing_evidence == ["encryption_at_rest_statement"]
    assert result.status == "evidence_needed"


def test_not_observable_never_reads_as_a_gap():
    for evidence in ({}, {"encryption_at_rest_statement": "accepted"}):
        result = evaluate_criterion(FALLBACK, check_outcomes=_at_rest("not_observable"),
                                    applicability_answers=APPLIES, evidence=evidence)
        assert result.status != "gap_identified"
    accepted = evaluate_criterion(
        FALLBACK, check_outcomes=_at_rest("not_observable"),
        applicability_answers=APPLIES,
        evidence={"encryption_at_rest_statement": "accepted"})
    assert accepted.status == "under_review"
    assert "encryption_at_rest_statement" in accepted.rationale


def test_fallback_evidence_is_not_demanded_after_an_observed_failure():
    failed = [crypto_outcome("at_rest_encryption", "s", state="observed_exposure",
                             outcome="failed", complete=True)]
    result = evaluate_criterion(FALLBACK, check_outcomes=failed,
                                applicability_answers=APPLIES)
    assert result.status == "gap_identified"
    assert result.fallback_required == []


def test_manual_only_criteria_cannot_declare_fallback_evidence():
    with pytest.raises(ValueError, match="fall back"):
        Criterion(id="X", framework="HIPAA", paraphrase="p", source_ids=["a"],
                  manual_evidence_only=True, manual_evidence=["a"],
                  fallback_evidence=["b"])


def test_risk_based_failure_is_a_gap_until_a_risk_determination_is_accepted():
    failed = [crypto_outcome("at_rest_encryption", "s", state="observed_exposure",
                             outcome="failed", complete=True)]
    gap = evaluate_criterion(RISK, check_outcomes=failed, applicability_answers=APPLIES)
    assert gap.status == "gap_identified"
    assert gap.risk_determination == "missing"
    assert gap.addressable_determination is None
    assert "risk-based" in gap.rationale and "Art. 32(1)" in gap.rationale

    excused = evaluate_criterion(RISK, check_outcomes=failed,
                                 applicability_answers=APPLIES,
                                 evidence={RISK_DETERMINATION: "accepted"})
    assert excused.status == "under_review"
    assert excused.gaps and "risk-based measure" in excused.gaps[0]


def test_a_hipaa_determination_does_not_excuse_a_gdpr_measure():
    failed = [crypto_outcome("at_rest_encryption", "s", state="observed_exposure",
                             outcome="failed", complete=True)]
    result = evaluate_criterion(RISK, check_outcomes=failed,
                                applicability_answers=APPLIES,
                                evidence={"addressable_determination": "accepted"})
    assert result.status == "gap_identified"


# ---- crypto states ---------------------------------------------------------

def test_crypto_outcomes_map_states_onto_existing_outcomes():
    assert crypto_outcome("at_rest_encryption", "s", state="verified")["outcome"] == "passed"
    assert crypto_outcome("at_rest_encryption", "s",
                          state="not_observable")["outcome"] == "unsupported"
    na = crypto_outcome("pan_representation", "s", state="not_applicable")
    assert na["outcome"] == "passed"
    assert na["coverage"]["crypto_state"] == "not_applicable"
    assert na["coverage"]["control"] == "VCR-06"
    with pytest.raises(ValueError, match="explicit outcome"):
        crypto_outcome("data_representation", "s", state="observed_exposure")
    with pytest.raises(ValueError, match="cannot fail"):
        crypto_outcome("at_rest_encryption", "s", state="not_observable",
                       outcome="failed")


# ---- the regulatory basis is a ceiling -------------------------------------

def test_every_framework_in_the_pack_has_a_crypto_basis_row():
    assert {row.framework for row in CRYPTO_BASIS} == {c.framework for c in CRITERIA}


def test_basis_rows_name_real_criteria_that_cite_crypto_checks():
    for row in CRYPTO_BASIS:
        for criterion_id in row.criteria:
            criterion = get_criterion(criterion_id)
            assert criterion is not None, criterion_id
            assert criterion.framework == row.framework
            assert set(criterion.technical_checks) & set(CRYPTO_CHECKS), criterion_id


def test_the_eu_ai_act_is_supporting_evidence_only():
    row = basis_for("EU AI Act")
    assert row.relationship == "supporting" and not row.criteria
    for criterion in criteria_for("EU AI Act"):
        assert not set(criterion.technical_checks) & set(CRYPTO_CHECKS), criterion.id


def test_criterion_semantics_follow_the_basis_table():
    expected = {"HIPAA": {"addressable"}, "GDPR": {"risk_based"},
                # § 7123 names encryption as an audit component, not a duty
                # to encrypt, so the criterion carries no specification kind.
                "SOC 2": {"risk_based"}, "CCPA/CPRA": {None},
                "PCI-DSS": {None}}
    for row in CRYPTO_BASIS:
        kinds = {get_criterion(cid).specification for cid in row.criteria}
        assert kinds <= expected.get(row.framework, set()), (row.framework, kinds)


def test_pci_storage_is_never_satisfied_by_storage_encryption():
    storage = get_criterion("PCI-DSS-3-STORAGE-01")
    assert "pan_representation" in storage.technical_checks
    assert "at_rest_encryption" not in storage.technical_checks


def test_no_criterion_rests_on_the_posture_umbrella_name():
    for criterion in CRITERIA:
        assert "configuration_posture" not in criterion.technical_checks, criterion.id


def test_ccpa_encryption_is_gated_on_the_cybersecurity_audit():
    criterion = get_criterion("CCPA-CYBERAUDIT-ENCRYPTION-01")
    assert "subject_to_cppa_cybersecurity_audit" in criterion.applicability_questions
    plaintext = [check_outcome("transport_encryption", "s", outcome="failed",
                               complete=True)]
    excluded = evaluate_criterion(
        criterion, check_outcomes=plaintext,
        applicability_answers={"business_subject_to_ccpa": "yes",
                               "subject_to_cppa_cybersecurity_audit": "no"})
    assert excluded.applicability_status == "excluded"
    assert excluded.status == "not_assessed"
    subject = evaluate_criterion(
        criterion, check_outcomes=plaintext,
        applicability_answers={"business_subject_to_ccpa": "yes",
                               "subject_to_cppa_cybersecurity_audit": "yes"})
    assert subject.status == "gap_identified"


def test_a_property_that_does_not_arise_is_not_a_pass():
    """A filesystem store has no transport; that does not verify TLS."""
    criterion = get_criterion("HIPAA-164-312-E2II-ENCRYPTION-01")
    outcomes = [crypto_outcome("transport_encryption", "s", state="not_applicable",
                               complete=True),
                crypto_outcome("transport_tls_enforcement", "s",
                               state="not_applicable", complete=True)]
    result = evaluate_criterion(criterion, check_outcomes=outcomes,
                                applicability_answers={
                                    "covered_entity_or_business_associate": "yes",
                                    "system_handles_ephi": "yes"})
    assert result.technical_result == "not_run"
    assert result.technical_coverage == "does_not_arise"
    assert result.fallback_required == ["transport_security_statement"]
    assert result.status == "evidence_needed"


def test_not_applicable_beside_a_real_observation_still_counts():
    """No PAN found, with classification complete, is a pass for PCI storage."""
    outcomes = [check_outcome("data_classification", "s", "docs", outcome="passed",
                              complete=True),
                crypto_outcome("pan_representation", "s", "docs",
                               state="not_applicable", complete=True)]
    [result] = [evaluate_criterion(get_criterion("PCI-DSS-3-STORAGE-01"),
                                   check_outcomes=outcomes)]
    assert result.technical_result == "passed"


def test_not_observable_has_its_own_coverage_wording():
    result = evaluate_criterion(FALLBACK, check_outcomes=_at_rest("not_observable"),
                                applicability_answers=APPLIES)
    assert (result.technical_result, result.technical_coverage) == (
        "not_run", "not_observable")
