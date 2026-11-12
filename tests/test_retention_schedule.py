"""Retention evaluated against the customer's own declared schedule.

The failure modes guarded here: calling a record over-retained when its age is
unknown, failing a store that never declared a schedule, reading a date of
birth as the record's age, and wording an exceedance as a legal conclusion.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from vecshield.models import Severity
from vecshield_platform.compliance.data import load_references, reference_ids
from vecshield_platform.coverage import not_requested, summarize_coverage
from vecshield_platform.scan.retention_schedule import (
    MAX_EXAMPLES,
    ScheduleError,
    category_catalog,
    category_severity,
    evaluate_retention_schedule,
    resolve_schedule,
    retention_schedule_findings,
    retention_schedule_outcome,
    valid_categories,
    validate_schedule,
)

NOW = datetime(2026, 9, 29, tzinfo=timezone.utc)
PCI_RULE = {"category": "pci", "max_age_days": 365, "basis": "Card data policy s4.2"}


def rec(chunk_id, *, labels=(), detectors=(), qualifiers=(), **metadata):
    return {"chunk_id": chunk_id, "labels": set(labels), "detectors": set(detectors),
            "qualifiers": set(qualifiers), "metadata": metadata}


# ---------------------------------------------------------------- categories
def test_categories_cover_labels_detectors_and_qualifiers():
    cats = valid_categories()
    assert {"pci", "phi", "pii", "special_category", "secret",
            "criminal_offence"} <= cats
    assert {"credit_card", "biometric_reference"} <= cats
    assert "minor" in cats
    assert "none" not in cats
    kinds = {row["id"]: row["kind"] for row in category_catalog()}
    assert kinds["pci"] == "label" and kinds["credit_card"] == "detector"
    assert kinds["minor"] == "qualifier"


@pytest.mark.parametrize("category,severity", [
    ("pci", Severity.HIGH), ("phi", Severity.HIGH), ("special_category", Severity.HIGH),
    ("secret", Severity.HIGH), ("pii", Severity.MEDIUM), ("minor", Severity.HIGH),
    ("credit_card", Severity.HIGH), ("email", Severity.MEDIUM),
])
def test_severity_follows_the_category(category, severity):
    assert category_severity(category) == severity


# ---------------------------------------------------------------- validation
def test_empty_or_missing_schedule_is_not_declared():
    assert validate_schedule(None) is None
    assert validate_schedule({}) is None
    assert validate_schedule({"rules": [], "default_max_age_days": None}) is None


def test_validation_reports_every_problem_at_once():
    with pytest.raises(ScheduleError) as err:
        validate_schedule({"rules": [
            {"category": "nonsense", "max_age_days": 30, "basis": "x"},
            {"category": "pci", "max_age_days": 0, "basis": "x"},
            {"category": "pii", "max_age_days": True, "basis": "x"},
            {"category": "phi", "max_age_days": 10, "basis": "  "},
            {"category": "email", "max_age_days": 10, "basis": "x", "clock": "last_use"},
            {"category": "us_phone", "max_age_days": 10, "basis": "x", "reference": "made_up"},
        ], "default_max_age_days": -1})
    problems = err.value.problems
    assert len(problems) == 7
    assert any("unknown category" in p for p in problems)
    assert any("positive whole number" in p for p in problems)
    assert any("basis is required" in p for p in problems)
    assert any("clock" in p for p in problems)
    assert any("unknown reference" in p for p in problems)
    assert any("default_max_age_days" in p for p in problems)


def test_duplicate_rules_are_rejected_but_scoped_ones_are_not():
    with pytest.raises(ScheduleError):
        validate_schedule({"rules": [PCI_RULE, PCI_RULE]})
    schedule = validate_schedule({"rules": [
        PCI_RULE, {**PCI_RULE, "max_age_days": 90, "collections": ["payments_*"]}]})
    assert len(schedule.rules) == 2


def test_store_schedule_replaces_the_global_one():
    config = {"global": {"rules": [PCI_RULE]},
              "stores": {"s2": {"rules": [{"category": "pii", "max_age_days": 30,
                                           "basis": "EU policy"}]}}}
    assert resolve_schedule(config, "s1").rules[0].category == "pci"
    assert [r.category for r in resolve_schedule(config, "s2").rules] == ["pii"]
    assert resolve_schedule(None, "s1") is None
    assert resolve_schedule({"rules": [PCI_RULE]}, "any").rules[0].category == "pci"


# ---------------------------------------------------------------- evaluation
def test_no_schedule_is_skipped_as_opt_in_and_does_not_make_the_run_partial():
    result = evaluate_retention_schedule([rec("a", labels={"pci"})], None, now=NOW)
    outcome = retention_schedule_outcome("store", "col", result)
    assert outcome["check"] == "retention_schedule"
    assert outcome["outcome"] == "skipped"
    assert outcome["reason"] == "No retention schedule declared"
    assert not_requested(outcome)
    assert summarize_coverage([outcome])["checks_expected"] == 0
    assert retention_schedule_findings("store", "col", result) == []


def test_record_older_than_declared_maximum_fails_with_ids_only():
    records = [
        rec("old", labels={"pci"}, created_at="2024-01-01T00:00:00Z", card="4111"),
        rec("new", labels={"pci"}, created_at="2026-09-01T00:00:00Z"),
        rec("plain", created_at="2019-01-01T00:00:00Z"),
    ]
    result = evaluate_retention_schedule(records, {"rules": [PCI_RULE]},
                                         collection="payments", now=NOW)
    assert result.status == "exceeded"
    [rule] = result.rules
    assert (rule.in_scope, rule.dated, rule.over_max) == (2, 2, 1)
    assert rule.examples == ("old",)
    assert rule.oldest_age_days == (NOW - datetime(2024, 1, 1, tzinfo=timezone.utc)).days

    outcome = retention_schedule_outcome("store", "payments", result)
    assert outcome["outcome"] == "failed"
    assert outcome["coverage"]["complete"] is True
    assert outcome["coverage"]["status"] == "complete", "details must not clobber coverage status"
    assert outcome["coverage"]["schedule_status"] == "exceeded"

    [finding] = retention_schedule_findings("store", "payments", result)
    assert finding.category == "retention_schedule"
    assert finding.severity == Severity.HIGH
    assert "declared maximum" in finding.title + finding.description
    assert "unlawful" not in finding.title
    assert "does not determine that holding them is unlawful" in finding.description
    assert "three months" in finding.remediation
    # Evidence carries ids, never record content.
    assert "4111" not in json.dumps(finding.evidence)


def test_pii_exceedance_is_medium():
    result = evaluate_retention_schedule(
        [rec("a", labels={"pii"}, created_at="2020-01-01")],
        {"rules": [{"category": "pii", "max_age_days": 30, "basis": "policy"}]}, now=NOW)
    assert retention_schedule_findings("s", "c", result)[0].severity == Severity.MEDIUM


def test_undated_in_scope_records_are_age_unknown_not_over_retained():
    records = [rec("a", labels={"pci"}), rec("b", labels={"pci"}, note="no date")]
    result = evaluate_retention_schedule(records, {"rules": [PCI_RULE]}, now=NOW)
    assert result.status == "undated"
    assert result.rules[0].age_unknown == 2 and result.rules[0].over_max == 0
    outcome = retention_schedule_outcome("s", "c", result)
    assert outcome["outcome"] == "inconclusive"
    assert outcome["coverage"]["complete"] is False
    assert retention_schedule_findings("s", "c", result) == []


def test_partly_dated_passes_but_is_not_complete():
    records = [rec("a", labels={"pci"}, created_at="2026-09-01"),
               rec("b", labels={"pci"})]
    result = evaluate_retention_schedule(records, {"rules": [PCI_RULE]}, now=NOW)
    assert result.status == "partly_dated"
    outcome = retention_schedule_outcome("s", "c", result)
    assert outcome["outcome"] == "passed" and outcome["coverage"]["complete"] is False
    assert "age is unknown" in outcome["reason"]


def test_subject_dates_never_become_record_age():
    """A date of birth is decades old; reading it as record time would fail
    every rule. The field choice is retention.py's, so both checks agree."""
    records = [rec("a", labels={"pii"}, date_of_birth="1960-05-01")]
    result = evaluate_retention_schedule(
        records, {"rules": [{"category": "pii", "max_age_days": 30, "basis": "p"}]},
        now=NOW)
    assert result.timestamp_field is None
    assert result.status == "undated"
    assert result.excluded_fields == {"date_of_birth": 1}


def test_detector_and_qualifier_rules_match_their_own_tags():
    records = [
        rec("kid", labels={"pii"}, qualifiers={"minor"}, created_at="2025-01-01"),
        rec("bio", labels={"special_category"}, detectors={"biometric_reference"},
            created_at="2021-01-01"),
        rec("adult", labels={"pii"}, created_at="2025-01-01"),
    ]
    schedule = {"rules": [
        {"category": "minor", "max_age_days": 180, "basis": "COPPA policy",
         "reference": "coppa_16_cfr_312_10"},
        {"category": "biometric_reference", "max_age_days": 1095, "basis": "BIPA schedule",
         "reference": "bipa_740_ilcs_14_15_a"},
    ]}
    result = evaluate_retention_schedule(records, schedule, now=NOW)
    by_cat = {r.category: r for r in result.rules}
    assert by_cat["minor"].examples == ("kid",)
    assert by_cat["biometric_reference"].examples == ("bio",)
    assert sum(r.in_scope for r in result.rules) == 2, "adult is in no rule"


def test_default_maximum_covers_only_what_no_rule_reaches():
    records = [rec("card", labels={"pci"}, created_at="2026-09-01"),
               rec("doc", created_at="2015-01-01")]
    result = evaluate_retention_schedule(
        records, {"rules": [PCI_RULE], "default_max_age_days": 3650,
                  "default_basis": "Records policy"}, now=NOW)
    default = next(r for r in result.rules if r.is_default)
    assert default.in_scope == 1 and default.examples == ("doc",)
    assert retention_schedule_findings("s", "c", result)[0].severity == Severity.LOW


def test_collection_scoped_rules_apply_only_to_matching_collections():
    schedule = {"rules": [{**PCI_RULE, "collections": ["payments_*"]}]}
    records = [rec("a", labels={"pci"}, created_at="2020-01-01")]
    assert evaluate_retention_schedule(records, schedule, collection="payments_eu",
                                       now=NOW).status == "exceeded"
    assert evaluate_retention_schedule(records, schedule, collection="support",
                                       now=NOW).status == "nothing_in_scope"


def test_examples_are_bounded_oldest_first_and_deterministic():
    records = [rec(f"c{i:03d}", labels={"pci"}, created_at=f"20{10 + i % 10}-01-01")
               for i in range(60)]
    first = evaluate_retention_schedule(records, {"rules": [PCI_RULE]}, now=NOW)
    second = evaluate_retention_schedule(list(reversed(records)), {"rules": [PCI_RULE]},
                                         now=NOW)
    examples = first.rules[0].examples
    assert len(examples) == MAX_EXAMPLES
    assert examples == second.rules[0].examples
    assert examples == ("c000", "c010", "c020", "c030", "c040")


def test_a_capped_scan_never_reports_a_complete_evaluation():
    result = evaluate_retention_schedule(
        [rec("a", labels={"pci"}, created_at="2026-09-01")], {"rules": [PCI_RULE]}, now=NOW)
    assert retention_schedule_outcome("s", "c", result, complete=False)[
        "coverage"]["complete"] is False


def test_labels_may_be_enums():
    from vecshield.models import SensitivityLabel
    result = evaluate_retention_schedule(
        [rec("a", labels={SensitivityLabel.PCI}, created_at="2020-01-01")],
        {"rules": [PCI_RULE]}, now=NOW)
    assert result.status == "exceeded"


# ---------------------------------------------------------------- references
def test_retention_references_are_sourced_and_never_auto_applied():
    data = load_references("retention")
    ids = reference_ids("retention")
    assert {"pci_dss_4_0_1_req_3_2_1", "coppa_16_cfr_312_10", "ccpa_1798_100_a_3",
            "bipa_740_ilcs_14_15_a", "gdpr_art_5_1_e", "glba_16_cfr_314_4_c_6",
            "hipaa_45_cfr_164_316_b_2"} <= ids
    for ref in data["references"]:
        assert ref["source_url"].startswith(("https://", "http://"))
        assert ref["citation"] and ref["summary"]
        rule = ref.get("suggested_rule")
        if rule is not None:
            assert rule["category"] in valid_categories()
    hipaa = next(r for r in data["references"] if r["id"] == "hipaa_45_cfr_164_316_b_2")
    assert hipaa["kind"] == "clarification" and hipaa["suggested_rule"] is None
    coppa = next(r for r in data["references"] if r["id"] == "coppa_16_cfr_312_10")
    assert coppa["compliance_date"] == "2026-04-22"
