"""Citation corrections, provenance, lifecycle and content-review gating.

These tests hold the pack to the citation audit of its sources and to the
provenance and review rules. They check what the content claims, not
whether the law says it: that is a qualified reviewer's job, and nothing here
stands in for one.
"""

from __future__ import annotations

import json
import re
from dataclasses import replace
from pathlib import Path

import pytest

from vecshield_platform.api.templates import enriched_policy_templates, get_template
from vecshield_platform.compliance.content_review import (
    CONTENT_REVIEWS,
    MAPPING_HINT,
    ContentReview,
    criterion_lifecycle,
    pack_lifecycle,
)
from vecshield_platform.compliance.criteria import (
    KNOWN_PACK_VERSIONS,
    PACK_VERSION,
    ReviewerDecision,
    evaluate_criterion,
)
from vecshield_platform.compliance.crypto_basis import basis_for, crypto_basis
from vecshield_platform.compliance.decisions import (
    annotate,
    criterion_digest,
    staleness,
)
from vecshield_platform.compliance.pack_history import (
    PACK_DIGESTS,
    PREVIOUS_PACK,
    compare,
    migration_markdown,
)
from vecshield_platform.compliance.packs import (
    CRITERIA,
    COVERAGE_GAPS,
    criteria_for,
    get_criterion,
    hipaa_pack_manifest,
    pack_manifest,
    resolve_criterion_id,
)
from vecshield_platform.compliance.sources import (
    CITATION_CHECKS,
    LEGAL_STATUSES,
    LIFECYCLE,
    REVIEW_GATED,
    SOURCES,
    RegulatorySource,
    resolve_sources,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = Path(__file__).parent / "fixtures" / "hipaa_ecfr_labels.json"
MIGRATION_DOC = ROOT / "docs" / "compliance" / "pack-draft-4-migration.md"

#: What each source ``specification`` must say in the record's own notes, so
#: the structured label and the prose a reader sees cannot drift apart.
_NOTE_PHRASE = {
    "required": "Required implementation specification",
    "addressable": "Addressable implementation specification",
    "standard": "tandard",
    "implementation_specification": "implementation specification",
    "definition": "efinition",
}


def _review(criteria, *, digests=None, **overrides) -> ContentReview:
    fields = dict(
        id="rev-test", reviewer="A. Counsel", firm="Example LLP",
        qualification="US health-privacy counsel", jurisdictions=("US-federal",),
        criterion_digests=digests or {c.id: criterion_digest(c) for c in criteria},
        reviewed_on="2026-10-01", next_review="2027-10-01",
        conflicts="None declared", pack_version=PACK_VERSION)
    fields.update(overrides)
    return ContentReview(**fields)


# --------------------------------------------------------------------------- #
# HIPAA labels against the stored eCFR fixture                                 #
# --------------------------------------------------------------------------- #

def test_hipaa_labels_match_the_stored_ecfr_fixture():
    fixture = json.loads(FIXTURE.read_text())
    by_section: dict[str, list[RegulatorySource]] = {}
    for source in SOURCES.values():
        if source.framework == "HIPAA" and source.section:
            by_section.setdefault(source.section, []).append(source)
    for section, label in fixture["labels"].items():
        records = by_section.get(section)
        assert records, f"no source record for {section}"
        for record in records:
            assert record.specification == label, (record.id, record.specification,
                                                   label)
            assert _NOTE_PHRASE[label] in record.notes, (record.id, label)
            # A fixture entry is a primary-source read; the record says so
            # without claiming a build fetched the text.
            assert record.citation_check == "primary_source", record.id
            assert record.verified is False


def test_no_hipaa_record_carries_a_label_the_fixture_contradicts():
    fixture = json.loads(FIXTURE.read_text())["labels"]
    for source in SOURCES.values():
        if source.framework != "HIPAA" or source.section not in fixture:
            continue
        for label, phrase in (("required", "(d)(2): it must"),
                              ("addressable", "Addressable implementation")):
            if phrase in source.notes:
                assert fixture[source.section] == label, source.id


def test_hipaa_criteria_follow_the_label_of_their_primary_provision():
    """A criterion's kind is the label of a provision it cites, never invented.

    An addressable criterion may be anchored on its standard (§164.308(a)(4))
    while its implementation specifications carry the addressable label; the
    label must still appear among its own citations. One anchored on a
    definitions section carries no kind.
    """
    fixture = json.loads(FIXTURE.read_text())["labels"]
    for criterion in criteria_for("HIPAA"):
        cited = {fixture.get(SOURCES[s].section) for s in criterion.source_ids}
        primary = fixture.get(SOURCES[criterion.source_ids[0]].section)
        if primary == "definition":
            assert criterion.specification is None, criterion.id
        elif primary is not None:
            assert criterion.specification in cited, (criterion.id, cited)


# --------------------------------------------------------------------------- #
# The §4A.2 worklist, row by row                                               #
# --------------------------------------------------------------------------- #

def test_hipaa_citation_fixes():
    assert "hipaa-164-304" in get_criterion("HIPAA-164-308-A6-INCIDENT-01").source_ids
    access = get_criterion("HIPAA-164-308-A4-ACCESS-MGMT-01")
    assert any("do not evaluate it" in lim for lim in access.limitations)
    baa = get_criterion("HIPAA-164-308-B1-BAA-01")
    assert {"hipaa-164-502-e", "hipaa-164-504-e"} <= set(baa.source_ids)
    for assumed in ("hipaa-164-502-e", "hipaa-164-504-e"):
        assert SOURCES[assumed].citation_check == "unverified"

    disposal = get_criterion("HIPAA-164-310-D2-DISPOSAL-01")
    assert disposal.title == "Disposal of ePHI on retired media and indexes"
    assert "no longer needed" not in disposal.paraphrase
    assert "interpretation, offered for counsel" in disposal.interpretation_notes
    assert "retention_horizon" not in disposal.technical_checks

    nprm = SOURCES["hipaa-security-nprm-2025"]
    assert nprm.legal_status == "proposed" and nprm.status == "proposed"
    assert "hipaa-security-nprm-2025" not in {
        s for c in CRITERIA for s in c.source_ids}
    assert [p["id"] for p in pack_manifest()["tracked_proposals"]] == [nprm.id]

    assert "hipaa-164-514-d" in get_criterion(
        "HIPAA-164-502-B-MIN-NECESSARY-01").source_ids
    deident = get_criterion("HIPAA-164-514-B-DEIDENT-01")
    assert deident.source_ids[0] == "hipaa-164-514-a"
    assert deident.specification == "standard"
    for spec in ("hipaa-164-514-b-1", "hipaa-164-514-b-2", "hipaa-164-514-c"):
        assert SOURCES[spec].specification == "implementation_specification"

    assert get_criterion("HIPAA-164-402-BREACH-ASSESS-01").specification is None
    assert hipaa_pack_manifest()["no_specification"] == [
        "HIPAA-164-402-BREACH-ASSESS-01"]


def test_privacy_rule_and_definition_dates_separate_effect_from_compliance():
    for source in SOURCES.values():
        if source.title in ("HIPAA Privacy Rule, 45 CFR Part 164 Subpart E",
                            "HIPAA General Administrative Requirements, "
                            "45 CFR Part 160 Subpart A"):
            assert source.effective_date == "2001-04-14", source.id
            assert source.compliance_date == "2003-04-14", source.id
    definitions = SOURCES["hipaa-160-103"]
    assert definitions.consolidated_as_of == "2026-03-24"
    assert "/on/2026-09-23/" in definitions.url
    assert "as amended through 2026-03-24" in definitions.edition


def test_gdpr_citation_fixes():
    assert get_criterion("GDPR-STORAGE-LIMITATION-01").source_ids == ["gdpr-art-5-1-e"]
    erasure = get_criterion("GDPR-ERASURE-01")
    assert {"gdpr-art-12-3", "gdpr-art-17-3", "gdpr-art-19",
            "edpb-cef-2025-erasure"} <= set(erasure.source_ids)
    assert any("is itself a legal question" in lim for lim in erasure.limitations)
    report = SOURCES["edpb-cef-2025-erasure"]
    assert report.legal_status == "guidance" and report.kind == "guidance"
    assert report.citation_check == "secondary_sources"
    security = get_criterion("GDPR-SECURITY-32-01")
    assert security.source_ids == ["gdpr-art-32-1-b", "gdpr-art-5-1-f"]
    for assumed in ("gdpr-art-5-1-e", "gdpr-art-32-1-b", "gdpr-art-5-1-f"):
        assert SOURCES[assumed].citation_check == "unverified", assumed


def test_ai_act_art_10_is_split_and_kept_only_as_a_provider_note():
    assert get_criterion("AIACT-ART10-DATA-GOV-01").id == "AIACT-ART26-4-INPUT-DATA-01"
    assert resolve_criterion_id("AIACT-ART10-DATA-GOV-01") == "AIACT-ART26-4-INPUT-DATA-01"
    assert {c.id for c in criteria_for("EU AI Act")} == {
        "AIACT-ART26-4-INPUT-DATA-01", "AIACT-ART15-5-RESILIENCE-01"}
    assert not any("aiact-art-10" in c.source_ids for c in CRITERIA)
    assert "provider" in SOURCES["aiact-art-10"].notes
    # Stored evidence reviews were filed under data_governance_record.
    assert "data_governance_record" in get_criterion(
        "AIACT-ART26-4-INPUT-DATA-01").manual_evidence


def test_ai_act_dates_are_per_provision_and_flagged_for_re_checking():
    for source_id in ("aiact-art-10", "aiact-art-15", "aiact-art-15-5", "aiact-art-26-4"):
        source = SOURCES[source_id]
        assert source.application_date is None, source_id
        assert source.legal_status == "future_effective"
        dates = {d.application_date for d in source.provision_dates}
        assert dates == {"2027-12-02", "2028-08-02"}, source_id
        assert source.amended_by == ("aiact-omnibus-2026-1744",)
        assert source.citation_check == "secondary_sources"
        assert "Official Journal" in source.citation_check_note
    omnibus = SOURCES["aiact-omnibus-2026-1744"]
    assert omnibus.effective_date == "2026-07-27"
    assert omnibus.citation_check == "secondary_sources"
    assert not any("2026-08-02" in json.dumps(s.to_dict())
                   for s in SOURCES.values() if s.framework == "EU AI Act")


def test_ccpa_citation_fixes():
    delete = get_criterion("CCPA-DELETE-01")
    assert {"ccpa-regs-7022", "ccpa-1798-105-d"} <= set(delete.source_ids)
    assert any("§ 7022(d)" in lim for lim in delete.limitations)
    audit = get_criterion("CCPA-CYBERAUDIT-ENCRYPTION-01")
    assert audit.title == "Encryption evidence for the CPPA cybersecurity audit"
    assert audit.specification is None
    assert "not a mandate" in audit.interpretation_notes
    row = basis_for("CCPA/CPRA")
    assert row.relationship == "audit_component"
    assert "does not itself require" in row.interpretation
    access = get_criterion("CCPA-CYBERAUDIT-ACCESS-01")
    assert access.source_ids == ["ccpa-regs-7123-c-3"]


def test_templates_are_remapped():
    assert get_template("hipaa-phi-invertible")["source_ids"] == ["hipaa-164-308-a-1-ii-a"]
    assert get_template("soc2-injection")["source_ids"] == ["tsc-cc7-2"]
    assert get_template("pci-secrets")["source_ids"] == [
        "pci-dss-req-8-6-2", "pci-dss-req-8-3-2"]
    for assumed in ("pci-dss-req-8-6-2", "pci-dss-req-8-3-2"):
        assert SOURCES[assumed].citation_check == "unverified"
    assert get_template("aiact-robustness")["source_ids"] == ["aiact-art-15-5"]
    assert get_template("aiact-data-governance")["source_ids"] == ["aiact-art-26-4"]


def test_soc2_links_point_at_the_criteria_download():
    for source_id in ("tsc-cc6-1", "tsc-cc6-7", "tsc-cc7-1", "tsc-cc7-2"):
        assert "trust-services-criteria" in SOURCES[source_id].url, source_id


def test_pci_gap_records_are_listed_not_evaluated():
    gaps = {g["source_id"] for g in COVERAGE_GAPS}
    assert gaps == {"pci-dss-req-3-3-1", "pci-dss-req-3-2-1"}
    for gap in gaps:
        assert SOURCES[gap].citation_check == "unverified"
        assert not any(gap in c.source_ids for c in CRITERIA)
    assert {g["source_id"] for g in pack_manifest()["coverage_gaps"]} == gaps


# --------------------------------------------------------------------------- #
# Provenance fields                                                            #
# --------------------------------------------------------------------------- #

def test_every_source_states_legal_status_and_reproduction():
    for source in SOURCES.values():
        assert source.legal_status in LEGAL_STATUSES
        assert source.citation_check in CITATION_CHECKS
        assert source.licence, source.id
        if not source.redistributable:
            assert source.reproduction == "link_only", source.id


def test_nothing_claims_a_fetch_or_a_review_it_did_not_have():
    for source in SOURCES.values():
        assert source.verified is False, source.id
        assert source.fetch_method is None and source.review_ref is None
        assert source.lifecycle not in REVIEW_GATED


def test_provenance_rules_are_enforced_on_construction():
    base = dict(id="x", framework="F", issuer="I", title="T", kind="regulation")
    with pytest.raises(ValueError):
        RegulatorySource(**base, lifecycle="regulatory_reviewed")
    with pytest.raises(ValueError):
        RegulatorySource(**base, redistributable=False, reproduction="paraphrase")
    with pytest.raises(ValueError):
        RegulatorySource(**base, legal_status="kinda")
    with pytest.raises(ValueError):
        RegulatorySource(**base, retrieved_at="2026-09-29", content_hash="ab")
    # Old-shaped records still load with defaults.
    legacy = RegulatorySource(**base)
    assert legacy.legal_status == "in_force" and legacy.reproduction == "paraphrase"
    assert legacy.citation_check == "not_recorded"


def test_an_unresolved_reference_has_the_same_shape_as_a_record():
    resolved, unresolved = resolve_sources(["gdpr-art-17", "no-such-source"])
    assert set(resolved) == set(unresolved)
    assert unresolved["status"] == "unresolved" and unresolved["verified"] is False


# --------------------------------------------------------------------------- #
# No licensed text                                                             #
# --------------------------------------------------------------------------- #

#: Headings from licensed standards that earlier drafts reproduced. They must
#: not come back; the plan asks for a paraphrase.
_LICENSED_HEADINGS = ("protect stored account data",
                      "identify users and authenticate access",
                      "uses encryption to protect data",
                      "rendered unreadable wherever it is stored")

#: A quoted span: an opening quote mark after a space or at the start. An
#: apostrophe inside a word ("auditor's") is not a quotation.
_QUOTED = re.compile(r"(^|[\s([])['\"‘“][^'\"’”]+['\"’”]")

_LICENSED_TITLE = re.compile(
    r"^(PCI DSS v4\.0\.1, Requirement [\d.]+|Trust Services Criteria, CC\d\.\d+) "
    r"\([A-Za-z0-9 ,.\-]+\)$")


def _licensed_text_surfaces():
    for source in SOURCES.values():
        if not source.redistributable:
            yield source.id, source.title
            yield source.id, source.notes
    for criterion in CRITERIA:
        if criterion.framework in ("PCI-DSS", "SOC 2"):
            yield criterion.id, " ".join([criterion.title, criterion.paraphrase,
                                         criterion.interpretation_notes,
                                         *criterion.limitations])
    for template in enriched_policy_templates():
        if template["regulation"] in ("PCI-DSS", "SOC 2"):
            yield template["id"], json.dumps(template)


def test_licensed_sources_are_linked_and_paraphrased_not_reproduced():
    for source in SOURCES.values():
        if source.redistributable:
            continue
        assert source.reproduction == "link_only"
        assert source.url and source.section
        assert _LICENSED_TITLE.match(source.title), source.title
        # No quotation of any length from the standard itself.
        for text in (source.title, source.notes):
            assert not _QUOTED.search(text), (source.id, text)
    for where, text in _licensed_text_surfaces():
        lowered = text.lower()
        for heading in _LICENSED_HEADINGS:
            assert heading not in lowered, (where, heading)


# --------------------------------------------------------------------------- #
# Lifecycle and content-review gating                                          #
# --------------------------------------------------------------------------- #

def test_no_content_review_is_shipped_and_everything_is_draft():
    assert CONTENT_REVIEWS == ()
    manifest = pack_manifest()
    assert manifest["lifecycle"] == "draft"
    assert manifest["lifecycle_label"] == "Draft mapping"
    assert manifest["regulatory_review"] is None and manifest["content_reviews"] == []
    assert manifest["lifecycle_by_state"] == {"draft": len(CRITERIA)}
    assert manifest["mapping_hint"] == MAPPING_HINT
    for criterion in CRITERIA:
        record = criterion.to_dict()
        assert record["lifecycle"] == "draft" and record["content_review"] is None


def test_criteria_cannot_declare_a_reviewed_state():
    template = CRITERIA[0]
    for state in REVIEW_GATED:
        with pytest.raises(ValueError):
            replace(template, lifecycle=state)
    assert replace(template, lifecycle="technically_validated").lifecycle == \
        "technically_validated"


def test_a_matching_content_review_is_the_only_route_to_reviewed():
    hipaa = criteria_for("HIPAA")
    review = _review(hipaa)
    lifecycle = criterion_lifecycle(hipaa[0], [review])
    assert lifecycle["state"] == "regulatory_reviewed"
    assert lifecycle["review"]["reviewer"] == "A. Counsel"
    assert lifecycle["review"]["conflicts"] == "None declared"
    # The pack is held back by its least-advanced criterion.
    assert pack_lifecycle(CRITERIA, [review])["state"] == "draft"
    assert pack_lifecycle(hipaa, [review])["state"] == "regulatory_reviewed"
    assert pack_lifecycle(hipaa, [review])["content_reviews"][0]["id"] == "rev-test"


def test_a_review_of_different_wording_does_not_apply():
    criterion = CRITERIA[0]
    stale = _review([criterion], digests={criterion.id: "0" * 64})
    lifecycle = criterion_lifecycle(criterion, [stale])
    assert lifecycle["state"] == "draft" and lifecycle["review"] is None
    assert lifecycle["stale_reviews"] == ["rev-test"]
    # Rewording after the review orphans it; retitling does not.
    review = _review([criterion])
    reworded = replace(criterion, paraphrase=criterion.paraphrase + " Changed.")
    assert criterion_lifecycle(reworded, [review])["state"] == "draft"
    retitled = replace(criterion, title="A different title")
    assert criterion_lifecycle(retitled, [review])["state"] == "regulatory_reviewed"


def test_the_pack_lifecycle_is_the_least_advanced_criterion():
    validated = replace(CRITERIA[0], lifecycle="technically_validated")
    reviewed_one = CRITERIA[1]
    review = _review([reviewed_one])
    assert pack_lifecycle([validated, reviewed_one], [review])["state"] == \
        "technically_validated"
    assert pack_lifecycle([validated], [])["state"] == "technically_validated"
    assert pack_lifecycle([replace(CRITERIA[0], lifecycle="superseded")], [])[
        "state"] == "superseded"
    assert pack_lifecycle([], [])["state"] == "draft"


def test_content_reviews_must_be_complete_records():
    criterion = CRITERIA[0]
    for bad in (dict(conflicts=""), dict(firm=" "), dict(jurisdictions=()),
                dict(next_review="2026-09-01"), dict(reviewed_on="yesterday"),
                dict(digests={criterion.id: "short"})):
        digests = bad.pop("digests", None)
        with pytest.raises(ValueError):
            _review([criterion], digests=digests, **bad)


def test_a_customer_reviewer_decision_never_moves_the_content_lifecycle():
    criterion = get_criterion("GDPR-ERASURE-01")
    decision = ReviewerDecision(reviewer="dpo@example.test", conclusion="satisfied",
                                rationale="Checked.", decided_at="2026-10-01")
    evaluate_criterion(criterion, reviewer_decision=decision)
    assert criterion.to_dict()["lifecycle"] == "draft"


# --------------------------------------------------------------------------- #
# Draft-4 migration                                                            #
# --------------------------------------------------------------------------- #

def test_the_pack_moved_to_draft_4_and_draft_3_is_still_recognised():
    assert PACK_VERSION == "vecshield-vector-store-draft-4"
    assert PREVIOUS_PACK in KNOWN_PACK_VERSIONS and PREVIOUS_PACK in PACK_DIGESTS


def test_the_migration_note_is_generated_not_written():
    assert MIGRATION_DOC.read_text() == migration_markdown()


def test_every_criterion_the_audit_touched_is_reported_changed():
    rows = {r["criterion_id"]: r for r in compare()["criteria"]}
    touched = {"HIPAA-164-308-A4-ACCESS-MGMT-01", "HIPAA-164-308-A6-INCIDENT-01",
               "HIPAA-164-308-B1-BAA-01", "HIPAA-164-310-D2-DISPOSAL-01",
               "HIPAA-164-502-B-MIN-NECESSARY-01", "HIPAA-164-514-B-DEIDENT-01",
               "HIPAA-164-402-BREACH-ASSESS-01", "GDPR-STORAGE-LIMITATION-01",
               "GDPR-ERASURE-01", "GDPR-SECURITY-32-01", "PCI-DSS-3-STORAGE-01",
               "CCPA-DELETE-01", "CCPA-CYBERAUDIT-ENCRYPTION-01"}
    for criterion_id in touched:
        assert rows[criterion_id]["outcome"] == "changed", criterion_id
    assert rows["AIACT-ART10-DATA-GOV-01"]["outcome"] == "replaced"
    assert set(compare()["added"]) == {"AIACT-ART15-5-RESILIENCE-01",
                                       "CCPA-CYBERAUDIT-ACCESS-01"}


def _draft3_decision(criterion_id: str) -> dict:
    return {"criterion_id": criterion_id, "pack_version": PREVIOUS_PACK,
            "criterion_digest": PACK_DIGESTS[PREVIOUS_PACK][criterion_id]["digest"]}


def test_decisions_on_unchanged_criteria_carry_forward_and_others_go_stale():
    for row in compare()["criteria"]:
        record = _draft3_decision(row["criterion_id"])
        current = get_criterion(row["criterion_id"])
        reason = staleness(record, current)
        if row["outcome"] == "unchanged":
            assert reason is None, row["criterion_id"]
            annotated = annotate(record, resolve=resolve_criterion_id,
                                 lookup=get_criterion)
            assert annotated["carried_from_pack_version"] == PREVIOUS_PACK
        else:
            assert reason == "pack_version_changed", row["criterion_id"]


def test_an_unknown_or_undigested_older_decision_is_still_stale():
    criterion = get_criterion("HIPAA-164-312-B-AUDIT-01")
    record = _draft3_decision(criterion.id)
    assert staleness({**record, "criterion_digest": None}, criterion) == \
        "pack_version_changed"
    assert staleness({**record, "pack_version": "someone-elses-pack"}, criterion) == \
        "pack_version_changed"


# --------------------------------------------------------------------------- #
# Nothing rendered claims compliance or scores                                 #
# --------------------------------------------------------------------------- #

_PERCENT = re.compile(r"\d\s?%|\bpercent")


def _visible_text(html: str) -> str:
    html = re.sub(r"<style.*?</style>", " ", html, flags=re.S)
    return re.sub(r"<[^>]+>", " ", html)


def _rendered_surfaces():
    yield "pack_manifest", json.dumps(pack_manifest())
    yield "hipaa_manifest", json.dumps(hipaa_pack_manifest())
    yield "criteria", json.dumps([c.to_dict() for c in CRITERIA])
    yield "templates", json.dumps(enriched_policy_templates())
    yield "crypto_basis", json.dumps(crypto_basis())
    yield "migration", migration_markdown()


def test_no_rendered_content_claims_compliance_or_a_percentage():
    for name, text in _rendered_surfaces():
        lowered = text.lower()
        assert "compliant" not in lowered, name
        assert not _PERCENT.search(lowered), name


def test_the_dpia_draft_leaves_the_decision_with_the_controller():
    from types import SimpleNamespace

    from vecshield.models import Finding, SensitivityLabel, Severity
    from vecshield_platform.compliance.pia import build_pia_html, generate_pia

    finding = Finding(id="f1", store="s", category="data_classification",
                      severity=Severity.HIGH, title="Health data", collection="notes",
                      evidence={"label_counts": {SensitivityLabel.PHI.value: 3}})
    audit = SimpleNamespace(all_findings=lambda: [finding], violations=[],
                            store="s")
    pia = generate_pia(audit, store="s")
    assert pia.high_risk is True
    report = pia.to_dict()
    assert report["controller_action_required"] is report["dpo_action_required"]
    assert "not a determination" in report["high_risk_basis"]
    text = _visible_text(build_pia_html(pia))
    assert "Art. 35(2)" in text and "controller" in text
    for overclaim in ("DPIA required", "sign-off", "exactly", "compliant"):
        assert overclaim not in text, overclaim
    assert not _PERCENT.search(text.lower())


# --------------------------------------------------------------------------- #
# The criteria endpoint serves the new fields                                  #
# --------------------------------------------------------------------------- #

def test_the_criteria_endpoint_serves_lifecycle_and_provenance(tmp_path):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from vecshield_platform.api import create_app
    from vecshield_platform.api.registry import StoreRegistry
    from vecshield_platform.history import ScanHistory

    registry = StoreRegistry()
    registry.register("prod", "fake", factory=lambda: None)
    history = ScanHistory(tmp_path / "history.db")
    app = create_app(registry=registry, scan_history=history, serve_ui=False)
    try:
        body = TestClient(app).get("/compliance/criteria").json()
        assert body["pack"]["lifecycle"] == "draft"
        assert body["pack"]["lifecycle_label"] == "Draft mapping"
        assert set(body["pack"]["lifecycle_labels"]) == set(LIFECYCLE)
        assert body["pack"]["regulatory_review"] is None
        record = body["criteria"][0]
        assert record["lifecycle"] == "draft" and record["content_review"] is None
        source = record["sources"][0]
        for key in ("legal_status", "legal_status_label", "reproduction",
                    "citation_check", "provision_dates", "compliance_date",
                    "consolidated_as_of", "licence", "review_ref"):
            assert key in source, key
    finally:
        app.state.jobs.shutdown(wait=False)
        history.close()
