"""CCPA Article 10 risk-assessment workbook: evidence, not conclusions."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from vecshield.classify import RegexClassifier
from vecshield_platform.compliance.ccpa_risk import (
    ELEMENTS,
    TRIGGERS,
    build_ccpa_risk_html,
    cyberaudit_7123_support,
    deadlines,
    prefill_ccpa_risk_assessment,
    triggers,
    validate_business_inputs,
)
from vecshield_platform.orchestrator import run_full_audit

from test_assessment_coverage import MemoryConnector, chunk

NOW = datetime(2026, 9, 29, tzinfo=timezone.utc)


def outcome(check, result, *, collection=None, complete=True, reason="", **cov):
    return {"check": check, "store": "kb", "collection": collection, "outcome": result,
            "reason": reason,
            "coverage": {"status": "complete" if complete else "partial",
                         "complete": complete, **cov}}


def snapshot(outcomes=(), findings=(), *, stats=None, coverage=None):
    return {
        "id": "audit-ccpa1", "store": "kb", "finished_at": "2026-09-29T00:00:00+00:00",
        "scope": {"collections": ["patients", "docs"]},
        "coverage": coverage or {"status": "partial", "complete": False},
        "jobs": [{"id": "job-1", "store": "kb", "stats": stats or {},
                  "findings": list(findings)}],
        "check_outcomes": list(outcomes),
    }


def classification_finding(collection, detectors, labels, fid="find-1"):
    return {"id": fid, "title": "PHI detected", "severity": "high",
            "category": "data_classification", "store": "kb", "collection": collection,
            "description": "", "remediation": "",
            "evidence": {"detector_counts": detectors, "label_counts": labels,
                         "examples": [{"preview": "SSN 123-45-6789"}],
                         "explanations": ["matched 123-45-6789"]}}


def by_key(assessment):
    return {e["key"]: e for e in assessment.elements}


def by_trigger(rows):
    return {t["id"]: t for t in rows}


def phi_snapshot(**extra):
    return snapshot(
        [outcome("data_classification", "failed", collection="patients",
                 complete=False, reason="Capped at 1000 chunks."),
         outcome("data_classification", "passed", collection="docs"),
         *extra.pop("outcomes", [])],
        [classification_finding("patients",
                                {"us_ssn": 4, "medical_record_context": 7, "email": 2},
                                {"pii": 5, "phi": 7}),
         *extra.pop("findings", [])],
        **extra)


# ---- structure --------------------------------------------------------------

def test_element_model_mirrors_7152a_subsections():
    subsections = [e.subsection for e in ELEMENTS]
    for required in ("7152(a)(1)", "7152(a)(2)", "7152(a)(3)(A)", "7152(a)(3)(B)",
                     "7152(a)(3)(C)", "7152(a)(3)(D)", "7152(a)(3)(E)", "7152(a)(3)(F)",
                     "7152(a)(3)(G)(i)", "7152(a)(3)(G)(ii)", "7152(a)(4)", "7152(a)(5)",
                     "7152(a)(6)", "7152(a)(7)", "7152(a)(8)", "7152(a)(9)"):
        assert required in subsections
    assert len({e.key for e in ELEMENTS}) == len(ELEMENTS)
    # § 7001(zz): the report is (a)(1)-(3) and (6)-(9).
    outside = {e.subsection for e in ELEMENTS if not e.in_report}
    assert outside == {"7152(a)(4)", "7152(a)(5)"}
    assert [t.id for t in TRIGGERS] == [f"7150(b)({n})" for n in range(1, 7)]


# ---- triggers ---------------------------------------------------------------

def test_sensitive_pi_in_store_suggests_b2_with_pointers_and_caveat():
    rows = by_trigger(triggers(phi_snapshot()))
    b2 = rows["7150(b)(2)"]
    assert b2["status"] == "suggested"
    assert "7150(b)(2)(A)" in b2["note"]
    assert any(p.get("finding_id") == "find-1" for p in b2["evidence"])
    assert "business determines" in b2["caveat"]
    # ADMT use is never inferred from a store.
    assert rows["7150(b)(3)"]["status"] == "not_determinable"


def test_biometric_templates_suggest_b6_only_as_a_suggestion():
    snap = snapshot([outcome("biometric_templates", "failed", collection="faces",
                             reason="Face embeddings found.")])
    b6 = by_trigger(triggers(snap))["7150(b)(6)"]
    assert b6["status"] == "suggested"
    assert "Confirm" in b6["note"]
    assert b6["evidence"][0]["check"] == "biometric_templates"


def test_missing_classification_is_not_assessed_and_clean_is_only_no_indication():
    assert by_trigger(triggers(snapshot()))["7150(b)(2)"]["status"] == "not_assessed"
    clean = snapshot([outcome("data_classification", "passed", collection="docs")])
    b2 = by_trigger(triggers(clean))["7150(b)(2)"]
    assert b2["status"] == "no_indication"
    assert "neural" in b2["note"]
    for row in triggers(clean):
        assert row["status"] != "not_triggered"


def test_egress_is_review_for_sale_or_sharing_not_a_conclusion():
    snap = snapshot([outcome("model_egress", "failed", collection="docs",
                             flows=[{"provider": "OpenAI", "collection": "docs",
                                     "purpose": "embedding"}])])
    b1 = by_trigger(triggers(snap))["7150(b)(1)"]
    assert b1["status"] == "review"
    assert "OpenAI" in b1["note"] and "service provider" in b1["note"]


def test_business_trigger_determination_is_recorded_beside_evidence():
    rows = by_trigger(triggers(phi_snapshot(), business_inputs={
        "triggers": {"7150(b)(2)": {"applies": True, "note": "Patient notes."},
                     "7150(b)(9)": True}}))
    assert rows["7150(b)(2)"]["business_determination"] == {
        "applies": True, "note": "Patient notes."}
    assert rows["7150(b)(2)"]["status"] == "suggested"


# ---- prefill ----------------------------------------------------------------

def test_categories_map_to_statute_subdivisions_without_raw_values():
    a = prefill_ccpa_risk_assessment(phi_snapshot(), now=NOW)
    codes = {c["code"]: c for c in a.categories}
    assert codes["ae1A"]["matches"] == 4           # SSN -> (ae)(1)(A)
    assert codes["ae2B"]["matches"] == 7           # medical record -> (ae)(2)(B)
    assert codes["v1A"]["citation"].endswith("(v)(1)(A)")
    # The phi label is explained by a detector, so it is not double-counted.
    assert codes["ae2B"]["basis"] == ["scan detector medical_record_context"]
    element = by_key(a)["pi_categories"]
    assert element["status"] == "partially_prefilled"  # classification partial
    dumped = json.dumps(a.to_dict())
    assert "123-45-6789" not in dumped


def test_complete_classification_prefills_categories():
    snap = phi_snapshot()
    snap["check_outcomes"] = [
        outcome("data_classification", "failed", collection="patients"),
        outcome("data_classification", "passed", collection="docs")]
    a = prefill_ccpa_risk_assessment(snap, now=NOW)
    assert by_key(a)["pi_categories"]["status"] == "prefilled"


def test_label_only_legacy_findings_still_categorise_as_possible():
    snap = snapshot([outcome("data_classification", "failed", collection="c")],
                    [classification_finding("c", {}, {"special_category": 3, "pci": 2})])
    codes = {c["code"]: c for c in prefill_ccpa_risk_assessment(snap, now=NOW).categories}
    assert codes["ae"]["confidence"] == "possible"
    assert codes["ae1B"]["confidence"] == "possible"
    assert codes["v1B"]["confidence"] == "observed"


def test_approximate_consumers_from_subject_counts_else_not_established():
    inv = {"distinct_subjects": 1234, "collections": [{"name": "patients",
                                                        "subject_count": 1000}]}
    a = prefill_ccpa_risk_assessment(phi_snapshot(), inventory=inv, now=NOW)
    el = by_key(a)["approximate_consumers"]
    assert el["status"] == "prefilled"
    assert "1,234" in el["evidence"][0]["statement"]
    assert "not people" in " ".join(el["evidence"][0]["limits"])

    per_col = {"collections": [{"name": "a", "subject_count": 10},
                               {"name": "b", "subject_count": 5}]}
    el = by_key(prefill_ccpa_risk_assessment(phi_snapshot(), inventory=per_col,
                                             now=NOW))["approximate_consumers"]
    assert "Between 10 and 15" in el["evidence"][0]["statement"]

    el = by_key(prefill_ccpa_risk_assessment(phi_snapshot(), now=NOW))["approximate_consumers"]
    assert el["status"] == "not_assessed"
    assert el["evidence_value"] == "not established"


def test_retention_horizon_and_declared_schedule():
    snap = phi_snapshot(outcomes=[
        outcome("retention_horizon", "passed", collection="patients",
                reason="Records span 2019-01-01 to 2026-09-01; the oldest is 2828 days old.",
                field="created_at", oldest_age_days=2828)])
    el = by_key(prefill_ccpa_risk_assessment(snap, now=NOW))["retention"]
    assert el["status"] == "partially_prefilled"
    assert "2828 days" in el["evidence"][0]["statement"]

    snap["check_outcomes"].append(outcome("retention_schedule", "passed",
                                          collection="patients", declared="365 days",
                                          reason="Schedule declared."))
    el = by_key(prefill_ccpa_risk_assessment(snap, now=NOW))["retention"]
    assert el["status"] == "prefilled"
    assert "365 days" in el["evidence"][0]["statement"]


def test_recipients_from_egress_and_managed_store_and_residency():
    snap = phi_snapshot(
        outcomes=[outcome("model_egress", "failed", collection="patients",
                          flows=[{"provider": "Anthropic", "purpose": "generation"}]),
                  outcome("data_residency", "passed", regions=["us-west-2"],
                          reason="Store region reported by the provider.")],
        stats={"store_kind": "pinecone"})
    els = by_key(prefill_ccpa_risk_assessment(snap, now=NOW))
    recipients = " ".join(i["statement"] for i in els["recipients"]["evidence"])
    assert "Pinecone" in recipients and "Anthropic" in recipients
    assert els["recipients"]["status"] == "partially_prefilled"
    method = " ".join(i["statement"] for i in els["method_and_sources"]["evidence"])
    assert "us-west-2" in method and "Anthropic" in method


def test_safeguards_observed_not_observed_and_missing_checks_not_assessed():
    snap = phi_snapshot(outcomes=[
        outcome("transport_encryption", "passed", reason="TLS 1.3."),
        outcome("at_rest_encryption", "failed", reason="Disabled."),
        outcome("authentication", "skipped", complete=False, reason="Excluded."),
        outcome("tenant_isolation", "inconclusive", complete=False, reason="Budget hit."),
    ])
    a = prefill_ccpa_risk_assessment(snap, now=NOW)
    states = {s["key"]: s["state"] for s in a.safeguards}
    assert states == {
        "transport_encryption": "observed", "at_rest_encryption": "not_observed",
        "authentication": "not_assessed", "tenant_isolation": "partially_assessed",
        "network_exposure": "not_assessed", "erasure_verification": "not_assessed",
        "vulnerability_posture": "not_assessed"}
    auth = next(s for s in a.safeguards if s["key"] == "authentication")
    assert auth["reason"] == "Excluded."
    impacts = " ".join(i["statement"] for i in by_key(a)["negative_impacts"]["evidence"])
    assert "Encryption at rest was checked and not observed" in impacts
    assert a.completeness["safeguards"]["not_assessed"] == 4


def test_no_audit_evidence_never_reads_as_passed():
    a = prefill_ccpa_risk_assessment(snapshot(), now=NOW)
    assert {s["state"] for s in a.safeguards} == {"not_assessed"}
    els = by_key(a)
    assert els["pi_categories"]["status"] == "not_assessed"
    assert els["safeguards"]["status"] == "not_assessed"
    assert all(r["evidence_availability"] == "not_assessed"
               for r in a.cyberaudit_support)
    assert "incomplete evidence" in build_ccpa_risk_html(a).lower()


def test_business_inputs_merge_and_bad_inputs_are_reported():
    a = prefill_ccpa_risk_assessment(phi_snapshot(), now=NOW, business_inputs={
        "processing_activity": "Clinical notes assistant",
        "purpose": "Let nurses retrieve a patient's discharge instructions at the bedside.",
        "benefits": "To improve our services.",
        "will_initiate": True,
        "contributors": [{"name": "Dana Lee", "role": "ML engineer"}],
        "review_and_approval": {"date": "2026-09-01",
                                "approvers": [{"name": "Sam Roe", "position": "CPO"}]},
        "triggers": {"7150(b)(3)": {"applies": False}},
        "approximate_consumers": 50000,
        "bogus": "x",
        "assessment_completed": "not a date",
    })
    els = by_key(a)
    assert els["purpose"]["status"] == "business_provided"
    assert els["will_initiate"]["business_input"] == "Yes"
    assert els["admt_logic"]["status"] == "not_applicable"
    assert els["admt_output"]["status"] == "not_applicable"
    assert els["approximate_consumers"]["business_input"] == "50,000"
    assert els["approximate_consumers"]["status"] == "business_provided"
    assert els["review_and_approval"]["status"] == "business_provided"
    assert els["consumer_disclosures"]["status"] == "requires_business_input"
    assert a.processing_activity == "Clinical notes assistant"
    assert any("bogus" in p for p in a.input_problems)
    assert any("assessment_completed" in p for p in a.input_problems)
    assert any("benefits reads as generic" in n for n in a.review_notes)
    assert a.completeness["approved"] is True


def test_completeness_summary_counts():
    a = prefill_ccpa_risk_assessment(phi_snapshot(), now=NOW)
    comp = a.completeness
    assert comp["total"] == len(ELEMENTS)
    assert sum(comp["counts"].values()) == len(ELEMENTS)
    assert comp["summary"].startswith(f"{comp['counts']['prefilled']} of {len(ELEMENTS)} "
                                      "elements prefilled from evidence")
    assert "need business input" in comp["summary"]
    assert "%" not in comp["summary"]


def test_real_audit_result_object_is_accepted():
    conn = MemoryConnector({"docs": [chunk(1, text="Patient SSN 123-45-6789, MRN 12345678")]})
    result = run_full_audit(conn, classifier=RegexClassifier(),
                            include_integrity=False, include_posture=False)
    a = prefill_ccpa_risk_assessment(result, now=NOW, store="reg-kb")
    assert a.store == "reg-kb" and a.audit_id == result.id
    assert any(c["code"] == "ae1A" for c in a.categories)
    tls = next(s for s in a.safeguards if s["key"] == "transport_encryption")
    assert tls["state"] == "not_assessed"
    assert "123-45-6789" not in json.dumps(a.to_dict())


# ---- deadlines --------------------------------------------------------------

def test_deadlines_cite_7155_and_7157_and_date_from_inputs():
    rows = {d["key"]: d for d in deadlines(now=NOW)}
    assert rows["existing_processing"]["due"] == "2027-12-31"
    assert rows["existing_processing"]["citation"].endswith("§ 7155(b)")
    assert rows["agency_submission"]["due"] == "2028-04-01"
    assert rows["agency_submission"]["section"] == "7157(a)(1)"
    assert rows["periodic_review"]["section"] == "7155(a)(2)"
    assert rows["material_change"]["section"] == "7155(a)(3)"
    assert rows["retention"]["section"] == "7155(c)"
    assert rows["on_request"]["section"] == "7157(e)"
    assert rows["existing_processing"]["applies"] is None

    rows = {d["key"]: d for d in deadlines({
        "processing_started": "2024-02-29", "assessment_completed": "2028-02-29",
        "material_change_on": "2026-09-01"}, now=NOW)}
    assert rows["existing_processing"]["applies"] is True
    assert rows["periodic_review"]["due"] == "2031-02-28"
    assert rows["material_change"]["due"] == "2026-10-16"
    assert rows["material_change"]["days_remaining"] == 17
    assert rows["retention"]["due"] == "2033-02-28"
    assert rows["agency_submission"] == {**rows["agency_submission"],
                                         "section": "7157(a)(2)", "due": "2029-04-01"}


# ---- rendering --------------------------------------------------------------

def test_html_escapes_business_input_and_states_no_conclusion():
    evil = "<script>alert(1)</script>"
    a = prefill_ccpa_risk_assessment(phi_snapshot(), now=NOW, store="<img src=x>",
                                     business_inputs={"purpose": evil,
                                                      "contributors": [evil]})
    page = build_ccpa_risk_html(a)
    assert "<script>" not in page and "&lt;script&gt;" in page
    assert "<img src=x>" not in page
    assert "§ 7155(b)" in page or "7155(b)" in page
    assert "2028-04-01" in page and "2027-12-31" in page
    assert "Draft: no review and approval" in page


def test_no_compliance_conclusions_anywhere():
    a = prefill_ccpa_risk_assessment(phi_snapshot(outcomes=[
        outcome(c, "passed") for c in ("transport_encryption", "at_rest_encryption",
                                        "authentication", "tenant_isolation",
                                        "network_exposure", "erasure_verification",
                                        "server_vulnerability")]), now=NOW)
    for text in (json.dumps(a.to_dict()).lower(), build_ccpa_risk_html(a).lower()):
        for phrase in ("compliant", "in compliance", "not required", "no assessment needed",
                       "risk assessment is required", "does not apply to this business",
                       "approved by vecshield", "certified"):
            assert phrase not in text, phrase


def test_cyberaudit_mapping_reports_evidence_not_results():
    rows = {r["section"]: r for r in cyberaudit_7123_support(phi_snapshot(outcomes=[
        outcome("authentication", "passed"), outcome("at_rest_encryption", "passed")]))}
    assert rows["7123(c)(1)"]["evidence_availability"] == "evidence_available"
    assert rows["7123(c)(2)"]["evidence_availability"] == "partial_evidence"
    assert rows["7123(c)(16)"]["evidence_availability"] == "not_assessed"
    assert all("not that assessment" in r["note"] for r in rows.values())


def test_validate_business_inputs_bounds_and_reports():
    clean, problems = validate_business_inputs({
        "purpose": "x" * 20_000, "contributors": 42, "triggers": {"7150(b)(2)": "yes"}})
    assert len(clean["purpose"]) == 10_000
    assert any(p.startswith("contributors") for p in problems)
    assert any(p.startswith("triggers.7150(b)(2)") for p in problems)
