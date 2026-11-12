"""A policy template must not read as a compliance conclusion."""

from __future__ import annotations

import pytest

from vecshield_platform.api.templates import (
    CONFIDENCE_CLASSES,
    POLICY_TEMPLATES,
    enriched_policy_templates,
)
from vecshield_platform.compliance.sources import (
    LIFECYCLE,
    SOURCES,
    RegulatorySource,
    resolve_sources,
)


def by_id():
    return {t["id"]: t for t in enriched_policy_templates()}


def test_every_template_cites_a_maintained_source_record():
    for template in enriched_policy_templates():
        sources = template["attribution"]["sources"]
        assert sources, f"{template['id']} has no source record"
        assert template["attribution"]["unresolved"] == []
        for source in sources:
            assert source["issuer"] and source["title"]
            assert source["framework"] in (template["regulation"], "General")


def test_attribution_is_not_parsed_from_the_display_name():
    template = dict(next(t for t in POLICY_TEMPLATES
                         if t["id"] == "gdpr-pii-invertible"))
    template["name"] = "Renamed by an operator (Art. 999)"
    enriched = enriched_policy_templates([template])[0]
    assert enriched["attribution"]["citation"] == "Art. 32"
    assert "999" not in enriched["attribution"]["source_text"]


def test_unresolved_source_reference_is_visible_not_dropped():
    template = dict(next(t for t in POLICY_TEMPLATES if t["id"] == "hipaa-phi"))
    template["source_ids"] = ["hipaa-164-312", "not-a-source"]
    enriched = enriched_policy_templates([template])[0]
    assert enriched["attribution"]["unresolved"] == ["not-a-source"]
    assert len(enriched["attribution"]["sources"]) == 2


def test_no_source_claims_a_review_or_a_retrieval_it_did_not_have():
    for source in SOURCES.values():
        assert source.lifecycle in LIFECYCLE
        assert source.lifecycle != "regulatory_reviewed"
        # verified means the provision text was fetched and hashed by a build.
        assert source.verified is False
    for template in enriched_policy_templates():
        assert template["attribution"]["reviewed"] is False
        assert template["attribution"]["verified"] is False


def test_licensed_standards_are_linked_not_reproduced():
    for source_id in ("pci-dss-req-3", "pci-dss-req-8", "tsc-cc6-1"):
        source = SOURCES[source_id]
        assert source.redistributable is False
        assert source.url and source.section


def test_regulated_templates_require_an_applicability_decision():
    templates = by_id()
    for template_id in ("hipaa-phi", "pci-pan", "ccpa-personal-info",
                        "aiact-data-governance", "soc2-secrets"):
        template = templates[template_id]
        assert template["requires_applicability_decision"] is True
        assert set(template["applicability"].values()) == {"requires_confirmation"}
        assert template["evidence"]["requires_reviewer_decision"] is True
    # The internal baseline asserts no obligation, so it needs no decision.
    assert templates["sec-secrets"]["requires_applicability_decision"] is False


def test_evidence_states_its_reach_and_limits():
    for template in enriched_policy_templates():
        evidence = template["evidence"]
        assert evidence["confidence"] in CONFIDENCE_CLASSES
        assert evidence["detects"] and evidence["does_not_establish"]
        assert len(evidence["limitations"]) >= 2


def test_descriptions_do_not_assert_unobservable_conclusions():
    # The classifier sees patterns in text; it cannot conclude that content *is*
    # protected health information or a live account number.
    banned = ("Protected health information found", "Personal data found",
              "Primary account numbers in a vector store",
              "the vectors themselves leak personal data",
              "Consumer personal info found")
    for template in POLICY_TEMPLATES:
        for phrase in banned:
            assert phrase not in template["description"], template["id"]


def test_source_records_reject_invented_vocabularies():
    with pytest.raises(ValueError):
        RegulatorySource(id="x", framework="F", issuer="I", title="T", kind="vibes")
    with pytest.raises(ValueError):
        RegulatorySource(id="x", framework="F", issuer="I", title="T",
                         kind="regulation", lifecycle="approved-ish")


def test_resolve_sources_preserves_request_order():
    ids = ["aiact-art-15", "gdpr-art-5", "unknown-one"]
    assert [s["id"] for s in resolve_sources(ids)] == ids


def test_policy_template_api_serves_the_governance_fields(tmp_path):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from vecshield_platform.api import create_app
    from vecshield_platform.api.config_store import ConfigStore

    app = create_app(config_store=ConfigStore(path=str(tmp_path / "config.json")),
                     serve_ui=False)
    client = TestClient(app)
    try:
        templates = {t["id"]: t for t in
                     client.get("/admin/policy-templates").json()["templates"]}
        phi = templates["hipaa-phi"]
        assert phi["attribution"]["sources"][0]["issuer"]
        assert phi["attribution"]["reviewed"] is False
        assert phi["requires_applicability_decision"] is True
        assert phi["evidence"]["does_not_establish"]
        assert phi["evidence"]["limitations"]
    finally:
        app.state.jobs.shutdown(wait=False)


def test_instantiating_a_template_keeps_its_source_reference(tmp_path):
    from vecshield_platform.api.config_store import ConfigStore

    config = ConfigStore(path=str(tmp_path / "config.json"))
    policy = config.add_policy_from_template("hipaa-phi", scope_store="prod")
    assert policy.template_id == "hipaa-phi"
    # The stored policy carries the reworded description, not a conclusion.
    assert "Protected health information found" not in policy.description


# ---------------------------------------------------------------------------
# HIPAA templates cite specific provisions and fire on real conditions
# ---------------------------------------------------------------------------

#: The `when` fields the policy engine actually evaluates
#: (vecshield_platform/compliance/policy.py, Policy.matches).
WHEN_FIELDS = {"category", "store", "collection", "min_severity",
               "requires_label", "evidence_gte"}

#: Finding categories the scan engine emits.
EMITTED_CATEGORIES = {"data_classification", "isolation", "rag_integrity",
                      "network_exposure", "transport_encryption", "cve", "any",
                      # crypto posture (posture/engine.py, crypto/*)
                      "transport_tls_enforcement", "tls_certificate_verification",
                      "at_rest_encryption", "data_representation",
                      "pan_representation", "retrieval_exposure"}


def test_no_template_invents_a_condition_field_the_engine_ignores():
    for template in POLICY_TEMPLATES:
        unknown = set(template["when"]) - WHEN_FIELDS
        assert not unknown, (template["id"], unknown)
        category = template["when"].get("category")
        if category is not None:
            wanted = category if isinstance(category, list) else [category]
            assert set(wanted) <= EMITTED_CATEGORIES, (template["id"], category)
        assert template["category"] in EMITTED_CATEGORIES, template["id"]


def test_every_template_condition_can_match_a_real_finding():
    """A rule nobody's findings can satisfy is worse than no rule."""
    from vecshield.models import Finding, Severity
    from vecshield_platform.compliance.policy import Policy

    for template in POLICY_TEMPLATES:
        when = template["when"]
        evidence = {"label_counts": {when["requires_label"]: 1}} if "requires_label" in when else {}
        for path, value in (when.get("evidence_gte") or {}).items():
            cursor = evidence
            parts = path.split(".")
            for part in parts[:-1]:
                cursor = cursor.setdefault(part, {})
            cursor[parts[-1]] = value
        category = when.get("category", template["category"])
        policy = Policy(id=template["id"], description="d", when=dict(when),
                        action=template["action"])
        for each in (category if isinstance(category, list) else [category]):
            finding = Finding(
                id="f-1", title="t", severity=Severity.CRITICAL, category=each,
                store="s", collection="c", description="d", evidence=evidence)
            assert policy.matches(finding), (template["id"], each)


def test_a_policy_may_name_several_categories():
    from vecshield.models import Finding, Severity
    from vecshield_platform.compliance.policy import Policy

    policy = Policy(id="p", description="d", action="a",
                    when={"category": ["transport_encryption",
                                       "transport_tls_enforcement"]})

    def finding(category):
        return Finding(id="f", title="t", severity=Severity.HIGH, category=category,
                       store="s", description="d")

    assert policy.matches(finding("transport_tls_enforcement"))
    assert policy.matches(finding("transport_encryption"))
    assert not policy.matches(finding("network_exposure"))


def test_hipaa_templates_cite_specific_provisions_not_the_bare_section():
    hipaa = [t for t in enriched_policy_templates() if t["regulation"] == "HIPAA"]
    assert {t["id"] for t in hipaa} == {
        "hipaa-phi", "hipaa-phi-invertible", "hipaa-min-necessary",
        "hipaa-deident-identifiers", "hipaa-store-publicly-reachable",
        "hipaa-transmission-plaintext", "hipaa-cross-tenant",
        "hipaa-corpus-integrity"}
    for template in hipaa:
        assert template["attribution"]["unresolved"] == []
        sections = [s["section"] for s in template["attribution"]["sources"]]
        # "45 CFR 164.312" on its own is the vague citation this work replaced.
        assert "45 CFR 164.312" not in sections, template["id"]
        for section in sections:
            assert section.startswith("45 CFR 16"), (template["id"], section)


def test_the_new_hipaa_templates_reach_beyond_the_security_rule():
    by = by_id()
    sections = {t: [s["section"] for s in by[t]["attribution"]["sources"]]
                for t in by if by[t]["regulation"] == "HIPAA"}
    flat = [s for group in sections.values() for s in group]
    # Privacy Rule
    assert "45 CFR 164.502(b)" in flat
    assert "45 CFR 164.514(b)(2)" in flat
    # Breach Notification Rule
    assert "45 CFR 164.402" in flat


def test_the_deidentification_template_admits_what_it_cannot_see():
    limits = " ".join(by_id()["hipaa-deident-identifiers"]["evidence"]["limitations"])
    assert "biometric" in limits
    assert "full-face" in limits
    assert "not observable" in limits or "not observable by this product" in limits
    does_not = by_id()["hipaa-deident-identifiers"]["evidence"]["does_not_establish"]
    assert "actual knowledge" in does_not


def test_the_addressable_template_does_not_read_as_optional():
    template = by_id()["hipaa-transmission-plaintext"]
    limits = " ".join(template["evidence"]["limitations"])
    assert "164.306(d)(3)" in limits
    assert "Addressable is not optional" in limits


def test_the_breach_template_scopes_itself_to_factors_one_and_two():
    limits = " ".join(by_id()["hipaa-cross-tenant"]["evidence"]["limitations"])
    assert "first two factors" in limits
    assert "cannot speak to whether the information was acquired or viewed" in limits
    assert "presumed to be a breach" in limits


def test_no_template_reports_a_score_or_a_percentage():
    import json

    blob = json.dumps(enriched_policy_templates())
    assert "%" not in blob
    assert "percent" not in blob.lower()
    assert "compliance score" not in blob.lower()
