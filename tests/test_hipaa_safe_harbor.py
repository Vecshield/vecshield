"""The Safe Harbor map reports what it cannot see, not just what it found.

The point of this module is the negative space. Three of the eighteen
categories at 45 CFR 164.514(b)(2)(i) are invisible to a text classifier, so a
result that listed only "observed" and "not observed" would read as a clean
bill of health that the product has no basis for.
"""

from __future__ import annotations

import json

import pytest

from vecshield_platform.compliance.hipaa import (
    SAFE_HARBOR_CAVEAT,
    SAFE_HARBOR_IDENTIFIERS,
    SAFE_HARBOR_LETTERS,
    VENDOR_MANAGED_KINDS,
    SafeHarborIdentifier,
    business_associate_exposure,
    detectable_identifiers,
    evaluate_safe_harbor,
    get_identifier,
    safe_harbor_manifest,
    undetectable_identifiers,
    vendor_profile,
)


def test_all_eighteen_categories_are_present_exactly_once():
    letters = [i.letter for i in SAFE_HARBOR_IDENTIFIERS]
    assert letters == list(SAFE_HARBOR_LETTERS)
    assert len(letters) == 18
    assert len(set(letters)) == 18
    for identifier in SAFE_HARBOR_IDENTIFIERS:
        assert identifier.paraphrase
        assert identifier.citation.startswith("45 CFR 164.514(b)(2)(i)(")


def test_every_named_detector_and_entity_type_actually_exists():
    """A category may only claim a detector the classifier really ships."""
    from vecshield.classify.regex_classifier import DETECTORS

    detector_names = {d.name for d in DETECTORS}
    from vecshield.classify.presidio_classifier import _ENTITY_LABEL

    for identifier in SAFE_HARBOR_IDENTIFIERS:
        for name in identifier.detectors:
            assert name in detector_names, (identifier.letter, name)
        for entity in identifier.entity_types:
            assert entity in _ENTITY_LABEL, (identifier.letter, entity)


def test_a_category_cannot_claim_detection_without_a_detector():
    with pytest.raises(ValueError):
        SafeHarborIdentifier(letter="A", paraphrase="Names.")
    with pytest.raises(ValueError):
        SafeHarborIdentifier(letter="P", paraphrase="Biometrics.", detectable=False)
    with pytest.raises(ValueError):
        SafeHarborIdentifier(letter="S", paraphrase="Not a subparagraph.",
                             detectors=("email",))


def test_undetectable_categories_are_named_and_give_a_reason():
    undetectable = {i.letter for i in undetectable_identifiers()}
    # Biometrics, full-face images, and the open-ended residual category.
    # (P) moved out of this set when a biometric *reference* detector was
    # added: a note saying a voiceprint was enrolled is text, and text is
    # what this product reads. The template itself is still invisible,
    # which is why (P) is partial rather than covered.
    assert undetectable == {"Q", "R"}
    for identifier in undetectable_identifiers():
        assert identifier.undetectable_reason
    assert len(detectable_identifiers()) == 16


def test_absence_of_a_match_in_an_undetectable_category_is_reported_as_such():
    observation = evaluate_safe_harbor(["email", "medical_record_context"])
    assert observation.observed == ("F", "H")
    # The categories nothing can see are never in not_observed, because they
    # were never looked for.
    assert set(observation.undetectable) == {"Q", "R"}
    assert not set(observation.undetectable) & set(observation.not_observed)
    # (P) still belongs here: reference-level detection means a store
    # whose biometric data is only ever binary produces no signal at all.
    assert set(observation.absence_is_not_evidence) >= {"P", "Q", "R"}
    assert observation.conclusion is None

    record = observation.to_dict()
    assert record["conclusion"] is None
    assert [c["letter"] for c in record["undetectable"]] == ["Q", "R"]
    assert all(c["undetectable_reason"] for c in record["undetectable"])
    assert "not evidence that they are absent" in record["note"]
    assert SAFE_HARBOR_CAVEAT in record["note"]


def test_every_category_is_accounted_for_in_exactly_one_bucket():
    observation = evaluate_safe_harbor(["email", "PERSON", "vehicle_vin"])
    buckets = (set(observation.observed) | set(observation.not_observed)
               | set(observation.undetectable))
    assert buckets == set(SAFE_HARBOR_LETTERS)
    assert not set(observation.observed) & set(observation.not_observed)


def test_an_empty_run_observes_nothing_and_concludes_nothing():
    observation = evaluate_safe_harbor([])
    assert observation.observed == ()
    assert len(observation.not_observed) == 16
    assert observation.conclusion is None
    assert observation.to_dict()["conclusion"] is None


def test_matched_signals_are_reported_so_a_reviewer_can_check_the_mapping():
    observation = evaluate_safe_harbor(["us_zip_context", "county_name", "email"])
    assert observation.signals_by_letter["B"] == ("county_name", "us_zip_context")
    record = observation.to_dict()
    geography = next(c for c in record["observed"] if c["letter"] == "B")
    assert geography["matched_signals"] == ["county_name", "us_zip_context"]


def test_a_signal_that_maps_to_no_category_is_surfaced_not_dropped():
    observation = evaluate_safe_harbor(["aws_access_key", "email"])
    assert observation.unmapped_signals == ("aws_access_key",)
    assert observation.observed == ("F",)


def test_phone_and_fax_cannot_be_told_apart_and_the_map_says_so():
    observation = evaluate_safe_harbor(["us_phone"])
    assert observation.observed == ("D", "E")
    assert get_identifier("e").partial
    assert "cannot" in get_identifier("E").notes


def test_partially_covered_categories_carry_their_caveat():
    partial = [i for i in SAFE_HARBOR_IDENTIFIERS if i.partial]
    assert {i.letter for i in partial} >= {"B", "C", "E", "I", "J", "K", "M"}
    for identifier in partial:
        assert identifier.notes, identifier.letter
    # The three-digit ZIP rule is the classic trap and must be called out.
    assert "three-digit" in get_identifier("B").notes
    assert "Census" in get_identifier("B").notes


def test_categories_that_need_the_nlp_classifier_are_flagged():
    manifest = safe_harbor_manifest()
    # Names and URLs come only from Presidio; a regex-only deployment is blind
    # to them, and the manifest has to say so.
    assert manifest["requires_nlp_classifier"] == ["A", "N"]


def test_the_manifest_reports_coverage_without_claiming_a_conclusion():
    manifest = safe_harbor_manifest()
    assert manifest["categories"] == 18
    assert manifest["detectable"] == 16
    assert manifest["lifecycle"] == "draft"
    assert manifest["regulatory_review"] is None
    assert len(manifest["undetectable"]) == 2
    assert "does not perform one" in manifest["note"]
    assert "actual knowledge" in manifest["note"]
    blob = json.dumps(manifest)
    assert "%" not in blob and "score" not in blob.lower()


def test_unknown_letter_lookup_returns_none():
    assert get_identifier("Z") is None
    assert get_identifier("a").letter == "A"


# ---------------------------------------------------------------------------
# Business associate exposure implied by the connector estate
# ---------------------------------------------------------------------------

def test_vendor_managed_kinds_track_the_posture_engines_saas_list():
    """Both lists answer 'is this store operated by the provider?'."""
    from vecshield_platform.posture.network import MANAGED_SAAS_KINDS

    assert VENDOR_MANAGED_KINDS == MANAGED_SAAS_KINDS


def test_every_shipped_connector_kind_has_a_vendor_profile():
    import importlib
    import pkgutil

    import vecshield_platform.connectors as package
    from vecshield_platform.connectors.base import Connector

    kinds = set()
    for module in pkgutil.iter_modules(package.__path__):
        if module.name == "base":
            continue
        loaded = importlib.import_module(f"{package.__name__}.{module.name}")
        for value in vars(loaded).values():
            if (isinstance(value, type) and issubclass(value, Connector)
                    and value is not Connector
                    and value.__module__ == loaded.__name__):
                kinds.add(value.kind)
    assert kinds
    for kind in kinds:
        assert vendor_profile(kind) is not None, kind


def test_a_vendor_managed_store_names_the_vendor_a_baa_is_needed_for():
    exposure = business_associate_exposure([
        {"store_id": "a", "kind": "pinecone"},
        {"store_id": "b", "kind": "bedrock_kb"},
    ])
    assert exposure["vendors_requiring_a_baa"] == [
        "Amazon Web Services (Bedrock Knowledge Bases)", "Pinecone"]
    assert exposure["operator_not_established"] == []
    assert "does not observe whether a contract exists" in exposure["note"]
    assert "164.308(b)(1)" in exposure["note"]


def test_a_self_hostable_kind_is_not_called_self_hosted():
    """The connector kind does not settle who runs a Qdrant or a pgvector."""
    exposure = business_associate_exposure([{"store_id": "a", "kind": "pgvector"}])
    assert exposure["vendors_requiring_a_baa"] == []
    assert len(exposure["operator_not_established"]) == 1
    note = exposure["operator_not_established"][0]["note"]
    assert "does not say who operates" in note
    assert "self-hosted" not in exposure["vendor_managed_stores"]


def test_mongodb_atlas_ambiguity_is_stated_rather_than_guessed():
    exposure = business_associate_exposure([{"store_id": "a", "kind": "mongodb"}])
    assert exposure["vendors_requiring_a_baa"] == []
    assert "Atlas" in exposure["operator_not_established"][0]["note"]


def test_an_unrecognised_kind_is_reported_not_silently_treated_as_safe():
    exposure = business_associate_exposure([{"store_id": "a", "kind": "brand-new"}])
    assert exposure["unrecognised_kinds"] == [{"store_id": "a", "kind": "brand-new"}]
    assert exposure["vendor_managed_stores"] == []
    assert exposure["operator_not_established"] == []


def test_the_exposure_result_cites_maintained_source_records():
    from vecshield_platform.compliance.sources import resolve_sources

    exposure = business_associate_exposure([])
    for source in resolve_sources(exposure["source_ids"]):
        assert source["status"] != "unresolved"
        assert source["framework"] == "HIPAA"
