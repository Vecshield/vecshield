"""A finding should say why it fired and what argues against it."""

from __future__ import annotations


import pytest

from vecshield.classify import RegexClassifier
from vecshield.classify.surfaces import chunk_text_surfaces, classify_chunk
from vecshield.models import Chunk, Collection, VectorStore
from vecshield_platform.connectors.base import Connector
from vecshield_platform.explain import (
    CALIBRATED,
    CONFIDENCE_CLASSES,
    confidence_for,
    counter_signals,
    explain_example,
    explain_span,
    matched_text,
    summarize_causes,
)
from vecshield_platform.scan import scan_store


# ------------------------------- confidence --------------------------------- #

def test_no_detector_may_claim_a_confidence_nobody_measured():
    """The rule, not the corpus of the day.

    This originally asserted `CALIBRATED == {}`, which was a fact about the
    benchmark before it existed. Growing the corpus earned a detector a class
    and the test failed for no good reason. What must hold permanently is that
    an *unmeasured* detector claims nothing, whatever else has been measured.
    """
    for detector in ("never_measured", "some_new_detector"):
        assert detector not in CALIBRATED
        level, reason = confidence_for(detector, "likely")
        assert level == "uncertain"
        assert "No measured precision" in reason


def test_a_detector_may_not_claim_a_class_stronger_than_it_earned():
    """The shipped calibration grants only what the corpus supports.

    Proposing a class the detector has not earned yields the strongest one it
    *has* earned at or below the proposal — never something stronger, and
    never 'uncertain' while a weaker measured class exists.
    """
    from vecshield_platform.explain import CONFIDENCE_CLASSES

    for detector, permitted in CALIBRATED.items():
        for claim in ("likely", "possible"):
            granted = confidence_for(detector, claim)[0]
            assert CONFIDENCE_CLASSES.index(granted) >= CONFIDENCE_CLASSES.index(claim)
            if granted != "uncertain":
                assert granted in permitted
            else:
                assert not any(c in permitted for c in
                               CONFIDENCE_CLASSES[CONFIDENCE_CLASSES.index(claim):-1])


def test_a_measured_detector_may_claim_the_class_it_was_measured_at(monkeypatch):
    monkeypatch.setitem(CALIBRATED, "aws_access_key", {"likely"})
    assert confidence_for("aws_access_key", "likely")[0] == "likely"
    # ...and only that class.
    assert confidence_for("aws_access_key", "possible")[0] == "uncertain"
    # ...and only that detector.
    assert confidence_for("credit_card", "likely")[0] == "uncertain"


def test_an_unknown_confidence_class_is_refused():
    with pytest.raises(ValueError, match="unknown confidence class"):
        confidence_for("aws_access_key", "definitely")
    assert CONFIDENCE_CLASSES == ("likely", "possible", "uncertain")


# ---------------------------- counter-signals ------------------------------- #

def codes(*args, **kwargs):
    return [c.code for c in counter_signals(*args, **kwargs)]


def test_a_vendors_published_example_is_named_as_such():
    # This is the AWS documentation key. It is shaped exactly like a real one.
    assert "published_example" in codes("AKIAIOSFODNN7EXAMPLE")
    detail = counter_signals("AKIAIOSFODNN7EXAMPLE")[0].detail
    assert "documentation" in detail


def test_published_test_cards_are_named_despite_passing_a_checksum():
    # These pass a Luhn check by design, which is why a checksum cannot clear them.
    for card in ("4111 1111 1111 1111", "4111111111111111", "5555-5555-5555-4444",
                 "378282246310005"):
        assert "published_example" in codes(card), card


def test_the_published_ssn_example_is_named():
    assert "published_example" in codes("123-45-6789")


def test_vendor_test_prefixes_are_named():
    assert "vendor_test_prefix" in codes("sk_test_4eC39HqLyjWDarjtT1zdp7dc")
    assert "vendor_test_prefix" not in codes("sk_live_4eC39HqLyjWDarjtT1zdp7dc")


def test_reserved_domains_are_named():
    assert "reserved_domain" in codes("maya@example.com")
    assert "reserved_domain" in codes("someone@acme.test")
    assert "reserved_domain" not in codes("maya@realcompany.io")


def test_a_non_production_scope_is_named_from_collection_or_metadata():
    assert "non_production_scope" in codes("secret-value", collection="test_fixtures")
    assert "non_production_scope" in codes("secret-value", metadata={"env": "sandbox"})
    assert "non_production_scope" not in codes("secret-value", collection="prod_tickets")
    # Substring matches must not fire: "contest" is not "test".
    assert "non_production_scope" not in codes("secret-value", collection="contest_entries")


def test_a_quoted_value_is_flagged_as_possibly_an_example():
    quoted = 'Do not paste keys like `AKIA1234567890ABCDEF` into chat.'
    assert "quoted_in_text" in codes("AKIA1234567890ABCDEF", text=quoted)
    plain = "AKIA1234567890ABCDEF is the production key"
    assert "quoted_in_text" not in codes("AKIA1234567890ABCDEF", text=plain)


def test_a_real_looking_secret_in_a_real_collection_has_nothing_against_it():
    assert codes("AKIA1234567890ABCDEF", collection="prod_runbooks",
                 text="export AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF") == []


# ------------------------------- explanations ------------------------------- #

def test_an_explanation_masks_what_it_reports():
    span = {"detector": "aws_access_key", "label": "secret", "start": 0, "end": 20}
    explanation = explain_span(span, matched="AKIAIOSFODNN7EXAMPLE")
    assert "AKIAIOSFODNN7EXAMPLE" not in explanation.matched_preview
    assert explanation.matched_preview.startswith("AK")
    assert explanation.matched_preview.endswith("LE")
    assert explanation.disputed is True


def test_span_offsets_resolve_against_their_own_surface():
    # Offsets are per surface. Slicing a concatenation returns the wrong
    # characters, and every counter-signal drawn from them would be wrong.
    surfaces = {"text": "hello world", "metadata.note": "AKIAIOSFODNN7EXAMPLE"}
    span = {"detector": "aws_access_key", "surface": "metadata.note", "start": 0, "end": 20}
    assert matched_text(span, surfaces) == "AKIAIOSFODNN7EXAMPLE"
    # Reading the same offsets off the wrong surface would have given this:
    assert surfaces["text"][0:20] != matched_text(span, surfaces)


def test_a_span_without_a_surface_falls_back_predictably():
    assert matched_text({"start": 0, "end": 5}, {"text": "hello world"}) == "hello"
    assert matched_text({"start": 0, "end": 5}, {}) == ""
    assert matched_text({"detector": "x"}, {"text": "hello"}) == ""


def test_explanations_are_built_for_every_span_in_an_example(monkeypatch):
    # Pinned: this tests the explanation shape, not the corpus of the day.
    monkeypatch.setattr("vecshield_platform.explain.CALIBRATED", {})
    chunk = Chunk(id="c1", collection="fixtures",
                  text="Key AKIAIOSFODNN7EXAMPLE ok",
                  metadata={"note": "card 4111 1111 1111 1111"})
    result = classify_chunk(RegexClassifier(), chunk)
    surfaces = {s.name: s.text for s in chunk_text_surfaces(chunk)}
    explanations = explain_example({"spans": result.spans}, collection=chunk.collection,
                                   surfaces=surfaces, metadata=chunk.metadata)
    # One explanation per span. Two detectors may fire on the same digits
    # (credit_card and card_like_number), so pin the spans, not a count.
    assert len(explanations) == len(result.spans)
    assert {(e["start"], e["end"]) for e in explanations} == \
        {(s["start"], s["end"]) for s in result.spans}
    by_detector = {e["detector"]: e for e in explanations}
    assert {"aws_access_key", "credit_card"} <= set(by_detector)
    assert by_detector["aws_access_key"]["confidence"] == "uncertain"
    assert "published_example" in [c["code"] for c in
                                   by_detector["aws_access_key"]["counter_signals"]]
    assert "published_example" in [c["code"] for c in
                                   by_detector["credit_card"]["counter_signals"]]
    for explanation in explanations:
        assert "AKIAIOSFODNN7EXAMPLE" not in str(explanation)
        assert "4111" not in explanation["matched_preview"][2:-2]


# ------------------------------ end to end ---------------------------------- #

class MemoryConnector(Connector):
    kind = "memory"

    def __init__(self, data):
        self.data = data

    def describe(self):
        return VectorStore(kind=self.kind, name="memory", endpoint="memory://",
                           collections=self.list_collections())

    def list_collections(self):
        return [Collection(name=n, count=len(c)) for n, c in self.data.items()]

    def iter_chunks(self, collection, batch_size=256):
        yield from self.data[collection]


def test_a_scanned_finding_carries_its_explanations(monkeypatch):
    monkeypatch.setattr("vecshield_platform.explain.CALIBRATED", {})
    connector = MemoryConnector({"fixtures": [
        Chunk(id="1", collection="fixtures", text="Key AKIAIOSFODNN7EXAMPLE",
              metadata={"source": "docs"}, embedding=[0.1, 0.2]),
    ]})
    job = scan_store(connector, classifier=RegexClassifier())
    finding = next(f for f in job.findings if f.category == "data_classification")
    explanations = finding.evidence["explanations"]
    assert explanations, "a classification finding explains itself"
    assert explanations[0]["detector"] == "aws_access_key"
    assert explanations[0]["confidence"] == "uncertain"
    codes_found = [c["code"] for c in explanations[0]["counter_signals"]]
    assert "published_example" in codes_found
    assert "non_production_scope" in codes_found


def test_a_production_looking_secret_is_not_argued_against():
    connector = MemoryConnector({"runbooks": [
        Chunk(id="1", collection="runbooks",
              text="export AWS_ACCESS_KEY_ID=AKIA2X4YTHISISREAL99",
              metadata={"source": "ops"}, embedding=[0.1, 0.2]),
    ]})
    job = scan_store(connector, classifier=RegexClassifier())
    finding = next(f for f in job.findings if f.category == "data_classification")
    explanations = finding.evidence["explanations"]
    assert explanations
    assert explanations[0]["counter_signals"] == []
    assert explanations[0]["disputed"] is False


# -------------------------------- grouping ---------------------------------- #

def test_findings_group_by_the_signal_that_produced_them():
    findings = [
        {"severity": "critical", "collection": "a", "category": "data_classification",
         "evidence": {"explanations": [{"detector": "aws_access_key", "disputed": True}]}},
        {"severity": "critical", "collection": "b", "category": "data_classification",
         "evidence": {"explanations": [{"detector": "aws_access_key", "disputed": False}]}},
        {"severity": "high", "collection": "a", "category": "rag_integrity",
         "evidence": {"explanations": [{"detector": "prompt_injection", "disputed": False}]}},
    ]
    causes = summarize_causes(findings)
    assert [c["cause"] for c in causes] == ["aws_access_key", "prompt_injection"]
    assert causes[0]["findings"] == 2
    assert causes[0]["locations"] == ["a", "b"]
    assert causes[0]["disputed"] == 1, "one of the two has something against it"
    assert causes[0]["severities"] == {"critical": 2}


def test_a_finding_with_no_explanation_still_groups_somewhere():
    causes = summarize_causes([
        {"severity": "medium", "collection": "a", "category": "configuration_posture",
         "evidence": {}},
    ])
    assert causes[0]["cause"] == "configuration_posture"
    assert causes[0]["findings"] == 1


def test_grouping_an_empty_list_is_empty():
    assert summarize_causes([]) == []
    assert summarize_causes(None) == []


# --------------------------- malformed input -------------------------------- #
# A corpus run feeds thousands of items through this layer. One malformed item
# must not end the run, and must not produce a plausible-looking wrong answer.

def test_a_negative_or_reversed_offset_yields_nothing_not_a_wrong_substring():
    surfaces = {"text": "hello world"}
    # Python would slice from the end and return "hell", which every
    # counter-signal would then be computed against.
    assert matched_text({"surface": "text", "start": -5, "end": -1}, surfaces) == ""
    assert matched_text({"surface": "text", "start": 9, "end": 2}, surfaces) == ""
    assert matched_text({"surface": "text", "start": "0", "end": "5"}, surfaces) == ""
    assert matched_text(None, surfaces) == ""


def test_an_offset_past_the_end_returns_what_there_is():
    assert matched_text({"surface": "text", "start": 0, "end": 999}, {"text": "hi"}) == "hi"


def test_one_malformed_span_does_not_lose_the_others():
    explanations = explain_example(
        {"spans": [None, "nonsense", {"detector": "x", "surface": "text",
                                      "start": 0, "end": 2}]},
        surfaces={"text": "hi there"})
    assert len(explanations) == 1
    assert explanations[0]["detector"] == "x"


def test_explaining_nothing_is_empty_rather_than_an_error():
    assert explain_example({}, surfaces={}) == []
    assert explain_example(None, surfaces=None) == []


def test_grouping_tolerates_malformed_findings():
    causes = summarize_causes([
        None, "nonsense", {"evidence": None},
        {"evidence": {"explanations": [None, {"detector": "real"}]}},
    ])
    by_cause = {c["cause"]: c for c in causes}
    assert "real" in by_cause
    assert by_cause["real"]["findings"] == 1


def test_counter_signals_tolerate_non_string_metadata():
    # Metadata comes from customer stores and is not guaranteed to be strings.
    assert counter_signals("x", metadata={"n": 5, "b": None, "l": [1, 2]}) == []
    assert counter_signals("x", collection="a.*+[test]")[0].code == "non_production_scope"
    assert counter_signals(None) == []
    assert counter_signals("") == []


def test_a_detector_at_possible_degrades_from_likely_rather_than_vanishing(monkeypatch):
    """Proposing 'likely' for a detector measured at 'possible' must yield
    'possible' — not 'uncertain' with a message denying any measurement."""
    monkeypatch.setitem(CALIBRATED, "aws_access_key", {"possible"})
    level, reason = confidence_for("aws_access_key", "likely")
    assert level == "possible"
    assert "supports 'possible', not 'likely'" in reason
    assert "No measured precision" not in reason
    # Proposing 'possible' directly is simply granted.
    assert confidence_for("aws_access_key", "possible")[0] == "possible"
