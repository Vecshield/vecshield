"""Staged actions: what gets proposed, what gets refused, and what the diff says.

Each test here pins a refusal. The module's value is not that it can build a
plan — it is that it declines to build the wrong one and says why.
"""

from __future__ import annotations

import pytest

from vecshield.models import Chunk, Collection
from vecshield_platform import actions
from vecshield_platform.actions import (
    ACTION_TEMPLATES,
    ActionError,
    blast_radius,
    capability_verdict,
    diff,
    format_diff,
    is_stale,
    resolve_targets,
    stage,
    suggest,
    suggest_all,
    warnings_for,
)
from vecshield_platform.connectors.base import Connector


# --------------------------------------------------------------------------- #
# Doubles                                                                      #
# --------------------------------------------------------------------------- #

class ReadOnlyStore(Connector):
    """A store that can be read and nothing else."""

    kind = "readonly"

    def __init__(self, chunks=None, count=300):
        self._chunks = chunks if chunks is not None else [
            Chunk(id="c1", collection="runbooks", text="key AKIAIOSFODNN7EXAMPLE here"),
        ]
        self._count = count

    def describe(self):
        return None

    def capabilities(self):
        return set()

    def list_collections(self):
        return [Collection(name="runbooks", count=self._count)]

    def iter_chunks(self, collection, batch_size=256):
        yield from (c for c in self._chunks if c.collection == collection)


class DeletingStore(ReadOnlyStore):
    kind = "deleting"

    def capabilities(self):
        return {"delete"}

    def delete_chunks(self, collection, ids):
        return len(ids)


class LyingStore(ReadOnlyStore):
    """Declares capabilities it has no methods for."""

    kind = "lying"

    def capabilities(self):
        return {"write", "redact", "metadata_write", "delete"}


class InheritingStore(ReadOnlyStore):
    """Declares 'delete' and leaves the base's raising stub in place."""

    kind = "inheriting"

    def capabilities(self):
        return {"delete"}


class TaggingStore(ReadOnlyStore):
    kind = "tagging"

    def capabilities(self):
        return {"metadata_write"}

    def set_chunk_metadata(self, collection, updates):
        return len(updates)


def finding(**overrides):
    base = {
        "id": "f1",
        "store": "demo",
        "collection": "runbooks",
        "evidence": {
            "labels": {"SECRET": 3},
            "sensitive_chunks": 300,
            "examples": [
                {"chunk_id": "c1", "label": "SECRET", "detectors": ["aws_access_key"]},
                {"chunk_id": "c2", "label": "SECRET", "detectors": ["aws_access_key"]},
            ],
        },
    }
    base.update(overrides)
    return base


@pytest.fixture(autouse=True)
def uncalibrated(monkeypatch):
    """Pin the calibration these tests assume, rather than reading the shipped one.

    These test suggestion *logic*. Reading `benchmark/calibration.json` made them
    change meaning when the corpus grew and a detector earned 'possible', which
    turned a corpus improvement into unrelated test failures. What each test
    needs is stated here instead.
    """
    monkeypatch.setattr(actions, "CALIBRATED", {})


@pytest.fixture
def calibrated(monkeypatch):
    """A detector measured at the strongest class, to reach the gated paths."""
    monkeypatch.setattr(actions, "CALIBRATED",
                        {"aws_access_key": {"likely", "possible"}})


# --------------------------------------------------------------------------- #
# Suggest                                                                      #
# --------------------------------------------------------------------------- #

def test_irreversible_actions_are_withheld_from_an_unmeasured_detector():
    """A delete is a recommendation to destroy data. It needs a measurement."""
    suggestions, withheld = suggest(finding())
    assert [s.action for s in suggestions] == [
        "label_sensitivity", "tag_exclude", "quarantine_collection"]
    refused = {w.action for w in withheld}
    assert refused == {"delete_chunks", "redact_text"}
    reason = next(w.reason for w in withheld if w.action == "delete_chunks")
    assert "aws_access_key" in reason and "uncertain" in reason


def test_a_reversible_action_may_rest_on_an_unmeasured_detector_and_says_so():
    suggestions, _ = suggest(finding())
    tag = next(s for s in suggestions if s.action == "tag_exclude")
    assert tag.calibrated is False
    assert "no measured precision" in tag.rationale
    assert "reversible" in tag.rationale


def test_calibration_unlocks_the_irreversible_action(calibrated):
    suggestions, withheld = suggest(finding())
    assert "delete_chunks" in {s.action for s in suggestions}
    assert not [w for w in withheld if w.action == "delete_chunks"]
    assert all(s.calibrated for s in suggestions)


def test_refusals_are_returned_rather_than_dropped():
    """A reader seeing three proposals is entitled to know two were refused."""
    suggestions, withheld = suggest(finding())
    assert len(suggestions) == 3 and len(withheld) == 2


def test_a_finding_with_no_chunk_ids_suggests_nothing_and_explains_why():
    record = finding()
    record["evidence"]["examples"] = []
    record["evidence"]["labels"] = {"SECRET": 3}
    suggestions, withheld = suggest(record)
    assert not [s for s in suggestions if s.action != "quarantine_collection"]
    assert any("retained no chunk ids" in w.reason for w in withheld)


def test_an_unlabelled_finding_proposes_nothing_rather_than_guessing():
    record = finding()
    record["evidence"] = {"examples": []}
    suggestions, withheld = suggest(record)
    assert suggestions == []
    assert any("no classified label" in w.reason for w in withheld)


def test_a_finding_without_a_store_is_refused():
    with pytest.raises(ActionError):
        suggest({"id": "f1", "evidence": {}})


def test_suggest_all_records_a_broken_finding_instead_of_failing_the_batch():
    suggestions, withheld = suggest_all([finding(), {"id": "bad"}])
    assert suggestions
    assert any(w.finding_id == "bad" for w in withheld)


def test_the_gap_between_observed_and_named_chunks_is_carried():
    """The finding saw 300; it kept 2 ids. The suggestion says both numbers."""
    suggestion = next(x for x in suggest(finding())[0] if x.action == "tag_exclude")
    assert suggestion.observed_chunks == 300
    assert suggestion.named_chunks == 2
    assert suggestion.to_dict()["reaches_all_observed"] is False


# --------------------------------------------------------------------------- #
# Capability                                                                   #
# --------------------------------------------------------------------------- #

def test_a_declared_capability_with_no_method_behind_it_is_not_supported():
    """A capability set is a promise; the method is what keeps it."""
    supported, reason = capability_verdict(LyingStore(), ACTION_TEMPLATES["redact_text"])
    assert supported is False
    assert "raises rather than acting" in reason      # base stub, never overridden


def test_an_inherited_raising_stub_is_not_an_implementation():
    supported, reason = capability_verdict(InheritingStore(), ACTION_TEMPLATES["delete_chunks"])
    assert supported is False
    assert "raises rather than acting" in reason


def test_a_real_implementation_is_supported():
    supported, reason = capability_verdict(DeletingStore(), ACTION_TEMPLATES["delete_chunks"])
    assert supported is True
    assert "delete_chunks()" in reason


def test_an_undeclared_capability_is_blocked_at_staging():
    supported, reason = capability_verdict(ReadOnlyStore(), ACTION_TEMPLATES["tag_exclude"])
    assert supported is False
    assert "does not declare 'metadata_write'" in reason


def test_a_connector_that_cannot_report_capabilities_is_not_assumed_capable():
    class Broken(ReadOnlyStore):
        def capabilities(self):
            raise RuntimeError("connection reset")

    supported, reason = capability_verdict(Broken(), ACTION_TEMPLATES["delete_chunks"])
    assert supported is False
    assert "could not report its capabilities" in reason


# --------------------------------------------------------------------------- #
# Stage                                                                        #
# --------------------------------------------------------------------------- #

def test_staging_resolves_targets_against_the_store_as_it_is_now(calibrated):
    """c1 is there, c2 is not. The plan records both, and does not delete c2."""
    plan = stage(suggest(finding())[0], connector=DeletingStore(), store="demo",
                 staged_by="kim")
    delete = next(op for op in plan.operations if op.action == "delete_chunks")
    assert [t.chunk_id for t in delete.present] == ["c1"]
    assert [t.chunk_id for t in delete.missing] == ["c2"]
    # Recognisable, and masked: the key itself is not republished in the plan.
    assert delete.present[0].preview.startswith("key AK")
    assert "AKIAIOSFODNN7EXAMPLE" not in delete.present[0].preview


def test_a_blocked_operation_leaves_its_targets_unchecked_not_absent():
    """We did not look, so we do not know. Reporting them as gone would be a lie."""
    plan = stage(suggest(finding())[0], connector=ReadOnlyStore(), store="demo",
                 staged_by="kim")
    tag = next(op for op in plan.operations if op.action == "tag_exclude")
    assert tag.supported is False
    assert tag.missing == ()
    assert len(tag.unchecked) == 2
    assert blast_radius(plan)["chunks_missing"] == 0
    # Two chunk-scoped operations (label and tag), two chunks each, none looked at.
    assert blast_radius(plan)["chunks_unchecked"] == 4


def test_a_plan_reaching_one_store_refuses_a_suggestion_for_another():
    suggestions = suggest(finding())[0]
    with pytest.raises(ActionError, match="different store"):
        stage(suggestions, connector=ReadOnlyStore(), store="other", staged_by="kim")


def test_a_plan_records_who_staged_it():
    with pytest.raises(ActionError, match="who staged it"):
        stage(suggest(finding())[0], connector=ReadOnlyStore(), store="demo", staged_by="")


def test_an_empty_plan_is_refused():
    with pytest.raises(ActionError, match="at least one suggestion"):
        stage([], connector=ReadOnlyStore(), store="demo", staged_by="kim")


def test_a_store_that_cannot_be_read_is_not_staged_against():
    class Unreachable(ReadOnlyStore):
        def list_collections(self):
            raise ConnectionError("no route to host")

    with pytest.raises(ActionError, match="cannot fingerprint"):
        stage(suggest(finding())[0], connector=Unreachable(), store="demo", staged_by="kim")


def test_the_plan_hash_covers_the_operations(calibrated):
    plan = stage(suggest(finding())[0], connector=DeletingStore(), store="demo",
                 staged_by="kim")
    before = plan.plan_hash
    trimmed = actions.ActionPlan(
        id=plan.id, store=plan.store, staged_by=plan.staged_by, staged_at=plan.staged_at,
        operations=plan.operations[:1], store_fingerprint=plan.store_fingerprint)
    assert trimmed.plan_hash != before


def test_equal_plans_hash_equally(calibrated):
    kwargs = dict(connector=DeletingStore(), store="demo", staged_by="kim")
    one = stage(suggest(finding())[0], **kwargs)
    two = actions.ActionPlan(id="other", store=one.store, staged_by=one.staged_by,
                            staged_at="later", operations=one.operations,
                            store_fingerprint=one.store_fingerprint)
    assert one.plan_hash == two.plan_hash   # the id and time are not the plan


def test_resolve_targets_stops_once_every_id_is_found():
    """A short-circuit, so a plan over three ids does not read a million chunks."""
    read = []

    class Counting(ReadOnlyStore):
        def iter_chunks(self, collection, batch_size=256):
            for index in range(1000):
                read.append(index)
                yield Chunk(id=f"c{index}", collection=collection, text="x")

    targets = resolve_targets(Counting(), "runbooks", ["c0", "c1"])
    assert all(t.present for t in targets)
    assert len(read) == 2


def test_resolving_no_ids_does_not_read_the_store():
    class Explodes(ReadOnlyStore):
        def iter_chunks(self, collection, batch_size=256):
            raise AssertionError("should not have been read")

    assert resolve_targets(Explodes(), "runbooks", []) == ()


# --------------------------------------------------------------------------- #
# Staleness                                                                    #
# --------------------------------------------------------------------------- #

def test_a_plan_is_stale_when_the_store_shape_changes(calibrated):
    store = DeletingStore()
    plan = stage(suggest(finding())[0], connector=store, store="demo", staged_by="kim")
    assert is_stale(plan, store)[0] is False
    assert is_stale(plan, DeletingStore(count=299))[0] is True


def test_a_plan_is_stale_when_a_targeted_chunk_changed(calibrated):
    store = DeletingStore()
    plan = stage(suggest(finding())[0], connector=store, store="demo", staged_by="kim")
    store._chunks = [Chunk(id="c1", collection="runbooks", text="something else entirely")]
    stale, reason = is_stale(plan, store)
    assert stale is True
    assert "has changed since staging" in reason


def test_a_plan_is_stale_when_a_targeted_chunk_is_gone(calibrated):
    store = DeletingStore()
    plan = stage(suggest(finding())[0], connector=store, store="demo", staged_by="kim")
    store._chunks = []
    stale, reason = is_stale(plan, store)
    assert stale is True
    assert "has gone since staging" in reason


def test_a_store_that_cannot_be_re_read_counts_as_stale(calibrated):
    plan = stage(suggest(finding())[0], connector=DeletingStore(), store="demo",
                 staged_by="kim")

    class Gone(DeletingStore):
        def list_collections(self):
            raise ConnectionError("gone")

    stale, reason = is_stale(plan, Gone())
    assert stale is True
    assert "cannot be trusted" in reason


# --------------------------------------------------------------------------- #
# Diff                                                                         #
# --------------------------------------------------------------------------- #

def test_the_diff_leads_with_what_cannot_be_undone(calibrated):
    report = diff(stage(suggest(finding())[0], connector=DeletingStore(), store="demo",
                        staged_by="kim"))
    assert "permanently deleted" in report["warnings"][0]
    assert "cannot be undone" in report["warnings"][0]


def test_the_diff_says_the_plan_does_not_resolve_the_finding(calibrated):
    """300 observed, 1 reachable. Executing it is not a fix, and it says so."""
    report = diff(stage(suggest(finding())[0], connector=DeletingStore(), store="demo",
                        staged_by="kim"))
    assert any("does not resolve the findings" in w for w in report["warnings"])
    assert report["blast_radius"]["reaches_all_observed"] is False


def test_the_diff_never_claims_to_execute(calibrated):
    report = diff(stage(suggest(finding())[0], connector=DeletingStore(), store="demo",
                        staged_by="kim"))
    assert report["executes"] is False
    assert "writes nothing to the store" in report["execution_note"]
    assert "Only an approved plan is executed" in report["execution_note"]


def test_an_inert_plan_says_it_is_not_something_to_approve():
    report = diff(stage(suggest(finding())[0], connector=ReadOnlyStore(), store="demo",
                        staged_by="kim"))
    assert any("not something to approve" in w for w in report["warnings"])


def test_the_diff_shows_a_sample_of_what_would_be_destroyed(calibrated):
    report = diff(stage(suggest(finding())[0], connector=DeletingStore(), store="demo",
                        staged_by="kim"))
    delete = next(op for op in report["operations"] if op["action"] == "delete_chunks")
    assert delete["sample"][0]["preview"].startswith("key AK")
    assert "AKIAIOSFODNN7EXAMPLE" not in delete["sample"][0]["preview"]


def test_a_supported_reversible_action_stages_and_reads_clean():
    plan = stage(suggest(finding())[0], connector=TaggingStore(), store="demo",
                 staged_by="kim")
    tag = plan.operations[0]
    assert tag.supported is True
    assert [t.chunk_id for t in tag.present] == ["c1"]
    report = diff(plan)
    assert not any("permanently deleted" in w for w in report["warnings"])
    assert any("no measured precision" in w for w in report["warnings"])


def test_warnings_are_computed_from_the_stored_plan(calibrated):
    """The stored body is what a person approves, so it must warn identically."""
    plan = stage(suggest(finding())[0], connector=DeletingStore(), store="demo",
                 staged_by="kim")
    assert warnings_for(plan.to_dict()) == diff(plan)["warnings"]


def test_format_diff_marks_the_irreversible_operation(calibrated):
    text = format_diff(diff(stage(suggest(finding())[0], connector=DeletingStore(),
                                  store="demo", staged_by="kim")))
    assert "IRREVERSIBLE" in text
    assert "It cannot be undone" in text


def test_the_unreachable_remainder_is_what_proposes_a_quarantine():
    """No per-chunk action covers 300 observed chunks named by 2 ids."""
    suggestions, _ = suggest(finding())
    quarantine = next(s for s in suggestions if s.action == "quarantine_collection")
    assert "retained only 2 id(s)" in quarantine.rationale
    assert "reaches what was observed" in quarantine.rationale


def test_a_finding_fully_covered_by_its_ids_does_not_propose_a_quarantine():
    """Quarantine answers a gap. With no gap there is nothing for it to answer."""
    record = finding()
    record["evidence"]["sensitive_chunks"] = 2
    suggestions, _ = suggest(record)
    assert "quarantine_collection" not in {s.action for s in suggestions}


def test_one_finding_is_counted_once_however_many_actions_answer_it():
    """Several proposals for one finding are several answers to one observation.

    Summing per operation reported 80 sensitive chunks for a finding that saw
    40, which overstates the problem in the one number a reader trusts.
    """
    plan = stage(suggest(finding())[0], connector=ReadOnlyStore(), store="demo",
                 staged_by="kim")
    assert len(plan.operations) == 3
    assert blast_radius(plan)["chunks_observed_by_findings"] == 300


def test_a_collection_scoped_operation_is_runnable_without_chunk_targets():
    """Requiring chunk targets of it reported a supported quarantine as blocked."""
    class Both(ReadOnlyStore):
        def capabilities(self):
            return {"metadata_write", "collection_metadata_write"}

        def set_chunk_metadata(self, collection, updates):
            return len(updates)

        def set_collection_metadata(self, collection, updates):
            return True

    plan = stage(suggest(finding())[0], connector=Both(), store="demo", staged_by="kim")
    quarantine = next(op for op in plan.operations
                      if op.action == "quarantine_collection")
    assert quarantine.targets == () and quarantine.runnable is True
    assert len(plan.executable) == 3
    assert blast_radius(plan)["blocked"] == 0
    assert not any("cannot run against this connector" in w
                   for w in warnings_for(plan.to_dict()))


# --------------------------------------------------------------------------- #
# The evidence shape the scan engine actually writes                           #
# --------------------------------------------------------------------------- #

def scanned_classification_finding():
    """A finding shaped as `scan/engine.py` emits it — not as the earlier tests
    imagined it. The keys are `label_counts` and `sensitive`; there is no
    `labels` and no `sensitive_chunks`."""
    return {
        "id": "f-real", "store": "demo", "collection": "patient_correspondence",
        "category": "data_classification", "title": "PHI detected in collection 'x'",
        "evidence": {
            "label_counts": {"pii": 5, "phi": 6}, "sensitive": 7, "scanned": 13,
            "examples": [{"chunk_id": f"c{i}", "label": "phi",
                          "detectors": ["medical_record_context"]} for i in range(5)],
        },
    }


def scanned_injection_finding():
    return {
        "id": "f-inj", "store": "demo", "collection": "incident_timeline",
        "category": "rag_integrity",
        "title": "Prompt-injection content in 'incident_timeline'",
        "evidence": {
            "count": 3, "scanned": 12,
            "examples": [{"chunk_id": "c2", "score": 0.9,
                          "categories": ["instruction_override"], "spans": []},
                         {"chunk_id": "c4", "score": 0.8,
                          "categories": ["role_manipulation"], "spans": []}],
        },
    }


def test_a_real_classification_finding_reports_the_gap_it_actually_has():
    """7 sensitive, 5 retained. With the wrong key this read as 5 of 5."""
    suggestions, _ = suggest(scanned_classification_finding())
    tag = next(s for s in suggestions if s.action == "tag_exclude")
    assert (tag.observed_chunks, tag.named_chunks) == (7, 5)
    assert tag.to_dict()["reaches_all_observed"] is False
    assert "quarantine_collection" in {s.action for s in suggestions}


def test_a_real_injection_finding_gets_a_proposal_rather_than_no_label():
    """The INJECTION action map existed from v2.4 and was never reachable."""
    suggestions, withheld = suggest(scanned_injection_finding())
    assert [s.action for s in suggestions] == [
        "label_sensitivity", "tag_exclude", "quarantine_collection"]
    assert not any("no classified label" in w.reason for w in withheld)
    tag = next(s for s in suggestions if s.action == "tag_exclude")
    assert tag.rests_on == ("instruction_override", "role_manipulation")
    assert (tag.observed_chunks, tag.named_chunks) == (3, 2)


# --------------------------------------------------------------------------- #
# Counter-signals arguing against a proposal                                   #
# --------------------------------------------------------------------------- #

def explained(chunk_id, *signals, detector="aws_access_key"):
    """An example whose one match carries the given counter-signal codes."""
    return {"chunk_id": chunk_id, "label": "SECRET", "detectors": [detector],
            "explanations": [{"detector": detector, "confidence": "uncertain",
                              "counter_signals": [{"code": c, "detail": c} for c in signals]}]}


def test_a_chunk_whose_only_match_is_a_published_example_is_held_back():
    """Redacting the key AWS prints in its own documentation is a wasted errand."""
    record = finding()
    record["evidence"]["examples"] = [explained("c1", "published_example"),
                                      explained("c2")]
    tag = next(s for s in suggest(record)[0] if s.action == "tag_exclude")
    assert tag.chunk_ids == ("c2",)
    assert tag.excluded == (("c1", "every match is disputed: published_example"),)


def test_a_context_signal_does_not_hold_a_chunk_back():
    """Terraform quotes every value; 'quoted' is a hint, not a verdict."""
    record = finding()
    record["evidence"]["examples"] = [explained("c1", "quoted_in_text"),
                                      explained("c2", "non_production_scope")]
    tag = next(s for s in suggest(record)[0] if s.action == "tag_exclude")
    assert tag.chunk_ids == ("c1", "c2")
    assert tag.excluded == ()


def test_one_undisputed_match_on_a_chunk_keeps_it_in_reach():
    record = finding()
    record["evidence"]["examples"] = [{
        "chunk_id": "c1", "label": "SECRET", "detectors": ["aws_access_key", "github_token"],
        "explanations": [
            {"detector": "aws_access_key", "counter_signals": [{"code": "published_example"}]},
            {"detector": "github_token", "counter_signals": []},        # this one is real
        ]}]
    tag = next(s for s in suggest(record)[0] if s.action == "tag_exclude")
    assert tag.chunk_ids == ("c1",)


def test_a_chunk_with_no_explanations_is_not_treated_as_disputed():
    """Absence of a dispute is not evidence the value is live, and the gate
    must not invent one either way."""
    record = finding()
    record["evidence"]["examples"] = [{"chunk_id": "c1", "label": "SECRET",
                                       "detectors": ["aws_access_key"]}]
    tag = next(s for s in suggest(record)[0] if s.action == "tag_exclude")
    assert tag.chunk_ids == ("c1",)


def test_when_every_chunk_is_disputed_the_action_is_withheld_and_says_how_to_override():
    record = finding()
    record["evidence"]["examples"] = [explained("c1", "published_example"),
                                      explained("c2", "vendor_test_prefix")]
    suggestions, withheld = suggest(record)
    assert not [s for s in suggestions if s.action == "tag_exclude"]
    reason = next(w.reason for w in withheld if w.action == "tag_exclude")
    assert "disputed as not a live value" in reason
    assert "published_example, vendor_test_prefix" in reason
    assert "include disputed chunks explicitly" in reason


def test_the_reviewer_can_include_disputed_chunks_explicitly():
    record = finding()
    record["evidence"]["examples"] = [explained("c1", "published_example"),
                                      explained("c2")]
    tag = next(s for s in suggest(record, include_disputed=True)[0]
               if s.action == "tag_exclude")
    assert tag.chunk_ids == ("c1", "c2")
    assert tag.excluded == ()


def test_a_dispute_and_a_confidence_shortfall_are_both_reported(calibrated):
    record = finding()
    record["evidence"]["examples"] = [explained("c1", "published_example"),
                                      explained("c2", detector="unmeasured_thing"),
                                      explained("c3")]
    delete = next(s for s in suggest(record)[0] if s.action == "delete_chunks")
    assert delete.chunk_ids == ("c3",)
    assert dict(delete.excluded) == {
        "c1": "every match is disputed: published_example",
        "c2": "unmeasured_thing is 'uncertain'",
    }


# --------------------------------------------------------------------------- #
# Previews are masked; staging only accepts what the server would propose      #
# --------------------------------------------------------------------------- #

def stored():
    """The finding as history holds it: the scan engine writes a category, and
    the server's catalogue keys its proposals on it."""
    return finding(category="data_classification")


RAW_VALUES = ("jane@example.com", "123-45-6789", "AKIAIOSFODNN7EXAMPLE")


def _raw_store():
    text = "Ticket from jane@example.com SSN 123-45-6789 key AKIAIOSFODNN7EXAMPLE"
    return ReadOnlyStore(chunks=[Chunk(id="c1", collection="runbooks", text=text,
                                       metadata={"team": "sre"})])


def test_target_previews_mask_what_the_classifier_finds():
    """A plan is readable by viewers and stored whole: its previews are masked."""
    from vecshield.classify import RegexClassifier

    (target,) = resolve_targets(_raw_store(), "runbooks", ["c1"], with_redaction=True,
                                classifier=RegexClassifier())
    record = target.to_dict()
    assert record["preview"].startswith("Ticket from ")
    for raw in RAW_VALUES:
        assert raw not in record["preview"]
        assert raw not in record["redacted_preview"]
    selected, _, _ = actions.resolve_selector(
        _raw_store(), "runbooks", {"match": "has_field", "field": "team"},
        classifier=RegexClassifier())
    assert not [raw for raw in RAW_VALUES if raw in selected[0].preview]


def test_a_preview_is_withheld_rather_than_shown_raw_when_nothing_can_classify(monkeypatch):
    import vecshield_platform.detection as detection

    def broken(*args, **kwargs):
        raise RuntimeError("model failed to load")

    monkeypatch.setattr(detection, "build_classifier", broken)
    (target,) = resolve_targets(_raw_store(), "runbooks", ["c1"])
    assert not [raw for raw in RAW_VALUES if raw in target.preview]


def test_staging_refuses_a_finding_the_server_does_not_hold():
    forged = actions.Suggestion(
        id="s1", action="tag_exclude", finding_id="made-up", store="demo",
        collection="runbooks", chunk_ids=("c1",), rests_on=(), calibrated=True,
        rationale="", observed_chunks=1, named_chunks=1)
    with pytest.raises(ActionError, match="made-up"):
        stage([forged], connector=TaggingStore(), store="demo", staged_by="kim",
              findings={"f1": stored()})


def test_staging_refuses_chunks_the_finding_did_not_name():
    made = suggest(finding())[0]
    tag = next(s for s in made if s.action == "tag_exclude")
    from dataclasses import replace

    widened = replace(tag, chunk_ids=("c1", "benign-chunk"))
    with pytest.raises(ActionError, match="benign-chunk"):
        stage([widened], connector=TaggingStore(), store="demo", staged_by="kim",
              findings={"f1": stored()})
    moved = replace(tag, collection="other")
    with pytest.raises(ActionError, match="collection"):
        stage([moved], connector=TaggingStore(), store="demo", staged_by="kim",
              findings={"f1": stored()})


def test_staging_refuses_a_gated_action_the_server_withheld():
    """Uncalibrated: the server withholds delete. A client-built one is refused,
    whatever it says about its own calibration."""
    forged = actions.Suggestion(
        id="s1", action="delete_chunks", finding_id="f1", store="demo",
        collection="runbooks", chunk_ids=("c1",), rests_on=("aws_access_key",),
        calibrated=True, rationale="", observed_chunks=1, named_chunks=1)
    with pytest.raises(ActionError, match="delete_chunks"):
        stage([forged], connector=DeletingStore(), store="demo", staged_by="kim",
              findings={"f1": stored()})
    # Without stored findings to compare against, the confidence bar is still
    # checked against this build's calibration, not the client's flag.
    with pytest.raises(ActionError, match="likely"):
        stage([forged], connector=DeletingStore(), store="demo", staged_by="kim")


def test_staging_uses_the_servers_calibration_and_labels_not_the_clients():
    from dataclasses import replace

    tag = next(s for s in suggest(finding())[0] if s.action == "label_sensitivity")
    lying = replace(tag, calibrated=True, labels=("PHI",), observed_chunks=1)
    plan = stage([lying], connector=TaggingStore(), store="demo", staged_by="kim",
                 findings={"f1": stored()})
    op = plan.operations[0]
    assert op.calibrated is False
    assert op.labels == ("SECRET",)
    assert op.observed_chunks == 300
    unchecked = stage([lying], connector=TaggingStore(), store="demo", staged_by="kim")
    assert unchecked.operations[0].calibrated is False


def test_staging_what_the_server_proposed_still_works(calibrated):
    plan = stage(suggest(finding())[0], connector=DeletingStore(), store="demo",
                 staged_by="kim", findings={"f1": stored()})
    assert "delete_chunks" in {op.action for op in plan.operations}


# --------------------------------------------------------------------------- #
# Inventory-only stores                                                       #
# --------------------------------------------------------------------------- #

class InventoryOnlyTaggingStore(TaggingStore):
    """Advertises a write but cannot enumerate content (Bedrock KB, Vertex AI)."""

    content_enumerable = False

    def iter_chunks(self, collection, batch_size=256):
        raise AssertionError("an inventory-only store must not be iterated")


def test_targets_on_an_inventory_only_store_are_unchecked_not_absent():
    [target] = resolve_targets(InventoryOnlyTaggingStore(), "runbooks", ["c1"])
    assert target.present is None


def test_selector_on_an_inventory_only_store_reports_it_never_looked():
    targets, selection, _ = actions.resolve_selector(
        InventoryOnlyTaggingStore(), "runbooks", {"match": "has_field", "field": "x"})
    assert targets == () and selection["content_enumerable"] is False


def test_an_inventory_only_store_is_unenumerable_for_chunk_actions_only():
    """The console reads this before staging, so it does not offer what staging
    would refuse; a whole-collection mark names no targets and is unaffected."""
    store = InventoryOnlyTaggingStore()
    assert "cannot be enumerated" in actions.unenumerable_reason(
        store, ACTION_TEMPLATES["tag_exclude"])
    assert actions.unenumerable_reason(store, ACTION_TEMPLATES["quarantine_collection"]) == ""
    assert actions.unenumerable_reason(TaggingStore(), ACTION_TEMPLATES["tag_exclude"]) == ""


def test_staging_against_an_inventory_only_store_is_refused():
    plan = stage(suggest(finding())[0], connector=InventoryOnlyTaggingStore(),
                 store="demo", staged_by="kim")
    op = plan.operations[0]
    assert op.supported is False
    assert "cannot be enumerated" in op.support_reason
    assert {t.present for t in op.targets} == {None}
