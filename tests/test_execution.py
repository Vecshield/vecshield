"""Approval, execution and verification: the only write path in the product.

Almost every test here asserts a refusal or a hedge. That is the shape of the
feature: the interesting behaviour is not that an approved plan runs, it is
that an unapproved, stale, self-approved, irreversible, or unverifiable one
does not — and that a marking action never gets reported as a removal.
"""

from __future__ import annotations

import pytest

from vecshield.models import Chunk, Collection
from vecshield_platform import execution as ex
from vecshield_platform.actions import stage, suggest
from vecshield_platform.connectors.base import Connector
from vecshield_platform.execution import (
    EXCLUDED_KEY,
    MARKING_CAVEAT,
    QUARANTINED_KEY,
    Approval,
    ApprovalError,
    ExecutionError,
    approve,
    execute,
    executable_operations,
    expected_marks,
    format_execution,
    safe_mode,
    verify,
)

FRESH = (False, "The store matches the plan as staged.")


class TaggingStore(Connector):
    """A store that can mark chunks and collections, and nothing else."""

    kind = "tagging"

    def __init__(self, chunks=None, count=300):
        self._chunks = chunks if chunks is not None else [
            Chunk(id="c1", collection="runbooks", text="key AKIAIOSFODNN7EXAMPLE here"),
        ]
        self._count = count
        self._collection_meta: dict[str, dict] = {}

    def describe(self):
        return None

    def capabilities(self):
        return {"metadata_write", "collection_metadata_write"}

    def list_collections(self):
        return [Collection(name="runbooks", count=self._count,
                           metadata=dict(self._collection_meta.get("runbooks", {})))]

    def iter_chunks(self, collection, batch_size=256):
        yield from (c for c in self._chunks if c.collection == collection)

    def set_chunk_metadata(self, collection, updates):
        changed = 0
        for chunk in self._chunks:
            if chunk.collection == collection and chunk.id in updates:
                chunk.metadata = {**(chunk.metadata or {}), **updates[chunk.id]}
                changed += 1
        return changed

    def set_collection_metadata(self, collection, updates):
        self._collection_meta.setdefault(collection, {}).update(updates)
        return True


class FailingStore(TaggingStore):
    kind = "failing"

    def set_chunk_metadata(self, collection, updates):
        raise ConnectionError("the store went away")


def finding(**overrides):
    base = {
        "id": "f1", "store": "demo", "collection": "runbooks",
        "evidence": {
            "labels": {"SECRET": 3}, "sensitive_chunks": 300,
            "examples": [
                {"chunk_id": "c1", "label": "SECRET", "detectors": ["aws_access_key"]},
                {"chunk_id": "c2", "label": "SECRET", "detectors": ["aws_access_key"]},
            ],
        },
    }
    base.update(overrides)
    return base


@pytest.fixture
def writable(monkeypatch):
    """Turn safe mode off, as a deployment would have to do deliberately."""
    monkeypatch.setenv(ex.SAFE_MODE_ENV, "0")


@pytest.fixture
def plan_body():
    store = TaggingStore()
    plan = stage(suggest(finding())[0], connector=store, store="demo", staged_by="kim")
    return plan.to_dict(), store


def approved(body, approver="dana"):
    return approve(body, approver=approver, reason="Reviewed the diff; the key is live.")


# --------------------------------------------------------------------------- #
# Safe mode                                                                    #
# --------------------------------------------------------------------------- #

def test_safe_mode_is_on_unless_a_deployment_turns_it_off(monkeypatch):
    monkeypatch.delenv(ex.SAFE_MODE_ENV, raising=False)
    assert safe_mode() is True
    for value in ("1", "true", "yes", "", "anything"):
        monkeypatch.setenv(ex.SAFE_MODE_ENV, value)
        assert safe_mode() is True, f"{value!r} should not permit writes"
    for value in ("0", "false", "no", "off", "OFF"):
        monkeypatch.setenv(ex.SAFE_MODE_ENV, value)
        assert safe_mode() is False


def test_safe_mode_blocks_execution_and_names_the_variable(plan_body, monkeypatch):
    monkeypatch.delenv(ex.SAFE_MODE_ENV, raising=False)
    body, store = plan_body
    with pytest.raises(ExecutionError, match="safe mode is on"):
        execute(body, approved(body), connector=store, executed_by="dana",
                staleness=FRESH)


def test_safe_mode_does_not_block_approval(plan_body, monkeypatch):
    """Reviewing and approving stay usable on a locked-down deployment."""
    monkeypatch.delenv(ex.SAFE_MODE_ENV, raising=False)
    body, _ = plan_body
    assert approved(body).approver == "dana"


# --------------------------------------------------------------------------- #
# Approval                                                                     #
# --------------------------------------------------------------------------- #

def test_the_stager_cannot_approve_their_own_plan(plan_body):
    body, _ = plan_body
    with pytest.raises(ApprovalError, match="cannot also approve"):
        approve(body, approver="kim", reason="looks fine")


def test_an_approval_needs_a_reason(plan_body):
    body, _ = plan_body
    with pytest.raises(ApprovalError, match="records why"):
        approve(body, approver="dana", reason="   ")


def test_an_approval_needs_an_approver(plan_body):
    body, _ = plan_body
    with pytest.raises(ApprovalError, match="who gave it"):
        approve(body, approver="", reason="fine")


def test_a_plan_that_no_longer_matches_its_hash_cannot_be_approved(plan_body):
    body, _ = plan_body
    body["operations"][0]["collection"] = "somewhere_else"
    with pytest.raises(ApprovalError, match="does not match its own hash"):
        approved(body)


def test_an_approval_is_scoped_to_the_plan_hash(plan_body):
    body, _ = plan_body
    assert approved(body).plan_hash == body["plan_hash"]


def test_a_plan_with_nothing_runnable_cannot_be_approved():
    """A blocked plan is a record of a proposal, not something to authorize."""
    class ReadOnly(TaggingStore):
        def capabilities(self):
            return set()

    plan = stage(suggest(finding())[0], connector=ReadOnly(), store="demo",
                 staged_by="kim")
    with pytest.raises(ApprovalError, match="nothing in this plan to approve"):
        approved(plan.to_dict())


def test_an_already_decided_plan_cannot_be_approved_again(plan_body):
    body, _ = plan_body
    body["state"] = "executed"
    with pytest.raises(ApprovalError, match="cannot be approved"):
        approved(body)


# --------------------------------------------------------------------------- #
# What this build will and will not run                                        #
# --------------------------------------------------------------------------- #

def test_every_action_a_plan_can_hold_is_either_runnable_or_refused_by_name(monkeypatch):
    """Nothing falls through. Each operation is runnable or carries a refusal."""
    monkeypatch.setattr("vecshield_platform.actions.CALIBRATED",
                        {"aws_access_key": {"likely", "possible"}})

    class Everything(TaggingStore):
        def capabilities(self):
            return {"metadata_write", "collection_metadata_write", "delete", "write",
                    "redact"}

        def delete_chunks(self, collection, ids):
            return len(ids)

        def add_chunks(self, collection, chunks):
            return len(chunks)

        def replace_chunk_text(self, collection, chunk_id, text, metadata_updates=None):
            return True

    plan = stage(suggest(finding())[0], connector=Everything(), store="demo",
                 staged_by="kim")
    runnable, refused = executable_operations(plan.to_dict())
    assert {op["action"] for op in runnable} == {
        "label_sensitivity", "tag_exclude", "quarantine_collection", "redact_text",
        "delete_chunks"}
    assert refused == []


def test_an_operation_the_connector_cannot_do_is_refused_with_its_reason():
    class ReadOnly(TaggingStore):
        def capabilities(self):
            return set()

    plan = stage(suggest(finding())[0], connector=ReadOnly(), store="demo",
                 staged_by="kim")
    _, refused = executable_operations(plan.to_dict())
    assert "does not declare 'metadata_write'" in refused[0]["refusal"]


# --------------------------------------------------------------------------- #
# Execution                                                                    #
# --------------------------------------------------------------------------- #

def test_an_approved_plan_marks_the_chunks_it_resolved(plan_body, writable):
    body, store = plan_body
    result = execute(body, approved(body), connector=store, executed_by="dana",
                     staleness=FRESH)
    assert result.complete is True
    tag = next(o for o in result.outcomes if o.action == "tag_exclude")
    assert tag.changed == 1                          # c1 was present, c2 was not
    assert store._chunks[0].metadata[EXCLUDED_KEY] is True
    assert store._chunks[0].metadata["vecshield_plan_id"] == body["id"]


def test_execution_refuses_an_approval_for_a_different_version(plan_body, writable):
    body, store = plan_body
    approval = approved(body)
    body["operations"][0]["collection"] = "somewhere_else"
    with pytest.raises(ExecutionError, match="does not match its own hash"):
        execute(body, approval, connector=store, executed_by="dana", staleness=FRESH)


def test_execution_refuses_an_approval_from_another_plan(plan_body, writable):
    body, store = plan_body
    foreign = Approval(id="appr-x", plan_id="plan-other", plan_hash=body["plan_hash"],
                       approver="dana", reason="fine", approved_at="2026-09-18T00:00:00Z")
    with pytest.raises(ExecutionError, match="different plan"):
        execute(body, foreign, connector=store, executed_by="dana", staleness=FRESH)


def test_execution_refuses_a_hash_the_approval_does_not_cover(plan_body, writable):
    body, store = plan_body
    wrong = Approval(id="appr-x", plan_id=body["id"], plan_hash="0" * 64,
                     approver="dana", reason="fine", approved_at="2026-09-18T00:00:00Z")
    with pytest.raises(ExecutionError, match="different version"):
        execute(body, wrong, connector=store, executed_by="dana", staleness=FRESH)


def test_a_stale_plan_is_refused_rather_than_re_resolved(plan_body, writable):
    body, store = plan_body
    with pytest.raises(ExecutionError, match="changed since this plan was staged"):
        execute(body, approved(body), connector=store, executed_by="dana",
                staleness=(True, "A targeted chunk has changed."))


def test_the_staleness_check_cannot_be_skipped_by_omission(plan_body, writable):
    body, store = plan_body
    with pytest.raises(ExecutionError, match="must be checked against the store"):
        execute(body, approved(body), connector=store, executed_by="dana")


def test_one_person_cannot_stage_approve_and_run_alone(plan_body, writable, monkeypatch):
    body, store = plan_body
    body["staged_by"] = "kim"
    approval = Approval(id="a", plan_id=body["id"], plan_hash=body["plan_hash"],
                        approver="kim", reason="mine", approved_at="2026-09-18T00:00:00Z")
    with pytest.raises(ExecutionError, match="staged, approved and ran"):
        execute(body, approval, connector=store, executed_by="kim", staleness=FRESH)


def _self_approval(body, mode):
    return Approval(id="a", plan_id=body["id"], plan_hash=body["plan_hash"],
                    approver="kim", reason="mine", approved_at="2026-09-18T00:00:00Z",
                    self_approved=True, separation_of_duties=mode)


def test_a_permitted_self_approval_can_be_run_by_the_same_person(plan_body, writable):
    """Without authentication every caller is one admin: a rule that lets that
    admin approve their own plan must also let them run it, or nothing runs."""
    from vecshield_platform.approvals import ADMIN_MAY_SELF_APPROVE, SeparationOfDuties

    body, store = plan_body
    body["staged_by"] = "kim"
    relaxed = SeparationOfDuties(ADMIN_MAY_SELF_APPROVE, source="default")
    outcome = execute(body, _self_approval(body, ADMIN_MAY_SELF_APPROVE), connector=store,
                      executed_by="kim", staleness=FRESH, separation=relaxed)
    assert outcome.executed_by == "kim"


def test_a_self_approval_is_not_runnable_once_the_rule_is_strict(plan_body, writable):
    from vecshield_platform.approvals import ADMIN_MAY_SELF_APPROVE

    body, store = plan_body
    body["staged_by"] = "kim"
    # Recorded under the relaxed rule, run after the deployment went strict.
    with pytest.raises(ExecutionError, match="staged, approved and ran"):
        execute(body, _self_approval(body, ADMIN_MAY_SELF_APPROVE), connector=store,
                executed_by="kim", staleness=FRESH)


def test_execution_stops_at_the_first_failure(writable):
    store = FailingStore()
    plan = stage(suggest(finding())[0], connector=store, store="demo", staged_by="kim")
    body = plan.to_dict()
    result = execute(body, approved(body), connector=store, executed_by="dana",
                     staleness=FRESH)
    assert result.halted is True
    assert result.complete is False
    assert result.outcomes[0].outcome == "failed"
    assert "ConnectionError" in result.outcomes[0].detail


def test_what_the_store_reported_is_recorded_not_what_was_asked(writable):
    """Two targets asked for, one actually marked. The record says one."""
    class Partial(TaggingStore):
        def set_chunk_metadata(self, collection, updates):
            first = sorted(updates)[0]
            for chunk in self._chunks:
                if chunk.id == first:
                    chunk.metadata = {**(chunk.metadata or {}), **updates[first]}
            return 1

    store = Partial(chunks=[Chunk(id="c1", collection="runbooks", text="a"),
                            Chunk(id="c2", collection="runbooks", text="b")])
    plan = stage(suggest(finding())[0], connector=store, store="demo", staged_by="kim")
    body = plan.to_dict()
    result = execute(body, approved(body), connector=store, executed_by="dana",
                     staleness=FRESH)
    outcome = result.outcomes[0]
    assert outcome.requested == 2 and outcome.changed == 1
    assert "were no longer in the collection" in outcome.detail
    # Ran to the end, but not every target changed: not halted, not complete.
    assert result.halted is False
    assert result.complete is False


def test_an_execution_records_that_safe_mode_was_off(plan_body, writable):
    body, store = plan_body
    result = execute(body, approved(body), connector=store, executed_by="dana",
                     staleness=FRESH)
    assert result.to_dict()["safe_mode"] is False


# --------------------------------------------------------------------------- #
# Verification                                                                 #
# --------------------------------------------------------------------------- #

def test_verification_confirms_a_mark_it_can_actually_read(plan_body, writable):
    body, store = plan_body
    result = execute(body, approved(body), connector=store, executed_by="dana",
                     staleness=FRESH)
    report = verify(result, connector=store, expected_ids=expected_marks(body))
    assert report.outcome == "confirmed"
    # One marked chunk plus the collection's own quarantine mark.
    assert report.observed == report.expected == 2


def test_a_confirmed_verification_still_says_nothing_was_removed(plan_body, writable):
    """The caveat that stops 'confirmed' being read as 'the data is gone'."""
    body, store = plan_body
    result = execute(body, approved(body), connector=store, executed_by="dana",
                     staleness=FRESH)
    report = verify(result, connector=store, expected_ids=expected_marks(body))
    assert MARKING_CAVEAT in report.caveats
    assert "does not establish that anything stopped being retrieved" in MARKING_CAVEAT


def test_a_store_it_could_not_read_back_is_inconclusive_not_confirmed(plan_body, writable):
    body, store = plan_body
    result = execute(body, approved(body), connector=store, executed_by="dana",
                     staleness=FRESH)

    class Unreadable(TaggingStore):
        def iter_chunks(self, collection, batch_size=256):
            raise ConnectionError("gone")

    report = verify(result, connector=Unreadable(), expected_ids=expected_marks(body))
    assert report.outcome == "inconclusive"
    assert report.unreadable == 1
    assert "were not checked" in report.reason


def test_a_chunk_the_store_never_returned_is_unknown_not_marked(plan_body, writable):
    body, store = plan_body
    result = execute(body, approved(body), connector=store, executed_by="dana",
                     staleness=FRESH)
    store._chunks = []                              # it is simply not returned now
    report = verify(result, connector=store, expected_ids=expected_marks(body))
    assert report.outcome == "inconclusive"
    assert report.unreadable == 1                   # the chunk, not counted either way
    assert "is unknown" in report.reason


def test_a_mark_that_did_not_take_reads_as_partial(writable):
    store = TaggingStore(chunks=[Chunk(id="c1", collection="runbooks", text="a"),
                                 Chunk(id="c2", collection="runbooks", text="b")])
    plan = stage(suggest(finding())[0], connector=store, store="demo", staged_by="kim")
    body = plan.to_dict()
    result = execute(body, approved(body), connector=store, executed_by="dana",
                     staleness=FRESH)
    store._chunks[1].metadata = {}                  # one mark quietly lost
    report = verify(result, connector=store, expected_ids=expected_marks(body))
    assert report.outcome == "partial"
    assert report.observed == 2 and report.expected == 3
    assert "does not carry the mark" in report.reason


def test_a_halted_execution_verifies_as_failed(writable):
    store = FailingStore()
    plan = stage(suggest(finding())[0], connector=store, store="demo", staged_by="kim")
    body = plan.to_dict()
    result = execute(body, approved(body), connector=store, executed_by="dana",
                     staleness=FRESH)
    report = verify(result, connector=store, expected_ids={})
    assert report.outcome == "failed"
    assert "Stopped after" in report.reason


def test_a_quarantine_is_written_and_read_back(writable):
    record = finding()
    record["evidence"]["examples"] = []
    store = TaggingStore()
    suggestions = [s for s in suggest(record)[0] if s.action == "quarantine_collection"]
    plan = stage(suggestions, connector=store, store="demo", staged_by="kim")
    body = plan.to_dict()
    result = execute(body, approved(body), connector=store, executed_by="dana",
                     staleness=FRESH)
    assert result.complete is True
    assert store._collection_meta["runbooks"][QUARANTINED_KEY] is True
    report = verify(result, connector=store, expected_ids=expected_marks(body))
    assert report.outcome == "confirmed"


def test_format_execution_leads_with_the_failure(writable):
    store = FailingStore()
    plan = stage(suggest(finding())[0], connector=store, store="demo", staged_by="kim")
    body = plan.to_dict()
    result = execute(body, approved(body), connector=store, executed_by="dana",
                     staleness=FRESH)
    text = format_execution(result, verify(result, connector=store, expected_ids={}))
    # Labelling is now the first thing proposed, so it is the first to fail —
    # and nothing was marked, so the note is the one about labels.
    assert text.index("Stopped after") < text.index("failed   label_sensitivity")
    assert "Note: This confirms the label was written" in text
    assert "A label does not restrict retrieval" in text


def test_a_plan_that_already_ran_cannot_run_again(plan_body, writable):
    """Stated, not inferred. The staleness check would also refuse this, but
    only because the first run altered the hashes it compares."""
    body, store = plan_body
    approval = approved(body)
    body["state"] = "executed"
    with pytest.raises(ExecutionError, match="already executed and cannot be run again"):
        execute(body, approval, connector=store, executed_by="dana", staleness=FRESH)


# --------------------------------------------------------------------------- #
# Delete, and the gate it waits behind                                         #
# --------------------------------------------------------------------------- #

class DeletingStore(TaggingStore):
    kind = "deleting"

    def capabilities(self):
        return {"metadata_write", "collection_metadata_write", "delete"}

    def delete_chunks(self, collection, ids):
        before = len(self._chunks)
        self._chunks = [c for c in self._chunks
                        if not (c.collection == collection and c.id in ids)]
        return before - len(self._chunks)


@pytest.fixture
def delete_ready(monkeypatch):
    """A detector measured at 'likely', which is what delete requires."""
    monkeypatch.setattr("vecshield_platform.actions.CALIBRATED",
                        {"aws_access_key": {"likely", "possible"}})


def delete_plan(store):
    plan = stage([s for s in suggest(finding())[0] if s.action == "delete_chunks"],
                 connector=store, store="demo", staged_by="kim")
    return plan.to_dict()


def test_a_detector_at_possible_unlocks_redaction_but_not_delete(monkeypatch):
    """The bar is per action. 'Measured at all' is not the same claim as
    'measured well enough to destroy data on'."""
    from vecshield_platform.actions import ACTION_TEMPLATES, below_confidence

    monkeypatch.setattr("vecshield_platform.actions.CALIBRATED",
                        {"aws_access_key": {"possible"}})
    assert below_confidence(ACTION_TEMPLATES["redact_text"], ["aws_access_key"]) == []
    short = below_confidence(ACTION_TEMPLATES["delete_chunks"], ["aws_access_key"])
    assert short == [("aws_access_key", "possible")]


def test_delete_is_withheld_at_the_suggestion_and_says_what_would_change_it(
        monkeypatch):
    monkeypatch.setattr("vecshield_platform.actions.CALIBRATED",
                        {"aws_access_key": {"possible"}})
    _, withheld = suggest(finding())
    reason = next(w.reason for w in withheld if w.action == "delete_chunks")
    assert "aws_access_key is 'possible'" in reason
    assert "'likely' or better" in reason
    assert "Growing the corpus is what changes this" in reason


def test_the_gate_is_per_chunk_so_a_measured_chunk_is_not_held_back_by_its_neighbour(
        monkeypatch):
    """c1 rests on a detector at 'likely'; c2 on an unmeasured one. Delete
    reaches c1 and lists c2 as excluded with the reason — it is neither
    withheld outright nor allowed to reach c2."""
    monkeypatch.setattr("vecshield_platform.actions.CALIBRATED",
                        {"aws_access_key": {"likely", "possible"}})
    record = finding()
    record["evidence"]["examples"][1]["detectors"] = ["some_new_detector"]
    suggestions, withheld = suggest(record)
    delete = next(s for s in suggestions if s.action == "delete_chunks")
    assert delete.chunk_ids == ("c1",)
    assert delete.excluded == (("c2", "some_new_detector is 'uncertain'"),)
    assert delete.rests_on == ("aws_access_key",)
    assert delete.to_dict()["reaches_all_observed"] is False
    assert "1 of the 2 named chunk(s) are not reached by this action" in delete.rationale
    assert not [w for w in withheld if w.action == "delete_chunks"]


def test_a_gated_action_is_withheld_only_when_no_chunk_qualifies(monkeypatch):
    monkeypatch.setattr("vecshield_platform.actions.CALIBRATED", {})
    _, withheld = suggest(finding())
    reason = next(w.reason for w in withheld if w.action == "delete_chunks")
    assert "aws_access_key is 'uncertain'" in reason


def test_an_ungated_action_reaches_every_named_chunk(monkeypatch):
    monkeypatch.setattr("vecshield_platform.actions.CALIBRATED", {})
    tag = next(s for s in suggest(finding())[0] if s.action == "tag_exclude")
    assert tag.chunk_ids == ("c1", "c2")
    assert tag.excluded == ()


def test_a_chunk_with_no_per_chunk_record_is_judged_on_the_aggregate(monkeypatch):
    """Conservative: unknown provenance of a detector list means the whole
    finding's detectors apply to that chunk."""
    monkeypatch.setattr("vecshield_platform.actions.CALIBRATED",
                        {"aws_access_key": {"likely", "possible"}})
    record = finding()
    record["evidence"]["examples"][1] = {"chunk_id": "c2", "label": "SECRET"}   # no detectors
    record["evidence"]["examples"].append(
        {"chunk_id": "c3", "label": "SECRET", "detectors": ["mystery"]})
    delete = next(s for s in suggest(record)[0] if s.action == "delete_chunks")
    # c2 has no record and falls back to the aggregate, which includes 'mystery'.
    assert "c2" not in delete.chunk_ids
    assert delete.chunk_ids == ("c1",)


def test_delete_cannot_be_approved_without_the_store_id_typed(delete_ready):
    body = delete_plan(DeletingStore())
    with pytest.raises(ApprovalError, match="type the store id"):
        approve(body, approver="dana", reason="The key is live.")


def test_delete_is_approved_when_the_store_id_is_typed(delete_ready):
    body = delete_plan(DeletingStore())
    approval = approve(body, approver="dana", reason="The key is live.",
                       typed_store_id="demo")
    assert approval.operations == ("delete_chunks",)
    assert approval.typed_store_id == "demo"


def test_a_wrong_store_id_does_not_confirm_a_delete(delete_ready):
    body = delete_plan(DeletingStore())
    with pytest.raises(ApprovalError, match="type the store id"):
        approve(body, approver="dana", reason="The key is live.",
                typed_store_id="production")


def test_an_approved_delete_removes_the_chunks_and_verifies_their_absence(
        delete_ready, writable):
    from vecshield_platform.execution import DELETION_CAVEAT, expected_removals

    store = DeletingStore(chunks=[Chunk(id="c1", collection="runbooks", text="key"),
                                  Chunk(id="c9", collection="runbooks", text="keep")])
    body = delete_plan(store)
    approval = approve(body, approver="dana", reason="The key is live.",
                       typed_store_id="demo")
    result = execute(body, approval, connector=store, executed_by="dana",
                     staleness=FRESH)
    assert result.complete is True
    assert [c.id for c in store._chunks] == ["c9"]

    report = verify(result, connector=store, removed_ids=expected_removals(body))
    assert report.outcome == "confirmed"
    assert DELETION_CAVEAT in report.caveats
    # A delete marked nothing, so the marking caveat must not be attached to it.
    assert MARKING_CAVEAT not in report.caveats


def test_a_delete_it_could_not_read_back_is_inconclusive_not_confirmed(
        delete_ready, writable):
    """Absence is only evidence when the collection could be read through."""
    from vecshield_platform.execution import expected_removals

    store = DeletingStore()
    body = delete_plan(store)
    approval = approve(body, approver="dana", reason="The key is live.",
                       typed_store_id="demo")
    result = execute(body, approval, connector=store, executed_by="dana",
                     staleness=FRESH)

    class Unreadable(DeletingStore):
        def iter_chunks(self, collection, batch_size=256):
            raise ConnectionError("gone")

    report = verify(result, connector=Unreadable(), removed_ids=expected_removals(body))
    assert report.outcome == "inconclusive"
    assert "not evidence that they were removed" in report.reason


def test_a_delete_that_removed_only_some_targets_is_not_complete(delete_ready, writable):
    """Two chunks asked for, one removed. The API and the audit entry read
    `complete` from this, so it must not say the plan ran in full."""
    class PartialDelete(DeletingStore):
        def delete_chunks(self, collection, ids):
            return super().delete_chunks(collection, sorted(ids)[:1])

    store = PartialDelete(chunks=[Chunk(id="c1", collection="runbooks", text="key"),
                                  Chunk(id="c2", collection="runbooks", text="key")])
    body = delete_plan(store)
    approval = approve(body, approver="dana", reason="The key is live.",
                       typed_store_id="demo")
    result = execute(body, approval, connector=store, executed_by="dana",
                     staleness=FRESH)
    delete = next(o for o in result.outcomes if o.action == "delete_chunks")
    assert delete.requested == 2 and delete.changed == 1
    assert result.halted is False
    assert result.complete is False


def test_a_chunk_the_delete_did_not_remove_is_reported(delete_ready, writable):
    from vecshield_platform.execution import expected_removals

    class Ineffective(DeletingStore):
        def delete_chunks(self, collection, ids):
            return len(ids)          # claims success, removes nothing

    store = Ineffective()
    body = delete_plan(store)
    approval = approve(body, approver="dana", reason="The key is live.",
                       typed_store_id="demo")
    result = execute(body, approval, connector=store, executed_by="dana",
                     staleness=FRESH)
    report = verify(result, connector=store, removed_ids=expected_removals(body))
    assert report.outcome == "inconclusive"
    assert "still returned by the store and were not removed" in report.reason


# --------------------------------------------------------------------------- #
# Redaction: the text goes, the vector stays, the original is kept             #
# --------------------------------------------------------------------------- #

from vecshield_platform.actions import redact  # noqa: E402
from vecshield_platform.execution import (  # noqa: E402
    NEEDS_REEMBED_KEY,
    ORIGINALS_COLLECTION,
    REDACTED_KEY,
    REDACTION_CAVEAT,
    verify_plan,
)


class RedactingStore(TaggingStore):
    """A store with random access and text replacement, and nothing that embeds."""

    kind = "redacting"

    def __init__(self, chunks=None, count=300):
        super().__init__(chunks, count)
        self.embed_calls = 0

    def capabilities(self):
        return {"metadata_write", "collection_metadata_write", "redact", "write"}

    def get_chunks(self, collection, ids):
        return [c for c in self._chunks if c.collection == collection and c.id in ids]

    def add_chunks(self, collection, chunks):
        for c in chunks:
            if c.embedding is None:
                self.embed_calls += 1          # the thing that must never happen
            self._chunks.append(Chunk(id=c.id, collection=collection, text=c.text,
                                      embedding=c.embedding, metadata=dict(c.metadata)))
        return len(chunks)

    def replace_chunk_text(self, collection, chunk_id, text, metadata_updates=None):
        for c in self._chunks:
            if c.collection == collection and c.id == chunk_id:
                c.text = text
                c.metadata = {**(c.metadata or {}), **(metadata_updates or {})}
                return True
        return False


@pytest.fixture
def redaction_ready(monkeypatch):
    monkeypatch.setattr("vecshield_platform.actions.CALIBRATED",
                        {"aws_access_key": {"possible"}})


def secret_chunk():
    return Chunk(id="c1", collection="runbooks",
                 text="rotate AKIA5TQ2NHBGVCXZ9WQ1 before Friday",
                 embedding=[0.25] * 8, metadata={"team": "sre"})


def test_redact_merges_overlaps_and_drops_offsets_that_do_not_fit():
    text = "key AKIA5TQ2NHBGVCXZ9WQ1 here"
    out, applied = redact(text, [
        {"start": 4, "end": 24, "label": "secret", "detector": "aws_access_key"},
        {"start": 10, "end": 20, "label": "secret", "detector": "other"},   # inside the first
        {"start": 100, "end": 120, "label": "pii"},                          # stale
    ])
    assert out == "key [REDACTED:secret] here"
    assert [a for a in applied if "dropped" in a] == [
        {"start": 100, "end": 120, "label": "pii",
         "dropped": "offsets do not fit the current text"}]


def test_redact_with_no_spans_returns_the_text_unchanged():
    assert redact("nothing here", []) == ("nothing here", [])


def test_staging_a_redaction_computes_the_replacement_from_the_current_text(
        redaction_ready):
    """The preview a reviewer approves is the exact text that will be written."""
    store = RedactingStore(chunks=[secret_chunk()])
    plan = stage([s for s in suggest(finding())[0] if s.action == "redact_text"],
                 connector=store, store="demo", staged_by="kim")
    target = plan.operations[0].present[0]
    assert target.redacted_text == "rotate [REDACTED:secret] before Friday"
    assert target.redaction_spans[0]["detector"] == "aws_access_key"
    body = plan.to_dict()
    sample = body["operations"][0]["targets"][0]
    assert sample["redacted_preview"].startswith("rotate [REDACTED:secret]")


def test_a_redaction_keeps_the_original_and_never_asks_the_store_to_embed(
        redaction_ready, writable):
    store = RedactingStore(chunks=[secret_chunk()])
    plan = stage([s for s in suggest(finding())[0] if s.action == "redact_text"],
                 connector=store, store="demo", staged_by="kim")
    body = plan.to_dict()
    result = execute(body, approved(body), connector=store, executed_by="dana",
                     staleness=FRESH)
    assert result.complete is True

    live = next(c for c in store._chunks if c.collection == "runbooks" and c.id == "c1")
    assert live.text == "rotate [REDACTED:secret] before Friday"
    assert live.embedding == [0.25] * 8                    # untouched
    assert live.metadata["team"] == "sre"                  # merged, not replaced
    assert live.metadata[REDACTED_KEY] is True
    assert live.metadata[NEEDS_REEMBED_KEY] is True

    kept = [c for c in store._chunks if c.collection == ORIGINALS_COLLECTION]
    assert len(kept) == 1
    assert kept[0].text == "rotate AKIA5TQ2NHBGVCXZ9WQ1 before Friday"
    assert kept[0].embedding == [0.25] * 8
    assert kept[0].metadata["vecshield_original_of"] == "c1"
    assert store._collection_meta[ORIGINALS_COLLECTION][QUARANTINED_KEY] is True
    assert store.embed_calls == 0


def test_the_original_is_copied_before_the_text_is_replaced(redaction_ready, writable):
    """A failure between the two steps must leave an unredacted chunk with a
    spare copy, never a redacted chunk with no way back."""
    class FailsToReplace(RedactingStore):
        def replace_chunk_text(self, *a, **k):
            raise ConnectionError("lost the store")

    store = FailsToReplace(chunks=[secret_chunk()])
    plan = stage([s for s in suggest(finding())[0] if s.action == "redact_text"],
                 connector=store, store="demo", staged_by="kim")
    body = plan.to_dict()
    result = execute(body, approved(body), connector=store, executed_by="dana",
                     staleness=FRESH)
    assert result.halted is True
    live = next(c for c in store._chunks if c.collection == "runbooks")
    assert "AKIA5TQ2NHBGVCXZ9WQ1" in live.text                     # unredacted
    assert [c for c in store._chunks if c.collection == ORIGINALS_COLLECTION]  # but copied


def test_a_chunk_without_a_stored_vector_is_skipped_rather_than_embedded(
        redaction_ready, writable):
    store = RedactingStore(chunks=[Chunk(id="c1", collection="runbooks",
                                         text="rotate AKIA5TQ2NHBGVCXZ9WQ1 now",
                                         embedding=None)])
    plan = stage([s for s in suggest(finding())[0] if s.action == "redact_text"],
                 connector=store, store="demo", staged_by="kim")
    body = plan.to_dict()
    result = execute(body, approved(body), connector=store, executed_by="dana",
                     staleness=FRESH)
    assert result.outcomes[0].outcome == "skipped"
    assert "no stored vector" in result.outcomes[0].detail
    assert store.embed_calls == 0


def test_redaction_verification_confirms_text_mark_and_that_nothing_still_matches(
        redaction_ready, writable):
    store = RedactingStore(chunks=[secret_chunk()])
    plan = stage([s for s in suggest(finding())[0] if s.action == "redact_text"],
                 connector=store, store="demo", staged_by="kim")
    body = plan.to_dict()
    result = execute(body, approved(body), connector=store, executed_by="dana",
                     staleness=FRESH)
    report = verify_plan(result, body, connector=store)
    assert report.outcome == "confirmed"
    assert REDACTION_CAVEAT in report.caveats
    assert "vector was not changed" in REDACTION_CAVEAT
    assert MARKING_CAVEAT not in report.caveats


def test_a_replacement_that_still_matches_is_not_confirmed(redaction_ready, writable):
    """A 'redaction' that leaves the secret in is caught by re-classifying."""
    class LeavesItIn(RedactingStore):
        def replace_chunk_text(self, collection, chunk_id, text, metadata_updates=None):
            # Writes the mark but keeps the original text.
            return super().replace_chunk_text(
                collection, chunk_id, secret_chunk().text, metadata_updates)

    store = LeavesItIn(chunks=[secret_chunk()])
    plan = stage([s for s in suggest(finding())[0] if s.action == "redact_text"],
                 connector=store, store="demo", staged_by="kim")
    body = plan.to_dict()
    result = execute(body, approved(body), connector=store, executed_by="dana",
                     staleness=FRESH)
    report = verify_plan(result, body, connector=store)
    assert report.outcome == "inconclusive"
    assert "does not hold the approved text" in report.reason


def test_verify_plan_covers_deletions_too(delete_ready, writable):
    """The API and CLI verified only marks, so a delete was checked against
    nothing. verify_plan gathers every kind of operation."""
    store = DeletingStore(chunks=[Chunk(id="c1", collection="runbooks", text="key")])
    body = delete_plan(store)
    approval = approve(body, approver="dana", reason="The key is live.",
                       typed_store_id="demo")
    result = execute(body, approval, connector=store, executed_by="dana",
                     staleness=FRESH)
    report = verify_plan(result, body, connector=store)
    assert report.outcome == "confirmed"
    assert report.expected == 1


def test_running_to_the_end_with_nothing_to_do_is_not_halted(plan_body, writable):
    """'Halted' means a failure stopped execution. Finding every target gone
    and finishing is not that, and the API labels the plan from `halted`."""
    body, store = plan_body
    approval = approved(body)
    store._chunks = []                      # every target has gone since staging
    result = execute(body, approval, connector=store, executed_by="dana",
                     staleness=FRESH)
    tag = next(o for o in result.outcomes if o.action == "tag_exclude")
    assert tag.outcome == "skipped"
    assert result.halted is False
    assert result.complete is False         # not everything applied...
    assert not result.halt_reason           # ...but nothing stopped it either


# --------------------------------------------------------------------------- #
# Separation of duties re-checked when the plan runs                           #
# --------------------------------------------------------------------------- #

def test_a_self_approval_is_rechecked_against_the_rule_in_force_at_execution(
        plan_body, writable):
    """Approved by its stager under 'off'; the deployment then tightened to
    'admin_may_self_approve'. A non-admin can no longer run their own plan."""
    from vecshield_platform.approvals import ADMIN_MAY_SELF_APPROVE, OFF, SeparationOfDuties

    body, store = plan_body
    body["staged_by"] = "kim"
    tightened = SeparationOfDuties(ADMIN_MAY_SELF_APPROVE, source="configured")
    with pytest.raises(ExecutionError, match="cannot also approve"):
        execute(body, _self_approval(body, OFF), connector=store, executed_by="kim",
                staleness=FRESH, separation=tightened, executor_roles=("compliance",))
    # The same rule still lets an admin run their own reversible plan.
    outcome = execute(body, _self_approval(body, OFF), connector=store, executed_by="kim",
                      staleness=FRESH, separation=tightened, executor_roles=("admin",))
    assert outcome.executed_by == "kim"


def test_a_self_approved_delete_is_refused_once_the_rule_excepts_irreversible_ones(
        delete_ready, writable):
    from vecshield_platform.approvals import ADMIN_MAY_SELF_APPROVE, OFF, SeparationOfDuties

    store = DeletingStore()
    body = delete_plan(store)
    approval = Approval(id="a", plan_id=body["id"], plan_hash=body["plan_hash"],
                        approver="kim", reason="mine", approved_at="2026-09-18T00:00:00Z",
                        typed_store_id="demo", self_approved=True, separation_of_duties=OFF)
    with pytest.raises(ExecutionError, match="irreversible"):
        execute(body, approval, connector=store, executed_by="kim", staleness=FRESH,
                separation=SeparationOfDuties(ADMIN_MAY_SELF_APPROVE),
                executor_roles=("admin",))
    assert [c.id for c in store._chunks] == ["c1"]


def test_without_executor_roles_the_existing_rule_applies(plan_body, writable):
    from vecshield_platform.approvals import ADMIN_MAY_SELF_APPROVE, OFF, SeparationOfDuties

    body, store = plan_body
    body["staged_by"] = "kim"
    outcome = execute(body, _self_approval(body, OFF), connector=store, executed_by="kim",
                      staleness=FRESH, separation=SeparationOfDuties(ADMIN_MAY_SELF_APPROVE))
    assert outcome.executed_by == "kim"


# --------------------------------------------------------------------------- #
# A chunk edited between the staleness check and the write is not overwritten  #
# --------------------------------------------------------------------------- #

def test_a_redaction_does_not_overwrite_a_chunk_edited_after_the_check(
        redaction_ready, writable):
    store = RedactingStore(chunks=[secret_chunk()])
    plan = stage([s for s in suggest(finding())[0] if s.action == "redact_text"],
                 connector=store, store="demo", staged_by="kim")
    body = plan.to_dict()
    # A concurrent writer, after is_stale passed and before the write.
    store._chunks[0].text += " UPDATED: refund approved by manager"
    result = execute(body, approved(body), connector=store, executed_by="dana",
                     staleness=FRESH)
    live = next(c for c in store._chunks if c.collection == "runbooks" and c.id == "c1")
    assert "UPDATED" in live.text
    assert not [c for c in store._chunks if c.collection == ORIGINALS_COLLECTION]
    assert result.outcomes[0].outcome == "skipped"
    assert "changed since" in result.outcomes[0].detail
    assert verify_plan(result, body, connector=store).outcome != "confirmed"


class MovingStore(RedactingStore):
    kind = "moving"

    def capabilities(self):
        return {"write", "delete", "collection_create", "collection_metadata_write"}

    def delete_chunks(self, collection, ids):
        before = len(self._chunks)
        self._chunks = [c for c in self._chunks
                        if not (c.collection == collection and c.id in ids)]
        return before - len(self._chunks)

    def create_collection_like(self, source, name, metadata=None):
        return True

    def list_collections(self):
        names = sorted({c.collection for c in self._chunks} | {"runbooks"})
        return [Collection(name=n, count=sum(1 for c in self._chunks if c.collection == n))
                for n in names]


def _one_op_plan(store, action, **extra):
    from vecshield_platform.actions import Suggestion

    suggestion = Suggestion(
        id="s1", action=action, finding_id="f1", store="demo", collection="runbooks",
        chunk_ids=extra.pop("chunk_ids", ()), rests_on=(), calibrated=False,
        rationale="", observed_chunks=1, named_chunks=1, **extra)
    return stage([suggestion], connector=store, store="demo", staged_by="kim").to_dict()


def test_a_quarantine_does_not_move_a_chunk_edited_after_the_check(writable):
    store = MovingStore(chunks=[secret_chunk()])
    body = _one_op_plan(store, "quarantine_chunks", chunk_ids=("c1",))
    assert body["operations"][0]["runnable"], body["operations"][0]["support_reason"]
    store._chunks[0].metadata = {**store._chunks[0].metadata, "edited": True}
    result = execute(body, approved(body), connector=store, executed_by="dana",
                     staleness=FRESH)
    assert result.outcomes[0].outcome == "skipped"
    assert "changed since" in result.outcomes[0].detail
    assert [c.collection for c in store._chunks] == ["runbooks"]


def test_a_batch_that_fails_part_way_still_reports_what_it_wrote(writable):
    """Chunk one is moved, then the store drops. The record must say one chunk
    changed, not none: that write is in the store and is not rolled back."""
    class DropsOnSecondCopy(MovingStore):
        def add_chunks(self, collection, chunks):
            if collection == "vecshield_quarantine" and any(
                    c.metadata.get("vecshield_original_id") == "c2" for c in chunks):
                raise ConnectionError("lost the store")
            return super().add_chunks(collection, chunks)

    chunks = [Chunk(id=cid, collection="runbooks", text=f"doc {cid}",
                    embedding=[0.1] * 4, metadata={}) for cid in ("c1", "c2")]
    store = DropsOnSecondCopy(chunks=chunks)
    body = _one_op_plan(store, "quarantine_chunks", chunk_ids=("c1", "c2"))
    assert body["operations"][0]["runnable"], body["operations"][0]["support_reason"]
    result = execute(body, approved(body), connector=store, executed_by="dana",
                     staleness=FRESH)
    assert result.halted is True
    outcome = result.outcomes[0]
    assert (outcome.outcome, outcome.requested, outcome.changed) == ("failed", 2, 1)
    assert "already written" in outcome.detail
    assert result.applied == 1
    assert result.complete is False


def test_a_split_does_not_copy_a_chunk_edited_after_the_check(writable):
    chunks = [Chunk(id=f"c{i}", collection="runbooks", text=f"doc {i}",
                    embedding=[0.1] * 4, metadata={"tenant": t})
              for i, t in enumerate(("acme", "globex"))]
    store = MovingStore(chunks=chunks)
    body = _one_op_plan(store, "split_by_tenant", params={"tenant_field": "tenant"})
    assert body["operations"][0]["runnable"], body["operations"][0]["support_reason"]
    store._chunks[0].text = "doc 0, rewritten after review"
    result = execute(body, approved(body), connector=store, executed_by="dana",
                     staleness=FRESH)
    copied = [c.id for c in store._chunks if c.collection != "runbooks"]
    assert copied == ["c1"]
    assert "changed since" in result.outcomes[0].detail


# --------------------------------------------------------------------------- #
# Tenants that differ only by type are different tenants                       #
# --------------------------------------------------------------------------- #

def _typed_tenants():
    return [Chunk(id=cid, collection="runbooks", text=f"doc {cid}", embedding=[0.1] * 4,
                  metadata={"tenant": tenant})
            for cid, tenant in (("a", 1), ("b", "1"), ("c", "2"))]


def test_a_split_refuses_tenant_values_that_differ_only_by_type():
    """A store filters tenant 1 and tenant '1' apart (Chroma does); one
    partition for both would copy two tenants into one collection."""
    body = _one_op_plan(MovingStore(chunks=_typed_tenants()), "split_by_tenant",
                        params={"tenant_field": "tenant"})
    op = body["operations"][0]
    assert op["runnable"] is False
    assert "differ only by type" in op["support_reason"]


def test_split_verification_treats_a_differently_typed_tenant_as_foreign():
    chunks = _typed_tenants()
    for c in chunks[:2]:
        c.collection = "runbooks__1"
    store = MovingStore(chunks=chunks)
    split = {"collection": "runbooks", "tenant_field": "tenant", "ids": ["b"],
             "partitions": {"1": {"collection": "runbooks__1", "chunks": 1, "type": "str"}}}
    total, observed, unreadable, reasons = ex._check_partitions(store, [split])
    assert (total, observed) == (1, 0)
    assert any("not isolated" in r for r in reasons)
