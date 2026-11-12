"""Writing the classification back onto the chunk, and what that does not mean.

Labelling is the one action here that adds information rather than withdrawing
content. The tests that matter are the ones asserting it stays honest: the
customer's own metadata survives, the label is verified on its own field rather
than on the exclusion mark's, and every surface says that a label does not stop
anything being retrieved.
"""

from __future__ import annotations

import pytest

from vecshield.models import Chunk, Collection
from vecshield_platform.actions import ACTION_TEMPLATES, stage, suggest
from vecshield_platform.connectors.base import Connector
from vecshield_platform.execution import (
    CATEGORIES_KEY,
    EXCLUDED_KEY,
    LABELLED_AT_KEY,
    LABELLING_CAVEAT,
    PLAN_KEY,
    SENSITIVITY_KEY,
    approve,
    execute,
    executable_operations,
    expected_labels,
    verify,
)

FRESH = (False, "The store matches the plan as staged.")


class LabellingStore(Connector):
    """Keeps chunks in memory and merges metadata the way the contract says."""

    kind = "labelling"

    def __init__(self):
        self._chunks = [
            Chunk(id="c1", collection="runbooks", text="AKIA-style key here",
                  metadata={"tenant_id": "acme", "owner": "platform"}),
            Chunk(id="c2", collection="runbooks", text="another key",
                  metadata={"tenant_id": "acme"}),
        ]

    def capabilities(self):
        return {"metadata_write"}

    def describe(self):
        from vecshield.models import VectorStore
        return VectorStore(kind=self.kind, name="demo", endpoint="memory://",
                           collections=self.list_collections())

    def list_collections(self):
        return [Collection(name="runbooks", count=len(self._chunks))]

    def iter_chunks(self, collection, batch_size=256):
        yield from (c for c in self._chunks if c.collection == collection)

    def set_chunk_metadata(self, collection, updates):
        changed = 0
        for chunk in self._chunks:
            if chunk.collection == collection and chunk.id in updates:
                chunk.metadata = {**(chunk.metadata or {}), **updates[chunk.id]}
                changed += 1
        return changed


def finding(**overrides):
    base = {
        "id": "f1", "store": "demo", "collection": "runbooks",
        "evidence": {
            "labels": {"SECRET": 2, "PII": 1}, "sensitive_chunks": 2,
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
    monkeypatch.setenv("VECSHIELD_SAFE_MODE", "0")


def _label_only(suggestions):
    """Stage the labelling proposal alone.

    A finding draws several proposals, and a plan holding all of them would
    write the exclusion mark too — which is a different claim about the same
    chunks. These tests are about what labelling does on its own.
    """
    return [s for s in suggestions if s.action == "label_sensitivity"]


@pytest.fixture
def ran(writable):
    store = LabellingStore()
    plan = stage(_label_only(suggest(finding())[0]), connector=store, store="demo",
                 staged_by="kim")
    body = plan.to_dict()
    approval = approve(body, approver="dana", reason="Reviewed the classification.")
    result = execute(body, approval, connector=store, executed_by="dana",
                     staleness=FRESH)
    return store, body, result


# --- the template's own claims ----------------------------------------------

def test_the_template_says_a_label_does_not_restrict_retrieval():
    template = ACTION_TEMPLATES["label_sensitivity"]
    assert template.reversible is True
    assert template.risk == "low"
    assert template.capability == "metadata_write"
    assert "does not restrict retrieval" in template.caveat
    assert "does not act on it" in template.caveat


def test_labelling_is_proposed_for_every_classified_label():
    from vecshield_platform.actions import LABEL_ACTIONS
    for label, kinds in LABEL_ACTIONS.items():
        assert kinds[0] == "label_sensitivity", label


# --- the write ----------------------------------------------------------------

def test_the_label_is_written_to_every_resolved_chunk(ran):
    store, _, result = ran
    outcome = next(o for o in result.outcomes if o.action == "label_sensitivity")
    assert outcome.outcome == "applied"
    assert outcome.changed == 2

    for chunk in store._chunks:
        assert chunk.metadata[SENSITIVITY_KEY] == "SECRET"
        assert chunk.metadata[CATEGORIES_KEY] == "PII,SECRET"
        assert chunk.metadata[LABELLED_AT_KEY]
        assert chunk.metadata[PLAN_KEY].startswith("plan-")


def test_the_customers_own_metadata_survives_the_write(ran):
    store, _, _ = ran
    c1 = next(c for c in store._chunks if c.id == "c1")
    assert c1.metadata["tenant_id"] == "acme"
    assert c1.metadata["owner"] == "platform"


def test_labelling_does_not_set_the_exclusion_mark(ran):
    """Two different claims. Writing one must not look like the other."""
    store, _, _ = ran
    assert all(EXCLUDED_KEY not in c.metadata for c in store._chunks)


def test_a_full_plan_still_writes_both_marks_separately(writable):
    """Labelling and tagging answer one finding differently; both may be staged."""
    store = LabellingStore()
    plan = stage(suggest(finding())[0], connector=store, store="demo", staged_by="kim")
    body = plan.to_dict()
    execute(body, approve(body, approver="dana", reason="Reviewed the classification."),
            connector=store, executed_by="dana", staleness=FRESH)

    for chunk in store._chunks:
        assert chunk.metadata[SENSITIVITY_KEY] == "SECRET"   # from labelling
        assert chunk.metadata[EXCLUDED_KEY] is True          # from tagging


def test_the_highest_label_leads_and_all_of_them_are_kept(ran):
    store, _, _ = ran
    meta = store._chunks[0].metadata
    assert meta[SENSITIVITY_KEY] == "SECRET"          # most serious
    assert set(meta[CATEGORIES_KEY].split(",")) == {"PII", "SECRET"}


def test_metadata_values_are_scalars_several_stores_accept(ran):
    """Nested values are rejected outright by some stores; a list is not safe."""
    store, _, _ = ran
    for chunk in store._chunks:
        for key in (SENSITIVITY_KEY, CATEGORIES_KEY, LABELLED_AT_KEY, PLAN_KEY):
            assert isinstance(chunk.metadata[key], (str, int, float, bool))


# --- verification -------------------------------------------------------------

def test_verification_checks_the_label_field_not_the_exclusion_mark(ran):
    store, body, result = ran
    v = verify(result, connector=store, expected_ids={},
               labelled_ids=expected_labels(body))

    assert v.outcome == "confirmed"
    assert v.expected == 2 and v.observed == 2
    assert LABELLING_CAVEAT in v.caveats


def test_a_label_that_was_not_written_is_not_confirmed(ran):
    store, body, result = ran
    for chunk in store._chunks:                 # somebody stripped them
        chunk.metadata.pop(SENSITIVITY_KEY)

    v = verify(result, connector=store, expected_ids={},
               labelled_ids=expected_labels(body))
    assert v.outcome == "inconclusive"
    assert "does not carry the label" in v.reason


def test_the_verification_carries_the_caveat_about_what_a_label_does_not_do(ran):
    _, body, result = ran
    store, _, _ = ran
    v = verify(result, connector=store, expected_ids={},
               labelled_ids=expected_labels(body))
    assert any("does not restrict retrieval" in c for c in v.caveats)


def test_expected_labels_only_names_labelling_operations(ran):
    _, body, _ = ran
    runnable, _ = executable_operations(body)
    assert {op["action"] for op in runnable} >= {"label_sensitivity"}
    assert expected_labels(body) == {"runbooks": ["c1", "c2"]}


# --- refusals -----------------------------------------------------------------

def test_a_store_that_cannot_write_metadata_is_refused_by_name(writable):
    class ReadOnly(LabellingStore):
        def capabilities(self):
            return set()

    plan = stage(suggest(finding())[0], connector=ReadOnly(), store="demo",
                 staged_by="kim")
    _, refused = executable_operations(plan.to_dict())
    label = next(op for op in refused if op["action"] == "label_sensitivity")
    assert "metadata_write" in label["refusal"]


def test_an_operation_with_no_labels_writes_nothing():
    """Nothing to write is skipped, not reported as applied.

    Exercised at the apply boundary: editing a staged plan to remove its labels
    would invalidate its hash, which the approval gate correctly refuses.
    """
    from vecshield_platform.execution import _apply

    store = LabellingStore()
    op = {"action": "label_sensitivity", "collection": "runbooks", "finding_id": "f1",
          "labels": [], "targets": [{"chunk_id": "c1", "present": True}]}
    outcome = _apply(op, store, "plan-test")

    assert outcome.outcome == "skipped"
    assert "names no label" in outcome.detail
    assert all(SENSITIVITY_KEY not in c.metadata for c in store._chunks)
