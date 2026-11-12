"""Erasure verification against stores that only *look* like they deleted.

A vector store commonly marks a record deleted rather than removing it, and an
index built over the old vectors can keep answering for it. Re-enumerating the
collection is exactly the check a soft delete fools, so these tests assert that
a store which drops a chunk from enumeration but still serves it is reported as
a failed erasure — not a clean one.
"""

import pytest

from vecshield.models import Chunk, Collection, QueryHit, VectorStore

from vecshield_platform.compliance.erasure import (
    ErasureProbe,
    build_erasure_receipt,
    erasure_impact,
    execute_erasure,
    plan_erasure,
    verify_erasure,
)
from vecshield_platform.connectors.base import Connector


@pytest.fixture(autouse=True)
def writes_permitted(monkeypatch):
    """These tests execute erasures, which safe mode refuses (see
    test_erasure_coverage for the refusal itself)."""
    monkeypatch.setenv("VECSHIELD_SAFE_MODE", "0")


class HonestStore(Connector):
    """Deletes properly: gone from enumeration, from get_chunks, and from query."""

    kind = "honest"

    def __init__(self, texts=()):
        self.chunks = [
            Chunk(id=str(i), collection="records", text=t, embedding=[float(i), 1.0])
            for i, t in enumerate(texts)
        ]

    def capabilities(self):
        return {"delete", "query"}

    def describe(self):
        return VectorStore(kind=self.kind, name=self.kind, endpoint="memory://",
                           collections=self.list_collections())

    def list_collections(self):
        return [Collection(name="records", count=len(self._visible()))]

    def _visible(self):
        return self.chunks

    def iter_chunks(self, collection, batch_size=256):
        yield from self._visible()

    def get_chunks(self, collection, ids):
        # Overridden, so erasure verification treats id re-read as informative.
        wanted = set(ids)
        return [c for c in self._retrievable() if c.id in wanted]

    def _retrievable(self):
        return self._visible()

    def query(self, collection, vector, top_k=10, where=None):
        return [QueryHit(id=c.id, score=1.0, text=c.text, metadata=c.metadata)
                for c in self._retrievable()][:top_k]

    def delete_chunks(self, collection, ids):
        before = len(self.chunks)
        self.chunks = [c for c in self.chunks if c.id not in set(ids)]
        return before - len(self.chunks)


class GhostingStore(HonestStore):
    """Soft-deletes: hidden from enumeration, still served by the index.

    This is the failure mode the whole three-way check exists for, and no
    well-behaved store can demonstrate it — hence the double.
    """

    kind = "ghosting"

    def __init__(self, texts=()):
        super().__init__(texts)
        self.tombstoned: set[str] = set()

    def _visible(self):
        return [c for c in self.chunks if c.id not in self.tombstoned]

    def _retrievable(self):
        return self.chunks  # the index never forgot

    def delete_chunks(self, collection, ids):
        self.tombstoned.update(ids)
        return len(ids)


class NoQueryStore(HonestStore):
    """Deletes, but cannot be asked to retrieve. Replay must be unavailable."""

    kind = "noquery"

    def capabilities(self):
        return {"delete"}


SUBJECT = "maya@example.test"
DOCS = (f"ticket from {SUBJECT} about billing", "unrelated runbook text",
        f"crm note: {SUBJECT} asked for deletion")


def _erase(store):
    report = erasure_impact(store, SUBJECT)
    return execute_erasure(store, plan_erasure(report))


def test_honest_delete_verifies_by_all_three_methods():
    execution = _erase(HonestStore(DOCS))
    v = execution.verification

    assert v.outcome == "passed"
    assert v.ok is True
    assert v.methods == ["enumeration", "id_reread", "retrieval_replay"]
    assert v.ghost_hits == []
    assert execution.verified is True


def test_soft_delete_is_caught_although_enumeration_is_clean():
    store = GhostingStore(DOCS)
    execution = _erase(store)
    v = execution.verification

    # Enumeration alone would have called this clean: the subject is gone from
    # every chunk the store is willing to list.
    assert v.remaining.chunks_to_delete == 0
    assert v.remaining.coverage_complete is True

    # It is not clean.
    assert v.outcome == "failed"
    assert v.ok is False
    assert execution.verified is False
    assert v.ghost_hits, "a soft-deleted chunk was not detected"

    methods = {h["method"] for h in v.ghost_hits}
    assert methods == {"id_reread", "retrieval_replay"}
    assert any("index was not rebuilt" in h["detail"] for h in v.ghost_hits)


def test_store_without_query_cannot_replay_and_says_so():
    execution = _erase(NoQueryStore(DOCS))
    v = execution.verification

    assert "retrieval_replay" not in v.methods
    assert any("does not support query()" in lim for lim in v.method_limitations)
    # It still passes on what it could check — the limitation is recorded, and
    # the receipt carries it rather than hiding it.
    assert v.outcome == "passed"


def test_replay_ignores_a_duplicate_vector_that_was_never_deleted():
    """A different chunk with the same vector is a duplicate, not a ghost."""
    store = HonestStore(DOCS)
    store.chunks.append(Chunk(id="99", collection="records",
                              text="an unrelated chunk that happens to sit nearby",
                              embedding=[0.0, 1.0]))
    execution = _erase(store)

    assert execution.verification.ghost_hits == []
    assert execution.verification.outcome == "passed"


def test_probe_capture_needs_no_embedding_model():
    """The probe is the store's own vector, so nothing re-embeds anything."""
    store = HonestStore(DOCS)
    report = erasure_impact(store, SUBJECT)
    doomed = plan_erasure(report).by_collection["records"]
    originals = {c.id: c.embedding for c in store.get_chunks("records", doomed)}

    assert all(e is not None for e in originals.values())
    execute_erasure(store, plan_erasure(report))
    # Nothing was written back, and no model was consulted to build the probe.
    assert all(c.id not in originals for c in store.chunks)


def test_receipt_records_the_failure_and_hashes_stably():
    execution = _erase(GhostingStore(DOCS))
    receipt = build_erasure_receipt(execution, store="demo", actor="alice",
                                    store_kind="ghosting")

    assert receipt["verification_outcome"] == "failed"
    assert "soft-deleted" in receipt["method_note"]
    assert receipt["ghost_hits"]
    assert "does not establish that a regulatory obligation is satisfied" \
        in receipt["establishes"]

    again = build_erasure_receipt(execution, store="demo", actor="alice",
                                  store_kind="ghosting")
    assert receipt["receipt_hash"] == again["receipt_hash"]

    tampered = dict(receipt)
    tampered["total_deleted"] = 999
    assert tampered["receipt_hash"] == receipt["receipt_hash"]  # hash is over the body
    rebuilt = build_erasure_receipt(execution, store="demo", actor="mallory",
                                    store_kind="ghosting")
    assert rebuilt["receipt_hash"] != receipt["receipt_hash"]


def test_receipt_carries_limitations_rather_than_dropping_them():
    receipt = build_erasure_receipt(_erase(NoQueryStore(DOCS)), store="demo",
                                    actor="alice", store_kind="noquery")

    assert receipt["verification_outcome"] == "passed"
    assert any("query()" in lim for lim in receipt["limitations"])


def test_verify_erasure_standalone_reports_methods_it_could_run():
    store = HonestStore(DOCS)
    v = verify_erasure(store, SUBJECT)
    # With no deleted ids or probes supplied, only enumeration is possible.
    assert v.methods == ["enumeration"]
    assert v.outcome == "failed"  # the subject is still there


def test_probe_dict_does_not_carry_the_embedding():
    probe = ErasureProbe(chunk_id="1", collection="records", embedding=[0.1, 0.2])
    assert probe.to_dict() == {"chunk_id": "1", "collection": "records",
                               "has_embedding": True}
