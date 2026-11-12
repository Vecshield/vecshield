"""Retrieval exposure probe: replayed vectors, classified hits, honest states."""

from __future__ import annotations

import json

from vecshield.classify import RegexClassifier
from vecshield.models import Chunk, Collection, QueryHit, VectorStore
from vecshield_platform.connectors.base import Connector, UnsupportedCapability
from vecshield_platform.crypto.retrieval import (
    probe_retrieval_exposure,
    representation_class,
)

SSN = "123-45-6789"
EMAIL = "john.doe@example.com"


class RetrievalConnector(Connector):
    """In-memory store whose query() returns the nearest stored chunks.

    ``render`` rewrites a hit's text as the store would return it, so a test
    can model a store (or an application layer) that masks on the way out.
    """

    kind = "memory"

    def __init__(self, chunks, *, query=True, enumerable=True, render=None,
                 fail_queries=False):
        self.chunks = chunks
        self.can_query = query
        self.content_enumerable = enumerable
        self.render = render or (lambda text: text)
        self.fail_queries = fail_queries
        self.queries: list[list[float]] = []
        self.writes = 0

    def describe(self):
        return VectorStore(kind=self.kind, name="memory", endpoint="memory://",
                           collections=self.list_collections())

    def list_collections(self):
        return [Collection(name="docs", count=len(self.chunks))]

    def capabilities(self):
        return {"query"} if self.can_query else set()

    def iter_chunks(self, collection, batch_size=256):
        yield from self.chunks

    def query(self, collection, vector, top_k=10, where=None):
        if self.fail_queries == "unsupported":
            raise UnsupportedCapability("no query")
        if self.fail_queries:
            raise RuntimeError(f"https://user:secret@db.internal {SSN}")
        self.queries.append(vector)
        scored = sorted(self.chunks, key=lambda c: (
            -sum(a * b for a, b in zip(vector, c.embedding or [])), c.id))
        return [QueryHit(id=c.id, score=1.0, text=self.render(c.text),
                         metadata=dict(c.metadata)) for c in scored[:top_k]]

    def upsert(self, *args, **kwargs):  # pragma: no cover - must never be called
        self.writes += 1


def _vec(i: int) -> list[float]:
    return [1.0 if j == i % 8 else 0.0 for j in range(8)]


def store(sensitive: int = 4, clean: int = 8, text=None) -> list[Chunk]:
    chunks = [Chunk(id=f"s{i}", collection="docs", embedding=_vec(i),
                    text=text or f"Customer SSN on file: {SSN}, email {EMAIL}.",
                    metadata={"source": "crm"})
              for i in range(sensitive)]
    chunks += [Chunk(id=f"c{i}", collection="docs", embedding=_vec(i + 4),
                     text="The quarterly roadmap focuses on latency.",
                     metadata={"source": "wiki"})
               for i in range(clean)]
    return chunks


def outcome(job):
    [item] = job.stats["check_outcomes"]
    return item


def _mask(text):
    return (text or "").replace(SSN, "***-**-6789").replace(EMAIL, "j*******@example.com")


def test_plaintext_returned_is_observed_exposure_with_one_medium_finding():
    conn = RetrievalConnector(store())
    job = probe_retrieval_exposure(conn, "docs", classifier=RegexClassifier(),
                                   samples=6, top_k=3)
    item = outcome(job)
    cov = item["coverage"]
    assert item["check"] == "retrieval_exposure" and item["collection"] == "docs"
    assert cov["crypto_state"] == "observed_exposure"
    assert item["outcome"] == "inconclusive"
    assert cov["probes"] == 6 and cov["top_k"] == 3 and cov["hits"] == 18
    assert cov["returned_plaintext"] > 0
    assert cov["returned_sensitive"] == cov["returned_plaintext"] + cov["returned_protected"]
    assert cov["complete"] is False and cov["sampled"] is True
    assert 0 < len(cov["examples"]) <= 5
    [finding] = job.findings
    assert finding.category == "retrieval_exposure"
    assert finding.severity.value == "medium"
    assert "readable by an authenticated retrieval client" in finding.description
    assert "does not mean the data is unencrypted on disk" in finding.description
    assert conn.writes == 0


def test_protected_representation_returned_passes_without_finding():
    # The identifier is detected under a sensitive key, but it is pseudonymous.
    chunks = [Chunk(id=f"p{i}", collection="docs", embedding=_vec(i),
                    text="Renewal notes for the account.",
                    metadata={"customer_id": f"550e8400-e29b-41d4-a716-44665544000{i}"})
              for i in range(4)]
    conn = RetrievalConnector(chunks)
    job = probe_retrieval_exposure(conn, "docs", classifier=RegexClassifier(),
                                   samples=4, top_k=2)
    item = outcome(job)
    assert item["coverage"]["crypto_state"] == "protected_representation"
    assert item["outcome"] == "passed"
    assert item["coverage"]["returned_protected"] > 0
    assert item["coverage"]["returned_plaintext"] == 0
    assert not job.findings


def test_masked_on_retrieval_is_not_applicable_when_nothing_is_detected():
    # Values masked beyond what detectors recognise leave nothing sensitive.
    conn = RetrievalConnector(store(), render=_mask)
    job = probe_retrieval_exposure(conn, "docs", classifier=RegexClassifier(),
                                   samples=4, top_k=2)
    item = outcome(job)
    assert item["coverage"]["crypto_state"] in {"not_applicable", "protected_representation"}
    assert item["coverage"]["returned_plaintext"] == 0
    assert not job.findings


def test_no_query_capability_is_not_observable_and_not_a_failure():
    conn = RetrievalConnector(store(), query=False)
    job = probe_retrieval_exposure(conn, "docs", classifier=RegexClassifier())
    item = outcome(job)
    assert item["coverage"]["crypto_state"] == "not_observable"
    assert item["outcome"] == "unsupported"
    assert "query" in item["reason"]
    assert not job.findings
    assert conn.queries == []


def test_inventory_only_store_is_not_observable():
    conn = RetrievalConnector(store(), enumerable=False)
    item = outcome(probe_retrieval_exposure(conn, "docs", classifier=RegexClassifier()))
    assert item["coverage"]["crypto_state"] == "not_observable"
    assert item["outcome"] == "unsupported"


def test_query_raising_unsupported_is_not_observable():
    conn = RetrievalConnector(store(), fail_queries="unsupported")
    item = outcome(probe_retrieval_exposure(conn, "docs", classifier=RegexClassifier()))
    assert item["coverage"]["crypto_state"] == "not_observable"
    assert item["outcome"] == "unsupported"


def test_no_sensitive_content_is_not_applicable():
    conn = RetrievalConnector(store(sensitive=0, clean=6))
    job = probe_retrieval_exposure(conn, "docs", classifier=RegexClassifier(),
                                   samples=4, top_k=3)
    item = outcome(job)
    assert item["coverage"]["crypto_state"] == "not_applicable"
    assert item["outcome"] == "passed"
    assert item["coverage"]["returned_sensitive"] == 0
    assert "not proof" in item["coverage"]["note"]
    assert not job.findings


def test_vectors_not_returned_by_connector_is_not_observable():
    chunks = [Chunk(id="a", collection="docs", text=f"SSN {SSN}")]
    item = outcome(probe_retrieval_exposure(RetrievalConnector(chunks), "docs",
                                            classifier=RegexClassifier()))
    assert item["coverage"]["crypto_state"] == "not_observable"


def test_failing_queries_are_an_error_without_leaking_the_message():
    conn = RetrievalConnector(store(), fail_queries=True)
    job = probe_retrieval_exposure(conn, "docs", classifier=RegexClassifier(), samples=3)
    item = outcome(job)
    assert item["outcome"] == "error"
    assert item["coverage"]["query_errors"] == 3
    dumped = json.dumps(job.to_dict())
    assert "secret" not in dumped and SSN not in dumped


def test_job_json_never_contains_raw_values_or_hit_ids():
    conn = RetrievalConnector(store())
    job = probe_retrieval_exposure(conn, "docs", classifier=RegexClassifier(),
                                   samples=6, top_k=3)
    dumped = json.dumps(job.to_dict())
    assert SSN not in dumped
    assert EMAIL not in dumped
    assert "Customer SSN on file" not in dumped
    assert '"s0"' not in dumped


def test_sampling_is_deterministic_and_prefers_sensitive_chunks():
    chunks = store(sensitive=10, clean=10)
    first = RetrievalConnector(chunks)
    second = RetrievalConnector(list(reversed(chunks)))
    a = probe_retrieval_exposure(first, "docs", classifier=RegexClassifier(), samples=8)
    b = probe_retrieval_exposure(second, "docs", classifier=RegexClassifier(), samples=8)
    assert first.queries == second.queries
    assert outcome(a)["coverage"]["sensitive_probes"] == 6  # 8 - 8 // 4
    assert {k: v for k, v in outcome(a)["coverage"].items() if k != "examples"} == \
        {k: v for k, v in outcome(b)["coverage"].items() if k != "examples"}


def test_sample_backfills_when_one_kind_is_scarce():
    conn = RetrievalConnector(store(sensitive=1, clean=10))
    job = probe_retrieval_exposure(conn, "docs", classifier=RegexClassifier(), samples=5)
    assert outcome(job)["coverage"]["sensitive_probes"] == 1
    assert outcome(job)["coverage"]["probes"] == 5


def test_max_chunks_caps_enumeration_and_is_recorded():
    conn = RetrievalConnector(store(sensitive=4, clean=8))
    item = outcome(probe_retrieval_exposure(conn, "docs", classifier=RegexClassifier(),
                                            samples=2, max_chunks=3))
    assert item["coverage"]["chunks_scanned"] == 3
    assert item["coverage"]["limit_reached"] is True


def test_returned_hits_are_judged_by_the_data_representation_rules():
    assert representation_class("***-**-6789") == "masked"
    assert representation_class("411111******1111") == "truncated"
    assert representation_class("XXXX-XXXX-XXXX-1111") == "truncated"
    assert representation_class("550e8400-e29b-41d4-a716-446655440000",
                                key="customer_id", key_context=True) == "pseudonymous"
    assert representation_class(SSN) == "plaintext"
    # A run of x inside a word is not a mask.
    assert representation_class("maxxxwell@example.com") == "plaintext"

def test_returned_chunks_are_counted_once_and_hits_keep_occurrences():
    # Every probe returns the same nearest chunks, so occurrences repeat.
    chunks = [Chunk(id=f"s{i}", collection="docs", embedding=[1.0, 0.0],
                    text=f"Customer SSN on file: {SSN}.") for i in range(3)]
    chunks += [Chunk(id=f"c{i}", collection="docs", embedding=[0.0, 1.0],
                     text="The quarterly roadmap focuses on latency.") for i in range(3)]
    conn = RetrievalConnector(chunks)
    cov = outcome(probe_retrieval_exposure(conn, "docs", classifier=RegexClassifier(),
                                           samples=4, top_k=2))["coverage"]
    assert cov["probes"] == 4 and cov["hits"] == 8
    assert cov["distinct_hits"] < cov["hits"]
    assert cov["returned_sensitive"] <= cov["distinct_hits"]
    assert cov["returned_plaintext"] == cov["returned_sensitive"] <= 3
    assert cov["returned_protected"] == 0


def test_reasons_are_one_short_sentence_with_details_in_note():
    scenarios = [
        RetrievalConnector(store()),
        RetrievalConnector(store(), render=_mask),
        RetrievalConnector(store(sensitive=0, clean=4)),
        RetrievalConnector(store(), query=False),
        RetrievalConnector(store(), enumerable=False),
        RetrievalConnector(store(), fail_queries=True),
        RetrievalConnector([Chunk(id="a", collection="docs", text=f"SSN {SSN}")]),
        RetrievalConnector([Chunk(id=f"p{i}", collection="docs", embedding=_vec(i),
                                  metadata={"customer_id": f"550e8400-e29b-41d4-a716-44665544000{i}"})
                            for i in range(2)]),
    ]
    for conn in scenarios:
        item = outcome(probe_retrieval_exposure(conn, "docs", classifier=RegexClassifier(),
                                                samples=4, top_k=2))
        reason = item["reason"]
        assert len(reason) <= 120, reason
        assert "(s)" not in reason and reason.count(". ") == 0, reason
    exposed = outcome(probe_retrieval_exposure(RetrievalConnector(store()), "docs",
                                               classifier=RegexClassifier(), samples=4))
    assert "retrieval client" in exposed["reason"]
    assert "top_k=5" in exposed["coverage"]["note"]
    assert "does not mean the data is unencrypted on disk" in exposed["coverage"]["note"]


def test_single_chunk_reasons_are_singular():
    chunks = [Chunk(id="s0", collection="docs", embedding=[1.0], text=f"SSN on file {SSN}.")]
    item = outcome(probe_retrieval_exposure(RetrievalConnector(chunks), "docs",
                                            classifier=RegexClassifier(), samples=1, top_k=1))
    assert item["reason"] == ("1 of 1 returned chunk exposed plaintext sensitive data "
                              "to a retrieval client.")
