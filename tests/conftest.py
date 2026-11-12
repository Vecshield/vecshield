"""Shared fixtures: a local Chroma store seeded with synthetic chunks, plus an
in-memory FakeConnector for runtime-monitoring tests."""

from __future__ import annotations

import hashlib
from typing import Callable, Iterator, Optional

import pytest

from vecshield_platform.connectors.base import Connector
from vecshield.models import Chunk, Collection, QueryHit, VectorStore


class FakeConnector(Connector):
    """Dependency-free connector for runtime tests. `hits_fn(collection, vector,
    top_k, where, call_index)` returns the QueryHit list for each query."""

    kind = "fake"

    def __init__(self, sizes: dict[str, int],
                 hits_fn: Optional[Callable[..., list[QueryHit]]] = None):
        self._sizes = sizes
        self._hits_fn = hits_fn
        self._calls = 0

    def capabilities(self) -> set[str]:
        return {"query"}

    def describe(self) -> VectorStore:
        return VectorStore(
            kind=self.kind, name="fake://store", endpoint="fake://store",
            collections=[Collection(name=n, count=c) for n, c in self._sizes.items()],
        )

    def list_collections(self) -> list[Collection]:
        return self.describe().collections

    def iter_chunks(self, collection: str, batch_size: int = 256) -> Iterator[Chunk]:
        return iter(())

    def query(self, collection, vector, top_k=10, where=None) -> list[QueryHit]:
        i = self._calls
        self._calls += 1
        if self._hits_fn:
            return self._hits_fn(collection, vector, top_k, where, i)
        return [QueryHit(id=f"{collection}-{i}-{k}", score=1.0) for k in range(top_k)]


@pytest.fixture
def make_fake_connector():
    def _make(sizes, hits_fn=None):
        return FakeConnector(sizes, hits_fn)
    return _make

# Synthetic sensitive content. NONE of this is real.
SENSITIVE_DOCS = [
    "Please contact john.doe@example.com about the invoice.",          # PII email
    "Customer SSN on file: 123-45-6789 for verification.",             # PII ssn
    "Charge the card 4111 1111 1111 1111 expiring soon.",              # PCI (luhn-valid)
    "Deploy key: AKIAIOSFODNN7EXAMPLE was committed by mistake.",      # SECRET aws
    "Reach the patient at (415) 555-0132 for the lab results.",        # PII phone
]

CLEAN_DOCS = [
    "The quarterly roadmap focuses on latency improvements.",
    "Our mascot is a friendly otter named Pebble.",
    "Vector databases store high-dimensional embeddings.",
    "The meeting is rescheduled to next Thursday afternoon.",
    "Gradient descent converges given a suitable learning rate.",
]


def _fake_embedding(text: str, dim: int = 8) -> list[float]:
    # Deterministic toy embedding so we don't need a real model in tests. Not
    # hash(): string hashing is salted per process, so runs would differ.
    h = int.from_bytes(hashlib.sha256(text.encode()).digest()[:8], "big")
    return [((h >> (i * 4)) & 0xF) / 15.0 for i in range(dim)]


@pytest.fixture
def chroma_path(tmp_path):
    """Seed a persistent Chroma store: ~10% sensitive chunks across collections."""
    import chromadb

    client = chromadb.PersistentClient(path=str(tmp_path / "chroma"))

    docs_col = client.create_collection("prod-docs")
    # 45 clean + 5 sensitive = 50 chunks, 10% sensitive
    clean = [CLEAN_DOCS[i % len(CLEAN_DOCS)] for i in range(45)]
    docs = clean + SENSITIVE_DOCS
    docs_col.add(
        ids=[f"d{i}" for i in range(len(docs))],
        documents=docs,
        embeddings=[_fake_embedding(d) for d in docs],
        metadatas=[{"source": f"doc_{i}.txt"} for i in range(len(docs))],
    )

    clean_col = client.create_collection("clean-kb")
    clean_only = [CLEAN_DOCS[i % len(CLEAN_DOCS)] for i in range(20)]
    clean_col.add(
        ids=[f"c{i}" for i in range(len(clean_only))],
        documents=clean_only,
        embeddings=[_fake_embedding(d) for d in clean_only],
    )

    return str(tmp_path / "chroma")
