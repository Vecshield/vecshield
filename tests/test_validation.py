"""Live connector validation harness tests."""

from __future__ import annotations

from typing import Iterator

from vecshield_platform.connectors.base import Connector
from vecshield.models import ApiKey, Chunk, Collection, QueryHit, VectorStore
from vecshield_platform.validation import validate_connector


class _ValidatingConnector(Connector):
    kind = "fake"

    def capabilities(self) -> set[str]:
        return {"query", "api_keys"}

    def describe(self) -> VectorStore:
        return VectorStore(
            kind=self.kind,
            name="fake://validate",
            endpoint="fake://validate",
            collections=[Collection(name="docs", count=2, dimension=3)],
        )

    def list_collections(self) -> list[Collection]:
        return self.describe().collections

    def iter_chunks(self, collection: str, batch_size: int = 256) -> Iterator[Chunk]:
        yield Chunk(
            id="a",
            collection=collection,
            text="email jane@example.com",
            embedding=[0.1, 0.2, 0.3],
        )
        yield Chunk(
            id="b",
            collection=collection,
            text="benign",
            embedding=[0.2, 0.3, 0.4],
        )

    def query(self, collection: str, vector: list[float], top_k: int = 10, where=None):
        return [QueryHit(id="a", score=1.0)]

    def list_api_keys(self) -> list[ApiKey]:
        return [ApiKey(id="k1", name="read-all", actions=["read"], namespaces=["*"])]


def test_validate_connector_exercises_contract():
    result = validate_connector(_ValidatingConnector(), sample_chunks=2)
    assert result.ok
    assert {c.name for c in result.checks} == {
        "describe", "sample_chunks", "classification_scan", "query", "api_keys"
    }
    assert any(f.category == "data_classification" for f in result.findings)
    assert any(f.category == "access_control" for f in result.findings)


def test_validate_connector_records_failures():
    class Broken(_ValidatingConnector):
        def iter_chunks(self, collection: str, batch_size: int = 256):
            raise RuntimeError("boom")

    result = validate_connector(Broken(), run_scan=False, run_query=False)
    assert not result.ok
    assert any(c.name == "sample_chunks" and not c.ok for c in result.checks)
