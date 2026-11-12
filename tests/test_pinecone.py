"""Pinecone connector tests with a fake client (cloud — no live key here)."""

from __future__ import annotations

import pytest

pytest.importorskip("pinecone")


class _FakeIndex:
    def describe_index_stats(self):
        return {"dimension": 4, "total_vector_count": 3,
                "namespaces": {"": {"vector_count": 3}}}

    def list(self, namespace=None):
        yield ["v0", "v1", "v2"]

    def fetch(self, ids, namespace=None):
        meta = {"v0": {"text": "leaked AKIAIOSFODNN7EXAMPLE"},
                "v1": {"text": "email jane@x.io"},
                "v2": {"text": "benign"}}
        return {"vectors": {i: {"values": [0.1, 0.2, 0.3, 0.4],
                                "metadata": meta[i]} for i in ids}}

    def query(self, vector, top_k, namespace=None, include_metadata=True, filter=None):
        return {"matches": [{"id": "v0", "score": 0.99,
                             "metadata": {"text": "leaked AKIAIOSFODNN7EXAMPLE"}}]}


class _FakePinecone:
    def __init__(self, api_key=None):
        self.api_key = api_key

    def list_indexes(self):
        return [{"name": "rag", "dimension": 4}]

    def Index(self, name):  # noqa: N802 (match pinecone API)
        return _FakeIndex()


@pytest.fixture
def patched(monkeypatch):
    import pinecone
    monkeypatch.setattr(pinecone, "Pinecone", _FakePinecone)


def test_requires_api_key(patched):
    from vecshield_platform.connectors.pinecone import PineconeConnector
    with pytest.raises(ValueError):
        PineconeConnector()


def test_list_iter_query_scan(patched):
    from vecshield.classify import RegexClassifier
    from vecshield_platform.connectors.pinecone import PineconeConnector
    from vecshield.models import Severity
    from vecshield_platform.scan import scan_store

    conn = PineconeConnector(api_key="fake-key-123456")
    cols = {c.name: c for c in conn.describe().collections}
    assert "rag" in cols and cols["rag"].dimension == 4

    chunks = list(conn.iter_chunks("rag"))
    assert len(chunks) == 3
    assert any("AKIA" in (c.text or "") for c in chunks)

    hits = conn.query("rag", [0.1, 0.2, 0.3, 0.4], top_k=1)
    assert hits[0].id == "v0"

    job = scan_store(conn, classifier=RegexClassifier())
    assert job.max_severity == Severity.CRITICAL


def test_namespace_split():
    from vecshield_platform.connectors.pinecone import _split
    assert _split("idx") == ("idx", "")
    assert _split("idx/tenant-a") == ("idx", "tenant-a")
