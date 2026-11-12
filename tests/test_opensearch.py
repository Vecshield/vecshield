"""OpenSearch k-NN connector — live (gated on OpenSearch at :9201)."""

from __future__ import annotations

import os

import pytest

pytest.importorskip("opensearchpy")

PORT = int(os.environ.get("VECSHIELD_OPENSEARCH_PORT", "9201"))


def _up() -> bool:
    import urllib.request
    try:
        urllib.request.urlopen(f"http://localhost:{PORT}/_cluster/health", timeout=2)
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _up(), reason="OpenSearch not reachable")


@pytest.fixture
def seeded():
    from opensearchpy import OpenSearch
    c = OpenSearch([{"host": "localhost", "port": PORT}], use_ssl=False, verify_certs=False)
    if c.indices.exists(index="t_docs"):
        c.indices.delete(index="t_docs")
    c.indices.create(index="t_docs", body={"settings": {"index.knn": True}, "mappings": {
        "properties": {"content": {"type": "text"}, "tenant_id": {"type": "keyword"},
                       "embedding": {"type": "knn_vector", "dimension": 4}}}})
    docs = [("leaked AKIAIOSFODNN7EXAMPLE", "acme"), ("email a@b.io", "acme"),
            ("benign", "globex"), ("ssn 123-45-6789", "globex")]
    for i, (t, ten) in enumerate(docs):
        c.index(index="t_docs", id=str(i),
                body={"content": t, "tenant_id": ten, "embedding": [0.1 * i, 0.2, 0.3, 0.4]},
                refresh=True)
    yield
    c.indices.delete(index="t_docs")


def test_full_flow(seeded):
    from vecshield_platform.access import probe_isolation
    from vecshield.classify import RegexClassifier
    from vecshield_platform.connectors.opensearch import OpenSearchConnector
    from vecshield.models import Severity
    from vecshield_platform.scan import scan_store

    with OpenSearchConnector(port=PORT) as conn:
        col = next(c for c in conn.describe().collections if c.name == "t_docs")
        assert col.count == 4 and col.dimension == 4
        chunks = list(conn.iter_chunks("t_docs"))
        assert all(c.embedding and len(c.embedding) == 4 for c in chunks)
        hits = conn.query("t_docs", [0.0, 0.2, 0.3, 0.4], top_k=2)
        assert hits and all(h.metadata.get("tenant_id") for h in hits)
        assert scan_store(conn, classifier=RegexClassifier()).max_severity == Severity.CRITICAL
        iso = probe_isolation(conn, "t_docs", tenant_field="tenant_id")
    assert any("convention-only" in f.title for f in iso.findings)
