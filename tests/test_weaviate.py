"""Weaviate connector tests against a live instance.

Gated on a reachable Weaviate at VECSHIELD_WEAVIATE_{HOST,PORT,GRPC}
(defaults to the local dev container). Skipped otherwise.
"""

from __future__ import annotations

import os

import pytest

pytest.importorskip("weaviate")

HOST = os.environ.get("VECSHIELD_WEAVIATE_HOST", "localhost")
PORT = int(os.environ.get("VECSHIELD_WEAVIATE_PORT", "8090"))
GRPC = int(os.environ.get("VECSHIELD_WEAVIATE_GRPC", "50051"))


def _available() -> bool:
    import urllib.request
    try:
        urllib.request.urlopen(f"http://{HOST}:{PORT}/v1/.well-known/ready", timeout=2)
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _available(), reason="Weaviate not reachable")


@pytest.fixture
def seeded():
    import weaviate
    from weaviate.classes.config import Configure, DataType, Property

    client = weaviate.connect_to_local(host=HOST, port=PORT, grpc_port=GRPC,
                                       skip_init_checks=True)
    if client.collections.exists("Docs"):
        client.collections.delete("Docs")
    client.collections.create(
        "Docs",
        properties=[Property(name="content", data_type=DataType.TEXT),
                    Property(name="tenant_id", data_type=DataType.TEXT)],
        vectorizer_config=Configure.Vectorizer.none())
    col = client.collections.get("Docs")
    data = [("leaked AKIAIOSFODNN7EXAMPLE", "acme", [0.1, 0.2, 0.3, 0.4]),
            ("email jane@x.io", "acme", [0.2, 0.3, 0.4, 0.5]),
            ("benign note", "globex", [0.9, 0.8, 0.7, 0.6]),
            ("ssn 123-45-6789", "globex", [0.15, 0.25, 0.35, 0.45])]
    for t, ten, v in data:
        col.data.insert(properties={"content": t, "tenant_id": ten}, vector=v)
    client.close()
    yield
    client = weaviate.connect_to_local(host=HOST, port=PORT, grpc_port=GRPC,
                                       skip_init_checks=True)
    client.collections.delete("Docs")
    client.close()


def test_describe_iter_query(seeded):
    from vecshield_platform.connectors.weaviate import WeaviateConnector

    with WeaviateConnector(host=HOST, port=PORT, grpc_port=GRPC) as conn:
        col = next(c for c in conn.describe().collections if c.name == "Docs")
        assert col.count == 4 and col.dimension == 4
        chunks = list(conn.iter_chunks("Docs"))
        assert len(chunks) == 4 and all(c.text for c in chunks)
        hits = conn.query("Docs", [0.1, 0.2, 0.3, 0.4], top_k=2)
        assert hits and all(h.metadata.get("tenant_id") for h in hits)


def test_scan_and_isolation(seeded):
    from vecshield_platform.access import probe_isolation
    from vecshield.classify import RegexClassifier
    from vecshield_platform.connectors.weaviate import WeaviateConnector
    from vecshield.models import Severity
    from vecshield_platform.scan import scan_store

    with WeaviateConnector(host=HOST, port=PORT, grpc_port=GRPC) as conn:
        job = scan_store(conn, classifier=RegexClassifier())
        assert job.max_severity == Severity.CRITICAL
        iso = probe_isolation(conn, "Docs", tenant_field="tenant_id")
    assert any(f.severity == Severity.HIGH and "convention-only" in f.title
               for f in iso.findings)
