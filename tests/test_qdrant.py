"""Qdrant connector tests against a live server.

Gated on a reachable Qdrant at VECSHIELD_QDRANT_URL (defaults to the local dev
container). Skipped if qdrant-client is missing or the server is unreachable.
"""

from __future__ import annotations

import os

import pytest

URL = os.environ.get("VECSHIELD_QDRANT_URL", "http://localhost:56333")


def _available() -> bool:
    try:
        from qdrant_client import QdrantClient
    except ImportError:
        return False
    try:
        QdrantClient(url=URL, timeout=2).get_collections()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _available(), reason="Qdrant not reachable at VECSHIELD_QDRANT_URL"
)


def _emb(seed: int, dim: int = 8) -> list[float]:
    return [((seed * (i + 7)) % 97) / 97.0 for i in range(dim)]


@pytest.fixture
def seeded_qdrant():
    from qdrant_client import QdrantClient, models

    client = QdrantClient(url=URL)
    name = "shared_rag"
    if client.collection_exists(name):
        client.delete_collection(name)
    client.create_collection(
        collection_name=name,
        vectors_config=models.VectorParams(size=8, distance=models.Distance.COSINE),
    )
    points = []
    for i in range(6):
        points.append(models.PointStruct(
            id=i + 1, vector=_emb(i + 1),
            payload={"tenant_id": "acme", "content": f"acme doc {i} email a{i}@x.io"}))
    for i in range(6):
        points.append(models.PointStruct(
            id=i + 100, vector=_emb(i + 50),
            payload={"tenant_id": "globex", "content": f"globex doc {i}"}))
    client.upsert(collection_name=name, points=points)
    yield name
    client.delete_collection(name)


def test_describe_and_dimension(seeded_qdrant):
    from vecshield_platform.connectors.qdrant import QdrantConnector

    with QdrantConnector(url=URL) as conn:
        store = conn.describe()
    col = next(c for c in store.collections if c.name == seeded_qdrant)
    assert col.dimension == 8
    assert col.count == 12


def test_iter_chunks_text_and_vector(seeded_qdrant):
    from vecshield_platform.connectors.qdrant import QdrantConnector

    with QdrantConnector(url=URL) as conn:
        chunks = list(conn.iter_chunks(seeded_qdrant))
    assert len(chunks) == 12
    assert all(c.text for c in chunks)
    assert all(c.embedding and len(c.embedding) == 8 for c in chunks)


def test_isolation_prober_on_qdrant(seeded_qdrant):
    # The prober is connector-agnostic: same HIGH bleed finding as on Chroma.
    from vecshield_platform.access import probe_isolation
    from vecshield_platform.connectors.qdrant import QdrantConnector
    from vecshield.models import Severity

    with QdrantConnector(url=URL) as conn:
        job = probe_isolation(conn, seeded_qdrant, tenant_field="tenant_id")

    assert set(job.stats["tenants"]) == {"acme", "globex"}
    assert any(f.severity == Severity.HIGH and "convention-only" in f.title
               for f in job.findings)
    # Qdrant honors the payload filter -> no CRITICAL, and the canary finds nothing.
    assert job.max_severity != Severity.CRITICAL
    [outcome] = job.stats["check_outcomes"]
    assert outcome["outcome"] == "failed"  # shared collection: convention-only
    assert outcome["coverage"]["canary"] == "passed"
    assert outcome["coverage"]["filter_enforcement"] in ("verified", "partially_verified")
