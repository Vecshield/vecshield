"""The assessment contract against real servers: pgvector and Qdrant.

Each store is seeded with the scenario from ``assessment_contract`` and audited
through the API, exactly as ``tests/test_full_assessment_contract.py`` does for
embedded Chroma. The outcomes the data decides (every integrity detector, the
classification, the planted evidence) must match on every store. Posture and
store controls are store facts; only the ones the other container tests
already establish are pinned, so these run with ``strict=False``.

pgvector also gets a real erasure: a subject's chunk is deleted from Postgres
and the deletion verified, the write path no other test drives against a real
server.
"""

from __future__ import annotations

import uuid

import pytest

pytest.importorskip("testcontainers")
pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from assessment_contract import (  # noqa: E402
    AUDIT_REQUEST,
    CLEAN,
    DIM,
    PLANTED,
    assert_capped,
    assert_contract,
    scenario,
)
from vecshield_platform.api import create_app  # noqa: E402
from vecshield_platform.api.config_store import ConfigStore  # noqa: E402
from vecshield_platform.history import ScanHistory  # noqa: E402

pytestmark = pytest.mark.integration

_PGVECTOR_IMAGE = "pgvector/pgvector:pg16"
_QDRANT_IMAGE = "qdrant/qdrant:v1.14.1"
_METADATA = ("source", "chunk_index", "version", "tenant_id", "ingested_at")


def _client(tmp_path, store_id: str, kind: str, conn: dict) -> TestClient:
    app = create_app(config_store=ConfigStore(path=str(tmp_path / "config.json")),
                     scan_history=ScanHistory(), serve_ui=False)
    client = TestClient(app)
    created = client.post("/admin/stores", json={"store_id": store_id, "kind": kind,
                                                 "conn": conn})
    assert created.status_code == 200, created.text
    return client


def _audit(client: TestClient, store_id: str, **extra) -> dict:
    response = client.post(f"/stores/{store_id}/audit", json={**AUDIT_REQUEST, **extra})
    assert response.status_code == 200, response.text
    return response.json()


# --- pgvector ----------------------------------------------------------------

@pytest.fixture(scope="module")
def pg_dsn(docker_available):
    pytest.importorskip("psycopg")
    from testcontainers.postgres import PostgresContainer

    with PostgresContainer(_PGVECTOR_IMAGE) as pg:
        dsn = (f"host={pg.get_container_host_ip()} port={pg.get_exposed_port(5432)} "
               f"dbname={pg.dbname} user={pg.username} password={pg.password}")
        _seed_pgvector(dsn)
        yield dsn


def _seed_pgvector(dsn: str) -> None:
    import psycopg

    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("CREATE EXTENSION IF NOT EXISTS vector")
        for name, chunks in scenario().collections.items():
            cur.execute(
                f"CREATE TABLE {name} (id text PRIMARY KEY, content text, "
                f"embedding vector({DIM}), source text, chunk_index integer, "
                "version text, tenant_id text, ingested_at text)")
            # Cosine, so the store reports the metric the scenario was built in.
            cur.execute(f"CREATE INDEX ON {name} USING hnsw (embedding vector_cosine_ops)")
            cur.executemany(
                f"INSERT INTO {name} (id, content, embedding, "
                f"{', '.join(_METADATA)}) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                [(c.id, c.text, "[" + ",".join(map(str, c.embedding)) + "]",
                  *(c.metadata.get(key) for key in _METADATA)) for c in chunks])
        conn.commit()


@pytest.fixture(scope="module")
def pg_client(pg_dsn, tmp_path_factory):
    return _client(tmp_path_factory.mktemp("pg"), "contract-pg", "pgvector",
                   {"dsn": pg_dsn})


#: What earlier container tests establish about the stock pgvector image.
PGVECTOR_OUTCOMES = {
    "authentication": "passed",       # scram-sha-256
    "server_hardening": "failed",     # listens on '*' with ssl off
    # No row security: filters hold only when every caller supplies one.
    ("tenant_isolation", CLEAN): ("failed", "inconclusive"),
    ("tenant_isolation", PLANTED): ("failed", "inconclusive"),
}


def test_pgvector_meets_the_contract(pg_client):
    audit = _audit(pg_client, "contract-pg")
    assert_contract(audit, store_outcomes=PGVECTOR_OUTCOMES, store_incomplete=None,
                    strict=False)


def test_a_capped_pgvector_run_never_passes(pg_client):
    assert_capped(_audit(pg_client, "contract-pg", max_chunks_per_collection=50),
                  limit=50)


def test_pgvector_erasure_deletes_and_verifies(pg_dsn):
    """A real delete in Postgres: the subject's chunk is gone and stays gone."""
    from vecshield_platform.compliance import erasure_impact, execute_erasure, plan_erasure
    from vecshield_platform.connectors.pgvector import PgVectorConnector

    subject = "jane.roe@example.com"
    conn = PgVectorConnector(dsn=pg_dsn, tables=[PLANTED])
    try:
        report = erasure_impact(conn, subject)
        assert report.chunks_to_delete == 1 and report.coverage_complete
        before = {c.id for c in conn.iter_chunks(PLANTED)}

        execution = execute_erasure(conn, plan_erasure(report))

        assert execution.total_deleted == 1
        assert execution.verification.ghost_hits == []
        assert execution.verification.ok is True
        assert "retrieval_replay" in execution.verification.methods
        after = {c.id for c in conn.iter_chunks(PLANTED)}
        assert before - after == {"pii-0"}
    finally:
        conn.close()


# --- Qdrant ------------------------------------------------------------------

def _qdrant_id(chunk_id: str) -> str:
    # Qdrant ids are unsigned integers or UUIDs; derive a stable UUID.
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"vecshield-contract/{chunk_id}"))


@pytest.fixture(scope="module")
def qdrant_url(docker_available):
    pytest.importorskip("qdrant_client")
    from testcontainers.core.container import DockerContainer
    from testcontainers.core.waiting_utils import wait_for_logs

    container = DockerContainer(_QDRANT_IMAGE).with_exposed_ports(6333)
    with container:
        wait_for_logs(container, "Actix runtime found", timeout=60)
        url = (f"http://{container.get_container_host_ip()}:"
               f"{container.get_exposed_port(6333)}")
        _seed_qdrant(url)
        yield url


def _seed_qdrant(url: str) -> None:
    from qdrant_client import QdrantClient
    from qdrant_client.models import Distance, PointStruct, VectorParams

    client = QdrantClient(url=url)
    for name, chunks in scenario().collections.items():
        client.create_collection(collection_name=name,
                                 vectors_config=VectorParams(size=DIM,
                                                             distance=Distance.COSINE))
        client.upsert(collection_name=name, wait=True, points=[
            PointStruct(id=_qdrant_id(c.id), vector=c.embedding,
                        payload={"content": c.text, **c.metadata}) for c in chunks])
    client.close()


@pytest.fixture(scope="module")
def qdrant_client(qdrant_url, tmp_path_factory):
    return _client(tmp_path_factory.mktemp("qdrant"), "contract-qdrant", "qdrant",
                   {"url": qdrant_url})


#: What the Qdrant container test establishes about an image with no API key.
QDRANT_OUTCOMES = {
    "authentication": "failed",       # serves data anonymously
    ("tenant_isolation", CLEAN): ("failed", "inconclusive"),
    ("tenant_isolation", PLANTED): ("failed", "inconclusive"),
}


def test_qdrant_meets_the_contract(qdrant_client):
    audit = _audit(qdrant_client, "contract-qdrant")
    assert_contract(audit, store_outcomes=QDRANT_OUTCOMES, store_incomplete=None,
                    strict=False, store_id=_qdrant_id)


def test_a_capped_qdrant_run_never_passes(qdrant_client):
    assert_capped(_audit(qdrant_client, "contract-qdrant", max_chunks_per_collection=50),
                  limit=50)
