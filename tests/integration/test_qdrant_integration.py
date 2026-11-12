"""Container-backed Qdrant: writes, erasure, and three-way verification.

The first Qdrant entry in the integration suite. Everything here runs against a
real qdrant server in a throwaway container — no SDK fakes — because the two
things most likely to be silently wrong (the point-id round-trip, and whether a
delete actually removes a point from the index) cannot be proven against a
double.

Guarded so it skips (never errors) without Docker or the optional deps.
"""

from __future__ import annotations

import uuid

import pytest

pytest.importorskip("testcontainers")
pytest.importorskip("qdrant_client")

from testcontainers.core.container import DockerContainer  # noqa: E402
from testcontainers.core.waiting_utils import wait_for_logs  # noqa: E402

from vecshield_platform.compliance import (  # noqa: E402
    build_erasure_receipt,
    erasure_impact,
    execute_erasure,
    plan_erasure,
)
from vecshield_platform.connectors.qdrant import QdrantConnector  # noqa: E402

pytestmark = pytest.mark.integration

#: Pinned, so a new server release cannot change the result of an old commit.
_QDRANT_IMAGE = "qdrant/qdrant:v1.14.1"
_COLLECTION = "support_rag"
_SUBJECT = "maya@example.test"

# Integer point ids on purpose: the read path stringifies them, so a write that
# forgot to restore the native type would silently address nothing.
_DOCS = [
    (1, f"Ticket from {_SUBJECT} about a billing dispute.", [0.10, 0.90], "acme"),
    (2, "Runbook: rotating the payment gateway key.", [0.80, 0.20], "acme"),
    (3, f"CRM note: {_SUBJECT} asked us to delete their account.", [0.12, 0.88], "acme"),
    (4, "Help centre article about refunds.", [0.50, 0.50], "public"),
]


@pytest.fixture
def qdrant_url(docker_available):
    container = DockerContainer(_QDRANT_IMAGE).with_exposed_ports(6333)
    with container:
        wait_for_logs(container, "Actix runtime found", timeout=60)
        url = (f"http://{container.get_container_host_ip()}:"
               f"{container.get_exposed_port(6333)}")
        _seed(url)
        yield url


def _seed(url: str) -> None:
    from qdrant_client import QdrantClient
    from qdrant_client.models import Distance, PointStruct, VectorParams

    client = QdrantClient(url=url)
    # A fresh container per test, so the collection never exists yet.
    client.create_collection(
        collection_name=_COLLECTION,
        vectors_config=VectorParams(size=2, distance=Distance.COSINE),
    )
    client.upsert(collection_name=_COLLECTION, points=[
        PointStruct(id=pid, vector=vec,
                    payload={"content": text, "tenant_id": tenant})
        for pid, text, vec, tenant in _DOCS
    ])
    client.close()


@pytest.fixture
def connector(qdrant_url):
    with QdrantConnector(url=qdrant_url) as conn:
        yield conn


# --- reads -------------------------------------------------------------------

def test_describe_and_enumerate(connector):
    store = connector.describe()
    assert store.kind == "qdrant"
    collections = {c.name: c for c in store.collections}
    assert collections[_COLLECTION].count == len(_DOCS)
    assert collections[_COLLECTION].dimension == 2

    chunks = list(connector.iter_chunks(_COLLECTION))
    assert {c.id for c in chunks} == {"1", "2", "3", "4"}
    assert all(c.embedding for c in chunks)


def test_get_chunks_addresses_integer_ids(connector):
    chunks = connector.get_chunks(_COLLECTION, ["1", "3"])
    assert {c.id for c in chunks} == {"1", "3"}
    assert connector.get_chunks(_COLLECTION, ["999"]) == []


# --- A1: writes --------------------------------------------------------------

def test_metadata_write_merges_and_preserves_customer_fields(connector):
    changed = connector.set_chunk_metadata(
        _COLLECTION, {"1": {"vecshield_sensitivity": "high"}})
    assert changed == 1

    chunk = connector.get_chunks(_COLLECTION, ["1"])[0]
    assert chunk.metadata["vecshield_sensitivity"] == "high"
    assert chunk.metadata["tenant_id"] == "acme"        # untouched
    assert chunk.metadata["content"].startswith("Ticket from")


def test_metadata_write_does_not_count_absent_ids(connector):
    changed = connector.set_chunk_metadata(
        _COLLECTION, {"2": {"marked": True}, "999": {"marked": True}})
    assert changed == 1


def test_redaction_replaces_text_and_leaves_the_vector(connector):
    before = connector.get_chunks(_COLLECTION, ["4"])[0]
    assert connector.replace_chunk_text(_COLLECTION, "4", "[redacted]") is True

    after = connector.get_chunks(_COLLECTION, ["4"])[0]
    assert after.text == "[redacted]"
    assert after.embedding == pytest.approx(before.embedding, abs=1e-6)
    assert after.metadata["tenant_id"] == "public"


def test_capabilities_match_what_the_store_can_do(connector):
    assert {"metadata_write", "redact", "delete", "query"} <= connector.capabilities()


# --- B3: erasure, verified three ways ----------------------------------------

def test_erasure_is_verified_by_enumeration_id_reread_and_replay(connector):
    report = erasure_impact(connector, _SUBJECT)
    assert report.chunks_to_delete == 2
    assert report.coverage_complete

    execution = execute_erasure(connector, plan_erasure(report))
    verification = execution.verification

    assert execution.total_deleted == 2
    assert verification.methods == ["enumeration", "id_reread", "retrieval_replay"]
    assert verification.ghost_hits == []
    assert verification.outcome == "passed"
    assert execution.verified is True

    # And the store really is done with them.
    assert connector.get_chunks(_COLLECTION, ["1", "3"]) == []
    remaining = {c.id for c in connector.iter_chunks(_COLLECTION)}
    assert remaining == {"2", "4"}


def test_the_receipt_records_a_real_run(connector):
    report = erasure_impact(connector, _SUBJECT)
    execution = execute_erasure(connector, plan_erasure(report))
    receipt = build_erasure_receipt(execution, store="qdrant-int", actor="tests",
                                    store_kind="qdrant",
                                    scope=list(execution.deleted))

    assert receipt["verification_outcome"] == "passed"
    assert receipt["total_deleted"] == 2
    assert receipt["coverage_complete"] is True
    assert "retrieval_replay" in receipt["verification_methods"]
    assert len(receipt["receipt_hash"]) == 64


def test_replay_probe_uses_the_stores_own_vector(connector):
    """No embedding model is involved: the probe is what qdrant already held."""
    report = erasure_impact(connector, _SUBJECT)
    doomed = plan_erasure(report).by_collection[_COLLECTION]
    stored = {c.id: c.embedding for c in connector.get_chunks(_COLLECTION, doomed)}
    assert all(v is not None for v in stored.values())

    execute_erasure(connector, plan_erasure(report))
    # Replaying a deleted vector must no longer return its id.
    for cid, vector in stored.items():
        hits = connector.query(_COLLECTION, vector, top_k=10)
        assert cid not in {str(h.id) for h in hits}


# --- A2: authentication posture against a real, open server ------------------

def test_an_unauthenticated_qdrant_is_reported_as_serving_data_anonymously(connector):
    from vecshield_platform.posture import check_authentication

    findings = check_authentication(connector.describe(), exposure="private")
    assert len(findings) == 1
    assert findings[0].category == "authentication"
    assert findings[0].severity.name == "HIGH"
    assert findings[0].evidence["probe"]["reach"] == "data"


def test_uuid_ids_round_trip_too(connector):
    """The other id type qdrant allows."""
    from qdrant_client.models import PointStruct

    pid = str(uuid.uuid4())
    connector._client.upsert(collection_name=_COLLECTION, points=[
        PointStruct(id=pid, vector=[0.3, 0.7], payload={"content": "uuid doc"})])

    assert connector.set_chunk_metadata(_COLLECTION, {pid: {"marked": True}}) == 1
    assert connector.get_chunks(_COLLECTION, [pid])[0].metadata["marked"] is True
