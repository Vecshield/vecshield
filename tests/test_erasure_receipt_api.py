"""Erasure receipts through the API, and into the hash-chained audit log."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from vecshield_platform.api import StoreRegistry, create_app  # noqa: E402
from vecshield_platform.compliance import AuditLog  # noqa: E402


@pytest.fixture(autouse=True)
def writes_permitted(monkeypatch):
    """These tests execute erasures, which safe mode refuses (see
    test_erasure_coverage for the refusal itself)."""
    monkeypatch.setenv("VECSHIELD_SAFE_MODE", "0")


@pytest.fixture
def subject_store(tmp_path):
    import chromadb

    client = chromadb.PersistentClient(path=str(tmp_path / "chroma"))
    col = client.create_collection("support")
    col.add(
        ids=["t1", "t2", "t3"],
        documents=["Ticket from jane@example.com about billing.",
                   "Unrelated note about cloud costs.",
                   "Re: jane@example.com account closure."],
        embeddings=[[0.1, 0.2], [0.9, 0.1], [0.15, 0.25]],
        metadatas=[{"reporter": "jane@example.com"}, {"reporter": "ops@example.com"},
                   {"reporter": "jane@example.com"}],
    )
    return str(tmp_path / "chroma")


@pytest.fixture
def client(subject_store):
    reg = StoreRegistry()
    reg.register("docs", "chroma", path=subject_store)
    app = create_app(reg, audit_log=AuditLog())
    return TestClient(app)


def test_execute_returns_a_receipt_naming_its_methods(client):
    r = client.post("/stores/docs/erasure/execute", json={"subject": "jane@example.com"})
    assert r.status_code == 200
    body = r.json()

    receipt = body["receipt"]
    assert receipt["verification_outcome"] == "passed"
    assert receipt["total_deleted"] == 2
    assert receipt["store"] == "docs"
    assert receipt["store_kind"] == "chroma"
    # Chroma addresses chunks by id and supports query, so all three ran.
    assert receipt["verification_methods"] == [
        "enumeration", "id_reread", "retrieval_replay"]
    assert receipt["ghost_hits"] == []
    assert len(receipt["receipt_hash"]) == 64


def test_the_receipt_refuses_to_claim_compliance(client):
    r = client.post("/stores/docs/erasure/execute", json={"subject": "jane@example.com"})
    establishes = r.json()["receipt"]["establishes"]
    assert "does not establish that a regulatory obligation is satisfied" in establishes
    assert "backups" in establishes


def test_the_receipt_is_in_the_chain_and_the_chain_still_verifies(client):
    client.post("/stores/docs/erasure/execute", json={"subject": "jane@example.com"})

    listed = client.get("/stores/docs/erasure/receipts")
    assert listed.status_code == 200
    body = listed.json()
    assert body["count"] == 1
    assert body["chain_verified"] is True
    # F3: the sealed receipt names the subject by its keyed hash only.
    assert body["receipts"][0]["subject"].startswith("subject-key:")
    assert body["receipts"][0]["seq"] >= 0

    audit = client.get("/audit-log")
    actions = [e["action"] for e in audit.json()["entries"]]
    assert "erasure_receipt" in actions
    assert "jane@example.com" not in audit.text


def test_receipts_are_scoped_to_their_store(client):
    client.post("/stores/docs/erasure/execute", json={"subject": "jane@example.com"})
    assert client.get("/stores/nope/erasure/receipts").status_code == 404


def test_a_subject_with_no_matches_produces_no_receipt(client):
    r = client.post("/stores/docs/erasure/execute",
                    json={"subject": "nobody@example.com"})
    assert r.status_code == 200
    assert "receipt" not in r.json()
    assert client.get("/stores/docs/erasure/receipts").json()["count"] == 0
