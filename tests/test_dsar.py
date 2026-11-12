"""Tests for the DSAR workflow: scan_all_stores, execute_dsar, evidence_bundle."""

from __future__ import annotations

import pytest

from vecshield_platform.compliance.dsar import (
    DSARRecord,
    create_dsar,
    execute_dsar,
    scan_all_stores,
)


@pytest.fixture(autouse=True)
def writes_permitted(monkeypatch):
    """These tests execute erasures, which safe mode refuses (see
    test_erasure_coverage for the refusal itself)."""
    monkeypatch.setenv("VECSHIELD_SAFE_MODE", "0")


@pytest.fixture
def chroma_registry(tmp_path):
    """A StoreRegistry with two Chroma stores, one containing subject data."""
    import chromadb
    from vecshield_platform.api.registry import StoreRegistry
    from vecshield_platform.connectors.chroma import ChromaConnector

    # Store A: has subject data
    path_a = str(tmp_path / "store_a")
    client_a = chromadb.PersistentClient(path=path_a)
    col_a = client_a.create_collection("tickets")
    col_a.add(ids=["a1", "a2"], documents=[
        "Email from dsar@test.com about refund.",
        "General support ticket.",
    ], embeddings=[[0.1, 0.2]] * 2,
    metadatas=[{"from": "dsar@test.com"}, {"from": "other@test.com"}])

    # Store B: no subject data
    path_b = str(tmp_path / "store_b")
    client_b = chromadb.PersistentClient(path=path_b)
    col_b = client_b.create_collection("products")
    col_b.add(ids=["b1"], documents=["Product catalog entry."],
              embeddings=[[0.3, 0.4]], metadatas=[{"source": "catalog"}])

    reg = StoreRegistry()
    reg.register("store-a", "chroma", factory=lambda: ChromaConnector(path=path_a))
    reg.register("store-b", "chroma", factory=lambda: ChromaConnector(path=path_b))
    return reg


def test_create_dsar_has_pending_status():
    dsar = create_dsar("user@example.com")
    assert dsar.status == "pending"
    assert dsar.subject == "user@example.com"
    assert dsar.id.startswith("dsar-")


def test_scan_all_stores_finds_matches(chroma_registry):
    dsar = create_dsar("dsar@test.com")
    scan_all_stores(dsar, chroma_registry)

    assert dsar.status == "scanned"
    assert len(dsar.stores) == 2
    assert dsar.total_chunks_found == 1  # only store-a has the subject

    store_a = next(r for r in dsar.stores if r.store_id == "store-a")
    store_b = next(r for r in dsar.stores if r.store_id == "store-b")
    assert store_a.chunks_found == 1
    assert store_b.chunks_found == 0


def test_scan_all_stores_filtered_by_store_ids(chroma_registry):
    dsar = create_dsar("dsar@test.com")
    scan_all_stores(dsar, chroma_registry, store_ids=["store-b"])
    assert len(dsar.stores) == 1
    assert dsar.stores[0].store_id == "store-b"


def test_execute_dsar_deletes_and_verifies(chroma_registry):
    dsar = create_dsar("dsar@test.com")
    scan_all_stores(dsar, chroma_registry)
    execute_dsar(dsar, chroma_registry, verify=True)

    assert dsar.status == "executed"
    assert dsar.total_chunks_deleted == 1
    assert not dsar.stores_with_errors

    store_a = next(r for r in dsar.stores if r.store_id == "store-a")
    assert store_a.execution is not None
    assert store_a.execution.ok
    assert store_a.execution.verification.ok


def test_execute_dsar_skips_clean_stores(chroma_registry):
    dsar = create_dsar("nobody@nowhere.test")
    scan_all_stores(dsar, chroma_registry)
    execute_dsar(dsar, chroma_registry)

    # No matches in any store → nothing executed, status still executed
    assert dsar.total_chunks_deleted == 0


def test_evidence_bundle_structure(chroma_registry):
    dsar = create_dsar("dsar@test.com")
    scan_all_stores(dsar, chroma_registry)
    execute_dsar(dsar, chroma_registry, verify=True)

    bundle = dsar.evidence_bundle()
    assert bundle["dsar_id"] == dsar.id
    assert bundle["data_subject"] == "dsar@test.com"
    assert bundle["status"] == "executed"
    assert bundle["summary"]["total_chunks_deleted"] == 1
    assert "compliance_note" in bundle
    assert "per_store_detail" in bundle


def test_execute_requires_scanned_status():
    dsar = create_dsar("x@test.com")
    # pending → not scanned → should raise
    with pytest.raises(ValueError, match="scanned"):
        from vecshield_platform.api.registry import StoreRegistry
        execute_dsar(dsar, StoreRegistry())


def test_dsar_from_dict_handles_error_store():
    """A store result carrying only an error round-trips (no impact/execution)."""
    from vecshield_platform.compliance.dsar import DSARStoreResult

    dsar = DSARRecord(
        id="dsar-err",
        subject="x@test.com",
        requested_at="2024-01-01T00:00:00+00:00",
        status="scanned",
        stores=[DSARStoreResult(store_id="broken", kind="chroma",
                                error="connection refused")],
    )
    restored = DSARRecord.from_dict(dsar.to_dict())
    assert len(restored.stores) == 1
    assert restored.stores[0].error == "connection refused"
    assert restored.stores[0].impact is None
    assert restored.stores[0].execution is None
    assert restored.stores_with_errors


def test_dsar_history_persistence():
    from vecshield_platform.history import ScanHistory
    dsar = create_dsar("hist@test.com")
    dsar.status = "scanned"

    with ScanHistory() as h:
        h.save_dsar(dsar)
        rows = h.list_dsars()
        assert len(rows) == 1
        assert rows[0]["subject"] == "hist@test.com"

        row = h.get_dsar(dsar.id)
        assert row is not None
        assert "record" in row or "record_json" in row


def test_inventory_only_store_flagged_not_clean(tmp_path):
    """Inventory-only stores must be flagged, not silently reported clean."""
    from vecshield_platform.api.registry import StoreRegistry
    from vecshield_platform.connectors.base import Connector
    from vecshield.models import Collection, VectorStore

    class InventoryOnly(Connector):
        kind = "inv"
        content_enumerable = False

        def capabilities(self):
            return set()

        def describe(self):
            return VectorStore(kind=self.kind, name="inv://x", endpoint="inv://x",
                               collections=[Collection(name="kb", count=100)])

        def list_collections(self):
            return self.describe().collections

        def iter_chunks(self, collection, batch_size=256):
            return iter(())

    reg = StoreRegistry()
    reg.register("managed", "inv", factory=lambda: InventoryOnly())

    dsar = create_dsar("someone@example.com")
    scan_all_stores(dsar, reg)

    res = dsar.stores[0]
    assert res.impact is None
    assert res.error and "inventory-only" in res.error
    assert res.chunks_found == 0
    assert dsar.stores_with_errors        # surfaced as an error, not "clean"
    assert not dsar.ok


def test_dsar_roundtrip_preserves_execution(chroma_registry):
    """Rehydrating a DSAR (the GET /evidence path) must keep deletion evidence."""
    dsar = create_dsar("dsar@test.com")
    scan_all_stores(dsar, chroma_registry)
    execute_dsar(dsar, chroma_registry, verify=True)
    assert dsar.total_chunks_deleted == 1

    restored = DSARRecord.from_dict(dsar.to_dict())
    assert restored.status == dsar.status
    assert restored.total_chunks_deleted == 1

    store_a = next(r for r in restored.stores if r.store_id == "store-a")
    assert store_a.execution is not None and store_a.execution.ok
    assert store_a.execution.verification is not None
    assert store_a.execution.verification.ok
    assert restored.evidence_bundle()["summary"]["total_chunks_deleted"] == 1


def test_api_dsar_execute_and_evidence_preserve_counts(tmp_path):
    """End-to-end: POST /execute then GET /evidence must agree after rehydration."""
    pytest.importorskip("fastapi")
    import chromadb
    from fastapi.testclient import TestClient

    from vecshield_platform.api import create_app
    from vecshield_platform.api.config_store import ConfigStore
    from vecshield_platform.history import ScanHistory

    path_a = str(tmp_path / "store_a")
    client_a = chromadb.PersistentClient(path=path_a)
    col = client_a.create_collection("tickets")
    col.add(ids=["a1"], documents=["Email from dsar@test.com about a refund."],
            embeddings=[[0.1, 0.2]], metadatas=[{"from": "dsar@test.com"}])

    cfg = ConfigStore(path=str(tmp_path / "config.json"))
    app = create_app(config_store=cfg, scan_history=ScanHistory(), serve_ui=False)
    c = TestClient(app)
    c.post("/admin/stores", json={"store_id": "store-a", "kind": "chroma",
                                  "conn": {"path": path_a}})

    created = c.post("/admin/dsar", json={"subject": "dsar@test.com"}).json()
    did = created["id"]
    ex = c.post(f"/admin/dsar/{did}/execute", json={"verify": True}).json()
    assert ex["summary"]["total_chunks_deleted"] == 1

    # GET /evidence rehydrates from persisted JSON — must still show the deletion.
    ev = c.get(f"/admin/dsar/{did}/evidence").json()
    assert ev["summary"]["total_chunks_deleted"] == 1
    assert ev["status"] == "executed"
