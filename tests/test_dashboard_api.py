"""Regression tests for the API surface the web dashboard depends on.

Covers the gaps found in the 2026-06 audit:
  * /admin/history/trend was shadowed by /admin/history/{job_id}
  * integrity scans were never persisted to history
  * /admin/dsar list rows lacked the found/deleted counters the UI renders
  * the DPIA HTML document had no route (JSON only)
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from vecshield_platform.api import create_app  # noqa: E402
from vecshield_platform.api.config_store import ConfigStore  # noqa: E402
from vecshield_platform.history import ScanHistory  # noqa: E402


@pytest.fixture
def chroma_path(tmp_path):
    import chromadb

    client = chromadb.PersistentClient(path=str(tmp_path / "chroma"))
    col = client.create_collection("prod-kb")
    col.add(ids=["a", "b"],
            documents=["contact jane@example.com about the invoice",
                       "benign note"],
            embeddings=[[0.1, 0.2]] * 2,
            metadatas=[{"tenant_id": "t1"}, {"tenant_id": "t2"}])
    return str(tmp_path / "chroma")


@pytest.fixture
def client(tmp_path, chroma_path):
    cfg = ConfigStore(path=str(tmp_path / "config.json"))
    app = create_app(config_store=cfg, scan_history=ScanHistory(),
                     serve_ui=False)
    c = TestClient(app)
    c.post("/admin/stores", json={"store_id": "prod", "kind": "chroma",
                                  "conn": {"path": chroma_path}})
    return c


def test_history_trend_route_not_shadowed(client):
    # Before the fix, FastAPI matched "trend" as a job_id -> 404 job not found.
    r = client.get("/admin/history/trend")
    assert r.status_code == 200
    assert "trend" in r.json()


def test_trend_reflects_scans(client):
    client.post("/stores/prod/scan")
    r = client.get("/admin/history/trend?days=7")
    assert r.status_code == 200
    trend = r.json()["trend"]
    assert trend and trend[0]["store"]


def test_integrity_scan_persisted_to_history(client):
    r = client.post("/stores/prod/scan/integrity?collection=prod-kb")
    assert r.status_code == 200
    job_id = r.json()["id"]
    jobs = client.get("/admin/history").json()["jobs"]
    assert any(j["id"] == job_id for j in jobs)


def test_dsar_list_rows_carry_counters(client):
    r = client.post("/admin/dsar", json={"subject": "jane@example.com"})
    assert r.status_code == 200
    assert r.json()["total_chunks_found"] == 1

    rows = client.get("/admin/dsar").json()["dsars"]
    assert rows, "list should contain the scanned DSAR"
    row = rows[0]
    # counters the dashboard renders (and gates Execute on)
    assert row["total_chunks_found"] == 1
    assert row["total_chunks_deleted"] == 0
    assert row["stores_scanned"] == 1
    # the raw record payload stays out of the list response
    assert "record_json" not in row


def test_pia_html_route(client):
    r = client.get("/stores/prod/pia/html")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "Data Protection Impact Assessment" in r.text


def test_schema_explorer_discovers_collections_and_metadata(client):
    r = client.get("/stores/prod/schema?sample_chunks=10")
    assert r.status_code == 200

    body = r.json()
    assert body["ok"] is True
    assert body["store_id"] == "prod"
    assert body["collection_count"] == 1
    assert body["total_vectors"] == 2
    assert [c["name"] for c in body["collections"]] == ["prod-kb"]

    collection = body["collections"][0]
    assert collection["count"] == 2
    assert collection["sample_size"] == 2
    assert collection["metadata_complete"] is True
    tenant = next(f for f in collection["metadata_fields"]
                  if f["path"] == "tenant_id")
    assert tenant["count"] == 2
    assert tenant["coverage"] == 1.0
    assert tenant["types"] == ["string"]
    assert {v["value"] for v in tenant["top_values"]} == {"t1", "t2"}

    admin_alias = client.get("/admin/stores/prod/schema?sample_chunks=0")
    assert admin_alias.status_code == 200
    assert admin_alias.json()["collections"][0]["metadata_fields"] == []
