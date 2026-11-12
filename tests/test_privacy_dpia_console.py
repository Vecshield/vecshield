"""Regressions found by exercising the console's DPIA and privacy-request flows.

  * GET /admin/dsar/{id} returned the raw database row, with stores, matches
    and totals nested under `record`, so the console showed no stores and zero
    matches for a request that had found some.
  * Executing a request that was already erased raised inside the handler and
    surfaced as a bare 500.
  * Saving a request with INSERT OR REPLACE reset its created_at, so executing
    it moved it to the top of the list as if it were new.
  * The DPIA ignored the requested chunk cap and resolved its settings on its
    own, and named the store by its connector URI (a local path here) instead
    of its registry id.
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
    col = client.create_collection("tickets")
    col.add(ids=["a1", "a2", "a3"],
            documents=["Email from dsar@test.org about a refund.",
                       "benign note",
                       "another benign note"],
            embeddings=[[0.1, 0.2], [0.2, 0.1], [0.3, 0.3]],
            metadatas=[{"tenant_id": "t1"}, {"tenant_id": "t1"}, {"tenant_id": "t2"}])
    return str(tmp_path / "chroma")


@pytest.fixture
def history():
    return ScanHistory()


@pytest.fixture
def client(tmp_path, chroma_path, history):
    cfg = ConfigStore(path=str(tmp_path / "config.json"))
    app = create_app(config_store=cfg, scan_history=history, serve_ui=False)
    c = TestClient(app)
    c.post("/admin/stores", json={"store_id": "store-a", "kind": "chroma",
                                  "conn": {"path": chroma_path}})
    return c


def test_dsar_detail_carries_stores_matches_and_totals(client):
    created = client.post("/admin/dsar", json={"subject": "dsar@test.org",
                                               "notes": "ticket 42"}).json()
    detail = client.get(f"/admin/dsar/{created['id']}").json()

    assert detail["id"] == created["id"]
    assert detail["subject"] == "dsar@test.org"
    assert detail["status"] == "scanned"
    assert detail["notes"] == "ticket 42"
    assert detail["total_chunks_found"] == 1
    assert detail["coverage_complete"] is True
    assert detail["created_at"]
    [store] = detail["stores"]
    assert store["store_id"] == "store-a"
    assert store["chunks_found"] == 1
    assert [m["chunk_id"] for m in store["impact"]["matches"]] == ["a1"]
    # The raw row is not echoed back as a second, stringified copy.
    assert "record_json" not in detail
    assert "record" not in detail


def test_executing_an_erased_request_is_a_conflict_not_a_server_error(client, monkeypatch):
    monkeypatch.setenv("VECSHIELD_SAFE_MODE", "0")  # execution obeys safe mode
    did = client.post("/admin/dsar", json={"subject": "dsar@test.org"}).json()["id"]
    first = client.post(f"/admin/dsar/{did}/execute", json={"verify": True})
    assert first.status_code == 200
    assert first.json()["status"] == "executed"

    again = client.post(f"/admin/dsar/{did}/execute", json={"verify": True})
    assert again.status_code == 409
    assert "executed" in again.json()["detail"]
    queued = client.post(f"/admin/dsar/{did}/execute?background=true", json={"verify": True})
    assert queued.status_code == 409, "refused before it is queued, too"


def test_executing_a_request_keeps_its_place_in_the_list(client, history, monkeypatch):
    monkeypatch.setenv("VECSHIELD_SAFE_MODE", "0")  # execution obeys safe mode
    first = client.post("/admin/dsar", json={"subject": "dsar@test.org"}).json()["id"]
    second = client.post("/admin/dsar", json={"subject": "nobody@test.org"}).json()["id"]
    # Opened at distinct, earlier times, so a reset created_at cannot pass
    # unnoticed within the same second.
    with history._conn:
        history._conn.execute("UPDATE dsars SET created_at = ? WHERE id = ?",
                              ("2026-01-01T00:00:00Z", first))
        history._conn.execute("UPDATE dsars SET created_at = ? WHERE id = ?",
                              ("2026-01-02T00:00:00Z", second))
    before = {r["id"]: r["created_at"] for r in client.get("/admin/dsar").json()["dsars"]}

    client.post(f"/admin/dsar/{first}/execute", json={"verify": True})
    after = {r["id"]: r for r in client.get("/admin/dsar").json()["dsars"]}

    assert after[first]["status"] == "executed"
    assert after[first]["created_at"] == before[first] == "2026-01-01T00:00:00Z"
    assert after[second]["created_at"] == before[second]
    assert [r["id"] for r in client.get("/admin/dsar").json()["dsars"]] == [second, first]


def test_dpia_honours_the_chunk_cap_and_names_the_registered_store(client):
    report = client.post("/stores/store-a/pia",
                         json={"max_chunks_per_collection": 1}).json()

    assert report["store"] == "store-a"
    assert "store-a" in report["processing_description"]
    assert "chroma" not in report["processing_description"], "no local path or URI"
    # One chunk of three was inspected, so classification did not cover the
    # scope and the DPIA must not call itself complete.
    assert report["assessment_complete"] is False
    assert report["coverage"].get("complete") is not True


def test_dpia_for_an_unknown_store_is_not_found(client):
    assert client.post("/stores/nope/pia").status_code == 404
    assert client.get("/stores/nope/pia/html").status_code == 404


def test_a_finished_dpia_run_prints_as_the_draft_that_was_read(client):
    import time

    queued = client.post("/stores/store-a/pia?background=true",
                         json={"max_chunks_per_collection": 1})
    assert queued.status_code == 202
    job_id = queued.json()["job_id"]
    for _ in range(200):
        job = client.get(f"/admin/jobs/{job_id}").json()
        if job["status"] in ("succeeded", "failed", "interrupted"):
            break
        time.sleep(0.05)
    assert job["status"] == "succeeded"

    page = client.get(f"/stores/store-a/pia/html?job_id={job_id}")
    assert page.status_code == 200
    assert "Data Protection Impact Assessment" in page.text
    assert "store-a" in page.text
    # The run inspected one chunk of three; the document says it is incomplete.
    assert "Incomplete assessment" in page.text
    assert job["finished_at"] in page.text

    # Only a finished DPIA of this store renders; other ids are not found.
    assert client.get("/stores/store-a/pia/html?job_id=nope").status_code == 404
    audit = client.post("/stores/store-a/audit?background=true", json={}).json()["job_id"]
    assert client.get(f"/stores/store-a/pia/html?job_id={audit}").status_code == 404
