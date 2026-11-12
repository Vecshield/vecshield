"""The async job queue.

Unit tests for the JobQueue primitive (run/fail/persist/state) plus API tests
for the opt-in ``?background=true`` mode and the /admin/jobs endpoints.
"""

from __future__ import annotations

import threading
import time

import pytest

from vecshield_platform.api.jobs import JobQueue
from vecshield_platform.history import ScanHistory


def _wait_for(queue: JobQueue, job_id: str, status: str, timeout: float = 5.0):
    deadline = time.time() + timeout
    rec = None
    while time.time() < deadline:
        rec = queue.get(job_id)
        if rec and rec["status"] == status:
            return rec
        time.sleep(0.01)
    raise AssertionError(f"job {job_id} never reached {status!r}; last={rec}")


# ----------------------------- JobQueue unit ----------------------------- #

def test_job_runs_and_returns_result():
    q = JobQueue()
    try:
        job_id = q.submit("test", lambda: {"answer": 42})
        rec = _wait_for(q, job_id, "succeeded")
        assert rec["result"] == {"answer": 42}
        assert rec["error"] is None
        assert rec["started_at"] and rec["finished_at"]
    finally:
        q.shutdown(wait=True)


def test_job_failure_is_captured():
    q = JobQueue()

    def boom():
        raise RuntimeError("kaboom")

    try:
        job_id = q.submit("test", boom)
        rec = _wait_for(q, job_id, "failed")
        assert rec["result"] is None
        assert "kaboom" in rec["error"]
    finally:
        q.shutdown(wait=True)


def test_job_state_transitions_queued_running_succeeded():
    q = JobQueue(max_workers=1)
    gate = threading.Event()
    started = threading.Event()

    def blocker():
        started.set()
        gate.wait(2.0)
        return {"ok": True}

    try:
        job_id = q.submit("test", blocker)
        assert started.wait(2.0), "worker never started"
        assert q.get(job_id)["status"] == "running"
        gate.set()
        rec = _wait_for(q, job_id, "succeeded")
        assert rec["result"] == {"ok": True}
    finally:
        gate.set()
        q.shutdown(wait=True)


def test_job_persisted_to_history():
    hist = ScanHistory()
    q = JobQueue(history=hist)
    try:
        job_id = q.submit("test", lambda: {"v": 1}, actor="tester", resource="r1")
        _wait_for(q, job_id, "succeeded")
        row = hist.get_async_job(job_id)
        assert row is not None
        assert row["status"] == "succeeded"
        assert row["result"] == {"v": 1}
        assert row["actor"] == "tester"
        assert row["resource"] == "r1"
        assert any(r["id"] == job_id for r in hist.list_async_jobs(kind="test"))
    finally:
        q.shutdown(wait=True)
        hist.close()


def test_get_unknown_job_returns_none():
    q = JobQueue()
    try:
        assert q.get("does-not-exist") is None
    finally:
        q.shutdown(wait=True)


# ------------------------------- API wiring ------------------------------ #

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from vecshield_platform.api import create_app  # noqa: E402
from vecshield_platform.api.config_store import ConfigStore  # noqa: E402


@pytest.fixture
def chroma_path(tmp_path):
    chromadb = pytest.importorskip("chromadb")
    client = chromadb.PersistentClient(path=str(tmp_path / "chroma"))
    col = client.create_collection("prod-kb")
    col.add(ids=["a", "b"],
            documents=["contact jane@example.com about the invoice", "benign note"],
            embeddings=[[0.1, 0.2]] * 2,
            metadatas=[{"tenant_id": "t1"}, {"tenant_id": "t2"}])
    return str(tmp_path / "chroma")


@pytest.fixture
def client(tmp_path, chroma_path):
    cfg = ConfigStore(path=str(tmp_path / "config.json"))
    app = create_app(config_store=cfg, scan_history=ScanHistory(), serve_ui=False)
    c = TestClient(app)
    c.post("/admin/stores", json={"store_id": "prod", "kind": "chroma",
                                  "conn": {"path": chroma_path}})
    yield c
    app.state.jobs.shutdown(wait=False)


def _poll_job(client: TestClient, job_id: str, timeout: float = 8.0) -> dict:
    deadline = time.time() + timeout
    rec = None
    while time.time() < deadline:
        r = client.get(f"/admin/jobs/{job_id}")
        assert r.status_code == 200
        rec = r.json()
        if rec["status"] in ("succeeded", "failed"):
            return rec
        time.sleep(0.02)
    raise AssertionError(f"job {job_id} did not finish; last={rec}")


def test_audit_sync_default_is_unchanged(client):
    r = client.post("/stores/prod/audit", json={})
    assert r.status_code == 200
    assert "summary" in r.json()


def test_audit_background_returns_202_then_completes(client):
    r = client.post("/stores/prod/audit?background=true", json={})
    assert r.status_code == 202
    body = r.json()
    assert body["status"] == "queued"
    assert body["kind"] == "audit"
    rec = _poll_job(client, body["job_id"])
    assert rec["status"] == "succeeded"
    assert "summary" in rec["result"]


def test_background_unknown_store_404_immediately(client):
    r = client.post("/stores/does-not-exist/audit?background=true", json={})
    assert r.status_code == 404


def test_admin_jobs_list_includes_submitted_job(client):
    r = client.post("/stores/prod/audit?background=true", json={})
    job_id = r.json()["job_id"]
    _poll_job(client, job_id)
    listed = client.get("/admin/jobs").json()["jobs"]
    assert any(j["id"] == job_id for j in listed)


def test_get_unknown_job_returns_404(client):
    assert client.get("/admin/jobs/nope").status_code == 404


def test_datasource_scan_background(client, tmp_path):
    (tmp_path / "docs.jsonl").write_text(
        '{"text": "Deploy key AKIAIOSFODNN7EXAMPLE was committed by mistake"}\n')
    r = client.post("/datasources/scan?background=true",
                    json={"kind": "local", "path": str(tmp_path),
                          "text_field": "text", "no_nlp": True})
    assert r.status_code == 202
    rec = _poll_job(client, r.json()["job_id"])
    assert rec["status"] == "succeeded"
    assert "id" in rec["result"]


def test_integrity_scan_runs_in_the_background_like_every_other_long_action(client):
    """The console tracks long work as jobs; integrity must not be the exception."""
    r = client.post("/stores/prod/scan/integrity?collection=prod-kb&background=true")
    assert r.status_code == 202
    body = r.json()
    assert body["kind"] == "scan_integrity"
    rec = _poll_job(client, body["job_id"])
    assert rec["status"] == "succeeded"
    assert rec["resource"] == "prod/prod-kb"
    assert "findings" in rec["result"]


def test_integrity_scan_sync_default_is_unchanged(client):
    r = client.post("/stores/prod/scan/integrity?collection=prod-kb")
    assert r.status_code == 200
    assert "findings" in r.json()


def test_background_integrity_on_unknown_store_fails_before_queueing(client):
    r = client.post("/stores/nope/scan/integrity?collection=prod-kb&background=true")
    assert r.status_code == 404
