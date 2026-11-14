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


# ------------------------- finished-job memory --------------------------- #

def test_finished_jobs_leave_memory_once_saved_and_stay_readable():
    """A result can be a whole audit; memory must not keep every one ever run."""
    hist = ScanHistory()
    q = JobQueue(history=hist)
    try:
        ok = q.submit("test", lambda: {"id": "a1", "big": list(range(100))})
        bad = q.submit("test", lambda: 1 / 0)
        q.shutdown(wait=True)  # both workers, including their cleanup, are done

        assert q._jobs == {}
        rec = q.get(ok)
        assert rec["status"] == "succeeded"
        assert rec["result"] == {"id": "a1", "big": list(range(100))}
        failed = q.get(bad)
        assert failed["status"] == "failed"
        assert "division by zero" in failed["error"]
    finally:
        q.shutdown(wait=True)
        hist.close()


def test_without_history_only_the_newest_finished_jobs_are_kept():
    q = JobQueue(max_workers=1)
    q.MAX_FINISHED_IN_MEMORY = 3
    try:
        ids = [q.submit("test", lambda i=i: {"id": i}) for i in range(5)]
        q.shutdown(wait=True)

        assert set(q._jobs) == set(ids[-3:])
        assert q.get(ids[0]) is None
        assert q.get(ids[-1])["result"] == {"id": 4}
    finally:
        q.shutdown(wait=True)


class _UnwritableHistory:
    """History whose writes always fail, as a full or locked disk would."""

    def save_async_job(self, record):
        raise OSError("disk full")

    def get_async_job(self, job_id):
        return None

    def touch_async_jobs(self, *args, **kwargs):
        pass


def test_a_job_whose_final_state_was_not_saved_stays_in_memory():
    q = JobQueue(history=_UnwritableHistory(), reconcile=False, heartbeat_s=0)
    try:
        job_id = q.submit("test", lambda: {"id": "kept"})
        q.shutdown(wait=True)

        assert job_id in q._jobs
        assert q.get(job_id)["result"] == {"id": "kept"}
    finally:
        q.shutdown(wait=True)


def test_a_running_job_is_never_evicted():
    q = JobQueue(max_workers=2)
    q.MAX_FINISHED_IN_MEMORY = 0
    gate = threading.Event()
    started = threading.Event()

    def blocker():
        started.set()
        gate.wait(5.0)
        return {"id": "slow"}

    try:
        slow = q.submit("test", blocker)
        assert started.wait(2.0), "worker never started"
        # With a cap of zero the fast job is evicted the moment it finishes.
        fast = q.submit("test", lambda: {"id": "fast"})
        deadline = time.time() + 5.0
        while fast in q._jobs and time.time() < deadline:
            time.sleep(0.01)
        assert fast not in q._jobs
        assert q.get(slow)["status"] == "running"
    finally:
        gate.set()
        q.shutdown(wait=True)


def test_list_summary_cuts_each_result_to_its_record_id():
    hist = ScanHistory()
    q = JobQueue(history=hist)
    try:
        with_id = q.submit("test", lambda: {"id": "audit-1", "findings": [1, 2, 3]})
        without_id = q.submit("test", lambda: {"findings": []})
        q.shutdown(wait=True)

        full = {j["id"]: j["result"] for j in q.list()}
        assert full[with_id] == {"id": "audit-1", "findings": [1, 2, 3]}

        summary = {j["id"]: j["result"] for j in q.list(summary=True)}
        assert summary == {with_id: {"id": "audit-1"}, without_id: None}
    finally:
        q.shutdown(wait=True)
        hist.close()


def test_list_summary_without_history():
    q = JobQueue()
    try:
        job_id = q.submit("test", lambda: {"id": "scan-9", "rows": [0] * 50})
        _wait_for(q, job_id, "succeeded")
        assert q.list(summary=True)[0]["result"] == {"id": "scan-9"}
        assert q.list()[0]["result"]["rows"] == [0] * 50
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


def test_admin_jobs_list_carries_only_the_saved_record_id(client):
    """The Runs list links each run to its record; the audit itself stays put."""
    r = client.post("/stores/prod/audit?background=true", json={})
    job_id = r.json()["job_id"]
    full = _poll_job(client, job_id)
    assert "summary" in full["result"] and full["result"]["id"]

    listed = {j["id"]: j for j in client.get("/admin/jobs").json()["jobs"]}
    assert listed[job_id]["result"] == {"id": full["result"]["id"]}
    # The full result is still one request away.
    assert client.get(f"/admin/jobs/{job_id}").json()["result"] == full["result"]


@pytest.mark.parametrize("query", ["limit=-1", "limit=0", "limit=501", "offset=-1"])
def test_admin_jobs_rejects_an_unbounded_page(client, query):
    assert client.get(f"/admin/jobs?{query}").status_code == 422


@pytest.mark.parametrize("query", ["limit=-1", "limit=1001", "offset=-1"])
def test_runtime_alerts_rejects_an_unbounded_page(client, query):
    assert client.get(f"/runtime/alerts?{query}").status_code == 422


def test_runtime_alerts_accepts_the_console_page_size(client):
    assert client.get("/runtime/alerts?limit=200").status_code == 200


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
