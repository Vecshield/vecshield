"""A persisted "running" row is not evidence that work is still running."""

from __future__ import annotations

import threading

from vecshield_platform.api.jobs import JobQueue, _now
from vecshield_platform.history import ScanHistory


def queue(history, **kwargs):
    return JobQueue(history=history, heartbeat_s=0, **kwargs)


def test_restart_marks_abandoned_jobs_interrupted_with_a_reason(tmp_path):
    db = tmp_path / "history.db"
    with ScanHistory(db) as history:
        dead = queue(history)
        history.save_async_job({"id": "abandoned", "kind": "audit", "status": "running",
                                "created_at": _now(), "started_at": _now(),
                                "runner_id": dead.runner_id, "heartbeat_at": _now(-3600)})
        history.save_async_job({"id": "finished", "kind": "audit", "status": "succeeded",
                                "created_at": _now(), "finished_at": _now(),
                                "runner_id": dead.runner_id})
        dead.shutdown()

    with ScanHistory(db) as history:
        restarted = queue(history)
        try:
            job = restarted.get("abandoned")
            assert job["status"] == "interrupted"
            assert "not resumed" in job["error"]
            assert job["finished_at"]
            # A terminal record from the previous process is left untouched.
            assert restarted.get("finished")["status"] == "succeeded"
        finally:
            restarted.shutdown()


def test_live_sibling_runner_jobs_are_not_interrupted(tmp_path):
    with ScanHistory(tmp_path / "history.db") as history:
        sibling = queue(history)
        history.save_async_job({"id": "live", "kind": "scan", "status": "running",
                                "created_at": _now(), "started_at": _now(),
                                "runner_id": sibling.runner_id, "heartbeat_at": _now()})
        other = queue(history)
        try:
            assert other.get("live")["status"] == "running"
        finally:
            sibling.shutdown()
            other.shutdown()


def test_heartbeat_keeps_a_long_job_owned_while_it_runs(tmp_path):
    with ScanHistory(tmp_path / "history.db") as history:
        running = JobQueue(history=history, heartbeat_s=0.01)
        release = threading.Event()
        try:
            job_id = running.submit("scan", lambda: release.wait(5) and {"ok": True})
            assert release.wait(0) is False
            for _ in range(200):
                if history.get_async_job(job_id)["status"] == "running":
                    break
            running._beat()
            beat = history.get_async_job(job_id)
            assert beat["runner_id"] == running.runner_id
            assert beat["heartbeat_at"] >= beat["created_at"]

            # A restart now must not steal a job whose owner is still beating.
            observer = queue(history)
            try:
                assert observer.get(job_id)["status"] == "running"
            finally:
                observer.shutdown()
        finally:
            release.set()
            running.shutdown(wait=True)


def test_reconciliation_survives_a_broken_history(tmp_path):
    class Broken:
        def interrupt_abandoned_async_jobs(self, **kwargs):
            raise RuntimeError("history unavailable")

        def save_async_job(self, record):
            raise RuntimeError("history unavailable")

    started = JobQueue(history=Broken(), heartbeat_s=0)
    try:
        assert started.reconcile() == []
        assert started.get(started.submit("scan", lambda: {"ok": True})) is not None
    finally:
        started.shutdown(wait=True)


def test_job_orphaned_by_a_fast_restart_is_interrupted_by_the_running_queue(
        tmp_path, monkeypatch):
    """Crash + restart inside the staleness window: startup reconcile must leave
    the (still fresh-looking) row alone, and the live queue's periodic sweep
    must interrupt it once its heartbeat goes stale — not leave it "running"
    until the next restart."""
    monkeypatch.setattr(JobQueue, "MIN_STALE_S", 0.3)
    db = tmp_path / "history.db"
    release = threading.Event()
    with ScanHistory(db) as history:
        crashed = JobQueue(history=history, heartbeat_s=0.05)
        job_id = crashed.submit("scan", lambda: release.wait(10))
        for _ in range(200):
            if (history.get_async_job(job_id) or {}).get("status") == "running":
                break
            threading.Event().wait(0.01)
        crashed._beat()
        # The process dies: its heartbeat stops and nothing more reaches history.
        crashed._stop.set()
        crashed._history = None

        restarted = JobQueue(history=history, heartbeat_s=0.05)
        try:
            # Startup cannot tell a crashed owner from a live sibling yet.
            assert restarted.get(job_id)["status"] == "running"
            for _ in range(300):
                if history.get_async_job(job_id)["status"] == "interrupted":
                    break
                threading.Event().wait(0.01)
            job = history.get_async_job(job_id)
            assert job["status"] == "interrupted"
            assert "not resumed" in job["error"]
        finally:
            restarted.shutdown()
            release.set()
            crashed.shutdown(wait=True)
