"""Live assessment progress: reporter, persistence, and job-queue wiring."""

from __future__ import annotations

import copy
import sqlite3
import threading
import time

from vecshield.classify import RegexClassifier
from vecshield.models import Chunk, Collection, VectorStore
from vecshield_platform.api.jobs import JobQueue
from vecshield_platform.connectors.base import Connector
from vecshield_platform.history import ScanHistory
from vecshield_platform.progress import (
    CLASSIFYING,
    CONFIGURATION,
    INTEGRITY,
    ProgressReporter,
    audit_phases,
    bind,
    chunks_bound_for,
    finish_phase,
    publish_plan,
    reset,
    start_phase,
    tick,
)
from vecshield_platform.scan import scan_store


def test_progress_helpers_are_noop_without_a_reporter():
    publish_plan(audit_phases())
    start_phase(CLASSIFYING)
    tick(chunks_read=12)
    finish_phase(CLASSIFYING)


def test_phase_change_persists_immediately():
    persisted = []

    def apply(progress, persist):
        if persist:
            persisted.append(copy.deepcopy(progress))

    reporter = ProgressReporter(apply, coalesce_s=10)
    previous = bind(reporter)
    try:
        publish_plan(audit_phases(include_integrity=False, include_posture=False))
        start_phase(CLASSIFYING)
    finally:
        reset(previous)
    assert len(persisted) >= 2
    assert persisted[0]["phases"][0]["state"] == "pending"
    current = [p for p in persisted[-1]["phases"] if p["id"] == CLASSIFYING]
    assert current and current[0]["state"] == "current"


def test_chunk_ticks_coalesce_sqlite_writes():
    clock = [0.0]
    persisted = []
    memory = []

    def apply(progress, persist):
        read = progress["phases"][0].get("chunks_read")
        memory.append(read)
        if persist:
            persisted.append(read)

    reporter = ProgressReporter(apply, clock=lambda: clock[0], coalesce_s=1.0)
    previous = bind(reporter)
    try:
        reporter.publish_plan([{"id": CLASSIFYING, "label": "Classifying stored text"}])
        reporter.start_phase(CLASSIFYING)
        persisted.clear()
        reporter.tick(chunks_read=1)
        reporter.tick(chunks_read=2)
        clock[0] = 1.0
        reporter.tick(chunks_read=3)
    finally:
        reset(previous)
    assert 1 in memory and 2 in memory and 3 in memory
    assert persisted == [3]


def test_async_jobs_gain_a_progress_column(tmp_path):
    db = str(tmp_path / "legacy.db")
    conn = sqlite3.connect(db)
    conn.execute(
        """CREATE TABLE async_jobs (
            id TEXT PRIMARY KEY, kind TEXT, status TEXT NOT NULL,
            actor TEXT, resource TEXT, created_at TEXT NOT NULL,
            started_at TEXT, finished_at TEXT, result TEXT, error TEXT
        )"""
    )
    conn.execute(
        """INSERT INTO async_jobs (id, kind, status, created_at)
           VALUES ('old-1', 'audit', 'queued', '2026-01-01T00:00:00+00:00')"""
    )
    conn.commit()
    conn.close()

    hist = ScanHistory(db)
    cols = {row["name"] for row in hist._conn.execute("PRAGMA table_info(async_jobs)")}
    assert "progress" in cols
    row = hist.get_async_job("old-1")
    assert row is not None
    assert row.get("progress") is None
    hist.close()


def test_saved_job_round_trips_progress_json():
    hist = ScanHistory()
    progress = {"phases": [{"id": CONFIGURATION, "label": "Checking configuration",
                            "state": "current"}]}
    hist.save_async_job({
        "id": "job-1", "kind": "posture", "status": "running",
        "created_at": "2026-01-01T00:00:00+00:00", "progress": progress,
    })
    row = hist.get_async_job("job-1")
    assert row["progress"] == progress
    hist.close()


def test_job_queue_records_progress_on_the_running_job():
    hist = ScanHistory()
    queue = JobQueue(history=hist, heartbeat_s=0)
    started = threading.Event()
    release = threading.Event()
    try:
        def work():
            publish_plan([{"id": CONFIGURATION, "label": "Checking configuration"}])
            start_phase(CONFIGURATION)
            started.set()
            release.wait(2.0)
            finish_phase(CONFIGURATION)
            return {"ok": True}

        job_id = queue.submit("posture", work)
        assert started.wait(2.0)
        rec = queue.get(job_id)
        assert rec["progress"]["phases"][0]["state"] == "current"
        assert rec["progress"]["phases"][0]["label"] == "Checking configuration"
        release.set()
        deadline = time.time() + 2
        while time.time() < deadline:
            rec = queue.get(job_id)
            if rec and rec["status"] == "succeeded":
                break
            time.sleep(0.01)
        assert rec["status"] == "succeeded"
        stored = hist.get_async_job(job_id)
        assert stored["progress"]["phases"][0]["state"] == "done"
    finally:
        release.set()
        queue.shutdown(wait=True)
        hist.close()


def test_audit_phases_omit_isolation_and_retrieval_when_unconfigured():
    ids = [p["id"] for p in audit_phases(closing="saving_audit")]
    assert ids == ["reading_store", "classifying", INTEGRITY, CONFIGURATION, "saving_audit"]
    with_tenant = [p["id"] for p in audit_phases(tenant_field="tenant_id",
                                                 retrieval_probe=True, closing="dpia")]
    assert "isolation" in with_tenant
    assert "retrieval" in with_tenant
    assert with_tenant[-2:] == ["finishing_pass", "writing_dpia"]
    assert "saving_audit" not in with_tenant


def test_chunks_bound_omits_denominator_when_any_count_is_unknown():
    known = Collection(name="orders", count=10)
    unknown = Collection(name="events", count=0, metadata={"count_known": False})
    assert chunks_bound_for([known, unknown], cap=100) is None
    assert chunks_bound_for([known], cap=4) == 4
    assert chunks_bound_for([known]) == 10


class _TwoCollectionStore(Connector):
    """Two collections with known counts, used only to assert progress ticks."""

    kind = "fake"

    def describe(self) -> VectorStore:
        return VectorStore(
            kind=self.kind, name="fake://progress", endpoint="fake://progress",
            collections=self.list_collections())

    def list_collections(self) -> list[Collection]:
        return [Collection(name="a", count=2), Collection(name="b", count=3)]

    def iter_chunks(self, collection: str, batch_size: int = 256):
        n = 2 if collection == "a" else 3
        for i in range(n):
            yield Chunk(id=f"{collection}-{i}", collection=collection, text="ok")


def test_classification_chunk_ticks_do_not_double_count():
    """Each classified chunk is counted once across collections."""
    snapshots = []

    def apply(progress, persist):
        snapshots.append(copy.deepcopy(progress))

    reporter = ProgressReporter(apply, coalesce_s=0)
    previous = bind(reporter)
    try:
        reporter.publish_plan([{"id": CLASSIFYING, "label": "Classifying stored text"}])
        reporter.start_phase(CLASSIFYING)
        scan_store(_TwoCollectionStore(), classifier=RegexClassifier())
    finally:
        reset(previous)

    reads = [
        phase.get("chunks_read")
        for snap in snapshots
        for phase in snap.get("phases") or []
        if phase.get("id") == CLASSIFYING
    ]
    assert max(r for r in reads if r is not None) == 5
    finished = reporter.snapshot()["phases"][0]
    assert finished["chunks_read"] == 5
    assert finished["chunks_bound"] == 5
    assert finished["collection"] == "b"
