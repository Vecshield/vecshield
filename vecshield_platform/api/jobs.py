"""In-process async job runner for long-running API operations.

Scans, audits, DSAR sweeps, and datasource scans can take a long time and hold
the HTTP connection open for the whole request. This module provides a small
thread-pool-backed job queue so those endpoints can accept the work, return a
``job_id`` immediately (HTTP 202), and let the client poll ``/admin/jobs/{id}``
for status and result.

Design notes:
  * The queue keeps an authoritative in-memory record per live job (fast, holds
    the native result object) and best-effort-persists each state change to
    ``ScanHistory`` so status/result survive across requests and restarts.
  * A finished job leaves memory once its final state is safely in history,
    and reads fall through to history from then on. A result can be a whole
    audit, so keeping every finished job in memory grew the process for as long
    as it ran. Without history (or when the final save fails) finished jobs
    stay in memory, capped at ``MAX_FINISHED_IN_MEMORY``, oldest out first.
  * Work is a callable held in this process, so a restart cannot resume it. Each
    queue stamps its jobs with a runner id and heartbeats the unfinished ones;
    on startup, and again on every heartbeat, it reconciles rows that no live
    runner claims into ``interrupted``. The periodic sweep matters after a fast
    restart: the dead runner's last heartbeat is still inside the staleness
    window at startup, so only a later sweep can tell it has stopped. An old
    ``running`` row is never read as work in progress.
  * Worker functions ("thunks") must be fully self-contained: they open their
    own connections, do the work, persist findings, and return a JSON-safe
    dict. They run on a worker thread, so they must not touch request state.
  * Failures are captured on the job record (``status="failed"``, ``error``),
    never propagated to a thread that would crash the pool.
"""

from __future__ import annotations

import logging
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

from vecshield_platform.history import summarize_job_result
from vecshield_platform.progress import ProgressReporter, bind, reset

logger = logging.getLogger(__name__)


def _now(offset_s: float = 0.0) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=offset_s)).isoformat()


_LIVE_STATES = ("queued", "running")


class JobQueue:
    """Thread-pool-backed async job runner with optional history persistence."""

    #: A job whose heartbeat is older than this many seconds has no live owner.
    STALE_AFTER_FACTOR = 4
    #: Floor for that window, so a short (or disabled) heartbeat interval can
    #: never make a job another process is running look abandoned.
    MIN_STALE_S = 60.0
    #: Finished jobs kept in memory when they cannot be handed to history.
    MAX_FINISHED_IN_MEMORY = 200

    def __init__(self, *, history: Any = None, max_workers: int = 2,
                 heartbeat_s: float = 15.0, reconcile: bool = True):
        self._history = history
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="vs-job"
        )
        self._lock = threading.Lock()
        self._jobs: dict[str, dict[str, Any]] = {}
        self._runner_id = uuid.uuid4().hex
        self._heartbeat_s = heartbeat_s
        self._stop = threading.Event()
        self._heartbeat: Optional[threading.Thread] = None
        self._reconcile_on_beat = reconcile
        if reconcile:
            self.reconcile()
        if history is not None and heartbeat_s > 0:
            self._heartbeat = threading.Thread(
                target=self._heartbeat_loop, name="vs-job-heartbeat", daemon=True)
            self._heartbeat.start()

    @property
    def runner_id(self) -> str:
        return self._runner_id

    # ------------------------------------------------------------------ #
    # Restart reconciliation                                              #
    # ------------------------------------------------------------------ #

    def reconcile(self) -> list[dict[str, Any]]:
        """Close out persisted jobs that no running worker owns.

        Returns the records that were moved to ``interrupted`` so callers can
        log or surface them. Best-effort: a history failure never blocks start.
        """
        if self._history is None:
            return []
        stale_before = _now(-max(self._heartbeat_s * self.STALE_AFTER_FACTOR,
                                 self.MIN_STALE_S))
        try:
            interrupted = self._history.interrupt_abandoned_async_jobs(
                runner_id=self._runner_id, stale_before=stale_before, at=_now(),
                reason=("worker restarted before this job finished; the work was "
                        "not resumed and must be run again"))
        except Exception:  # noqa: BLE001 - reconciliation is best-effort
            logger.warning("failed to reconcile abandoned async jobs", exc_info=True)
            return []
        for record in interrupted:
            logger.warning("async job %s (%s) was interrupted by a restart",
                           record.get("id"), record.get("kind"))
        return interrupted

    def _heartbeat_loop(self) -> None:
        while not self._stop.wait(self._heartbeat_s):
            self._beat()
            if self._reconcile_on_beat and not self._stop.is_set():
                # A runner that died shortly before this process started was
                # still "fresh" at startup; sweep again once it has gone stale.
                self.reconcile()

    def _beat(self) -> None:
        with self._lock:
            active = [job_id for job_id, rec in self._jobs.items()
                      if rec["status"] in ("queued", "running")]
        if not active or self._history is None:
            return
        try:
            self._history.touch_async_jobs(active, runner_id=self._runner_id, at=_now())
        except Exception:  # noqa: BLE001 - liveness reporting is best-effort
            logger.warning("failed to record async job heartbeat", exc_info=True)

    # ------------------------------------------------------------------ #
    # Submit / run                                                         #
    # ------------------------------------------------------------------ #

    def submit(
        self,
        kind: str,
        fn: Callable[[], Any],
        *,
        actor: Optional[str] = None,
        resource: Optional[str] = None,
    ) -> str:
        """Enqueue ``fn`` for background execution and return its job id."""
        job_id = uuid.uuid4().hex
        record = {
            "id": job_id,
            "kind": kind,
            "status": "queued",
            "actor": actor,
            "resource": resource,
            "created_at": _now(),
            "started_at": None,
            "finished_at": None,
            "result": None,
            "error": None,
            "progress": None,
            "runner_id": self._runner_id,
            "heartbeat_at": _now(),
        }
        with self._lock:
            self._jobs[job_id] = record
        self._persist(record)
        self._executor.submit(self._run, job_id, fn)
        return job_id

    def _run(self, job_id: str, fn: Callable[[], Any]) -> None:
        self._update(job_id, status="running", started_at=_now())
        reporter = ProgressReporter(
            lambda progress, persist: self._set_progress(job_id, progress, persist=persist)
        )
        previous = bind(reporter)
        try:
            result = fn()
        except Exception as exc:  # noqa: BLE001 - report, never crash the worker
            logger.exception("async job %s (%s) failed", job_id, self._kind(job_id))
            saved = self._update(job_id, status="failed", finished_at=_now(), error=str(exc))
            self._retire(job_id, saved=saved)
            return
        finally:
            reporter.flush()
            reset(previous)
        saved = self._update(job_id, status="succeeded", finished_at=_now(), result=result)
        self._retire(job_id, saved=saved)

    def _retire(self, job_id: str, *, saved: bool) -> None:
        """Release a finished job's memory.

        A job whose final state reached history is dropped; ``get`` reads it
        from there. One that did not stays readable here, but only the newest
        ``MAX_FINISHED_IN_MEMORY`` finished jobs are kept. Live jobs are never
        evicted: the heartbeat claims them by reading this map.
        """
        with self._lock:
            if saved:
                self._jobs.pop(job_id, None)
                return
            finished = [rec for rec in self._jobs.values()
                        if rec["status"] not in _LIVE_STATES]
            excess = len(finished) - self.MAX_FINISHED_IN_MEMORY
            if excess <= 0:
                return
            finished.sort(key=lambda rec: rec.get("finished_at") or rec["created_at"])
            for rec in finished[:excess]:
                self._jobs.pop(rec["id"], None)

    # ------------------------------------------------------------------ #
    # State updates + persistence                                          #
    # ------------------------------------------------------------------ #

    def _kind(self, job_id: str) -> Optional[str]:
        with self._lock:
            rec = self._jobs.get(job_id)
            return rec.get("kind") if rec else None

    def _update(self, job_id: str, **changes: Any) -> bool:
        """Apply ``changes`` to a job; True when the new state reached history."""
        with self._lock:
            rec = self._jobs.get(job_id)
            if rec is None:
                return False
            rec.update(changes)
            rec["heartbeat_at"] = _now()
            snapshot = dict(rec)
        return self._persist(snapshot)

    def _set_progress(self, job_id: str, progress: dict[str, Any], *, persist: bool) -> None:
        """Write live progress onto the job. Chunk ticks may skip SQLite."""
        with self._lock:
            rec = self._jobs.get(job_id)
            if rec is None:
                return
            rec["progress"] = progress
            rec["heartbeat_at"] = _now()
            snapshot = dict(rec)
        if persist:
            self._persist(snapshot)

    def _persist(self, record: dict[str, Any]) -> bool:
        """Save ``record`` to history; True only when it was written."""
        if self._history is None:
            return False
        try:
            self._history.save_async_job(record)
        except Exception:  # noqa: BLE001 - persistence is best-effort
            logger.warning(
                "failed to persist async job %s", record.get("id"), exc_info=True
            )
            return False
        return True

    # ------------------------------------------------------------------ #
    # Read                                                                 #
    # ------------------------------------------------------------------ #

    def get(self, job_id: str) -> Optional[dict[str, Any]]:
        """Return a job record, preferring the fresh in-memory copy and falling
        back to history (e.g. for a job submitted before a restart)."""
        with self._lock:
            rec = self._jobs.get(job_id)
            if rec is not None:
                return dict(rec)
        if self._history is not None:
            return self._history.get_async_job(job_id)
        return None

    def list(
        self,
        *,
        kind: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
        summary: bool = False,
    ) -> list[dict[str, Any]]:
        """Jobs, newest first. ``summary`` cuts each result to its record id."""
        if self._history is not None:
            return self._history.list_async_jobs(
                kind=kind, status=status, limit=limit, offset=offset, summary=summary
            )
        with self._lock:
            jobs = sorted(
                self._jobs.values(), key=lambda r: r["created_at"], reverse=True
            )
        if kind:
            jobs = [j for j in jobs if j["kind"] == kind]
        if status:
            jobs = [j for j in jobs if j["status"] == status]
        page = [dict(j) for j in jobs[offset : offset + limit]]
        if summary:
            for job in page:
                job["result"] = summarize_job_result(job.get("result"))
        return page

    def shutdown(self, *, wait: bool = False) -> None:
        self._stop.set()
        self._executor.shutdown(wait=wait)
