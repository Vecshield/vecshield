"""Live assessment progress for background jobs.

Scanners call the module-level helpers. When no reporter is bound (CLI, sync
requests, and most unit tests), the helpers do nothing. A JobQueue worker binds
a reporter that writes the job's ``progress`` object for the console to poll.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable, Optional

from vecshield_platform.coverage import count_known

# Stable phase ids. Labels are what the console shows; ids are what tests assert.
READING_STORE = "reading_store"
CLASSIFYING = "classifying"
INTEGRITY = "integrity"
ISOLATION = "isolation"
CONFIGURATION = "configuration"
RETRIEVAL = "retrieval"
SAVING_AUDIT = "saving_audit"
FINISHING_PASS = "finishing_pass"
WRITING_DPIA = "writing_dpia"

LABELS = {
    READING_STORE: "Reading store configuration",
    CLASSIFYING: "Classifying stored text",
    INTEGRITY: "Checking integrity",
    ISOLATION: "Checking tenant isolation",
    CONFIGURATION: "Checking configuration",
    RETRIEVAL: "Probing retrieval exposure",
    SAVING_AUDIT: "Saving the audit",
    FINISHING_PASS: "Finishing the pass",
    WRITING_DPIA: "Writing the DPIA draft",
}

_UNSET = object()
_tls = threading.local()


def bind(reporter: Optional["ProgressReporter"]) -> Optional["ProgressReporter"]:
    """Install ``reporter`` on this thread. Returns the previous reporter."""
    previous = getattr(_tls, "reporter", None)
    _tls.reporter = reporter
    return previous


def reset(previous: Optional["ProgressReporter"]) -> None:
    """Restore the reporter returned by :func:`bind`."""
    _tls.reporter = previous


def current() -> Optional["ProgressReporter"]:
    """The reporter bound to this thread, if any."""
    return getattr(_tls, "reporter", None)


def _phase(phase_id: str, *, state: str = "pending") -> dict[str, Any]:
    return {"id": phase_id, "label": LABELS[phase_id], "state": state}


def audit_phases(
    *,
    include_integrity: bool = True,
    tenant_field: Optional[str] = None,
    include_posture: bool = True,
    retrieval_probe: bool = False,
    include_crypto: bool = True,
    closing: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Coarse phases this request will actually attempt.

    ``closing`` is ``saving_audit`` for a persisted full audit, ``dpia`` for a
    DPIA (finishing pass + draft), or omitted when the caller has no closing
    work of its own (CLI).
    """
    phases = [_phase(READING_STORE), _phase(CLASSIFYING)]
    if include_integrity:
        phases.append(_phase(INTEGRITY))
    if tenant_field:
        phases.append(_phase(ISOLATION))
    if include_posture:
        phases.append(_phase(CONFIGURATION))
    if retrieval_probe and include_crypto:
        phases.append(_phase(RETRIEVAL))
    if closing == "dpia":
        phases.append(_phase(FINISHING_PASS))
        phases.append(_phase(WRITING_DPIA))
    elif closing == SAVING_AUDIT:
        phases.append(_phase(SAVING_AUDIT))
    return phases


def posture_phases() -> list[dict[str, Any]]:
    """One-row plan for a posture-only run."""
    return [_phase(CONFIGURATION)]


def integrity_phases() -> list[dict[str, Any]]:
    """One-row plan for an integrity-only run."""
    return [_phase(INTEGRITY)]


def chunks_bound_for(collections, cap: Optional[int] = None) -> Optional[int]:
    """Upper bound for a chunk walk, or None when any collection size is unknown.

    A configured cap still cannot supply a denominator when inventory counts
    are missing: the plan omits ``of N`` rather than guessing.
    """
    if not collections:
        return 0
    if any(not count_known(col) for col in collections):
        return None
    total = 0
    for col in collections:
        n = int(getattr(col, "count", 0) or 0)
        if cap is not None:
            n = min(n, cap)
        total += n
    return total


class ProgressReporter:
    """In-thread progress state with coalesced persistence for chunk ticks.

    ``apply(progress, persist)`` receives a snapshot. Phase changes pass
    ``persist=True`` immediately. Chunk ticks pass ``persist=True`` at most
    once per ``coalesce_s`` seconds so SQLite is not rewritten per chunk.
    In-memory ``apply(..., persist=False)`` still runs on every tick so a
    poller sees the latest count.
    """

    def __init__(
        self,
        apply: Callable[[dict[str, Any], bool], None],
        *,
        clock: Callable[[], float] = time.monotonic,
        coalesce_s: float = 1.0,
    ):
        self._apply = apply
        self._clock = clock
        self._coalesce_s = coalesce_s
        self._lock = threading.Lock()
        self._phases: list[dict[str, Any]] = []
        self._last_persist = 0.0
        self._pending_persist = False

    def snapshot(self) -> dict[str, Any]:
        """A JSON-safe copy of the current progress object."""
        with self._lock:
            return self._snapshot_unlocked()

    def _snapshot_unlocked(self) -> dict[str, Any]:
        return {"phases": [dict(phase) for phase in self._phases]}

    def _emit(self, persist: bool) -> None:
        snapshot = self._snapshot_unlocked()
        if persist:
            self._last_persist = self._clock()
            self._pending_persist = False
        self._apply(snapshot, persist)

    def has_plan(self) -> bool:
        with self._lock:
            return bool(self._phases)

    def publish_plan(self, phases: list[dict[str, Any]]) -> None:
        """Replace the checklist. Every row starts ``pending`` unless given a state."""
        with self._lock:
            self._phases = []
            for item in phases:
                phase = {
                    "id": item["id"],
                    "label": item.get("label") or LABELS.get(item["id"], item["id"]),
                    "state": item.get("state") or "pending",
                }
                self._phases.append(phase)
            self._emit(True)

    def start_phase(self, phase_id: str) -> None:
        """Mark ``phase_id`` current. A previous current row becomes finished."""
        with self._lock:
            if not self._find(phase_id):
                return
            for phase in self._phases:
                if phase["state"] == "current" and phase["id"] != phase_id:
                    phase["state"] = "done"
                if phase["id"] == phase_id:
                    phase["state"] = "current"
                    phase.pop("detail", None)
                    phase.pop("chunks_read", None)
                    phase.pop("chunks_bound", None)
                    phase.pop("collection", None)
                    phase.pop("collection_index", None)
                    phase.pop("collection_count", None)
                    phase.pop("collections_in_flight", None)
            self._emit(True)

    def finish_phase(self, phase_id: str) -> None:
        """Mark a phase finished. Findings stay in the result, not on this row."""
        with self._lock:
            phase = self._find(phase_id)
            if phase is None:
                return
            phase["state"] = "done"
            self._emit(True)

    def skip_phase(self, phase_id: str, reason: str) -> None:
        """A planned phase that this run did not perform."""
        with self._lock:
            phase = self._find(phase_id)
            if phase is None:
                return
            phase["state"] = "skipped"
            phase["detail"] = reason
            phase.pop("chunks_read", None)
            phase.pop("chunks_bound", None)
            self._emit(True)

    def tick(
        self,
        *,
        collection: Any = _UNSET,
        collection_index: Any = _UNSET,
        collection_count: Any = _UNSET,
        collections_in_flight: Any = _UNSET,
        chunks_read: Any = _UNSET,
        chunks_bound: Any = _UNSET,
    ) -> None:
        """Update the current phase's collection and/or chunk counters."""
        with self._lock:
            phase = self._current()
            if phase is None:
                return
            if collection is not _UNSET:
                if collection is None:
                    phase.pop("collection", None)
                else:
                    phase["collection"] = collection
            if collection_index is not _UNSET:
                if collection_index is None:
                    phase.pop("collection_index", None)
                else:
                    phase["collection_index"] = collection_index
            if collection_count is not _UNSET:
                if collection_count is None:
                    phase.pop("collection_count", None)
                else:
                    phase["collection_count"] = collection_count
            if collections_in_flight is not _UNSET:
                if not collections_in_flight:
                    phase.pop("collections_in_flight", None)
                else:
                    phase["collections_in_flight"] = list(collections_in_flight)
                    phase.pop("collection_index", None)
            if chunks_read is not _UNSET:
                if chunks_read is None:
                    phase.pop("chunks_read", None)
                else:
                    phase["chunks_read"] = int(chunks_read)
            if chunks_bound is not _UNSET:
                if chunks_bound is None:
                    phase.pop("chunks_bound", None)
                else:
                    phase["chunks_bound"] = int(chunks_bound)
            self._refresh_detail(phase)
            now = self._clock()
            persist = (now - self._last_persist) >= self._coalesce_s
            if persist:
                self._emit(True)
            else:
                self._pending_persist = True
                self._emit(False)

    def flush(self) -> None:
        """Persist a coalesced tick that has not yet been written."""
        with self._lock:
            if self._pending_persist:
                self._emit(True)

    def _find(self, phase_id: str) -> Optional[dict[str, Any]]:
        for phase in self._phases:
            if phase["id"] == phase_id:
                return phase
        return None

    def _current(self) -> Optional[dict[str, Any]]:
        for phase in self._phases:
            if phase["state"] == "current":
                return phase
        return None

    def _refresh_detail(self, phase: dict[str, Any]) -> None:
        if phase["state"] == "skipped":
            return
        in_flight = phase.get("collections_in_flight") or []
        if in_flight:
            phase["detail"] = ", ".join(str(name) for name in in_flight)
            return
        name = phase.get("collection")
        index = phase.get("collection_index")
        total = phase.get("collection_count")
        if name and index is not None and total:
            phase["detail"] = f"{name}, {index} of {total}"
        elif name:
            phase["detail"] = str(name)
        else:
            phase.pop("detail", None)


def publish_plan(phases: list[dict[str, Any]]) -> None:
    reporter = current()
    if reporter is not None:
        reporter.publish_plan(phases)


def publish_plan_if_empty(phases: list[dict[str, Any]]) -> None:
    """Publish only when this thread has a reporter with no plan yet (CLI)."""
    reporter = current()
    if reporter is not None and not reporter.has_plan():
        reporter.publish_plan(phases)


def start_phase(phase_id: str) -> None:
    reporter = current()
    if reporter is not None:
        reporter.start_phase(phase_id)


def finish_phase(phase_id: str) -> None:
    reporter = current()
    if reporter is not None:
        reporter.finish_phase(phase_id)


def skip_phase(phase_id: str, reason: str) -> None:
    reporter = current()
    if reporter is not None:
        reporter.skip_phase(phase_id, reason)


def tick(**fields: Any) -> None:
    reporter = current()
    if reporter is not None:
        reporter.tick(**fields)


def start_closing_if_planned() -> None:
    """Start Saving the audit or Finishing the pass when the plan includes it."""
    reporter = current()
    if reporter is None:
        return
    ids = {phase["id"] for phase in reporter.snapshot().get("phases", [])}
    if SAVING_AUDIT in ids:
        reporter.start_phase(SAVING_AUDIT)
    elif FINISHING_PASS in ids:
        reporter.start_phase(FINISHING_PASS)
