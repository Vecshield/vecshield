"""Runtime exfiltration / abuse detectors.

Each detector is self-contained: it owns its per-principal state and exposes a
single `process(event) -> Optional[Alert]`. Detectors do NOT manage alert
cadence — they may fire on every qualifying event; the engine's cooldown
collapses floods into a single actionable alert. Detectors assume the engine
serializes calls (one lock), so they hold no internal locks.

All time reasoning uses `event.timestamp`.
"""

from __future__ import annotations

import math
from abc import ABC, abstractmethod
from typing import Any, Callable, Optional

from vecshield.models import Severity
from vecshield_platform.runtime.events import Alert, QueryEvent
from vecshield_platform.runtime.windows import Ewma, SlidingWindow, WindowedDistinct


class Detector(ABC):
    name: str = "detector"

    @abstractmethod
    def process(self, event: QueryEvent) -> Optional[Alert]:
        ...


def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)


class BulkVolumeDetector(Detector):
    """Too many queries from one principal in a trailing window — the classic
    scrape signature."""

    name = "bulk_volume"

    def __init__(self, threshold: int = 500, window_s: float = 600.0,
                 severity: Severity = Severity.HIGH):
        self.threshold = threshold
        self.window_s = window_s
        self.severity = severity
        self._w: dict[str, SlidingWindow] = {}

    def process(self, event: QueryEvent) -> Optional[Alert]:
        w = self._w.setdefault(event.principal, SlidingWindow(self.window_s))
        w.add(event.timestamp)
        count = w.count(event.timestamp)
        if count >= self.threshold:
            return Alert(
                rule=self.name,
                severity=self.severity,
                principal=event.principal,
                timestamp=event.timestamp,
                collection=event.collection,
                message=(f"{count} queries in {int(self.window_s)}s from "
                         f"'{event.principal}' (threshold {self.threshold})"),
                dedup_key=f"{event.principal}:{self.name}",
                evidence={"count": count, "window_s": self.window_s,
                          "threshold": self.threshold},
            )
        return None


class CollectionSweepDetector(Detector):
    """One principal retrieves a large fraction of a collection's distinct
    vectors in a window — reconstructing the corpus rather than answering a
    question."""

    name = "collection_sweep"

    def __init__(self, fraction: float = 0.8, window_s: float = 600.0,
                 size_fn: Optional[Callable[[str], Optional[int]]] = None,
                 severity: Severity = Severity.HIGH):
        self.fraction = fraction
        self.window_s = window_s
        self.size_fn = size_fn or (lambda _c: None)
        self.severity = severity
        self._d: dict[tuple[str, str], WindowedDistinct] = {}

    def process(self, event: QueryEvent) -> Optional[Alert]:
        if not event.result_ids:
            return None
        size = self.size_fn(event.collection)
        key = (event.principal, event.collection)
        wd = self._d.setdefault(key, WindowedDistinct(self.window_s))
        wd.add(event.timestamp, event.result_ids)
        if not size or size <= 0:
            return None
        distinct = wd.distinct(event.timestamp)
        if distinct >= self.fraction * size:
            return Alert(
                rule=self.name,
                severity=self.severity,
                principal=event.principal,
                timestamp=event.timestamp,
                collection=event.collection,
                message=(f"'{event.principal}' retrieved {distinct}/{size} distinct "
                         f"vectors ({distinct / size:.0%}) of '{event.collection}' "
                         f"in {int(self.window_s)}s"),
                dedup_key=f"{event.principal}:{event.collection}:{self.name}",
                evidence={"distinct": distinct, "collection_size": size,
                          "coverage": round(distinct / size, 4)},
            )
        return None


class EnumerationDetector(Detector):
    """A sustained run of consecutive queries whose vectors are near-duplicates
    of the previous one — systematic walking of the embedding space (e.g.
    feeding results back as the next query to enumerate neighbors)."""

    name = "enumeration"

    def __init__(self, sim_threshold: float = 0.97, run_length: int = 10,
                 max_gap_s: float = 30.0, severity: Severity = Severity.MEDIUM):
        self.sim_threshold = sim_threshold
        self.run_length = run_length
        self.max_gap_s = max_gap_s
        self.severity = severity
        self._state: dict[str, dict] = {}

    def process(self, event: QueryEvent) -> Optional[Alert]:
        if not event.query_vector:
            return None
        st = self._state.setdefault(event.principal,
                                    {"last_vec": None, "last_ts": None, "run": 1})
        if st["last_vec"] is not None and st["last_ts"] is not None:
            sim = _cosine(event.query_vector, st["last_vec"])
            gap = event.timestamp - st["last_ts"]
            if sim >= self.sim_threshold and 0 <= gap <= self.max_gap_s:
                st["run"] += 1
            else:
                st["run"] = 1
        st["last_vec"] = event.query_vector
        st["last_ts"] = event.timestamp

        if st["run"] >= self.run_length:
            return Alert(
                rule=self.name,
                severity=self.severity,
                principal=event.principal,
                timestamp=event.timestamp,
                collection=event.collection,
                message=(f"'{event.principal}' issued {st['run']} consecutive "
                         f"near-identical queries (sim >= {self.sim_threshold}) — "
                         "embedding-space enumeration"),
                dedup_key=f"{event.principal}:{self.name}",
                evidence={"run_length": st["run"],
                          "sim_threshold": self.sim_threshold},
            )
        return None


class RateBaselineDetector(Detector):
    """Per-principal rolling baseline. Learns each principal's normal query rate
    (EWMA, sampled at window boundaries) and flags a sudden spike relative to
    that principal's OWN history — catching abuse that's below any global
    threshold but abnormal for this key."""

    name = "rate_baseline"

    def __init__(self, window_s: float = 60.0, spike_factor: float = 5.0,
                 warmup_samples: int = 3, min_rate: float = 10.0,
                 alpha: float = 0.3, severity: Severity = Severity.MEDIUM):
        self.window_s = window_s
        self.spike_factor = spike_factor
        self.warmup_samples = warmup_samples
        self.min_rate = min_rate
        self.alpha = alpha
        self.severity = severity
        self._state: dict[str, dict] = {}

    def process(self, event: QueryEvent) -> Optional[Alert]:
        st = self._state.setdefault(event.principal, {
            "window": SlidingWindow(self.window_s),
            "ewma": Ewma(self.alpha),
            "last_sample": event.timestamp,
        })
        w: SlidingWindow = st["window"]
        ewma: Ewma = st["ewma"]
        w.add(event.timestamp)
        cur = w.count(event.timestamp)

        alert = None
        # Detect a spike against the established baseline BEFORE folding this
        # period's (possibly anomalous) count into the baseline.
        if ewma.samples >= self.warmup_samples and ewma.value >= 1.0:
            if cur >= self.min_rate and cur >= ewma.value * self.spike_factor:
                alert = Alert(
                    rule=self.name,
                    severity=self.severity,
                    principal=event.principal,
                    timestamp=event.timestamp,
                    collection=event.collection,
                    message=(f"'{event.principal}' query rate {cur}/"
                             f"{int(self.window_s)}s is {cur / ewma.value:.1f}x its "
                             f"baseline (~{ewma.value:.1f})"),
                    dedup_key=f"{event.principal}:{self.name}",
                    evidence={"current_rate": cur, "baseline": round(ewma.value, 2),
                              "spike_factor": self.spike_factor},
                )

        # Sample the baseline once per window boundary.
        if event.timestamp - st["last_sample"] >= self.window_s:
            ewma.update(cur)
            st["last_sample"] = event.timestamp

        return alert


def default_detectors(
    *,
    bulk_threshold: int = 500,
    bulk_window_s: float = 600.0,
    sweep_fraction: float = 0.8,
    sweep_window_s: float = 600.0,
    size_fn: Optional[Callable[[str], Optional[int]]] = None,
) -> list[Detector]:
    """Assemble the standard detector set used by the live monitor.

    The collection-sweep detector only fires when a ``size_fn`` can report a
    collection's size; the API-level engine has no single connector, so it
    passes ``None`` and sweep detection is inert there (bulk/enumeration/rate
    still work on the raw event stream).
    """
    return [
        BulkVolumeDetector(threshold=bulk_threshold, window_s=bulk_window_s),
        CollectionSweepDetector(fraction=sweep_fraction, window_s=sweep_window_s,
                                size_fn=size_fn),
        EnumerationDetector(),
        RateBaselineDetector(),
    ]


def detectors_from_settings(
    settings: Optional[dict[str, Any]] = None,
    *,
    size_fn: Optional[Callable[[str], Optional[int]]] = None,
) -> list[Detector]:
    """Assemble detectors from persisted dashboard settings.

    Policy templates decide what findings mean. These settings tune the runtime
    monitor itself: thresholds, windows, and detector enablement.
    """

    from vecshield_platform.api.config_store import DetectorSettings

    cfg = DetectorSettings.from_dict(settings).to_dict()
    out: list[Detector] = []

    bulk = cfg["bulk_volume"]
    if bulk["enabled"]:
        out.append(BulkVolumeDetector(
            threshold=bulk["threshold"],
            window_s=float(bulk["window_s"]),
            severity=Severity(bulk["severity"]),
        ))

    sweep = cfg["collection_sweep"]
    if sweep["enabled"]:
        out.append(CollectionSweepDetector(
            fraction=float(sweep["fraction"]),
            window_s=float(sweep["window_s"]),
            size_fn=size_fn,
            severity=Severity(sweep["severity"]),
        ))

    enum = cfg["enumeration"]
    if enum["enabled"]:
        out.append(EnumerationDetector(
            sim_threshold=float(enum["sim_threshold"]),
            run_length=enum["run_length"],
            max_gap_s=float(enum["max_gap_s"]),
            severity=Severity(enum["severity"]),
        ))

    rate = cfg["rate_baseline"]
    if rate["enabled"]:
        out.append(RateBaselineDetector(
            window_s=float(rate["window_s"]),
            spike_factor=float(rate["spike_factor"]),
            warmup_samples=rate["warmup_samples"],
            min_rate=float(rate["min_rate"]),
            alpha=float(rate["alpha"]),
            severity=Severity(rate["severity"]),
        ))

    return out
