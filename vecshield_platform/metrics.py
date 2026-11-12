"""Dependency-free Prometheus metrics for the VecShield platform.

Both packages avoid mandatory third-party deps, so this
is a small, thread-safe metrics registry that renders the Prometheus text
exposition format (v0.0.4). It supports the three families we need — counters,
gauges and histograms — with optional labels.

A single process-wide :data:`REGISTRY` holds the metrics the API and CLI record;
the ``/metrics`` endpoint calls :func:`render` on it. Instrumentation helpers
(:func:`record_findings`, :func:`observe_scan`, ...) keep call sites terse and
make the metric names/labels consistent across emitters.
"""

from __future__ import annotations

import math
import threading
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

_LabelValues = Tuple[str, ...]

# Default histogram buckets (seconds) — tuned for scan/audit style operations
# that range from sub-second (cached) to minutes (large stores).
DEFAULT_BUCKETS: Tuple[float, ...] = (
    0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0,
)


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _fmt_labels(names: Sequence[str], values: _LabelValues, extra: str = "") -> str:
    parts = [f'{n}="{_escape(str(v))}"' for n, v in zip(names, values)]
    if extra:
        parts.append(extra)
    return "{" + ",".join(parts) + "}" if parts else ""


def _fmt_value(value: float) -> str:
    if value == math.inf:
        return "+Inf"
    if value == -math.inf:
        return "-Inf"
    if value != value:  # NaN
        return "NaN"
    if float(value).is_integer():
        return str(int(value))
    return repr(value)


class _Metric:
    def __init__(self, name: str, documentation: str, labelnames: Sequence[str]):
        self.name = name
        self.documentation = documentation
        self.labelnames = tuple(labelnames)
        self._lock = threading.Lock()

    def _key(self, labels: Optional[Dict[str, str]]) -> _LabelValues:
        labels = labels or {}
        if set(labels) != set(self.labelnames):
            raise ValueError(
                f"metric {self.name!r} expects labels {self.labelnames}, got {tuple(labels)}"
            )
        return tuple(str(labels[n]) for n in self.labelnames)


class Counter(_Metric):
    """Monotonically increasing counter."""

    def __init__(self, name: str, documentation: str, labelnames: Sequence[str] = ()):
        super().__init__(name, documentation, labelnames)
        self._values: Dict[_LabelValues, float] = {}

    def inc(self, amount: float = 1.0, **labels: str) -> None:
        if amount < 0:
            raise ValueError("counters cannot decrease")
        key = self._key(labels)
        with self._lock:
            self._values[key] = self._values.get(key, 0.0) + amount

    def value(self, **labels: str) -> float:
        with self._lock:
            return self._values.get(self._key(labels), 0.0)

    def render(self) -> List[str]:
        lines = [f"# HELP {self.name} {self.documentation}", f"# TYPE {self.name} counter"]
        with self._lock:
            items = sorted(self._values.items()) or ([((),  0.0)] if not self.labelnames else [])
            for key, val in items:
                lines.append(f"{self.name}{_fmt_labels(self.labelnames, key)} {_fmt_value(val)}")
        return lines


class Gauge(_Metric):
    """Value that can go up or down."""

    def __init__(self, name: str, documentation: str, labelnames: Sequence[str] = ()):
        super().__init__(name, documentation, labelnames)
        self._values: Dict[_LabelValues, float] = {}

    def set(self, amount: float, **labels: str) -> None:
        key = self._key(labels)
        with self._lock:
            self._values[key] = float(amount)

    def inc(self, amount: float = 1.0, **labels: str) -> None:
        key = self._key(labels)
        with self._lock:
            self._values[key] = self._values.get(key, 0.0) + amount

    def value(self, **labels: str) -> float:
        with self._lock:
            return self._values.get(self._key(labels), 0.0)

    def render(self) -> List[str]:
        lines = [f"# HELP {self.name} {self.documentation}", f"# TYPE {self.name} gauge"]
        with self._lock:
            for key, val in sorted(self._values.items()):
                lines.append(f"{self.name}{_fmt_labels(self.labelnames, key)} {_fmt_value(val)}")
        return lines


class Histogram(_Metric):
    """Cumulative histogram with a ``_sum`` and ``_count``."""

    def __init__(
        self,
        name: str,
        documentation: str,
        labelnames: Sequence[str] = (),
        buckets: Sequence[float] = DEFAULT_BUCKETS,
    ):
        super().__init__(name, documentation, labelnames)
        self._bounds: Tuple[float, ...] = tuple(sorted(buckets)) + (math.inf,)
        self._counts: Dict[_LabelValues, List[int]] = {}
        self._sums: Dict[_LabelValues, float] = {}

    def observe(self, amount: float, **labels: str) -> None:
        key = self._key(labels)
        with self._lock:
            counts = self._counts.setdefault(key, [0] * len(self._bounds))
            self._sums[key] = self._sums.get(key, 0.0) + amount
            # Increment only the smallest bucket the value falls into; render()
            # turns these per-bucket counts into the cumulative Prometheus form.
            for i, bound in enumerate(self._bounds):
                if amount <= bound:
                    counts[i] += 1
                    break

    def render(self) -> List[str]:
        lines = [f"# HELP {self.name} {self.documentation}", f"# TYPE {self.name} histogram"]
        with self._lock:
            for key, counts in sorted(self._counts.items()):
                cumulative = 0
                for bound, count in zip(self._bounds, counts):
                    cumulative += count
                    le = _fmt_value(bound)
                    labels = _fmt_labels(self.labelnames, key, f'le="{le}"')
                    lines.append(f"{self.name}_bucket{labels} {cumulative}")
                base = _fmt_labels(self.labelnames, key)
                lines.append(f"{self.name}_sum{base} {_fmt_value(self._sums.get(key, 0.0))}")
                lines.append(f"{self.name}_count{base} {cumulative}")
        return lines


class Registry:
    """A collection of metrics rendered together."""

    def __init__(self) -> None:
        self._metrics: List[_Metric] = []
        self._lock = threading.Lock()

    def register(self, metric: _Metric) -> _Metric:
        with self._lock:
            self._metrics.append(metric)
        return metric

    def counter(self, name: str, documentation: str, labelnames: Sequence[str] = ()) -> Counter:
        return self.register(Counter(name, documentation, labelnames))  # type: ignore[return-value]

    def gauge(self, name: str, documentation: str, labelnames: Sequence[str] = ()) -> Gauge:
        return self.register(Gauge(name, documentation, labelnames))  # type: ignore[return-value]

    def histogram(
        self,
        name: str,
        documentation: str,
        labelnames: Sequence[str] = (),
        buckets: Sequence[float] = DEFAULT_BUCKETS,
    ) -> Histogram:
        return self.register(Histogram(name, documentation, labelnames, buckets))  # type: ignore[return-value]

    def render(self) -> str:
        with self._lock:
            metrics = list(self._metrics)
        lines: List[str] = []
        for metric in metrics:
            lines.extend(metric.render())
        return "\n".join(lines) + "\n"


# --- process-wide registry and the metrics VecShield records ----------------

REGISTRY = Registry()

SCANS_TOTAL = REGISTRY.counter(
    "vecshield_operations_total",
    "Detection operations run, by operation type.",
    ["op"],
)
FINDINGS_TOTAL = REGISTRY.counter(
    "vecshield_findings_total",
    "Findings produced, by severity.",
    ["severity"],
)
OPERATION_DURATION = REGISTRY.histogram(
    "vecshield_operation_duration_seconds",
    "Wall-clock duration of detection operations, by operation type.",
    ["op"],
)
ALERTS_DISPATCHED_TOTAL = REGISTRY.counter(
    "vecshield_alerts_dispatched_total",
    "Alerts dispatched to configured sinks.",
)
CONNECTOR_ERRORS_TOTAL = REGISTRY.counter(
    "vecshield_connector_errors_total",
    "Connector-level errors encountered during operations.",
)


def record_findings(findings: Iterable) -> None:
    """Increment ``vecshield_findings_total`` for a batch of findings.

    Accepts any objects exposing a ``severity`` (enum with ``.value`` or a
    plain string); unknown shapes are counted under ``severity="unknown"`` so a
    metric bug can never break the operation being measured.
    """
    for finding in findings:
        sev = getattr(finding, "severity", None)
        label = getattr(sev, "value", sev)
        FINDINGS_TOTAL.inc(severity=str(label) if label is not None else "unknown")


def observe_operation(op: str, seconds: float) -> None:
    """Record that ``op`` ran and how long it took."""
    SCANS_TOTAL.inc(op=op)
    OPERATION_DURATION.observe(seconds, op=op)


def render() -> str:
    """Render the process registry in Prometheus text exposition format."""
    return REGISTRY.render()
