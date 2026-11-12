"""Monitor engine: runs detectors over events, dedups, dispatches to sinks.

Concurrency model: a single re-entrant lock serializes the whole process() path.
Detectors and the cooldown map are therefore accessed by one thread at a time,
so neither needs internal synchronization. The critical section is small (in-
memory state updates); network I/O in sinks happens inside it too, so use async/
queued sinks if a slow webhook would matter under high QPS (the bundled
WebhookSink has a hard timeout to bound this).

Cooldown: a detector may fire on every event during a flood; the engine emits at
most one alert per (dedup_key) per `cooldown_s` of event time and folds the rest
into `suppressed_since`, so a 10k-query attack yields one actionable alert, not
10k.
"""

from __future__ import annotations

import logging
import threading
from collections import Counter
from typing import Optional

from vecshield_platform.runtime.detectors import Detector
from vecshield_platform.runtime.events import Alert, QueryEvent
from vecshield_platform.runtime.sinks import AlertSink

logger = logging.getLogger(__name__)


class MonitorEngine:
    def __init__(
        self,
        detectors: list[Detector],
        sinks: Optional[list[AlertSink]] = None,
        *,
        cooldown_s: float = 300.0,
    ):
        self.detectors = detectors
        self.sinks = sinks or []
        self.cooldown_s = cooldown_s
        self._last_emit: dict[str, float] = {}
        self._suppressed: Counter[str] = Counter()
        self._lock = threading.RLock()
        self.processed = 0

    def process(self, event: QueryEvent) -> list[Alert]:
        """Run all detectors for one event; return the alerts actually emitted."""
        emitted: list[Alert] = []
        with self._lock:
            self.processed += 1
            for det in self.detectors:
                try:
                    alert = det.process(event)
                except Exception:  # a buggy detector must not sink the others
                    logger.exception("detector %s failed", det.name)
                    continue
                if alert is None:
                    continue
                if self._should_emit(alert):
                    alert.suppressed_since = self._suppressed.pop(alert.dedup_key, 0)
                    self._last_emit[alert.dedup_key] = alert.timestamp
                    self._dispatch(alert)
                    emitted.append(alert)
                else:
                    self._suppressed[alert.dedup_key] += 1
        return emitted

    def _should_emit(self, alert: Alert) -> bool:
        last = self._last_emit.get(alert.dedup_key)
        return last is None or (alert.timestamp - last) >= self.cooldown_s

    def _dispatch(self, alert: Alert) -> None:
        for sink in self.sinks:
            try:
                sink.emit(alert)
            except Exception:  # noqa: BLE001 — never break on a bad sink
                logger.exception("alert sink failed")
