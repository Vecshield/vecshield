"""IngestMonitor — real-time observer for the ingestion path.

Symmetric with the query monitor: each ingested batch produces an
IngestEvent; batches carrying blocked PII also raise an Alert dispatched to the
same sink architecture (webhook / Slack / PagerDuty / in-memory).

Fail-open by contract: a classifier crash or a flaky sink must never break the
ingest path. All event timestamps are caller-supplied (event time), so detection
is deterministic and replayable — same rule as the query monitor.
"""

from __future__ import annotations

import logging
import threading
from typing import Optional

from vecshield.ingest.gate import IngestGate
from vecshield.models import Chunk, IngestEvent, IngestGateReport, Severity
from vecshield_platform.runtime.events import Alert
from vecshield_platform.runtime.sinks import AlertSink

logger = logging.getLogger(__name__)


class IngestMonitor:
    def __init__(
        self,
        gate: IngestGate,
        sinks: Optional[list[AlertSink]] = None,
        *,
        alert_severity: Severity = Severity.HIGH,
        keep_events: bool = True,
    ):
        self.gate = gate
        self.sinks = sinks or []
        self.alert_severity = alert_severity
        self.keep_events = keep_events
        self.events: list[IngestEvent] = []
        self._lock = threading.RLock()
        self.processed = 0

    def observe(
        self,
        chunks: list[Chunk],
        *,
        principal: str,
        dataset: str,
        timestamp: float,
    ) -> IngestGateReport:
        """Inspect a batch, record an IngestEvent, alert if PII was blocked.

        Returns the gate report. Never raises (fail-open), even in hard mode —
        use the returned report's `blocked` flag to decide whether to proceed.
        """
        with self._lock:
            self.processed += 1
            try:
                report = self.gate.inspect(chunks)
            except Exception:  # noqa: BLE001 — never break ingest
                logger.exception("ingest gate error")
                return IngestGateReport(allowed_chunks=list(chunks))

            event = IngestEvent(
                principal=principal,
                dataset=dataset,
                timestamp=timestamp,
                batch_size=report.total,
                pii_count=len(report.blocked_chunks),
                blocked=report.blocked,
                metadata={"pii_density": round(report.pii_density, 4)},
            )
            if self.keep_events:
                self.events.append(event)

            if report.blocked:
                self._dispatch(event, report)
            return report

    def _dispatch(self, event: IngestEvent, report: IngestGateReport) -> None:
        alert = Alert(
            rule="ingest_pii",
            severity=self.alert_severity,
            principal=event.principal,
            timestamp=event.timestamp,
            message=(
                f"{event.pii_count} of {event.batch_size} chunks blocked at ingest "
                f"into '{event.dataset}'"
            ),
            dedup_key=f"ingest:{event.dataset}:{event.principal}",
            collection=event.dataset,
            evidence={"pii_count": event.pii_count, "batch_size": event.batch_size,
                      "pii_density": event.metadata.get("pii_density"),
                      "blocked_chunk_ids": [c.id for c in report.blocked_chunks][:20]},
        )
        for sink in self.sinks:
            try:
                sink.emit(alert)
            except Exception:  # noqa: BLE001 — bad sink never breaks ingest
                logger.exception("ingest sink error")
