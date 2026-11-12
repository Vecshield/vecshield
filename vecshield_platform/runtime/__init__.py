"""Runtime query monitoring.

Build an engine from detectors + sinks, then wrap any connector:

    from vecshield_platform.runtime import (
        MonitorEngine, MonitoredConnector, BulkVolumeDetector,
        CollectionSweepDetector, EnumerationDetector, RateBaselineDetector,
        ConsoleSink, WebhookSink, collection_size_fn,
    )

    engine = MonitorEngine(
        detectors=[
            BulkVolumeDetector(threshold=500, window_s=600),
            CollectionSweepDetector(size_fn=collection_size_fn(inner)),
            EnumerationDetector(),
            RateBaselineDetector(),
        ],
        sinks=[ConsoleSink(), WebhookSink(slack_url)],
    )
    conn = MonitoredConnector(inner, engine, principal="svc-rag")
    conn.query("docs", vector)   # observed transparently
"""

from __future__ import annotations

from vecshield_platform.runtime.detectors import (
    BulkVolumeDetector,
    CollectionSweepDetector,
    Detector,
    EnumerationDetector,
    RateBaselineDetector,
    default_detectors,
    detectors_from_settings,
)
from vecshield_platform.runtime.adapters import (
    LangChainRetrieverCallback,
    emit_retrieval_event,
    wrap_retriever,
)
from vecshield_platform.runtime.engine import MonitorEngine
from vecshield_platform.runtime.events import Alert, QueryEvent
from vecshield_platform.runtime.ingest_monitor import IngestMonitor
from vecshield_platform.runtime.proxy import MonitoredConnector, collection_size_fn
from vecshield_platform.runtime.sinks import (
    AlertSink,
    ConsoleSink,
    InMemorySink,
    PersistentAlertSink,
    WebhookSink,
    build_sinks,
)
from vecshield_platform.runtime.store import AlertStore

__all__ = [
    "MonitorEngine",
    "MonitoredConnector",
    "collection_size_fn",
    "QueryEvent",
    "Alert",
    "IngestMonitor",
    "Detector",
    "BulkVolumeDetector",
    "CollectionSweepDetector",
    "EnumerationDetector",
    "RateBaselineDetector",
    "default_detectors",
    "detectors_from_settings",
    "AlertSink",
    "InMemorySink",
    "ConsoleSink",
    "PersistentAlertSink",
    "WebhookSink",
    "build_sinks",
    "AlertStore",
    "emit_retrieval_event",
    "wrap_retriever",
    "LangChainRetrieverCallback",
]
