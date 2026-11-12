"""Framework-neutral runtime adapter tests."""

from __future__ import annotations

from vecshield_platform.runtime import (
    BulkVolumeDetector,
    CollectionSweepDetector,
    InMemorySink,
    MonitorEngine,
    emit_retrieval_event,
    wrap_retriever,
)


def test_emit_retrieval_event_extracts_result_ids():
    sink = InMemorySink()
    engine = MonitorEngine(
        detectors=[CollectionSweepDetector(fraction=0.5, size_fn=lambda _c: 2)],
        sinks=[sink],
        cooldown_s=0,
    )
    docs = [
        {"metadata": {"source": "doc-a"}},
        {"id": "doc-b", "metadata": {"source": "ignored"}},
    ]
    alerts = emit_retrieval_event(
        engine,
        principal="svc",
        collection="docs",
        results=docs,
        timestamp=1.0,
    )
    assert alerts
    assert alerts[0].rule == "collection_sweep"


def test_wrap_retriever_passes_results_through_and_observes():
    sink = InMemorySink()
    engine = MonitorEngine(
        detectors=[BulkVolumeDetector(threshold=1, window_s=60)],
        sinks=[sink],
        cooldown_s=0,
    )

    def retrieve(query, query_vector=None):
        return [{"id": "doc-1", "text": query}]

    observed = wrap_retriever(
        retrieve,
        engine,
        principal="svc",
        collection="docs",
    )
    result = observed("hello", query_vector=[0.1, 0.2])
    assert result == [{"id": "doc-1", "text": "hello"}]
    assert len(sink.alerts) == 1
    assert sink.alerts[0].rule == "bulk_volume"
