"""Proxy tests: transparency, delegation, fail-open, and end-to-end detection."""

from __future__ import annotations

from vecshield.models import QueryHit
from vecshield_platform.runtime import (
    BulkVolumeDetector,
    InMemorySink,
    MonitorEngine,
    MonitoredConnector,
)
from vecshield_platform.runtime.engine import MonitorEngine as RealEngine


def test_query_results_pass_through_unchanged(make_fake_connector):
    inner = make_fake_connector({"docs": 100})
    engine = MonitorEngine([BulkVolumeDetector(threshold=999, window_s=10)])
    conn = MonitoredConnector(inner, engine, principal="svc")
    hits = conn.query("docs", [0.1, 0.2], top_k=3)
    assert len(hits) == 3 and all(isinstance(h, QueryHit) for h in hits)


def test_delegates_describe_and_capabilities(make_fake_connector):
    inner = make_fake_connector({"docs": 42})
    conn = MonitoredConnector(inner, MonitorEngine([]), principal="svc")
    assert conn.capabilities() == {"query"}
    assert conn.describe().collections[0].count == 42


class _BoomEngine(RealEngine):
    def process(self, event):
        raise RuntimeError("monitoring exploded")


def test_fail_open_keeps_serving_queries(make_fake_connector):
    inner = make_fake_connector({"docs": 100})
    conn = MonitoredConnector(inner, _BoomEngine([]), principal="svc",
                              fail_open=True)
    hits = conn.query("docs", [0.1], top_k=2)  # must not raise
    assert len(hits) == 2


def test_fail_closed_propagates(make_fake_connector):
    inner = make_fake_connector({"docs": 100})
    conn = MonitoredConnector(inner, _BoomEngine([]), principal="svc",
                              fail_open=False)
    import pytest
    with pytest.raises(RuntimeError):
        conn.query("docs", [0.1])


def test_end_to_end_detection_through_proxy(make_fake_connector):
    inner = make_fake_connector({"docs": 100})
    sink = InMemorySink()
    engine = MonitorEngine([BulkVolumeDetector(threshold=5, window_s=600)],
                           sinks=[sink], cooldown_s=0)
    # Deterministic clock advancing 1s per query.
    t = [0.0]

    def clock():
        v = t[0]
        t[0] += 1.0
        return v

    conn = MonitoredConnector(inner, engine, principal="scraper", clock=clock)
    for _ in range(6):
        conn.query("docs", [0.1, 0.2])
    assert any(a.rule == "bulk_volume" and a.principal == "scraper"
               for a in sink.alerts)
