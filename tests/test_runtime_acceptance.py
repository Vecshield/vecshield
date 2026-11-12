"""Acceptance: a bulk exfiltration script triggers an alert within 60s.

Latency is measured in EVENT time (the timestamps the queries carry), which is
exactly how a real deployment would measure detection latency — and makes the
assertion exact rather than dependent on test-machine speed.
"""

from __future__ import annotations

from vecshield_platform.runtime import (
    BulkVolumeDetector,
    CollectionSweepDetector,
    EnumerationDetector,
    InMemorySink,
    MonitorEngine,
    MonitoredConnector,
    RateBaselineDetector,
    collection_size_fn,
)


def test_bulk_exfiltration_alerts_within_60s(make_fake_connector):
    inner = make_fake_connector({"docs": 100_000})  # large, so it's not a "sweep"
    sink = InMemorySink()
    engine = MonitorEngine(
        detectors=[
            BulkVolumeDetector(threshold=500, window_s=600),
            CollectionSweepDetector(fraction=0.8, size_fn=collection_size_fn(inner)),
            EnumerationDetector(),
            RateBaselineDetector(),
        ],
        sinks=[sink],
        cooldown_s=300,
    )

    # Attacker script: 600 queries, one every 50ms -> 30s of event time total.
    start = 1_000_000.0
    t = [start]

    def clock():
        v = t[0]
        t[0] += 0.05
        return v

    conn = MonitoredConnector(inner, engine, principal="leaked-key-7", clock=clock)
    for _ in range(600):
        conn.query("docs", [0.1, 0.2, 0.3])

    bulk = [a for a in sink.alerts if a.rule == "bulk_volume"]
    assert bulk, "expected a bulk_volume alert"

    latency = bulk[0].timestamp - start
    assert latency <= 60.0, f"detection latency {latency:.1f}s exceeded 60s"
    # Cooldown means the 600-query flood yields ONE actionable alert, not 600.
    assert len(bulk) == 1
    assert bulk[0].principal == "leaked-key-7"
