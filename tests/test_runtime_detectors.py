"""Unit tests for each runtime detector, driven by synthetic event time."""

from __future__ import annotations

from vecshield_platform.runtime.detectors import (
    BulkVolumeDetector,
    CollectionSweepDetector,
    EnumerationDetector,
    RateBaselineDetector,
)
from vecshield_platform.runtime.events import QueryEvent


def _ev(principal="p", collection="c", ts=0.0, vector=None, ids=None):
    return QueryEvent(principal=principal, collection=collection, timestamp=ts,
                      query_vector=vector, result_ids=ids or [])


# ---- BulkVolume ----

def test_bulk_volume_fires_at_threshold():
    det = BulkVolumeDetector(threshold=5, window_s=10)
    alerts = [det.process(_ev(ts=float(i))) for i in range(5)]
    assert alerts[-1] is not None and alerts[-1].rule == "bulk_volume"
    assert all(a is None for a in alerts[:4])


def test_bulk_volume_respects_sliding_window():
    det = BulkVolumeDetector(threshold=5, window_s=10)
    # one query every 20s -> never more than 1 in a 10s window
    alerts = [det.process(_ev(ts=float(i * 20))) for i in range(10)]
    assert all(a is None for a in alerts)


# ---- CollectionSweep ----

def test_collection_sweep_fires_on_high_coverage():
    det = CollectionSweepDetector(fraction=0.8, window_s=600,
                                  size_fn=lambda c: 100)
    alert = None
    for i in range(10):  # each query returns 10 fresh ids -> 100 distinct by i=9
        ids = [f"id-{i}-{k}" for k in range(10)]
        alert = det.process(_ev(ts=float(i), ids=ids)) or alert
    assert alert is not None and alert.rule == "collection_sweep"
    assert alert.evidence["coverage"] >= 0.8


def test_collection_sweep_silent_when_size_unknown():
    det = CollectionSweepDetector(fraction=0.8, size_fn=lambda c: None)
    for i in range(50):
        det.process(_ev(ts=float(i), ids=[f"x{i}"]))
    # no size -> cannot compute coverage -> no alert (no crash)


# ---- Enumeration ----

def test_enumeration_fires_on_similar_vector_run():
    det = EnumerationDetector(sim_threshold=0.97, run_length=5, max_gap_s=30)
    v = [1.0, 0.0, 0.0, 0.0]
    alert = None
    for i in range(6):
        alert = det.process(_ev(ts=float(i), vector=v)) or alert
    assert alert is not None and alert.rule == "enumeration"


def test_enumeration_silent_on_diverse_queries():
    det = EnumerationDetector(sim_threshold=0.97, run_length=5)
    vecs = [[1, 0, 0, 0], [0, 1, 0, 0], [0, 0, 1, 0], [0, 0, 0, 1]] * 3
    alerts = [det.process(_ev(ts=float(i), vector=v)) for i, v in enumerate(vecs)]
    assert all(a is None for a in alerts)


# ---- RateBaseline ----

def test_rate_baseline_flags_spike_against_learned_norm():
    det = RateBaselineDetector(window_s=10, spike_factor=3, warmup_samples=2,
                               min_rate=10, alpha=0.5)
    alerts = []
    # Warmup: ~3 queries per 10s window across several windows -> low baseline.
    for w in range(5):
        for i in range(3):
            alerts.append(det.process(_ev(ts=w * 10 + i * 0.1)))
    assert all(a is None for a in alerts), "no alert during calm warmup"

    # Spike: 40 queries inside one window, well above the learned baseline.
    spike_alert = None
    for i in range(40):
        spike_alert = det.process(_ev(ts=100 + i * 0.1)) or spike_alert
    assert spike_alert is not None and spike_alert.rule == "rate_baseline"
    assert spike_alert.evidence["current_rate"] >= 10
