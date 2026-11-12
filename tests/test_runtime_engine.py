"""Engine tests: cooldown/dedup, detector isolation, multi-sink dispatch."""

from __future__ import annotations

from vecshield_platform.runtime.detectors import BulkVolumeDetector, Detector
from vecshield_platform.runtime.engine import MonitorEngine
from vecshield_platform.runtime.events import QueryEvent
from vecshield_platform.runtime.sinks import InMemorySink


def _ev(ts):
    return QueryEvent(principal="p", collection="c", timestamp=ts)


def test_cooldown_collapses_flood_into_one_alert():
    sink = InMemorySink()
    engine = MonitorEngine(
        [BulkVolumeDetector(threshold=3, window_s=1000)],
        sinks=[sink], cooldown_s=100,
    )
    # Detector fires from the 3rd event onward; cooldown lets only one through.
    for t in range(10):
        engine.process(_ev(float(t)))
    assert len(sink) == 1

    # After the cooldown elapses (event time), a new alert is allowed and folds
    # in how many were suppressed in between.
    engine.process(_ev(200.0))
    assert len(sink) == 2
    assert sink.alerts[1].suppressed_since == 7  # events at ts 3..9


class _BoomDetector(Detector):
    name = "boom"

    def process(self, event):
        raise RuntimeError("detector blew up")


def test_buggy_detector_does_not_block_others():
    sink = InMemorySink()
    engine = MonitorEngine(
        [_BoomDetector(), BulkVolumeDetector(threshold=1, window_s=10)],
        sinks=[sink], cooldown_s=0,
    )
    engine.process(_ev(0.0))
    assert len(sink) == 1  # the good detector still fired despite the boom


def test_multiple_sinks_all_receive():
    s1, s2 = InMemorySink(), InMemorySink()
    engine = MonitorEngine(
        [BulkVolumeDetector(threshold=1, window_s=10)],
        sinks=[s1, s2], cooldown_s=0,
    )
    engine.process(_ev(0.0))
    assert len(s1) == 1 and len(s2) == 1
