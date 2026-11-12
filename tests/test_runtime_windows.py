"""Unit tests for the sliding-window primitives."""

from __future__ import annotations

from vecshield_platform.runtime.windows import Ewma, SlidingWindow, WindowedDistinct


def test_sliding_window_counts_and_evicts():
    w = SlidingWindow(window_s=10)
    for t in range(5):
        w.add(float(t))           # ts 0..4
    assert w.count(4.0) == 5
    # advance well past the window: everything before t-10 is evicted
    assert w.count(20.0) == 0


def test_sliding_window_partial_eviction():
    w = SlidingWindow(window_s=10)
    for t in [0, 5, 8, 12]:
        w.add(float(t))
    # at now=12, window is (2, 12]; ts 0 evicted, 5/8/12 remain
    assert w.count(12.0) == 3


def test_windowed_distinct():
    d = WindowedDistinct(window_s=10)
    d.add(0.0, ["a", "b"])
    d.add(1.0, ["b", "c"])         # b repeats
    assert d.distinct(1.0) == 3    # a, b, c
    # advance so the early entries age out
    d.add(20.0, ["z"])
    assert d.distinct(20.0) == 1


def test_ewma_warmup_and_smoothing():
    e = Ewma(alpha=0.5)
    assert e.update(10) == 10      # first sample initializes
    assert e.samples == 1
    v = e.update(0)
    assert 0 < v < 10              # smoothed toward 0
