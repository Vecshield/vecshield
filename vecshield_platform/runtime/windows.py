"""Sliding-window primitives, all driven by caller-supplied event time.

These are deliberately simple and self-evicting so each detector can own its own
instance without sharing mutable state. Memory is bounded by (rate × window).

None of these read the system clock; the caller passes `now` (an event
timestamp) on every operation.
"""

from __future__ import annotations

from collections import Counter, deque


class SlidingWindow:
    """Counts timestamps within the trailing `window_s` seconds of event time."""

    def __init__(self, window_s: float):
        self.window_s = window_s
        self._times: deque[float] = deque()

    def add(self, now: float) -> None:
        self._times.append(now)
        self._evict(now)

    def _evict(self, now: float) -> None:
        cutoff = now - self.window_s
        t = self._times
        while t and t[0] < cutoff:
            t.popleft()

    def count(self, now: float) -> int:
        self._evict(now)
        return len(self._times)


class WindowedDistinct:
    """Number of distinct ids seen within the trailing `window_s` seconds.

    Maintains per-id counts so ids can be evicted correctly as they age out —
    the standard approach for distinct-count over a sliding window.
    """

    def __init__(self, window_s: float):
        self.window_s = window_s
        self._events: deque[tuple[float, str]] = deque()
        self._counts: Counter[str] = Counter()

    def add(self, now: float, ids: list[str]) -> None:
        for _id in ids:
            self._events.append((now, _id))
            self._counts[_id] += 1
        self._evict(now)

    def _evict(self, now: float) -> None:
        cutoff = now - self.window_s
        ev = self._events
        while ev and ev[0][0] < cutoff:
            _, _id = ev.popleft()
            c = self._counts.get(_id, 0)
            if c <= 1:
                self._counts.pop(_id, None)
            else:
                self._counts[_id] = c - 1

    def distinct(self, now: float) -> int:
        self._evict(now)
        return len(self._counts)


class Ewma:
    """Exponentially-weighted moving average with explicit warmup tracking."""

    def __init__(self, alpha: float = 0.3):
        self.alpha = alpha
        self.value: float = 0.0
        self.samples: int = 0

    def update(self, x: float) -> float:
        if self.samples == 0:
            self.value = x
        else:
            self.value = self.alpha * x + (1 - self.alpha) * self.value
        self.samples += 1
        return self.value
