"""Background auto-update of the server advisory feed.

A daemon thread wakes every ``tick_s`` seconds (15 minutes by default) and
calls :func:`vecshield_platform.posture.vulnfeed.refresh_if_due`. That is a
no-op unless an admin turned ``auto_update`` on (``FeedSchedule``, stored at
``<state>/vulnfeed/schedule.json``), which is the admin's consent to the
outbound requests the refresh makes. A tick never raises, and ``stop()`` ends
the thread promptly. The server starts it; tests and the CLI do not.

Manual refreshes (``POST /admin/vulnfeed/refresh``) share :attr:`lock`, so a
scheduled tick and an admin's refresh never write the feed at the same time.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

#: Every host a refresh contacts (posture/vulnfeed.py's fixed endpoints).
EGRESS_HOSTS = ("api.osv.dev", "api.github.com", "services.nvd.nist.gov",
                "www.postgresql.org", "www.cisa.gov", "endoflife.date")

#: Guards read-modify-write of ``schedule.json`` in this process. Held only
#: briefly, never across a refresh, so an admin's settings change is not
#: blocked by (or overwritten by) a refresh that is running.
SCHEDULE_LOCK = threading.Lock()

DEFAULT_TICK_S = 15 * 60
#: Delay before the first tick, so startup is not slowed by a refresh.
DEFAULT_FIRST_TICK_S = 60.0


def refresh_preserving_settings(state_dir: str | Path, settings: Any = None, *,
                                now: Optional[datetime] = None, force: bool = False,
                                **refresh_kwargs: Any) -> tuple[Any, Any]:
    """``refresh_if_due`` that records only its own outcome in the schedule.

    A refresh takes about a minute. Persisting the settings object it loaded
    at the start would undo an admin's change made meanwhile (turning
    auto-update off, say), so only ``last_attempt``/``last_success``/
    ``last_error`` are written back onto the schedule as it is now.
    """
    from vecshield_platform.posture import vulnfeed

    settings, result = vulnfeed.refresh_if_due(state_dir, settings, now=now, force=force,
                                               persist=False, **refresh_kwargs)
    with SCHEDULE_LOCK:
        current = vulnfeed.load_schedule(state_dir)
        current.last_attempt = settings.last_attempt
        current.last_success = settings.last_success
        current.last_error = settings.last_error
        vulnfeed.save_schedule(state_dir, current)
    return current, result


class FeedScheduler:
    def __init__(self, state_dir: str | Path, *,
                 tick_s: float = DEFAULT_TICK_S,
                 first_tick_s: float = DEFAULT_FIRST_TICK_S,
                 refresh: Optional[Callable[..., Any]] = None,
                 credentials: Optional[Callable[[], dict]] = None,
                 on_refresh: Optional[Callable[[Any, Any], None]] = None,
                 clock: Optional[Callable[[], datetime]] = None,
                 lock: Optional[threading.Lock] = None) -> None:
        self.state_dir = Path(state_dir)
        self.tick_s = float(tick_s)
        self.first_tick_s = float(first_tick_s)
        self._refresh = refresh or refresh_preserving_settings
        self._credentials = credentials or dict
        self._on_refresh = on_refresh
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self.lock = lock or threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.ticks = 0

    # ------------------------------------------------------------------ #
    def tick(self) -> Optional[Any]:
        """One scheduler pass. Returns the refresh result, or None. Never raises."""
        from vecshield_platform.posture import vulnfeed

        self.ticks += 1
        try:
            now = self._clock()
            settings = vulnfeed.load_schedule(self.state_dir)
            if not vulnfeed.due(settings, now):
                return None
            if not self.lock.acquire(blocking=False):
                return None  # an admin's refresh is running
            try:
                settings, result = self._refresh(self.state_dir, settings, now=now,
                                                 **self._credentials())
            finally:
                self.lock.release()
            if self._on_refresh is not None:
                try:
                    self._on_refresh(settings, result)
                except Exception:  # noqa: BLE001 - reporting must not stop the loop
                    logger.warning("vulnfeed auto-update callback failed", exc_info=True)
            return result
        except Exception:  # noqa: BLE001 - a scheduler tick never raises
            logger.warning("vulnfeed auto-update tick failed", exc_info=True)
            return None

    def _loop(self) -> None:
        wait = self.first_tick_s
        while not self._stop.wait(wait):
            self.tick()
            wait = self.tick_s

    def start(self) -> "FeedScheduler":
        if self._thread is not None and self._thread.is_alive():
            return self
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="vecshield-vulnfeed",
                                        daemon=True)
        self._thread.start()
        return self

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout)

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()
