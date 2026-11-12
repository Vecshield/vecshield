"""MonitoredConnector — a transparent wrapper that observes queries.

Wraps any Connector and forwards every method unchanged. On query() it records a
QueryEvent (after the query returns, so result ids are available for sweep
detection) and feeds it to the MonitorEngine.

Fail-open: monitoring is a *detective* control. A failure in the monitoring path
must never deny a legitimate query, so the query result is computed and returned
first, and engine processing is wrapped in a guard. Set fail_open=False only if
you intend monitoring to be a *preventive* control (then a monitoring failure
raises and the query fails — rarely what you want).
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Iterator, Optional, Union

from vecshield_platform.connectors.base import Connector
from vecshield.models import ApiKey, Chunk, Collection, QueryHit, VectorStore
from vecshield_platform.runtime.engine import MonitorEngine
from vecshield_platform.runtime.events import QueryEvent

logger = logging.getLogger(__name__)


def collection_size_fn(connector: Connector) -> Callable[[str], Optional[int]]:
    """Cached collection-size lookup for the CollectionSweepDetector."""
    sizes = {c.name: c.count for c in connector.describe().collections}
    return lambda name: sizes.get(name)


class MonitoredConnector(Connector):
    def __init__(
        self,
        inner: Connector,
        engine: MonitorEngine,
        *,
        principal: Union[str, Callable[[], str]] = "anonymous",
        clock: Callable[[], float] = time.time,
        fail_open: bool = True,
    ):
        self.inner = inner
        self.engine = engine
        self._principal = principal
        self._clock = clock
        self.fail_open = fail_open
        self.kind = f"monitored:{inner.kind}"

    # ---- observed path ----

    def query(
        self,
        collection: str,
        vector: list[float],
        top_k: int = 10,
        where: Optional[dict[str, Any]] = None,
    ) -> list[QueryHit]:
        ts = self._clock()
        hits = self.inner.query(collection, vector, top_k=top_k, where=where)
        try:
            event = QueryEvent(
                principal=self._resolve_principal(),
                collection=collection,
                timestamp=ts,
                query_vector=vector,
                result_ids=[h.id for h in hits],
                result_count=len(hits),
                metadata={"top_k": top_k, "filtered": where is not None},
            )
            self.engine.process(event)
        except Exception:  # noqa: BLE001
            if not self.fail_open:
                raise
            logger.exception("monitoring error (fail-open)")
        return hits

    def _resolve_principal(self) -> str:
        p = self._principal
        return p() if callable(p) else p

    # ---- delegated path ----

    def capabilities(self) -> set[str]:
        return self.inner.capabilities()

    def describe(self) -> VectorStore:
        return self.inner.describe()

    def list_collections(self) -> list[Collection]:
        return self.inner.list_collections()

    def iter_chunks(self, collection: str, batch_size: int = 256) -> Iterator[Chunk]:
        return self.inner.iter_chunks(collection, batch_size=batch_size)

    def list_api_keys(self) -> list[ApiKey]:
        return self.inner.list_api_keys()

    def close(self) -> None:
        self.inner.close()
