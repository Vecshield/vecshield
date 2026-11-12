"""Qdrant connector.

Implements read + query + payload writes. Tenants in Qdrant are typically
modeled as a payload field, so the isolation prober works by passing a payload
filter through query(). qdrant-client is imported lazily.

Writes use ``set_payload``, which merges server-side: the keys named are set and
every other key on the point is left alone. That is exactly the merge contract
:meth:`Connector.set_chunk_metadata` promises, so unlike Chroma there is no
read-modify-write race here. The vector is never sent on a write, so nothing in
this module can cause a point to be re-embedded.

A collection can hold one unnamed vector or several named ones, dense, sparse
or multi-vector. Only a dense single vector decodes as an embedding and can be
searched with a float query, so the connector finds that vector's name per
collection and passes it as ``using=``. Requires qdrant-client >= 1.10
(``query_points`` with ``using``).
"""

from __future__ import annotations

import json
from numbers import Real
from typing import Any, Callable, Iterator, Optional, TypeVar

from vecshield_platform.connectors.base import (
    Connector,
    ConnectorError,
    ConnectorUnavailable,
    UnsupportedCapability,
    retry_read,
    translate_error,
)
from vecshield_platform.connectors.redact import redact_credentials
from vecshield.models import Chunk, Collection, QueryHit, VectorStore

# Payload keys we treat as the chunk's raw text, best first.
_TEXT_KEYS = ("content", "text", "document", "chunk", "body", "page_content")

#: qdrant-client exceptions by class name (imported lazily, so names).
#: ``UnexpectedResponse`` carries ``status_code`` and maps by HTTP status in the
#: shared mapper: 401/403 → auth, 404 → not found, 429/5xx → unavailable.
#: ``ResponseHandlingException`` wraps the transport error as ``source`` and is
#: unwrapped in :func:`_translate`.
_ERRORS: dict[str, type[ConnectorError]] = {
    "ResourceExhaustedResponse": ConnectorUnavailable,
    # httpx transport errors (ConnectError, ReadError, WriteError...).
    "NetworkError": ConnectorUnavailable,
    "RemoteProtocolError": ConnectorUnavailable,
}

_T = TypeVar("_T")


class QdrantConnector(Connector):
    kind = "qdrant"

    def __init__(
        self,
        url: Optional[str] = None,
        *,
        host: Optional[str] = None,
        port: int = 6333,
        api_key: Optional[str] = None,
    ):
        try:
            from qdrant_client import QdrantClient
        except ImportError as e:  # pragma: no cover
            raise ImportError(
                "qdrant-client not installed. Run: pip install 'vecshield[qdrant]'"
            ) from e

        if url:
            self._client = QdrantClient(url=url, api_key=api_key)
            # Display/error-message form: a URL can carry userinfo.
            self._endpoint = redact_credentials(url)
        else:
            host = host or "localhost"
            self._client = QdrantClient(host=host, port=port, api_key=api_key)
            self._endpoint = f"http://{host}:{port}"

    def capabilities(self) -> set[str]:
        # metadata_write and redact are both payload writes, which every
        # Qdrant deployment supports. No "api_keys": Qdrant Cloud's key
        # management is a separate control-plane API, not the data plane this
        # client talks to.
        return {"query", "delete", "metadata_write", "redact"}

    def describe(self) -> VectorStore:
        return VectorStore(
            kind=self.kind,
            name=self._endpoint,
            endpoint=self._endpoint,
            collections=self.list_collections(),
        )

    def list_collections(self) -> list[Collection]:
        cols = self._read(lambda: self._client.get_collections()).collections
        out: list[Collection] = []
        for c in cols:
            metadata: dict[str, Any] = {}
            try:
                info = self._read(lambda: self._client.get_collection(c.name))
            except Exception as exc:  # noqa: BLE001 - iter_chunks reports it as an error
                out.append(Collection(name=c.name, count=0, metadata={
                    "count_known": False, "info_error": type(exc).__name__}))
                continue
            layout = _vector_layout(info)
            self._layouts()[c.name] = layout
            metadata["vector_name"] = layout["using"]
            if layout["skipped"]:
                metadata["non_dense_vectors"] = dict(layout["skipped"])
            count = getattr(info, "points_count", None)
            if count is None:
                # Zero would read as "empty" and pass every count cross-check.
                metadata["count_known"] = False
            out.append(Collection(name=c.name, count=int(count or 0),
                                  dimension=layout["dim"], metadata=metadata))
        return out

    # ---- error handling ------------------------------------------------- #

    def _read(self, fn: Callable[[], _T]) -> _T:
        """An idempotent read: errors translated, transient ones retried."""
        return retry_read(_call(fn))

    def _layouts(self) -> dict[str, dict[str, Any]]:
        layouts = getattr(self, "_vector_layouts", None)
        if layouts is None:
            layouts = {}
            self._vector_layouts = layouts
        return layouts

    def _layout(self, collection: str) -> dict[str, Any]:
        layouts = self._layouts()
        if collection not in layouts:
            info = self._read(lambda: self._client.get_collection(collection))
            layouts[collection] = _vector_layout(info)
        return layouts[collection]

    def iter_chunks(self, collection: str, batch_size: int = 256) -> Iterator[Chunk]:
        using = self._layout(collection)["using"]
        offset = None
        while True:
            points, offset = self._read(lambda: self._client.scroll(
                collection_name=collection,
                limit=batch_size,
                offset=offset,
                with_payload=True,
                with_vectors=True,
            ))
            for p in points:
                payload = p.payload or {}
                yield Chunk(
                    id=str(p.id),
                    collection=collection,
                    text=_extract_text(payload),
                    embedding=_extract_vector(p.vector, using),
                    metadata=payload,
                )
            if offset is None or not points:
                break

    def query(
        self,
        collection: str,
        vector: list[float],
        top_k: int = 10,
        where: Optional[dict[str, Any]] = None,
    ) -> list[QueryHit]:
        layout = self._layout(collection)
        if not layout["dense"]:
            raise UnsupportedCapability(
                f"qdrant collection {collection!r} has no dense single vector to "
                "query with a float vector")
        qfilter = _build_filter(where)
        results = self._read(lambda: self._client.query_points(
            collection_name=collection,
            query=vector,
            using=layout["using"],
            limit=top_k,
            with_payload=True,
            query_filter=qfilter,
        )).points
        hits: list[QueryHit] = []
        for r in results:
            payload = r.payload or {}
            hits.append(
                QueryHit(
                    id=str(r.id),
                    score=float(r.score),  # Qdrant returns similarity, higher = closer
                    text=_extract_text(payload),
                    metadata=payload,
                )
            )
        return hits

    def delete_chunks(self, collection: str, ids: list[str]) -> int:
        from qdrant_client.models import PointIdsList
        # A write: errors are translated but never retried.
        _call(lambda: self._client.delete(
            collection_name=collection,
            points_selector=PointIdsList(points=[_point_id(i) for i in ids]),
        ))()
        # Qdrant's delete returns only an operation id and status, never how
        # many points existed, so this is the number of ids *requested*.
        # Erasure verification re-reads the ids to establish what is gone.
        return len(ids)

    def get_chunks(self, collection: str, ids: list[str]) -> list[Chunk]:
        """Fetch points by id directly.

        The base class falls back to walking the whole collection. Qdrant can
        address points, and erasure verification re-reads deleted ids on every
        run, so the scan-the-world default would make verification cost a full
        pass per check.
        """
        if not ids:
            return []
        points = self._read(lambda: self._client.retrieve(
            collection_name=collection,
            ids=[_point_id(i) for i in ids],
            with_payload=True,
            with_vectors=True,
        ))
        using = self._layouts().get(collection, {}).get("using")
        out: list[Chunk] = []
        for p in points:
            payload = p.payload or {}
            out.append(Chunk(
                id=str(p.id),
                collection=collection,
                text=_extract_text(payload),
                embedding=_extract_vector(p.vector, using),
                metadata=payload,
            ))
        return out

    def set_chunk_metadata(self, collection: str,
                           updates: dict[str, dict[str, Any]]) -> int:
        """Merge fields into each named point's payload.

        Ids absent from the collection are skipped and not counted: a caller
        must not be told it marked a point that was not there. Points sharing
        the same update are written in one call, because set_payload takes a
        list of point ids.
        """
        if not updates:
            return 0
        wanted = {str(cid): _point_id(cid) for cid in updates}
        existing = self._read(lambda: self._client.retrieve(
            collection_name=collection,
            ids=list(wanted.values()),
            with_payload=False,
            with_vectors=False,
        ))
        present = {str(p.id) for p in existing}
        if not present:
            return 0

        batches: dict[str, list[Any]] = {}
        payloads: dict[str, dict[str, Any]] = {}
        changed = 0
        for cid, fields in updates.items():
            key = str(cid)
            if key not in present:
                continue
            sig = json.dumps(fields, sort_keys=True, default=str)
            batches.setdefault(sig, []).append(wanted[key])
            payloads.setdefault(sig, fields)
            changed += 1

        for sig, points in batches.items():
            _call(lambda: self._client.set_payload(
                collection_name=collection,
                payload=payloads[sig],
                points=points,
            ))()
        return changed

    def replace_chunk_text(self, collection: str, chunk_id: str, text: str,
                           metadata_updates: Optional[dict[str, Any]] = None) -> bool:
        """Replace the payload key that holds this point's text.

        The vector is deliberately left as it is — this product does not have
        the model the collection was embedded with. The old vector still
        encodes the old text, so the caller marks the point for whatever
        pipeline owns that model.
        """
        pid = _point_id(chunk_id)
        found = self._read(lambda: self._client.retrieve(
            collection_name=collection,
            ids=[pid],
            with_payload=True,
            with_vectors=False,
        ))
        if not found:
            return False
        key = _text_key(found[0].payload or {})
        if key is None:
            raise UnsupportedCapability(
                f"{chunk_id} has no recognised text field in its payload, so there "
                "is nothing to replace; writing one would invent a field the "
                "collection does not use"
            )
        update: dict[str, Any] = {key: text, **(metadata_updates or {})}
        _call(lambda: self._client.set_payload(
            collection_name=collection, payload=update, points=[pid]
        ))()
        return True

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:  # pragma: no cover
            pass


def _translate(exc: BaseException) -> BaseException:
    """Map a qdrant-client error onto the connector error taxonomy.

    ``ResponseHandlingException`` wraps whatever the HTTP transport raised
    (a refused connection, a timeout) as ``source``; that source decides the
    mapping. A wrapped response-validation error stays as it is.
    """
    source = getattr(exc, "source", None)
    if (isinstance(source, BaseException)
            and any(c.__name__ == "ResponseHandlingException" for c in type(exc).__mro__)):
        translated = translate_error(source, kind=QdrantConnector.kind, extra=_ERRORS)
        if translated is not source:
            return translated
    return translate_error(exc, kind=QdrantConnector.kind, extra=_ERRORS)


def _call(fn: Callable[[], _T]) -> Callable[[], _T]:
    """``fn`` with its SDK errors translated, for use inside retry_read."""
    def call() -> _T:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - translated or re-raised as is
            translated = _translate(exc)
            if translated is exc:
                raise
            raise translated from exc
    return call


def _vector_layout(info: Any) -> dict[str, Any]:
    """Which vector a float query and an embedding read should use.

    ``using`` is the dense vector's name, or None for the unnamed default
    vector. ``dense`` is False when the collection has no dense single vector
    at all (sparse-only, or only multi-vectors). ``skipped`` names the vectors
    that are not decoded as embeddings, with their kind.
    """
    layout: dict[str, Any] = {"using": None, "dense": False, "dim": None, "skipped": {}}
    try:
        params = info.config.params
    except AttributeError:
        return layout
    vectors = getattr(params, "vectors", None)
    if isinstance(vectors, dict):
        for name, vp in vectors.items():
            if getattr(vp, "multivector_config", None) is not None:
                layout["skipped"][name] = "multivector"
            elif not layout["dense"]:
                layout.update(using=name, dense=True, dim=getattr(vp, "size", None))
    elif vectors is not None:
        if getattr(vectors, "multivector_config", None) is not None:
            layout["skipped"][""] = "multivector"
        else:
            layout.update(dense=True, dim=getattr(vectors, "size", None))
    for name in (getattr(params, "sparse_vectors", None) or {}):
        layout["skipped"][name] = "sparse"
    return layout


def _text_key(payload: dict) -> Optional[str]:
    """The payload key holding this point's raw text, by preference order."""
    for k in _TEXT_KEYS:
        if isinstance(payload.get(k), str):
            return k
    return None


def _extract_text(payload: dict) -> Optional[str]:
    key = _text_key(payload)
    return payload[key] if key else None


def _point_id(raw: Any) -> Any:
    """Restore a Qdrant point id from the string form iter_chunks yields.

    Qdrant ids are unsigned integers or UUIDs, and the read path stringifies
    them. Handing "42" back to the SDK where it expects 42 is rejected, so a
    write that skipped this would fail on every integer-keyed collection.
    UUID strings are accepted by the SDK as they are.
    """
    if isinstance(raw, int):
        return raw
    s = str(raw)
    return int(s) if s.isdigit() else s


def _dense(value: Any) -> Optional[list[float]]:
    """A flat list of numbers as plain floats; anything else is not dense."""
    if value is None or isinstance(value, (str, bytes, dict)):
        return None
    try:
        items = list(value)
    except TypeError:  # a SparseVector, or another non-sequence
        return None
    if not items or not all(isinstance(x, Real) and not isinstance(x, bool) for x in items):
        return None  # a multivector is a list of lists
    return [float(x) for x in items]


def _extract_vector(vector: Any, using: Optional[str] = None) -> Optional[list[float]]:
    """The dense embedding of a point, or None.

    Named vectors: the collection's dense vector (``using``) when known, else
    the first value that is a flat list of numbers. Sparse vectors and
    multi-vectors are skipped, never decoded as floats.
    """
    if vector is None:
        return None
    if isinstance(vector, dict):
        if using is not None and using in vector:
            return _dense(vector[using])
        for value in vector.values():
            dense = _dense(value)
            if dense is not None:
                return dense
        return None
    return _dense(vector)


def _build_filter(where: Optional[dict[str, Any]]):
    if not where:
        return None
    from qdrant_client import models

    return models.Filter(must=[_condition(models, k, v) for k, v in where.items()])


def _condition(models: Any, key: str, value: Any):
    """One equality condition on a payload field.

    MatchValue takes only bool, int or str, so a float (a tenant id stored as
    1.5, say) is matched as the closed range [v, v] — the numeric equality
    Qdrant applies to float payloads — instead of crashing the query.
    """
    if isinstance(value, float):
        return models.FieldCondition(key=key, range=models.Range(gte=value, lte=value))
    return models.FieldCondition(key=key, match=models.MatchValue(value=value))
