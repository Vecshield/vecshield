"""Pinecone connector.

Pinecone is cloud-only. A VecShield collection maps to an (index, namespace)
pair, named "index" (default namespace) or "index/namespace". Pinecone stores no
raw text field — text, if present, lives in vector metadata (for an index with
integrated embedding, in the field its ``field_map`` names). pinecone imported
lazily; no network at construction beyond client init.
"""

from __future__ import annotations

import hashlib
from typing import Any, Iterator, Optional

from vecshield_platform.connectors.base import (
    AtRestObservation,
    Connector,
    ConnectorAuthError,
    ConnectorNotFound,
    ConnectorTimeout,
    ConnectorUnavailable,
    ErrorRegistry,
    UnsupportedCapability,
    mapped_call,
    mapped_errors,
    mask_reference,
    retry_read,
)
from vecshield_platform.store_facts import pinecone as _facts
from vecshield_platform.store_facts._managed_util import get as _get
from vecshield.models import Chunk, Collection, QueryHit, VectorStore

_TEXT_KEYS = ("content", "text", "document", "chunk", "body", "page_content")
_MISSING = object()  # an SDK/API too old to have the field at all
_PINECONE_DEFAULT = {
    "text": "Pinecone documents AES-256 encryption of stored data.",
    "source_url": "https://docs.pinecone.io/guides/production/security-overview",
}

#: Pinecone SDK exceptions (v10 names and the legacy ``*Exception`` aliases),
#: by class name. ApiError subclasses also carry ``status_code``.
_ERRORS: ErrorRegistry = {
    "UnauthorizedError": ConnectorAuthError,
    "UnauthorizedException": ConnectorAuthError,
    "ForbiddenError": ConnectorAuthError,
    "ForbiddenException": ConnectorAuthError,
    "NotFoundError": ConnectorNotFound,
    "NotFoundException": ConnectorNotFound,
    "RateLimitError": ConnectorUnavailable,
    "RateLimitException": ConnectorUnavailable,
    "ServiceError": ConnectorUnavailable,
    "ServiceException": ConnectorUnavailable,
    "PineconeTimeoutError": ConnectorTimeout,
    "PineconeConnectionError": ConnectorUnavailable,
    "PineconeProtocolError": ConnectorUnavailable,
}

#: Pinecone deletes at most 1,000 ids per request.
_DELETE_BATCH = 1000


def _split(name: str) -> tuple[str, str]:
    if "/" in name:
        idx, ns = name.split("/", 1)
        return idx, ns
    return name, ""


def _is_dense(field: Any) -> bool:
    """A dense vector field, as a 2026-07 dict or an SDK v10 msgspec struct.

    SDK v10 fields are tagged structs: the ``type`` tag is not an attribute,
    so the struct's tag (``dense_vector``) or class name identifies them.
    """
    if isinstance(field, dict):
        return field.get("type") == "dense_vector"
    config = getattr(type(field), "__struct_config__", None)
    return getattr(config, "tag", None) == "dense_vector" or \
        type(field).__name__ == "DenseVectorField"


def _dimension_of(desc: Any) -> Optional[int]:
    """Index dimension from a pre-2026-07 model, or from the 2026-07 schema.

    API 2026-07 moved dimension from the index into ``schema.fields``. SDK v10
    keeps a deprecated ``dimension`` property that raises AttributeError
    unless the schema has exactly one dense field; getattr's default absorbs
    that. With several dense fields there is no single dimension, and None
    is returned rather than a guess.
    """
    top = desc.get("dimension") if isinstance(desc, dict) else getattr(desc, "dimension", None)
    if top is not None:
        return int(top)
    schema = desc.get("schema") if isinstance(desc, dict) else getattr(desc, "schema", None)
    fields = (schema.get("fields") if isinstance(schema, dict)
              else getattr(schema, "fields", None)) or {}
    dims = []
    for field in (fields.values() if isinstance(fields, dict) else []):
        if _is_dense(field):
            dim = field.get("dimension") if isinstance(field, dict) \
                else getattr(field, "dimension", None)
            if dim is not None:
                dims.append(int(dim))
    return dims[0] if len(dims) == 1 else None


def _text_of(meta: dict, preferred: Optional[str] = None) -> Optional[str]:
    if preferred:
        v = (meta or {}).get(preferred)
        if isinstance(v, str):
            return v
    for k in _TEXT_KEYS:
        v = (meta or {}).get(k)
        if isinstance(v, str):
            return v
    return None


def _index_info(desc: Any) -> dict[str, Any]:
    """What the connector needs from one index description (list or describe).

    ``ready`` is None when the description has no status (an old API shape);
    only an explicit ``False`` marks the index as not ready.
    """
    ready = _get(desc, "status", "ready")
    return {"index_type": _facts._deployment(desc)["index_type"],
            "ready": ready if isinstance(ready, bool) else None,
            "state": _get(desc, "status", "state"),
            "text_field": _text_field(desc)}


def _text_field(desc: Any) -> Optional[str]:
    """The metadata field an integrated-embedding index keeps its text in.

    ``embed.field_map["text"]`` up to API 2025-10 (and SDK v10's deprecated
    ``embed`` view); the ``semantic_text`` field's name in a 2026-07 schema.
    """
    field_map = _get(desc, "embed", "field_map")
    if isinstance(field_map, dict) and isinstance(field_map.get("text"), str):
        return field_map["text"]
    for fname, field in _facts._fields(desc):
        if _facts._field_type(field) == "semantic_text":
            return str(fname)
    return None


def _page_ids(page: Any) -> list[str]:
    """The ids on one list page: a list of ids (old SDKs) or a ListResponse."""
    items = page if isinstance(page, (list, tuple)) else (_get(page, "vectors") or [])
    ids = []
    for item in items:
        vid = item if isinstance(item, str) else _get(item, "id")
        if vid is not None:
            ids.append(str(vid))
    return ids


def _where_filter(where: Optional[dict[str, Any]]) -> Optional[dict[str, Any]]:
    if not where:
        return None
    out: dict[str, Any] = {}
    for key, value in where.items():
        if isinstance(value, dict):
            out[key] = value  # already an operator expression
        elif isinstance(value, (list, tuple)):
            out[key] = {"$in": list(value)}
        else:
            out[key] = {"$eq": value}
    return out


class PineconeConnector(Connector):
    kind = "pinecone"
    #: Pinecone operation limits: "Max top_k value | 10,000"
    #: (docs.pinecone.io/reference/api/database-limits/operation-limits).
    max_top_k = 10000

    def __init__(self, *, api_key: Optional[str] = None, **_ignored):
        try:
            from pinecone import Pinecone
        except ImportError as e:  # pragma: no cover
            raise ImportError("pinecone not installed. pip install 'vecshield[pinecone]'") from e
        if not api_key:
            raise ValueError("pinecone requires api_key")
        self._pc = Pinecone(api_key=api_key)
        # A one-way fingerprint tells two projects apart in history without
        # carrying any characters of the key itself.
        fingerprint = hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:12]
        self._endpoint = f"pinecone://key-{fingerprint}"
        self._idx_cache: dict[str, Any] = {}
        self._info_cache: dict[str, dict[str, Any]] = {}

    def capabilities(self) -> set[str]:
        return {"query", "delete", "at_rest_introspection"}

    def at_rest_encryption_state(self, collection: Optional[str] = None) -> AtRestObservation:
        """Customer-managed key on the index, from ``cmek_id`` (API 2026-07+).

        Pinecone's default encryption uses keys Pinecone manages and is not
        reported, so an index without a CMEK is not observable, never disabled.
        A namespace shares its index's storage and inherits its answer.
        """
        source = "index.cmek_id"
        if collection is None:
            return AtRestObservation(
                state="not_observable", scope="store", source=source, per_collection=True,
                reason="customer-managed keys are set per index; each index is "
                       "reported separately")
        iname, _ns = _split(collection)
        try:
            model = self._pc.describe_index(iname)
        except Exception as exc:  # noqa: BLE001
            return AtRestObservation(
                state="error", scope="collection", collection=collection, source=source,
                reason=f"the index could not be described ({type(exc).__name__})")
        if isinstance(model, dict):
            cmek = model.get("cmek_id", _MISSING)
        else:
            cmek = getattr(model, "cmek_id", _MISSING)
        if cmek is _MISSING:
            return AtRestObservation(
                state="not_observable", scope="collection", collection=collection,
                source=source,
                reason="This Pinecone SDK or API version doesn't report encryption "
                       "keys. API version 2026-07 or later is needed to see "
                       "customer-managed keys.")
        if not cmek:
            return AtRestObservation(
                state="not_observable", scope="collection", collection=collection,
                source=source,
                reason="This Pinecone index has no customer-managed key. Pinecone's "
                       "default encryption is not reported by its API.",
                documented_default=dict(_PINECONE_DEFAULT))
        return AtRestObservation(
            state="enabled", scope="collection", collection=collection, source=source,
            mechanism="customer-managed key (Pinecone CMEK)",
            key_reference=mask_reference(cmek),
            evidence={"index": iname},
            reason="the index is encrypted with a customer-managed key")

    # ---- plumbing ---------------------------------------------------------- #

    def _read(self, fn: Any) -> Any:
        """An idempotent read, error-mapped and retried on transient failure."""
        return retry_read(mapped_call(fn, kind=self.kind, extra=_ERRORS))

    def _index(self, name: str):
        cache = getattr(self, "_idx_cache", None)
        if cache is None:
            cache = self._idx_cache = {}
        if name not in cache:
            cache[name] = self._read(lambda: self._pc.Index(name))
        return cache[name]

    def _infos(self) -> dict[str, dict[str, Any]]:
        cache = getattr(self, "_info_cache", None)
        if cache is None:
            cache = self._info_cache = {}
        return cache

    def _info(self, name: str) -> dict[str, Any]:
        """Deployment, readiness and text field of an index; {} if unreadable."""
        cache = self._infos()
        if name not in cache:
            try:
                cache[name] = _index_info(self._read(lambda: self._pc.describe_index(name)))
            except Exception:  # noqa: BLE001 - unknown; the read itself then decides
                return {}
        return cache[name]

    # ---- inventory --------------------------------------------------------- #

    def describe(self) -> VectorStore:
        return VectorStore(kind=self.kind, name=self._endpoint, endpoint=self._endpoint,
                           collections=self.list_collections())

    def list_collections(self) -> list[Collection]:
        out = []
        for desc in self._read(lambda: _facts._indexes(self)):
            iname = desc["name"] if isinstance(desc, dict) else desc.name
            dim = _dimension_of(desc)
            info = _index_info(desc)
            self._infos()[iname] = info
            base: dict[str, Any] = {"index_type": info["index_type"]}
            if info["text_field"]:
                base["text_field"] = info["text_field"]
            if info["ready"] is False:
                state = info["state"]
                self._record_read_error(iname, operation="list_indexes",
                                        error_type="IndexNotReady",
                                        reason=f"the index is not ready (state {state}); "
                                               "it was not read")
                out.append(Collection(name=iname, count=0, dimension=dim,
                                      metadata={**base, "count_known": False,
                                                "index_state": state}))
                continue
            try:
                idx = self._index(iname)
                stats = self._read(idx.describe_index_stats)
            except Exception as exc:  # noqa: BLE001 - one index never hides the rest
                self._record_read_error(iname, operation="describe_index_stats",
                                        error_type=type(exc).__name__,
                                        reason="the index statistics could not be read")
                out.append(Collection(name=iname, count=0, dimension=dim,
                                      metadata={**base, "count_known": False}))
                continue
            namespaces = (stats.get("namespaces") if isinstance(stats, dict)
                          else getattr(stats, "namespaces", {})) or {}
            if not namespaces:
                out.append(Collection(name=iname, count=0, dimension=dim, metadata=dict(base)))
            for ns, summary in namespaces.items():
                cnt = (summary.get("vector_count", 0) if isinstance(summary, dict)
                       else getattr(summary, "vector_count", 0))
                cname = iname if ns in ("", None) else f"{iname}/{ns}"
                out.append(Collection(name=cname, count=int(cnt or 0), dimension=dim,
                                      metadata=dict(base)))
        return out

    # ---- content ----------------------------------------------------------- #

    def _id_pages(self, idx: Any, ns: str) -> Iterator[list[str]]:
        """Pages of vector ids. Each page request is retried on its own token."""
        lister = getattr(idx, "list_paginated", None)
        if callable(lister):
            token = None
            while True:
                kw: dict[str, Any] = {"namespace": ns}
                if token:
                    kw["pagination_token"] = token
                page = self._read(lambda: lister(**kw))
                ids = _page_ids(page)
                if ids:
                    yield ids
                token = _get(page, "pagination", "next")
                if not token:
                    return
        with mapped_errors(self.kind, _ERRORS):
            for page in idx.list(namespace=ns):
                ids = _page_ids(page)
                if ids:
                    yield ids

    def iter_chunks(self, collection: str, batch_size: int = 100) -> Iterator[Chunk]:
        iname, ns = _split(collection)
        info = self._info(iname)
        if info.get("index_type") == "pod":
            raise UnsupportedCapability(
                f"pinecone: {iname!r} is a pod-based index; Pinecone lists vector ids "
                "only on serverless indexes, so its content cannot be enumerated")
        idx = self._index(iname)
        text_field = info.get("text_field")
        for ids in self._id_pages(idx, ns):
            fetched = self._read(lambda: idx.fetch(ids=list(ids), namespace=ns))
            vectors = (fetched.get("vectors") if isinstance(fetched, dict)
                       else fetched.vectors) or {}
            missing = [i for i in ids if i not in vectors]
            if missing:
                self._record_read_error(collection, item_id=missing[0],
                                        missing=len(missing), operation="fetch",
                                        error_type="NotReturned",
                                        reason="listed ids were not returned by fetch")
            for vid, rec in vectors.items():
                meta = rec.get("metadata") if isinstance(rec, dict) else getattr(rec, "metadata", {})
                vals = rec.get("values") if isinstance(rec, dict) else getattr(rec, "values", None)
                yield Chunk(id=str(vid), collection=collection,
                            text=_text_of(meta or {}, text_field),
                            embedding=list(vals) if vals else None, metadata=dict(meta or {}))

    def delete_chunks(self, collection: str, ids: list[str]) -> int:
        iname, ns = _split(collection)
        idx = self._index(iname)
        for start in range(0, len(ids), _DELETE_BATCH):
            batch = list(ids[start:start + _DELETE_BATCH])
            with mapped_errors(self.kind, _ERRORS):
                idx.delete(ids=batch, namespace=ns)
        # Pinecone's delete returns an empty body, so this is the number of
        # ids *requested*; erasure verification re-reads what is gone.
        return len(ids)

    def query(self, collection: str, vector: list[float], top_k: int = 10,
              where: Optional[dict[str, Any]] = None) -> list[QueryHit]:
        iname, ns = _split(collection)
        idx = self._index(iname)
        flt = _where_filter(where)
        res = self._read(lambda: idx.query(vector=vector, top_k=top_k, namespace=ns,
                                           include_metadata=True, filter=flt))
        text_field = self._infos().get(iname, {}).get("text_field")
        matches = res.get("matches") if isinstance(res, dict) else res.matches
        hits = []
        for m in (matches or []):
            mid = m.get("id") if isinstance(m, dict) else m.id
            score = m.get("score") if isinstance(m, dict) else m.score
            meta = m.get("metadata") if isinstance(m, dict) else getattr(m, "metadata", {})
            hits.append(QueryHit(id=str(mid), score=float(score or 0.0),
                                 text=_text_of(meta or {}, text_field),
                                 metadata=dict(meta or {})))
        return hits
