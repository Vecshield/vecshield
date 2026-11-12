"""Milvus connector.

Uses pymilvus MilvusClient. Works against a remote Milvus (uri=http://host:19530)
or local Milvus Lite (uri=./file.db). Schema is introspected to find the vector
field (+ its dim), primary key, and a text field. pymilvus imported lazily.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Iterator, Optional, TypeVar

from vecshield_platform.connectors.base import (
    AtRestObservation,
    Connector,
    ConnectorAuthError,
    ConnectorError,
    ConnectorNotFound,
    ConnectorUnavailable,
    UnsupportedCapability,
    mask_reference,
    retry_read,
    translate_error,
)
from vecshield_platform.connectors.redact import redact_credentials
from vecshield.models import Chunk, Collection, QueryHit, VectorStore

_TEXT_KEYS = ("content", "text", "document", "chunk", "body", "passage", "page_content")
#: The first release whose properties can carry native encryption zones
#: (cipher.ezID / cipher.key). The keys lived in internal/util/hookutil/cipher.go
#: in 2.6.0-2.6.9 and moved to pkg/common in 2.6.10; the property names did not
#: change. Needs a live spike before leaving draft.
NATIVE_ENCRYPTION_SINCE = (2, 6, 0)
_EZ_ID, _EZ_KEY = "cipher.ezID", "cipher.key"
_DISK_CACHE_NOTE = ("cipherPlugin.enableDiskEncryption (the local cache) is a server "
                    "setting and is not visible through the API")
#: pymilvus DataType numbers for vector fields (pymilvus/client/types.py).
_VECTOR_TYPE_NUMBERS = {100: "BINARY_VECTOR", 101: "FLOAT_VECTOR", 102: "FLOAT16_VECTOR",
                        103: "BFLOAT16_VECTOR", 104: "SPARSE_FLOAT_VECTOR",
                        105: "INT8_VECTOR"}
#: The only vector type pymilvus returns as a list of floats. FLOAT16 and
#: BFLOAT16 come back as raw bytes, BINARY as packed bits and SPARSE as a dict:
#: none of them decodes as an embedding by iterating, and a float query vector
#: cannot search them.
_FLOAT_VECTOR = "FLOAT_VECTOR"
#: pymilvus LoadState names (pymilvus/client/types.py): NotExist, NotLoad,
#: Loading, Loaded.
_LOADED = "Loaded"
#: Rows per query_iterator page; pymilvus caps a page at MAX_BATCH_SIZE.
_PAGE = 1000
_MAX_PAGE = 16384  # pymilvus client/constants.py MAX_BATCH_SIZE
_T = TypeVar("_T")

#: pymilvus exceptions by class name. pymilvus is imported lazily (and stubbed
#: in tests), so names rather than classes.
_ERRORS: dict[str, type[ConnectorError]] = {
    "MilvusUnavailableException": ConnectorUnavailable,
    "ConnectError": ConnectorUnavailable,
    "CollectionNotExistException": ConnectorNotFound,
}
#: Legacy ``common_pb2.ErrorCode`` values carried on ``compatible_code``
#: (pymilvus/grpc_gen/common_pb2): ConnectFailed=2, PermissionDenied=3,
#: CollectionNotExists=4, CollectionNameNotFound=28, NotShardLeader=45,
#: NoReplicaAvailable=46, ForceDeny=48, RateLimit=49, NotReadyServe=56,
#: NotReadyCoordActivating=57.
_COMPATIBLE_CODES: dict[int, type[ConnectorError]] = {
    2: ConnectorUnavailable, 3: ConnectorAuthError, 4: ConnectorNotFound,
    28: ConnectorNotFound, 45: ConnectorUnavailable, 46: ConnectorUnavailable,
    48: ConnectorAuthError, 49: ConnectorUnavailable, 56: ConnectorUnavailable,
    57: ConnectorUnavailable,
}
#: ``pymilvus.exceptions.ErrorCode`` values on ``code``: RATE_LIMIT=8 and
#: COLLECTION_NOT_FOUND=100. Other Milvus codes are not HTTP statuses and are
#: never read as one.
_MILVUS_CODES: dict[int, type[ConnectorError]] = {
    8: ConnectorUnavailable, 100: ConnectorNotFound,
}


class MilvusConnector(Connector):
    kind = "milvus"
    #: Milvus search limits: "topk (number of the most similar result to
    #: return): 16,384" (milvus.io/docs/limitations.md).
    max_top_k = 16384

    def __init__(
        self,
        uri: Optional[str] = None,
        *,
        host: Optional[str] = None,
        port: int = 19530,
        token: Optional[str] = None,
        db_name: str = "default",
    ):
        try:
            from pymilvus import MilvusClient
        except ImportError as e:  # pragma: no cover
            raise ImportError("pymilvus not installed. pip install 'vecshield[milvus]'") from e
        if not uri:
            uri = f"http://{host or 'localhost'}:{port}"
        self._uri = uri
        # The display name is persisted on findings; a URI can carry userinfo.
        self._endpoint = redact_credentials(uri)
        self._db_name = db_name
        self._client = MilvusClient(uri=uri, token=token or "", db_name=db_name)
        self._layout: dict[str, dict] = {}  # name -> {pk, vec, text, dim}

    def capabilities(self) -> set[str]:
        return {"query", "delete", "at_rest_introspection"}

    def at_rest_encryption_state(self, collection: Optional[str] = None) -> AtRestObservation:
        """Native encryption zones (Milvus 2.6+): only "enabled" can be proven.

        An encryption zone shows as ``cipher.ezID`` and ``cipher.key`` on the
        database and ``cipher.ezID`` on its collections. Their absence says
        nothing about object-storage, disk or message-queue encryption, which
        happen outside Milvus — so it is not observable, never disabled.
        """
        source = "database.properties.cipher"
        db_name = getattr(self, "_db_name", "default")
        version, error = self._server_version()
        if error:
            return AtRestObservation(
                state="not_observable" if error == "permission" else "error",
                scope="store", collection=collection, source=source,
                reason=("This user cannot read the Milvus server version."
                        if error == "permission" else
                        f"The Milvus server version could not be read ({error})."))
        if version is None or version < NATIVE_ENCRYPTION_SINCE:
            return AtRestObservation(
                state="not_observable", scope="store", collection=collection,
                source=source,
                evidence={"server_version": _version_text(version)},
                reason="This Milvus version predates native encryption zones. Any "
                       "encryption is in object storage or on disk, outside what the "
                       "Milvus API reports.")
        evidence = {"server_version": _version_text(version), "database": db_name,
                    "not_visible": _DISK_CACHE_NOTE}
        no_zone = ("Milvus shows no native encryption for this database. Encryption "
                   "of object storage, disks or the message queue happens outside "
                   "Milvus and cannot be seen through its API.")
        if collection is None:
            try:
                props = _properties(self._client.describe_database(db_name))
            except Exception as exc:  # noqa: BLE001
                return self._denied_or_error(exc, None, source, evidence)
            if props.get(_EZ_ID) and props.get(_EZ_KEY):
                return AtRestObservation(
                    state="enabled", scope="store", source=source,
                    mechanism="Milvus native encryption zone",
                    key_reference=mask_reference(props.get(_EZ_KEY)),
                    evidence={**evidence, "encryption_zone": str(props.get(_EZ_ID))},
                    reason=f"database '{db_name}' has a native encryption zone")
            return AtRestObservation(
                state="not_observable", scope="store", source=source,
                per_collection=True, evidence=evidence, reason=no_zone)
        try:
            props = _properties(self._client.describe_collection(collection))
        except Exception as exc:  # noqa: BLE001
            return self._denied_or_error(exc, collection, source, evidence)
        zone = props.get(_EZ_ID)
        if zone:
            return AtRestObservation(
                state="enabled", scope="collection", collection=collection,
                source="collection.properties.cipher.ezID",
                mechanism="Milvus native encryption zone",
                evidence={**evidence, "encryption_zone": str(zone)},
                reason="the collection belongs to a native encryption zone")
        return AtRestObservation(
            state="not_observable", scope="collection", collection=collection,
            source=source, evidence=evidence, reason=no_zone)

    def _server_version(self) -> tuple[Optional[tuple[int, ...]], Optional[str]]:
        try:
            text = str(self._client.get_server_version())
        except Exception as exc:  # noqa: BLE001
            return None, "permission" if _is_denied(exc) else type(exc).__name__
        match = re.search(r"(\d+)\.(\d+)\.(\d+)", text)
        return (tuple(int(g) for g in match.groups()) if match else None), None

    @staticmethod
    def _denied_or_error(exc: BaseException, collection: Optional[str], source: str,
                         evidence: dict) -> AtRestObservation:
        scope = "collection" if collection else "store"
        if _is_denied(exc):
            return AtRestObservation(
                state="not_observable", scope=scope, collection=collection, source=source,
                evidence=evidence,
                reason="This user is not permitted to describe the database or "
                       "collection, so its encryption properties cannot be read.")
        return AtRestObservation(
            state="error", scope=scope, collection=collection, source=source,
            evidence=evidence,
            reason=f"The encryption properties could not be read ({type(exc).__name__}).")

    def describe(self) -> VectorStore:
        endpoint = getattr(self, "_endpoint", None) or redact_credentials(self._uri)
        return VectorStore(kind=self.kind, name=endpoint, endpoint=endpoint,
                           collections=self.list_collections())

    def list_collections(self) -> list[Collection]:
        out = []
        for name in _read(lambda: self._client.list_collections()):
            metadata: dict[str, Any] = {}
            dim = None
            try:
                lay = self._layout_of(name)
            except Exception as exc:  # noqa: BLE001 - iter_chunks reports it as an error
                metadata["schema_readable"] = False
                metadata["schema_error"] = type(_translate(exc)).__name__
            else:
                dim = lay["dim"]
                metadata["vector_field"] = lay["vec"]
                if lay["non_float_vectors"]:
                    metadata["non_float_vector_fields"] = dict(lay["non_float_vectors"])
            try:
                stats = _read(lambda: self._client.get_collection_stats(name))
                count = int(stats.get("row_count", 0))
            except Exception:  # noqa: BLE001
                # Zero would read as "empty" and pass every count cross-check.
                count = 0
                metadata["count_known"] = False
            state = self._load_state(name)
            if state is not None:
                metadata["load_state"] = state
            out.append(Collection(name=name, count=count, dimension=dim,
                                  metadata=metadata))
        self._record_unscanned_databases()
        return out

    def _record_unscanned_databases(self) -> None:
        """Record databases this connection does not scan, as a coverage gap.

        A MilvusClient is bound to one database (``db_name``) and lists only
        its collections. Other databases are recorded store-wide, so the scan
        is not read as covering the whole server.
        """
        db_name = getattr(self, "_db_name", "default")
        try:
            names = [str(d) for d in (_read(lambda: self._client.list_databases()) or [])]
        except Exception as exc:  # noqa: BLE001
            self._record_read_error(
                None, operation="list_databases",
                error_type=type(_translate(exc)).__name__,
                reason=f"Databases other than '{db_name}' could not be listed, so "
                       "whether any were left unscanned is unknown.")
            return
        others = sorted(n for n in names if n != db_name)
        if others:
            self._record_read_error(
                None, operation="list_databases", error_type="DatabaseNotScanned",
                databases_not_scanned=others,
                reason=f"Only database '{db_name}' was scanned; "
                       f"{len(others)} other database(s) were not.")

    def _load_state(self, collection: str) -> Optional[str]:
        """The collection's LoadState name, or None when it cannot be read."""
        try:
            res = _read(lambda: self._client.get_load_state(collection))
        except Exception:  # noqa: BLE001
            return None
        state = res.get("state") if isinstance(res, dict) else res
        if state is None:
            return None
        name = getattr(state, "name", None)
        return name if isinstance(name, str) else str(state)

    def iter_chunks(self, collection: str, batch_size: int = 256) -> Iterator[Chunk]:
        """Every row, read through a primary-key cursor.

        Offset paging stops at Milvus's offset + limit cap of 16,384; the query
        iterator has no such cap. No filter is set, so every primary key is
        read, negative ones included. A collection that is not loaded is
        reported, not loaded: loading changes the server's memory use and is
        the owner's decision.
        """
        lay = self._layout_of(collection)
        pk, text, vec = lay["pk"], lay["text"], lay["vec"]
        state = self._load_state(collection)
        if state is not None and state != _LOADED:
            self._record_read_error(
                collection, operation="iter_chunks", error_type="CollectionNotLoaded",
                load_state=state,
                reason="The collection is not loaded, so its rows cannot be queried. "
                       "VecShield does not load collections; load it and re-run.")
            return
        vector_fields = set(lay["vector_fields"])
        page = max(1, min(int(batch_size or _PAGE), _MAX_PAGE))
        iterator = _read(lambda: self._client.query_iterator(
            collection_name=collection, batch_size=page, filter="",
            output_fields=["*"], consistency_level="Strong"))
        try:
            while True:
                rows = _read(iterator.next)
                if not rows:
                    break
                for r in rows:
                    yield Chunk(
                        id=str(r.get(pk)),
                        collection=collection,
                        text=str(r[text]) if text and r.get(text) is not None else None,
                        embedding=_as_floats(r.get(vec)) if vec else None,
                        metadata={k: v for k, v in r.items()
                                  if k not in (pk, text) and k not in vector_fields},
                    )
        finally:
            try:
                iterator.close()
            except Exception:  # noqa: BLE001 - cleanup only
                pass

    def query(self, collection: str, vector: list[float], top_k: int = 10,
              where: Optional[dict[str, Any]] = None) -> list[QueryHit]:
        lay = self._layout_of(collection)
        if not lay["vec"]:
            raise UnsupportedCapability(
                f"milvus collection {collection!r} has no FLOAT_VECTOR field to query")
        state = self._load_state(collection)
        if state is not None and state != _LOADED:
            raise UnsupportedCapability(
                f"milvus collection {collection!r} is not loaded ({state}); "
                "VecShield does not load collections")
        vector_fields = set(lay["vector_fields"])
        res = _read(lambda: self._client.search(
            collection_name=collection, data=[vector], anns_field=lay["vec"],
            limit=top_k, output_fields=["*"], filter=_filter(where)))
        hits = []
        for r in (res[0] if res else []):
            ent = r.get("entity", {}) or {}
            hits.append(QueryHit(
                id=str(r.get("id")),
                score=float(r.get("distance", 0.0)),
                text=str(ent[lay["text"]]) if lay["text"] and ent.get(lay["text"]) is not None else None,
                metadata={k: v for k, v in ent.items() if k not in vector_fields}))
        return hits

    def delete_chunks(self, collection: str, ids: list[str]) -> int:
        """Delete by primary key; returns the count Milvus reports.

        Ids reach the filter expression as literals only: string keys are
        escaped, and an id for an integer key must parse as an integer, so a
        stored id cannot rewrite the filter into a wider delete.
        """
        if not ids:
            return 0
        lay = self._layout_of(collection)
        pk = lay["pk"]
        if lay.get("pk_numeric"):
            id_list = ", ".join(str(_int_id(i)) for i in ids)
        else:
            id_list = ", ".join(_string_literal(str(_id)) for _id in ids)
        # A write: errors are translated but never retried.
        res = _call(lambda: self._client.delete(
            collection_name=collection, filter=f"{_field_name(pk)} in [{id_list}]"))()
        count = _delete_count(res)
        # Older pymilvus returns a bare list of primary keys (or nothing): the
        # request size is then the best available figure, not a confirmed one.
        return len(ids) if count is None else count

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:  # pragma: no cover
            pass

    # --- schema introspection ---
    def _layout_of(self, name: str) -> dict:
        if name in self._layout:
            return self._layout[name]
        desc = _read(lambda: self._client.describe_collection(name))
        fields = desc.get("fields", [])
        pk = vec = text = None
        dim = None
        pk_numeric = True
        text_candidates = {}
        vector_fields: dict[str, str] = {}
        for f in fields:
            fname = f.get("name")
            tname = _type_name(f.get("type"))
            if f.get("is_primary"):
                pk = fname
                pk_numeric = "INT" in tname
            if tname.endswith("VECTOR"):
                vector_fields[fname] = tname
                # The first FLOAT_VECTOR: the only kind that decodes as floats.
                if tname == _FLOAT_VECTOR and vec is None:
                    vec = fname
                    dim = (f.get("params", {}) or {}).get("dim")
            elif "VARCHAR" in tname or "STRING" in tname:
                text_candidates[fname] = tname
        for pref in _TEXT_KEYS:
            if pref in text_candidates:
                text = pref
                break
        if not text and text_candidates:
            text = next(iter(text_candidates))
        self._layout[name] = {
            "pk": pk or "id", "vec": vec, "text": text,
            "dim": int(dim) if dim else None, "pk_numeric": pk_numeric,
            "vector_fields": vector_fields,
            "non_float_vectors": {k: v for k, v in vector_fields.items()
                                  if v != _FLOAT_VECTOR},
        }
        return self._layout[name]


def _is_milvus_exception(exc: BaseException) -> bool:
    return any(cls.__name__ == "MilvusException" for cls in type(exc).__mro__)


def _translate(exc: BaseException) -> BaseException:
    """Map a pymilvus error onto the connector error taxonomy.

    ``MilvusException.code`` is a Milvus error code, not an HTTP status, so the
    shared mapper's status heuristics are kept away from it. A Milvus error
    maps by class name, legacy ``compatible_code``, the SDK's own codes or the
    server's ``retriable`` flag, and otherwise stays as it is. Transport errors
    (gRPC status, builtins) go through the shared mapper.
    """
    if not _is_milvus_exception(exc):
        return translate_error(exc, kind=MilvusConnector.kind, extra=_ERRORS)
    target: Optional[type[ConnectorError]] = None
    for cls in type(exc).__mro__:
        target = _ERRORS.get(cls.__name__)
        if target is not None:
            break
    code = getattr(exc, "code", None)
    if target is None:
        compat = getattr(exc, "compatible_code", None)
        if isinstance(compat, int):
            target = _COMPATIBLE_CODES.get(compat)
    if target is None and isinstance(code, int):
        target = _MILVUS_CODES.get(code)
    if target is None and getattr(exc, "retriable", False) is True:
        target = ConnectorUnavailable
    if target is None:
        return exc
    return target(f"milvus: {type(exc).__name__} (code {code})")


def _call(fn: Callable[[], _T]) -> Callable[[], _T]:
    """``fn`` with its pymilvus errors translated, for use inside retry_read."""
    def call() -> _T:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - translated or re-raised as is
            translated = _translate(exc)
            if translated is exc:
                raise
            raise translated from exc
    return call


def _read(fn: Callable[[], _T]) -> _T:
    """An idempotent read: errors translated, transient ones retried."""
    return retry_read(_call(fn))


def _type_name(ftype: Any) -> str:
    """A field type as its DataType name, whatever shape pymilvus gave it."""
    name = getattr(ftype, "name", None)
    if isinstance(name, str):
        return name.upper()
    if isinstance(ftype, int) and not isinstance(ftype, bool):
        return _VECTOR_TYPE_NUMBERS.get(int(ftype), str(ftype))
    return str(ftype).upper().split(".")[-1]


def _as_floats(v) -> Optional[list[float]]:
    if v is None:
        return None
    try:
        return [float(x) for x in v]
    except (TypeError, ValueError):
        return None


def _filter(where: Optional[dict]) -> str:
    if not where:
        return ""
    parts = []
    for k, v in where.items():
        field = _field_name(k)
        parts.append(
            f'{field} == {_string_literal(v)}' if isinstance(v, str)
            else f"{field} == {v}"
        )
    return " and ".join(parts)


def _field_name(name: str) -> str:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        raise ValueError(f"invalid Milvus filter field: {name!r}")
    return name


def _int_id(raw: object) -> int:
    """An id for an integer primary key, or ValueError — never a raw string."""
    if isinstance(raw, bool):
        raise ValueError(f"invalid Milvus integer id: {raw!r}")
    if isinstance(raw, int):
        return raw
    text = str(raw).strip()
    if not re.fullmatch(r"[+-]?\d+", text):
        raise ValueError(f"invalid Milvus integer id: {raw!r}")
    return int(text)


def _delete_count(res: object) -> Optional[int]:
    """``delete_count`` from a MilvusClient.delete result (dict or object)."""
    value = res.get("delete_count") if isinstance(res, dict) else \
        getattr(res, "delete_count", None)
    try:
        return None if value is None else int(value)
    except (TypeError, ValueError):
        return None


def _string_literal(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _properties(described: Any) -> dict[str, Any]:
    """Flatten Milvus property shapes: top-level keys, a dict, or [{key, value}]."""
    if not isinstance(described, dict):
        return {}
    props: dict[str, Any] = {k: v for k, v in described.items() if isinstance(k, str)}
    nested = described.get("properties")
    if isinstance(nested, dict):
        props.update(nested)
    elif isinstance(nested, list):
        for item in nested:
            if isinstance(item, dict) and "key" in item:
                props[str(item["key"])] = item.get("value")
    return props


def _is_denied(exc: BaseException) -> bool:
    text = str(exc).lower()
    return "permission" in text or "denied" in text or "privilege" in text


def _version_text(version: Optional[tuple[int, ...]]) -> Optional[str]:
    return ".".join(str(p) for p in version) if version else None
