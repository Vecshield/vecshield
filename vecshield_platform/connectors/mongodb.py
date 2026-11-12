"""MongoDB Atlas Vector Search connector.

Each (db.collection) carrying a vectorSearch index = a collection, including
indexes whose field is ``autoEmbed`` (mongot embeds the text at ``path`` and
keeps the vectors outside the documents, so those chunks carry text only).
Documents are read in ``_id`` order, ``batch_size`` per round trip; stored
vectors are arrays or BSON vectors (binary subtype 9, decoded with
``Binary.as_vector()``). Vector query uses the $vectorSearch stage, and a
``where`` key the index does not declare as a ``filter`` field raises
UnsupportedCapability. A failure to list a collection's search indexes is
recorded as a read error naming it. pymongo imported lazily.

The endpoint is deliberately stripped to host:port because the URI can carry
credentials. The TLS facts the URI holds (scheme, ``+srv``, ``tls=``/``ssl=``)
are read before stripping and kept in describe().metadata["transport"].
"""

from __future__ import annotations

import time
from typing import Any, Callable, Iterator, Optional
from urllib.parse import parse_qs, urlsplit

from vecshield_platform.connectors.base import (
    RETRYABLE_ERRORS,
    AtRestObservation,
    Connector,
    ConnectorAuthError,
    ConnectorNotFound,
    ConnectorTimeout,
    ConnectorUnavailable,
    UnsupportedCapability,
    mask_reference,
    retry_read,
    translate_error,
)
from vecshield_platform.store_facts.mongodb import _search_unavailable
from vecshield.models import Chunk, Collection, QueryHit, VectorStore

_TEXT_KEYS = ("content", "text", "document", "chunk", "body", "page_content")
_SKIP_DBS = {"admin", "local", "config"}

#: pymongo exception class names and what they mean for a caller (names, so
#: pymongo stays optional). NetworkTimeout is an AutoReconnect subclass; the
#: MRO is walked, so it is a timeout rather than an outage.
_ERRORS = {
    "NetworkTimeout": ConnectorTimeout,
    "ExecutionTimeout": ConnectorTimeout,          # maxTimeMS exceeded
    "ServerSelectionTimeoutError": ConnectorUnavailable,
    "WaitQueueTimeoutError": ConnectorUnavailable,
    "AutoReconnect": ConnectorUnavailable,
    "ConnectionFailure": ConnectorUnavailable,
    "CursorNotFound": ConnectorUnavailable,
}

#: OperationFailure server error codes that have a meaning for callers.
_CODE_ERRORS = {
    13: ConnectorAuthError,      # Unauthorized
    18: ConnectorAuthError,      # AuthenticationFailed
    8000: ConnectorAuthError,    # AtlasError ("bad auth")
    26: ConnectorNotFound,       # NamespaceNotFound
    50: ConnectorTimeout,        # MaxTimeMSExpired
}

#: BSON binary subtype for vectors (bson.binary.VECTOR_SUBTYPE).
_VECTOR_SUBTYPE = 9
_NOTHING = object()
_RETRY_DELAY = 0.1
_MAX_RESUMES = 3


def _get_path(doc: Any, path: Optional[str]) -> Any:
    """A document value by dotted path (``a.b``); None when absent."""
    if not path or not isinstance(doc, dict):
        return None
    if path in doc:
        return doc[path]
    cur: Any = doc
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _decode_vector(value: Any) -> Optional[list[float]]:
    """A stored embedding as floats.

    Arrays of numbers are read as they are. BSON vectors (binary subtype 9)
    are decoded with ``Binary.as_vector()`` (pymongo 4.10+): INT8 and FLOAT32
    become floats; PACKED_BIT is binary, not a dense vector, and is not
    decoded. Any other binary value is not a vector this can read.
    """
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        if getattr(value, "subtype", None) != _VECTOR_SUBTYPE:
            return None
        as_vector = getattr(value, "as_vector", None)
        if not callable(as_vector):
            return None
        try:
            vec = as_vector()
        except (ValueError, TypeError):
            return None
        if getattr(getattr(vec, "dtype", None), "name", "") == "PACKED_BIT":
            return None
        try:
            return [float(x) for x in vec.data]
        except (TypeError, ValueError):
            return None
    if isinstance(value, (list, tuple)):
        try:
            return [float(x) for x in value] or None
        except (TypeError, ValueError):
            return None
    return None


def _bson_type_alias(value: Any) -> Optional[str]:
    """The ``$type`` alias whose values ``$gt`` compares ``value`` against."""
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, (bytes, bytearray)):
        return "binData"
    import datetime
    if isinstance(value, datetime.datetime):
        return "date"
    name = type(value).__name__
    return {"ObjectId": "objectId", "Decimal128": "number", "UUID": "binData",
            "Int64": "number"}.get(name)


class MongoDBConnector(Connector):
    kind = "mongodb"
    #: $vectorSearch requires numCandidates <= 10,000 and limit <= numCandidates
    #: (MongoDB Vector Search stage docs). query() asks for ten candidates per
    #: result, capped at 10,000, so a top_k up to 10,000 stays valid.
    max_top_k = 10000

    def __init__(self, *, uri: str, **_ignored):
        try:
            from pymongo import MongoClient
        except ImportError as e:  # pragma: no cover
            raise ImportError("pymongo not installed. pip install 'vecshield[mongodb]'") from e
        if not uri:
            raise ValueError("mongodb requires uri")
        self._c = MongoClient(uri)
        self._endpoint = mongo_hosts(uri)
        self._transport = mongo_transport_config(uri)
        self._layout: dict[str, dict] = {}

    def capabilities(self) -> set[str]:
        return {"query", "delete", "transport_introspection", "at_rest_introspection",
                "field_encryption_introspection"}

    def describe(self) -> VectorStore:
        transport = getattr(self, "_transport", None)
        return VectorStore(kind=self.kind, name=f"mongodb://{self._endpoint}",
                           endpoint=self._endpoint, collections=self.list_collections(),
                           metadata={"transport": dict(transport)} if transport else {})

    # ------------------------- crypto introspection ------------------------- #

    def transport_session_info(self) -> dict[str, Any]:
        """TLS as the driver's pool is configured.

        pymongo refuses to talk to a server without TLS once TLS is configured,
        so the pool's SSL context describes every live connection it holds.
        """
        try:
            ctx = self._c.options.pool_options._ssl_context
        except Exception as exc:  # noqa: BLE001
            return {"tls": None, "version": None, "cipher": None,
                    "source": "client_options",
                    "reason": f"client options could not be read ({type(exc).__name__})"}
        info: dict[str, Any] = {"tls": ctx is not None, "version": None, "cipher": None,
                                "source": "client_options"}
        if ctx is not None:
            import ssl

            info["certificate_verification"] = getattr(ctx, "verify_mode", None) != ssl.CERT_NONE
        return info

    def at_rest_encryption_state(self, collection: Optional[str] = None) -> AtRestObservation:
        """The encrypted storage engine's state on this mongod node, from serverStatus.

        ``encryptionAtRest`` (encryptionEnabled / encryptionCipherMode /
        encryptionKeyId) appears on Enterprise and Percona servers; the field
        names are documented by Percona rather than MongoDB, so confidence is
        medium. The answer covers the node VecShield is connected to. Atlas
        encrypts volumes outside the database, so an Atlas "not enabled" is
        not observable, never disabled.
        """
        source = "serverStatus.encryptionAtRest"
        atlas = _is_atlas_host(self._endpoint)
        base_evidence: dict[str, Any] = {"scope_note": "this mongod node",
                                         "confidence": "medium (field names documented "
                                                       "by Percona)"}
        if self._has_vector_search_index():
            base_evidence["caveat"] = ("Vector search indexes are stored by mongot, "
                                       "outside the encrypted storage engine.")
        try:
            status = self._c.admin.command("serverStatus")
        except Exception as exc:  # noqa: BLE001
            denied = "auth" in type(exc).__name__.lower() or \
                getattr(exc, "code", None) in (13, 18)
            return AtRestObservation(
                state="not_observable" if denied else "error", scope="store",
                collection=collection, source=source, evidence=base_evidence,
                reason=("This user cannot run serverStatus. Grant the clusterMonitor "
                        "role, or provide the server's security.enableEncryption "
                        "setting." if denied else
                        f"serverStatus failed ({type(exc).__name__})."),
                evidence_to_supply=(["The server's security.enableEncryption setting"]
                                    if denied else []))
        evidence = {**base_evidence, "host": (status or {}).get("host")}
        ear = (status or {}).get("encryptionAtRest")
        if isinstance(ear, dict) and ear.get("encryptionEnabled"):
            mode = ear.get("encryptionCipherMode")
            return AtRestObservation(
                state="enabled", scope="store", collection=collection, source=source,
                mechanism="encrypted storage engine" + (f" ({mode})" if mode else ""),
                key_reference=mask_reference(ear.get("encryptionKeyId")),
                evidence={**evidence, "cipher_mode": mode} if mode else evidence,
                reason="the encrypted storage engine is enabled on this node")
        if atlas:
            return AtRestObservation(
                state="not_observable", scope="store", collection=collection,
                source=source, evidence=evidence,
                reason="Atlas always encrypts storage volumes, but the database does "
                       "not report this. For customer-managed keys, provide the "
                       "project's Encryption at Rest settings from Atlas.",
                evidence_to_supply=["The Atlas project's Encryption at Rest (customer "
                                    "key management) settings"],
                documented_default={
                    "text": "MongoDB documents that Atlas encrypts all cluster storage "
                            "and snapshot volumes at rest by default.",
                    "source_url": "https://www.mongodb.com/docs/atlas/security-kms-encryption/"})
        if not isinstance(ear, dict) or "encryptionEnabled" not in ear:
            return AtRestObservation(
                state="not_observable", scope="store", collection=collection,
                source=source, evidence=evidence,
                reason="MongoDB Community has no built-in encryption at rest and "
                       "cannot report disk encryption. Provide your volume or "
                       "filesystem encryption configuration.",
                evidence_to_supply=["Volume or filesystem encryption configuration of "
                                    "every data-bearing node"])
        return AtRestObservation(
            state="disabled", scope="store", collection=collection, source=source,
            evidence=evidence,
            reason="the encrypted storage engine is not enabled on this node. Volume "
                   "or disk encryption beneath it is not visible here")

    def _has_vector_search_index(self) -> bool:
        return any(lay.get("index") for lay in (getattr(self, "_layout", None) or {}).values())

    def field_encryption_config(self, collection: str) -> list[dict[str, Any]]:
        """Queryable Encryption ``encryptedFields`` and server-side CSFLE schema.

        CSFLE configured only in a client's schema map is invisible to the
        server and therefore to this check.
        """
        db, coll = collection.split(".", 1)
        infos = list(self._c[db].list_collections(filter={"name": coll}))
        options = (infos[0].get("options") or {}) if infos else {}
        fields: list[dict[str, Any]] = []
        for spec in (options.get("encryptedFields") or {}).get("fields", []) or []:
            queries = spec.get("queries")
            if isinstance(queries, dict):
                queries = [queries]
            fields.append({"path": spec.get("path"), "mechanism": "queryable_encryption",
                           "queries": sorted({q.get("queryType") for q in queries or []
                                              if isinstance(q, dict) and q.get("queryType")})})
        schema = (options.get("validator") or {}).get("$jsonSchema")
        if isinstance(schema, dict):
            fields.extend(_json_schema_encrypted_fields(schema))
        return fields

    # ------------------------------------------------------------ errors -- #

    def _translate(self, exc: BaseException) -> BaseException:
        """A pymongo error as a connector error, where it maps.

        OperationFailure is mapped by its server error code only: its ``code``
        is a MongoDB code, not an HTTP status, so an unrecognised one is left
        as it is rather than read as one.
        """
        names = {cls.__name__ for cls in type(exc).__mro__}
        if "OperationFailure" in names and not names & set(_ERRORS):
            code = getattr(exc, "code", None)
            target = _CODE_ERRORS.get(code) if isinstance(code, int) else None
            if target is None:
                return exc
            return target(f"{self.kind}: {type(exc).__name__} (code {code})")
        return translate_error(exc, kind=self.kind, extra=_ERRORS)

    def _call(self, fn: Callable[[], Any]) -> Any:
        """An idempotent read, with errors mapped and transient ones retried."""
        def call() -> Any:
            try:
                return fn()
            except Exception as exc:  # noqa: BLE001 - translated or re-raised
                translated = self._translate(exc)
                if translated is exc:
                    raise
                raise translated from exc
        return retry_read(call)

    def _record_once(self, collection: str, **fields: Any) -> None:
        """One read error per collection and operation, however often it recurs."""
        for entry in self.read_errors():
            if (entry.get("collection") == collection
                    and entry.get("operation") == fields.get("operation")):
                return
        self._record_read_error(collection, **fields)

    # ------------------------------------------------------- inventory -- #

    def _vector_index(self, coll, name: str) -> Optional[dict[str, Any]]:
        """The collection's vector search index as a layout, or None.

        Reads ``$listSearchIndexes``. A ``vectorSearch`` index qualifies when
        it has a ``vector`` field (stored embeddings) or an ``autoEmbed``
        field (mongot embeds the text at ``path`` and stores the vectors in
        its own database, not in the documents). ``filter`` fields are the
        paths a ``$vectorSearch`` may filter on.

        A failure to list indexes is recorded as a read error naming the
        collection; it is not the same as having no vector index. A deployment
        without a search service (mongot) has no search indexes at all, which
        is an answer, not a failure.
        """
        try:
            indexes = self._call(lambda: list(coll.list_search_indexes()))
        except Exception as exc:  # noqa: BLE001 - recorded, never swallowed
            if _search_unavailable(exc.__cause__ or exc):
                return None
            self._record_once(name, operation="list_search_indexes",
                              error_type=type(exc).__name__,
                              reason="the collection's search indexes could not be "
                                     "listed, so whether it holds vectors is unknown")
            return None
        for idx in indexes:
            if not isinstance(idx, dict):
                continue
            typ = str(idx.get("type", ""))
            if typ != "vectorSearch" and "vector" not in typ.lower():
                continue
            definition = idx.get("latestDefinition") or idx.get("definition") or {}
            fields = [f for f in (definition.get("fields") or []) if isinstance(f, dict)]
            filters = sorted(str(f.get("path")) for f in fields
                             if f.get("type") == "filter" and f.get("path"))
            for f in fields:
                if f.get("type") == "vector" and f.get("path"):
                    return {"index": idx.get("name"), "vec": f.get("path"),
                            "dim": f.get("numDimensions"), "filters": filters,
                            "auto_embed": None}
            for f in fields:
                if f.get("type") == "autoEmbed" and f.get("path"):
                    return {"index": idx.get("name"), "vec": None,
                            "dim": f.get("numDimensions"), "filters": filters,
                            "auto_embed": {"path": f.get("path"), "model": f.get("model"),
                                           "modality": f.get("modality")}}
        return None

    def _vector_collections(self, *, refresh: bool = False) -> set[str]:
        """``db.collection`` names that carry a vector search index.

        The same inventory list_collections() reports: system databases and
        ``system.*`` collections are never part of it.
        """
        cached = getattr(self, "_allowed", None)
        if cached is not None and not refresh:
            return cached
        allowed: set[str] = set()
        for db in self._call(self._c.list_database_names):
            if db in _SKIP_DBS:
                continue
            for coll in self._call(self._c[db].list_collection_names):
                if coll.startswith("system."):
                    continue
                if self._vector_index(self._c[db][coll], f"{db}.{coll}"):
                    allowed.add(f"{db}.{coll}")
        self._allowed = allowed
        return allowed

    def _require_collection(self, name: str) -> tuple[str, str]:
        """Split ``db.collection``, refusing anything outside the inventory.

        Collection names reach here from API callers. Without this check any
        database the connecting user can read — ``admin.system.users``, or an
        application's ``users`` collection — could be read, sampled or deleted
        from through a vector-store connector.
        """
        db, sep, coll = str(name).partition(".")
        if (not sep or not db or not coll or db in _SKIP_DBS
                or coll.startswith("system.")):
            raise ValueError(f"not a vector collection on this store: {name!r}")
        cached = getattr(self, "_allowed", None)
        if cached is None or name not in cached:
            # Enumerate (again): the inventory may predate a new vector index.
            if name not in self._vector_collections(refresh=True):
                raise ValueError(f"not a vector collection on this store: {name!r}")
        return db, coll

    def _with_text(self, c, lay: dict[str, Any]) -> dict[str, Any]:
        """The layout plus its text field: the autoEmbed path, else a common name."""
        text = lay["auto_embed"]["path"] if lay.get("auto_embed") else None
        if text is None:
            doc = self._call(lambda: c.find_one()) or {}
            for k in _TEXT_KEYS:
                if isinstance(doc.get(k), str):
                    text = k
                    break
        return {**lay, "text": text}

    def _layout_of(self, name: str) -> dict:
        if name in self._layout and "filters" in self._layout[name]:
            return self._layout[name]
        db, coll = name.split(".", 1)
        c = self._c[db][coll]
        lay = self._vector_index(c, name) or {
            "index": None, "vec": None, "dim": None, "filters": [], "auto_embed": None}
        self._layout[name] = self._with_text(c, lay)
        return self._layout[name]

    def list_collections(self) -> list[Collection]:
        out = []
        allowed: set[str] = set()
        for db in self._call(self._c.list_database_names):
            if db in _SKIP_DBS:
                continue
            for coll in self._call(self._c[db].list_collection_names):
                if coll.startswith("system."):
                    continue
                name = f"{db}.{coll}"
                c = self._c[db][coll]
                lay = self._vector_index(c, name)
                if not lay:
                    continue
                lay = self._layout[name] = self._with_text(c, lay)
                allowed.add(name)
                metadata: dict[str, Any] = {"index": lay["index"],
                                            "vector_path": lay["vec"],
                                            "filter_fields": list(lay["filters"])}
                if lay["auto_embed"]:
                    metadata["auto_embed"] = dict(lay["auto_embed"])
                    metadata["embedding_unavailable"] = (
                        "autoEmbed: mongot stores the vectors outside the documents")
                count = 0
                try:
                    count = int(self._call(c.estimated_document_count))
                except Exception as exc:  # noqa: BLE001 - unknown, not zero
                    metadata.update(count_known=False, count_error=type(exc).__name__)
                out.append(Collection(name=name, count=count, dimension=lay["dim"],
                                      metadata=metadata))
        self._allowed = allowed
        return out

    # ------------------------------------------------------------ reads -- #

    def _resumable(self, coll, last: Any) -> bool:
        """Whether ``_id > last`` resumes a read without skipping documents.

        MongoDB compares across types by type order, so ``$gt`` on an
        ObjectId never matches a string ``_id``. Resuming is safe only when
        every ``_id`` shares the last one's type.
        """
        if last is _NOTHING:
            return True
        alias = _bson_type_alias(last)
        if alias is None:
            return False
        try:
            other = coll.find_one({"_id": {"$not": {"$type": alias}}}, projection={"_id": 1})
        except Exception:  # noqa: BLE001 - unknown means not safe
            return False
        return other is None

    def iter_chunks(self, collection: str, batch_size: int = 256) -> Iterator[Chunk]:
        """Read every document in ``_id`` order, ``batch_size`` per round trip.

        A transient failure resumes after the last ``_id`` read, when that is
        known to skip nothing; otherwise, and for any other failure, the
        failure is recorded as a read error and raised.
        """
        db, coll = self._require_collection(collection)
        lay = self._layout_of(collection)
        c = self._c[db][coll]
        vec_path, text_path = lay["vec"], lay["text"]
        last: Any = _NOTHING
        failure: Optional[Exception]
        retries = 0
        delay = _RETRY_DELAY
        while True:
            flt = {} if last is _NOTHING else {"_id": {"$gt": last}}
            try:
                it = iter(c.find(flt, sort=[("_id", 1)], batch_size=batch_size))
            except Exception as exc:  # noqa: BLE001 - mapped below
                it, failure = None, exc
            else:
                failure = None
            while it is not None:
                try:
                    doc = next(it)
                except StopIteration:
                    return
                except Exception as exc:  # noqa: BLE001 - mapped below
                    failure = exc
                    break
                last = doc.get("_id")
                text = _get_path(doc, text_path) if text_path else None
                yield Chunk(
                    id=str(doc.get("_id")), collection=collection,
                    text=text if isinstance(text, str) else None,
                    embedding=_decode_vector(_get_path(doc, vec_path)) if vec_path else None,
                    metadata={k: v for k, v in doc.items()
                              if k not in ("_id", vec_path)})
            assert failure is not None
            translated = self._translate(failure)
            if (isinstance(translated, RETRYABLE_ERRORS) and retries < _MAX_RESUMES
                    and self._resumable(c, last)):
                retries += 1
                time.sleep(delay)
                delay *= 2
                continue
            self._record_read_error(
                collection, operation="find", error_type=type(translated).__name__,
                reason="the collection could not be read to the end; documents after "
                       "the last one read were not scanned")
            if translated is failure:
                raise failure
            raise translated from failure

    def query(self, collection: str, vector: list[float], top_k: int = 10,
              where: Optional[dict[str, Any]] = None) -> list[QueryHit]:
        """``$vectorSearch`` with ``where`` as a pre-filter.

        A ``$vectorSearch`` filter can only use paths the index declares as
        ``filter`` fields; on any other path Atlas fails the query. That is
        reported as UnsupportedCapability (the tenant filter cannot be
        tested), never as a query returning nothing.
        """
        db, coll = self._require_collection(collection)
        lay = self._layout_of(collection)
        if not lay["vec"]:
            raise UnsupportedCapability(
                f"{self.kind}: {collection} is indexed with autoEmbed, which "
                "searches by query text, not by a vector")
        if where:
            unindexed = [k for k in where if k not in set(lay["filters"])]
            if unindexed:
                raise UnsupportedCapability(
                    f"{self.kind}: {', '.join(sorted(map(str, unindexed)))} not indexed as a "
                    f"filter field of vector index {lay['index']!r} on {collection}")
        stage = {"$vectorSearch": {"index": lay["index"], "path": lay["vec"],
                                   "queryVector": vector,
                                   "numCandidates": min(max(top_k * 10, top_k), 10000),
                                   "limit": top_k}}
        if where:
            stage["$vectorSearch"]["filter"] = where
        pipe = [stage, {"$addFields": {"_score": {"$meta": "vectorSearchScore"}}}]
        docs = self._call(lambda: list(self._c[db][coll].aggregate(pipe)))
        hits = []
        for doc in docs:
            hits.append(QueryHit(id=str(doc.get("_id")), score=float(doc.get("_score", 0.0)),
                                 text=_get_path(doc, lay["text"]) if lay["text"] else None,
                                 metadata={k: v for k, v in doc.items()
                                           if k not in ("_id", lay["vec"], "_score")}))
        return hits

    def delete_chunks(self, collection: str, ids: list[str]) -> int:
        from bson import ObjectId
        db, coll = self._require_collection(collection)
        oids = []
        raw_ids = []
        for _id in ids:
            try:
                oids.append(ObjectId(_id))
            except Exception:
                raw_ids.append(_id)
        result = self._c[db][coll].delete_many(
            {"$or": [{"_id": {"$in": oids + raw_ids}}]}
        )
        return result.deleted_count

    def close(self) -> None:
        try:
            self._c.close()
        except Exception:  # pragma: no cover
            pass


def mongo_hosts(uri: str) -> str:
    """The host list of a MongoDB URI (``h1:27017,h2:27017``), never userinfo.

    The last ``@`` ends the userinfo, so a password holding ``@``, ``/`` or
    ``?`` cannot leak into the result. A URI without userinfo keeps its hosts
    (it used to collapse to ``mongodb:``, which also hid an Atlas host).
    """
    text = str(uri or "")
    scheme_end = text.find("://")
    rest = text[scheme_end + 3:] if scheme_end >= 0 else text
    at = rest.rfind("@")
    if at >= 0:
        rest = rest[at + 1:]
    for sep in ("/", "?", "#"):
        rest = rest.split(sep, 1)[0]
    return rest


def mongo_transport_config(uri: str) -> dict[str, Any]:
    """TLS facts from a MongoDB URI — never the URI, host list or credentials."""
    parts = urlsplit(uri)
    scheme = (parts.scheme or "mongodb").lower()
    params = {k.lower(): v[-1].lower() for k, v in parse_qs(parts.query).items() if v}
    flag = params.get("tls", params.get("ssl"))
    config: dict[str, Any] = {"scheme": scheme, "source": "dsn"}
    if flag in ("true", "1"):
        config.update(tls=True, reason="The connection string sets tls=true.")
    elif flag in ("false", "0"):
        config.update(tls=False, reason="The connection string sets tls=false.")
    elif scheme == "mongodb+srv":
        config.update(tls=True, reason="The mongodb+srv scheme enables TLS by default.")
    else:
        config.update(tls=None, reason="No tls flag is set; the driver default does not "
                                       "use TLS.")
    if params.get("tlsinsecure") in ("true", "1") or \
            params.get("tlsallowinvalidcertificates") in ("true", "1"):
        config["certificate_verification"] = False
    return config


def _is_atlas_host(endpoint: str) -> bool:
    hosts = (endpoint or "").split(",")
    return any(h.split(":")[0].lower().endswith(".mongodb.net") for h in hosts)


def _json_schema_encrypted_fields(schema: dict, prefix: str = "") -> list[dict[str, Any]]:
    """Paths a server-side $jsonSchema marks with ``encrypt``, and the algorithm it names."""
    out: list[dict[str, Any]] = []
    for name, spec in (schema.get("properties") or {}).items():
        if not isinstance(spec, dict):
            continue
        path = f"{prefix}.{name}" if prefix else name
        if isinstance(spec.get("encrypt"), dict):
            entry: dict[str, Any] = {"path": path,
                                     "mechanism": "client_side_field_level_encryption"}
            algorithm = spec["encrypt"].get("algorithm") or \
                (schema.get("encryptMetadata") or {}).get("algorithm")
            if algorithm:
                entry["algorithm"] = algorithm
            out.append(entry)
        elif spec.get("properties"):
            out.extend(_json_schema_encrypted_fields(spec, path))
    return out
