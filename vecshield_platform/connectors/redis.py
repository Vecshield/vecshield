"""Redis Vector Search connector (RediSearch / Redis Stack / Redis 8).

Each FT index = a VecShield collection. redis-py is imported lazily.

What ``FT.INFO`` says about an index decides how it is read:

* ``index_definition.key_type``: HASH documents are read with ``HGETALL``;
  JSON documents with ``JSON.GET key $ <attribute paths>``, so the whole
  document is classified and the vector and text are taken from the paths
  the index declares.
* ``index_definition.prefixes``: documents are enumerated with
  ``SCAN MATCH <prefix>* TYPE <hash|ReJSON-RL>`` over every prefix and
  de-duplicated, which neither skips nor repeats keys the way unsorted
  ``FT.SEARCH ... LIMIT`` paging does. SCAN may return a key more than once;
  a key seen before is not read again.
* each attribute's ``identifier`` (hash field or JSON path) and ``attribute``
  (the alias queries must use), its ``type``, and for vectors its
  ``data_type`` and ``dim``. HASH vectors are little-endian blobs decoded by
  their declared type (FLOAT32, FLOAT64, FLOAT16, BFLOAT16, INT8, UINT8), and
  query vectors are packed the same way.

Filters in ``query(where=...)`` are built from the field's type: TAG fields as
``@f:{v}`` with the value escaped, NUMERIC fields as ``@f:[v v]``. A field the
index does not declare, or one that cannot be matched exactly (TEXT, GEO),
raises UnsupportedCapability rather than running an unfiltered query.
"""

from __future__ import annotations

import json
import math
import re
import struct
from typing import Any, Iterator, Optional

from vecshield_platform.connectors.base import (
    Connector,
    ConnectorAuthError,
    ConnectorTimeout,
    ConnectorUnavailable,
    UnsupportedCapability,
    mapped_call,
    retry_read,
)
from vecshield_platform.connectors.redact import redact_credentials
from vecshield.models import Chunk, Collection, QueryHit, VectorStore

_TEXT_KEYS = ("content", "text", "document", "chunk", "body", "passage")

#: redis-py exception class names and what they mean for a caller. Names, so
#: redis stays optional; the MRO is walked, so AuthenticationError (a
#: ConnectionError subclass) is an auth failure, not an outage.
_ERRORS = {
    "AuthenticationError": ConnectorAuthError,
    "AuthenticationWrongNumberOfArgsError": ConnectorAuthError,
    "AuthorizationError": ConnectorAuthError,
    "NoPermissionError": ConnectorAuthError,      # ACL NOPERM
    "TimeoutError": ConnectorTimeout,
    "BusyLoadingError": ConnectorUnavailable,
    "ClusterDownError": ConnectorUnavailable,
    "TryAgainError": ConnectorUnavailable,
    "MaxConnectionsError": ConnectorUnavailable,
    "ConnectionError": ConnectorUnavailable,
}

#: Vector element types RediSearch accepts for HASH blobs: struct format and
#: element size. BFLOAT16 has no struct code; it is the top half of a float32.
_DTYPES: dict[str, tuple[Optional[str], int]] = {
    "FLOAT32": ("f", 4), "FLOAT64": ("d", 8), "FLOAT16": ("e", 2),
    "BFLOAT16": (None, 2), "INT8": ("b", 1), "UINT8": ("B", 1),
}

#: The TYPE a SCAN filters on, per index key type.
_SCAN_TYPES = {"HASH": "hash", "JSON": "ReJSON-RL"}


def _dec(v):
    return v.decode("utf-8", "replace") if isinstance(v, bytes) else v


def _field_name(name: str) -> str:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", str(name)):
        raise ValueError(f"invalid Redis filter field: {name!r}")
    return str(name)


def _field_ref(name: str) -> str:
    """An attribute name escaped for the query language (``$.a`` -> ``\\$\\.a``)."""
    return re.sub(r"([^A-Za-z0-9_])", r"\\\1", str(name))


def _tag_value(value: Any) -> str:
    """Escape a TAG query value so it can only ever match itself."""
    return re.sub(r"([^A-Za-z0-9_])", r"\\\1", str(value))


def _numeric_value(value: Any) -> str:
    """A NUMERIC filter bound; anything that is not a finite number is refused."""
    if isinstance(value, bool):
        raise ValueError("a boolean is not a NUMERIC filter value")
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"not a number for a NUMERIC filter: {value!r}") from None
    if math.isnan(number) or math.isinf(number):
        raise ValueError("a NUMERIC filter value must be finite")
    return format(number, ".17g")


def _glob_escape(prefix: str) -> str:
    """A key prefix as a literal in a SCAN MATCH glob."""
    return re.sub(r"([*?\[\]\\])", r"\\\1", prefix)


class RedisDeleteRefused(ValueError):
    """A delete refused because an id is not a key of the named index (F5)."""

    def __init__(self, message: str, *, refused: int = 0, requested: int = 0):
        super().__init__(message)
        self.refused = refused
        self.requested = requested


# ------------------------------------------------------------ vectors -- #

def decode_vector(blob: Any, data_type: Optional[str] = "FLOAT32") -> Optional[list[float]]:
    """A HASH vector blob as floats, by the index's declared ``data_type``.

    Little-endian, as RediSearch stores them. Returns None for a value that
    is not bytes, an unknown type, or a length that is not a whole number of
    elements.
    """
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        return None
    data = bytes(blob)
    dtype = str(data_type or "FLOAT32").upper()
    if dtype not in _DTYPES or not data:
        return None
    fmt, size = _DTYPES[dtype]
    if len(data) % size:
        return None
    n = len(data) // size
    if fmt is None:  # BFLOAT16: shift each half into the high bits of a float32
        halves = struct.unpack(f"<{n}H", data)
        return list(struct.unpack(f"<{n}f", struct.pack(f"<{n}I", *(h << 16 for h in halves))))
    return [float(x) for x in struct.unpack(f"<{n}{fmt}", data)]


def _to_bfloat16(value: float) -> int:
    bits = struct.unpack("<I", struct.pack("<f", value))[0]
    if math.isnan(value):
        return (bits >> 16) | 0x40  # keep it a NaN after truncation
    return ((bits + 0x7FFF + ((bits >> 16) & 1)) >> 16) & 0xFFFF  # round to nearest even


def encode_vector(vector: list[float], data_type: Optional[str] = "FLOAT32") -> bytes:
    """Pack a query vector the way the index stores its vectors (little-endian)."""
    dtype = str(data_type or "FLOAT32").upper()
    if dtype not in _DTYPES:
        raise UnsupportedCapability(f"redis: unknown vector data_type {data_type!r}")
    fmt, _size = _DTYPES[dtype]
    values = [float(x) for x in vector]
    n = len(values)
    if fmt is None:
        return struct.pack(f"<{n}H", *(_to_bfloat16(v) for v in values))
    if fmt in ("b", "B"):
        lo, hi = (-128, 127) if fmt == "b" else (0, 255)
        ints = [int(round(v)) for v in values]
        if any(i < lo or i > hi for i in ints):
            raise ValueError(f"query vector has values outside the {dtype} range")
        return struct.pack(f"<{n}{fmt}", *ints)
    try:
        return struct.pack(f"<{n}{fmt}", *values)
    except (OverflowError, struct.error) as exc:
        raise ValueError(f"query vector does not fit {dtype}") from exc


# ------------------------------------------------------------ FT.INFO -- #

def _attr_fields(attr: Any) -> dict[str, Any]:
    """One FT.INFO attribute as ``{lower-case key: value}``.

    RESP2 gives a flat ``[key, value, ..., FLAG, ...]`` list; RESP3 a dict.
    Nested lists (vector parameters on some versions) are merged in, the
    outer value winning.
    """
    out: dict[str, Any] = {}

    def merge(nested: Any) -> None:
        for k, v in _attr_fields(nested).items():
            out.setdefault(k, v)

    if isinstance(attr, dict):
        for k, v in attr.items():
            if isinstance(v, (list, tuple, dict)):
                merge(v)
            out.setdefault(str(_dec(k)).lower(), _dec(v))
        return out
    items = list(attr or [])
    i = 0
    while i < len(items):
        key = items[i]
        if isinstance(key, (list, tuple, dict)):
            merge(key)
            i += 1
            continue
        if i + 1 >= len(items):
            break
        value = items[i + 1]
        if isinstance(value, (list, tuple, dict)):
            merge(value)
        out.setdefault(str(_dec(key)).lower(), _dec(value))
        i += 2
    return out


def _definition(raw: dict) -> tuple[Optional[list[str]], str]:
    """(key prefixes or None when unreported, key type) from FT.INFO."""
    definition = raw.get("index_definition") or raw.get(b"index_definition")
    if isinstance(definition, dict):
        items = {str(_dec(k)): v for k, v in definition.items()}
    elif isinstance(definition, (list, tuple)):
        items = {str(_dec(definition[i])): definition[i + 1]
                 for i in range(0, len(definition) - 1, 2)}
    else:
        items = {}
    key_type = str(_dec(items.get("key_type") or "HASH")).upper()
    if "prefixes" not in items:
        return None, key_type
    prefixes_raw = items["prefixes"]
    if isinstance(prefixes_raw, (bytes, str)):
        prefixes_raw = [prefixes_raw]
    return [str(_dec(p)) for p in (prefixes_raw or [])], key_type


def _json_path(identifier: str) -> str:
    """A JSON attribute identifier as a JSONPath (``$.a``), as JSON.GET takes it."""
    text = str(identifier)
    if text.startswith("$"):
        return text
    if text.startswith("."):
        return "$" + text
    return "$." + text


def _simple_path_get(doc: Any, path: str) -> Any:
    """Follow a plain ``$.a.b`` path; None for anything more elaborate."""
    if not re.fullmatch(r"\$(\.[A-Za-z0-9_]+)+", path or ""):
        return None
    cur = doc
    for part in path[2:].split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _top_key(path: Optional[str]) -> Optional[str]:
    m = re.fullmatch(r"\$\.([A-Za-z0-9_]+)", path or "")
    return m.group(1) if m else None


def _json_floats(value: Any) -> Optional[list[float]]:
    if isinstance(value, list) and value and all(
            isinstance(x, (int, float)) and not isinstance(x, bool) for x in value):
        return [float(x) for x in value]
    return None


def parse_index_info(raw: dict) -> dict[str, Any]:
    """The layout VecShield reads an index by, from an ``FT.INFO`` reply."""
    raw = {str(_dec(k)): v for k, v in (raw or {}).items()}
    prefixes, key_type = _definition(raw)
    num_raw = raw.get("num_docs")
    try:
        num: Optional[int] = int(_dec(num_raw)) if num_raw is not None else None
    except (TypeError, ValueError):
        num = None
    fields: dict[str, dict[str, Any]] = {}
    vec = text = None
    for attr in raw.get("attributes", []) or []:
        f = _attr_fields(attr)
        identifier = f.get("identifier")
        if identifier is None:
            continue
        identifier = str(identifier)
        alias = str(f.get("attribute") or identifier)
        typ = str(f.get("type") or "").upper()
        entry: dict[str, Any] = {"alias": alias, "identifier": identifier, "type": typ}
        if typ == "VECTOR":
            dim = f.get("dim")
            try:
                entry["dim"] = int(dim) if dim is not None else None
            except (TypeError, ValueError):
                entry["dim"] = None
            entry["data_type"] = str(f.get("data_type") or "FLOAT32").upper()
            if vec is None:
                vec = entry
        elif text is None and typ in ("TEXT", "TAG") and (
                alias.lower() in _TEXT_KEYS
                or identifier.rsplit(".", 1)[-1].lower() in _TEXT_KEYS):
            text = entry
        fields[alias] = entry
    return {"num": num, "key_type": key_type, "prefixes": prefixes, "fields": fields,
            "vec": vec, "text": text, "dim": vec["dim"] if vec else None}


class RedisConnector(Connector):
    kind = "redis"

    def __init__(self, *, host: str = "localhost", port: int = 6379,
                 db: int = 0, password: Optional[str] = None,
                 url: Optional[str] = None):
        try:
            import redis
        except ImportError as e:  # pragma: no cover
            raise ImportError("redis not installed. pip install 'vecshield[redis]'") from e
        self._r = (redis.from_url(url, decode_responses=False) if url
                   else redis.Redis(host=host, port=port, db=db, password=password,
                                    decode_responses=False))
        # A redis:// URL can carry the password (redis://:pw@host); the
        # endpoint is the display name persisted on findings.
        self._endpoint = redact_credentials(url) if url else f"redis://{host}:{port}/{db}"
        self._layout: dict[str, dict] = {}

    def capabilities(self) -> set[str]:
        return {"query", "delete", "transport_introspection"}

    def transport_session_info(self) -> dict[str, Any]:
        """TLS as the connection pool is built: rediss:// and ssl=True use SSLConnection."""
        try:
            pool = self._r.connection_pool
            cls = pool.connection_class
            kwargs = dict(getattr(pool, "connection_kwargs", {}) or {})
        except Exception as exc:  # noqa: BLE001
            return {"tls": None, "version": None, "cipher": None,
                    "source": "connection_class",
                    "reason": f"the connection pool could not be read ({type(exc).__name__})"}
        names = [c.__name__ for c in getattr(cls, "__mro__", (cls,))]
        info: dict[str, Any] = {"version": None, "cipher": None,
                                "source": "connection_class", "connection_class": names[0]}
        if any("UnixDomainSocket" in n for n in names):
            info.update(tls=None, local_socket=True,
                        reason="a Unix-socket connection never crosses a network")
            return info
        info["tls"] = any(n == "SSLConnection" for n in names)
        if info["tls"]:
            reqs = kwargs.get("ssl_cert_reqs")
            if reqs is not None:
                text = str(getattr(reqs, "name", reqs)).lower()
                info["certificate_verification"] = text not in ("none", "cert_none")
        return info

    def describe(self) -> VectorStore:
        return VectorStore(kind=self.kind, name=self._endpoint, endpoint=self._endpoint,
                           collections=self.list_collections())

    # ------------------------------------------------------------ reads -- #

    def _call(self, fn):
        """An idempotent read: errors mapped, transient ones retried."""
        return retry_read(mapped_call(fn, kind=self.kind, extra=_ERRORS))

    def _indexes(self) -> list[str]:
        return [_dec(x) for x in self._call(lambda: self._r.execute_command("FT._LIST"))]

    def _info(self, index: str) -> dict:
        if index in self._layout:
            return self._layout[index]
        raw = self._call(lambda: self._r.ft(index).info())
        self._layout[index] = parse_index_info(raw)
        return self._layout[index]

    def list_collections(self) -> list[Collection]:
        out = []
        for idx in self._indexes():
            try:
                info = self._info(idx)
            except Exception as exc:  # noqa: BLE001 - one bad index is a gap, not the store
                self._record_read_error(idx, operation="ft_info",
                                        error_type=type(exc).__name__,
                                        reason="FT.INFO failed, so the index's documents "
                                               "and count could not be read")
                out.append(Collection(name=idx, count=0, metadata={
                    "count_known": False, "error": type(exc).__name__}))
                continue
            metadata: dict[str, Any] = {
                "key_type": info["key_type"],
                "vector_field": info["vec"]["alias"] if info["vec"] else None,
                "vector_data_type": info["vec"]["data_type"] if info["vec"] else None,
                "text_field": info["text"]["alias"] if info["text"] else None,
            }
            if info["prefixes"] is not None:
                metadata["prefixes"] = list(info["prefixes"])
            if info["num"] is None:
                metadata["count_known"] = False
            out.append(Collection(name=idx, count=info["num"] or 0, dimension=info["dim"],
                                  metadata=metadata))
        return out

    def iter_chunks(self, collection: str, batch_size: int = 256) -> Iterator[Chunk]:
        info = self._info(collection)
        key_type = info["key_type"]
        scan_type = _SCAN_TYPES.get(key_type)
        if scan_type is None or info["prefixes"] is None:
            self._record_read_error(
                collection, operation="enumerate",
                error_type="UnsupportedIndexDefinition",
                reason=(f"key type {key_type} is not readable" if scan_type is None else
                        "FT.INFO reported no key prefixes, so the index's documents "
                        "could not be enumerated"))
            return
        seen: set[bytes] = set()
        for prefix in info["prefixes"] or [""]:
            pattern = _glob_escape(prefix) + "*"
            cursor: Any = 0
            while True:
                try:
                    cursor, keys = self._call(
                        lambda c=cursor: self._r.scan(cursor=c, match=pattern,
                                                      count=batch_size, _type=scan_type))
                except Exception as exc:
                    self._record_read_error(
                        collection, operation="scan", error_type=type(exc).__name__,
                        reason="SCAN failed; keys after this point were not read")
                    raise
                fresh = []
                for key in keys or []:
                    raw = key if isinstance(key, bytes) else str(key).encode("utf-8")
                    if raw not in seen:
                        seen.add(raw)
                        fresh.append(key)
                if fresh:
                    yield from self._read_docs(collection, info, fresh)
                if int(cursor or 0) == 0:
                    break

    def _read_docs(self, collection: str, info: dict, keys: list) -> Iterator[Chunk]:
        is_json = info["key_type"] == "JSON"
        paths: list[str] = []
        if is_json:
            for entry in (info["vec"], info["text"]):
                if entry:
                    path = _json_path(entry["identifier"])
                    if path != "$" and path not in paths:
                        paths.append(path)

        def fetch() -> list:
            pipe = self._r.pipeline(transaction=False)
            for key in keys:
                if is_json:
                    pipe.execute_command("JSON.GET", key, "$", *paths)
                else:
                    pipe.hgetall(key)
            return pipe.execute(raise_on_error=False)

        try:
            results = self._call(fetch)
        except Exception as exc:
            self._record_read_error(collection, operation="read_batch",
                                    error_type=type(exc).__name__,
                                    reason=f"{len(keys)} document(s) could not be read")
            raise
        for key, result in zip(keys, results):
            name = str(_dec(key))
            if isinstance(result, BaseException):
                self._record_read_error(collection, item_id=name, operation="read",
                                        error_type=type(result).__name__,
                                        reason="the document could not be read")
                continue
            if not result:
                continue  # removed between SCAN and the read
            chunk = (self._json_chunk(collection, info, name, result, paths) if is_json
                     else self._hash_chunk(collection, info, name, result))
            if chunk is None:
                self._record_read_error(collection, item_id=name, operation="decode",
                                        error_type="UndecodableDocument",
                                        reason="the document's JSON could not be parsed")
                continue
            yield chunk

    def _hash_chunk(self, collection: str, info: dict, key: str, raw: dict) -> Chunk:
        fields = {str(_dec(k)): v for k, v in raw.items()}
        vec_field = info["vec"]["identifier"] if info["vec"] else None
        text_field = info["text"]["identifier"] if info["text"] else None
        if text_field is None:
            text_field = next((k for k in _TEXT_KEYS if k in fields), None)
        emb = (decode_vector(fields.get(vec_field), info["vec"]["data_type"])
               if vec_field else None)
        txt = fields.get(text_field) if text_field else None
        return Chunk(id=key, collection=collection,
                     text=_dec(txt) if txt is not None else None, embedding=emb,
                     metadata={k: _dec(v) for k, v in fields.items()
                               if k not in (vec_field, text_field)})

    def _json_chunk(self, collection: str, info: dict, key: str, raw: Any,
                    paths: list[str]) -> Optional[Chunk]:
        try:
            parsed = json.loads(_dec(raw)) if isinstance(raw, (bytes, str)) else raw
        except ValueError:
            return None
        by_path = parsed if isinstance(parsed, dict) and "$" in parsed else {"$": parsed}
        docs = by_path.get("$")
        doc = docs[0] if isinstance(docs, list) and docs else docs
        if not isinstance(doc, dict):
            doc = {"$": doc}

        def first(entry: Optional[dict]) -> Any:
            if not entry:
                return None
            path = _json_path(entry["identifier"])
            matches = by_path.get(path)
            if isinstance(matches, list):
                return matches[0] if matches else None
            return _simple_path_get(doc, path)

        vec_path = _json_path(info["vec"]["identifier"]) if info["vec"] else None
        text_path = _json_path(info["text"]["identifier"]) if info["text"] else None
        text = first(info["text"])
        if text is None and info["text"] is None:
            text_path = next((f"$.{k}" for k in _TEXT_KEYS if isinstance(doc.get(k), str)),
                             None)
            text = doc.get(_top_key(text_path)) if text_path else None
        drop = {_top_key(vec_path), _top_key(text_path)}
        return Chunk(id=key, collection=collection,
                     text=text if isinstance(text, str) else None,
                     embedding=_json_floats(first(info["vec"])),
                     metadata={k: v for k, v in doc.items() if k not in drop})

    # ------------------------------------------------------------ query -- #

    def _filter(self, collection: str, info: dict, where: dict[str, Any]) -> str:
        clauses = []
        by_identifier = {f["identifier"]: f for f in info["fields"].values()}
        for key, value in where.items():
            field = (info["fields"].get(key) or by_identifier.get(key)
                     or by_identifier.get(f"$.{key}"))
            if field is None:
                raise UnsupportedCapability(
                    f"redis: {key!r} is not a field of index {collection!r}, so a "
                    "filter on it cannot be applied")
            ref = _field_ref(field["alias"])
            if field["type"] == "TAG":
                clauses.append(f"@{ref}:{{{_tag_value(value)}}}")
            elif field["type"] == "NUMERIC":
                number = _numeric_value(value)
                clauses.append(f"@{ref}:[{number} {number}]")
            else:
                raise UnsupportedCapability(
                    f"redis: {field['type'] or 'untyped'} field {key!r} cannot be "
                    "matched exactly; only TAG and NUMERIC filters are applied")
        return " ".join(clauses)

    def query(self, collection: str, vector: list[float], top_k: int = 10,
              where: Optional[dict[str, Any]] = None) -> list[QueryHit]:
        from redis.commands.search.query import Query
        info = self._info(collection)
        if not info["vec"]:
            raise UnsupportedCapability(f"redis: index {collection!r} has no vector field")
        # Values come from stored metadata; escaped so one cannot rewrite the
        # query (TAG syntax treats punctuation as operators).
        pre = self._filter(collection, info, where) if where else "*"
        vec_ref = _field_ref(info["vec"]["alias"])
        q = (Query(f"({pre})=>[KNN {top_k} @{vec_ref} $vec AS _score]")
             .sort_by("_score").dialect(2).paging(0, top_k))
        blob = encode_vector(vector, info["vec"]["data_type"])
        res = self._call(lambda: self._r.ft(collection).search(
            q, query_params={"vec": blob}))
        is_json = info["key_type"] == "JSON"
        vec_id = info["vec"]["identifier"]
        text_id = info["text"]["identifier"] if info["text"] else None
        hits = []
        for d in res.docs:
            fields = {k: v for k, v in d.__dict__.items() if k not in ("id", "payload")}
            score = float(_dec(fields.pop("_score", 0)) or 0)
            if is_json and ("$" in fields or "json" in fields):
                raw = fields.get("$", fields.get("json"))
                try:
                    doc = json.loads(_dec(raw)) if raw is not None else {}
                except ValueError:
                    doc = {}
                doc = doc[0] if isinstance(doc, list) and doc else doc
                doc = doc if isinstance(doc, dict) else {}
                text_path = _json_path(text_id) if text_id else None
                txt = _simple_path_get(doc, text_path) if text_path else None
                drop = {_top_key(_json_path(vec_id)), _top_key(text_path)}
                metadata = {k: v for k, v in doc.items() if k not in drop}
            else:
                txt = fields.get(text_id) if text_id else None
                txt = _dec(txt) if txt is not None else None
                metadata = {k: _dec(v) for k, v in fields.items()
                            if k not in (vec_id, info["vec"]["alias"], text_id)}
            hits.append(QueryHit(id=_dec(d.id), score=1.0 / (1.0 + score),
                                 text=txt if isinstance(txt, str) else None,
                                 metadata=metadata))
        return hits

    # ------------------------------------------------------------ writes -- #

    def _key_scope(self, index: str) -> tuple[list[str], str]:
        """The key prefixes and key type the index covers, from ``FT.INFO``.

        Read fresh (not from the layout cache): this decides which keys a
        delete may touch. Raises ``RedisDeleteRefused`` when the definition
        cannot be read, so an unknown scope never means "any key".
        """
        try:
            raw = self._r.ft(index).info()
        except Exception as exc:  # noqa: BLE001 - reported as a refusal
            raise RedisDeleteRefused(
                f"index {index!r} definition could not be read "
                f"({type(exc).__name__}); nothing was deleted") from exc
        prefixes, key_type = _definition(raw if isinstance(raw, dict) else {})
        if prefixes is None:
            raise RedisDeleteRefused(
                f"index {index!r} reports no key prefixes; nothing was deleted")
        return prefixes, key_type

    def delete_chunks(self, collection: str, ids: list[str]) -> int:
        """Delete document keys, but only keys that belong to ``collection``.

        ``DEL`` takes any key name, so ids are checked against the index's own
        key prefixes (``FT.INFO``) first. If any id falls outside them, the
        whole batch is refused and nothing is deleted: an id from another
        index or an unrelated key is a sign the request is wrong. For an index
        with an empty (catch-all) prefix, each key must also be of the index's
        key type. The customer's Redis ACL key pattern (``~<prefix>*``) remains
        the backstop.
        """
        if not ids:
            return 0
        prefixes, key_type = self._key_scope(collection)
        keys = [str(i) for i in ids]
        wildcard = not prefixes or any(p == "" for p in prefixes)
        if wildcard:
            pipe = self._r.pipeline()
            for key in keys:
                pipe.type(key)
            types = [str(_dec(t)).upper() for t in pipe.execute()]
            outside = [k for k, t in zip(keys, types) if t != key_type]
            rule = f"not {key_type} keys indexed by {collection!r}"
        else:
            outside = [k for k in keys if not any(k.startswith(p) for p in prefixes)]
            rule = (f"outside index {collection!r} key prefixes "
                    f"({', '.join(prefixes)})")
        if outside:
            raise RedisDeleteRefused(
                f"refused {len(outside)} of {len(keys)} id(s) {rule}; "
                f"nothing was deleted", refused=len(outside), requested=len(keys))
        deleted = self._r.delete(*keys)
        return int(deleted)

    def close(self) -> None:
        try:
            self._r.close()
        except Exception:  # pragma: no cover
            pass
