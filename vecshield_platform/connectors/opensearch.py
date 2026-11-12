"""OpenSearch vector (k-NN) connector.

Each index with a knn_vector field = a collection; the field may sit inside an
object or ``nested`` property. Reads raw vectors from _source (full mode).
Also the common landing store for Bedrock Knowledge Bases.
opensearch-py imported lazily.
"""

from __future__ import annotations

import copy
import fnmatch
import json
import re
from typing import Any, Iterator, Optional

from vecshield_platform.connectors.base import (
    AtRestObservation,
    Connector,
    ConnectorAuthError,
    ConnectorError,
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
from vecshield_platform.connectors.redact import redact_credentials
from vecshield_platform.store_facts.opensearch import knn_fields
from vecshield.models import ApiKey, Chunk, Collection, QueryHit, VectorStore

#: opensearch-py exceptions, by class name. TransportError subclasses carry
#: the HTTP status as ``status_code`` too, which the shared mapper reads.
#: A certificate failure is not transient: it maps to the base error, which
#: is never retried.
_ERRORS: ErrorRegistry = {
    "AuthenticationException": ConnectorAuthError,
    "AuthorizationException": ConnectorAuthError,
    "NotFoundError": ConnectorNotFound,
    "ConnectionTimeout": ConnectorTimeout,
    "SSLError": ConnectorError,
    "ConnectionError": ConnectorUnavailable,
}

#: Field types a ``term`` query matches exactly. ``text`` is analysed, so a
#: term on it matches tokens, not the stored value.
_EXACT_TYPES = frozenset({
    "keyword", "constant_keyword", "wildcard", "long", "integer", "short", "byte",
    "double", "float", "half_float", "scaled_float", "unsigned_long", "boolean",
    "date", "date_nanos", "ip", "version"})
_ANALYSED_TYPES = frozenset({"text", "match_only_text"})

# Characters OpenSearch forbids in index names, plus the multi-target syntax
# (wildcards, comma lists) that would let one "collection" name several indices.
_BAD_INDEX_CHARS = re.compile(r'[*?,\s"\\/<>|#:]')

_TEXT_KEYS = ("content", "text", "document", "chunk", "body", "passage", "page_content",
              "amazon_bedrock_text_chunk", "amazon_bedrock_text")


class OpenSearchConnector(Connector):
    kind = "opensearch"
    #: k-NN query "k" accepts at most 10,000, and "size" is bounded by the
    #: index.max_result_window default of 10,000 (OpenSearch k-NN docs).
    max_top_k = 10000

    def __init__(self, *, host: str = "localhost", port: int = 9200,
                 url: Optional[str] = None, user: Optional[str] = None,
                 password: Optional[str] = None, use_ssl: bool = False,
                 verify_certs: Optional[bool] = None):
        try:
            from opensearchpy import OpenSearch
        except ImportError as e:  # pragma: no cover
            raise ImportError("opensearch-py not installed. pip install 'vecshield[opensearch]'") from e
        auth = (user, password) if user else None
        tls = url.lower().startswith("https://") if url else bool(use_ssl)
        # Certificates are verified on every TLS connection unless the store's
        # configuration turns it off explicitly. A plaintext connection has no
        # certificate, so there is nothing to verify.
        if verify_certs is None:
            verify_certs = tls
        verify_certs = bool(verify_certs)
        if url:
            self._c = OpenSearch(hosts=[url], http_auth=auth, verify_certs=verify_certs)
            self._endpoint = redact_credentials(url)
            self._transport = {"tls": url.lower().startswith("https://"),
                               "source": "endpoint", "verify_certs": bool(verify_certs)}
        else:
            self._c = OpenSearch(hosts=[{"host": host, "port": port}], http_auth=auth,
                                 use_ssl=use_ssl, verify_certs=verify_certs)
            self._endpoint = f"http{'s' if use_ssl else ''}://{host}:{port}"
            self._transport = {"tls": bool(use_ssl), "source": "connector_flag",
                               "use_ssl": bool(use_ssl), "verify_certs": bool(verify_certs)}
        if self._transport["tls"] and not verify_certs:
            # Encrypted but unauthenticated: anyone on the path can present a cert.
            self._transport["certificate_verification"] = False
        self._layout: dict[str, dict] = {}

    def capabilities(self) -> set[str]:
        return {"query", "delete", "api_keys", "at_rest_introspection"}

    def at_rest_encryption_state(self, collection: Optional[str] = None) -> AtRestObservation:
        """The storage-encryption plugin's ``cryptofs`` store type, per index.

        Domain, node or disk encryption beneath OpenSearch (e.g. Amazon
        OpenSearch Service encryption at rest) is not reported through index
        settings, so an index on the plain store is not observable, never
        disabled.
        """
        source = "index.store.type"
        if collection is None:
            evidence = {}
            plugin = self._storage_plugin_installed()
            if plugin is not None:
                evidence["storage_encryption_plugin_installed"] = plugin
            return AtRestObservation(
                state="not_observable", scope="store", source=source, per_collection=True,
                evidence=evidence,
                reason="the storage type is set per index; each index is reported "
                       "separately")
        try:
            raw = self._c.indices.get_settings(index=collection, include_defaults=True,
                                               flat_settings=True)
        except Exception as exc:  # noqa: BLE001
            return AtRestObservation(
                state="error", scope="collection", collection=collection, source=source,
                reason=f"the index settings could not be read ({type(exc).__name__})")
        entry: dict[str, Any] = ((raw or {}).get(collection)
                                 or next(iter((raw or {}).values()), {}) or {})
        settings = {**_flatten(entry.get("defaults") or {}),
                    **_flatten(entry.get("settings") or {})}
        store_type = settings.get("index.store.type")
        if str(store_type or "").lower() == "cryptofs":
            crypto = {name: settings.get(f"index.store.crypto.{key}")
                      for name, key in (("key_provider", "key_provider"),
                                        ("kms_type", "kms.type"))}
            return AtRestObservation(
                state="enabled", scope="collection", collection=collection, source=source,
                mechanism="storage-encryption plugin (cryptofs, pre-release)",
                key_reference=mask_reference(settings.get("index.store.crypto.kms.key_arn")),
                evidence={k: v for k, v in crypto.items() if v},
                reason="the index is stored with the storage-encryption plugin")
        return AtRestObservation(
            state="not_observable", scope="collection", collection=collection,
            source=source, evidence={"store_type": store_type} if store_type else {},
            reason="This index is not stored with the storage-encryption plugin. Disk "
                   "or domain encryption beneath OpenSearch is not visible here; "
                   "provide that configuration as evidence.")

    def _storage_plugin_installed(self) -> Optional[bool]:
        try:
            rows = self._c.cat.plugins(format="json")
        except Exception:  # noqa: BLE001 - presence is context, not evidence
            return None
        return any("storage-encryption" in str(r.get("component", "")).lower()
                   for r in rows or [] if isinstance(r, dict))

    def describe(self) -> VectorStore:
        transport = getattr(self, "_transport", None)
        return VectorStore(kind=self.kind, name=self._endpoint, endpoint=self._endpoint,
                           collections=self.list_collections(),
                           metadata={"transport": dict(transport)} if transport else {})

    def _read(self, fn: Any) -> Any:
        """An idempotent read, error-mapped and retried on transient failure."""
        return retry_read(mapped_call(fn, kind=self.kind, extra=_ERRORS))

    def _layout_of(self, index: str) -> dict:
        _index_name(index)
        if index in self._layout:
            return self._layout[index]
        mp = self._read(lambda: self._c.indices.get_mapping(index=index)) or {}
        entry: dict = mp.get(index) or next(iter(mp.values()), {}) or {}
        props = (entry.get("mappings", {}) or {}).get("properties", {}) or {}
        vectors = knn_fields(props)
        # A top-level vector is preferred; otherwise the first nested one.
        top = [p for p in vectors if "." not in p]
        vec = top[0] if top else next(iter(vectors), None)
        dim = vectors[vec].get("dimension") if vec else None
        fields = _field_index(props)
        text = None
        for name, spec in props.items():
            if (isinstance(spec, dict) and spec.get("type") in ("text", "keyword")
                    and name.lower() in _TEXT_KEYS and text is None):
                text = name
        if not text:  # any text field
            text = next((n for n, s in props.items()
                         if isinstance(s, dict) and s.get("type") in ("text", "keyword")),
                        None)
        self._layout[index] = {
            "vec": vec, "text": text, "dim": dim,
            "vec_nested": (fields.get(vec) or {}).get("nested") if vec else None,
            "vectors": list(vectors), "fields": fields}
        return self._layout[index]

    def _indices(self) -> list[str]:
        listed = self._read(lambda: self._c.indices.get(index="*")) or {}
        return [i for i in listed if not i.startswith(".")]

    def list_collections(self) -> list[Collection]:
        out = []
        for idx in self._indices():
            try:
                lay = self._layout_of(idx)
            except Exception as exc:  # noqa: BLE001 - listed as unknown, never dropped
                self._record_read_error(idx, operation="get_mapping",
                                        error_type=type(exc).__name__,
                                        reason="the index mapping could not be read, so "
                                               "whether it holds vectors is unknown")
                out.append(Collection(name=idx, count=0, dimension=None,
                                      metadata={"count_known": False,
                                                "mapping_readable": False}))
                continue
            if not lay["vec"]:
                continue  # not a vector index
            metadata: dict[str, Any] = {"vector_field": lay["vec"]}
            if lay.get("vec_nested"):
                metadata["vector_nested_path"] = lay["vec_nested"]
            if len(lay.get("vectors") or []) > 1:
                metadata["vector_fields"] = list(lay["vectors"])
            try:
                cnt = int(self._read(lambda: self._c.count(index=idx)).get("count", 0))
            except Exception as exc:  # noqa: BLE001 - a count is not read as zero
                cnt = 0
                metadata.update(count_known=False, count_error=type(exc).__name__)
            out.append(Collection(name=idx, count=cnt, dimension=lay["dim"],
                                  metadata=metadata))
        return out

    def iter_chunks(self, collection: str, batch_size: int = 256) -> Iterator[Chunk]:
        _index_name(collection)
        lay = self._layout_of(collection)
        # Use the Scroll API rather than from+size: from+size is capped by
        # index.max_result_window (10k by default), which silently truncated
        # large indices. Scroll walks the entire index in batches. The first
        # search is retried; a scroll continuation is not, because a retried
        # continuation the server already served would skip a page.
        res = self._read(lambda: self._c.search(
            index=collection, scroll="2m",
            body={"size": batch_size, "query": {"match_all": {}}},
        ))
        scroll_id = res.get("_scroll_id")
        try:
            while True:
                hits = res.get("hits", {}).get("hits", [])
                if not hits:
                    break
                for h in hits:
                    src = h.get("_source", {}) or {}
                    emb = _vector_at(src, lay["vec"]) if lay["vec"] else None
                    yield Chunk(id=str(h.get("_id")), collection=collection,
                                text=src.get(lay["text"]) if lay["text"] else None,
                                embedding=[float(x) for x in emb] if emb else None,
                                metadata=_without_path(src, lay["vec"]))
                if not scroll_id:
                    break
                sid = scroll_id
                with mapped_errors(self.kind, _ERRORS):
                    res = self._c.scroll(body={"scroll_id": sid, "scroll": "2m"})
                scroll_id = res.get("_scroll_id")
        finally:
            if scroll_id:
                try:
                    self._c.clear_scroll(body={"scroll_id": [scroll_id]})
                except Exception:  # pragma: no cover - best-effort cleanup
                    pass

    def delete_chunks(self, collection: str, ids: list[str]) -> int:
        _index_name(collection)
        if not ids:
            return 0
        # Serialised, never formatted: an id holding a quote, backslash or
        # newline must stay one value inside one action line.
        body = "".join(
            json.dumps({"delete": {"_index": collection, "_id": str(_id)}}) + "\n"
            for _id in ids
        )
        with mapped_errors(self.kind, _ERRORS):
            resp = self._c.bulk(body=body)
        deleted = sum(
            1 for item in resp.get("items", [])
            if item.get("delete", {}).get("result") == "deleted"
        )
        return deleted

    def list_api_keys(self) -> list[ApiKey]:
        """Internal users of the Security plugin, with their effective roles.

        A user's backend roles are not security roles: what a user may do is
        decided by the roles mapped to it in ``rolesmapping`` (by user name or
        backend role) plus any security roles assigned to it directly. When the
        mapping cannot be read, actions fall back to the direct and backend
        role names, and each key says its roles were not resolved.
        """
        try:
            resp = self._read(lambda: self._c.transport.perform_request(
                "GET", "/_plugins/_security/api/internalusers"))
        except (ConnectorTimeout, ConnectorUnavailable):
            raise
        except Exception as e:
            raise UnsupportedCapability(
                f"OpenSearch security plugin not available ({type(e).__name__})"
            ) from e
        mapping: Optional[dict] = None
        mapping_error: Optional[str] = None
        try:
            mapping = self._read(lambda: self._c.transport.perform_request(
                "GET", "/_plugins/_security/api/rolesmapping")) or {}
        except Exception as e:  # noqa: BLE001 - reported on every key
            mapping_error = type(e).__name__
        keys: list[ApiKey] = []
        for username, spec in (resp or {}).items():
            spec = spec or {}
            backend = [str(r) for r in spec.get("backend_roles", []) or []]
            direct = [str(r) for r in spec.get("opendistro_security_roles", []) or []]
            metadata: dict[str, Any] = {"backend_roles": backend,
                                        "security_roles": direct,
                                        "attributes": spec.get("attributes", {})}
            if mapping is not None:
                effective = sorted(set(direct) | _mapped_roles(mapping, username, backend))
                metadata.update(effective_roles=effective, roles_resolved=True)
                actions = _roles_to_actions(effective)
            else:
                metadata.update(roles_resolved=False, rolesmapping_error=mapping_error)
                actions = _roles_to_actions(backend + direct)
            keys.append(ApiKey(
                id=username,
                name=username,
                actions=actions,
                namespaces=["*"],
                metadata=metadata,
            ))
        return keys

    def query(self, collection: str, vector: list[float], top_k: int = 10,
              where: Optional[dict[str, Any]] = None) -> list[QueryHit]:
        _index_name(collection)
        lay = self._layout_of(collection)
        if not lay.get("vec"):
            raise UnsupportedCapability(
                f"opensearch: index {collection!r} has no knn_vector field")
        knn: dict[str, Any] = {"knn": {lay["vec"]: {"vector": vector, "k": top_k}}}
        if lay.get("vec_nested"):
            knn = {"nested": {"path": lay["vec_nested"], "query": knn}}
        if where:
            filt = [_term(lay, k, v) for k, v in where.items()]
            body = {"size": top_k, "query": {"bool": {"must": [knn], "filter": filt}}}
        else:
            body = {"size": top_k, "query": knn}
        res = self._read(lambda: self._c.search(index=collection, body=body))
        hits = []
        for h in res.get("hits", {}).get("hits", []):
            src = h.get("_source", {}) or {}
            hits.append(QueryHit(id=str(h.get("_id")), score=float(h.get("_score", 0.0)),
                                 text=src.get(lay["text"]) if lay["text"] else None,
                                 metadata=_without_path(src, lay["vec"])))
        return hits


def _field_index(props: Any, prefix: str = "",
                 nested: Optional[str] = None) -> dict[str, dict[str, Any]]:
    """Dotted path -> {type, keyword subfield, nearest nested ancestor}."""
    out: dict[str, dict[str, Any]] = {}
    for name, spec in (props or {}).items():
        if not isinstance(spec, dict):
            continue
        path = f"{prefix}.{name}" if prefix else str(name)
        kind = spec.get("type") or ("object" if "properties" in spec else None)
        subfields = spec.get("fields") or {}
        keyword_subs = [n for n, sub in subfields.items()
                        if isinstance(sub, dict) and sub.get("type") == "keyword"]
        keyword = None
        if keyword_subs:
            keyword = f"{path}.{'keyword' if 'keyword' in keyword_subs else keyword_subs[0]}"
        out[path] = {"type": kind, "keyword": keyword, "nested": nested}
        if isinstance(spec.get("properties"), dict):
            out.update(_field_index(spec["properties"], path,
                                    path if kind == "nested" else nested))
    return out


def _term(layout: dict, field: str, value: Any) -> dict[str, Any]:
    """An exact-match clause for ``field``, chosen from the index mapping.

    A ``keyword`` (or numeric, boolean, date...) field is matched as is; an
    analysed ``text`` field through its keyword subfield. A text field with no
    keyword subfield cannot be matched exactly, so the query is refused rather
    than run with a filter that silently matches nothing. A field the mapping
    does not know is used as named (no document holds it).
    """
    info = (layout.get("fields") or {}).get(field)
    target = field
    if info is not None:
        kind = info.get("type")
        if kind in _ANALYSED_TYPES:
            if not info.get("keyword"):
                raise UnsupportedCapability(
                    f"opensearch: {field!r} is analysed text with no keyword subfield; "
                    "an exact filter on it cannot be expressed")
            target = info["keyword"]
    clause: dict[str, Any] = ({"terms": {target: list(value)}}
                              if isinstance(value, (list, tuple))
                              else {"term": {target: value}})
    nested = (info or {}).get("nested")
    if nested:
        clause = {"nested": {"path": nested, "query": clause}}
    return clause


def _vector_at(src: dict, path: str) -> Any:
    """The vector at a dotted path in _source; the first one under a nested list."""
    if path in src:
        return src[path]
    cur: Any = src
    for part in path.split("."):
        if isinstance(cur, list):
            cur = next((item for item in cur if isinstance(item, dict) and part in item),
                       None)
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _without_path(src: dict, path: Optional[str]) -> dict:
    """_source without the vector at ``path`` (from every nested element)."""
    if not path:
        return dict(src)
    if path in src:
        return {k: v for k, v in src.items() if k != path}
    out = copy.deepcopy(src)

    def strip(node: Any, rest: list[str]) -> None:
        if isinstance(node, list):
            for item in node:
                strip(item, rest)
            return
        if not isinstance(node, dict):
            return
        if len(rest) == 1:
            node.pop(rest[0], None)
        elif rest[0] in node:
            strip(node[rest[0]], rest[1:])

    strip(out, path.split("."))
    return out


def _mapped_roles(mapping: dict, user: str, backend_roles: list[str]) -> set[str]:
    """Security roles ``rolesmapping`` grants a user, by name or backend role.

    Users and backend roles in a mapping may be wildcard patterns. A mapping
    with ``and_backend_roles`` applies only when the user holds every one.
    Host-based mappings depend on where a request comes from and are not
    applied here.
    """
    roles: set[str] = set()
    for role, spec in (mapping or {}).items():
        if not isinstance(spec, dict):
            continue
        users = [str(u) for u in spec.get("users", []) or []]
        backends = [str(b) for b in spec.get("backend_roles", []) or []]
        required = [str(b) for b in spec.get("and_backend_roles", []) or []]
        if any(fnmatch.fnmatchcase(user, u) for u in users) or any(
                fnmatch.fnmatchcase(b, pattern) for b in backend_roles
                for pattern in backends):
            roles.add(str(role))
        elif required and all(any(fnmatch.fnmatchcase(b, pattern) for b in backend_roles)
                              for pattern in required):
            roles.add(str(role))
    return roles


def _index_name(name: str) -> str:
    """One concrete, non-system index, or ValueError.

    Collections come from the listing, which skips ``.``-prefixed system
    indices; a caller-supplied name must not reach them, or several indices at
    once, through wildcards, comma lists, ``_all`` or ``-`` exclusions.
    """
    text = str(name)
    if (not text or text.startswith((".", "_", "-", "+"))
            or _BAD_INDEX_CHARS.search(text)):
        raise ValueError(f"invalid OpenSearch index name: {name!r}")
    return text


# OpenSearch security plugin role → VecShield action heuristic
_ADMIN_ROLES = {"all_access", "security_manager", "manage", "superuser"}
_WRITE_ROLES = {"readwrite", "crud", "write", "kibana_all_write"}


def _roles_to_actions(roles: list[str]) -> list[str]:
    lower = {r.lower() for r in roles}
    if lower & _ADMIN_ROLES:
        return ["read", "write", "delete", "admin"]
    acts = ["read"]
    if lower & _WRITE_ROLES:
        acts += ["write", "delete"]
    return acts


def _flatten(settings: dict, prefix: str = "") -> dict[str, Any]:
    """Nested or flat OpenSearch settings as dotted keys."""
    out: dict[str, Any] = {}
    for key, value in (settings or {}).items():
        path = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, dict):
            out.update(_flatten(value, path))
        else:
            out[path] = value
    return out
