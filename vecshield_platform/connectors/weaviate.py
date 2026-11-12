"""Weaviate connector (v4 client).

Each Weaviate collection (class) maps to a VecShield collection. Connects to a
local instance (host/port + grpc), to Weaviate Cloud (``*.weaviate.cloud`` /
``*.weaviate.network`` URLs, whose gRPC host the client derives), or to a
custom endpoint with an API key. weaviate-client imported lazily.

Multi-tenant collections
------------------------
A collection with ``multi_tenancy_config.enabled`` keeps each tenant in its
own shard, and every read must name a tenant. Only ACTIVE tenants are read.
INACTIVE, OFFLOADED and in-transit tenants are recorded in ``read_errors()``
for the collection and never touched: reading one with auto-activation on
would activate it, which is a change to the customer's store.

A chunk read from a tenant carries its tenant in two places:

* its id is ``"<tenant>:<uuid>"`` (Weaviate tenant names cannot contain
  ``:``), so ``delete_chunks()`` deletes from exactly that tenant's shard.
  Two tenants can hold objects with the same uuid, so a bare uuid on a
  multi-tenant collection is never deleted: guessing the tenant could remove
  another tenant's object. Collections without multi-tenancy keep bare uuids.
* its metadata holds ``_tenant``. ``query()`` routes a ``where`` containing
  ``_tenant`` to that tenant's shard; without one, it queries every ACTIVE
  tenant and merges the results by score.

Named vectors
-------------
When a collection declares named vectors, one dense vector is used throughout
(enumeration, dimension and ``target_vector`` on queries): the first named
vector that is not a multi-vector, in the order the schema lists them.
"""

from __future__ import annotations

from typing import Any, Callable, Iterator, Optional, TypeVar
from urllib.parse import urlparse

from vecshield_platform.connectors.base import (
    Connector,
    ConnectorAuthError,
    ConnectorError,
    ConnectorTimeout,
    ConnectorUnavailable,
    ErrorRegistry,
    mapped_call,
    mapped_errors,
    retry_read,
)
from vecshield_platform.connectors.redact import redact_credentials
from vecshield.models import Chunk, Collection, QueryHit, VectorStore

_TEXT_KEYS = ("content", "text", "document", "chunk", "body", "passage", "page_content")

#: weaviate-client exceptions by class name, so the module imports without it.
#: UnexpectedStatusCodeError and its subclasses carry ``status_code`` and are
#: mapped from it by the shared translator.
_ERRORS: ErrorRegistry = {
    "AuthenticationFailedError": ConnectorAuthError,
    "InsufficientPermissionsError": ConnectorAuthError,
    "WeaviateTimeoutError": ConnectorTimeout,
    "WeaviateConnectionError": ConnectorUnavailable,
    "WeaviateGRPCUnavailableError": ConnectorUnavailable,
    "WeaviateRetryError": ConnectorUnavailable,
}

#: Chunk metadata key, and ``where`` key on query(), naming a chunk's tenant.
TENANT_KEY = "_tenant"
_ID_SEP = ":"
#: Tenant states whose shard can be read without activating it. The client
#: reports the deprecated HOT as ACTIVE; both are accepted.
_READABLE_TENANT_STATES = frozenset({"ACTIVE", "HOT"})
_CLOUD_SUFFIXES = (".weaviate.cloud", ".weaviate.network")

_T = TypeVar("_T")


class WeaviateConnector(Connector):
    kind = "weaviate"
    #: QUERY_MAXIMUM_RESULTS, "the maximum total number of objects that can be
    #: retrieved", defaults to 10,000 (Weaviate environment variables docs). A
    #: server configured lower returns fewer, which reads as partial, not clean.
    max_top_k = 10000

    def __init__(
        self,
        *,
        host: str = "localhost",
        port: int = 8080,
        grpc_port: int = 50051,
        url: Optional[str] = None,
        api_key: Optional[str] = None,
        secure: bool = False,
        grpc_host: Optional[str] = None,
    ):
        try:
            import weaviate
            from weaviate.classes.init import Auth
        except ImportError as e:  # pragma: no cover
            raise ImportError("weaviate-client not installed. pip install 'vecshield[weaviate]'") from e

        self._read_errors: list[dict] = []
        self._layouts: dict[str, dict[str, Any]] = {}
        auth = Auth.api_key(api_key) if api_key else None
        if url:
            # A bare cluster hostname is how Weaviate Cloud's console shows it.
            normalized = url if "://" in url else f"https://{url}"
            u = urlparse(normalized)
            host = u.hostname or host
            # Weaviate Cloud's helper requires credentials; without a key the
            # custom connect below is used, as before.
            if is_weaviate_cloud(host) and not grpc_host and auth is not None:
                # WCD serves gRPC on a sibling host (grpc-<cluster> or
                # <id>.grpc.<domain>); connect_to_custom pointed gRPC at the
                # HTTP host, which WCD does not answer.
                self._client = weaviate.connect_to_weaviate_cloud(
                    cluster_url=host, auth_credentials=auth, skip_init_checks=True)
                self._endpoint = redact_credentials(normalized)
                self._transport = {"tls": True, "source": "endpoint", "scheme": "https"}
                return
            port = u.port or (443 if u.scheme == "https" else port)
            secure = u.scheme == "https"
            self._client = weaviate.connect_to_custom(
                http_host=host, http_port=port, http_secure=secure,
                grpc_host=grpc_host or host, grpc_port=grpc_port, grpc_secure=secure,
                auth_credentials=auth, skip_init_checks=True)
            self._endpoint = redact_credentials(normalized)
            self._transport = {"tls": secure, "source": "endpoint"}
        elif secure or (grpc_host and grpc_host != host):
            # connect_to_local() can neither speak TLS nor take a separate
            # gRPC host, so `secure` used to be dropped silently on this path.
            self._client = weaviate.connect_to_custom(
                http_host=host, http_port=port, http_secure=bool(secure),
                grpc_host=grpc_host or host, grpc_port=grpc_port, grpc_secure=bool(secure),
                auth_credentials=auth, skip_init_checks=True)
            # Endpoint string unchanged: finding fingerprints are keyed on it.
            self._endpoint = f"http://{host}:{port}"
            self._transport = {"tls": bool(secure), "source": "connector_flag",
                               "scheme": "https" if secure else "http"}
        else:
            self._client = weaviate.connect_to_local(
                host=host, port=port, grpc_port=grpc_port, auth_credentials=auth,
                skip_init_checks=True)
            self._endpoint = f"http://{host}:{port}"
            self._transport = {"tls": False, "source": "connector_flag", "scheme": "http"}

    def capabilities(self) -> set[str]:
        return {"query", "delete"}

    # ---- helpers --------------------------------------------------------- #

    def _read(self, fn: Callable[[], _T]) -> _T:
        """An idempotent read, with SDK errors mapped and transient ones retried."""
        return retry_read(mapped_call(fn, kind=self.kind, extra=_ERRORS))

    def _layout(self, name: str, config: Any = None) -> dict[str, Any]:
        """Multi-tenancy and the dense vector to use, from the collection config.

        ``multi_tenancy`` is None when the config could not be read; reads then
        go out without a tenant, which a multi-tenant collection refuses, so
        the failure surfaces rather than reading as an empty collection.
        """
        cached = self._layouts.get(name)
        if cached is not None:
            return cached
        if config is None:
            try:
                config = self._read(lambda: self._client.collections.get(name).config.get())
            except ConnectorAuthError:
                raise
            except Exception:  # noqa: BLE001 - unknown layout, not cached
                return {"multi_tenancy": None, "target_vector": None}
        layout = {"multi_tenancy": _multi_tenancy_enabled(config),
                  "target_vector": _dense_vector_name(config)}
        self._layouts[name] = layout
        return layout

    def _tenant_state(self, col) -> tuple[list[str], list[tuple[str, str]]]:
        """(ACTIVE tenant names, [(other tenant name, its state)]), both sorted."""
        tenants = self._read(lambda: col.tenants.get()) or {}
        active: list[str] = []
        inactive: list[tuple[str, str]] = []
        for name in sorted(tenants):
            state = _state_name(getattr(tenants[name], "activity_status", None))
            if state in _READABLE_TENANT_STATES:
                active.append(str(name))
            else:
                inactive.append((str(name), state or "UNKNOWN"))
        return active, inactive

    # ---- inventory -------------------------------------------------------- #

    def describe(self) -> VectorStore:
        transport = getattr(self, "_transport", None)
        return VectorStore(kind=self.kind, name=self._endpoint, endpoint=self._endpoint,
                           collections=self.list_collections(),
                           metadata={"transport": dict(transport)} if transport else {})

    def list_collections(self) -> list[Collection]:
        configs = self._read(lambda: self._client.collections.list_all(simple=False)) or {}
        out = []
        for name, config in configs.items():
            layout = self._layout(name, config)
            col = self._client.collections.get(name)
            metadata: dict[str, Any] = {}
            if layout["multi_tenancy"]:
                count, known, metadata, sample = self._count_tenants(col)
            else:
                count, known = self._count(col)
                sample = col
            if not known:
                count = 0
                metadata["count_known"] = False
            out.append(Collection(name=name, count=count, metadata=metadata,
                                  dimension=self._dim(sample, layout)))
        return out

    def _count(self, handle) -> tuple[int, bool]:
        try:
            total = self._read(lambda: handle.aggregate.over_all(total_count=True)).total_count
        except Exception:  # noqa: BLE001 - reported as an unknown count
            return 0, False
        if total is None:
            return 0, False
        return int(total), True

    def _count_tenants(self, col) -> tuple[int, bool, dict[str, Any], Any]:
        """Sum the ACTIVE tenants' counts. Known only when every tenant counted.

        An inactive tenant's objects cannot be counted without activating it,
        so its presence leaves the collection's total unknown.
        """
        metadata: dict[str, Any] = {"multi_tenancy": True}
        try:
            active, inactive = self._tenant_state(col)
        except Exception:  # noqa: BLE001 - tenants unreadable, count unknown
            metadata["tenants_readable"] = False
            return 0, False, metadata, None
        metadata.update(tenants=len(active) + len(inactive), tenants_active=len(active),
                        tenants_inactive=len(inactive))
        total, known = 0, not inactive
        for tenant in active:
            count, ok = self._count(col.with_tenant(tenant))
            total += count
            known = known and ok
        sample = col.with_tenant(active[0]) if active else None
        return total, known, metadata, sample

    def _dim(self, handle, layout: dict[str, Any]) -> Optional[int]:
        if handle is None:
            return None
        target = layout.get("target_vector")
        try:
            res = self._read(lambda: handle.query.fetch_objects(
                limit=1, include_vector=[target] if target else True))
            for obj in res.objects or []:
                v = _vec_of(obj.vector, target)
                return len(v) if v else None
        except Exception:  # noqa: BLE001 - dimension is descriptive only
            pass
        return None

    # ---- content ---------------------------------------------------------- #

    def iter_chunks(self, collection: str, batch_size: int = 256) -> Iterator[Chunk]:
        col = self._client.collections.get(collection)
        layout = self._layout(collection)
        if not layout["multi_tenancy"]:
            yield from self._iter_objects(col, collection, None, layout, batch_size)
            return
        active, inactive = self._tenant_state(col)
        for tenant, state in inactive:
            self._record_read_error(
                collection, tenant=tenant, tenant_state=state, operation="iter_chunks",
                error_type="TenantNotActive",
                reason=(f"Tenant is {state}. VecShield does not activate tenants, so "
                        "its objects were not read."))
        for tenant in active:
            try:
                yield from self._iter_objects(col.with_tenant(tenant), collection, tenant,
                                              layout, batch_size)
            except ConnectorAuthError:
                raise
            except Exception as exc:  # noqa: BLE001 - recorded; other tenants still read
                self._record_read_error(
                    collection, tenant=tenant, operation="iter_chunks",
                    error_type=type(exc).__name__,
                    reason="Reading this tenant failed; its remaining objects were not read.")

    def _iter_objects(self, handle, collection: str, tenant: Optional[str],
                      layout: dict[str, Any], batch_size: int) -> Iterator[Chunk]:
        """Cursor paging (``after``) over one shard, one retried read per page."""
        target = layout.get("target_vector")
        include: Any = [target] if target else True
        limit = max(1, int(batch_size))
        after = None
        while True:
            res = self._read(lambda: handle.query.fetch_objects(
                limit=limit, after=after, include_vector=include))
            objs = list(res.objects or [])
            for obj in objs:
                yield self._chunk(obj, collection, tenant, target)
            if len(objs) < limit:
                return
            after = objs[-1].uuid

    @staticmethod
    def _chunk(obj, collection: str, tenant: Optional[str], target: Optional[str]) -> Chunk:
        props = dict(obj.properties or {})
        metadata = dict(props)
        cid = str(obj.uuid)
        if tenant is not None:
            metadata[TENANT_KEY] = tenant
            cid = f"{tenant}{_ID_SEP}{cid}"
        return Chunk(id=cid, collection=collection, text=_text_of(props),
                     embedding=_vec_of(obj.vector, target), metadata=metadata)

    def query(self, collection: str, vector: list[float], top_k: int = 10,
              where: Optional[dict[str, Any]] = None) -> list[QueryHit]:
        from weaviate.classes.query import Filter, MetadataQuery
        col = self._client.collections.get(collection)
        layout = self._layout(collection)
        where = dict(where or {})
        tenant = where.pop(TENANT_KEY, None) if layout["multi_tenancy"] else None
        flt = None
        if where:
            conds = [Filter.by_property(k).equal(v) for k, v in where.items()]
            flt = conds[0] if len(conds) == 1 else Filter.all_of(conds)
        kwargs: dict[str, Any] = {"near_vector": vector, "limit": top_k, "filters": flt,
                                  "return_metadata": MetadataQuery(distance=True)}
        if layout["target_vector"]:
            kwargs["target_vector"] = layout["target_vector"]

        def run(handle, shard: Optional[str]) -> list[QueryHit]:
            res = self._read(lambda: handle.query.near_vector(**kwargs))
            return [self._hit(o, shard) for o in res.objects or []]

        if not layout["multi_tenancy"]:
            return run(col, None)
        active, inactive = self._tenant_state(col)
        if tenant is not None:
            tenant = str(tenant)
            if tenant in active:
                return run(col.with_tenant(tenant), tenant)
            if any(name == tenant for name, _ in inactive):
                raise ConnectorError(
                    "weaviate: the requested tenant is not active, and VecShield does "
                    "not activate tenants")
            return []  # no such tenant: there is no shard to return anything from
        # No tenant named: every ACTIVE shard, merged as one ranking.
        hits: list[QueryHit] = []
        for name in active:
            hits.extend(run(col.with_tenant(name), name))
        hits.sort(key=lambda h: h.score, reverse=True)
        return hits[:top_k]

    @staticmethod
    def _hit(obj, tenant: Optional[str]) -> QueryHit:
        props = dict(obj.properties or {})
        metadata = dict(props)
        cid = str(obj.uuid)
        if tenant is not None:
            metadata[TENANT_KEY] = tenant
            cid = f"{tenant}{_ID_SEP}{cid}"
        dist = getattr(obj.metadata, "distance", None)
        # Higher is closer. Weaviate's dot distance is the negative dot product
        # and can be zero or negative, so 1/(1+d) divided by zero or flipped
        # the ranking; the negated distance orders correctly for every metric.
        score = -float(dist) if dist is not None else 0.0
        return QueryHit(id=cid, score=score, text=_text_of(props), metadata=metadata)

    def delete_chunks(self, collection: str, ids: list[str]) -> int:
        """Delete by id; the count is the deletes Weaviate confirmed (HTTP 204).

        ``delete_by_id`` returns False for an object that was not there (404),
        which used to be counted as deleted. On a multi-tenant collection each
        id names its tenant (``tenant:uuid``); bare uuids and ids naming an
        inactive tenant are not deleted, and the shortfall shows in the count.
        """
        import uuid as _uuid
        col = self._client.collections.get(collection)
        layout = self._layout(collection)
        multi = bool(layout["multi_tenancy"])
        active: Optional[set[str]] = None
        if multi:
            active = set(self._tenant_state(col)[0])
        deleted = 0
        for raw in ids:
            tenant, _, uid = str(raw).rpartition(_ID_SEP) if multi else (None, "", str(raw))
            if multi and (not tenant or active is None or tenant not in active):
                continue
            try:
                key = _uuid.UUID(uid)
            except ValueError:
                continue
            handle = col.with_tenant(tenant) if multi and tenant else col
            try:
                with mapped_errors(self.kind, _ERRORS):
                    ok = handle.data.delete_by_id(key)
            except ConnectorAuthError:
                raise  # every later delete would fail the same way
            except Exception:  # noqa: BLE001 - not confirmed, so not counted
                continue
            if ok is True:
                deleted += 1
        return deleted

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:  # pragma: no cover
            pass


def is_weaviate_cloud(host: Optional[str]) -> bool:
    """Whether ``host`` is a Weaviate Cloud cluster hostname."""
    h = (host or "").lower().rstrip(".")
    return any(h.endswith(s) for s in _CLOUD_SUFFIXES)


def _multi_tenancy_enabled(config: Any) -> Optional[bool]:
    if config is None:
        return None
    mt = getattr(config, "multi_tenancy_config", None)
    return bool(getattr(mt, "enabled", False))


def _dense_vector_name(config: Any) -> Optional[str]:
    """The first named vector that is a single dense vector, or None.

    None also for collections with the legacy unnamed vector, which take no
    ``target_vector``.
    """
    named = getattr(config, "vector_config", None)
    if not isinstance(named, dict) or not named:
        return None
    for name, vc in named.items():
        index = getattr(vc, "vector_index_config", None)
        if getattr(index, "multi_vector", None) is None:
            return str(name)
    return None


def _state_name(status: Any) -> Optional[str]:
    if status is None:
        return None
    value = getattr(status, "value", status)
    return str(value).upper()


def _text_of(props: dict) -> Optional[str]:
    for k in _TEXT_KEYS:
        v = props.get(k)
        if isinstance(v, str):
            return v
    return None


def _is_dense(vector: Any) -> bool:
    if not isinstance(vector, (list, tuple)) or not vector:
        return False
    return not isinstance(vector[0], (list, tuple))


def _vec_of(vector: Any, target: Optional[str] = None) -> Optional[list[float]]:
    """The dense vector to use: ``target`` when named, else the default one.

    Multi-vectors (a list of vectors per object) are not a single embedding
    and come back as None rather than being flattened into one.
    """
    if vector is None:
        return None
    if isinstance(vector, dict):
        if target is not None:
            vector = vector.get(target)
        else:
            vector = vector.get("default") if _is_dense(vector.get("default")) else next(
                (v for v in vector.values() if _is_dense(v)), None)
    if not _is_dense(vector):
        return None
    try:
        return [float(x) for x in vector]
    except (TypeError, ValueError):
        return None
