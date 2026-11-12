"""Google Vertex AI Vector Search connector.

Vertex AI Vector Search stores dense embeddings in a managed index. Per-datapoint
text content is typically kept in the caller's backing store (GCS/BigQuery); the
index exposes IDs, vectors, and restricts (metadata). This connector operates in
inventory+query+delete mode:

  - list_collections(): list MatchingEngineIndexes in the configured project/location
  - iter_chunks(): inventory-only — returns empty (no bulk-ID enumeration API)
  - query(): via a MatchingEngineIndexEndpoint (requires endpoint_id kwarg),
    against the deployment of the requested index on that endpoint
  - delete_chunks(): remove_datapoints() by ID, on STREAM_UPDATE indexes only

Project, location and credentials are passed to every SDK constructor and
call. ``aiplatform.init()`` is never called: it sets process-wide defaults, so
two Vertex stores in one process would read each other's project.

google-cloud-aiplatform imported lazily.
"""

from __future__ import annotations

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
from vecshield.models import Chunk, Collection, QueryHit, VectorStore

#: google.api_core and google.auth exceptions, by class name so the mapping
#: needs no import. api_core errors also carry an HTTP ``code``, which the
#: shared mapper reads when a class is not listed here.
_ERRORS: ErrorRegistry = {
    "Unauthenticated": ConnectorAuthError,
    "Unauthorized": ConnectorAuthError,
    "PermissionDenied": ConnectorAuthError,
    "Forbidden": ConnectorAuthError,
    "DefaultCredentialsError": ConnectorAuthError,
    "RefreshError": ConnectorAuthError,
    "NotFound": ConnectorNotFound,
    "DeadlineExceeded": ConnectorTimeout,
    "GatewayTimeout": ConnectorTimeout,
    "ServiceUnavailable": ConnectorUnavailable,
    "TooManyRequests": ConnectorUnavailable,
    "ResourceExhausted": ConnectorUnavailable,
    "InternalServerError": ConnectorUnavailable,
    "RetryError": ConnectorUnavailable,
}

#: The only update method whose indexes accept remove_datapoints(). Batch
#: indexes are rebuilt from files in Cloud Storage; an unset method is batch.
_STREAM_UPDATE = "STREAM_UPDATE"


class VertexAIConnector(Connector):
    kind = "vertex_ai"
    content_enumerable = False  # inventory only: no bulk-enumerate API for content

    def __init__(
        self,
        *,
        project: str,
        location: str = "us-central1",
        endpoint_id: Optional[str] = None,
        credentials_json: Optional[str] = None,
        **_ignored,
    ):
        try:
            from google.cloud import aiplatform  # type: ignore
        except ImportError as e:  # pragma: no cover
            raise ImportError(
                "google-cloud-aiplatform not installed. "
                "pip install 'vecshield[vertex]'"
            ) from e

        credentials = None
        if credentials_json:
            from google.oauth2 import service_account  # type: ignore

            credentials = service_account.Credentials.from_service_account_file(
                credentials_json)
        self._ai = aiplatform
        self._project = project
        self._location = location
        self._credentials = credentials
        self._endpoint_id = endpoint_id
        self._endpoint_url = f"vertex-ai://{project}/{location}"
        self._endpoint_obj: Any = None
        #: index id -> indexUpdateMethod, filled by list_collections().
        self._update_methods: Optional[dict[str, Optional[str]]] = None

    # ---- SDK plumbing ----------------------------------------------------- #

    def _sdk_kw(self) -> dict[str, Any]:
        """project / location / credentials for an SDK constructor or call.

        Only the values that are set, so a connector assembled without them
        (tests build one with ``__new__``) still calls the SDK the plain way.
        """
        kw: dict[str, Any] = {}
        for key, attr in (("project", "_project"), ("location", "_location"),
                          ("credentials", "_credentials")):
            value = getattr(self, attr, None)
            if value is not None:
                kw[key] = value
        return kw

    def _list_indexes(self) -> list[Any]:
        return retry_read(mapped_call(
            lambda: list(self._ai.MatchingEngineIndex.list(**self._sdk_kw())),
            kind=self.kind, extra=_ERRORS))

    def _get_index(self, collection: str) -> Any:
        return retry_read(mapped_call(
            lambda: self._ai.MatchingEngineIndex(collection, **self._sdk_kw()),
            kind=self.kind, extra=_ERRORS))

    def _endpoint(self) -> Any:
        if getattr(self, "_endpoint_obj", None) is None:
            self._endpoint_obj = retry_read(mapped_call(
                lambda: self._ai.MatchingEngineIndexEndpoint(self._endpoint_id,
                                                             **self._sdk_kw()),
                kind=self.kind, extra=_ERRORS))
        return self._endpoint_obj

    # ---- capabilities ------------------------------------------------------ #

    def capabilities(self) -> set[str]:
        caps = {"at_rest_introspection"}
        if getattr(self, "_endpoint_id", None):
            caps.add("query")
        if any(m == _STREAM_UPDATE for m in self._known_update_methods().values()):
            # Per index: delete_chunks() refuses batch-update indexes.
            caps.add("delete")
        return caps

    def _known_update_methods(self) -> dict[str, Optional[str]]:
        methods = getattr(self, "_update_methods", None)
        if methods is not None:
            return methods
        try:
            listed = list(self._ai.MatchingEngineIndex.list(**self._sdk_kw()))
            methods = {_index_id(idx): _update_method(_plain(idx)) for idx in listed}
        except Exception:  # noqa: BLE001 - unknown: delete is not advertised
            methods = {}
        self._update_methods = methods
        return methods

    # ---- inventory --------------------------------------------------------- #

    def describe(self) -> VectorStore:
        return VectorStore(
            kind=self.kind,
            name=self._endpoint_url,
            endpoint=self._endpoint_url,
            collections=self.list_collections(),
            metadata={"managed": True, "enumeration": "inventory_only"},
        )

    def list_collections(self) -> list[Collection]:
        out = []
        methods: dict[str, Optional[str]] = {}
        for idx in self._list_indexes():
            name = _index_id(idx)
            try:
                plain = idx.to_dict() or {}
            except Exception as exc:  # noqa: BLE001 - recorded, count unknown
                plain = {}
                self._record_read_error(name, operation="index.to_dict",
                                        error_type=type(exc).__name__,
                                        reason="the index resource could not be read")
            stats = plain.get("indexStats")
            # proto3 omits zero values, so a present, non-empty indexStats
            # without vectorsCount is a real zero. No stats at all is unknown.
            count_known = isinstance(stats, dict) and bool(stats)
            count = int((stats or {}).get("vectorsCount") or 0) if count_known else 0
            config = ((plain.get("metadata") or {}).get("config") or {})
            dim = config.get("dimensions")
            method = _update_method(plain)
            methods[name] = method
            deployed = [d.get("deployedIndexId") for d in plain.get("deployedIndexes") or []
                        if isinstance(d, dict) and d.get("deployedIndexId")]
            metadata: dict[str, Any] = {
                "display_name": getattr(idx, "display_name", None),
                "resource_name": getattr(idx, "resource_name", None) or plain.get("name")
                or name,
                "index_update_method": method,
                "streaming_delete": method == _STREAM_UPDATE,
                "deployed_index_ids": deployed,
                "count_source": "indexStats.vectorsCount",
            }
            sparse = (stats or {}).get("sparseVectorsCount")
            if sparse is not None:
                metadata["sparse_vectors_count"] = int(sparse)
            if not count_known:
                metadata["count_known"] = False
            out.append(Collection(
                name=name, count=count,
                dimension=int(dim) if isinstance(dim, (int, float)) else None,
                metadata=metadata))
        self._update_methods = methods
        return out

    def iter_chunks(self, collection: str, batch_size: int = 256) -> Iterator[Chunk]:
        # Vertex AI Vector Search has no bulk-enumerate API.
        # Point at the backing data source (GCS bucket / BigQuery table) for
        # content-level PII scans.
        return iter(())

    # ---- query ------------------------------------------------------------- #

    def query(
        self,
        collection: str,
        vector: list[float],
        top_k: int = 10,
        where: Optional[dict[str, Any]] = None,
    ) -> list[QueryHit]:
        if not self._endpoint_id:
            raise UnsupportedCapability(
                "vertex_ai: provide endpoint_id to enable query()"
            )
        endpoint = self._endpoint()
        deployed_id = _deployed_index_id(endpoint, collection)
        if deployed_id is None:
            raise UnsupportedCapability(
                f"vertex_ai: index {collection!r} is not deployed to the configured "
                "endpoint, so it cannot be queried")
        kwargs: dict[str, Any] = {"deployed_index_id": deployed_id,
                                  "queries": [vector], "num_neighbors": top_k,
                                  "return_full_datapoint": True}
        tokens, numeric = _filters(where)
        if tokens:
            kwargs["filter"] = tokens
        if numeric:
            kwargs["numeric_filter"] = numeric
        results = retry_read(mapped_call(lambda: endpoint.find_neighbors(**kwargs),
                                         kind=self.kind, extra=_ERRORS))

        hits: list[QueryHit] = []
        for neighbor in results[0] if results else []:
            distance = getattr(neighbor, "distance", None)
            hits.append(
                QueryHit(
                    id=str(neighbor.id),
                    score=float(distance) if distance is not None else 0.0,
                    text=None,
                    metadata=_neighbor_metadata(neighbor),
                )
            )
        return hits

    # ---- encryption -------------------------------------------------------- #

    def at_rest_encryption_state(self, collection: Optional[str] = None) -> AtRestObservation:
        """CMEK on an index, from ``encryption_spec.kms_key_name``.

        Google encrypts all index data by default, but that layer is not
        reported through the index resource, so absence of a CMEK is *not
        observable*, never *disabled*.
        """
        if collection is None:
            return AtRestObservation(
                state="not_observable", scope="store", source="encryption_spec.kms_key_name",
                per_collection=True,
                reason="customer-managed keys are set per index; each index is "
                       "reported separately")
        try:
            key = _kms_key(self._ai.MatchingEngineIndex(collection, **self._sdk_kw()))
        except Exception as exc:  # noqa: BLE001
            return AtRestObservation(
                state="error", scope="collection", collection=collection,
                source="encryption_spec.kms_key_name",
                reason=f"the index could not be read ({type(exc).__name__})")
        evidence: dict[str, Any] = {}
        endpoint_id = getattr(self, "_endpoint_id", None)
        if endpoint_id:
            try:
                endpoint_key = _kms_key(self._ai.MatchingEngineIndexEndpoint(
                    endpoint_id, **self._sdk_kw()))
                evidence["endpoint_key_reference"] = mask_reference(endpoint_key)
                evidence["endpoint_key_matches_index"] = (endpoint_key == key)
            except Exception as exc:  # noqa: BLE001
                evidence["endpoint_error"] = type(exc).__name__
        if not key:
            return AtRestObservation(
                state="not_observable", scope="collection", collection=collection,
                source="encryption_spec.kms_key_name", evidence=evidence,
                reason="This index has no customer-managed key. Google documents "
                       "that Vertex AI encrypts customer content at rest by default; "
                       "that layer is documented, not reported on the index.",
                documented_default={
                    "text": "Google documents that Vertex AI encrypts customer content "
                            "at rest by default (Google default encryption).",
                    "source_url": "https://docs.cloud.google.com/docs/security/"
                                  "encryption/default-encryption"})
        return AtRestObservation(
            state="enabled", scope="collection", collection=collection,
            source="encryption_spec.kms_key_name",
            mechanism="customer-managed key (Cloud KMS)",
            key_reference=mask_reference(key), evidence=evidence,
            reason="the index is encrypted with a customer-managed key")

    # ---- delete ------------------------------------------------------------ #

    def delete_chunks(self, collection: str, ids: list[str]) -> int:
        """Remove datapoints from a STREAM_UPDATE index by ID.

        Batch-update indexes are rebuilt from Cloud Storage files and reject
        streaming removal, so they are refused here rather than half-applied.
        """
        idx = self._get_index(collection)
        method = _update_method(_plain(idx))
        if method != _STREAM_UPDATE:
            raise UnsupportedCapability(
                f"vertex_ai: index {collection!r} uses {method or 'BATCH_UPDATE'}; only "
                "STREAM_UPDATE indexes accept datapoint removal. Remove the "
                "datapoints from the index's source files and rebuild it.")
        with mapped_errors(self.kind, _ERRORS):
            idx.remove_datapoints(datapoint_ids=ids)
        # remove_datapoints returns the index resource, not a count, so this
        # is the number of ids *requested*, not a confirmed count.
        return len(ids)


def _plain(idx: Any) -> dict[str, Any]:
    """The index resource as its REST dict, or {} when it cannot be read."""
    try:
        plain = idx.to_dict()
    except Exception:  # noqa: BLE001
        return {}
    return plain if isinstance(plain, dict) else {}


def _index_id(idx: Any) -> str:
    """The index id (last resource-name segment), the connector's collection name."""
    name = getattr(idx, "name", None) or getattr(idx, "resource_name", None) or ""
    return str(name)


def _update_method(plain: dict[str, Any]) -> Optional[str]:
    method = plain.get("indexUpdateMethod") if isinstance(plain, dict) else None
    return str(method) if method else None


def _deployed_index_id(endpoint: Any, collection: str) -> Optional[str]:
    """The id of ``collection``'s deployment on ``endpoint``, or None.

    A deployed index has its own id, chosen at deploy time and usually not the
    index id. An index deployed more than once resolves to the first id in
    sorted order. A ``collection`` that is itself a deployed id is accepted.
    """
    by_index: list[str] = []
    direct: Optional[str] = None
    for deployed in getattr(endpoint, "deployed_indexes", None) or []:
        dep_id = _field(deployed, "id")
        index_name = _field(deployed, "index")
        if not dep_id:
            continue
        if index_name and (str(index_name) == collection
                           or str(index_name).rsplit("/", 1)[-1] == collection):
            by_index.append(str(dep_id))
        elif str(dep_id) == collection:
            direct = str(dep_id)
    if by_index:
        return sorted(by_index)[0]
    return direct


def _field(obj: Any, name: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def _filters(where: Optional[dict[str, Any]]) -> tuple[list[Any], list[Any]]:
    """``where`` as Vector Search token (Namespace) and numeric filters.

    ``{field: "a"}`` and ``{field: {"$eq": "a"}}`` allow one token,
    ``{field: ["a", "b"]}`` and ``{"$in": [...]}`` allow any of them; an int or
    float is an EQUAL numeric restrict. Anything else cannot be expressed
    exactly and raises UnsupportedCapability rather than querying unfiltered.
    """
    if not where:
        return [], []
    from google.cloud.aiplatform.matching_engine.matching_engine_index_endpoint import (  # type: ignore  # noqa: E501
        Namespace,
        NumericNamespace,
    )

    tokens: list[Any] = []
    numeric: list[Any] = []
    for field, raw in where.items():
        value = raw
        if isinstance(raw, dict):
            if set(raw) == {"$eq"}:
                value = raw["$eq"]
            elif set(raw) == {"$in"} and isinstance(raw["$in"], (list, tuple)):
                value = list(raw["$in"])
            else:
                raise UnsupportedCapability(
                    f"vertex_ai: filter operator(s) {sorted(raw)} on {field!r} "
                    "cannot be expressed as a Vector Search restrict")
        if isinstance(value, bool) or value is None:
            raise UnsupportedCapability(
                f"vertex_ai: a {type(value).__name__} filter on {field!r} has no "
                "exact Vector Search restrict")
        if isinstance(value, str):
            tokens.append(Namespace(name=str(field), allow_tokens=[value]))
        elif isinstance(value, int):
            numeric.append(NumericNamespace(name=str(field), value_int=value, op="EQUAL"))
        elif isinstance(value, float):
            numeric.append(NumericNamespace(name=str(field), value_double=value,
                                            op="EQUAL"))
        elif isinstance(value, (list, tuple)) and value and all(
                isinstance(v, str) for v in value):
            tokens.append(Namespace(name=str(field), allow_tokens=list(value)))
        else:
            raise UnsupportedCapability(
                f"vertex_ai: the filter value for {field!r} cannot be expressed as a "
                "Vector Search restrict")
    return tokens, numeric


def _neighbor_metadata(neighbor: Any) -> dict[str, Any]:
    """Restricts, numeric restricts and embedding metadata of one neighbour.

    The SDK returns restricts as ``Namespace(name, allow_tokens, deny_tokens)``
    when the query asked for the full datapoint. A namespace with one allowed
    token reads as that token; several read as a list.
    """
    meta: dict[str, Any] = {}
    for restrict in getattr(neighbor, "restricts", None) or []:
        name = _field(restrict, "name") or _field(restrict, "namespace")
        allow = _field(restrict, "allow_tokens")
        if allow is None:
            allow = _field(restrict, "allow_list")
        allow = [str(t) for t in (allow or [])]
        if not name or not allow:
            continue
        meta[str(name)] = allow[0] if len(allow) == 1 else allow
    for restrict in getattr(neighbor, "numeric_restricts", None) or []:
        name = _field(restrict, "name") or _field(restrict, "namespace")
        if not name:
            continue
        for attr in ("value_int", "value_float", "value_double"):
            value = _field(restrict, attr)
            if value is not None:
                meta[str(name)] = value
                break
    extra = getattr(neighbor, "embedding_metadata", None)
    if isinstance(extra, dict):
        for key, value in extra.items():
            meta.setdefault(str(key), value)
    return meta


def _kms_key(resource: Any) -> Optional[str]:
    """encryption_spec.kms_key_name from an SDK resource, or its raw proto."""
    spec = getattr(resource, "encryption_spec", None)
    if spec is None:
        spec = getattr(getattr(resource, "_gca_resource", None), "encryption_spec", None)
    key = getattr(spec, "kms_key_name", None) if spec is not None else None
    return key or None
