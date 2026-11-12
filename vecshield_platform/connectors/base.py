"""Connector interface.

A connector knows how to talk to one kind of vector store and yield its
structure (collections) and contents (chunks) in VecShield's normalized model.

Read access is the required core: list collections, iterate chunks. Everything
else -- access-control introspection (list_api_keys, get_rbac), query
simulation, deletes -- is optional and advertised through capabilities().
"""

from __future__ import annotations

import re
import time
from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterator, Mapping, Optional, TypeVar

from vecshield.models import ApiKey, Chunk, Collection, QueryHit, VectorStore


class UnsupportedCapability(Exception):
    """Raised when a connector is asked for a capability it doesn't expose."""


# --------------------------------------------------------------------------- #
# Typed error taxonomy                                                        #
#                                                                             #
# Connectors talk to remote managed stores; callers (validation, scanning,    #
# the API) need to tell "auth failed" from "timeout" from "not found" so they #
# can react correctly (surface a 401 vs. retry vs. report a coverage gap).    #
# Connectors should translate SDK/transport exceptions into these where they  #
# can; raw exceptions are still allowed and treated as non-retryable.         #
# --------------------------------------------------------------------------- #

class ConnectorError(Exception):
    """Base class for connector runtime failures talking to a backing store."""


class ConnectorAuthError(ConnectorError):
    """Authentication or authorization failed (bad key, expired token, denied).

    Not retryable — retrying with the same credentials will fail identically.
    """


class ConnectorTimeout(ConnectorError):
    """A request to the backing store timed out. Retryable (transient)."""


class ConnectorUnavailable(ConnectorError):
    """The backing store is unreachable or returned a transient 5xx / throttle.

    Retryable (transient).
    """


class ConnectorNotFound(ConnectorError):
    """A requested collection/namespace/index does not exist. Not retryable."""


#: Error types that represent transient conditions worth retrying for
#: idempotent reads.
RETRYABLE_ERRORS: tuple[type[BaseException], ...] = (
    ConnectorTimeout,
    ConnectorUnavailable,
)

_T = TypeVar("_T")


def retry_read(
    fn: Callable[[], _T],
    *,
    attempts: int = 3,
    delay: float = 0.1,
    backoff: float = 2.0,
    max_delay: float = 5.0,
    retryable: tuple[type[BaseException], ...] = RETRYABLE_ERRORS,
    sleep: Callable[[float], None] = time.sleep,
) -> _T:
    """Call ``fn`` and retry on transient connector errors with backoff.

    Only for **idempotent reads** — never wrap a mutating call in this. Non-
    retryable errors (auth, not-found, or any exception not in ``retryable``)
    propagate immediately. ``sleep`` is injectable so tests need not wait.

    Raises the last transient error if all attempts are exhausted.
    """
    if attempts < 1:
        raise ValueError("attempts must be >= 1")
    current = delay
    last_exc: Optional[BaseException] = None
    for i in range(attempts):
        try:
            return fn()
        except retryable as e:  # transient
            last_exc = e
            if i == attempts - 1:
                break
            sleep(min(current, max_delay))
            current *= backoff
    assert last_exc is not None  # only reached after a retryable failure
    raise last_exc


# --------------------------------------------------------------------------- #
# Error translation                                                           #
#                                                                             #
# Each SDK raises its own exceptions. translate_error() maps them onto the    #
# taxonomy above so callers can tell a bad key from a transient outage — a    #
# 401 reported as "unavailable" would be retried, and one reported as a raw   #
# SDK error is indistinguishable from a bug.                                  #
# --------------------------------------------------------------------------- #

#: Exception class (or its name) -> connector error. Keys are ``type | str``;
#: typed ``Any`` because Mapping is invariant in its key, so a connector's
#: ``dict[str, ...]`` registry would not otherwise be accepted.
ErrorRegistry = Mapping[Any, type[ConnectorError]]

_GRPC_CODES: dict[str, type[ConnectorError]] = {
    "UNAUTHENTICATED": ConnectorAuthError,
    "PERMISSION_DENIED": ConnectorAuthError,
    "NOT_FOUND": ConnectorNotFound,
    "DEADLINE_EXCEEDED": ConnectorTimeout,
    "UNAVAILABLE": ConnectorUnavailable,
    "RESOURCE_EXHAUSTED": ConnectorUnavailable,
}

#: Checked in order against the exception's class names (its MRO), so the
#: more specific words come first: "AuthenticationTimeout" is a timeout.
_NAME_PATTERNS: tuple[tuple[re.Pattern[str], type[ConnectorError]], ...] = (
    (re.compile(r"timeout|timedout", re.I), ConnectorTimeout),
    (re.compile(r"unauthori[sz]ed|unauthenticated|forbidden|authentication|"
                r"permissiondenied|accessdenied", re.I), ConnectorAuthError),
    (re.compile(r"notfound", re.I), ConnectorNotFound),
    (re.compile(r"connectionerror|connecterror|unavailable|serviceunavailable|"
                r"throttl|ratelimit|toomanyrequests", re.I), ConnectorUnavailable),
)


def error_class_for_status(status: Any) -> Optional[type[ConnectorError]]:
    """The connector error an HTTP status code stands for, or None."""
    if isinstance(status, bool):
        return None
    try:
        code = int(status)
    except (TypeError, ValueError):
        return None
    if code in (401, 403):
        return ConnectorAuthError
    if code == 404:
        return ConnectorNotFound
    if code in (408, 504):
        return ConnectorTimeout
    if code == 429 or 500 <= code <= 599:
        return ConnectorUnavailable
    return None


def _status_of(exc: BaseException) -> Any:
    # Not ``code``: several SDKs use it for their own error codes (a MongoDB
    # OperationFailure, a MilvusException), which are not HTTP statuses.
    for attr in ("status_code", "status", "http_status"):
        value = getattr(exc, attr, None)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    response = getattr(exc, "response", None)
    if response is not None:
        for attr in ("status_code", "status"):
            value = getattr(response, attr, None)
            if isinstance(value, int) and not isinstance(value, bool):
                return value
    return None


def _grpc_code_name(exc: BaseException) -> Optional[str]:
    code = getattr(exc, "code", None)
    if not callable(code):
        return None
    try:
        value = code()
    except Exception:  # noqa: BLE001 - a code() that needs arguments is not gRPC
        return None
    name = getattr(value, "name", None)
    return name if isinstance(name, str) else None


def translate_error(exc: BaseException, *, kind: str,
                    extra: Optional[ErrorRegistry] = None) -> BaseException:
    """Map an SDK or transport exception onto the connector error taxonomy.

    Checked in order: errors already in the taxonomy (and
    UnsupportedCapability) pass through; then the connector's own
    registrations in ``extra`` (by class or class name, walking the MRO); then
    an HTTP status; then a gRPC status code; then the class name. Anything
    unrecognised is returned unchanged, which callers treat as non-retryable.

    The new error's message names the store kind, the original class and the
    status only. ``str(exc)`` is deliberately left out: SDK messages can echo
    request URLs, headers or keys. The original stays reachable as
    ``__cause__`` for logs that need it.
    """
    if isinstance(exc, (ConnectorError, UnsupportedCapability)):
        return exc
    target: Optional[type[ConnectorError]] = None
    mro = type(exc).__mro__
    if extra:
        for cls in mro:
            target = extra.get(cls) or extra.get(cls.__name__)
            if target is not None:
                break
    status = _status_of(exc)
    if target is None:
        target = error_class_for_status(status)
    if target is None:
        grpc = _grpc_code_name(exc)
        if grpc is not None:
            target = _GRPC_CODES.get(grpc)
            status = status or grpc
    if target is None:
        names = [cls.__name__ for cls in mro if cls not in (BaseException, Exception, object)]
        for pattern, cls_target in _NAME_PATTERNS:
            if any(pattern.search(name) for name in names):
                target = cls_target
                break
    if target is None:
        # The builtins carry the meaning in the type itself.
        if isinstance(exc, TimeoutError):
            target = ConnectorTimeout
        elif isinstance(exc, (ConnectionError, PermissionError)):
            target = (ConnectorAuthError if isinstance(exc, PermissionError)
                      else ConnectorUnavailable)
    if target is None:
        return exc
    message = f"{kind}: {type(exc).__name__}"
    if status is not None:
        message += f" (status {status})"
    return target(message)


@contextmanager
def mapped_errors(kind: str, extra: Optional[ErrorRegistry] = None) -> Iterator[None]:
    """Re-raise exceptions from the block as connector errors where they map.

    Use around SDK calls, inside ``retry_read`` for reads so transient errors
    are retried::

        with mapped_errors(self.kind, _ERRORS):
            page = retry_read(lambda: self._client.scroll(...))

    ``retry_read`` only retries the taxonomy's transient types, so the mapping
    has to happen inside the retried function for retries to apply; see
    :func:`mapped_call`.
    """
    try:
        yield
    except Exception as exc:  # noqa: BLE001 - translated or re-raised as is
        translated = translate_error(exc, kind=kind, extra=extra)
        if translated is exc:
            raise
        raise translated from exc


def mapped_call(fn: Callable[[], _T], *, kind: str,
                extra: Optional[ErrorRegistry] = None) -> Callable[[], _T]:
    """Wrap ``fn`` so its exceptions are translated — for use with retry_read.

    ``retry_read(mapped_call(lambda: client.read(...), kind=self.kind))``
    retries a read whose SDK raised a 503, and stops at once on a 401.
    """
    def call() -> _T:
        with mapped_errors(kind, extra):
            return fn()
    return call



# --------------------------------------------------------------------------- #
# Crypto introspection results                                                #
# --------------------------------------------------------------------------- #

#: What a connector can say about database-native encryption at rest.
#: ``not_observable`` means the interface was asked and cannot answer (the
#: property lives in infrastructure the data plane does not expose);
#: ``unsupported`` means this connector has no way to ask at all. Neither is a
#: failure, and neither is evidence the data is unencrypted.
AT_REST_STATES = ("enabled", "disabled", "not_observable", "unsupported", "error")


def mask_reference(value: Any) -> Optional[str]:
    """Mask a key identifier (ARN, Key Vault URI, KMS resource name) for evidence.

    A key reference is not a secret, but it names infrastructure. Evidence only
    needs enough of it to tell two keys apart, so the middle is dropped.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if len(text) <= 8:
        return text[:1] + "*" * (len(text) - 1)
    return f"{text[:6]}…{text[-4:]}"


def fill_declared_embedding_model(connector: Any, collections: Any) -> int:
    """Give collections that declare no model the one the store config declares.

    Most stores keep no record of the model that produced their vectors, so
    inversion risk and embedding consistency had nothing to work from outside
    Chroma. A model the store itself records always wins; the configured one
    only fills the gap, and is marked as configured rather than observed.
    Returns how many collections it filled.
    """
    declared = getattr(connector, "declared_embedding_model", None)
    if not declared:
        return 0
    filled = 0
    for col in collections or []:
        if getattr(col, "embedding_model", None):
            continue
        col.embedding_model = str(declared)
        if isinstance(getattr(col, "metadata", None), dict):
            col.metadata["embedding_model_source"] = "store_config"
        filled += 1
    return filled


@dataclass
class AtRestObservation:
    """One observation of encryption at rest, as the data plane reports it.

    ``scope`` says what the observation covers: the whole store (a cluster-wide
    setting such as EDB TDE or MongoDB's encrypted storage engine) or one
    collection (pg_tde per table, an Azure index's customer-managed key).
    ``per_collection`` on a store-scope observation tells the caller the real
    answer is only available collection by collection. ``evidence`` holds
    configuration facts and counts, never credentials or stored values.

    ``evidence_to_supply`` and ``documented_default`` override the kind-level
    entry in ``posture/at_rest_support.py`` when the connector knows more about
    this particular store (for example, that a Postgres host is Amazon RDS).
    ``documented_default`` is ``{"text", "source_url"}``: vendor documentation,
    shown as context and never read as the state.
    """

    state: str
    scope: str = "store"
    source: Optional[str] = None
    collection: Optional[str] = None
    mechanism: Optional[str] = None
    key_reference: Optional[str] = None
    reason: str = ""
    per_collection: bool = False
    evidence: dict[str, Any] = field(default_factory=dict)
    evidence_to_supply: list[str] = field(default_factory=list)
    documented_default: Optional[dict[str, str]] = None
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if self.state not in AT_REST_STATES:
            raise ValueError(f"unknown at-rest state: {self.state}")
        if self.scope not in ("store", "collection"):
            raise ValueError(f"unknown at-rest scope: {self.scope}")

    def to_dict(self) -> dict[str, Any]:
        return {"state": self.state, "scope": self.scope, "source": self.source,
                "collection": self.collection, "mechanism": self.mechanism,
                "key_reference": self.key_reference, "reason": self.reason,
                "per_collection": self.per_collection, "evidence": dict(self.evidence),
                "evidence_to_supply": list(self.evidence_to_supply),
                "documented_default": (dict(self.documented_default)
                                       if self.documented_default else None),
                "observed_at": self.observed_at.isoformat()}



class Connector(ABC):
    """Base class for all vector store connectors.

    Only the read methods are required (describe/list_collections/
    iter_chunks). Optional capabilities add query() for the
    isolation prober and list_api_keys() for the access auditor — which not
    every store exposes. Connectors advertise what they support via
    capabilities(); callers should check before using.
    """

    kind: str = "base"

    #: Whether iter_chunks() can enumerate real per-chunk content. Managed,
    #: inventory-only stores (e.g. Bedrock KB, Vertex AI Vector Search) expose
    #: inventory but no bulk chunk/vector enumeration API, so content-level
    #: scans (classification, erasure impact, DSAR) cannot see inside them and
    #: must target the backing store directly. Callers should check this before
    #: treating an empty scan result as "no matching data".
    content_enumerable: bool = True

    #: The largest ``top_k`` one query() call may request, where the store
    #: documents a hard limit. None means no known cap; callers that size a
    #: query to a whole collection (the tenant isolation check) then apply their
    #: own default. Set this only from the store's documentation.
    max_top_k: Optional[int] = None

    #: The embedding model the store's owner declared in its configuration
    #: (``embedding_model`` in the store's connection settings), for stores
    #: that do not record one themselves. Applied by
    #: :func:`fill_declared_embedding_model` to collections that declare none.
    declared_embedding_model: Optional[str] = None

    def capabilities(self) -> set[str]:
        """The optional capabilities this connector implements.

        Each name is a promise backed by a method (``CAPABILITY_METHODS`` in
        ``actions.py`` holds the mapping for the ones actions rely on):

        * ``query`` — query(); ``api_keys`` — list_api_keys()
        * ``delete`` — delete_chunks(); ``redact`` — replace_chunk_text()
        * ``metadata_write`` — set_chunk_metadata();
          ``collection_metadata_write`` — set_collection_metadata()
        * ``transport_introspection`` — transport_session_info()
        * ``tls_enforcement_introspection`` — tls_enforcement_info()
        * ``session_auth_introspection`` — session_auth_info()
        * ``access_introspection`` — access_model()
        * ``ann_iterative_scan`` — ann_index_info() and query_iterative()
        * ``at_rest_introspection`` — at_rest_encryption_state()
        * ``field_encryption_introspection`` — field_encryption_config()
        * ``server_info`` — server_info(); ``location_introspection`` —
          store_location(); ``egress_introspection`` — model_integrations();
          ``aliases`` — list_aliases()

        Advertise a name only when the method is implemented; the default
        methods raise UnsupportedCapability.
        """
        return set()

    def read_errors(self) -> list[dict[str, Any]]:
        """Per-item content-read failures accumulated during iter_chunks().

        Some managed stores (e.g. OpenAI Vector Stores) expose file/chunk
        inventory but can fail to return an individual item's *content*. Rather
        than silently yielding empty text — which would make an unreadable item
        look clean — connectors record the failure here so the scan engine can
        emit an explicit coverage finding instead of under-reporting. Default:
        nothing to report.

        Each entry carries a ``collection`` key naming the collection it
        affects, so a failure in one collection downgrades that collection's
        coverage only. An entry without one is treated as store-wide.
        Connectors record entries through :meth:`_record_read_error`; callers
        clear them with :meth:`reset_read_errors` before a pass.
        """
        return list(getattr(self, "_read_errors", None) or [])

    def reset_read_errors(self) -> None:
        """Forget read errors from earlier passes, so each pass starts clean."""
        errors = getattr(self, "_read_errors", None)
        if isinstance(errors, list):
            errors.clear()

    def _record_read_error(self, collection: Optional[str], **fields: Any) -> None:
        """Record one item whose content could not be read. Never a secret.

        ``fields`` describe the item and the failure (``item_id``,
        ``error_type``, ``reason``, ``operation``...). Pass the exception's
        type name, not its message: SDK messages can echo credentials.
        """
        errors = getattr(self, "_read_errors", None)
        if not isinstance(errors, list):
            errors = []
            self._read_errors = errors
        errors.append({"collection": collection, **fields})

    # Inventory counts: a connector that cannot read a collection's count
    # reports ``count=0`` with ``metadata["count_known"] = False`` (see
    # ``coverage.count_known``), so cross-checks that compare the count with
    # what was read report "could not be verified" instead of passing.

    @abstractmethod
    def describe(self) -> VectorStore:
        """Return store-level metadata and its collections (without chunks)."""

    @abstractmethod
    def list_collections(self) -> list[Collection]:
        """List collections / namespaces / indexes."""

    @abstractmethod
    def iter_chunks(self, collection: str, batch_size: int = 256) -> Iterator[Chunk]:
        """Stream chunks from a collection. Includes text when the store has it."""

    def query(
        self,
        collection: str,
        vector: list[float],
        top_k: int = 10,
        where: Optional[dict[str, Any]] = None,
    ) -> list[QueryHit]:
        """Similarity search. `where` is an optional metadata filter.

        The isolation prober relies on `where` being honored (or absent) so it
        can simulate a tenant query that forgets to filter by tenant.
        """
        raise UnsupportedCapability(f"{self.kind} does not support query()")

    def query_many(
        self,
        collection: str,
        vectors: list[list[float]],
        top_k: int = 10,
        where: Optional[dict[str, Any]] = None,
    ) -> list[list[QueryHit]]:
        """:meth:`query` for each vector, under one ``where``, in order.

        The default issues one :meth:`query` per vector. A connector whose
        store answers several vectors in one request overrides it; callers
        such as the isolation sweep only batch through connectors that do.
        """
        return [self.query(collection, vector, top_k=top_k, where=where)
                for vector in vectors]

    def list_api_keys(self) -> list[ApiKey]:
        """Enumerate access credentials, if the store exposes them via API."""
        raise UnsupportedCapability(f"{self.kind} does not support list_api_keys()")

    def delete_chunks(self, collection: str, ids: list[str]) -> int:
        """Delete chunks by id from a collection. Returns the count deleted.

        Only supported by connectors that advertise "delete" in capabilities().
        Callers should run verify_erasure() afterwards to produce audit evidence.
        """
        raise UnsupportedCapability(f"{self.kind} does not support delete_chunks()")

    def set_chunk_metadata(self, collection: str,
                           updates: dict[str, dict[str, Any]]) -> int:
        """Merge metadata into existing chunks. Returns the count updated.

        ``updates`` maps chunk id to the fields to set. Merging, not replacing:
        a caller marking a chunk must not destroy the metadata the customer's
        own pipeline put there.

        Only supported by connectors advertising "metadata_write". Writing
        metadata does not by itself change what a retriever returns — that
        depends on the retrieving application honouring the field — so callers
        must not report a metadata write as content removed.
        """
        raise UnsupportedCapability(f"{self.kind} does not support set_chunk_metadata()")

    def get_chunks(self, collection: str, ids: list[str]) -> list[Chunk]:
        """Read specific chunks by id, with text, metadata and embedding.

        Optional. Connectors without random access leave the default, and
        callers fall back to iteration.
        """
        wanted = set(ids)
        out: list[Chunk] = []
        for chunk in self.iter_chunks(collection):
            if chunk.id in wanted:
                out.append(chunk)
                wanted.discard(chunk.id)
                if not wanted:
                    break
        return out

    def replace_chunk_text(self, collection: str, chunk_id: str, text: str,
                           metadata_updates: Optional[dict[str, Any]] = None) -> bool:
        """Replace one chunk's stored text, leaving its vector as it is.

        Only supported by connectors advertising "redact". The vector is
        deliberately **not** recomputed: this product does not have the model
        the collection was embedded with, and letting the store embed the
        replacement with whatever it defaults to would write a vector in a
        different space from every neighbour it has. The old vector still
        encodes the old text; the caller marks the chunk for the pipeline that
        owns the model.
        """
        raise UnsupportedCapability(f"{self.kind} does not support replace_chunk_text()")

    def set_collection_metadata(self, collection: str,
                                updates: dict[str, Any]) -> bool:
        """Merge metadata onto a collection itself. Returns whether it was written.

        Separate from set_chunk_metadata() and advertised separately as
        "collection_metadata_write": a store can perfectly well allow one and
        not the other, and a single capability covering both would promise more
        than some connectors can keep.
        """
        raise UnsupportedCapability(
            f"{self.kind} does not support set_collection_metadata()")

    # ---- crypto introspection (optional) ------------------------------- #

    def transport_session_info(self) -> dict[str, Any]:
        """What the live connection VecShield holds says about its encryption.

        Returns ``{"tls": bool|None, "version": str|None, "cipher": str|None,
        "source": str}``. This describes *this* session only: it shows the
        store can speak TLS, not that it refuses clients who do not.
        """
        raise UnsupportedCapability(f"{self.kind} does not support transport_session_info()")

    def tls_enforcement_info(self) -> dict[str, Any]:
        """Whether the store refuses plaintext clients, read from its own catalog.

        Returns ``{"plaintext_accepted": bool|None, "method": "catalog",
        "source": str, "reason": str, "readable": bool, "evidence": dict}``.
        ``plaintext_accepted=None`` means the catalog could not settle it.
        """
        raise UnsupportedCapability(f"{self.kind} does not support tls_enforcement_info()")

    def session_auth_info(self) -> dict[str, Any]:
        """How the server authenticated the live connection VecShield holds.

        Returns ``{"observed": bool, "authenticated": bool|None,
        "auth_method": str|None, "source": str, "reason": str}``.
        ``authenticated=False`` means the server admitted this session without
        authenticating it; ``None`` means it could not be told. It describes
        this session's path only, not every client's.
        """
        raise UnsupportedCapability(f"{self.kind} does not support session_auth_info()")

    def access_model(self) -> dict[str, Any]:
        """Who can read and change the store's data, as the store itself reports it.

        A plain dict (the RBAC evaluation plan's ``AccessObservation``):
        ``{"engine", "observed_as", "retrieval_principal", "tables",
        "schemas", "sections_readable", "reasons", "inventory_complete",
        "observed_at"}``. ``observed_as`` is the principal VecShield connected
        as; ``retrieval_principal`` the one the application retrieves with,
        flagged ``assumed`` when it was not declared. A section the credential
        may not read is ``False`` in ``sections_readable`` with its reason, so
        a caller reports it as not observable rather than as clean.
        """
        raise UnsupportedCapability(f"{self.kind} does not support access_model()")

    def ann_index_info(self, collection: str) -> dict[str, Any]:
        """The collection's approximate index and the settings that bound its scans.

        ``{"index_type": None}`` when its searches are exact. A store whose
        approximate index applies filters after the scan can return fewer
        filtered results than asked for, without any leak.
        """
        raise UnsupportedCapability(f"{self.kind} does not support ann_index_info()")

    def query_iterative(
        self,
        collection: str,
        vector: list[float],
        top_k: int = 10,
        where: Optional[dict[str, Any]] = None,
    ) -> list[QueryHit]:
        """``query()`` with the index told to keep scanning until enough rows pass
        the filter, for this request only; read-only."""
        raise UnsupportedCapability(f"{self.kind} does not support query_iterative()")

    def at_rest_encryption_state(self, collection: Optional[str] = None) -> AtRestObservation:
        """Database-native encryption at rest, for the store or one collection.

        Only what the data plane reports. Volume, disk and cloud-KMS encryption
        are outside a connector's view and come back ``not_observable`` — never
        ``disabled``.
        """
        raise UnsupportedCapability(f"{self.kind} does not support at_rest_encryption_state()")

    def field_encryption_config(self, collection: str) -> list[dict[str, Any]]:
        """Field-level encryption the store itself declares for a collection.

        Returns ``[{"path": str, "mechanism": str, ...}]`` — configuration, not
        a test of the stored values. An empty list means the store declares
        none, which is different from the connector being unable to ask.
        """
        raise UnsupportedCapability(f"{self.kind} does not support field_encryption_config()")

    # ---- store facts (optional) ----------------------------------------- #
    #
    # Read-only facts about the store itself rather than its contents. Each
    # returns what the data plane reports; anything the credential or API
    # cannot see is ``None`` / ``observable=False`` with a reason — never a
    # guess. Values are configuration, never secrets: API keys, header values
    # and passwords are dropped before they reach the returned dict.

    def server_info(self) -> dict[str, Any]:
        """The server product and version this connection talks to.

        Returns ``{"product": str, "version": str|None, "edition": str|None,
        "managed": bool, "source": str, "reason": str, "features": dict}``.
        ``product`` is the server software ("qdrant", "weaviate", "milvus",
        "chroma", "postgresql", "redis", "opensearch", "mongodb", ...), not the
        client library. ``source`` names where the version came from (e.g.
        ``"GET /"``, ``"SELECT version()"``). ``features`` holds enabled server
        features that decide whether an advisory applies (modules, plugins,
        extension versions such as ``{"pgvector": "0.8.1"}``). Managed services
        whose server version is not exposed return ``version=None,
        managed=True``. Advertised as ``server_info``.
        """
        raise UnsupportedCapability(f"{self.kind} does not support server_info()")

    def store_location(self) -> dict[str, Any]:
        """Where the store's data lives, as the provider's own API reports it.

        Returns ``{"provider": str|None, "region": str|None,
        "replica_regions": list[str], "source": str, "observable": bool,
        "reason": str, "evidence": dict}``. ``provider`` is the hosting
        provider ("aws", "gcp", "azure", "pinecone", "openai", "mongodb_atlas",
        "zilliz", "qdrant_cloud", "weaviate_cloud", "self_hosted", ...).
        ``region`` is the provider's region identifier exactly as reported
        (``us-east-1``, ``europe-west4``, ``westeurope``), never a guess from
        an IP address. ``observable=False`` when the connection cannot say.
        Advertised as ``location_introspection``.
        """
        raise UnsupportedCapability(f"{self.kind} does not support store_location()")

    def model_integrations(self) -> dict[str, Any]:
        """External model providers the store itself sends data to.

        Some databases call an embedding, reranking or generative model on
        their own — at ingest, at query time or to generate answers — so chunk
        text leaves the store without passing through the customer's code.
        Returns ``{"observable": bool, "reason": str, "source": str,
        "integrations": [ {"collection": str|None, "stage": "ingest"|"query"|
        "generate"|"rerank", "provider": str, "model": str|None,
        "endpoint_host": str|None, "auth": "managed_identity"|"api_key"|
        "none"|"unknown", "module": str|None, "evidence": dict} ],
        "controls": dict}``. ``collection=None`` means store-wide (an enabled
        module). ``controls`` holds store-level guards such as an allow-list of
        permitted model endpoints. Configured is not the same as used; the
        caller reports it as configured. Advertised as ``egress_introspection``.
        """
        raise UnsupportedCapability(f"{self.kind} does not support model_integrations()")

    def list_aliases(self) -> dict[str, str]:
        """Alias name → collection it currently points at.

        An alias can be repointed to a different collection without the
        application changing, which silently swaps the corpus it retrieves
        from. Advertised as ``aliases``.
        """
        raise UnsupportedCapability(f"{self.kind} does not support list_aliases()")

    def close(self) -> None:  # optional cleanup hook
        pass

    def __enter__(self) -> "Connector":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
