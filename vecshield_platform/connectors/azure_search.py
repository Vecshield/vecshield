"""Azure AI Search (vector) connector.

Each search index = a collection. Vector fields are often not retrievable, so
embeddings may be None (text + metadata still scanned). Vector query supported
when a vector field is present. azure-search-documents imported lazily.

Reading an index
----------------
``$skip`` cannot exceed 100,000, so skip paging stops there. Documents are
read in key order instead: ``$orderby=<key> asc`` with ``$filter=<key> gt
'<last key>'``, 1,000 at a time, which has no such ceiling. When the key field
is not sortable or filterable, reads fall back to skip paging, deduplicated by
key, and a read error is recorded if the 100,000 ceiling is reached.

A searchable string field that is not retrievable is indexed content the
query API never returns, so it cannot be classified; each one is recorded as a
read error for its index.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Iterator, Optional, TypeVar

from vecshield_platform.connectors.base import (
    AtRestObservation,
    Connector,
    ConnectorAuthError,
    ConnectorNotFound,
    ConnectorTimeout,
    ConnectorUnavailable,
    ErrorRegistry,
    mapped_call,
    mapped_errors,
    mask_reference,
    retry_read,
)
from vecshield_platform.connectors.redact import redact_credentials
from vecshield.models import Chunk, Collection, QueryHit, VectorStore

_TEXT_KEYS = ("content", "text", "document", "chunk", "body", "page_content")

#: azure-core exceptions by class name. HttpResponseError carries
#: ``status_code`` and is mapped from it by the shared translator.
_ERRORS: ErrorRegistry = {
    "ClientAuthenticationError": ConnectorAuthError,
    "ResourceNotFoundError": ConnectorNotFound,
    "ServiceRequestTimeoutError": ConnectorTimeout,
    "ServiceResponseTimeoutError": ConnectorTimeout,
    "ServiceRequestError": ConnectorUnavailable,
    "ServiceResponseError": ConnectorUnavailable,
}
#: Documents per request; Azure returns up to 1,000 without a continuation.
_PAGE = 1000
#: "$skip ... cannot be greater than 100,000" (Search Documents REST reference).
_MAX_SKIP = 100_000

_T = TypeVar("_T")

_MICROSOFT_MANAGED = {
    "text": "Microsoft documents always-on AES-256 encryption with Microsoft-managed "
            "keys for all Azure AI Search data.",
    "source_url": "https://learn.microsoft.com/azure/search/search-security-built-in",
}


class AzureSearchConnector(Connector):
    kind = "azure_search"

    def __init__(self, *, endpoint: str, api_key: str, **_ignored):
        try:
            from azure.core.credentials import AzureKeyCredential
            from azure.search.documents.indexes import SearchIndexClient
        except ImportError as e:  # pragma: no cover
            raise ImportError("azure-search-documents not installed. "
                              "pip install 'vecshield[azure]'") from e
        if not endpoint or not api_key:
            raise ValueError("azure_search requires endpoint and api_key")
        self._endpoint = endpoint
        # Display form only; the SDK keeps the endpoint as given.
        self._display = redact_credentials(endpoint)
        self._cred = AzureKeyCredential(api_key)
        self._ix = SearchIndexClient(endpoint, self._cred)
        self._layout: dict[str, dict] = {}
        self._read_errors: list[dict] = []

    def capabilities(self) -> set[str]:
        return {"query", "delete", "at_rest_introspection"}

    def at_rest_encryption_state(self, collection: Optional[str] = None) -> AtRestObservation:
        """Customer-managed key on an index, from ``SearchIndex.encryption_key``.

        Azure encrypts every index with Microsoft-managed keys, but the data
        plane does not report that layer. An index without a customer-managed
        key is therefore *not observable*, never *disabled*.
        """
        if collection is None:
            return AtRestObservation(
                state="not_observable", scope="store", source="index.encryption_key",
                per_collection=True,
                reason="customer-managed keys are set per index; each index is "
                       "reported separately")
        try:
            key = getattr(self._ix.get_index(collection), "encryption_key", None)
        except Exception as exc:  # noqa: BLE001
            return AtRestObservation(
                state="error", scope="collection", collection=collection,
                source="index.encryption_key",
                reason=f"the index definition could not be read ({type(exc).__name__})")
        if key is None:
            return AtRestObservation(
                state="not_observable", scope="collection", collection=collection,
                source="index.encryption_key",
                reason="This index has no customer-managed key. Microsoft documents "
                       "always-on AES-256 encryption with Microsoft-managed keys for "
                       "all Azure AI Search data; this is documented, not reported.",
                documented_default=dict(_MICROSOFT_MANAGED))
        # Only the key's name, version and vault are read. access_credentials
        # (an application secret) is never touched or serialised.
        vault = getattr(key, "vault_uri", None) or ""
        name = getattr(key, "key_name", None) or ""
        return AtRestObservation(
            state="enabled", scope="collection", collection=collection,
            source="index.encryption_key",
            mechanism="Customer-managed key (Azure Key Vault) on top of "
                      "Microsoft-managed keys",
            key_reference=mask_reference(f"{vault.rstrip('/')}/keys/{name}"
                                         if vault or name else None),
            evidence={"key_version_pinned": bool(getattr(key, "key_version", None))},
            reason="the index is encrypted with a customer-managed key")

    def _client(self, index: str):
        from azure.search.documents import SearchClient
        return SearchClient(self._endpoint, index, self._cred)

    def _read(self, fn: Callable[[], _T]) -> _T:
        """An idempotent read, with SDK errors mapped and transient ones retried."""
        return retry_read(mapped_call(fn, kind=self.kind, extra=_ERRORS))

    def describe(self) -> VectorStore:
        display = getattr(self, "_display", None) or redact_credentials(self._endpoint)
        return VectorStore(kind=self.kind, name=display, endpoint=display,
                           collections=self.list_collections())

    def _layout_of(self, index) -> dict:
        name = index if isinstance(index, str) else index.name
        if name in self._layout:
            return self._layout[name]
        ix = index if not isinstance(index, str) else self._read(
            lambda: self._ix.get_index(index))
        vec = text = key = None
        dim = None
        key_sortable = key_filterable = None
        unretrievable: list[str] = []
        for f in ix.fields:
            if getattr(f, "key", False) and key is None:
                key = f.name
                key_sortable = getattr(f, "sortable", None)
                key_filterable = getattr(f, "filterable", None)
            vdim = getattr(f, "vector_search_dimensions", None)
            is_string = "string" in str(getattr(f, "type", "")).lower()
            if vdim:
                vec, dim = f.name, vdim
            elif is_string and not _retrievable(f):
                # Searchable is the default for strings; only an explicit
                # False says the field holds nothing a query could surface.
                if getattr(f, "searchable", None) is not False:
                    unretrievable.append(f.name)
            elif is_string and f.name.lower() in _TEXT_KEYS and text is None:
                text = f.name
        # The document key is whatever field the index marks key=True; the
        # portal's "Import and vectorize data" layout, for one, uses chunk_id.
        self._layout[name] = {"vec": vec, "text": text, "dim": dim, "key": key,
                              "key_sortable": key_sortable,
                              "key_filterable": key_filterable,
                              "unretrievable": unretrievable}
        return self._layout[name]

    def list_collections(self) -> list[Collection]:
        out = []
        # azure-search-documents 11.x and 12.x name this list_indexes();
        # get_indexes() only existed in early previews.
        lister = getattr(self._ix, "list_indexes", None) or self._ix.get_indexes
        for ix in self._read(lambda: list(lister())):
            lay = self._layout_of(ix)
            cnt, known = self._count(self._client(ix.name))
            out.append(Collection(name=ix.name, count=cnt, dimension=lay["dim"],
                                  metadata={} if known else {"count_known": False}))
        return out

    def _count(self, client) -> tuple[int, bool]:
        """The index's document count, and whether it was actually read.

        ``get_document_count`` first; then a ``$count`` search returning no
        documents; then unknown. A count that could not be read is reported as
        unknown, never as zero.
        """
        try:
            return int(self._read(lambda: client.get_document_count())), True
        except Exception:  # noqa: BLE001 - try the next method
            pass
        try:
            total = self._read(lambda: client.search(
                search_text="*", include_total_count=True, top=0).get_count())
        except Exception:  # noqa: BLE001 - unknown, and reported as such
            return 0, False
        if isinstance(total, int) and not isinstance(total, bool):
            return total, True
        return 0, False

    def iter_chunks(self, collection: str, batch_size: int = 256) -> Iterator[Chunk]:
        lay = self._layout_of(collection)
        client = self._client(collection)
        for field_name in lay.get("unretrievable") or []:
            self._record_read_error(
                collection, field=field_name, operation="iter_chunks",
                error_type="FieldNotRetrievable",
                reason="This searchable field is not retrievable, so the index never "
                       "returns its content and it could not be classified.")
        keyset = (bool(lay.get("key")) and lay.get("key_sortable") is not False
                  and lay.get("key_filterable") is not False)
        docs = (self._iter_by_key(client, collection, lay) if keyset
                else self._iter_by_skip(client, collection, lay))
        for doc in docs:
            yield self._chunk(doc, collection, lay)

    def _iter_by_key(self, client, collection: str, lay: dict) -> Iterator[dict]:
        """Key-ordered pages (``key gt last``), so no $skip ceiling applies."""
        try:
            field = _odata_field(lay["key"])
        except ValueError:
            yield from self._iter_by_skip(client, collection, lay)
            return
        last: Any = None
        first = True
        while True:
            flt = None if last is None else f"{field} gt {_odata_literal(str(last))}"
            try:
                page = self._read(lambda: list(client.search(
                    search_text="*", filter=flt, order_by=[f"{field} asc"], top=_PAGE,
                    include_total_count=False)))
            except Exception as exc:
                # A key the index will not sort or filter on is refused with 400
                # on the first request; a later failure is a real one.
                if first and _status_of(exc) == 400:
                    yield from self._iter_by_skip(client, collection, lay)
                    return
                raise
            first = False
            yield from page
            if len(page) < _PAGE:
                return
            next_last = _doc_key(page[-1], lay)
            if next_last is None or (last is not None and str(next_last) == str(last)):
                self._record_read_error(
                    collection, operation="iter_chunks", error_type="KeyPagingStalled",
                    reason="Key-ordered paging stopped advancing, so the rest of the "
                           "index was not read.")
                return
            last = next_last

    def _iter_by_skip(self, client, collection: str, lay: dict) -> Iterator[dict]:
        """$skip pages, deduplicated by key, up to the 100,000 ceiling.

        Without a total order the service can return a document on two pages,
        so repeats are dropped; past the ceiling the rest is recorded as unread.
        """
        seen: set[str] = set()
        skip = 0
        while True:
            page = self._read(lambda: list(client.search(
                search_text="*", skip=skip, top=_PAGE, include_total_count=False)))
            for doc in page:
                k = _doc_key(doc, lay)
                if k is not None:
                    if str(k) in seen:
                        continue
                    seen.add(str(k))
                yield doc
            if len(page) < _PAGE:
                return
            skip += _PAGE
            if skip > _MAX_SKIP:
                self._record_read_error(
                    collection, operation="iter_chunks", error_type="SkipLimitReached",
                    reason=(f"The index key cannot be both sorted and filtered, and $skip "
                            f"cannot exceed {_MAX_SKIP:,}; documents beyond the first "
                            f"{skip:,} results were not read."))
                return

    @staticmethod
    def _chunk(doc: dict, collection: str, lay: dict) -> Chunk:
        emb = doc.get(lay["vec"]) if lay["vec"] else None
        cid = _doc_key(doc, lay)
        return Chunk(id=str(cid), collection=collection,
                     text=doc.get(lay["text"]) if lay["text"] else None,
                     embedding=[float(x) for x in emb] if emb else None,
                     metadata={k: v for k, v in doc.items()
                               if not k.startswith("@") and k != lay["vec"]})

    def delete_chunks(self, collection: str, ids: list[str]) -> int:
        key_field = self._layout_of(collection).get("key") or "id"
        docs = [{key_field: _id} for _id in ids]
        with mapped_errors(self.kind, _ERRORS):
            results = list(self._client(collection).delete_documents(documents=docs))
        deleted = sum(1 for r in results if r.succeeded)
        failures = [f"{getattr(r, 'key', '?')}: {getattr(r, 'error_message', 'failed')}"
                    for r in results if not r.succeeded]
        if failures:
            raise RuntimeError(
                f"failed to delete {len(failures)}/{len(ids)} document(s) from "
                f"'{collection}' (deleted {deleted}): " + "; ".join(failures[:5])
            )
        return deleted

    def query(self, collection: str, vector: list[float], top_k: int = 10,
              where: Optional[dict[str, Any]] = None) -> list[QueryHit]:
        from azure.search.documents.models import VectorizedQuery
        lay = self._layout_of(collection)
        vq = VectorizedQuery(vector=vector, k_nearest_neighbors=top_k, fields=lay["vec"])
        flt = " and ".join(f"{_odata_field(k)} eq {_odata_literal(v)}"
                           for k, v in (where or {}).items()) or None
        client = self._client(collection)
        res = self._read(lambda: list(client.search(
            search_text=None, vector_queries=[vq], top=top_k, filter=flt)))
        hits = []
        for doc in res:
            cid = _doc_key(doc, lay)
            hits.append(QueryHit(id=str(cid), score=float(doc.get("@search.score", 0.0)),
                                 text=doc.get(lay["text"]) if lay["text"] else None,
                                 metadata={k: v for k, v in doc.items()
                                           if not k.startswith("@") and k != lay["vec"]}))
        return hits


def _doc_key(doc: dict, layout: dict) -> Any:
    """The document's key: the index's key field, else the common names."""
    key = layout.get("key")
    if key and doc.get(key) is not None:
        return doc[key]
    return doc.get("id") or doc.get("@search.documentKey") or doc.get("key")


def _retrievable(field: Any) -> bool:
    """Whether the service returns the field: ``retrievable`` (SDK 12) or
    ``hidden`` (SDK 11). Unknown counts as retrievable."""
    if getattr(field, "retrievable", None) is False:
        return False
    return getattr(field, "hidden", None) is not True


def _status_of(exc: BaseException) -> Any:
    status = getattr(exc, "status_code", None)
    if status is None:
        status = getattr(getattr(exc, "response", None), "status_code", None)
    return status


def _odata_field(name: str) -> str:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(/[A-Za-z_][A-Za-z0-9_]*)*", str(name)):
        raise ValueError(f"invalid Azure AI Search filter field: {name!r}")
    return str(name)


def _odata_literal(value: Any) -> str:
    """An OData literal that can only ever compare equal to ``value``.

    Values come from stored metadata; a quote left unescaped would let one
    rewrite the filter.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value)
    return "'" + str(value).replace("'", "''") + "'"
