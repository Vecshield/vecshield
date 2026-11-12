"""Azure AI Search connector: keyset paging, skip fallback, hidden fields, counts.

No service: SearchClient and SearchIndexClient are fakes shaped like
azure-search-documents 12 (``search(filter=, order_by=, skip=, top=)``,
``get_document_count()``, ``SearchField.retrievable`` / ``hidden``).
"""

from __future__ import annotations

import bisect
import re
from types import SimpleNamespace

import pytest

pytest.importorskip("azure.search.documents")

from azure.core.exceptions import (  # noqa: E402
    ClientAuthenticationError,
    HttpResponseError,
    ServiceRequestError,
)

from vecshield_platform.connectors import azure_search  # noqa: E402
from vecshield_platform.connectors.azure_search import AzureSearchConnector  # noqa: E402
from vecshield_platform.connectors.base import ConnectorAuthError  # noqa: E402
from vecshield_platform.coverage import count_known  # noqa: E402


def _field(name, type_="Edm.String", **attrs):
    return SimpleNamespace(name=name, type=type_, key=attrs.pop("key", False),
                           vector_search_dimensions=attrs.pop("dims", None), **attrs)


def _index(name="docs", key_attrs=None, extra=()):
    return SimpleNamespace(name=name, fields=[
        _field("id", key=True, **(key_attrs or {})),
        _field("content"),
        _field("embedding", "Collection(Edm.Single)", dims=2, retrievable=False),
        *extra])


class _Http400(HttpResponseError):
    def __init__(self):
        super().__init__(message="Invalid expression")
        self.status_code = 400


class _Service:
    """Documents in key order, with the service's $skip ceiling enforced."""

    def __init__(self, keys, *, sortable=True, returned=None):
        self.keys = sorted(keys)
        self.returned = returned  # order of an unordered search, if not key order
        self.sortable = sortable
        self.calls: list[dict] = []

    def search(self, search_text=None, filter=None, order_by=None, top=50, skip=None,
               include_total_count=None, **_):
        self.calls.append({"filter": filter, "order_by": order_by, "top": top, "skip": skip})
        if skip is not None and skip > 100_000:
            raise _Http400()
        if order_by and not self.sortable:
            raise _Http400()
        keys = self.keys if order_by or self.returned is None else self.returned
        start = 0
        if filter:
            m = re.fullmatch(r"id gt '((?:[^']|'')*)'", filter)
            assert m, filter
            start = bisect.bisect_right(keys, m.group(1).replace("''", "'"))
        start += skip or 0
        return iter([{"id": k, "content": f"text {k}", "@search.score": 1.0}
                     for k in keys[start:start + top]])

    def get_document_count(self):
        return len(self.keys)


def _connector(service, index) -> AzureSearchConnector:
    conn = AzureSearchConnector.__new__(AzureSearchConnector)
    conn._endpoint = "https://x.search.windows.net"
    conn._display = conn._endpoint
    conn._ix = SimpleNamespace(get_index=lambda name: index, list_indexes=lambda: [index])
    conn._layout = {}
    conn._read_errors = []
    conn._client = lambda name: service
    return conn


def test_keyset_paging_reads_past_the_skip_ceiling():
    keys = [f"doc-{i:06d}" for i in range(100_500)]
    service = _Service(keys)
    conn = _connector(service, _index(key_attrs={"sortable": True, "filterable": True}))
    ids = [c.id for c in conn.iter_chunks("docs")]
    assert len(ids) == 100_500 and len(set(ids)) == 100_500
    assert all(c["skip"] is None and c["order_by"] == ["id asc"] and c["top"] == 1000
               for c in service.calls)
    assert service.calls[0]["filter"] is None
    assert service.calls[1]["filter"] == "id gt 'doc-000999'"
    assert conn.read_errors() == []


def test_keyset_filter_escapes_quotes(monkeypatch):
    monkeypatch.setattr(azure_search, "_PAGE", 1)
    service = _Service(["a", "o'brien", "z"])
    conn = _connector(service, _index())
    assert [c.id for c in conn.iter_chunks("docs")] == ["a", "o'brien", "z"]
    assert "id gt 'o''brien'" in [c["filter"] for c in service.calls]


def test_skip_fallback_stops_at_the_ceiling_and_says_so():
    keys = [f"doc-{i:06d}" for i in range(101_500)]
    service = _Service(keys, sortable=False)
    conn = _connector(service, _index(key_attrs={"sortable": False, "filterable": True}))
    ids = [c.id for c in conn.iter_chunks("docs")]
    assert len(ids) == 101_000
    assert max(c["skip"] for c in service.calls) == 100_000
    assert all(c["order_by"] is None for c in service.calls)
    (err,) = conn.read_errors()
    assert err["collection"] == "docs" and err["error_type"] == "SkipLimitReached"


def test_key_refused_for_ordering_falls_back_to_skip():
    # Attributes unknown: keyset is tried, the 400 sends it to skip paging.
    service = _Service(["a", "b", "c"], sortable=False)
    conn = _connector(service, _index())
    assert [c.id for c in conn.iter_chunks("docs")] == ["a", "b", "c"]
    assert service.calls[0]["order_by"] == ["id asc"] and service.calls[1]["skip"] == 0


def test_skip_paging_drops_repeated_documents(monkeypatch):
    monkeypatch.setattr(azure_search, "_PAGE", 2)
    service = _Service(["a", "b", "c"], sortable=False, returned=["a", "b", "b", "c"])
    conn = _connector(service, _index(key_attrs={"sortable": False}))
    assert [c.id for c in conn.iter_chunks("docs")] == ["a", "b", "c"]


def test_searchable_fields_that_are_not_retrievable_are_read_errors():
    index = _index(extra=[
        _field("notes", retrievable=False, searchable=True),
        _field("legacy_hidden", hidden=True),                  # SDK 11 attribute
        _field("tags", "Collection(Edm.String)", retrievable=False),
        _field("sort_key", retrievable=False, searchable=False),  # nothing to search
        _field("year", "Edm.Int32", retrievable=False)])
    conn = _connector(_Service(["a"]), index)
    conn.reset_read_errors()
    list(conn.iter_chunks("docs"))
    errors = conn.read_errors()
    assert sorted(e["field"] for e in errors) == ["legacy_hidden", "notes", "tags"]
    assert all(e["collection"] == "docs" and e["error_type"] == "FieldNotRetrievable"
               for e in errors)


def test_count_falls_back_to_a_count_query_then_unknown():
    class _NoCount(_Service):
        def get_document_count(self):
            raise RuntimeError("count endpoint failed")

        def search(self, **kw):
            if kw.get("include_total_count"):
                assert kw.get("top") == 0
                return SimpleNamespace(get_count=lambda: 42)
            return super().search(**kw)

    conn = _connector(_NoCount(["a"]), _index())
    (col,) = conn.list_collections()
    assert col.count == 42 and count_known(col)

    class _Nothing(_NoCount):
        def search(self, **kw):
            raise RuntimeError("search failed too")

    conn = _connector(_Nothing(["a"]), _index())
    (col,) = conn.list_collections()
    assert col.count == 0 and not count_known(col)


def test_errors_are_mapped_and_transient_reads_retried():

    class _Flaky(_Service):
        failures = 1

        def search(self, **kw):
            if self.failures:
                self.failures -= 1
                raise ServiceRequestError("connection reset")
            return super().search(**kw)

    service = _Flaky(["a", "b"])
    conn = _connector(service, _index())
    assert [c.id for c in conn.iter_chunks("docs")] == ["a", "b"]

    class _Denied(_Service):
        def search(self, **kw):
            raise ClientAuthenticationError(message="invalid api-key")

    conn = _connector(_Denied(["a"]), _index())
    with pytest.raises(ConnectorAuthError):
        list(conn.iter_chunks("docs"))
