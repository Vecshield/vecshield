"""Pinecone connector fixes from the scan audit (fake client; pinecone 10.0.0).

* one unreadable or not-ready index is recorded and never hides the rest;
* pod-based indexes have no list(), so enumerating one is unsupported, not
  empty;
* deletes go out in batches of 1,000 ids;
* the integrated-embedding text field is found through ``field_map``;
* the endpoint name carries no characters of the API key;
* SDK v10 list pages (ListResponse) are read by id and retried per page.
"""

from __future__ import annotations

import pytest

pytest.importorskip("pinecone")

from pinecone.errors.exceptions import ServiceError, UnauthorizedError  # noqa: E402
from pinecone.models.vectors.responses import (  # noqa: E402
    ListItem,
    ListResponse,
    Pagination,
)

from vecshield_platform.connectors.base import (  # noqa: E402
    ConnectorAuthError,
    UnsupportedCapability,
)
from vecshield_platform.coverage import count_known  # noqa: E402

_KEY = "pcsk_SECRETabcdef0123456789"


class _Index:
    def __init__(self, records=None, stats=None, pages=None):
        self.records = records or {}
        self.stats = stats if stats is not None else {
            "namespaces": {"": {"vector_count": len(self.records)}}}
        self.pages = pages
        self.deletes: list[list[str]] = []
        self.page_calls: list[dict] = []
        self.fail_next_page = 0

    def describe_index_stats(self):
        if isinstance(self.stats, Exception):
            raise self.stats
        return self.stats

    def list_paginated(self, namespace="", pagination_token=None, **_):
        self.page_calls.append({"namespace": namespace, "token": pagination_token})
        if self.fail_next_page:
            self.fail_next_page -= 1
            raise ServiceError("upstream hiccup")
        if self.pages is not None:
            return self.pages[pagination_token]
        return ListResponse(vectors=[ListItem(id=i) for i in self.records],
                            namespace=namespace, pagination=None)

    def list(self, namespace=""):  # pragma: no cover - list_paginated is preferred
        raise AssertionError("list_paginated should be used when available")

    def fetch(self, ids, namespace=""):
        return {"vectors": {i: {"values": [0.1, 0.2], "metadata": self.records[i]}
                            for i in ids if i in self.records}}

    def delete(self, ids=None, namespace=""):
        self.deletes.append(list(ids))

    def query(self, vector, top_k, namespace="", include_metadata=True, filter=None):
        return {"matches": [{"id": i, "score": 0.9, "metadata": m}
                            for i, m in self.records.items()]}


class _Client:
    def __init__(self, descs, indexes):
        self.descs = descs
        self.indexes = indexes

    def list_indexes(self):
        return list(self.descs)

    def describe_index(self, name):
        return next(d for d in self.descs if d["name"] == name)

    def Index(self, name):  # noqa: N802 - Pinecone API
        index = self.indexes[name]
        if isinstance(index, Exception):
            raise index
        return index


def _connector(monkeypatch, descs, indexes):
    import pinecone

    from vecshield_platform.connectors.pinecone import PineconeConnector

    monkeypatch.setattr(pinecone, "Pinecone", lambda api_key=None: _Client(descs, indexes))
    return PineconeConnector(api_key=_KEY)


def _serverless(name, **extra):
    return {"name": name, "dimension": 2, "status": {"ready": True, "state": "Ready"},
            "spec": {"serverless": {"cloud": "aws", "region": "us-east-1"}}, **extra}


def test_endpoint_name_carries_no_key_characters(monkeypatch):
    conn = _connector(monkeypatch, [], {})
    assert conn._endpoint.startswith("pinecone://key-")
    assert _KEY[:6] not in conn._endpoint and "SECRET" not in conn._endpoint
    assert conn.describe().name == conn._endpoint


def test_not_ready_and_unreadable_indexes_are_recorded_not_dropped(monkeypatch):
    descs = [_serverless("good"),
             {**_serverless("warming"), "status": {"ready": False,
                                                   "state": "Initializing"}},
             _serverless("denied"), _serverless("gone")]
    indexes = {"good": _Index({"a": {"text": "x"}}),
               "warming": _Index(),
               "denied": _Index(stats=UnauthorizedError("key pcsk_LEAK refused")),
               "gone": UnauthorizedError("key pcsk_LEAK refused")}
    conn = _connector(monkeypatch, descs, indexes)
    cols = {c.name: c for c in conn.list_collections()}
    assert set(cols) == {"good", "warming", "denied", "gone"}
    assert count_known(cols["good"]) and cols["good"].count == 1
    for name in ("warming", "denied", "gone"):
        assert not count_known(cols[name]) and cols[name].count == 0
    assert cols["warming"].metadata["index_state"] == "Initializing"
    errors = {e["collection"]: e for e in conn.read_errors()}
    assert errors["warming"]["error_type"] == "IndexNotReady"
    assert errors["denied"]["error_type"] == "ConnectorAuthError"
    assert errors["gone"]["error_type"] == "ConnectorAuthError"
    assert "LEAK" not in repr(conn.read_errors())


def test_pod_index_enumeration_is_unsupported(monkeypatch):
    pod = {"name": "pods", "dimension": 2, "status": {"ready": True, "state": "Ready"},
           "spec": {"pod": {"environment": "us-east-1-aws", "pod_type": "p1.x1"}}}
    conn = _connector(monkeypatch, [pod], {"pods": _Index({"a": {}})})
    cols = conn.list_collections()
    assert cols[0].metadata["index_type"] == "pod"
    with pytest.raises(UnsupportedCapability):
        list(conn.iter_chunks("pods"))
    # Without an inventory first, describe_index decides the same way.
    fresh = _connector(monkeypatch, [pod], {"pods": _Index({"a": {}})})
    with pytest.raises(UnsupportedCapability):
        list(fresh.iter_chunks("pods"))


def test_deletes_go_out_in_batches_of_1000(monkeypatch):
    index = _Index()
    conn = _connector(monkeypatch, [_serverless("rag")], {"rag": index})
    ids = [f"id-{i}" for i in range(2500)]
    assert conn.delete_chunks("rag", ids) == 2500
    assert [len(b) for b in index.deletes] == [1000, 1000, 500]
    assert [i for b in index.deletes for i in b] == ids


def test_field_map_names_the_integrated_embedding_text_field(monkeypatch):
    legacy = _serverless("legacy", embed={"model": "llama-text-embed-v2",
                                          "field_map": {"text": "chunk_text"}})
    modern = {"name": "modern", "status": {"ready": True, "state": "Ready"},
              "deployment": {"deployment_type": "managed", "cloud": "aws",
                             "region": "us-east-1"},
              "schema": {"fields": {"body_md": {"type": "semantic_text",
                                                "model": "llama-text-embed-v2"}}}}
    records = {"legacy": {"r1": {"chunk_text": "ssn 123-45-6789", "text": "decoy"}},
               "modern": {"r2": {"body_md": "card 4111 1111 1111 1111"}}}
    conn = _connector(monkeypatch, [legacy, modern],
                      {name: _Index(recs) for name, recs in records.items()})
    cols = {c.name: c for c in conn.list_collections()}
    assert cols["legacy"].metadata["text_field"] == "chunk_text"
    assert cols["modern"].metadata["text_field"] == "body_md"
    assert [c.text for c in conn.iter_chunks("legacy")] == ["ssn 123-45-6789"]
    assert [c.text for c in conn.iter_chunks("modern")] == ["card 4111 1111 1111 1111"]
    assert conn.query("legacy", [0.1, 0.2])[0].text == "ssn 123-45-6789"


def test_v10_list_pages_are_followed_and_each_page_is_retried(monkeypatch):
    records = {"a": {"text": "1"}, "b": {"text": "2"}, "c": {"text": "3"}}
    pages = {None: ListResponse(vectors=[ListItem(id="a"), ListItem(id="b")],
                                namespace="t1", pagination=Pagination(next="tok")),
             "tok": ListResponse(vectors=[ListItem(id="c")], namespace="t1",
                                 pagination=None)}
    index = _Index(records, stats={"namespaces": {"t1": {"vector_count": 3}}},
                   pages=pages)
    index.fail_next_page = 1  # a transient 5xx on the first page
    monkeypatch.setattr("vecshield_platform.connectors.base.time.sleep",
                        lambda _s: None)
    conn = _connector(monkeypatch, [_serverless("rag")], {"rag": index})
    assert [c.name for c in conn.list_collections()] == ["rag/t1"]
    assert sorted(c.id for c in conn.iter_chunks("rag/t1")) == ["a", "b", "c"]
    assert [c["token"] for c in index.page_calls] == [None, None, "tok"]
    assert all(c["namespace"] == "t1" for c in index.page_calls)


def test_ids_listed_but_not_fetched_are_read_errors(monkeypatch):
    pages = {None: ListResponse(vectors=[ListItem(id="a"), ListItem(id="vanished")],
                                namespace="", pagination=None)}
    index = _Index({"a": {"text": "x"}}, pages=pages)
    conn = _connector(monkeypatch, [_serverless("rag")], {"rag": index})
    assert [c.id for c in conn.iter_chunks("rag")] == ["a"]
    assert conn.read_errors() == [{"collection": "rag", "item_id": "vanished",
                                   "missing": 1, "operation": "fetch",
                                   "error_type": "NotReturned",
                                   "reason": "listed ids were not returned by fetch"}]


def test_sdk_auth_errors_map_and_are_not_retried(monkeypatch):
    class Denied(_Client):
        calls = 0

        def list_indexes(self):
            Denied.calls += 1
            raise UnauthorizedError("Invalid API key pcsk_SECRET")

    import pinecone

    from vecshield_platform.connectors.pinecone import PineconeConnector

    monkeypatch.setattr(pinecone, "Pinecone", lambda api_key=None: Denied([], {}))
    conn = PineconeConnector(api_key=_KEY)
    with pytest.raises(ConnectorAuthError) as info:
        conn.list_collections()
    assert Denied.calls == 1 and "SECRET" not in str(info.value)
