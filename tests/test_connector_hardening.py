"""Connector write-path injection, delete accounting and collection scope.

Regression tests, all against fakes (no live stores):

* Milvus delete filter built from unescaped ids, and a delete count that was
  the request size rather than the server's answer;
* OpenSearch bulk delete body built by string formatting;
* Azure AI Search reads/queries that ignored the index's key field;
* MongoDB reads of any ``db.collection``, including ``admin.system.users``;
* OpenSearch wildcard / multi-index / system-index collection names;
* Qdrant tenant filters on float values.
"""
from __future__ import annotations

import json
import sys
import types

import pytest


# --------------------------------------------------------------------------- #
# Milvus                                                                      #
# --------------------------------------------------------------------------- #

class _FakeMilvus:
    pk_type = "VARCHAR"
    delete_result: object = {"delete_count": 0}

    def __init__(self, **kw):
        self.deletes: list[str] = []

    def describe_collection(self, name):
        return {"fields": [
            {"name": "doc_id", "type": self.pk_type, "is_primary": True},
            {"name": "vector", "type": "FLOAT_VECTOR", "params": {"dim": 4}},
            {"name": "content", "type": "VARCHAR"},
        ]}

    def delete(self, collection_name, filter):
        self.deletes.append(filter)
        return self.delete_result


@pytest.fixture
def milvus(monkeypatch):
    mod = types.ModuleType("pymilvus")
    mod.MilvusClient = _FakeMilvus
    monkeypatch.setitem(sys.modules, "pymilvus", mod)
    monkeypatch.setattr(_FakeMilvus, "pk_type", "VARCHAR")
    monkeypatch.setattr(_FakeMilvus, "delete_result", {"delete_count": 0})
    from vecshield_platform.connectors.milvus import MilvusConnector
    return MilvusConnector(uri="http://127.0.0.1:19530")


def test_milvus_string_ids_are_escaped(milvus):
    hostile = 'x"] or doc_id not in ["'
    milvus.delete_chunks("kb", [hostile, "a\\b"])
    assert milvus._client.deletes[-1] == \
        'doc_id in ["x\\"] or doc_id not in [\\"", "a\\\\b"]'


def test_milvus_numeric_pk_rejects_non_integer_ids(monkeypatch, milvus):
    monkeypatch.setattr(_FakeMilvus, "pk_type", "INT64")
    with pytest.raises(ValueError):
        milvus.delete_chunks("kb", ["1 or doc_id >= 0"])
    assert milvus._client.deletes == []
    milvus.delete_chunks("kb", ["1", " 2", 3])
    assert milvus._client.deletes[-1] == "doc_id in [1, 2, 3]"


def test_milvus_reports_the_servers_delete_count(monkeypatch, milvus):
    assert milvus.delete_chunks("kb", ["a", "b", "c"]) == 0
    monkeypatch.setattr(_FakeMilvus, "delete_result", types.SimpleNamespace(delete_count=2))
    assert milvus.delete_chunks("kb", ["a", "b", "c"]) == 2
    assert milvus.delete_chunks("kb", []) == 0


# --------------------------------------------------------------------------- #
# OpenSearch                                                                  #
# --------------------------------------------------------------------------- #

class _FakeOS:
    def __init__(self, **kw):
        self.bodies: list = []

    def bulk(self, body):
        self.bodies.append(body)
        lines = body if isinstance(body, list) else body.strip().split("\n")
        items = []
        for line in lines:
            action = json.loads(line) if isinstance(line, str) else line
            items.append({"delete": {"_index": action["delete"]["_index"],
                                     "_id": action["delete"]["_id"], "result": "deleted"}})
        return {"items": items}


@pytest.fixture
def opensearch(monkeypatch):
    mod = types.ModuleType("opensearchpy")
    mod.OpenSearch = _FakeOS
    monkeypatch.setitem(sys.modules, "opensearchpy", mod)
    from vecshield_platform.connectors.opensearch import OpenSearchConnector
    return OpenSearchConnector(host="127.0.0.1", port=9200)


def _actions(body):
    lines = body if isinstance(body, list) else body.strip().split("\n")
    return [json.loads(line) if isinstance(line, str) else line for line in lines]


@pytest.mark.parametrize("chunk_id", [
    'x"}}\n{"delete":{"_index":"audit-trail","_id":"42',
    r"C:\docs\contract.pdf#3",
    'quote " and newline \n and tab \t',
])
def test_opensearch_bulk_delete_names_only_the_requested_ids(opensearch, chunk_id):
    n = opensearch.delete_chunks("kb", [chunk_id, "plain"])
    actions = _actions(opensearch._c.bodies[-1])
    assert [a["delete"] for a in actions] == [
        {"_index": "kb", "_id": chunk_id}, {"_index": "kb", "_id": "plain"}]
    assert n == 2


@pytest.mark.parametrize("bad", ["*", "kb,audit", ".security", "_all", "-kb", "kb*"])
def test_opensearch_rejects_wildcard_and_system_index_names(opensearch, bad):
    for call in (lambda: list(opensearch.iter_chunks(bad)),
                 lambda: opensearch.query(bad, [0.1], top_k=1),
                 lambda: opensearch.delete_chunks(bad, ["1"])):
        with pytest.raises(ValueError):
            call()
    assert opensearch._c.bodies == []


# --------------------------------------------------------------------------- #
# MongoDB                                                                     #
# --------------------------------------------------------------------------- #

class _MColl:
    def __init__(self, db, name, vector):
        self.db, self.name, self.vector = db, name, vector
        self.reads = 0

    def list_search_indexes(self):
        if not self.vector:
            return []
        return [{"name": "vec_idx", "type": "vectorSearch",
                 "latestDefinition": {"fields": [
                     {"type": "vector", "path": "embedding", "numDimensions": 2}]}}]

    def estimated_document_count(self):
        return 1

    def find_one(self, *a, **k):
        self.reads += 1
        return {"content": "x", "embedding": [0.1, 0.2]}

    def find(self, *a, **k):
        self.reads += 1
        return [{"_id": 1, "content": f"{self.db}.{self.name} row", "embedding": [0.1, 0.2]}]

    def aggregate(self, pipe):
        self.reads += 1
        return []

    def delete_many(self, flt):
        self.reads += 1
        return types.SimpleNamespace(deleted_count=0)


class _MDB:
    def __init__(self, name, colls):
        self.name, self._colls = name, colls

    def list_collection_names(self):
        return list(self._colls)

    def __getitem__(self, coll):
        return self._colls.setdefault(coll, _MColl(self.name, coll, False))


class _MClient:
    def __init__(self, uri=None):
        self.dbs = {
            "app": _MDB("app", {"kb": _MColl("app", "kb", True),
                                "users": _MColl("app", "users", False)}),
            "admin": _MDB("admin", {"system.users": _MColl("admin", "system.users", True)}),
        }

    def list_database_names(self):
        return list(self.dbs)

    def __getitem__(self, db):
        return self.dbs.setdefault(db, _MDB(db, {}))


@pytest.fixture
def mongo(monkeypatch):
    pytest.importorskip("pymongo")
    import pymongo
    monkeypatch.setattr(pymongo, "MongoClient", _MClient)
    from vecshield_platform.connectors.mongodb import MongoDBConnector
    return MongoDBConnector(uri="mongodb://svc:pw@db:27017/app")


def test_mongo_vector_collections_are_readable(mongo):
    assert [c.name for c in mongo.list_collections()] == ["app.kb"]
    assert [c.text for c in mongo.iter_chunks("app.kb")] == ["app.kb row"]


@pytest.mark.parametrize("name", ["admin.system.users", "app.users", "app.system.js",
                                  "nosuch.coll", "nodot"])
def test_mongo_refuses_collections_outside_the_vector_inventory(mongo, name):
    for call in (lambda: list(mongo.iter_chunks(name)),
                 lambda: mongo.query(name, [0.1, 0.2], top_k=1),
                 lambda: mongo.get_chunks(name, ["1"]),
                 lambda: mongo.delete_chunks(name, ["1"])):
        with pytest.raises(ValueError):
            call()
    admin_users = mongo._c.dbs["admin"]._colls["system.users"]
    assert admin_users.reads == 0
    assert mongo._c.dbs["app"]._colls["users"].reads == 0


# --------------------------------------------------------------------------- #
# Azure AI Search key field                                                   #
# --------------------------------------------------------------------------- #

class _AField:
    def __init__(self, name, type_, key=False, dims=None):
        self.name, self.type, self.key, self.vector_search_dimensions = name, type_, key, dims


class _AIndex:
    def __init__(self, name):
        self.name = name
        self.fields = [_AField("chunk_id", "Edm.String", key=True),
                       _AField("parent_id", "Edm.String"),
                       _AField("chunk", "Edm.String"),
                       _AField("text_vector", "Collection(Edm.Single)", dims=2)]


class _AIndexClient:
    def get_index(self, name):
        return _AIndex(name)


class _ASearchClient:
    def __init__(self):
        self.deleted = []

    def search(self, search_text=None, vector_queries=None, **_):
        return [{"chunk_id": "c-1", "parent_id": "p-1", "chunk": "hello",
                 "text_vector": [0.1, 0.2], "@search.score": 0.5}]

    def delete_documents(self, documents=None):
        self.deleted.append(documents)
        return [types.SimpleNamespace(succeeded=True, key=d["chunk_id"]) for d in documents]


@pytest.fixture
def azure(monkeypatch):
    from vecshield_platform.connectors.azure_search import AzureSearchConnector
    conn = AzureSearchConnector.__new__(AzureSearchConnector)
    conn._endpoint, conn._ix, conn._layout = "https://x.search.windows.net", _AIndexClient(), {}
    client = _ASearchClient()
    conn._client = lambda index: client
    return conn, client


def test_azure_uses_the_index_key_field(azure, monkeypatch):
    conn, client = azure
    assert [c.id for c in conn.iter_chunks("rag")] == ["c-1"]
    vq = types.ModuleType("azure.search.documents.models")
    vq.VectorizedQuery = lambda **kw: types.SimpleNamespace(**kw)
    monkeypatch.setitem(sys.modules, "azure.search.documents.models", vq)
    assert [h.id for h in conn.query("rag", [0.1, 0.2], top_k=1)] == ["c-1"]
    assert conn.delete_chunks("rag", ["c-1"]) == 1
    assert client.deleted == [[{"chunk_id": "c-1"}]]
    assert conn._layout["rag"]["key"] == "chunk_id"


# --------------------------------------------------------------------------- #
# Qdrant float tenant filter                                                  #
# --------------------------------------------------------------------------- #

def test_qdrant_filter_handles_float_values():
    pytest.importorskip("qdrant_client")
    from qdrant_client import QdrantClient, models
    from vecshield_platform.connectors.qdrant import QdrantConnector, _build_filter

    flt = _build_filter({"tenant_id": 1.5, "n": 2, "s": "acme", "b": True})
    by_key = {c.key: c for c in flt.must}
    assert by_key["tenant_id"].range == models.Range(gte=1.5, lte=1.5)
    assert by_key["tenant_id"].match is None
    assert by_key["n"].match == models.MatchValue(value=2)
    assert by_key["s"].match == models.MatchValue(value="acme")
    assert by_key["b"].match == models.MatchValue(value=True)

    cl = QdrantClient(":memory:")
    cl.create_collection("f", vectors_config=models.VectorParams(
        size=2, distance=models.Distance.EUCLID))
    cl.upsert("f", points=[models.PointStruct(id=i, vector=[float(i), 1.0],
                                              payload={"tenant_id": v})
                           for i, v in enumerate([1.5, 1.5, 2.5, 2.5])])
    conn = QdrantConnector.__new__(QdrantConnector)
    conn._client, conn._endpoint = cl, "mem"
    hits = conn.query("f", [0.0, 1.0], top_k=10, where={"tenant_id": 2.5})
    assert sorted(h.id for h in hits) == ["2", "3"]
