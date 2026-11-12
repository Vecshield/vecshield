"""Mock-based tests for cloud/managed connectors (no live creds here)."""

from __future__ import annotations

import pytest


# ---------------- registry resolves all 12 kinds ----------------

def test_registry_has_all_kinds():
    from vecshield_platform.connectors import AVAILABLE, get_connector
    expected = {"chroma", "pgvector", "qdrant", "weaviate", "milvus", "pinecone",
                "redis", "opensearch", "mongodb", "openai", "azure_search",
                "bedrock_kb", "vertex_ai"}
    assert expected <= set(AVAILABLE)
    for k in expected:
        assert get_connector(k).__name__  # imports without error


# ---------------- OpenAI Vector Stores (managed, no vectors) ----------------

class _OAIFiles:
    def list(self, vector_store_id=None, **_):
        return [type("F", (), {"id": "file_1", "status": "completed",
                               "usage_bytes": 10, "attributes": {}})()]

    def content(self, vector_store_id=None, file_id=None):
        return [type("P", (), {"text": "leaked AKIAIOSFODNN7EXAMPLE in doc"})()]


class _OAIVectorStores:
    files = _OAIFiles()

    def list(self, **_):
        return [type("VS", (), {"id": "vs_1", "name": "kb",
                                "file_counts": type("C", (), {"total": 1})()})()]


class _FakeOpenAI:
    def __init__(self, api_key=None):
        self.vector_stores = _OAIVectorStores()


def test_openai_managed(monkeypatch):
    pytest.importorskip("openai")
    import openai
    monkeypatch.setattr(openai, "OpenAI", _FakeOpenAI)
    from vecshield.classify import RegexClassifier
    from vecshield_platform.connectors.openai_vs import OpenAIVectorStoreConnector
    from vecshield.models import Severity
    from vecshield_platform.scan import scan_store

    conn = OpenAIVectorStoreConnector(api_key="sk-fake")
    assert "query" not in conn.capabilities()  # managed: no vector query
    cols = conn.describe().collections
    assert cols and cols[0].dimension is None
    chunks = list(conn.iter_chunks(cols[0].name))
    assert chunks and chunks[0].embedding is None and "AKIA" in chunks[0].text
    assert scan_store(conn, classifier=RegexClassifier()).max_severity == Severity.CRITICAL


def test_openai_requires_key(monkeypatch):
    pytest.importorskip("openai")
    import openai
    monkeypatch.setattr(openai, "OpenAI", _FakeOpenAI)
    from vecshield_platform.connectors.openai_vs import OpenAIVectorStoreConnector
    with pytest.raises(ValueError):
        OpenAIVectorStoreConnector()


def test_openai_delete_chunks(monkeypatch):
    pytest.importorskip("openai")
    deleted_vs = []
    deleted_files = []

    class _Files2:
        def list(self, vector_store_id=None, **_):
            return []

        def content(self, **_):
            return []

        def delete(self, vector_store_id=None, file_id=None):
            deleted_vs.append(file_id)

    class _FilesTop:
        def delete(self, fid):
            deleted_files.append(fid)

    class _VS2:
        files = _Files2()

        def list(self):
            return []

    class _FakeOAI2:
        def __init__(self, api_key=None):
            self.vector_stores = _VS2()
            self.files = _FilesTop()

    import openai
    monkeypatch.setattr(openai, "OpenAI", _FakeOAI2)
    from vecshield_platform.connectors.openai_vs import OpenAIVectorStoreConnector

    # F6: File-object deletion is opt-in; this store opted in.
    conn = OpenAIVectorStoreConnector(api_key="sk-fake", delete_file_objects=True)
    assert "delete" in conn.capabilities()
    count = conn.delete_chunks("vs_abc", ["file_1", "file_2"])
    assert count == 2
    assert deleted_vs == ["file_1", "file_2"]
    assert deleted_files == ["file_1", "file_2"]
    assert conn.erasure_notes()["file_objects_deleted"] is True


def test_openai_delete_raises_on_failure(monkeypatch):
    """A failed removal must surface (not be swallowed) so erasure evidence is honest."""
    pytest.importorskip("openai")
    class _Files2:
        def list(self, vector_store_id=None, **_):
            return []

        def content(self, **_):
            return []

        def delete(self, vector_store_id=None, file_id=None):
            if file_id == "bad":
                raise RuntimeError("boom")

    class _FilesTop:
        def delete(self, fid):
            pass

    class _VS2:
        files = _Files2()

        def list(self):
            return []

    class _FakeOAI2:
        def __init__(self, api_key=None):
            self.vector_stores = _VS2()
            self.files = _FilesTop()

    import openai
    monkeypatch.setattr(openai, "OpenAI", _FakeOAI2)
    from vecshield_platform.connectors.openai_vs import OpenAIVectorStoreConnector

    conn = OpenAIVectorStoreConnector(api_key="sk-fake")
    with pytest.raises(RuntimeError, match="failed to remove"):
        conn.delete_chunks("vs_abc", ["file_1", "bad"])


# ---------------- MongoDB Atlas (full mode) ----------------

class _FakeColl:
    def list_search_indexes(self):
        return [{"name": "vec_idx", "type": "vectorSearch",
                 "latestDefinition": {"fields": [
                     {"type": "vector", "path": "embedding", "numDimensions": 4}]}}]

    def estimated_document_count(self):
        return 2

    def find_one(self, *a, **k):
        return {"content": "x", "embedding": [0.1, 0.2, 0.3, 0.4]}

    def find(self, *a, **k):
        return [{"_id": 1, "content": "leaked AKIAIOSFODNN7EXAMPLE",
                 "embedding": [0.1, 0.2, 0.3, 0.4], "tenant_id": "acme"},
                {"_id": 2, "content": "benign", "embedding": [0.5, 0.6, 0.7, 0.8],
                 "tenant_id": "globex"}]


class _FakeDB:
    def list_collection_names(self):
        return ["kb"]

    def __getitem__(self, name):
        return _FakeColl()


class _FakeMongo:
    def __init__(self, uri=None):
        pass

    def list_database_names(self):
        return ["appdb", "admin"]

    def __getitem__(self, name):
        return _FakeDB()

    def close(self):
        pass


def test_mongodb_full(monkeypatch):
    pytest.importorskip("pymongo")
    import pymongo
    monkeypatch.setattr(pymongo, "MongoClient", _FakeMongo)
    from vecshield.classify import RegexClassifier
    from vecshield_platform.connectors.mongodb import MongoDBConnector
    from vecshield.models import Severity
    from vecshield_platform.scan import scan_store

    conn = MongoDBConnector(uri="mongodb+srv://fake/db")
    cols = {c.name: c for c in conn.describe().collections}
    assert "appdb.kb" in cols and cols["appdb.kb"].dimension == 4
    chunks = list(conn.iter_chunks("appdb.kb"))
    assert len(chunks) == 2 and all(c.embedding for c in chunks)
    assert scan_store(conn, classifier=RegexClassifier()).max_severity == Severity.CRITICAL


# ---------------- Bedrock KB (inventory only) ----------------

class _FakeBedrock:
    def list_knowledge_bases(self):
        return {"knowledgeBaseSummaries": [
            {"knowledgeBaseId": "kb-1", "name": "support", "status": "ACTIVE"}]}

    def get_knowledge_base(self, knowledgeBaseId=None):
        return {"knowledgeBase": {"storageConfiguration": {"type": "OPENSEARCH_SERVERLESS"}}}


def test_bedrock_inventory(monkeypatch):
    pytest.importorskip("boto3")
    import boto3

    class _Session:
        def __init__(self, **kw):
            pass

        def client(self, service, **kw):
            return _FakeBedrock()

    monkeypatch.setattr(boto3, "Session", _Session)
    from vecshield_platform.connectors.bedrock_kb import BedrockKBConnector
    from vecshield_platform.coverage import count_known

    conn = BedrockKBConnector(region="us-east-1")
    # Inventory only: nothing that reads or changes content, just the
    # data-source encryption configuration.
    assert conn.capabilities() == {"at_rest_introspection"}
    cols = conn.describe().collections
    assert cols and cols[0].metadata["backing_store"] == "OPENSEARCH_SERVERLESS"
    assert not count_known(cols[0])  # Bedrock reports no count: 0 is not one
    assert list(conn.iter_chunks(cols[0].name)) == []  # not enumerable via API


# ---------------- Azure AI Search delete_chunks ----------------

class _FakeAzureResult:
    def __init__(self, succeeded=True):
        self.succeeded = succeeded


class _FakeSearchClient:
    def __init__(self):
        self._deleted = []

    def delete_documents(self, documents=None):
        self._deleted.extend(d.get("id") for d in (documents or []))
        return [_FakeAzureResult(True)] * len(documents or [])

    def get_document_count(self):
        return 5

    def search(self, *a, **k):
        return iter([])


class _FakeAzureField:
    def __init__(self, name, key=False, is_vector=False):
        self.name = name
        self.key = key
        self.type = "Edm.String"
        self.vector_search_dimensions = 4 if is_vector else None


class _FakeAzureIndex:
    def __init__(self, name):
        self.name = name
        self.fields = [_FakeAzureField("id", key=True), _FakeAzureField("content"),
                       _FakeAzureField("embedding", is_vector=True)]


class _FakeAzureIndexClient:
    # Shaped like azure-search-documents 12: list_indexes(), no get_indexes().
    def list_indexes(self):
        return [_FakeAzureIndex("my-index")]

    def get_index(self, name):
        return _FakeAzureIndex(name)


def test_azure_list_collections_uses_sdk12_list_indexes(monkeypatch):
    pytest.importorskip("azure.search.documents")
    import azure.search.documents.indexes
    import azure.core.credentials
    monkeypatch.setattr(azure.search.documents.indexes, "SearchIndexClient",
                        lambda *a, **k: _FakeAzureIndexClient())
    monkeypatch.setattr(azure.core.credentials, "AzureKeyCredential", lambda k: k)

    import azure.search.documents
    monkeypatch.setattr(azure.search.documents, "SearchClient",
                        lambda *a, **k: _FakeSearchClient())

    from vecshield_platform.connectors.azure_search import AzureSearchConnector

    conn = AzureSearchConnector(endpoint="https://fake.search.windows.net",
                                api_key="fake-key")
    cols = conn.list_collections()
    assert [(c.name, c.count, c.dimension) for c in cols] == [("my-index", 5, 4)]


def test_azure_delete_chunks(monkeypatch):
    pytest.importorskip("azure.search.documents")
    search_client_instance = _FakeSearchClient()

    import azure.search.documents.indexes
    import azure.core.credentials
    monkeypatch.setattr(azure.search.documents.indexes, "SearchIndexClient",
                        lambda *a, **k: _FakeAzureIndexClient())
    monkeypatch.setattr(azure.core.credentials, "AzureKeyCredential", lambda k: k)

    import azure.search.documents
    monkeypatch.setattr(azure.search.documents, "SearchClient",
                        lambda *a, **k: search_client_instance)

    from vecshield_platform.connectors.azure_search import AzureSearchConnector

    conn = AzureSearchConnector(endpoint="https://fake.search.windows.net",
                                api_key="fake-key")
    assert "delete" in conn.capabilities()
    count = conn.delete_chunks("my-index", ["doc-1", "doc-2"])
    assert count == 2
    assert "doc-1" in search_client_instance._deleted
    assert "doc-2" in search_client_instance._deleted


def test_azure_delete_raises_on_partial_failure(monkeypatch):
    pytest.importorskip("azure.search.documents")
    class _PartialSearchClient:
        def delete_documents(self, documents=None):
            docs = documents or []
            out = []
            for i, _d in enumerate(docs):
                r = _FakeAzureResult(succeeded=(i == 0))
                r.key = f"doc-{i}"
                r.error_message = None if i == 0 else "not found"
                out.append(r)
            return out

        def get_document_count(self):
            return 5

        def search(self, *a, **k):
            return iter([])

    import azure.core.credentials
    import azure.search.documents
    import azure.search.documents.indexes
    monkeypatch.setattr(azure.search.documents.indexes, "SearchIndexClient",
                        lambda *a, **k: _FakeAzureIndexClient())
    monkeypatch.setattr(azure.core.credentials, "AzureKeyCredential", lambda k: k)
    monkeypatch.setattr(azure.search.documents, "SearchClient",
                        lambda *a, **k: _PartialSearchClient())

    from vecshield_platform.connectors.azure_search import AzureSearchConnector

    conn = AzureSearchConnector(endpoint="https://fake.search.windows.net",
                                api_key="fake-key")
    with pytest.raises(RuntimeError, match="failed to delete"):
        conn.delete_chunks("my-index", ["doc-1", "doc-2"])


# ---------------- Vertex AI Vector Search ----------------
# Deeper coverage (filters, deployed ids, restricts) is in test_vertex_ai_audit.py.

class _FakeIndex:
    def __init__(self, name="idx-1", method="STREAM_UPDATE", removed=None):
        self.name = name
        self.display_name = "my-index"
        self.resource_name = f"projects/p/locations/us-central1/indexes/{name}"
        self._method = method
        self._removed = removed if removed is not None else []

    def to_dict(self):
        out = {"name": self.resource_name, "indexStats": {"vectorsCount": "7"},
               "metadata": {"config": {"dimensions": 768.0}}}
        if self._method:
            out["indexUpdateMethod"] = self._method
        return out

    def remove_datapoints(self, datapoint_ids=None):
        self._removed.extend(datapoint_ids or [])


def _vertex_conn(monkeypatch, indexes, calls=None):
    from google.cloud import aiplatform

    from vecshield_platform.connectors.vertex_ai import VertexAIConnector

    calls = calls if calls is not None else []

    class MatchingEngineIndex:
        @staticmethod
        def list(**kw):
            calls.append(("list", kw))
            return list(indexes)

        def __new__(cls, name, **kw):
            calls.append(("get", name, kw))
            return next(i for i in indexes if i.name == name)

    def no_init(**_kw):
        raise AssertionError("aiplatform.init must not be called")

    monkeypatch.setattr(aiplatform, "init", no_init)
    conn = VertexAIConnector(project="my-proj", location="europe-west4")
    conn._ai = type("AI", (), {"MatchingEngineIndex": MatchingEngineIndex})
    return conn


def test_vertex_ai_inventory(monkeypatch):
    pytest.importorskip("google.cloud.aiplatform")
    calls = []
    conn = _vertex_conn(monkeypatch, [_FakeIndex()], calls)
    assert "query" not in conn.capabilities()  # no endpoint_id
    assert "delete" in conn.capabilities()  # a STREAM_UPDATE index exists
    cols = conn.list_collections()
    assert [(c.name, c.count, c.dimension) for c in cols] == [("idx-1", 7, 768)]
    assert list(conn.iter_chunks(cols[0].name)) == []  # inventory only
    assert all(c[1] == {"project": "my-proj", "location": "europe-west4"}
               for c in calls if c[0] == "list")


def test_vertex_ai_delete_chunks(monkeypatch):
    pytest.importorskip("google.cloud.aiplatform")
    removed = []
    calls = []
    conn = _vertex_conn(monkeypatch, [_FakeIndex(removed=removed)], calls)
    count = conn.delete_chunks("idx-1", ["dp-1", "dp-2"])
    assert count == 2
    assert removed == ["dp-1", "dp-2"]
    assert ("get", "idx-1", {"project": "my-proj", "location": "europe-west4"}) in calls


# ---------------- Pinecone dimension: pre-2026-07 and 2026-07 shapes ----------------

@pytest.mark.parametrize("desc,dimension", [
    ({"name": "idx", "dimension": 1536}, 1536),
    ({"name": "idx", "schema": {"fields": {
        "embedding": {"type": "dense_vector", "dimension": 768, "metric": "cosine"},
        "title": {"type": "string"}}}}, 768),
    ({"name": "idx", "schema": {"fields": {
        "a": {"type": "dense_vector", "dimension": 768},
        "b": {"type": "dense_vector", "dimension": 1024}}}}, None),
    ({"name": "idx", "schema": {"fields": {"kw": {"type": "sparse_vector"}}}}, None),
])
def test_pinecone_dimension_from_either_api_shape(desc, dimension):
    from vecshield_platform.connectors.pinecone import _dimension_of

    assert _dimension_of(desc) == dimension


def test_pinecone_dimension_from_sdk_v10_structs():
    """SDK v10 (verified against pinecone 10.0.0): IndexModel.dimension is a
    deprecated property raising AttributeError unless there is exactly one dense
    field, and DenseVectorField's ``type`` is a msgspec tag, not an attribute."""
    from vecshield_platform.connectors.pinecone import _dimension_of

    class DenseVectorField:
        __struct_config__ = type("C", (), {"tag": "dense_vector"})()

        def __init__(self, dimension):
            self.dimension = dimension

    class SparseVectorField:
        __struct_config__ = type("C", (), {"tag": "sparse_vector"})()

    class IndexModel:
        def __init__(self, fields):
            self.name = "idx"
            self.schema = type("S", (), {"fields": fields})()

        @property
        def dimension(self):
            dense = [f for f in self.schema.fields.values()
                     if isinstance(f, DenseVectorField)]
            if len(dense) == 1:
                return dense[0].dimension
            raise AttributeError("dimension")

    assert _dimension_of(IndexModel({"e": DenseVectorField(384),
                                     "k": SparseVectorField()})) == 384
    assert _dimension_of(IndexModel({"a": DenseVectorField(8),
                                     "b": DenseVectorField(16)})) is None
