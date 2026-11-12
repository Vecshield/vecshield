"""Store facts (server info, location, model egress, aliases, distance metrics)
for the self-hosted connectors, through ``vecshield_platform.store_facts``.

Connectors are built with ``__new__`` and a fake client, as in
tests/test_crypto_at_rest.py, so no SDK or server is needed. One Chroma test
uses the real embedded chromadb when it is installed.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest

from vecshield_platform import store_facts as sf
from vecshield_platform.connectors.base import Connector, UnsupportedCapability
from vecshield_platform.connectors.chroma import ChromaConnector
from vecshield_platform.connectors.milvus import MilvusConnector
from vecshield_platform.connectors.mongodb import MongoDBConnector
from vecshield_platform.connectors.opensearch import OpenSearchConnector
from vecshield_platform.connectors.pgvector import PgVectorConnector
from vecshield_platform.connectors.qdrant import QdrantConnector
from vecshield_platform.connectors.redis import RedisConnector
from vecshield_platform.connectors.weaviate import WeaviateConnector
from vecshield.models import Collection


def _no_secrets(result: Any, *secrets: str) -> None:
    text = json.dumps(result, default=str)
    for secret in secrets:
        assert secret not in text, f"{secret!r} leaked into {text}"


class _HTTPError(Exception):
    def __init__(self, status: int, msg: str = "") -> None:
        super().__init__(msg or f"HTTP {status}")
        self.status_code = status


def _shape_location(loc: dict) -> None:
    assert set(loc) == {"provider", "region", "replica_regions", "source", "observable",
                        "reason", "evidence"}


def _shape_server(info: dict) -> None:
    assert set(info) == {"product", "version", "edition", "managed", "source", "reason",
                         "features"}


def _shape_integrations(res: dict) -> None:
    assert set(res) == {"observable", "reason", "source", "integrations", "controls"}
    for entry in res["integrations"]:
        assert set(entry) == {"collection", "stage", "provider", "model", "endpoint_host",
                              "auth", "module", "evidence"}
        assert entry["stage"] in ("ingest", "query", "generate", "rerank")
        assert entry["auth"] in ("managed_identity", "api_key", "none", "unknown")


# ================================================================ dispatcher #

class _Overriding(Connector):
    kind = "qdrant"

    def describe(self):  # pragma: no cover - not used
        raise NotImplementedError

    def list_collections(self):
        return [Collection(name="a", distance_metric="cosine")]

    def iter_chunks(self, collection, batch_size=256):  # pragma: no cover
        return iter(())

    def server_info(self):
        return {"product": "own"}


class _NoAdapter(_Overriding):
    kind = "nosuchstore"

    server_info = Connector.server_info  # back to the base method


def test_dispatch_prefers_the_connectors_own_method():
    assert sf.server_info(_Overriding()) == {"product": "own"}


def test_dispatch_without_adapter_is_unsupported():
    conn = _NoAdapter()
    with pytest.raises(UnsupportedCapability):
        sf.server_info(conn)
    with pytest.raises(UnsupportedCapability):
        sf.list_aliases(conn)
    assert sf.supported(conn) == set()
    # distance falls back to what the connector reports on its collections
    assert sf.distance_metrics(conn) == {"a": "cosine"}


def test_kind_is_never_used_as_an_arbitrary_module_path():
    conn = _NoAdapter()
    conn.kind = "..connectors.base"
    with pytest.raises(UnsupportedCapability):
        sf.store_location(conn)


def test_supported_matches_the_adapters():
    assert sf.supported(_qdrant(_FakeQdrant())) == {
        "server_info", "location_introspection", "egress_introspection", "aliases"}
    assert sf.supported(_redis(_FakeRedis())) == {
        "server_info", "location_introspection", "aliases"}
    assert sf.supported(_chroma(_FakeChroma([]))) == {
        "server_info", "location_introspection", "egress_introspection"}
    assert "aliases" not in sf.supported(_pg(_PgConn({})))
    assert "aliases" not in sf.supported(_mongo(_FakeMongo()))


# ==================================================================== qdrant #

class _FakeQdrant:
    def __init__(self, collections=None, info_exc=None, aliases=()):
        self.collections = collections or {}
        self.info_exc = info_exc
        self.aliases = aliases

    def info(self):
        if self.info_exc:
            raise self.info_exc
        return SimpleNamespace(title="qdrant - vector search engine", version="1.12.4",
                               commit="deadbeef")

    def get_collections(self):
        return SimpleNamespace(collections=[SimpleNamespace(name=n) for n in self.collections])

    def get_collection(self, name):
        return SimpleNamespace(config=SimpleNamespace(params=SimpleNamespace(
            vectors=self.collections[name])))

    def get_aliases(self):
        return SimpleNamespace(aliases=[SimpleNamespace(alias_name=a, collection_name=c)
                                        for a, c in self.aliases])


def _qdrant(client, endpoint="http://localhost:6333"):
    c = QdrantConnector.__new__(QdrantConnector)
    c._client = client
    c._endpoint = endpoint
    return c


def _vp(distance):
    return SimpleNamespace(size=4, distance=SimpleNamespace(value=distance))


def test_qdrant_server_info_and_self_hosted_location():
    conn = _qdrant(_FakeQdrant())
    info = sf.server_info(conn)
    _shape_server(info)
    assert info["product"] == "qdrant" and info["version"] == "1.12.4"
    assert info["managed"] is False and info["features"] == {"commit": "deadbeef"}
    loc = sf.store_location(conn)
    _shape_location(loc)
    assert loc["provider"] == "self_hosted" and loc["observable"] is False
    assert "cannot place" in loc["reason"]


def test_qdrant_cloud_hostname_gives_region():
    conn = _qdrant(_FakeQdrant(), "https://xyz-example.eu-central.aws.cloud.qdrant.io")
    loc = sf.store_location(conn)
    assert loc["provider"] == "qdrant_cloud" and loc["region"] == "eu-central"
    assert loc["observable"] is True and loc["evidence"]["cloud"] == "aws"
    info = sf.server_info(conn)
    assert info["managed"] is True and info["edition"] == "qdrant_cloud"


def test_qdrant_public_unknown_host_is_not_guessed():
    loc = sf.store_location(_qdrant(_FakeQdrant(), "https://vectors.example.com"))
    assert loc["provider"] is None and loc["region"] is None and loc["observable"] is False


def test_qdrant_server_info_denied_is_reported_not_raised():
    info = sf.server_info(_qdrant(_FakeQdrant(info_exc=_HTTPError(403, "forbidden"))))
    assert info["version"] is None and "refused" in info["reason"]


def test_qdrant_distance_metrics_single_named_and_mixed():
    conn = _qdrant(_FakeQdrant({
        "single": _vp("Cosine"),
        "named_same": {"a": _vp("Dot"), "b": _vp("Dot")},
        "named_mixed": {"a": _vp("Cosine"), "b": _vp("Euclid")},
        "manhattan": _vp("Manhattan"),
    }))
    assert sf.distance_metrics(conn) == {"single": "cosine", "named_same": "dot",
                                         "named_mixed": None, "manhattan": "manhattan"}
    details = sf.distance_metric_details(conn)
    assert details["named_mixed"]["vector_metrics"] == {"a": "Cosine", "b": "Euclid"}


def test_qdrant_aliases_and_egress_not_observable():
    conn = _qdrant(_FakeQdrant(aliases=[("live", "docs_v2")]))
    assert sf.list_aliases(conn) == {"live": "docs_v2"}
    res = sf.model_integrations(conn)
    _shape_integrations(res)
    assert res["observable"] is False and res["integrations"] == []
    assert "per request" in res["reason"]


# ================================================================== weaviate #

class _Cfg:
    def __init__(self, data):
        self._data = data

    def to_dict(self):
        return json.loads(json.dumps(self._data))


class _FakeWeaviate:
    def __init__(self, meta=None, schemas=None, schema_exc=None, aliases=None):
        self.meta = meta or {"version": "1.33.0", "modules": {}}
        self._schemas = schemas or {}
        self._schema_exc = schema_exc
        self.collections = SimpleNamespace(list_all=self._list_all)
        if aliases is not None:
            self.alias = SimpleNamespace(list_all=lambda: {
                a: SimpleNamespace(alias=a, collection=c) for a, c in aliases.items()})

    def get_meta(self):
        return self.meta

    def _list_all(self, simple=True):
        assert simple is False
        if self._schema_exc:
            raise self._schema_exc
        return {n: _Cfg(s) for n, s in self._schemas.items()}


def _weaviate(client, endpoint="http://localhost:8080"):
    c = WeaviateConnector.__new__(WeaviateConnector)
    c._client = client
    c._endpoint = endpoint
    return c


_WV_META = {"version": "1.33.1", "hostname": "http://[::]:8080", "modules": {
    "text2vec-openai": {"name": "OpenAI Module"},
    "generative-cohere": {"name": "Generative Search - Cohere"},
    "text2vec-transformers": {"model": {"_name_or_path": "sentence-transformers"}},
    "backup-s3": {"name": "Backup S3"},
}}
_WV_SCHEMAS = {
    "Docs": {"class": "Docs", "vectorizer": "text2vec-openai",
             "vectorIndexConfig": {"distanceMetric": "cosine"},
             "moduleConfig": {
                 "text2vec-openai": {"model": "text-embedding-3-small",
                                     "baseURL": "https://api.openai.com",
                                     "apiKey": "sk-WEAVIATE-SECRET"},
                 "generative-openai": {"model": "gpt-4o",
                                       "headers": {"X-OpenAI-Api-Key": "sk-HEADER"}}}},
    "Multi": {"class": "Multi", "vectorizer": "none", "moduleConfig": {},
              "vectorConfig": {
                  "title": {"vectorizer": {"text2vec-cohere": {"model": "embed-v3"}},
                            "vectorIndexConfig": {"distance": "l2-squared"}},
                  "bits": {"vectorizer": {"none": {}},
                           "vectorIndexConfig": {"distance": "hamming"}}}},
    "Local": {"class": "Local", "vectorizer": "text2vec-ollama",
              "vectorIndexConfig": {"distance": "dot"},
              "moduleConfig": {"text2vec-ollama": {"apiEndpoint": "http://ollama:11434",
                                                   "model": "nomic-embed-text"}}},
}


def test_weaviate_server_info_lists_modules():
    info = sf.server_info(_weaviate(_FakeWeaviate(meta=_WV_META)))
    assert info["product"] == "weaviate" and info["version"] == "1.33.1"
    assert info["features"]["modules"] == sorted(_WV_META["modules"])
    assert info["managed"] is False


def test_weaviate_distance_metrics_normalised_and_hamming_is_none():
    conn = _weaviate(_FakeWeaviate(schemas=_WV_SCHEMAS))
    metrics = sf.distance_metrics(conn)
    assert metrics["Docs"] == "cosine" and metrics["Local"] == "dot"
    assert metrics["Multi"] is None  # l2-squared + hamming disagree
    details = sf.distance_metric_details(conn)
    assert details["Multi"]["vector_metrics"] == {"title": "l2-squared", "bits": "hamming"}
    only_l2 = {"X": {"vectorConfig": {"v": {"vectorIndexConfig": {"distance": "l2-squared"}}}}}
    assert sf.distance_metrics(_weaviate(_FakeWeaviate(schemas=only_l2))) == {"X": "euclidean"}


def test_weaviate_model_integrations_modules_and_collections_without_secrets():
    res = sf.model_integrations(_weaviate(_FakeWeaviate(meta=_WV_META, schemas=_WV_SCHEMAS)))
    _shape_integrations(res)
    assert res["observable"] is True
    _no_secrets(res, "sk-WEAVIATE-SECRET", "sk-HEADER", "apiKey", "X-OpenAI-Api-Key")
    store_wide = {e["module"]: e for e in res["integrations"] if e["collection"] is None}
    assert set(store_wide) == {"text2vec-openai", "generative-cohere", "text2vec-transformers"}
    assert store_wide["text2vec-transformers"]["provider"] == "self_hosted"
    assert store_wide["text2vec-transformers"]["auth"] == "none"
    assert store_wide["generative-cohere"]["stage"] == "generate"
    docs = [e for e in res["integrations"] if e["collection"] == "Docs"]
    ingest = next(e for e in docs if e["stage"] == "ingest")
    assert ingest["provider"] == "openai" and ingest["model"] == "text-embedding-3-small"
    assert ingest["endpoint_host"] == "api.openai.com" and ingest["auth"] == "api_key"
    gen = next(e for e in docs if e["stage"] == "generate")
    assert gen["provider"] == "openai" and gen["model"] == "gpt-4o"
    multi = [e for e in res["integrations"] if e["collection"] == "Multi"]
    assert [(e["provider"], e["model"], e["evidence"]["vector"]) for e in multi] == [
        ("cohere", "embed-v3", "title")]
    local = next(e for e in res["integrations"] if e["collection"] == "Local")
    assert local["provider"] == "self_hosted" and local["endpoint_host"] == "ollama"


def test_weaviate_schema_denied_is_not_observable():
    res = sf.model_integrations(_weaviate(_FakeWeaviate(
        meta=_WV_META, schema_exc=_HTTPError(403, "forbidden"))))
    assert res["observable"] is False and "read_collections" in res["reason"]
    assert any(e["collection"] is None for e in res["integrations"])  # meta still read


def test_weaviate_aliases_are_version_gated():
    old = _weaviate(_FakeWeaviate(meta={"version": "1.31.4"}, aliases={"a": "B"}))
    with pytest.raises(UnsupportedCapability):
        sf.list_aliases(old)
    new = _weaviate(_FakeWeaviate(meta={"version": "1.32.0"}, aliases={"Live": "Docs_v2"}))
    assert sf.list_aliases(new) == {"Live": "Docs_v2"}
    no_client_api = _weaviate(_FakeWeaviate(meta={"version": "1.32.0"}))
    with pytest.raises(UnsupportedCapability):
        sf.list_aliases(no_client_api)


def test_weaviate_cloud_location():
    loc = sf.store_location(_weaviate(
        _FakeWeaviate(), "https://ne3wnkulta2jutxerkzpea.c0.europe-west3.gcp.weaviate.cloud"))
    assert loc["provider"] == "weaviate_cloud" and loc["region"] == "europe-west3"
    assert loc["observable"] is True and loc["evidence"]["cloud"] == "gcp"
    legacy = sf.store_location(_weaviate(_FakeWeaviate(), "https://my-sandbox.weaviate.network"))
    assert legacy["provider"] == "weaviate_cloud" and legacy["observable"] is False


# ==================================================================== milvus #

class _FakeMilvus:
    def __init__(self, version="v2.6.2", collections=None, indexes=None, describe_exc=None):
        self.version = version
        self.collections = collections or {}
        self.indexes = indexes or {}
        self.describe_exc = describe_exc

    def get_server_version(self):
        if isinstance(self.version, Exception):
            raise self.version
        return self.version

    def list_collections(self):
        return list(self.collections)

    def describe_collection(self, name):
        if self.describe_exc:
            raise self.describe_exc
        return self.collections[name]

    def list_indexes(self, collection_name):
        return list(self.indexes.get(collection_name, {}))

    def describe_index(self, collection_name, index_name):
        return self.indexes[collection_name][index_name]


def _milvus(client, uri="http://localhost:19530"):
    c = MilvusConnector.__new__(MilvusConnector)
    c._client = client
    c._uri = uri
    c._endpoint = uri
    return c


def test_milvus_server_info_and_zilliz_string():
    info = sf.server_info(_milvus(_FakeMilvus()))
    assert info["product"] == "milvus" and info["version"] == "2.6.2"
    assert info["managed"] is False
    z = sf.server_info(_milvus(_FakeMilvus(
        version="Zilliz Cloud Vector Database(Compatible with Milvus 2.5)")))
    assert z["edition"] == "zilliz_cloud" and z["managed"] is True and z["version"] == "2.5"
    denied = sf.server_info(_milvus(_FakeMilvus(version=Exception("permission deny"))))
    assert denied["version"] is None and "refused" in denied["reason"]


def test_milvus_distance_metrics_from_indexes():
    conn = _milvus(_FakeMilvus(
        collections={"a": {}, "b": {}, "c": {}, "d": {}},
        indexes={"a": {"i": {"metric_type": "COSINE", "field_name": "vec"}},
                 "b": {"i": {"metric_type": "IP", "field_name": "vec"},
                       "j": {"metric_type": "L2", "field_name": "vec2"}},
                 "c": {"i": {"metric_type": "HAMMING", "field_name": "bits"}}}))
    assert sf.distance_metrics(conn) == {"a": "cosine", "b": None, "c": None, "d": None}
    assert sf.distance_metric_details(conn)["c"]["vector_metrics"] == {"bits": "HAMMING"}


def test_milvus_text_embedding_functions_without_credentials():
    collections = {
        "docs": {"aliases": ["docs_live"], "functions": [
            {"name": "openai_embedding", "type": SimpleNamespace(name="TEXTEMBEDDING"),
             "input_field_names": ["document"], "output_field_names": ["dense"],
             "params": {"provider": "openai", "model_name": "text-embedding-3-small",
                        "credential": "apikey_prod", "dim": "1536"}},
            {"name": "bm25", "type": 1, "params": {}}]},
        "local": {"functions": [
            {"name": "tei", "type": 2, "params": {"provider": "TEI",
                                                  "endpoint": "http://tei:8080"}}]},
    }
    conn = _milvus(_FakeMilvus(collections=collections))
    res = sf.model_integrations(conn)
    _shape_integrations(res)
    assert res["observable"] is True and len(res["integrations"]) == 2
    _no_secrets(res, "apikey_prod")
    docs = next(e for e in res["integrations"] if e["collection"] == "docs")
    assert (docs["provider"], docs["model"], docs["auth"]) == (
        "openai", "text-embedding-3-small", "api_key")
    local = next(e for e in res["integrations"] if e["collection"] == "local")
    assert local["provider"] == "self_hosted" and local["endpoint_host"] == "tei"
    assert sf.list_aliases(conn) == {"docs_live": "docs"}


def test_milvus_describe_denied_is_not_observable():
    res = sf.model_integrations(_milvus(_FakeMilvus(
        collections={"x": {}}, describe_exc=Exception("PERMISSION DENIED: privilege"))))
    assert res["observable"] is False and "DescribeCollection" in res["reason"]


def test_milvus_location_zilliz_and_lite():
    loc = sf.store_location(_milvus(
        _FakeMilvus(), "https://in03-abc123.serverless.gcp-us-west1.vectordb.zillizcloud.com"))
    assert loc["provider"] == "zilliz" and loc["region"] == "gcp-us-west1"
    dedicated = sf.store_location(_milvus(
        _FakeMilvus(), "https://in01-xyz.aws-us-west-2.vectordb.zillizcloud.com:19530"))
    assert dedicated["region"] == "aws-us-west-2"
    lite = sf.store_location(_milvus(_FakeMilvus(), "./milvus_demo.db"))
    assert lite["provider"] == "self_hosted" and lite["evidence"]["host_class"] == "local_file"
    userinfo = sf.store_location(_milvus(_FakeMilvus(), "http://root:Milvus-PW@10.0.0.5:19530"))
    assert userinfo["provider"] == "self_hosted"
    _no_secrets(userinfo, "Milvus-PW", "root")


# ==================================================================== chroma #

class _FakeChroma:
    def __init__(self, cols, version="1.0.20"):
        self.cols = cols
        self.version = version

    def get_version(self):
        return self.version

    def list_collections(self):
        return self.cols


def _col(name, cfg=None, metadata=None):
    return SimpleNamespace(name=name, configuration_json=cfg or {}, metadata=metadata)


def _chroma(client, endpoint="http://localhost:8000"):
    c = ChromaConnector.__new__(ChromaConnector)
    c._client = client
    c._endpoint = endpoint
    return c


def test_chroma_metrics_from_configuration_and_legacy_metadata():
    conn = _chroma(_FakeChroma([
        _col("cfg", {"hnsw": {"space": "cosine"}}),
        _col("spann", {"spann": {"space": "ip"}}),
        _col("legacy", {}, {"hnsw:space": "l2"}),
        _col("unknown", {}),
    ]))
    assert sf.distance_metrics(conn) == {"cfg": "cosine", "spann": "dot",
                                         "legacy": "euclidean", "unknown": None}


def test_chroma_embedding_function_config_is_reported_without_secrets():
    ef = {"type": "known", "name": "openai", "config": {
        "api_key_env_var": "CHROMA_OPENAI_API_KEY", "model_name": "text-embedding-3-small",
        "api_base": "https://api.openai.com/v1",
        "default_headers": {"Authorization": "Bearer sk-CHROMA-SECRET"}}}
    conn = _chroma(_FakeChroma([
        _col("docs", {"embedding_function": ef}),
        _col("local", {"embedding_function": {"type": "known", "name": "default",
                                               "config": {}}}),
        _col("azure", {"embedding_function": {"type": "known", "name": "openai", "config": {
            "api_type": "azure", "api_base": "https://acme.openai.azure.com",
            "model_name": "ada"}}}),
        _col("old", {"embedding_function": {"type": "legacy"}}),
    ]))
    res = sf.model_integrations(conn)
    _shape_integrations(res)
    _no_secrets(res, "sk-CHROMA-SECRET", "CHROMA_OPENAI_API_KEY", "Authorization")
    by = {e["collection"]: e for e in res["integrations"]}
    assert (by["docs"]["provider"], by["docs"]["model"], by["docs"]["endpoint_host"],
            by["docs"]["auth"]) == ("openai", "text-embedding-3-small", "api.openai.com",
                                    "api_key")
    assert by["docs"]["evidence"]["execution"] == "client"
    assert by["local"]["provider"] == "local" and by["local"]["auth"] == "none"
    assert by["azure"]["provider"] == "azure_openai"
    assert by["old"]["provider"] == "unknown"


def test_chroma_server_info_and_location():
    info = sf.server_info(_chroma(_FakeChroma([])))
    assert info["product"] == "chroma" and info["version"] == "1.0.20"
    assert info["source"] == "GET /api/v2/version"
    loc = sf.store_location(_chroma(_FakeChroma([])))
    assert loc["provider"] == "self_hosted"
    embedded = _chroma(_FakeChroma([]), "file:///data/chroma")
    assert sf.server_info(embedded)["edition"] == "embedded"
    assert sf.store_location(embedded)["evidence"]["host_class"] == "local_file"
    cloud = sf.store_location(_chroma(_FakeChroma([]), "http://api.trychroma.com:443"))
    assert cloud["provider"] == "chroma_cloud" and cloud["observable"] is False


def test_chroma_real_embedded_store(tmp_path):
    chromadb = pytest.importorskip("chromadb")
    client = chromadb.PersistentClient(path=str(tmp_path))
    client.create_collection("cos", configuration={"hnsw": {"space": "cosine"}})
    client.create_collection("inner", configuration={"hnsw": {"space": "ip"}})
    conn = ChromaConnector(path=str(tmp_path))
    try:
        assert sf.distance_metrics(conn) == {"cos": "cosine", "inner": "dot"}
        res = sf.model_integrations(conn)
        assert res["observable"] is True
        assert {e["collection"]: e["provider"] for e in res["integrations"]} == {
            "cos": "local", "inner": "local"}  # the default ONNX embedding function
        assert sf.server_info(conn)["version"] == chromadb.__version__
    finally:
        conn.close()


# ================================================================== pgvector #

class _PgCursor:
    def __init__(self, conn):
        self.conn = conn
        self.rows: list = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        self.conn.statements.append(sql)
        self.conn.params.append(params)
        for needle, result in self.conn.answers.items():
            if needle in sql:
                if isinstance(result, Exception):
                    raise result
                self.rows = list(result)
                return
        self.rows = []

    def fetchall(self):
        return self.rows


class _PgConn:
    def __init__(self, answers, host="localhost"):
        self.answers = answers
        self.statements: list[str] = []
        self.params: list = []
        self.rolled_back = 0
        self.info = SimpleNamespace(host=host)

    def cursor(self):
        return _PgCursor(self)

    def rollback(self):
        self.rolled_back += 1


class _PgDenied(Exception):
    sqlstate = "42501"


def _pg(conn, endpoint="postgresql://app:***@db:5432/app"):
    c = PgVectorConnector.__new__(PgVectorConnector)
    c._conn = conn
    c._schema = "public"
    c._table_filter = None
    c._endpoint = endpoint
    return c


def test_pg_server_info_versions_and_aurora():
    conn = _PgConn({
        "SHOW server_version": [("16.4 (Debian 16.4-1)",)],
        "FROM pg_extension": [("vector", "0.8.0"), ("ai", "0.10.1")],
        "proname = 'aurora_version'": [(1,)],
        "SELECT aurora_version()": [("16.4.1",)],
    })
    info = sf.server_info(_pg(conn))
    _shape_server(info)
    assert info["product"] == "postgresql" and info["version"] == "16.4"
    assert info["features"] == {"pgvector": "0.8.0", "pgai": "0.10.1",
                                "extensions": {"ai": "0.10.1", "vector": "0.8.0"},
                                "aurora_version": "16.4.1"}
    assert info["edition"] == "aurora" and info["managed"] is True


def test_pg_server_info_reports_advisory_feature_keys():
    """The keys the advisory overlay decides applicability on."""
    conn = _PgConn({
        "SHOW server_version": [("16.4",)],
        "SELECT version()": [("PostgreSQL 16.4 on x86_64-pc-linux-gnu, compiled by gcc "
                              "12.2.0, 64-bit",)],
        "FROM pg_extension": [("pg_trgm", "1.6"), ("vector", "0.8.1")],
        "SHOW max_parallel_maintenance_workers": [("2",)],
        "SHOW shared_preload_libraries": [("pg_stat_statements, 'auto_explain'",)],
    })
    features = sf.server_info(_pg(conn))["features"]
    assert features["pgvector"] == "0.8.1"
    assert features["extensions"] == {"pg_trgm": "1.6", "vector": "0.8.1"}
    assert features["version_string"].endswith("64-bit")
    assert features["max_parallel_maintenance_workers"] == 2
    assert features["shared_preload_libraries"] == ["auto_explain", "pg_stat_statements"]


def test_pg_server_info_reports_installed_package_next_to_extversion():
    """The package (the C library backends load) and the catalog version both."""
    conn = _PgConn({
        "SHOW server_version": [("17.2",)],
        "FROM pg_extension": [("vector", "0.8.1")],
        "FROM pg_available_extensions": [("0.8.7",)],
    })
    features = sf.server_info(_pg(conn))["features"]
    assert features["pgvector"] == "0.8.1"
    assert features["pgvector_package"] == "0.8.7"
    assert "name = 'vector'" in next(s for s in conn.statements
                                     if "pg_available_extensions" in s)


def test_pg_server_info_snapshots_only_the_allowlisted_settings():
    from vecshield_platform.posture.pg_hardening import SETTINGS

    conn = _PgConn({
        "SHOW server_version": [("16.4",)],
        "FROM pg_extension": [("vector", "0.8.7"), ("pg_stat_statements", "1.10")],
        "name = ANY": [("ssl", "on"), ("password_encryption", "md5"),
                       ("log_statement", None)],
        "pg_read_all_stats": [("reporting",)],
    })
    features = sf.server_info(_pg(conn))["features"]
    # Rows, not a mapping: password_encryption is a hash algorithm, and a
    # credential-looking key would be scrubbed from a mapping.
    assert features["settings"] == [{"name": "ssl", "setting": "on"},
                                    {"name": "password_encryption", "setting": "md5"},
                                    {"name": "log_statement", "setting": ""}]
    assert features["pg_read_all_stats_members"] == ["reporting"]
    sql, params = next((s, p) for s, p in zip(conn.statements, conn.params)
                       if "name = ANY" in s)
    assert params == (list(SETTINGS),)
    readers = next(s for s in conn.statements if "pg_read_all_stats" in s)
    assert "current_user" in readers and "NOT r.rolsuper" in readers


def test_pg_stat_statements_readers_are_not_read_without_the_extension():
    conn = _PgConn({"SHOW server_version": [("16.4",)],
                    "FROM pg_extension": [("vector", "0.8.7")]})
    features = sf.server_info(_pg(conn))["features"]
    assert "pg_read_all_stats_members" not in features
    assert not any("pg_read_all_stats" in s for s in conn.statements)


def test_pg_refused_preload_setting_is_not_a_failure():
    conn = _PgConn({"SHOW server_version": [("17.0",)],
                    "FROM pg_extension": [("vector", "0.8.0")],
                    "SHOW shared_preload_libraries": _PgDenied("permission denied")})
    info = sf.server_info(_pg(conn))
    assert info["version"] == "17.0" and "shared_preload_libraries" not in info["features"]
    assert "pg_read_all_settings" in info["reason"]
    assert conn.rolled_back >= 1


def test_pg_server_info_self_managed_without_vector():
    conn = _PgConn({"SHOW server_version": [("17.0",)], "FROM pg_extension": []})
    info = sf.server_info(_pg(conn))
    assert info["edition"] is None and info["managed"] is False
    assert "not installed" in info["reason"]


def test_pg_distance_metrics_from_operator_classes():
    conn = _PgConn({
        "DISTINCT c.relname": [("docs",), ("notes",), ("mixed",)],
        "FROM pg_index i": [
            ("docs", "id", "int4_ops", "btree", "docs_pkey"),
            ("docs", "embedding", "vector_cosine_ops", "hnsw", "docs_emb_idx"),
            ("mixed", "e1", "vector_l2_ops", "hnsw", "m1"),
            ("mixed", "e2", "halfvec_ip_ops", "ivfflat", "m2"),
        ]})
    assert sf.distance_metrics(_pg(conn)) == {"docs": "cosine", "notes": None,
                                              "mixed": None}
    details = sf.distance_metric_details(_pg(conn))
    assert "no pgvector index" in details["notes"]["note"]


def test_pg_pgai_vectorizers_without_secrets():
    config = {"embedding": {"implementation": "openai", "model": "text-embedding-3-small",
                            "dimensions": 768, "api_key_name": "OPENAI_API_KEY_PROD"}}
    ollama = {"embedding": {"implementation": "ollama", "model": "nomic-embed-text",
                            "base_url": "http://ollama:11434"}}
    conn = _PgConn({
        "to_regclass('ai.vectorizer')": [(True,)],
        "FROM pg_extension": [("vector", "0.8.0")],
        "FROM ai.vectorizer": [(1, "public", "docs", json.dumps(config)),
                               (2, "public", "notes", ollama)],
    })
    res = sf.model_integrations(_pg(conn))
    _shape_integrations(res)
    _no_secrets(res, "OPENAI_API_KEY_PROD")
    by = {e["collection"]: e for e in res["integrations"]}
    assert (by["docs"]["provider"], by["docs"]["model"], by["docs"]["auth"]) == (
        "openai", "text-embedding-3-small", "api_key")
    assert by["notes"]["provider"] == "self_hosted" and by["notes"]["endpoint_host"] == "ollama"


def test_pg_pgai_denied_is_not_observable_and_rolled_back():
    conn = _PgConn({"to_regclass('ai.vectorizer')": [(True,)],
                    "FROM ai.vectorizer": _PgDenied("permission denied for table vectorizer")})
    res = sf.model_integrations(_pg(conn))
    assert res["observable"] is False and "ai.vectorizer" in res["reason"]
    assert conn.rolled_back >= 1


def test_pg_no_pgai_is_observable_empty():
    res = sf.model_integrations(_pg(_PgConn({"to_regclass('ai.vectorizer')": [(False,)]})))
    assert res["observable"] is True and res["integrations"] == []


@pytest.mark.parametrize("host,provider,region", [
    ("mydbcluster.cluster-c7tj4example.us-east-1.rds.amazonaws.com", "aws", "us-east-1"),
    ("ep-cool-darkness-a1b2c3d4-pooler.us-east-2.aws.neon.tech", "neon", "us-east-2"),
    ("aws-1-us-east-2.pooler.supabase.com", "supabase", "us-east-2"),
])
def test_pg_location_from_documented_hostnames(host, provider, region):
    loc = sf.store_location(_pg(_PgConn({}, host=host)))
    assert (loc["provider"], loc["region"], loc["observable"]) == (provider, region, True)


def test_pg_location_without_region_or_private():
    azure = sf.store_location(_pg(_PgConn({}, host="srv.postgres.database.azure.com")))
    assert azure["provider"] == "azure" and azure["region"] is None
    assert azure["observable"] is False
    local = sf.store_location(_pg(_PgConn({}, host="10.1.2.3")))
    assert local["provider"] == "self_hosted"
    rds_private = sf.store_location(_pg(_PgConn({"FROM pg_settings": [("rds.extensions",)]},
                                                host="10.1.2.3")))
    assert rds_private["provider"] == "aws" and rds_private["observable"] is False
    socket = sf.store_location(_pg(_PgConn({}, host="/var/run/postgresql")))
    assert socket["provider"] == "self_hosted"


def test_pg_location_falls_back_to_keyword_dsn_host():
    conn = _PgConn({})
    conn.info = None
    loc = sf.store_location(_pg(conn, "host=ep-x-1.eu-central-1.aws.neon.tech "
                                      "password=*** dbname=app"))
    assert loc["region"] == "eu-central-1"


# ===================================================================== redis #

class _FakeFT:
    def __init__(self, info):
        self._info = info

    def info(self):
        return self._info


class _FakeRedis:
    def __init__(self, info=None, modules=None, indexes=None, aliases=None,
                 host="localhost", info_exc=None):
        self._server = info or {"redis_version": "7.4.1", "redis_mode": "standalone"}
        self._modules = modules if modules is not None else [
            [b"name", b"search", b"ver", 21005, b"path", b"/opt/redis/redisearch.so"]]
        self._indexes = indexes or {}
        self._aliases = aliases
        self._info_exc = info_exc
        self.connection_pool = SimpleNamespace(connection_kwargs={"host": host,
                                                                  "password": "REDIS-PW"})

    def info(self, section=None):
        if self._info_exc:
            raise self._info_exc
        return dict(self._server)

    def execute_command(self, *args):
        if args == ("MODULE", "LIST"):
            return self._modules
        if args == ("FT._LIST",):
            return [i.encode() for i in self._indexes]
        if args[0] == "FT.ALIASLIST":
            if self._aliases is None:
                raise Exception("ERR unknown command 'FT.ALIASLIST'")
            return [a.encode() for a in self._aliases.get(args[1], [])]
        raise AssertionError(args)

    def ft(self, index):
        return _FakeFT(self._indexes[index])


def _redis(r):
    c = RedisConnector.__new__(RedisConnector)
    c._r = r
    c._endpoint = "redis://localhost:6379/0"
    return c


def _vec_attr(name, metric):
    return [b"identifier", name.encode(), b"attribute", name.encode(), b"type", b"VECTOR",
            b"algorithm", b"HNSW", b"data_type", b"FLOAT32", b"dim", 4,
            b"distance_metric", metric.encode()]


def test_redis_server_info_modules_and_valkey():
    info = sf.server_info(_redis(_FakeRedis()))
    assert info["product"] == "redis" and info["version"] == "7.4.1"
    assert info["features"]["modules"] == {"search": "21005"}
    _no_secrets(info, "/opt/redis", "REDIS-PW")
    valkey = sf.server_info(_redis(_FakeRedis(info={"server_name": "valkey",
                                                    "valkey_version": "8.1.0",
                                                    "redis_version": "7.2.4"})))
    assert valkey["product"] == "valkey" and valkey["version"] == "8.1.0"
    denied = sf.server_info(_redis(_FakeRedis(info_exc=Exception("NOPERM no permission"))))
    assert denied["version"] is None and "refused" in denied["reason"]


def test_redis_distance_metric_from_ft_info():
    conn = _redis(_FakeRedis(indexes={
        "cos": {"attributes": [_vec_attr("embedding", "COSINE"),
                               [b"identifier", b"content", b"type", b"TEXT"]]},
        "ip": {"attributes": [_vec_attr("e", "IP")]},
        "mixed": {"attributes": [_vec_attr("a", "L2"), _vec_attr("b", "COSINE")]},
        "text": {"attributes": [[b"identifier", b"t", b"type", b"TEXT"]]},
    }))
    assert sf.distance_metrics(conn) == {"cos": "cosine", "ip": "dot", "mixed": None,
                                         "text": None}


def test_redis_aliases_need_aliaslist():
    old = _redis(_FakeRedis(indexes={"idx": {}}))
    with pytest.raises(UnsupportedCapability):
        sf.list_aliases(old)
    new = _redis(_FakeRedis(indexes={"idx": {}}, aliases={"idx": ["live"]}))
    assert sf.list_aliases(new) == {"live": "idx"}
    with pytest.raises(UnsupportedCapability):
        sf.model_integrations(new)


def test_redis_location():
    assert sf.store_location(_redis(_FakeRedis()))["provider"] == "self_hosted"
    cloud = sf.store_location(_redis(_FakeRedis(
        host="redis-12345.c1.us-east-1-1.ec2.cloud.redislabs.com")))
    assert cloud["provider"] == "redis_cloud" and cloud["region"] is None
    assert cloud["observable"] is False
    _no_secrets(cloud, "REDIS-PW")


# ================================================================ opensearch #

_TRUSTED = "plugins.ml_commons.trusted_connector_endpoints_regex"


class _FakeOS:
    def __init__(self, routes=None, mappings=None, info=None, settings=None, aliases=None):
        self.routes = routes or {}
        self._mappings = mappings or {}
        self._info = info or {"version": {"number": "2.17.1", "distribution": "opensearch"},
                              "tagline": "The OpenSearch Project: https://opensearch.org/"}
        self._settings = settings or {}
        self._aliases = aliases or {}
        self.transport = SimpleNamespace(perform_request=self._perform)
        self.cat = SimpleNamespace(plugins=lambda format=None: [
            {"name": "node-1", "component": "opensearch-ml", "version": "2.17.1.0"},
            {"name": "node-1", "component": "opensearch-knn", "version": "2.17.1.0"}])
        self.indices = SimpleNamespace(get_mapping=lambda index=None: self._mappings,
                                       get_settings=lambda **kw: self._settings,
                                       get_alias=lambda: self._aliases)
        self.cluster = SimpleNamespace(get_settings=lambda **kw: {
            "persistent": {_TRUSTED: ["^https://api\\.openai\\.com/.*$"]},
            "defaults": {_TRUSTED: ["^https://.*$"]}})

    def info(self):
        if isinstance(self._info, Exception):
            raise self._info
        return self._info

    def _perform(self, method, path, body=None):
        result = self.routes.get((method, path), {})
        if isinstance(result, Exception):
            raise result
        return result


def _os(client, endpoint="http://localhost:9200"):
    c = OpenSearchConnector.__new__(OpenSearchConnector)
    c._c = client
    c._endpoint = endpoint
    c._layout = {}
    return c


_OS_CONNECTORS = {"hits": {"hits": [
    {"_id": "c-openai", "_source": {
        "name": "OpenAI embeddings", "protocol": "http",
        "parameters": {"model": "text-embedding-ada-002"},
        "credential": {"openAI_key": "sk-OS-LEAK"},
        "actions": [{"action_type": "predict", "method": "POST",
                     "url": "https://api.openai.com/v1/embeddings",
                     "headers": {"Authorization": "Bearer ${credential.openAI_key}"}}]}},
    {"_id": "c-bedrock", "_source": {
        "name": "Bedrock Claude", "protocol": "aws_sigv4",
        "parameters": {"region": "us-east-1", "service_name": "bedrock"},
        "credential": {"roleArn": "arn:aws:iam::123456789012:role/ml"},
        "actions": [{"action_type": "predict", "method": "POST",
                     "url": "https://bedrock-runtime.${parameters.region}.amazonaws.com/"
                            "model/anthropic.claude-v2/invoke"}]}},
    {"_id": "c-unused", "_source": {
        "name": "Cohere", "protocol": "http", "parameters": {"model": "embed-english-v3.0"},
        "credential": {"cohere_key": "co-LEAK"},
        "actions": [{"url": "https://api.cohere.ai/v1/embed"}]}},
]}}
_OS_MODELS = {"hits": {"hits": [
    {"_id": "m-embed", "_source": {"name": "ada", "algorithm": "REMOTE",
                                   "connector_id": "c-openai"}},
    {"_id": "m-rag", "_source": {"name": "claude", "algorithm": "REMOTE",
                                 "connector_id": "c-bedrock"}},
    {"_id": "m-local", "_source": {"name": "all-MiniLM-L6-v2",
                                   "algorithm": "TEXT_EMBEDDING"}},
]}}
_OS_ROUTES = {
    ("POST", "/_plugins/_ml/connectors/_search"): _OS_CONNECTORS,
    ("POST", "/_plugins/_ml/models/_search"): _OS_MODELS,
    ("GET", "/_ingest/pipeline"): {
        "embed": {"processors": [{"text_embedding": {"model_id": "m-embed",
                                                     "field_map": {"text": "emb"}}}]},
        "local": {"processors": [{"text_embedding": {"model_id": "m-local"}}]}},
    ("GET", "/_search/pipeline"): {
        "rag": {"response_processors": [{"retrieval_augmented_generation": {
            "model_id": "m-rag", "context_field_list": ["text"]}}]}},
}


def test_opensearch_model_integrations_resolve_pipelines_and_hide_credentials():
    conn = _os(_FakeOS(routes=_OS_ROUTES, settings={
        "docs": {"settings": {"index.default_pipeline": "embed",
                              "index.search.default_pipeline": "rag"}},
        ".plugins-ml-model": {"settings": {"index.default_pipeline": "embed"}}}))
    res = sf.model_integrations(conn)
    _shape_integrations(res)
    assert res["observable"] is True
    _no_secrets(res, "sk-OS-LEAK", "co-LEAK", "Bearer", "arn:aws:iam", "openAI_key")
    entries = res["integrations"]
    ingest = next(e for e in entries if e["evidence"].get("pipeline") == "embed")
    assert (ingest["collection"], ingest["stage"], ingest["provider"], ingest["model"],
            ingest["endpoint_host"], ingest["auth"]) == (
        "docs", "ingest", "openai", "text-embedding-ada-002", "api.openai.com", "api_key")
    rag = next(e for e in entries if e["evidence"].get("pipeline") == "rag")
    assert (rag["collection"], rag["stage"], rag["provider"], rag["endpoint_host"],
            rag["auth"]) == ("docs", "generate", "aws_bedrock",
                             "bedrock-runtime.us-east-1.amazonaws.com", "managed_identity")
    local = next(e for e in entries if e["evidence"].get("pipeline") == "local")
    assert local["provider"] == "local" and local["collection"] is None
    unused = next(e for e in entries if e["evidence"].get("connector_id") == "c-unused")
    assert unused["provider"] == "cohere" and unused["collection"] is None
    assert res["controls"]["trusted_endpoints"] == ["^https://api\\.openai\\.com/.*$"]
    assert res["controls"]["trusted_endpoints_source"] == "persistent"


def test_opensearch_connector_search_denied_is_not_observable():
    routes = dict(_OS_ROUTES)
    routes[("POST", "/_plugins/_ml/connectors/_search")] = _HTTPError(403, "security_exception")
    res = sf.model_integrations(_os(_FakeOS(routes=routes)))
    assert res["observable"] is False
    assert "cluster:admin/opensearch/ml/connectors/search" in res["reason"]


def test_opensearch_without_ml_commons_is_observable_empty():
    missing = _HTTPError(400, "no handler found for uri [/_plugins/_ml/connectors/_search]")
    routes = {("POST", "/_plugins/_ml/connectors/_search"): missing,
              ("GET", "/_ingest/pipeline"): {}, ("GET", "/_search/pipeline"): {}}
    res = sf.model_integrations(_os(_FakeOS(routes=routes)))
    assert res["observable"] is True and res["controls"]["ml_commons"] == "not_installed"


def test_opensearch_server_info_and_metrics():
    conn = _os(_FakeOS(mappings={
        "method": {"mappings": {"properties": {"emb": {
            "type": "knn_vector", "dimension": 4,
            "method": {"name": "hnsw", "engine": "faiss", "space_type": "cosinesimil"}}}}},
        "top": {"mappings": {"properties": {"nested": {"properties": {"v": {
            "type": "knn_vector", "dimension": 4, "space_type": "innerproduct"}}}}}},
        "l1": {"mappings": {"properties": {"v": {"type": "knn_vector", "space_type": "l1"}}}},
        "linf": {"mappings": {"properties": {"v": {"type": "knn_vector",
                                                   "space_type": "linf"}}}},
        "unset": {"mappings": {"properties": {"v": {"type": "knn_vector", "dimension": 4}}}},
        "text": {"mappings": {"properties": {"t": {"type": "text"}}}},
        ".kibana_1": {"mappings": {"properties": {"v": {"type": "knn_vector"}}}},
    }))
    info = sf.server_info(conn)
    assert (info["product"], info["version"]) == ("opensearch", "2.17.1")
    assert info["features"]["plugins"]["opensearch-ml"] == "2.17.1.0"
    assert sf.distance_metrics(conn) == {"method": "cosine", "top": "dot", "l1": "manhattan",
                                         "linf": None, "unset": None}
    assert "not set" in sf.distance_metric_details(conn)["unset"]["note"]
    denied = sf.server_info(_os(_FakeOS(info=_HTTPError(403))))
    assert denied["version"] is None and "cluster:monitor/main" in denied["reason"]


def test_opensearch_aliases_skip_system_indices():
    conn = _os(_FakeOS(aliases={
        "docs_v2": {"aliases": {"docs": {}, "all": {}}},
        "notes": {"aliases": {"all": {}}},
        ".kibana_1": {"aliases": {".kibana": {}}}}))
    assert sf.list_aliases(conn) == {"all": "docs_v2,notes", "docs": "docs_v2"}


@pytest.mark.parametrize("endpoint,region,service", [
    ("https://search-mydomain-1a2a3a4a5a6a7a8a9a0a9a8a7a.us-east-1.es.amazonaws.com",
     "us-east-1", "opensearch_service"),
    ("https://vpc-logs-abc123.eu-west-1.es.amazonaws.com:443", "eu-west-1",
     "opensearch_service"),
    ("https://07tjusf2h91cunochc.us-east-1.aoss.amazonaws.com", "us-east-1",
     "opensearch_serverless"),
    ("https://1tg2xudton46knx2a95g.aoss.us-east-1.on.aws", "us-east-1",
     "opensearch_serverless"),
])
def test_opensearch_aws_locations(endpoint, region, service):
    loc = sf.store_location(_os(_FakeOS(), endpoint))
    assert (loc["provider"], loc["region"], loc["evidence"]["service"]) == (
        "aws", region, service)
    assert sf.server_info(_os(_FakeOS(), endpoint))["managed"] is True


def test_opensearch_self_hosted_location_strips_userinfo():
    loc = sf.store_location(_os(_FakeOS(), "https://admin:OS-PW@opensearch:9200"))
    assert loc["provider"] == "self_hosted"
    _no_secrets(loc, "OS-PW", "admin")


# =================================================================== mongodb #

class _OpFailure(Exception):
    def __init__(self, msg, code):
        super().__init__(msg)
        self.code = code
        self.details = {"errmsg": msg}


class _FakeColl:
    def __init__(self, indexes, exc=None):
        self._indexes = indexes
        self._exc = exc

    def list_search_indexes(self):
        if self._exc:
            raise self._exc
        return list(self._indexes)


class _FakeDB:
    def __init__(self, colls):
        self._colls = colls

    def list_collection_names(self):
        return list(self._colls)

    def __getitem__(self, name):
        return self._colls[name]


class _FakeAdmin:
    def __init__(self, answers):
        self.answers = answers

    def command(self, name):
        result = self.answers.get(name)
        if isinstance(result, Exception):
            raise result
        if result is None:
            raise _OpFailure(f"no such command: {name}", 59)
        return result


class _FakeMongo:
    def __init__(self, dbs=None, admin=None):
        self._dbs = dbs or {}
        self.admin = _FakeAdmin(admin or {})

    def list_database_names(self):
        return ["admin", *self._dbs]

    def __getitem__(self, name):
        return self._dbs[name]


def _mongo(client, endpoint="localhost:27017"):
    c = MongoDBConnector.__new__(MongoDBConnector)
    c._c = client
    c._endpoint = endpoint
    c._layout = {}
    return c


def _vs_index(name, fields):
    return {"name": name, "type": "vectorSearch", "latestDefinition": {"fields": fields}}


def test_mongo_server_info_editions():
    ent = sf.server_info(_mongo(_FakeMongo(admin={"buildInfo": {
        "version": "7.0.12", "modules": ["enterprise"]}})))
    assert (ent["product"], ent["version"], ent["edition"], ent["managed"]) == (
        "mongodb", "7.0.12", "enterprise", False)
    atlas = sf.server_info(_mongo(_FakeMongo(admin={"buildInfo": {"version": "8.0.4",
                                                                  "modules": []}}),
                                  "cluster0-shard-00-00.abcde.mongodb.net:27017"))
    assert atlas["edition"] == "atlas" and atlas["managed"] is True
    percona = sf.server_info(_mongo(_FakeMongo(admin={"buildInfo": {
        "version": "7.0.8", "psmdbVersion": "7.0.8-5", "modules": []}})))
    assert percona["edition"] == "percona"


def test_mongo_distance_metrics_and_auto_embed():
    dbs = {"app": _FakeDB({
        "docs": _FakeColl([_vs_index("vi", [{"type": "vector", "path": "emb",
                                               "numDimensions": 4, "similarity": "dotProduct"},
                                              {"type": "filter", "path": "tenant"}])]),
        "euclid": _FakeColl([_vs_index("vi", [{"type": "vector", "path": "e",
                                                 "similarity": "euclidean"}])]),
        "auto": _FakeColl([_vs_index("ae", [{"type": "autoEmbed", "modality": "text",
                                               "path": "body", "model": "voyage-4"}])]),
        "plain": _FakeColl([]),
        "system.views": _FakeColl([_vs_index("x", [{"type": "vector",
                                                      "similarity": "cosine"}])]),
    })}
    conn = _mongo(_FakeMongo(dbs=dbs))
    assert sf.distance_metrics(conn) == {"app.docs": "dot", "app.euclid": "euclidean"}
    res = sf.model_integrations(conn)
    _shape_integrations(res)
    assert res["observable"] is True
    [entry] = res["integrations"]
    assert (entry["collection"], entry["provider"], entry["model"], entry["auth"]) == (
        "app.auto", "voyageai", "voyage-4", "api_key")


def test_mongo_search_index_denied_or_unavailable():
    denied = _mongo(_FakeMongo(dbs={"app": _FakeDB({"docs": _FakeColl(
        [], _OpFailure("not authorized on app to execute command", 13))})}))
    res = sf.model_integrations(denied)
    assert res["observable"] is False and "listSearchIndexes" in res["reason"]
    community = _mongo(_FakeMongo(dbs={"app": _FakeDB({"docs": _FakeColl(
        [], _OpFailure("$listSearchIndexes stage is only allowed on MongoDB Atlas", 6047401))})}))
    res = sf.model_integrations(community)
    assert res["observable"] is True and res["integrations"] == []


def test_mongo_atlas_location_from_replica_set_tags():
    admin = {
        "hello": {"isWritablePrimary": True, "tags": {
            "provider": "AWS", "region": "US_EAST_1", "nodeType": "ELECTABLE"}},
        "replSetGetConfig": {"config": {"members": [
            {"host": "a:27017", "tags": {"region": "US_EAST_1"}},
            {"host": "b:27017", "tags": {"region": "EU_WEST_1"}},
            {"host": "c:27017", "tags": {"region": "US_EAST_1"}}]}},
    }
    loc = sf.store_location(_mongo(_FakeMongo(admin=admin),
                                   "cluster0-shard-00-00.abcde.mongodb.net:27017"))
    _shape_location(loc)
    assert (loc["provider"], loc["region"], loc["observable"]) == (
        "mongodb_atlas", "US_EAST_1", True)
    assert loc["replica_regions"] == ["EU_WEST_1"] and loc["evidence"]["cloud"] == "AWS"


def test_mongo_atlas_location_partial_and_missing_tags():
    admin = {"hello": {"tags": {"provider": "GCP", "region": "CENTRAL_US"}},
             "replSetGetConfig": _OpFailure("not authorized", 13)}
    loc = sf.store_location(_mongo(_FakeMongo(admin=admin), "c0.xyz.mongodb.net"))
    assert loc["region"] == "CENTRAL_US" and loc["observable"] is True
    assert "clusterMonitor" in loc["evidence"]["replica_regions"]
    untagged = sf.store_location(_mongo(_FakeMongo(admin={"hello": {}}),
                                        "c0.xyz.mongodb.net"))
    assert untagged["provider"] == "mongodb_atlas" and untagged["observable"] is False


def test_mongo_non_atlas_location_is_not_placed():
    assert sf.store_location(_mongo(_FakeMongo()))["provider"] == "self_hosted"
    public = sf.store_location(_mongo(_FakeMongo(), "mongo.example.com:27017"))
    assert public["provider"] is None and public["observable"] is False
    with pytest.raises(UnsupportedCapability):
        sf.list_aliases(_mongo(_FakeMongo()))
