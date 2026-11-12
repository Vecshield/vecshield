"""Credentials carried inside connection strings, and the config store around them.

Regression tests for:

* passwords inside ``uri``/``url``/keyword DSNs returned to viewers, accepted
  by strict mode, and written into store display names (and so into every
  finding's ``store`` field);
* a masked secret carried over to a different endpoint on edit or pre-save
  test;
* a refused alerting update that still changed the in-memory config;
* a webhook mask that kept the URL's userinfo;
* one unresolvable secret reference making every store unavailable.
"""
from __future__ import annotations

import sys
import types

import pytest
from fastapi.testclient import TestClient

from vecshield_platform.api import create_app
from vecshield_platform.api.config_store import ConfigStore, mask_webhook_url
from vecshield_platform.api.secrets import SecretResolutionError
from vecshield_platform.connectors.redact import (
    embedded_credentials,
    redact_credentials,
)

ADMIN = {"Authorization": "Bearer admin-tok"}
VIEWER = {"Authorization": "Bearer read-tok"}

MONGO_URI = "mongodb+srv://svc:Sup3rS3cretPw@cluster0.abcde.mongodb.net/?retryWrites=true"
REDIS_URL = "redis://:RedisPw123@cache.internal:6379/0"
MILVUS_URI = "http://root:MilvusPw9@milvus.internal:19530"


# --------------------------------------------------------------------------- #
# The shared redaction helper                                                 #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("raw,expected", [
    (MONGO_URI, "mongodb+srv://svc:***@cluster0.abcde.mongodb.net/?retryWrites=true"),
    (REDIS_URL, "redis://:***@cache.internal:6379/0"),
    ("postgresql://svc:p@ssW0rd@db.internal:5432/rag",
     "postgresql://svc:***@db.internal:5432/rag"),
    ("postgresql://svc:pa/ss?x@db:5432/rag", "postgresql://svc:***@db:5432/rag"),
    ("https://svc:QdPw55@qdrant.internal:6333", "https://svc:***@qdrant.internal:6333"),
    ("http://db:5432/rag?sslmode=require&password=QpPw&user=svc",
     "http://db:5432/rag?sslmode=require&password=***&user=svc"),
    ("mongodb://h1:27017,h2:27017/?authMechanism=MONGODB-AWS"
     "&authMechanismProperties=AWS_SESSION_TOKEN:tok123",
     "mongodb://h1:27017,h2:27017/?authMechanism=MONGODB-AWS"
     "&authMechanismProperties=***"),
    ("host=db.internal dbname=rag user=svc password=PgPw777",
     "host=db.internal dbname=rag user=svc password=***"),
    ("host=db password = 'a b\\'c' dbname=rag", "host=db password = *** dbname=rag"),
])
def test_redact_credentials(raw, expected):
    assert redact_credentials(raw) == expected
    assert redact_credentials(expected) == expected  # idempotent


@pytest.mark.parametrize("plain", [
    "http://localhost:6333", "https://x.search.windows.net", "redis://cache:6379/0",
    "mongodb://svc@db:27017/app", "postgresql://db:5432/app", "file:///tmp/chroma",
    "./milvus.db", "http://host:8080/v1?timeout=5", "",
])
def test_redaction_leaves_credential_free_strings_unchanged(plain):
    # Finding fingerprints are keyed on the store name, so a string without a
    # credential must come back byte for byte.
    assert redact_credentials(plain) == plain
    assert embedded_credentials(plain) == []


def test_embedded_credentials_lists_the_secret_values():
    assert embedded_credentials(MONGO_URI) == ["Sup3rS3cretPw"]
    assert embedded_credentials("host=db password=PgPw777") == ["PgPw777"]
    assert embedded_credentials("redis://:***@cache:6379") == ["***"]


# --------------------------------------------------------------------------- #
# Item 1: credentials in uri/url returned to viewers, and strict mode         #
# --------------------------------------------------------------------------- #

@pytest.fixture
def client(tmp_path):
    cfg = ConfigStore(str(tmp_path / "vecshield.json"))
    app = create_app(config_store=cfg, serve_ui=False,
                     auth_token="read-tok", admin_token="admin-tok")
    return TestClient(app), cfg


def test_viewer_never_receives_credentials_in_uri_or_url(client):
    c, _ = client
    for sid, kind, conn in [("m", "mongodb", {"uri": MONGO_URI}),
                            ("r", "redis", {"url": REDIS_URL}),
                            ("v", "milvus", {"uri": MILVUS_URI}),
                            ("p", "pgvector", {"host": "db", "conninfo":
                                               "host=db password=PgPw777"})]:
        r = c.post("/admin/stores", json={"store_id": sid, "kind": kind, "conn": conn},
                   headers=ADMIN)
        assert r.status_code == 200, r.text
        assert "Sup3rS3cretPw" not in r.text and "PgPw777" not in r.text
    listed = c.get("/admin/stores", headers=VIEWER)
    assert listed.status_code == 200
    for secret in ("Sup3rS3cretPw", "RedisPw123", "MilvusPw9", "PgPw777"):
        assert secret not in listed.text
    one = c.get("/admin/stores/m", headers=VIEWER).json()
    # Viewers may read the config: host, user and options stay visible.
    assert one["conn"]["uri"] == \
        "mongodb+srv://svc:***@cluster0.abcde.mongodb.net/?retryWrites=true"


def test_masked_uri_round_trips_without_clobbering_the_secret(tmp_path):
    cfg = ConfigStore(str(tmp_path / "c.json"))
    cfg.add_store("m", "mongodb", conn={"uri": MONGO_URI})
    shown = cfg.get_store("m").public_dict()["conn"]
    s = cfg.update_store("m", kind="mongodb", conn=dict(shown), description="renamed")
    assert s.conn["uri"] == MONGO_URI
    assert s.description == "renamed"
    assert cfg.resolve_masked_conn("m", dict(shown))["uri"] == MONGO_URI


def test_strict_mode_rejects_a_password_inside_a_uri(tmp_path, monkeypatch):
    monkeypatch.setenv("VECSHIELD_REJECT_PLAINTEXT_SECRETS", "1")
    cfg = ConfigStore(str(tmp_path / "strict.json"))
    for conn in ({"uri": MONGO_URI}, {"url": REDIS_URL},
                 {"url": "http://db:9200/?api_key=abc"},
                 {"conninfo": "host=db password=PgPw777"}):
        with pytest.raises(ValueError, match="plaintext secret"):
            cfg.add_store("m", "mongodb", conn=conn)
    assert not (tmp_path / "strict.json").exists() or \
        "Sup3rS3cretPw" not in (tmp_path / "strict.json").read_text()
    # A URI with only a user name, or none, is fine.
    cfg.add_store("ok", "mongodb", conn={"uri": "mongodb://svc@db:27017/app",
                                         "password_env": "VECSHIELD_STORE_MONGO_PW"})


# --------------------------------------------------------------------------- #
# Item 4: store display names carry credentials                               #
# --------------------------------------------------------------------------- #

def _stub(monkeypatch, name, **attrs):
    mod = types.ModuleType(name)
    for k, v in attrs.items():
        setattr(mod, k, v)
    monkeypatch.setitem(sys.modules, name, mod)
    return mod


def test_redis_name_has_no_password(monkeypatch):
    class _R:
        def execute_command(self, *a):
            return []
    _stub(monkeypatch, "redis", from_url=lambda url, **k: _R(), Redis=lambda **k: _R())
    from vecshield_platform.connectors.redis import RedisConnector
    store = RedisConnector(url=REDIS_URL).describe()
    assert store.name == "redis://:***@cache.internal:6379/0"
    assert "RedisPw123" not in store.endpoint


def test_pgvector_keyword_and_at_sign_dsns_are_redacted(monkeypatch):
    _stub(monkeypatch, "psycopg", connect=lambda *a, **k: object())
    from vecshield_platform.connectors.pgvector import PgVectorConnector, _redact_dsn
    c = PgVectorConnector("host=db.internal dbname=rag user=svc password=PgPw777")
    assert "PgPw777" not in c._endpoint
    assert _redact_dsn("postgresql://svc:p@ssW0rd@db.internal:5432/rag") == \
        "postgresql://svc:***@db.internal:5432/rag"
    # Unchanged for the common credential-bearing URL form (fingerprints).
    assert _redact_dsn("postgresql://svc:pw@db:5432/rag") == "postgresql://svc:***@db:5432/rag"


def test_qdrant_endpoint_has_no_password():
    pytest.importorskip("qdrant_client")
    from vecshield_platform.connectors.qdrant import QdrantConnector
    c = QdrantConnector(url="https://svc:QdPw55@qdrant.internal:6333")
    assert c._endpoint == "https://svc:***@qdrant.internal:6333"


def test_milvus_and_opensearch_names_have_no_password(monkeypatch):
    class _Milvus:
        def __init__(self, **kw):
            pass

        def list_collections(self):
            return []
    _stub(monkeypatch, "pymilvus", MilvusClient=_Milvus)
    from vecshield_platform.connectors.milvus import MilvusConnector
    assert "MilvusPw9" not in MilvusConnector(uri=MILVUS_URI).describe().name

    class _Indices:
        def get(self, index=None):
            return {}

    class _OS:
        def __init__(self, **kw):
            self.indices = _Indices()
    _stub(monkeypatch, "opensearchpy", OpenSearch=_OS)
    from vecshield_platform.connectors.opensearch import OpenSearchConnector
    os_store = OpenSearchConnector(url="https://admin:OsPw1@search:9200").describe()
    assert os_store.name == "https://admin:***@search:9200"


def test_mongo_endpoint_is_the_host_list_with_or_without_credentials(monkeypatch):
    pytest.importorskip("pymongo")
    class _Mongo:
        def __init__(self, uri=None):
            pass
    import pymongo
    monkeypatch.setattr(pymongo, "MongoClient", _Mongo)
    from vecshield_platform.connectors.mongodb import MongoDBConnector
    assert MongoDBConnector(uri=MONGO_URI)._endpoint == "cluster0.abcde.mongodb.net"
    # A URI without userinfo used to become the endpoint "mongodb+srv:", which
    # also hid that the host is Atlas from the at-rest check.
    iam = MongoDBConnector(uri="mongodb+srv://cluster0.abcde.mongodb.net/"
                               "?authMechanism=MONGODB-AWS")
    assert iam._endpoint == "cluster0.abcde.mongodb.net"
    assert MongoDBConnector(uri="mongodb://svc:p@ss@h1:1,h2:2/db")._endpoint == "h1:1,h2:2"


# --------------------------------------------------------------------------- #
# Item 5: a masked secret must not follow a changed endpoint                  #
# --------------------------------------------------------------------------- #

def test_masked_secret_is_not_carried_to_a_new_endpoint(tmp_path):
    cfg = ConfigStore(str(tmp_path / "c.json"))
    cfg.add_store("q", "qdrant", conn={"url": "https://qdrant.prod.internal:6333",
                                       "api_key": "PROD-KEY"})
    moved = {"url": "http://127.0.0.1:9", "api_key": "***"}
    with pytest.raises(ValueError, match="re-enter"):
        cfg.resolve_masked_conn("q", moved)
    with pytest.raises(ValueError, match="re-enter"):
        cfg.update_store("q", kind="qdrant", conn=moved)
    assert cfg.get_store("q").conn["url"] == "https://qdrant.prod.internal:6333"
    # Switching url for host is a change of endpoint too.
    with pytest.raises(ValueError, match="re-enter"):
        cfg.resolve_masked_conn("q", {"host": "evil", "api_key": "***"})
    # Same endpoint: the mask still stands for the stored key.
    same = cfg.resolve_masked_conn("q", {"url": "https://qdrant.prod.internal:6333",
                                         "api_key": "***"})
    assert same["api_key"] == "PROD-KEY"
    # A re-entered key is accepted for the new endpoint.
    assert cfg.resolve_masked_conn("q", {"url": "http://127.0.0.1:9",
                                         "api_key": "NEW"})["api_key"] == "NEW"


def test_masked_password_inside_a_uri_is_not_carried_to_a_new_host(tmp_path):
    cfg = ConfigStore(str(tmp_path / "c.json"))
    cfg.add_store("m", "mongodb", conn={"uri": MONGO_URI})
    moved = {"uri": "mongodb+srv://svc:***@attacker.example/?retryWrites=true"}
    with pytest.raises(ValueError, match="re-enter"):
        cfg.update_store("m", kind="mongodb", conn=moved)
    with pytest.raises(ValueError, match="re-enter"):
        cfg.resolve_masked_conn("m", moved)
    assert cfg.get_store("m").conn["uri"] == MONGO_URI


def test_masked_secret_is_not_carried_to_another_connector_kind(tmp_path):
    cfg = ConfigStore(str(tmp_path / "c.json"))
    cfg.add_store("q", "qdrant", conn={"host": "h", "api_key": "PROD-KEY"})
    with pytest.raises(ValueError, match="re-enter"):
        cfg.update_store("q", kind="weaviate", conn={"host": "h", "api_key": "***"})
    with pytest.raises(ValueError, match="re-enter"):
        cfg.resolve_masked_conn("q", {"host": "h", "api_key": "***"}, kind="weaviate")


def test_masked_secret_test_connection_to_new_host_is_refused(client):
    c, _ = client
    r = c.post("/admin/stores", json={"store_id": "q", "kind": "qdrant",
               "conn": {"url": "https://qdrant.prod.internal:6333",
                        "api_key": "PROD-QDRANT-KEY-123"}}, headers=ADMIN)
    assert r.status_code == 200, r.text
    r = c.post("/admin/stores/test-connection", headers=ADMIN, json={
        "kind": "qdrant", "store_id": "q",
        "conn": {"url": "http://127.0.0.1:9", "api_key": "***"}})
    assert r.status_code == 422
    assert "re-enter" in r.json()["detail"]


def test_file_and_env_references_are_allowed_on_any_key_within_the_allowlist(
        tmp_path, monkeypatch):
    # Any key may be a *_file / *_env reference, but only to an allowlisted
    # variable name or file root (ADR 0003; the old "not restricted" decision
    # let an admin read the server's own secrets).
    secret = tmp_path / "k"
    secret.write_text("FILE-KEY\n")
    monkeypatch.setenv("VECSHIELD_SECRET_FILE_ROOTS", str(tmp_path))
    monkeypatch.setenv("VECSHIELD_STORE_QD_URL", "http://127.0.0.1:9")
    cfg = ConfigStore(str(tmp_path / "c.json"))
    cfg.add_store("q", "qdrant", conn={"url_env": "VECSHIELD_STORE_QD_URL",
                                       "api_key_file": str(secret)})
    reg = cfg.build_registry()
    assert reg.get("q").unavailable is None


# --------------------------------------------------------------------------- #
# Item 9 / 10: alerting                                                       #
# --------------------------------------------------------------------------- #

def test_refused_alerting_update_changes_nothing(tmp_path):
    cfg = ConfigStore(str(tmp_path / "vecshield.json"))
    cfg.set_alerting(webhooks=[{"url": "https://hooks.slack.com/services/T/B/X"}])
    before = cfg.alerting.to_dict()
    with pytest.raises(ValueError):
        cfg.set_alerting(enabled=True, min_severity="low",
                         webhooks=[{"url": "https://other.example/…"}])
    assert cfg.alerting.to_dict() == before
    assert ConfigStore(str(tmp_path / "vecshield.json")).alerting.to_dict() == before
    with pytest.raises(ValueError):
        cfg.set_alerting(enabled=True, min_severity="not-a-severity")
    assert cfg.alerting.to_dict() == before


def test_webhook_mask_drops_userinfo():
    url = "https://svc:HookPw@alerts.example.com:8443/hook/abc"
    masked = mask_webhook_url(url)
    assert masked == "https://alerts.example.com:8443/…"
    assert "HookPw" not in masked and "svc" not in masked
    # ... and the masked form still round-trips to the stored URL.
    cfg = ConfigStore()
    cfg.set_alerting(webhooks=[{"url": url}])
    cfg.set_alerting(webhooks=[{"url": masked}], enabled=True)
    assert cfg.alerting.webhooks[0]["url"] == url


# --------------------------------------------------------------------------- #
# Item 11: one unresolvable secret reference                                  #
# --------------------------------------------------------------------------- #

def _two_stores(tmp_path):
    chromadb = pytest.importorskip("chromadb")
    chromadb.PersistentClient(path=str(tmp_path / "db"))  # the "good" store exists
    path = str(tmp_path / "c.json")
    cfg = ConfigStore(path)
    cfg.add_store("good", "chroma", conn={"path": str(tmp_path / "db")})
    cfg.add_store("bad", "pinecone", conn={"api_key_env": "VECSHIELD_STORE_TEST_UNSET_KEY"})
    return path


def test_one_unresolvable_reference_does_not_block_the_other_stores(tmp_path, monkeypatch):
    monkeypatch.delenv("VECSHIELD_STORE_TEST_UNSET_KEY", raising=False)
    path = _two_stores(tmp_path)
    reg = ConfigStore(path).build_registry()  # e.g. at server start
    assert {s.store_id for s in reg.list()} == {"good", "bad"}
    assert reg.get("good").unavailable is None
    assert "VECSHIELD_STORE_TEST_UNSET_KEY" in reg.get("bad").unavailable
    assert reg.get("bad").public_dict()["unavailable"] == reg.get("bad").unavailable
    with pytest.raises(SecretResolutionError, match="VECSHIELD_STORE_TEST_UNSET_KEY"):
        reg.open("bad")
    reg.open("good").close()


def test_server_starts_and_serves_other_stores_with_one_bad_reference(tmp_path, monkeypatch):
    monkeypatch.delenv("VECSHIELD_STORE_TEST_UNSET_KEY", raising=False)
    cfg = ConfigStore(_two_stores(tmp_path))
    c = TestClient(create_app(config_store=cfg, serve_ui=False,
                              auth_token="read-tok", admin_token="admin-tok"))
    assert c.get("/stores", headers=VIEWER).status_code == 200
    # Adding another store is not blocked by the broken one...
    r = c.post("/admin/stores", json={"store_id": "more", "kind": "chroma",
                                      "conn": {"path": str(tmp_path / "db2")}},
               headers=ADMIN)
    assert r.status_code == 200, r.text
    # ...and a new store whose own reference is unresolvable is still refused.
    r = c.post("/admin/stores", json={"store_id": "pc", "kind": "pinecone",
                                      "conn": {"api_key_env": "VECSHIELD_STORE_TEST_UNSET_KEY"}},
               headers=ADMIN)
    assert r.status_code == 400
    assert "environment variable not set" in r.json()["detail"]
    assert "pc" not in cfg.stores


def test_masked_weaviate_key_is_not_carried_to_a_new_grpc_host(tmp_path):
    # Weaviate sends the API key in gRPC metadata to grpc_host, which can be a
    # different machine from the HTTP host.
    cfg = ConfigStore(str(tmp_path / "c.json"))
    cfg.add_store("w", "weaviate", conn={"host": "weaviate.internal",
                                         "grpc_host": "grpc.weaviate.internal",
                                         "api_key": "PROD-KEY"})
    with pytest.raises(ValueError, match="re-enter"):
        cfg.resolve_masked_conn("w", {"host": "weaviate.internal",
                                      "grpc_host": "attacker.example",
                                      "api_key": "***"})
    # Turning TLS off is a change of endpoint as well.
    cfg.add_store("c", "chroma", conn={"host": "chroma.internal", "ssl": True,
                                       "api_key": "PROD-KEY"})
    with pytest.raises(ValueError, match="re-enter"):
        cfg.resolve_masked_conn("c", {"host": "chroma.internal", "ssl": False,
                                      "api_key": "***"})


# --------------------------------------------------------------------------- #
# Chroma's auth header is a credential                                        #
# --------------------------------------------------------------------------- #

CHROMA_HEADERS = {"Authorization": "Bearer ChromaTok42"}


def test_viewer_never_receives_chroma_auth_headers(client):
    c, _ = client
    r = c.post("/admin/stores", headers=ADMIN, json={
        "store_id": "ch", "kind": "chroma",
        "conn": {"host": "chroma.internal", "port": 8000, "headers": CHROMA_HEADERS}})
    assert r.status_code == 200, r.text
    assert "ChromaTok42" not in r.text
    for url in ("/admin/stores", "/admin/stores/ch"):
        shown = c.get(url, headers=VIEWER)
        assert shown.status_code == 200
        assert "ChromaTok42" not in shown.text
    assert c.get("/admin/stores/ch", headers=VIEWER).json()["conn"]["headers"] == "***"


def test_masked_chroma_headers_round_trip_but_not_to_a_new_host(tmp_path):
    cfg = ConfigStore(str(tmp_path / "c.json"))
    cfg.add_store("ch", "chroma", conn={"host": "chroma.internal",
                                        "headers": CHROMA_HEADERS})
    shown = cfg.get_store("ch").public_dict()["conn"]
    assert shown["headers"] == "***"
    kept = cfg.update_store("ch", kind="chroma", conn=dict(shown))
    assert kept.conn["headers"] == CHROMA_HEADERS
    with pytest.raises(ValueError, match="re-enter"):
        cfg.resolve_masked_conn("ch", {"host": "attacker.example", "headers": "***"})


def test_strict_mode_rejects_plaintext_chroma_headers(tmp_path, monkeypatch):
    monkeypatch.setenv("VECSHIELD_REJECT_PLAINTEXT_SECRETS", "1")
    cfg = ConfigStore(str(tmp_path / "strict.json"))
    with pytest.raises(ValueError, match="plaintext secret"):
        cfg.add_store("ch", "chroma", conn={"host": "h", "headers": CHROMA_HEADERS})
