"""Encryption at rest and field-level encryption: connectors, rollup, criteria.

The rule under test throughout: a store that cannot expose a property is
``not_observable`` → ``unsupported``. It never fails and never raises a finding.
"""

from __future__ import annotations

import types
from dataclasses import replace

import pytest

from vecshield.models import Collection, Severity, VectorStore
from vecshield_platform.compliance.criteria import evaluate_criterion
from vecshield_platform.compliance.packs import get_criterion
from vecshield_platform.compliance.policy import evaluate_policies
from vecshield_platform.connectors.base import AtRestObservation, mask_reference
from vecshield_platform.connectors.mongodb import MongoDBConnector
from vecshield_platform.connectors.pgvector import PgVectorConnector
from vecshield_platform.posture import posture_policies, run_posture_audit
from vecshield_platform.posture.at_rest import at_rest_check, observe_at_rest

EPHI = {"covered_entity_or_business_associate": "yes", "system_handles_ephi": "yes"}


# ---- AtRestObservation ------------------------------------------------------

def test_observation_rejects_unknown_states_and_scopes():
    with pytest.raises(ValueError):
        AtRestObservation(state="probably")
    with pytest.raises(ValueError):
        AtRestObservation(state="enabled", scope="disk")
    record = AtRestObservation(state="enabled", key_reference="k").to_dict()
    assert record["state"] == "enabled" and "observed_at" in record


def test_key_references_are_masked():
    arn = "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"
    masked = mask_reference(arn)
    assert "123456789012" not in masked and masked.endswith("90ab")
    assert mask_reference(None) is None and mask_reference("") is None
    assert mask_reference("short") == "s****"


# ---- pgvector ---------------------------------------------------------------

class _Cursor:
    def __init__(self, conn):
        self._conn = conn

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        self._conn.calls.append((sql, list(params or [])))
        for substr, exc in self._conn.errors:
            if substr in sql:
                raise exc
        self._conn.last = sql
        self._conn.last_params = list(params or [])

    def fetchall(self):
        for substr, rows in self._conn.rows:
            if substr in self._conn.last:
                return rows(self._conn.last_params) if callable(rows) else rows
        return []


class _Conn:
    def __init__(self, rows=(), errors=()):
        self.rows = list(rows)
        self.errors = list(errors)
        self.calls: list = []
        self.last = ""
        self.last_params: list = []
        self.rolled_back = 0

    def cursor(self):
        return _Cursor(self)

    def rollback(self):
        self.rolled_back += 1


def _pg(conn):
    c = PgVectorConnector.__new__(PgVectorConnector)
    c._conn = conn
    c._schema = "public"
    c._endpoint = "postgresql://db:5432/app"
    return c


_EDB_COLUMNS = ("FROM pg_proc", [(["pg_control_version", "data_encryption_version"],)])


def test_pg_edb_tde_enabled_is_store_wide():
    conn = _Conn(rows=[_EDB_COLUMNS, ("FROM pg_control_init()", [(1,)])])
    obs = _pg(conn).at_rest_encryption_state()
    assert obs.state == "enabled" and obs.scope == "store"
    assert obs.source == "pg_control_init.data_encryption_version"


def test_pg_edb_tde_off_is_disabled():
    conn = _Conn(rows=[_EDB_COLUMNS, ("FROM pg_control_init()", [(0,)])])
    obs = _pg(conn).at_rest_encryption_state("docs")
    assert obs.state == "disabled" and obs.scope == "store"


def test_pg_community_is_not_observable_and_never_queries_the_missing_column():
    conn = _Conn(rows=[("FROM pg_proc", [(["pg_control_version"],)]),
                       # pgcrypto is installed; it must not count as evidence.
                       ("extname = 'pgcrypto'", [("1.3",)])])
    obs = _pg(conn).at_rest_encryption_state()
    assert obs.state == "not_observable"
    assert obs.reason.startswith("PostgreSQL does not report disk or storage encryption")
    assert obs.evidence["provider_hint"] == "self_managed"
    assert obs.evidence_to_supply and obs.documented_default is None
    assert not any("FROM pg_control_init()" in sql for sql, _ in conn.calls)
    assert not any("pgcrypto" in sql for sql, _ in conn.calls)


@pytest.mark.parametrize("setting,provider,reason_start,has_default", [
    ("rds.extensions", "aws_rds", "Amazon RDS reports storage encryption only", False),
    ("azure.extensions", "azure", "Azure Database for PostgreSQL encrypts storage", True),
    ("cloudsql.iam_authentication", "cloud_sql",
     "Google encrypts this database by default, but reports it only through the "
     "Cloud SQL API", True),
    ("alloydb.enable_pgaudit", "alloydb",
     "Google encrypts this database by default, but reports it only through the "
     "AlloyDB API", True),
])
def test_pg_provider_hint_chooses_what_to_ask_for(setting, provider, reason_start,
                                                  has_default):
    conn = _Conn(rows=[("FROM pg_proc", []), ("FROM pg_settings", [(setting,)])])
    obs = _pg(conn).at_rest_encryption_state()
    assert obs.state == "not_observable"  # a provider is identification, never evidence
    assert obs.evidence["provider_hint"] == provider
    assert obs.reason.startswith(reason_start)
    assert bool(obs.documented_default) is has_default
    settings_sql = next(sql for sql, _ in conn.calls if "pg_settings" in sql)
    assert "LIKE 'rds.%'" in settings_sql


def test_pg_tde_is_reported_per_table():
    def encrypted(params):
        return [(params[0] == '"public"."secure_docs"',)]

    conn = _Conn(rows=[("FROM pg_proc", []),
                       ("extname = 'pg_tde'", [("2.0",)]),
                       ("pg_tde_is_encrypted", encrypted)])
    pg = _pg(conn)
    store = pg.at_rest_encryption_state()
    assert store.state == "not_observable" and store.per_collection
    assert pg.at_rest_encryption_state("secure_docs").state == "enabled"
    plain = pg.at_rest_encryption_state("docs")
    assert plain.state == "disabled" and plain.scope == "collection"


def _tde_conn(encrypted_names, relations):
    def answer(params):
        return [(params[0] in encrypted_names,)]

    return _Conn(rows=[("FROM pg_proc", []),
                       ("extname = 'pg_tde'", [("2.0",)]),
                       ("pg_tde.wal_encrypt", [("on",)]),
                       ("pg_inherits", relations),
                       ("pg_tde_is_encrypted", answer)])


_RELATIONS = [("docs_2025", "table"), ("docs_2026", "table"),
              ("docs_2025_embedding_idx", "index"), ("pg_toast.pg_toast_1", "toast")]


def test_pg_tde_needs_every_partition_index_and_toast_relation():
    names = {r[0] for r in _RELATIONS}
    enabled = _pg(_tde_conn(names, _RELATIONS)).at_rest_encryption_state("docs")
    assert enabled.state == "enabled"
    assert enabled.evidence["relations_checked"] == {"table": 2, "index": 1, "toast": 1}
    assert enabled.evidence["wal_encrypt"] == "on"
    assert "temporary files" in enabled.evidence["not_covered"]


@pytest.mark.parametrize("missing", ["docs_2026", "docs_2025_embedding_idx",
                                     "pg_toast.pg_toast_1"])
def test_pg_tde_any_unencrypted_relation_is_disabled(missing):
    names = {r[0] for r in _RELATIONS} - {missing}
    obs = _pg(_tde_conn(names, _RELATIONS)).at_rest_encryption_state("docs")
    assert obs.state == "disabled"
    assert obs.evidence["unencrypted_relations"] == [missing]


def test_pg_catalog_errors_roll_back_and_never_raise():
    class Denied(Exception):
        sqlstate = "42501"

    conn = _Conn(errors=[("FROM pg_proc", Denied("permission denied")),
                         ("pg_extension", Denied("permission denied"))])
    obs = _pg(conn).at_rest_encryption_state()
    assert obs.state == "not_observable"
    assert conn.rolled_back == 2
    assert "permission denied" in repr(obs.evidence)


# ---- MongoDB ----------------------------------------------------------------

class _Admin:
    def __init__(self, status=None, exc=None):
        self._status, self._exc = status, exc

    def command(self, name):
        assert name == "serverStatus"
        if self._exc:
            raise self._exc
        return self._status


class _DB:
    def __init__(self, infos):
        self._infos = infos

    def list_collections(self, filter=None):
        return [i for i in self._infos if i["name"] == filter["name"]]


class _Client:
    def __init__(self, admin=None, infos=()):
        self.admin = admin
        self._infos = list(infos)

    def __getitem__(self, name):
        return _DB(self._infos)


def _mongo(client, endpoint="db.internal:27017"):
    c = MongoDBConnector.__new__(MongoDBConnector)
    c._c = client
    c._endpoint = endpoint
    return c


def test_mongo_encrypted_storage_engine():
    status = {"encryptionAtRest": {"encryptionEnabled": True,
                                   "encryptionCipherMode": "AES256-CBC",
                                   "encryptionKeyId": "local-key-0123456789"}}
    obs = _mongo(_Client(_Admin(status))).at_rest_encryption_state()
    assert obs.state == "enabled" and "AES256-CBC" in obs.mechanism
    assert obs.key_reference and "0123456789" not in obs.key_reference


@pytest.mark.parametrize("status,endpoint,state", [
    ({"encryptionAtRest": {"encryptionEnabled": False}}, "db.internal:27017", "disabled"),
    ({"encryptionAtRest": {"encryptionEnabled": False}}, "c0.ab.mongodb.net", "not_observable"),
    ({"version": "7.0"}, "db.internal:27017", "not_observable"),
])
def test_mongo_at_rest_states(status, endpoint, state):
    assert _mongo(_Client(_Admin(status)), endpoint).at_rest_encryption_state().state == state


def test_mongo_server_status_denied_is_not_observable():
    pytest.importorskip("pymongo")
    from pymongo.errors import OperationFailure

    obs = _mongo(_Client(_Admin(exc=OperationFailure("not authorized", code=13)))) \
        .at_rest_encryption_state()
    assert obs.state == "not_observable"
    boom = _mongo(_Client(_Admin(exc=RuntimeError("x")))).at_rest_encryption_state()
    assert boom.state == "error"


def test_mongo_field_encryption_from_encrypted_fields_and_json_schema():
    infos = [
        {"name": "qe", "options": {"encryptedFields": {"fields": [
            {"path": "ssn", "bsonType": "string", "keyId": "k",
             "queries": {"queryType": "equality"}},
            {"path": "notes", "bsonType": "string", "keyId": "k"}]}}},
        {"name": "csfle", "options": {"validator": {"$jsonSchema": {
            "encryptMetadata": {"algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Random"},
            "properties": {
                "patient": {"bsonType": "object", "properties": {
                    "mrn": {"encrypt": {"bsonType": "string", "algorithm":
                                        "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"}}}},
                "diagnosis": {"encrypt": {"bsonType": "string"}},
                "title": {"bsonType": "string"}}}}}},
        {"name": "plain", "options": {}},
    ]
    conn = _mongo(_Client(infos=infos))
    assert conn.field_encryption_config("app.qe") == [
        {"path": "ssn", "mechanism": "queryable_encryption", "queries": ["equality"]},
        {"path": "notes", "mechanism": "queryable_encryption", "queries": []}]
    csfle = conn.field_encryption_config("app.csfle")
    assert {f["path"]: f["algorithm"] for f in csfle} == {
        "patient.mrn": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
        "diagnosis": "AEAD_AES_256_CBC_HMAC_SHA_512-Random"}
    assert conn.field_encryption_config("app.plain") == []
    assert "keyId" not in repr(conn.field_encryption_config("app.qe"))


# ---- Azure AI Search / Vertex AI / Bedrock ----------------------------------

def _azure(index):
    from vecshield_platform.connectors.azure_search import AzureSearchConnector

    c = AzureSearchConnector.__new__(AzureSearchConnector)
    c._ix = types.SimpleNamespace(get_index=lambda name: index)
    return c


def test_azure_customer_managed_key_is_enabled_and_absence_is_not_disabled():
    key = types.SimpleNamespace(key_name="vecshield-cmk", key_version="3",
                                vault_uri="https://vault-prod.vault.azure.net/")
    obs = _azure(types.SimpleNamespace(encryption_key=key)).at_rest_encryption_state("idx")
    assert obs.state == "enabled" and obs.source == "index.encryption_key"
    assert obs.key_reference and "vault-prod" not in obs.key_reference
    absent = _azure(types.SimpleNamespace(encryption_key=None)).at_rest_encryption_state("idx")
    assert absent.state == "not_observable"
    store = _azure(None).at_rest_encryption_state()
    assert store.per_collection


def test_vertex_cmek(monkeypatch):
    specs = {"with": types.SimpleNamespace(
        kms_key_name="projects/p/locations/l/keyRings/r/cryptoKeys/vector-key"),
        "without": None}

    class Index:
        def __init__(self, name):
            self.encryption_spec = specs[name]

    from vecshield_platform.connectors.vertex_ai import VertexAIConnector

    c = VertexAIConnector.__new__(VertexAIConnector)
    c._ai = types.SimpleNamespace(MatchingEngineIndex=Index)
    c._endpoint_id = None
    assert "at_rest_introspection" in c.capabilities()
    enabled = c.at_rest_encryption_state("with")
    assert enabled.state == "enabled" and enabled.source == "encryption_spec.kms_key_name"
    assert "keyRings/r" not in enabled.key_reference
    assert c.at_rest_encryption_state("without").state == "not_observable"


class _Bedrock:
    def __init__(self, kb, ds_keys=None):
        self._kb = kb
        self._keys = ds_keys or {}

    def get_knowledge_base(self, knowledgeBaseId=None):
        assert knowledgeBaseId == "kb-1"
        return {"knowledgeBase": self._kb}

    def list_data_sources(self, knowledgeBaseId=None, nextToken=None):
        return {"dataSourceSummaries": [{"dataSourceId": d} for d in self._keys]}

    def get_data_source(self, knowledgeBaseId=None, dataSourceId=None):
        key = self._keys[dataSourceId]
        sse = {"kmsKeyArn": key} if key else {}
        return {"dataSource": {"serverSideEncryptionConfiguration": sse}}


def _bedrock(kb, ds_keys=None):
    from vecshield_platform.connectors.bedrock_kb import BedrockKBConnector

    c = BedrockKBConnector.__new__(BedrockKBConnector)
    c._c = _Bedrock(kb, ds_keys)
    return c.at_rest_encryption_state("support (kb-1)")


_ARN = "arn:aws:kms:us-east-1:111122223333:key/abc-0001"


def _custom(store_type="OPENSEARCH_SERVERLESS"):
    return {"knowledgeBaseConfiguration": {"type": "VECTOR"},
            "storageConfiguration": {"type": store_type, "opensearchServerlessConfiguration": {
                "collectionArn": "arn:aws:aoss:us-east-1:111122223333:collection/kb"}}}


def test_bedrock_data_source_keys_never_yield_enabled():
    """Regression: data-source keys cover transient ingestion storage only."""
    obs = _bedrock(_custom(), {"ds-1": _ARN, "ds-2": _ARN})
    assert obs.state == "not_observable"
    assert obs.evidence["ingestion (transient) storage"] == {"data_sources": 2,
                                                             "with_customer_key": 2}
    assert obs.key_reference is None


def test_bedrock_custom_kb_names_the_backing_store_and_its_documented_default():
    obs = _bedrock(_custom())
    assert obs.reason.startswith("Bedrock does not report how the backing vector store")
    assert obs.evidence["backing_store_type"] == "OPENSEARCH_SERVERLESS"
    assert obs.evidence["backing_store_arn"].endswith("collection/kb")
    assert "always encrypts at rest, per AWS" in obs.documented_default["text"]
    rds = _bedrock(_custom("RDS"))
    assert rds.state == "not_observable" and rds.documented_default is None


def _managed(key=None):
    """A GetKnowledgeBase ``knowledgeBase`` in botocore's real shape: the managed
    configuration is nested inside knowledgeBaseConfiguration."""
    config: dict = {"type": "MANAGED", "managedKnowledgeBaseConfiguration": {}}
    if key:
        config["managedKnowledgeBaseConfiguration"]["serverSideEncryptionConfiguration"] = \
            {"kmsKeyArn": key}
    return {"knowledgeBaseConfiguration": config}


def test_bedrock_fixture_matches_the_installed_botocore_model():
    """The shape the connector reads must be the shape AWS returns."""
    pytest.importorskip("botocore")
    import botocore.session

    model = botocore.session.get_session().get_service_model("bedrock-agent")
    kb = model.shape_for("KnowledgeBase")
    config = kb.members["knowledgeBaseConfiguration"]
    assert "managedKnowledgeBaseConfiguration" not in kb.members
    managed = config.members["managedKnowledgeBaseConfiguration"]
    sse = managed.members["serverSideEncryptionConfiguration"]
    assert "kmsKeyArn" in sse.members
    assert "MANAGED" in config.members["type"].enum
    assert "storageConfiguration" in kb.members

    fixture = _managed(_ARN)
    assert set(fixture) <= set(kb.members)
    assert set(fixture["knowledgeBaseConfiguration"]) <= set(config.members)


def test_bedrock_top_level_managed_configuration_is_not_read():
    """Regression: a key at the wrong (top) level must not be reported as enabled."""
    wrong = {"knowledgeBaseConfiguration": {"type": "MANAGED"},
             "managedKnowledgeBaseConfiguration": {
                 "serverSideEncryptionConfiguration": {"kmsKeyArn": _ARN}}}
    assert _bedrock(wrong).state == "not_observable"


def test_bedrock_managed_kb_key():
    obs = _bedrock(_managed(_ARN))
    assert obs.state == "enabled"
    assert obs.mechanism == "customer-managed KMS key (managed KB storage)"
    assert "111122223333" not in obs.key_reference
    default = _bedrock(_managed())
    assert default.state == "not_observable"
    assert default.reason.startswith("This managed knowledge base names no "
                                     "customer-managed KMS key")
    assert default.documented_default["text"] == ("By default, Amazon Bedrock encrypts "
                                                  "this data using an AWS-owned key.")
    assert default.documented_default["source_url"].endswith("encryption-kb.html")


@pytest.mark.parametrize("store_type,page", [
    ("OPENSEARCH_SERVERLESS", "serverless-encryption.html"),
    ("S3_VECTORS", "s3-vectors-data-encryption.html"),
    ("NEPTUNE_ANALYTICS", "security-pillar.html"),
])
def test_bedrock_backing_store_defaults_cite_their_own_pages(store_type, page):
    obs = _bedrock(_custom(store_type))
    assert obs.documented_default["source_url"].endswith(page)


@pytest.mark.parametrize("kb", [_custom(), _managed(),
                                {}])
def test_bedrock_is_never_disabled(kb):
    assert _bedrock(kb, {"ds-1": None}).state != "disabled"


# ---- Pinecone / Milvus / OpenSearch ----------------------------------------

def _pinecone(model):
    from vecshield_platform.connectors.pinecone import PineconeConnector

    c = PineconeConnector.__new__(PineconeConnector)
    c._pc = types.SimpleNamespace(describe_index=lambda name: model)
    return c


def test_pinecone_cmek():
    enabled = _pinecone(types.SimpleNamespace(name="idx", cmek_id="cmek-0123456789abcdef")) \
        .at_rest_encryption_state("idx/tenant-a")
    assert enabled.state == "enabled" and "0123456789" not in enabled.key_reference
    none = _pinecone(types.SimpleNamespace(name="idx", cmek_id=None)) \
        .at_rest_encryption_state("idx")
    assert none.state == "not_observable"
    assert none.reason.startswith("This Pinecone index has no customer-managed key")
    old = _pinecone(types.SimpleNamespace(name="idx")).at_rest_encryption_state("idx")
    assert old.state == "not_observable" and "2026-07" in old.reason
    as_dict = _pinecone({"name": "idx", "cmek_id": "k-1234567890"}) \
        .at_rest_encryption_state("idx")
    assert as_dict.state == "enabled"


class _Milvus:
    def __init__(self, version="v2.6.12", db=None, collections=None, deny=False):
        self._version, self._db, self._cols, self._deny = version, db or {}, \
            collections or {}, deny

    def get_server_version(self):
        return self._version

    def describe_database(self, db_name):
        if self._deny:
            raise RuntimeError("PermissionDenied: privilege DescribeDatabase")
        return {"name": db_name, **self._db}

    def describe_collection(self, name):
        return {"collection_name": name, "properties": self._cols.get(name, {})}


def _milvus(client):
    from vecshield_platform.connectors.milvus import MilvusConnector

    c = MilvusConnector.__new__(MilvusConnector)
    c._client = client
    c._db_name = "default"
    return c


def test_milvus_database_encryption_zone_is_enabled():
    obs = _milvus(_Milvus(db={"cipher.ezID": "ez-1", "cipher.key": _ARN})) \
        .at_rest_encryption_state()
    assert obs.state == "enabled" and obs.scope == "store"
    assert obs.evidence["encryption_zone"] == "ez-1"
    assert "111122223333" not in obs.key_reference
    assert "enableDiskEncryption" in obs.evidence["not_visible"]


def test_milvus_collection_zone_and_absence():
    client = _Milvus(collections={"secure": {"cipher.ezID": "ez-2"}})
    store = _milvus(client).at_rest_encryption_state()
    assert store.state == "not_observable" and store.per_collection
    assert _milvus(client).at_rest_encryption_state("secure").state == "enabled"
    plain = _milvus(client).at_rest_encryption_state("plain")
    assert plain.state == "not_observable"
    assert plain.reason.startswith("Milvus shows no native encryption for this database")


@pytest.mark.parametrize("version", ["2.5.14", "v2.4.0-lite", "v2.5.99"])
def test_milvus_before_2_6_predates_encryption_zones(version):
    obs = _milvus(_Milvus(version=version)).at_rest_encryption_state()
    assert obs.state == "not_observable" and not obs.per_collection
    assert obs.reason.startswith("This Milvus version predates native encryption zones")
    assert "no native encryption at rest" not in obs.reason


@pytest.mark.parametrize("version", ["v2.6.0", "v2.6.9"])
def test_milvus_2_6_0_to_2_6_9_already_carry_cipher_properties(version):
    """cipher.ezID lived in internal/util/hookutil/cipher.go before 2.6.10."""
    obs = _milvus(_Milvus(version=version, db={"cipher.ezID": "ez-1",
                                               "cipher.key": _ARN})) \
        .at_rest_encryption_state()
    assert obs.state == "enabled"


def test_milvus_permission_denied_is_not_observable_never_disabled():
    obs = _milvus(_Milvus(deny=True)).at_rest_encryption_state()
    assert obs.state == "not_observable" and "not permitted" in obs.reason


class _OSIndices:
    def __init__(self, settings):
        self._settings = settings
        self.kwargs = None

    def get_settings(self, **kwargs):
        self.kwargs = kwargs
        return {kwargs["index"]: self._settings}


def _opensearch(settings, plugins=()):
    from vecshield_platform.connectors.opensearch import OpenSearchConnector

    c = OpenSearchConnector.__new__(OpenSearchConnector)
    c._c = types.SimpleNamespace(indices=_OSIndices(settings), cat=types.SimpleNamespace(
        plugins=lambda format=None: [{"component": p} for p in plugins]))
    return c


def test_opensearch_cryptofs_index_is_enabled():
    c = _opensearch({"settings": {"index.store.type": "cryptofs",
                                  "index.store.crypto.key_provider": "aws-kms",
                                  "index.store.crypto.kms.type": "aws-kms",
                                  "index.store.crypto.kms.key_arn": _ARN}})
    obs = c.at_rest_encryption_state("docs")
    assert obs.state == "enabled"
    assert obs.evidence == {"key_provider": "aws-kms", "kms_type": "aws-kms"}
    assert "pre-release" in obs.mechanism
    assert "111122223333" not in obs.key_reference
    assert c._c.indices.kwargs["include_defaults"] is True


def test_opensearch_plain_store_is_not_observable_and_nested_settings_parse():
    obs = _opensearch({"settings": {"index": {"number_of_shards": "1"}},
                       "defaults": {"index": {"store": {"type": "fs"}}}}) \
        .at_rest_encryption_state("docs")
    assert obs.state == "not_observable" and obs.evidence == {"store_type": "fs"}
    assert obs.reason.startswith("This index is not stored with the storage-encryption")
    store = _opensearch({}, plugins=["opensearch-storage-encryption"]) \
        .at_rest_encryption_state()
    assert store.per_collection
    assert store.evidence["storage_encryption_plugin_installed"] is True


# ---- rollup -----------------------------------------------------------------

def _obs(state, collection=None, scope="collection", **kw):
    return AtRestObservation(state=state, scope=scope, collection=collection, **kw)


@pytest.mark.parametrize("states,outcome,crypto_state", [
    (["enabled", "enabled"], "passed", "verified"),
    (["enabled", "not_observable"], "inconclusive", "not_verified"),
    (["enabled", "disabled", "not_observable"], "failed", "observed_exposure"),
    (["not_observable", "not_observable"], "unsupported", "not_observable"),
    (["unsupported"], "unsupported", "not_observable"),
    (["error", "error"], "error", "not_verified"),
])
def test_rollup_counts_and_states(states, outcome, crypto_state):
    store = _obs("not_observable", scope="store", per_collection=True, source="s")
    per = [_obs(s, f"c{i}", source="s") for i, s in enumerate(states)]
    record, findings = at_rest_check("store", store, per)
    assert record["outcome"] == outcome
    assert record["coverage"]["crypto_state"] == crypto_state
    counts = record["coverage"]["collections"]
    assert counts == {"total": len(states),
                      "verified_encrypted": states.count("enabled"),
                      "verified_unencrypted": states.count("disabled"),
                      "unknown": len(states) - states.count("enabled")
                      - states.count("disabled")}
    assert [p["state"] for p in record["coverage"]["per_collection"]] == states
    assert len(findings) == states.count("disabled")
    assert all(f.severity is Severity.HIGH and f.category == "at_rest_encryption"
               for f in findings)


def test_not_observable_never_fails_and_never_finds():
    for state in ("not_observable", "unsupported", "error"):
        store = _obs(state, scope="store")
        record, findings = at_rest_check("s", store, [_obs(state, "c")])
        assert record["outcome"] != "failed" and findings == []


def test_store_wide_disabled_is_one_finding_not_one_per_collection():
    class Conn:
        kind = "pgvector"

        def at_rest_encryption_state(self, collection=None):
            return AtRestObservation(state="disabled", scope="store",
                                     collection=collection, source="x", reason="off")

    store, per = observe_at_rest(Conn(), ["a", "b", "c"], supported=True)
    record, findings = at_rest_check("s", store, per)
    assert record["coverage"]["collections"]["verified_unencrypted"] == 3
    assert record["coverage"]["scope"] == "store"
    assert len(findings) == 1 and findings[0].collection is None


def test_observe_asks_per_collection_only_when_told_to_and_survives_exceptions():
    asked = []

    class Conn:
        kind = "azure_search"

        def at_rest_encryption_state(self, collection=None):
            asked.append(collection)
            if collection is None:
                return AtRestObservation(state="not_observable", per_collection=True)
            if collection == "bad":
                raise RuntimeError("SDK blew up")
            return AtRestObservation(state="enabled", scope="collection",
                                     collection=collection)

    store, per = observe_at_rest(Conn(), ["good", "bad"], supported=True)
    assert asked == [None, "good", "bad"]
    assert [o.state for o in per] == ["enabled", "error"]

    _, unsupported = observe_at_rest(Conn(), ["good"], supported=False)
    assert unsupported[0].state == "unsupported" and asked == [None, "good", "bad"]


# ---- engine -----------------------------------------------------------------

class _Store:
    kind = "mongodb"

    def __init__(self, caps=(), at_rest=None, fields=None, collections=("a", "b")):
        self._caps = set(caps)
        self._at_rest = at_rest
        self._fields = fields or {}
        self._collections = collections

    def capabilities(self):
        return self._caps

    def describe(self):
        return VectorStore(kind=self.kind, name="mongodb://db.internal:27017",
                           endpoint="db.internal:27017",
                           metadata={"transport": {"tls": True, "source": "dsn"}},
                           collections=[Collection(name=n, count=1)
                                        for n in self._collections])

    def at_rest_encryption_state(self, collection=None):
        return self._at_rest(collection)

    def field_encryption_config(self, collection):
        value = self._fields[collection]
        if isinstance(value, Exception):
            raise value
        return value


def _audit(conn, **kw):
    return run_posture_audit(conn, resolve_dns=False, include_cve=False,
                             auth_probe=False, **kw)


def _outcomes(job, check):
    return [o for o in job.stats["check_outcomes"] if o["check"] == check]


def test_engine_unsupported_connector_is_unsupported_not_failed():
    job = _audit(_Store())
    [at_rest] = _outcomes(job, "at_rest_encryption")
    assert at_rest["outcome"] == "unsupported"
    assert at_rest["coverage"]["crypto_state"] == "not_observable"
    assert at_rest["coverage"]["collections"] == {"total": 2, "verified_encrypted": 0,
                                                  "verified_unencrypted": 0, "unknown": 2}
    [field] = _outcomes(job, "field_encryption")
    assert field["collection"] is None and field["outcome"] == "unsupported"
    assert field["coverage"]["supported"] is False
    assert not [f for f in job.findings if f.category == "at_rest_encryption"]
    assert "at_rest_encryption" in job.stats["checks"]


def test_engine_disabled_raises_a_finding_and_trips_the_policy():
    conn = _Store(caps={"at_rest_introspection"},
                  at_rest=lambda c: AtRestObservation(state="disabled", scope="store",
                                                      collection=c, source="serverStatus",
                                                      reason="engine off"))
    job = _audit(conn)
    [at_rest] = _outcomes(job, "at_rest_encryption")
    assert at_rest["outcome"] == "failed"
    violations = {v.policy_id for v in evaluate_policies(posture_policies(), job.findings)}
    assert "at-rest-encryption-not-disabled" in violations


def test_engine_not_observable_trips_no_policy():
    conn = _Store(caps={"at_rest_introspection"},
                  at_rest=lambda c: AtRestObservation(state="not_observable"))
    job = _audit(conn)
    violations = {v.policy_id for v in evaluate_policies(posture_policies(), job.findings)}
    assert "at-rest-encryption-not-disabled" not in violations
    assert _outcomes(job, "at_rest_encryption")[0]["outcome"] == "unsupported"


def test_engine_field_encryption_per_collection():
    conn = _Store(caps={"field_encryption_introspection"},
                  fields={"a": [{"path": "ssn", "mechanism": "queryable_encryption",
                                 "keyId": "secret-key-id"}],
                          "b": [], "c": RuntimeError("boom")},
                  collections=("a", "b", "c"))
    by_collection = {o["collection"]: o for o in _outcomes(_audit(conn), "field_encryption")}
    assert by_collection["a"]["outcome"] == "passed"
    assert by_collection["a"]["coverage"]["fields"] == [
        {"path": "ssn", "mechanism": "queryable_encryption"}]
    assert by_collection["b"]["outcome"] == "inconclusive"
    assert by_collection["b"]["coverage"]["supported"] is True
    assert by_collection["c"]["outcome"] == "error"


# ---- outcomes feed the criteria --------------------------------------------

def _pg_like(tls_accepted, at_rest_state):
    class Conn:
        kind = "pgvector"

        def capabilities(self):
            return {"transport_introspection", "tls_enforcement_introspection",
                    "at_rest_introspection"}

        def describe(self):
            return VectorStore(kind="pgvector", name="pg", endpoint="postgresql://db:5432/app",
                               collections=[Collection(name="docs", count=1)])

        def transport_session_info(self):
            return {"tls": True, "version": "TLSv1.3", "cipher": "X", "source": "pg_stat_ssl"}

        def tls_enforcement_info(self):
            return {"plaintext_accepted": tls_accepted, "method": "catalog",
                    "reason": "catalog", "evidence": {}}

        def at_rest_encryption_state(self, collection=None):
            return AtRestObservation(state=at_rest_state, scope="store",
                                     collection=collection)

    return Conn()


def _criterion(cid, job, evidence=None):
    return evaluate_criterion(get_criterion(cid), check_outcomes=job.stats["check_outcomes"],
                              applicability_answers=EPHI, evidence=evidence or {})


def test_hipaa_transmission_passes_technically_when_tls_is_used_and_enforced():
    result = _criterion("HIPAA-164-312-E2II-ENCRYPTION-01", _audit(_pg_like(False, "enabled")))
    assert result.technical_result == "passed"
    assert result.fallback_required == []


def test_hipaa_transmission_is_a_gap_when_plaintext_is_accepted():
    result = _criterion("HIPAA-164-312-E2II-ENCRYPTION-01", _audit(_pg_like(True, "enabled")))
    assert result.technical_result == "failed" and result.status == "gap_identified"


def test_hipaa_transmission_asks_for_evidence_when_enforcement_was_not_requested():
    conn = _pg_like(None, "enabled")
    result = _criterion("HIPAA-164-312-E2II-ENCRYPTION-01", _audit(conn))
    assert result.status == "evidence_needed"
    assert "transport_security_statement" in result.fallback_required


@pytest.mark.parametrize("state,status", [
    ("not_observable", "evidence_needed"),
    ("disabled", "gap_identified"),
])
def test_hipaa_at_rest_reads_the_at_rest_outcome(state, status):
    result = _criterion("HIPAA-164-312-A2IV-ENCRYPTION-01", _audit(_pg_like(False, state)))
    assert result.status == status
    if state == "not_observable":
        assert result.fallback_required == ["encryption_at_rest_statement"]


def test_hipaa_at_rest_enabled_needs_no_fallback():
    result = _criterion("HIPAA-164-312-A2IV-ENCRYPTION-01", _audit(_pg_like(False, "enabled")))
    assert result.technical_result == "passed" and result.fallback_required == []



# ---- MongoDB, Azure and Vertex wording ---------------------------------------

def test_mongo_records_the_node_and_the_vector_search_caveat():
    conn = _mongo(_Client(_Admin({"host": "shard0-a:27017",
                                  "encryptionAtRest": {"encryptionEnabled": True}})))
    conn._layout = {"app.kb": {"index": "vec_idx", "vec": "embedding"}}
    obs = conn.at_rest_encryption_state()
    assert obs.evidence["host"] == "shard0-a:27017"
    assert obs.evidence["scope_note"] == "this mongod node"
    assert "mongot" in obs.evidence["caveat"]
    assert "medium" in obs.evidence["confidence"]


@pytest.mark.parametrize("status,endpoint,reason_start,has_default", [
    ({"host": "h"}, "db.internal:27017", "MongoDB Community has no built-in", False),
    ({"host": "h"}, "c0.ab.mongodb.net", "Atlas always encrypts storage volumes", True),
    ({"host": "h", "encryptionAtRest": {"encryptionEnabled": False}},
     "c0.ab.mongodb.net", "Atlas always encrypts storage volumes", True),
])
def test_mongo_not_observable_reasons(status, endpoint, reason_start, has_default):
    obs = _mongo(_Client(_Admin(status)), endpoint).at_rest_encryption_state()
    assert obs.state == "not_observable"
    assert obs.reason.startswith(reason_start)
    assert bool(obs.documented_default) is has_default


def test_mongo_permission_denied_reason_names_the_role():
    pytest.importorskip("pymongo")
    from pymongo.errors import OperationFailure

    obs = _mongo(_Client(_Admin(exc=OperationFailure("not authorized", code=13)))) \
        .at_rest_encryption_state()
    assert "clusterMonitor" in obs.reason and "security.enableEncryption" in obs.reason


def test_azure_wording_and_documented_default():
    key = types.SimpleNamespace(key_name="k", key_version=None, vault_uri="https://v/",
                                access_credentials=types.SimpleNamespace(
                                    application_secret="app-secret-value"))
    enabled = _azure(types.SimpleNamespace(encryption_key=key)).at_rest_encryption_state("i")
    assert enabled.mechanism == ("Customer-managed key (Azure Key Vault) on top of "
                                 "Microsoft-managed keys")
    assert "app-secret-value" not in repr(enabled.to_dict())
    absent = _azure(types.SimpleNamespace(encryption_key=None)).at_rest_encryption_state("i")
    assert absent.reason.startswith("This index has no customer-managed key")
    assert "if any" not in absent.reason
    assert absent.documented_default["source_url"].endswith("search-security-built-in")


def test_vertex_endpoint_key_is_compared_with_the_index():
    index_key = "projects/p/locations/l/keyRings/r/cryptoKeys/index-key"

    class Resource:
        def __init__(self, key):
            self.encryption_spec = types.SimpleNamespace(kms_key_name=key)

    from vecshield_platform.connectors.vertex_ai import VertexAIConnector

    c = VertexAIConnector.__new__(VertexAIConnector)
    c._ai = types.SimpleNamespace(
        MatchingEngineIndex=lambda name: Resource(index_key),
        MatchingEngineIndexEndpoint=lambda eid: Resource(index_key.replace("index", "ep")))
    c._endpoint_id = "ep-1"
    obs = c.at_rest_encryption_state("idx")
    assert obs.state == "enabled"
    assert obs.evidence["endpoint_key_matches_index"] is False
    assert "keyRings" not in obs.evidence["endpoint_key_reference"]

    c._ai = types.SimpleNamespace(MatchingEngineIndex=lambda name: Resource(None),
                                  MatchingEngineIndexEndpoint=lambda eid: Resource(None))
    absent = c.at_rest_encryption_state("idx")
    assert absent.reason.startswith("This index has no customer-managed key")
    assert absent.documented_default["source_url"].endswith("default-encryption")
    assert "AES-256" not in absent.reason + absent.documented_default["text"]


# ---- the support table is held to the connectors ---------------------------

def test_every_connector_kind_has_a_support_entry_that_matches_its_capabilities():
    from vecshield_platform.actions import capability_verdict
    from vecshield_platform.connectors import AVAILABLE, get_connector
    from vecshield_platform.posture.at_rest_support import AT_REST_SUPPORT

    template = types.SimpleNamespace(capability="at_rest_introspection", title="Inspect")
    assert set(AT_REST_SUPPORT) == set(AVAILABLE)
    for kind in AVAILABLE:
        entry = AT_REST_SUPPORT[kind]
        cls = get_connector(kind)
        inst = cls.__new__(cls)
        inst._endpoint_id = None  # vertex_ai reads it in capabilities()
        honest, _ = capability_verdict(inst, template)
        assert (entry.support == "supported") is honest, kind
        if entry.support == "not_supported":
            assert entry.not_supported_reason and entry.evidence_to_supply, kind
            assert len(entry.not_supported_reason.split()) <= 30, kind
        assert entry.sources, kind


def test_documented_defaults_carry_their_source():
    from vecshield_platform.posture.at_rest_support import AtRestSupport, support_matrix

    with pytest.raises(ValueError):
        AtRestSupport(kind="x", database="X", support="not_supported", observable="-")
    with pytest.raises(ValueError):
        AtRestSupport(kind="x", database="X", support="supported", observable="-",
                      documented_default="always on")
    for row in support_matrix():
        if row["documented_default"]:
            assert row["documented_default"]["source_url"].startswith("https://")


# ---- outcome details ---------------------------------------------------------

class _Plain:
    """A connector kind whose database has no at-rest or field interface."""

    kind = "qdrant"

    def capabilities(self):
        return {"query"}

    def describe(self):
        return VectorStore(kind="qdrant", name="q", endpoint="https://q.internal:6333",
                           collections=[Collection(name="docs", count=3)])


def test_not_supported_outcomes_carry_the_researched_reason_and_capability_limit():
    job = _audit(_Plain())
    [at_rest] = _outcomes(job, "at_rest_encryption")
    cov = at_rest["coverage"]
    assert at_rest["outcome"] == "unsupported" and cov["crypto_state"] == "not_observable"
    assert at_rest["reason"].startswith("Qdrant has no encryption-at-rest setting")
    assert cov["capability_limit"] is True
    assert cov["support"] == "not_supported" and cov["database"] == "Qdrant"
    assert any("LUKS" in item for item in cov["evidence_to_supply"])
    assert cov["documented_default"]["text"].startswith("Qdrant Cloud documents")
    assert cov["sources"]
    [field] = _outcomes(job, "field_encryption")
    assert field["coverage"]["capability_limit"] is True
    assert field["coverage"]["database"] == "Qdrant"
    assert field["coverage"]["support"] == "not_supported"
    assert not [f for f in job.findings if f.category == "at_rest_encryption"]
    # at_rest, field encryption and access_grants (Qdrant reports no grants).
    assert job.stats["coverage"]["checks_not_supported"] == 3


def test_supported_but_unobservable_asks_for_evidence_without_capability_limit():
    class Azure(_Plain):
        kind = "azure_search"

        def capabilities(self):
            return {"at_rest_introspection"}

        def at_rest_encryption_state(self, collection=None):
            return AtRestObservation(
                state="not_observable", scope="collection" if collection else "store",
                collection=collection, per_collection=collection is None,
                reason="This index has no customer-managed key.",
                documented_default={"text": "always on", "source_url": "https://x"})

    [at_rest] = _outcomes(_audit(Azure()), "at_rest_encryption")
    cov = at_rest["coverage"]
    assert at_rest["outcome"] == "unsupported"
    assert "capability_limit" not in cov
    assert cov["support"] == "supported" and cov["database"] == "Azure AI Search"
    assert cov["evidence_to_supply"]
    assert cov["documented_default"] == {"text": "always on", "source_url": "https://x"}
    assert at_rest["reason"].startswith("This index has no customer-managed key.")


def test_verified_needs_no_evidence_to_supply():
    store = _obs("enabled", scope="store", source="s")
    record, _ = at_rest_check("s", store, [replace(store, collection="c")])
    assert record["coverage"]["evidence_to_supply"] == []


def test_supported_field_outcomes_name_the_database():
    conn = _Store(caps={"field_encryption_introspection"}, fields={"a": [], "b": []})
    for outcome in _outcomes(_audit(conn), "field_encryption"):
        assert outcome["coverage"]["database"] == "MongoDB"
        assert outcome["coverage"]["support"] == "supported"
        assert "capability_limit" not in outcome["coverage"]


def test_pinecone_default_is_documented_not_reported():
    obs = _pinecone(types.SimpleNamespace(name="idx", cmek_id=None)) \
        .at_rest_encryption_state("idx")
    assert obs.reason == ("This Pinecone index has no customer-managed key. Pinecone's "
                          "default encryption is not reported by its API.")
    assert obs.documented_default["source_url"].endswith("security-overview")


def test_pgvector_azure_default_cites_the_security_page():
    conn = _Conn(rows=[("FROM pg_proc", []), ("FROM pg_settings", [("azure.extensions",)])])
    obs = _pg(conn).at_rest_encryption_state()
    assert obs.documented_default["source_url"].endswith("security/security-data-encryption")


def test_support_entries_carry_the_verified_sources():
    from vecshield_platform.posture.at_rest_support import AT_REST_SUPPORT

    assert AT_REST_SUPPORT["chroma"].sources == (
        "https://github.com/chroma-core/chroma/blob/1.5.9/chromadb/api/types.py",)
    assert AT_REST_SUPPORT["chroma"].not_supported_reason.startswith(
        "Chroma documents no encryption-at-rest setting")
    assert AT_REST_SUPPORT["weaviate"].documented_default_source == "https://weaviate.io/security"
    assert not any("Enterprise CMK" in e for e in AT_REST_SUPPORT["weaviate"].evidence_to_supply)
    assert AT_REST_SUPPORT["openai"].documented_default_source == \
        "https://openai.com/enterprise-privacy/"
    assert any("redis.io/faq" in u for u in AT_REST_SUPPORT["redis"].sources)
    mongo = [u for u in AT_REST_SUPPORT["mongodb"].sources if "percona" in u]
    assert mongo == ["https://docs.percona.com/percona-server-for-mongodb/8.0/"
                     "data-at-rest-encryption.html"]
    assert "BYOC" in AT_REST_SUPPORT["pinecone"].observable
    assert "3.6.0-SNAPSHOT" in AT_REST_SUPPORT["opensearch"].observable
    assert "AES-256" not in (AT_REST_SUPPORT["vertex_ai"].documented_default or "")
