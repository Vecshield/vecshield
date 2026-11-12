"""Transport crypto posture: TLS facts, session evidence, enforcement and the probe.

No test touches the network or a live store. SDKs that are not installed are
replaced by stand-in modules; connectors that need a live client are built
with ``__new__`` and a fake, as in tests/test_pgvector_unit.py.
"""

from __future__ import annotations

import struct
import sys
import types

import pytest

from vecshield.models import Collection, Severity, VectorStore
from vecshield_platform.compliance.fingerprint import fingerprint_finding
from vecshield_platform.compliance.policy import evaluate_policies
from vecshield_platform.connectors import build_connector
from vecshield_platform.connectors.mongodb import MongoDBConnector, mongo_transport_config
from vecshield_platform.connectors.pgvector import (
    PgVectorConnector,
    hba_plaintext_verdict,
    pg_transport_config,
)
from vecshield_platform.connectors.redis import RedisConnector
from vecshield_platform.posture import posture_policies, run_posture_audit
from vecshield_platform.posture.encryption import (
    check_tls_certificate_verification,
    check_transport_encryption,
    transport_status,
)
from vecshield_platform.posture.tls_probe import (
    PROBE_HEADERS,
    probe_postgres_plaintext,
    probe_tls_enforcement,
)

SECRET = "s3cr3t-Pa55word"


# ---- fake Postgres connection (as in test_pgvector_unit) --------------------

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

    def fetchall(self):
        for substr, rows in self._conn.rows:
            if substr in self._conn.last:
                return rows
        return []


class _Conn:
    def __init__(self, rows=(), errors=()):
        self.rows = list(rows)
        self.errors = list(errors)
        self.calls: list = []
        self.last = ""
        self.rolled_back = 0

    def cursor(self):
        return _Cursor(self)

    def rollback(self):
        self.rolled_back += 1


class _PermissionDenied(Exception):
    sqlstate = "42501"


def _pg(conn, endpoint="postgresql://db.internal:5432/app", transport=None,
        collections=()):
    c = PgVectorConnector.__new__(PgVectorConnector)
    c._conn = conn
    c._schema = "public"
    c._endpoint = endpoint
    c._layout = {}
    c._meta_cols = {}
    c._table_filter = None
    c._transport = transport or {"sslmode": None, "source": None}
    c.list_collections = lambda: [Collection(name=n, count=1) for n in collections]
    return c


# ---- transport facts in metadata, endpoint unchanged ------------------------

@pytest.mark.parametrize("uri,tls,scheme", [
    ("mongodb://u:pw@h:27017/db?tls=true", True, "mongodb"),
    ("mongodb://u:pw@h:27017/db?ssl=false", False, "mongodb"),
    ("mongodb+srv://u:pw@cluster0.x.mongodb.net/db", True, "mongodb+srv"),
    ("mongodb+srv://u:pw@cluster0.x.mongodb.net/db?tls=false", False, "mongodb+srv"),
    ("mongodb://h:27017", None, "mongodb"),
])
def test_mongo_transport_is_read_before_the_endpoint_is_stripped(uri, tls, scheme):
    config = mongo_transport_config(uri)
    assert config["tls"] is tls and config["scheme"] == scheme
    assert "pw" not in repr(config) and "u:" not in repr(config)
    status = transport_status("h:27017", kind="mongodb", metadata={"transport": config})
    assert status["encrypted"] is tls


def test_mongo_describe_keeps_the_stripped_endpoint_and_adds_transport(monkeypatch):
    pytest.importorskip("pymongo")
    import pymongo

    class _Client:
        def __init__(self, uri):
            pass

        def list_database_names(self):
            return []

    monkeypatch.setattr(pymongo, "MongoClient", _Client)
    conn = MongoDBConnector(uri=f"mongodb://admin:{SECRET}@db.internal:27017/?tls=true")
    store = conn.describe()
    assert store.endpoint == "db.internal:27017"
    assert store.name == "mongodb://db.internal:27017"
    assert store.metadata["transport"]["tls"] is True
    assert SECRET not in repr(store.metadata)
    assert transport_status(store.endpoint, kind="mongodb",
                            metadata=store.metadata)["encrypted"] is True


def test_mongo_session_info_reads_the_pool_tls_context():
    pytest.importorskip("pymongo")
    import pymongo

    conn = MongoDBConnector.__new__(MongoDBConnector)
    conn._c = pymongo.MongoClient("mongodb://h:27017/?tls=true&tlsInsecure=true",
                                  connect=False)
    info = conn.transport_session_info()
    assert info["tls"] is True and info["certificate_verification"] is False
    conn._c = pymongo.MongoClient("mongodb://h:27017/", connect=False)
    assert conn.transport_session_info()["tls"] is False


@pytest.mark.parametrize("dsn,kwarg,env,expected", [
    (None, "require", None, ("require", "connector_flag")),
    ("postgresql://u:p@h/db?sslmode=disable", "verify-full", None,
     ("verify-full", "connector_flag")),
    ("postgresql://u:p@h/db?sslmode=disable", None, "require", ("disable", "dsn")),
    ("host=h dbname=db sslmode=verify-ca", None, None, ("verify-ca", "dsn")),
    (None, None, "require", ("require", "environment")),
    (None, None, None, (None, None)),
])
def test_pg_sslmode_precedence_follows_libpq(monkeypatch, dsn, kwarg, env, expected):
    monkeypatch.delenv("PGSSLMODE", raising=False)
    if env:
        monkeypatch.setenv("PGSSLMODE", env)
    config = pg_transport_config(dsn, kwarg)
    assert (config["sslmode"], config["source"]) == expected
    assert "u:p" not in repr(config)


@pytest.mark.parametrize("sslmode,encrypted", [
    ("disable", False), ("allow", False), ("prefer", None), ("require", True),
    ("verify-ca", True), ("verify-full", True), (None, None),
])
def test_pg_metadata_sslmode_decides_a_host_port_endpoint(sslmode, encrypted):
    status = transport_status("postgresql://h:5432/db", kind="pgvector",
                              metadata={"transport": {"sslmode": sslmode,
                                                      "source": "connector_flag"}})
    assert status["encrypted"] is encrypted


def test_prefer_is_opportunistic_not_encrypted():
    """libpq's default and an explicit prefer both fall back to plaintext silently."""
    explicit = transport_status("postgresql://h:5432/db?sslmode=prefer", kind="pgvector")
    implicit = transport_status("postgresql://h:5432/db", kind="pgvector")
    assert explicit["encrypted"] is None and implicit["encrypted"] is None


def test_pgvector_accepts_sslmode_and_leaves_the_endpoint_alone(monkeypatch):
    captured = {}
    fake = types.ModuleType("psycopg")
    fake.connect = lambda *a, **k: captured.update(args=a, kwargs=k) or object()
    monkeypatch.setitem(sys.modules, "psycopg", fake)
    monkeypatch.delenv("PGSSLMODE", raising=False)

    conn = build_connector("pgvector", host="db", port=5432, dbname="app", user="u",
                           password=SECRET, sslmode="verify-full")
    assert captured["kwargs"]["sslmode"] == "verify-full"
    assert conn._endpoint == "postgresql://db:5432/app"
    assert conn._transport == {"sslmode": "verify-full", "source": "connector_flag"}
    with pytest.raises(ValueError):
        PgVectorConnector(host="db", sslmode="sometimes")


def test_opensearch_records_use_ssl_and_verify_certs(monkeypatch):
    fake = types.ModuleType("opensearchpy")
    fake.OpenSearch = lambda *a, **k: object()
    monkeypatch.setitem(sys.modules, "opensearchpy", fake)
    from vecshield_platform.connectors.opensearch import OpenSearchConnector

    plain = OpenSearchConnector(host="os", port=9200)
    assert plain._endpoint == "http://os:9200"
    assert plain._transport == {"tls": False, "source": "connector_flag",
                                "use_ssl": False, "verify_certs": False}
    tls = OpenSearchConnector(host="os", port=9200, use_ssl=True, verify_certs=False)
    assert tls._endpoint == "https://os:9200"
    assert tls._transport["certificate_verification"] is False
    status = transport_status(tls._endpoint, kind="opensearch",
                              metadata={"transport": tls._transport})
    assert status["encrypted"] is True and status["certificate_verification"] is False


def test_weaviate_honours_secure_on_the_host_port_path(monkeypatch):
    calls = {}
    weaviate = types.ModuleType("weaviate")
    weaviate.connect_to_local = lambda **k: calls.setdefault("local", k) or object()
    weaviate.connect_to_custom = lambda **k: calls.setdefault("custom", k) or object()
    classes = types.ModuleType("weaviate.classes")
    init = types.ModuleType("weaviate.classes.init")
    init.Auth = types.SimpleNamespace(api_key=lambda key: ("key", key))
    monkeypatch.setitem(sys.modules, "weaviate", weaviate)
    monkeypatch.setitem(sys.modules, "weaviate.classes", classes)
    monkeypatch.setitem(sys.modules, "weaviate.classes.init", init)
    from vecshield_platform.connectors.weaviate import WeaviateConnector

    secure = WeaviateConnector(host="wv", port=8080, secure=True)
    assert calls["custom"]["http_secure"] is True and calls["custom"]["grpc_secure"] is True
    assert secure._endpoint == "http://wv:8080"  # fingerprints are keyed on it
    status = transport_status(secure._endpoint, kind="weaviate",
                              metadata={"transport": secure._transport})
    assert status["encrypted"] is True

    plain = WeaviateConnector(host="wv", port=8080)
    assert "local" in calls and plain._transport["tls"] is False


def test_redis_session_info_reads_the_connection_class():
    class Connection:
        pass

    class SSLConnection(Connection):
        pass

    class UnixDomainSocketConnection(Connection):
        pass

    def connector(cls, **kwargs):
        c = RedisConnector.__new__(RedisConnector)
        c._r = types.SimpleNamespace(connection_pool=types.SimpleNamespace(
            connection_class=cls, connection_kwargs=kwargs))
        return c

    assert connector(Connection).transport_session_info()["tls"] is False
    tls = connector(SSLConnection, ssl_cert_reqs="none").transport_session_info()
    assert tls["tls"] is True and tls["certificate_verification"] is False
    unix = connector(UnixDomainSocketConnection).transport_session_info()
    assert unix["tls"] is None and unix["local_socket"] is True
    assert "transport_introspection" in RedisConnector.capabilities(connector(Connection))


# ---- session evidence -------------------------------------------------------

def test_pg_session_info_from_pg_stat_ssl():
    conn = _Conn(rows=[("pg_stat_ssl", [(True, "TLSv1.3", "TLS_AES_256_GCM_SHA384", False)])])
    info = _pg(conn).transport_session_info()
    assert info == {"tls": True, "version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
                    "source": "pg_stat_ssl"}
    unix = _pg(_Conn(rows=[("pg_stat_ssl", [(False, None, None, True)])]))
    assert unix.transport_session_info()["tls"] is None


def test_pg_session_info_failure_rolls_back_and_does_not_raise():
    conn = _Conn(errors=[("pg_stat_ssl", _PermissionDenied("permission denied"))])
    info = _pg(conn).transport_session_info()
    assert info["tls"] is None and "permission denied" in info["reason"]
    assert conn.rolled_back == 1


def test_session_evidence_outranks_configuration():
    status = transport_status("postgresql://h:5432/db", kind="pgvector",
                              session={"tls": True, "version": "TLSv1.3",
                                       "cipher": "X", "source": "pg_stat_ssl"})
    assert status["encrypted"] is True and status["source"] == "session"
    assert status["protocol"] == "TLSv1.3"
    downgraded = transport_status("postgresql://h:5432/db?sslmode=require",
                                  kind="pgvector", session={"tls": False})
    assert downgraded["encrypted"] is False
    # A filesystem store has no session to speak of.
    assert transport_status("file:///x", session={"tls": False})["encrypted"] is None


# ---- fingerprints -----------------------------------------------------------

@pytest.mark.parametrize("endpoint,kind,metadata,session", [
    # Same verdict, now reached through connector metadata or the session.
    ("http://os:9200", "opensearch",
     {"transport": {"tls": False, "source": "connector_flag", "use_ssl": False}}, None),
    ("postgresql://h:5432/db?sslmode=disable", "pgvector", {},
     {"tls": False, "source": "pg_stat_ssl"}),
    ("h:27017", "mongodb", {"transport": mongo_transport_config("mongodb://h:27017")},
     None),
    ("postgresql://h:5432/db", "pgvector",
     {"transport": {"sslmode": None, "source": None}}, None),
])
def test_transport_finding_fingerprints_do_not_depend_on_the_new_evidence(
        endpoint, kind, metadata, session):
    """Fingerprints hash category, store, title and endpoint only. The new
    evidence keys (source, protocol, sslmode) must not orphan cases or
    suppressions filed against the old findings."""
    before = check_transport_encryption(
        VectorStore(kind=kind, name="s", endpoint=endpoint, metadata={}))
    after = check_transport_encryption(
        VectorStore(kind=kind, name="s", endpoint=endpoint, metadata=metadata),
        session=session)
    assert before and after
    assert [f.title for f in before] == [f.title for f in after]
    assert [fingerprint_finding(f) for f in before] == \
        [fingerprint_finding(f) for f in after]


def test_newly_visible_plaintext_keeps_the_endpoint_as_its_identity():
    """pgvector's host/port path could not be decided before; now it can, and
    the finding is keyed on the unchanged endpoint string."""
    endpoint = "postgresql://h:5432/db"
    found = check_transport_encryption(VectorStore(
        kind="pgvector", name="s", endpoint=endpoint,
        metadata={"transport": {"sslmode": "disable", "source": "connector_flag"}}))
    assert found[0].severity is Severity.HIGH
    assert found[0].evidence["endpoint"] == endpoint


# ---- passive enforcement: pg_hba -------------------------------------------

def _rule(line, kind, address="0.0.0.0", netmask="0.0.0.0", method="scram-sha-256",
          database=("all",), users=("all",), error=None):
    return (line, kind, list(database), list(users), address, netmask, method, error)


@pytest.mark.parametrize("rules,accepted", [
    ([_rule(1, "local", None, None, "peer"), _rule(2, "hostssl")], False),
    ([_rule(1, "hostssl"), _rule(2, "host")], True),
    ([_rule(1, "host", "127.0.0.1", "255.255.255.255"), _rule(2, "hostssl")], False),
    ([_rule(1, "hostnossl", method="reject"), _rule(2, "hostnossl", "::", "::",
                                                     method="reject"),
      _rule(3, "host", "all", None)], False),
    ([_rule(1, "hostnossl", method="reject"), _rule(2, "host", "all", None)], True),
    ([_rule(1, "host", "10.0.0.0", "255.0.0.0", method="reject"), _rule(2, "hostssl")],
     False),
    ([_rule(1, "local", None, None, "peer")], None),
    ([_rule(1, "hostssl"), _rule(2, "host", error="invalid")], None),
])
def test_hba_verdict(rules, accepted):
    assert hba_plaintext_verdict(rules)["plaintext_accepted"] is accepted


def test_pg_tls_enforcement_info_permission_denied_is_unreadable():
    conn = _Conn(errors=[("pg_hba_file_rules", _PermissionDenied("permission denied"))])
    info = _pg(conn).tls_enforcement_info()
    assert info["plaintext_accepted"] is None and info["readable"] is False
    assert conn.rolled_back == 1


# ---- the active probe never carries credentials ----------------------------

def test_http_probe_sends_no_credentials_and_only_host_and_port():
    seen = []

    def fake_get(*args, **kwargs):
        seen.append((args, kwargs))
        return 200, {}, b"{}"

    result = probe_tls_enforcement(f"https://admin:{SECRET}@search.example:9200",
                                   kind="opensearch", http_get=fake_get)
    assert result["plaintext_accepted"] is True and result["method"] == "active_probe"
    assert seen == [(("search.example", 9200, 3.0), {})]
    assert SECRET not in repr(result)
    assert set(PROBE_HEADERS) == {"User-Agent", "Connection"}


@pytest.mark.parametrize("response,accepted", [
    (ConnectionResetError(), False),
    (ConnectionRefusedError(), False),
    ((400, {}, b"The plain HTTP request was sent to HTTPS port"), False),
    ((301, {"Location": "https://search.example/"}, b""), None),
    ((401, {}, b""), True),
    (TimeoutError(), None),
    (OSError("name resolution"), None),
])
def test_http_probe_classification(response, accepted):
    def fake_get(host, port, timeout):
        if isinstance(response, BaseException):
            raise response
        return response

    result = probe_tls_enforcement("https://search.example", http_get=fake_get)
    assert result["plaintext_accepted"] is accepted


def test_http_probe_only_runs_for_https_endpoints():
    called = []
    result = probe_tls_enforcement("http://q:6333", http_get=lambda *a: called.append(a))
    assert result["plaintext_accepted"] is None and not called
    assert probe_tls_enforcement("pinecone://idx")["method"] is None


class _FakeSocket:
    def __init__(self, reply: bytes):
        self.sent = b""
        self._reply = reply
        self.closed = False

    def sendall(self, data):
        self.sent += data

    def recv(self, n):
        out, self._reply = self._reply[:n], self._reply[n:]
        return out

    def close(self):
        self.closed = True


def _pg_message(kind: bytes, payload: bytes) -> bytes:
    return kind + struct.pack("!I", len(payload) + 4) + payload


def _pg_error(code: str, message: str) -> bytes:
    return _pg_message(b"E", b"SFATAL\x00C" + code.encode() + b"\x00M"
                       + message.encode() + b"\x00\x00")


@pytest.mark.parametrize("reply,accepted", [
    (_pg_message(b"R", struct.pack("!I", 10) + b"SCRAM-SHA-256\x00\x00"), True),
    (_pg_message(b"R", struct.pack("!I", 0)), True),
    # A refusal for the throwaway role says nothing about per-role rules.
    (_pg_error("28000", 'no pg_hba.conf entry for host "10.0.0.9", user "x", '
                        'database "app", no encryption'), None),
    (_pg_error("28000", 'no pg_hba.conf entry for host "10.0.0.9", user "x", '
                        'database "app", SSL off'), None),
    (_pg_error("28000", 'role "vecshield_tls_probe_ab" does not exist'), True),
    (_pg_error("53300", "sorry, too many clients already"), None),
    (b"", None),
])
def test_postgres_probe_classification_and_safety(reply, accepted):
    sockets = []

    def open_socket(host, port, timeout):
        sockets.append((host, port, timeout))
        sock = _FakeSocket(reply)
        opened.append(sock)
        return sock

    opened: list = []
    result = probe_tls_enforcement(
        f"postgresql://admin:{SECRET}@db.internal:6543/app?sslmode=require",
        kind="pgvector", open_socket=open_socket)
    assert result["plaintext_accepted"] is accepted
    assert sockets == [("db.internal", 6543, 3.0)]
    sent = opened[0].sent
    assert SECRET.encode() not in sent and b"admin" not in sent
    assert b"vecshield_tls_probe_" in sent and b"app\x00" in sent
    # Only the startup message: no SSLRequest, and never a PasswordMessage ('p').
    assert struct.unpack("!I", sent[:4])[0] == len(sent)
    assert struct.unpack("!I", sent[4:8])[0] == 196608
    assert opened[0].closed


def test_postgres_probe_ignores_unix_socket_endpoints():
    assert probe_tls_enforcement("host=/var/run/postgresql dbname=app",
                                 kind="pgvector")["method"] is None


def test_postgres_probe_signature_has_no_credential_parameter():
    import inspect

    for fn in (probe_tls_enforcement, probe_postgres_plaintext):
        params = set(inspect.signature(fn).parameters)
        assert not params & {"password", "api_key", "token", "user", "credentials"}


# ---- engine ----------------------------------------------------------------

class _EngineConn:
    kind = "qdrant"

    def __init__(self, endpoint="https://q.example:6333", caps=(), metadata=None,
                 **methods):
        self._endpoint = endpoint
        self._caps = set(caps)
        self._metadata = metadata or {}
        self.password = SECRET  # present on the connector, never passed to the probe
        for name, fn in methods.items():
            setattr(self, name, fn)

    def capabilities(self):
        return self._caps

    def describe(self):
        return VectorStore(kind=self.kind, name="store", endpoint=self._endpoint,
                           metadata=self._metadata, collections=[])


def _audit(conn, **kw):
    return run_posture_audit(conn, resolve_dns=False, include_cve=False,
                             auth_probe=False, **kw)


def _outcome(job, check):
    return next(o for o in job.stats["check_outcomes"] if o["check"] == check)


def test_enforcement_is_skipped_opt_in_when_not_requested_and_nothing_passive():
    job = _audit(_EngineConn())
    tls = _outcome(job, "transport_tls_enforcement")
    assert tls["outcome"] == "skipped"
    assert tls["coverage"]["opt_in"] is True
    assert tls["coverage"]["crypto_state"] == "not_verified"
    assert job.stats["coverage"]["checks_not_requested"] == 1
    assert job.stats["tls_probe"] is False


def test_probe_receives_only_the_endpoint_and_a_plaintext_answer_fails():
    calls = []

    def prober(*args, **kwargs):
        calls.append((args, kwargs))
        return {"plaintext_accepted": True, "method": "active_probe",
                "reason": "answered over http", "evidence": {"status": 200}}

    job = _audit(_EngineConn(), tls_probe=True, tls_prober=prober)
    assert calls == [(("https://q.example:6333",), {"kind": "qdrant", "timeout": 3.0})]
    assert SECRET not in repr(calls)
    tls = _outcome(job, "transport_tls_enforcement")
    assert tls["outcome"] == "failed"
    assert tls["coverage"]["crypto_state"] == "observed_exposure"
    assert tls["coverage"]["method"] == "active_probe"
    assert tls["coverage"]["plaintext_accepted"] is True
    findings = [f for f in job.findings if f.category == "transport_tls_enforcement"]
    assert len(findings) == 1 and findings[0].severity is Severity.HIGH
    violations = evaluate_policies(posture_policies(), job.findings)
    assert "tls-enforced" in {v.policy_id for v in violations}


def test_probe_refusal_is_verified_and_uninterpretable_is_not_verified():
    refused = _audit(_EngineConn(), tls_probe=True, tls_prober=lambda *a, **k: {
        "plaintext_accepted": False, "method": "active_probe", "reason": "reset"})
    assert _outcome(refused, "transport_tls_enforcement")["coverage"]["crypto_state"] \
        == "verified"
    unclear = _audit(_EngineConn(), tls_probe=True, tls_prober=lambda *a, **k: {
        "plaintext_accepted": None, "method": "active_probe", "reason": "timeout"})
    tls = _outcome(unclear, "transport_tls_enforcement")
    assert tls["outcome"] == "inconclusive"
    assert not [f for f in unclear.findings if f.category == "transport_tls_enforcement"]
    none_defined = _audit(_EngineConn(endpoint="pinecone://x"), tls_probe=True)
    assert _outcome(none_defined, "transport_tls_enforcement")["outcome"] == "unsupported"


def test_passive_catalog_wins_and_the_probe_is_not_sent():
    probed = []
    conn = _EngineConn(
        caps={"tls_enforcement_introspection"},
        tls_enforcement_info=lambda: {"plaintext_accepted": False, "method": "catalog",
                                      "reason": "hostssl only", "evidence": {}})
    job = _audit(conn, tls_probe=True, tls_prober=lambda *a, **k: probed.append(a))
    tls = _outcome(job, "transport_tls_enforcement")
    assert tls["outcome"] == "passed" and tls["coverage"]["method"] == "catalog"
    assert probed == []


def test_unreadable_catalog_without_probe_is_not_observable_never_failed():
    conn = _EngineConn(
        caps={"tls_enforcement_introspection"},
        tls_enforcement_info=lambda: {"plaintext_accepted": None, "method": "catalog",
                                      "readable": False, "reason": "permission denied"})
    job = _audit(conn)
    tls = _outcome(job, "transport_tls_enforcement")
    assert tls["outcome"] == "unsupported"
    assert tls["coverage"]["crypto_state"] == "not_observable"
    assert not [f for f in job.findings if f.category == "transport_tls_enforcement"]


def test_plaintext_connection_settles_enforcement_without_a_probe():
    job = _audit(_EngineConn(endpoint="http://q:6333"), tls_probe=True,
                 tls_prober=lambda *a, **k: pytest.fail("probe must not run"))
    tls = _outcome(job, "transport_tls_enforcement")
    assert tls["outcome"] == "failed" and tls["coverage"]["method"] == "connection"
    # The transport_encryption finding already reports it; no duplicate.
    assert not [f for f in job.findings if f.category == "transport_tls_enforcement"]


def test_transport_outcome_carries_session_details():
    conn = _EngineConn(
        endpoint="postgresql://h:5432/db", caps={"transport_introspection"},
        transport_session_info=lambda: {"tls": True, "version": "TLSv1.3",
                                        "cipher": "AES", "source": "pg_stat_ssl"})
    conn.kind = "pgvector"
    job = _audit(conn)
    te = _outcome(job, "transport_encryption")
    assert te["outcome"] == "passed"
    assert te["coverage"]["crypto_state"] == "verified"
    assert te["coverage"]["control"] == "VCR-01"
    details = te["coverage"]
    assert (details["source"], details["protocol"], details["cipher"],
            details["encrypted"], details["scheme"]) == \
        ("session", "TLSv1.3", "AES", True, "postgresql")
    assert not [f for f in job.findings if f.category == "transport_encryption"]


def test_session_errors_do_not_break_the_audit():
    def boom():
        raise RuntimeError("driver exploded")

    conn = _EngineConn(endpoint="postgresql://h:5432/db?sslmode=disable",
                       caps={"transport_introspection"}, transport_session_info=boom)
    te = _outcome(_audit(conn), "transport_encryption")
    assert te["outcome"] == "failed"
    assert te["coverage"]["session_error"] == "RuntimeError"


def test_config_sources_map_onto_the_contract_vocabulary():
    conn = _EngineConn(endpoint="h:27017",
                       metadata={"transport": mongo_transport_config("mongodb://h/?tls=true")})
    conn.kind = "mongodb"
    te = _outcome(_audit(conn), "transport_encryption")
    assert te["coverage"]["source"] == "connector_flag"
    assert te["coverage"]["config_source"] == "dsn"


# ---- capability honesty -----------------------------------------------------

@pytest.mark.parametrize("capability", ["transport_introspection",
                                        "tls_enforcement_introspection",
                                        "at_rest_introspection",
                                        "field_encryption_introspection"])
def test_capability_verdict_rejects_an_unbacked_crypto_capability(capability):
    from vecshield_platform.actions import CAPABILITY_METHODS, capability_verdict
    from vecshield_platform.connectors.base import Connector

    class Liar(Connector):
        kind = "liar"

        def capabilities(self):
            return {capability}

        def describe(self):  # pragma: no cover
            raise NotImplementedError

        def list_collections(self):  # pragma: no cover
            return []

        def iter_chunks(self, collection, batch_size=256):  # pragma: no cover
            return iter(())

    template = types.SimpleNamespace(capability=capability, title="Inspect")
    ok, reason = capability_verdict(Liar(), template)
    assert not ok and "inherits the unimplemented" in reason

    method = CAPABILITY_METHODS[capability]
    Honest = type("Honest", (Liar,), {method: lambda self, *a, **k: {}})
    assert capability_verdict(Honest(), template)[0] is True


def test_every_advertised_crypto_capability_is_implemented():
    from vecshield_platform.actions import CAPABILITY_METHODS
    from vecshield_platform.connectors.azure_search import AzureSearchConnector
    from vecshield_platform.connectors.base import Connector
    from vecshield_platform.connectors.bedrock_kb import BedrockKBConnector

    crypto = {"transport_introspection", "tls_enforcement_introspection",
              "at_rest_introspection", "field_encryption_introspection"}
    for cls in (PgVectorConnector, MongoDBConnector, RedisConnector,
                BedrockKBConnector, AzureSearchConnector):
        for cap in cls.capabilities(cls.__new__(cls)) & crypto:
            method = CAPABILITY_METHODS[cap]
            assert getattr(cls, method) is not getattr(Connector, method), (cls, cap)


@pytest.mark.parametrize("body", [
    b"<html>400 The plain HTTP request was sent to HTTPS port</html>",
    b"Client sent an HTTP request to an HTTPS server.\n",
    b"Reason: You're speaking plain HTTP to an SSL-enabled server port.",
])
def test_tls_listeners_rejecting_plaintext_in_their_own_words_are_refusals(body):
    from vecshield_platform.posture.tls_probe import probe_http_plaintext

    result = probe_http_plaintext("db.example", 6333,
                                  http_get=lambda h, p, t: (400, {}, body))
    assert result["plaintext_accepted"] is False


def test_an_ordinary_400_from_a_plaintext_server_is_still_accepted_plaintext():
    from vecshield_platform.posture.tls_probe import probe_http_plaintext

    result = probe_http_plaintext("db.example", 6333,
                                  http_get=lambda h, p, t: (400, {}, b"missing query"))
    assert result["plaintext_accepted"] is True


def test_a_postgres_refusal_for_the_test_user_is_not_verified_and_asks_for_evidence():
    from vecshield_platform.compliance.criteria import evaluate_criterion
    from vecshield_platform.compliance.packs import get_criterion
    from vecshield_platform.posture.tls_probe import probe_postgres_plaintext

    class _Sock:
        def __init__(self):
            self.sent = b""
            self.reply = _pg_error("28000", 'no pg_hba.conf entry for host "h", '
                                   'user "x", database "app", no encryption')

        def sendall(self, data):
            self.sent += data

        def recv(self, n):
            chunk, self.reply = self.reply[:n], self.reply[n:]
            return chunk

        def close(self):
            pass

    result = probe_postgres_plaintext("h", 5432, "app",
                                      open_socket=lambda h, p, t: _Sock())
    assert result["plaintext_accepted"] is None
    assert "refused for a test user" in result["reason"]
    assert "per-user rules could not be checked" in result["reason"]

    job = _audit(_EngineConn(), tls_probe=True,
                 tls_prober=lambda *a, **k: result)
    tls = _outcome(job, "transport_tls_enforcement")
    assert (tls["outcome"], tls["coverage"]["crypto_state"]) == (
        "inconclusive", "not_verified")
    assert not [f for f in job.findings if f.category == "transport_tls_enforcement"]
    e2ii = evaluate_criterion(
        get_criterion("HIPAA-164-312-E2II-ENCRYPTION-01"),
        check_outcomes=[tls],
        applicability_answers={"covered_entity_or_business_associate": "yes",
                               "system_handles_ephi": "yes"})
    assert e2ii.fallback_required == ["transport_security_statement"]


# ---- TLS without certificate verification -----------------------------------

@pytest.mark.parametrize("kind,endpoint,metadata,session,remedy", [
    ("opensearch", "https://os:9200",
     {"transport": {"tls": True, "source": "connector_flag", "verify_certs": False,
                    "certificate_verification": False}}, None, "verify_certs=True"),
    ("pgvector", "postgresql://h:5432/db?sslmode=require", {}, None, "verify-full"),
    ("pgvector", "postgresql://h:5432/db",
     {"transport": {"sslmode": "require", "source": "connector_flag"}}, None, "verify-full"),
    ("mongodb", "h:27017",
     {"transport": mongo_transport_config("mongodb://h/?tls=true&tlsInsecure=true")},
     None, "tlsInsecure"),
    ("redis", "rediss://cache:6380", {}, {"tls": True, "certificate_verification": False,
                                          "source": "connection_class"}, "ssl_cert_reqs"),
])
def test_tls_without_certificate_verification_is_a_medium_finding(
        kind, endpoint, metadata, session, remedy):
    store = VectorStore(kind=kind, name="s", endpoint=endpoint, metadata=metadata)
    [finding] = check_tls_certificate_verification(store, session=session)
    assert finding.severity is Severity.MEDIUM
    assert finding.category == "tls_certificate_verification"
    assert finding.title == ("Vector store 's' connection uses TLS without verifying the "
                             "server certificate")
    assert "interception" in finding.description or "intercept" in finding.description
    assert remedy in finding.remediation
    assert finding.evidence["certificate_verification"] is False
    # Encrypted: no transport_encryption finding alongside it.
    assert check_transport_encryption(store, session=session) == []


@pytest.mark.parametrize("endpoint,metadata,session", [
    ("postgresql://h:5432/db?sslmode=verify-full", {}, None),
    ("postgresql://h:5432/db?sslmode=verify-ca", {}, None),
    ("https://os:9200", {}, None),  # verification unknown: no finding
    ("postgresql://h:5432/db", {}, {"tls": True, "source": "pg_stat_ssl"}),
    # prefer does not verify, but it is not known to be encrypted either
    ("postgresql://h:5432/db?sslmode=prefer", {}, None),
    ("http://os:9200", {"transport": {"tls": False, "certificate_verification": False}},
     None),
])
def test_certificate_finding_needs_encryption_and_an_explicit_false(endpoint, metadata,
                                                                     session):
    store = VectorStore(kind="pgvector", name="s", endpoint=endpoint, metadata=metadata)
    assert check_tls_certificate_verification(store, session=session) == []


def test_prefer_with_a_tls_session_does_not_verify_the_certificate():
    store = VectorStore(kind="pgvector", name="s",
                        endpoint="postgresql://h:5432/db?sslmode=prefer")
    findings = check_tls_certificate_verification(
        store, session={"tls": True, "source": "pg_stat_ssl"})
    assert len(findings) == 1


def test_engine_keeps_transport_verified_and_adds_the_certificate_finding():
    conn = _EngineConn(endpoint="https://os:9200", metadata={"transport": {
        "tls": True, "source": "connector_flag", "certificate_verification": False}})
    conn.kind = "opensearch"
    job = _audit(conn)
    te = _outcome(job, "transport_encryption")
    assert te["outcome"] == "passed" and te["coverage"]["crypto_state"] == "verified"
    assert te["coverage"]["certificate_verification"] is False
    assert "server certificate is not verified" in te["reason"]
    cert = [f for f in job.findings if f.category == "tls_certificate_verification"]
    assert len(cert) == 1
    violations = {v.policy_id for v in evaluate_policies(posture_policies(), job.findings)}
    assert "verify-tls-certificates" in violations
    assert "encrypt-in-transit" not in violations


def test_certificate_and_transport_fingerprints_never_collide():
    store = VectorStore(kind="pgvector", name="s",
                        endpoint="postgresql://h:5432/db?sslmode=require")
    [cert] = check_tls_certificate_verification(store)
    [plain] = check_transport_encryption(VectorStore(
        kind="pgvector", name="s", endpoint="postgresql://h:5432/db?sslmode=disable"))
    assert fingerprint_finding(cert) != fingerprint_finding(plain)
    again = check_tls_certificate_verification(store)[0]
    assert fingerprint_finding(cert) == fingerprint_finding(again)


def test_require_tls_off_suppresses_the_certificate_finding():
    conn = _EngineConn(endpoint="postgresql://h:5432/db?sslmode=require")
    conn.kind = "pgvector"
    job = _audit(conn, require_tls=False)
    assert not [f for f in job.findings if f.category == "tls_certificate_verification"]


# ---- every transport reason is a sentence -----------------------------------

@pytest.mark.parametrize("endpoint,kind,metadata,session", [
    ("http://h:8000", "chroma", {}, None),
    ("https://h:9200", "opensearch", {}, None),
    ("file:///data", "chroma", {}, None),
    ("/data", "chroma", {}, None),
    ("pinecone://k", "pinecone", {}, None),
    ("postgresql://h/db?sslmode=disable", "pgvector", {}, None),
    ("postgresql://h/db?sslmode=allow", "pgvector", {}, None),
    ("postgresql://h/db?sslmode=require", "pgvector", {}, None),
    ("postgresql://h/db?sslmode=verify-full", "pgvector", {}, None),
    ("postgresql://h/db?sslmode=prefer", "pgvector", {}, None),
    ("postgresql://h/db", "pgvector", {}, None),
    ("postgresql://h/db", "pgvector", {"transport": {"sslmode": "require",
                                                     "source": "environment"}}, None),
    ("mongodb://h/?tls=true", "mongodb", {}, None),
    ("mongodb://h/?tls=false", "mongodb", {}, None),
    ("mongodb+srv://h/db", "mongodb", {}, None),
    ("mongodb://h/db", "mongodb", {}, None),
    ("h:27017", "mongodb", {"transport": mongo_transport_config("mongodb://h/?tls=true")},
     None),
    ("h:27017", "mongodb", {"transport": mongo_transport_config("mongodb://h/")}, None),
    ("http://os:9200", "opensearch", {"transport": {"tls": True,
                                                    "source": "connector_flag"}}, None),
    ("http://os:9200", "opensearch", {"use_ssl": True}, None),
    ("weird://h", "qdrant", {}, None),
    ("postgresql://h/db", "pgvector", {}, {"tls": True, "version": "TLSv1.3"}),
    ("postgresql://h/db", "pgvector", {}, {"tls": False, "source": "pg_stat_ssl"}),
])
def test_every_transport_reason_is_a_capitalised_sentence(endpoint, kind, metadata,
                                                          session):
    reason = transport_status(endpoint, kind=kind, metadata=metadata,
                              session=session)["reason"]
    assert reason[:1].isupper(), reason
    assert reason.endswith("."), reason
    assert ".." not in reason and ". ." not in reason, reason


def test_scheme_literals_stay_readable():
    assert transport_status("https://h")["reason"] == "The https:// scheme is TLS."
    assert transport_status("redis://h:6379", kind="redis")["reason"] == \
        "The redis:// scheme is plaintext (no TLS)."
    assert transport_status("postgresql://h/db", kind="pgvector", metadata={
        "transport": {"sslmode": "require", "source": "dsn"}})["reason"] == \
        "The connection uses sslmode=require (dsn)."


def test_finding_descriptions_do_not_double_the_full_stop():
    [finding] = check_transport_encryption(VectorStore(kind="chroma", name="c",
                                                       endpoint="http://h:8000"))
    assert finding.description.startswith("The http:// scheme is plaintext (no TLS). "
                                          "Embeddings")
