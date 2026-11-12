"""Unit tests for the pgvector connector's SQL logic (no live DB).

The full pgvector integration tests in ``test_pgvector.py`` are gated on a
reachable Postgres. These tests instead drive the connector through a fake
DB-API connection that routes SQL to canned rows by substring, so the
hand-written SQL (catalog detection, keyset paging, typed deletes, the
``<=>`` distance operator, ``where`` handling, metadata surfacing) is covered
even when Docker/psycopg aren't available.
"""
from __future__ import annotations

import json
import sys
import types

import pytest

from vecshield_platform.connectors.base import (
    ConnectorAuthError,
    UnsupportedCapability,
)
from vecshield_platform.connectors.pgvector import (
    PgVectorConnector,
    group_vector_columns,
)
from vecshield_platform.coverage import count_known


class InsufficientPrivilege(Exception):
    """Named like psycopg's SQLSTATE 42501 class; the registry maps by name."""


class AdminShutdown(Exception):
    """Named like psycopg's SQLSTATE 57P01 class (transient)."""


class _FakeCursor:
    def __init__(self, conn: "_FakeConn", name: str = "") -> None:
        self._conn = conn
        self.name = name
        self.rowcount = -1
        self._rows: list = []

    def __enter__(self) -> "_FakeCursor":
        return self

    def __exit__(self, *exc) -> bool:
        return False

    def execute(self, sql: str, params=None) -> None:
        self._conn.calls.append((sql, list(params) if params else [], self.name))
        result = self._conn._rows_for(sql)
        if isinstance(result, BaseException):
            raise result
        if isinstance(result, int):
            self.rowcount = result
            self._rows = []
        else:
            self._rows = list(result)

    def fetchall(self):
        return list(self._rows)

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchmany(self, size):
        out, self._rows = self._rows[:size], self._rows[size:]
        return out


class _Tx:
    def __init__(self, conn: "_FakeConn") -> None:
        self._conn = conn

    def __enter__(self):
        self._conn.tx.append("begin")
        return self

    def __exit__(self, exc_type, exc, tb):
        self._conn.tx.append("rollback" if exc_type else "commit")
        return False


class _FakeConn:
    """Minimal psycopg stand-in: routes SQL to canned rows by substring match.

    ``seq`` entries deplete one result per statement (a result may be an
    exception to raise); ``static`` entries always answer. A list result is
    rows, an int is a DELETE's rowcount.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, list, str]] = []
        self.static: list[tuple] = []
        self.seq: list[tuple] = []
        self.tx: list[str] = []

    def cursor(self, name: str = "") -> _FakeCursor:
        return _FakeCursor(self, name)

    def transaction(self) -> _Tx:
        return _Tx(self)

    def _rows_for(self, sql: str):
        for substr, results in self.seq:
            if substr in sql and results:
                return results.pop(0)
        for substr, rows in self.static:
            if substr in sql:
                return rows
        return []

    def close(self) -> None:
        pass


def _make_connector(conn: _FakeConn) -> PgVectorConnector:
    """Build a connector bound to a fake conn, bypassing psycopg.connect()."""
    c = PgVectorConnector.__new__(PgVectorConnector)
    c._conn = conn
    c._schema = "public"
    c._table_filter = None
    c._endpoint = "postgresql://fake/db"
    c._layout = {}
    c._meta_cols = {}
    return c


def _vec_row(table, column, typ="vector", dim=2, readable=True, bit_indexed=False,
             row_filtered=False):
    return (table, column, typ, dim, readable, bit_indexed, row_filtered)


def _docs_conn(vector_rows=None, keys=(("id", "bigint"),), text=(("content", "text"),),
               columns=(("id",), ("content",), ("tenant",), ("embedding",)), count=1):
    conn = _FakeConn()
    conn.static += [
        ("has_table_privilege", list(vector_rows or [_vec_row("docs", "embedding")])),
        ("data_type IN", list(text)),
        ("indisprimary", list(keys)),
        ("ORDER BY ordinal_position", list(columns)),
        ("COUNT(*)", [(count,)]),
    ]
    return conn


def _no_sleep(monkeypatch):
    import vecshield_platform.connectors.base as base
    monkeypatch.setattr(base.time, "sleep", lambda _s: None)


# --------------------------------------------------------------- basics -- #

def test_capabilities_include_query():
    assert PgVectorConnector.capabilities(PgVectorConnector.__new__(PgVectorConnector)) \
        == {"query", "delete", "transport_introspection",
            "tls_enforcement_introspection", "session_auth_introspection",
            "access_introspection", "at_rest_introspection", "ann_iterative_scan"}


def test_connects_in_autocommit_mode(monkeypatch):
    captured = {}
    fake = types.ModuleType("psycopg")
    fake.connect = lambda *a, **k: captured.update(args=a, kwargs=k) or object()
    monkeypatch.setitem(sys.modules, "psycopg", fake)
    PgVectorConnector("postgresql://u:pw@db/app")
    assert captured["kwargs"]["autocommit"] is True
    PgVectorConnector(host="db", dbname="app")
    assert captured["kwargs"]["autocommit"] is True


# ------------------------------------------------- session authentication -- #

def _auth_connector(conn, server_version=170002, used_password=False):
    c = _make_connector(conn)
    conn.info = types.SimpleNamespace(server_version=server_version)
    conn.pgconn = types.SimpleNamespace(used_password=used_password)
    return c


def test_session_auth_reads_system_user_method_not_identity():
    conn = _FakeConn()
    conn.static.append(("SELECT system_user", [("scram-sha-256:reporting_svc",)]))
    info = _auth_connector(conn).session_auth_info()
    assert info["observed"] is True and info["authenticated"] is True
    assert info["auth_method"] == "scram-sha-256" and info["source"] == "system_user"
    assert "reporting_svc" not in json.dumps(info)


def test_session_auth_null_system_user_is_trust():
    conn = _FakeConn()
    conn.static.append(("SELECT system_user", [(None,)]))
    info = _auth_connector(conn).session_auth_info()
    assert info["observed"] is True and info["authenticated"] is False
    assert "trust" in info["reason"]


@pytest.mark.parametrize("version,used_password,observed", [
    (150004, True, True), (150004, False, False), (None, False, False)])
def test_session_auth_before_16_relies_on_libpq(version, used_password, observed):
    conn = _FakeConn()
    info = _auth_connector(conn, server_version=version,
                           used_password=used_password).session_auth_info()
    assert info["observed"] is observed
    assert not any("system_user" in sql for sql, _p, _n in conn.calls)
    if observed:
        assert info["authenticated"] is True and info["auth_method"] == "password"
    else:
        assert info["authenticated"] is None and "PostgreSQL 16" in info["reason"]


def test_session_auth_unreadable_system_user_is_not_a_failure():
    conn = _FakeConn()
    conn.static.append(("SELECT system_user", InsufficientPrivilege("permission denied")))
    info = _auth_connector(conn).session_auth_info()
    assert info["observed"] is False and info["authenticated"] is None
    assert "permission denied" in info["reason"]


@pytest.mark.parametrize("dsn,password,env,expected", [
    ("host=db dbname=app user=app password=secret", None, {}, ["dsn_password"]),
    ("postgresql://app:secret@db/app", None, {}, ["dsn_password"]),
    ("postgresql://app@db/app?password=secret", None, {}, ["dsn_password"]),
    (None, "secret", {}, ["password_option"]),
    ("host=db dbname=app", None, {"PGPASSWORD": "x"}, ["environment_password"]),
    ("host=db passfile=/etc/pgpass", None, {}, ["password_file"]),
    ("host=db sslcert=/etc/client.crt", None, {}, ["client_certificate"]),
    ("host=db dbname=app user=app", None, {}, []),
    ("postgresql://app@db/app", None, {}, []),
])
def test_credential_sources_are_named_never_kept(monkeypatch, tmp_path, dsn, password, env,
                                                 expected):
    from vecshield_platform.connectors import pgvector as pgv
    for name in ("PGPASSWORD", "PGPASSFILE", "PGSSLCERT"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(pgv, "_default_passfile", lambda: tmp_path / "absent")
    config = pgv.pg_credential_config(dsn, password)
    assert config == {"sources": expected}
    assert "secret" not in json.dumps(config)


def test_describe_reports_credential_sources(monkeypatch, tmp_path):
    from vecshield_platform.connectors import pgvector as pgv
    for name in ("PGPASSWORD", "PGPASSFILE", "PGSSLCERT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(pgv, "_default_passfile", lambda: tmp_path / "absent")
    fake = types.ModuleType("psycopg")
    fake.connect = lambda *a, **k: _docs_conn()
    monkeypatch.setitem(sys.modules, "psycopg", fake)
    store = PgVectorConnector("host=db dbname=app user=app password=secret").describe()
    assert store.metadata["credential_configured"] is True
    assert store.metadata["credential_sources"] == ["dsn_password"]
    assert "secret" not in store.endpoint
    bare = PgVectorConnector("host=db dbname=app user=app").describe()
    assert "credential_configured" not in bare.metadata


def test_stores_in_different_schemas_of_one_database_do_not_share_findings(monkeypatch):
    """Two schemas, same table name: a risk accepted on one store leaves the other's open."""
    from vecshield.models import Finding, Severity
    from vecshield_platform.compliance.allowlist import Suppression, evaluate_suppressions
    from vecshield_platform.compliance.fingerprint import fingerprint_finding

    fake = types.ModuleType("psycopg")
    fake.connect = lambda *a, **k: _docs_conn()
    monkeypatch.setitem(sys.modules, "psycopg", fake)
    stores = {schema: PgVectorConnector(host="db", port=5432, dbname="app",
                                        schema=schema).describe()
              for schema in ("public", "clinical", "support")}

    # Probes read the endpoint, which is the same server for all three.
    assert {s.endpoint for s in stores.values()} == {"postgresql://db:5432/app"}
    # The default schema keeps the bare endpoint, so its fingerprints are unchanged.
    assert stores["public"].name == "postgresql://db:5432/app"
    assert stores["clinical"].name == "postgresql://db:5432/app schema=clinical"

    def finding(store):
        return Finding(id="f", store=store.name, collection="docs",
                       category="data_classification", severity=Severity.HIGH,
                       title="PHI detected in collection 'docs'")

    accepted = Suppression(fingerprint=fingerprint_finding(finding(stores["clinical"])),
                           reason="accepted for clinical only", owner="owner",
                           expires_at="2999-01-01T00:00:00+00:00")
    result = evaluate_suppressions([finding(s) for s in stores.values()],
                                   suppressions=[accepted])
    assert [f.store for f in result.suppressed] == [stores["clinical"].name]


def test_a_schema_scoped_dsn_store_is_named_without_its_password(monkeypatch):
    fake = types.ModuleType("psycopg")
    fake.connect = lambda *a, **k: _docs_conn()
    monkeypatch.setitem(sys.modules, "psycopg", fake)
    store = PgVectorConnector("postgresql://app:secret@db/app", schema="clinical").describe()
    assert store.name == f"{store.endpoint} schema=clinical"
    assert "secret" not in store.name


def test_query_builds_knn_sql_and_parses_hits():
    conn = _docs_conn()
    conn.static.append(("<=>", [(1, "hello", "t1", 0.0), (2, "world", "t2", 0.5)]))
    c = _make_connector(conn)

    hits = c.query("docs", [0.1, 0.2], top_k=5)

    assert [h.id for h in hits] == ["1", "2"]
    assert hits[0].text == "hello"
    assert hits[0].metadata == {"tenant": "t1"}
    # score = 1/(1+distance): distance 0 -> 1.0, distance 0.5 -> ~0.667
    assert hits[0].score == 1.0
    assert abs(hits[1].score - (1.0 / 1.5)) < 1e-9

    knn_sql, params, _ = next(call for call in conn.calls if "<=>" in call[0])
    assert "%s::vector" in knn_sql
    assert "ORDER BY _distance" in knn_sql
    assert knn_sql.strip().endswith("LIMIT %s")
    # param order: vector literal first, top_k last (no WHERE here)
    assert params[0] == "[0.1,0.2]"
    assert params[-1] == 5


def test_query_scores_are_never_nan():
    """A NaN distance must not become a NaN score.

    pgvector returns NaN from `<=>` when either vector has zero norm, and
    `1/(1+NaN)` is NaN. A NaN score compares false against every threshold, so
    a caller filtering on score silently drops the hit instead of seeing an
    unscored one.
    """
    import math

    conn = _docs_conn()
    conn.static.append(("<=>", [(1, "hello", "t1", float("nan")),
                                (2, "world", "t2", 0.5)]))
    c = _make_connector(conn)

    hits = c.query("docs", [0.0, 0.0], top_k=5)

    assert [h.id for h in hits] == ["1", "2"]
    assert not math.isnan(hits[0].score)
    assert hits[0].score == 0.0
    # The rows that do have a real distance are scored as before.
    assert abs(hits[1].score - (1.0 / 1.5)) < 1e-9


def test_query_where_filters_known_columns_only():
    conn = _docs_conn()
    conn.static.append(("<=>", [(1, "hello", "t1", 0.0)]))
    c = _make_connector(conn)

    c.query("docs", [0.1, 0.2], top_k=3, where={"tenant": "t1", "bogus": "x"})

    knn_sql, params, _ = next(call for call in conn.calls if "<=>" in call[0])
    assert '"tenant" = %s' in knn_sql
    assert "bogus" not in knn_sql            # unknown column ignored, not injected
    # params: [vector, tenant_value, top_k]
    assert params == ["[0.1,0.2]", "t1", 3]


def test_iter_chunks_surfaces_metadata_columns():
    conn = _docs_conn()
    conn.seq.append(("LIMIT %s", [[(1, "hello", "t1", "[0.1,0.2]")]]))
    c = _make_connector(conn)

    chunks = list(c.iter_chunks("docs"))

    assert len(chunks) == 1
    assert chunks[0].id == "1"
    assert chunks[0].text == "hello"
    assert chunks[0].metadata == {"tenant": "t1"}
    assert chunks[0].embedding == [0.1, 0.2]


# ------------------------------------------------- vector type detection -- #

def test_halfvec_sparsevec_and_bit_columns_are_detected_and_grouped():
    rows = [
        _vec_row("docs", "embedding", "vector", 3),
        _vec_row("docs", "emb_half", "halfvec", 3),
        _vec_row("docs", "sparse", "sparsevec", 30000),
        _vec_row("docs", "bits", "bit", 64),                      # co-located: kept
        _vec_row("flags_tbl", "flags", "bit", 8),                 # plain bit: not a vector
        _vec_row("binq", "code", "bit", 1024, bit_indexed=True),  # bit_hamming_ops index
        _vec_row("half_only", "e", "halfvec", 4),
    ]
    grouped = group_vector_columns(rows)
    assert set(grouped) == {"docs", "binq", "half_only"}
    assert [c["column"] for c in grouped["docs"]["columns"]] == [
        "embedding", "emb_half", "sparse", "bits"]

    conn = _docs_conn(rows, columns=[("id",), ("content",), ("embedding",),
                                     ("emb_half",), ("sparse",), ("bits",)])
    c = _make_connector(conn)
    cols = {col.name: col for col in c.list_collections()}
    # One collection per table, never one per vector column.
    assert sorted(cols) == ["binq", "docs", "half_only"]
    docs = cols["docs"].metadata
    assert docs["vector_column"] == "embedding" and docs["vector_type"] == "vector"
    assert docs["unread_vector_columns"] == ["emb_half", "sparse", "bits"]
    assert {v["column"]: (v["type"], v["dense"]) for v in docs["vector_columns"]} == {
        "embedding": ("vector", True), "emb_half": ("halfvec", True),
        "sparse": ("sparsevec", False), "bits": ("bit", False)}
    assert cols["half_only"].metadata["vector_type"] == "halfvec"
    assert cols["half_only"].dimension == 4
    assert cols["binq"].metadata["vector_type"] == "bit"
    assert "not dense" in cols["binq"].metadata["embedding_unavailable"]


def test_other_vector_columns_are_not_read_as_metadata():
    rows = [_vec_row("docs", "embedding", "vector", 2), _vec_row("docs", "emb_half", "halfvec", 2)]
    conn = _docs_conn(rows, columns=[("id",), ("content",), ("tenant",), ("embedding",),
                                     ("emb_half",)])
    conn.seq.append(("LIMIT %s", [[(1, "hello", "t1", "[0.5,0.25]")]]))
    c = _make_connector(conn)
    chunk = next(c.iter_chunks("docs"))
    assert chunk.metadata == {"tenant": "t1"}
    assert chunk.embedding == [0.5, 0.25]
    page_sql = next(s for s, _p, _n in conn.calls if "LIMIT %s" in s)
    assert '"emb_half"' not in page_sql


def test_halfvec_is_decoded_as_floats_and_queried_as_halfvec():
    conn = _docs_conn([_vec_row("docs", "embedding", "halfvec", 2)])
    conn.seq.append(("LIMIT %s", [[(1, "hello", "t1", "[0.5,1.5]")]]))
    conn.static.append(("<=>", [(1, "hello", "t1", 0.0)]))
    c = _make_connector(conn)
    assert next(c.iter_chunks("docs")).embedding == [0.5, 1.5]
    c.query("docs", [0.5, 1.5], top_k=1)
    knn_sql = next(s for s, _p, _n in conn.calls if "<=>" in s)
    assert "%s::halfvec" in knn_sql


def test_sparsevec_and_bit_are_never_decoded_as_dense():
    conn = _docs_conn([_vec_row("docs", "embedding", "sparsevec", 3)])
    conn.seq.append(("LIMIT %s", [[(1, "hello", "t1", "{1:0.5,3:2}/3")]]))
    c = _make_connector(conn)
    chunk = next(c.iter_chunks("docs"))
    assert chunk.embedding is None and chunk.text == "hello"
    with pytest.raises(UnsupportedCapability):
        c.query("docs", [0.1, 0.2, 0.3], top_k=1)


# -------------------------------------------------------------- paging -- #

def test_keyset_paging_over_a_composite_key():
    conn = _docs_conn(keys=[("tenant", "text"), ("doc_id", "bigint")],
                      columns=[("tenant",), ("doc_id",), ("content",), ("source",),
                               ("embedding",)])
    conn.seq.append(("LIMIT %s", [
        [("t1", 1, "a", "s", "[0.1,0.2]"), ("t1", 2, "b", "s", "[0.1,0.2]")],
        [("t2", 1, "c", "s", "[0.1,0.2]")],
    ]))
    c = _make_connector(conn)

    chunks = list(c.iter_chunks("docs", batch_size=2))

    assert [json.loads(ch.id) for ch in chunks] == [["t1", "1"], ["t1", "2"], ["t2", "1"]]
    assert chunks[0].metadata == {"tenant": "t1", "doc_id": 1, "source": "s"}
    pages = [(s, p) for s, p, _n in conn.calls if "LIMIT %s" in s]
    assert len(pages) == 2
    assert all("OFFSET" not in s for s, _p in pages)
    assert 'ORDER BY "tenant", "doc_id" LIMIT %s' in pages[0][0]
    assert 'WHERE ("tenant", "doc_id") > (%s, %s)' in pages[1][0]
    assert pages[1][1] == ["t1", 2, 2]


def test_single_key_keyset_continues_after_the_last_key():
    conn = _docs_conn()
    conn.seq.append(("LIMIT %s", [[(1, "a", "t", "[0,1]"), (5, "b", "t", "[0,1]")], []]))
    c = _make_connector(conn)
    assert [ch.id for ch in c.iter_chunks("docs", batch_size=2)] == ["1", "5"]
    second = [p for s, p, _n in conn.calls if "LIMIT %s" in s][1]
    assert second == [5, 2]


def test_table_without_a_primary_key_reads_through_a_server_side_cursor():
    conn = _docs_conn(keys=[])
    conn.static.append(("ORDER BY a.attnum LIMIT 1", [("id", "integer")]))
    conn.static.append(('SELECT "id", "content", "tenant", "embedding" FROM',
                        [(i, f"t{i}", "x", "[0,1]") for i in range(5)]))
    c = _make_connector(conn)
    chunks = list(c.iter_chunks("docs", batch_size=2))
    assert [ch.id for ch in chunks] == ["0", "1", "2", "3", "4"]
    reads = [(s, n) for s, _p, n in conn.calls if s.startswith('SELECT "id"')]
    assert len(reads) == 1 and reads[0][1].startswith("vecshield_")
    assert "LIMIT" not in reads[0][0] and "OFFSET" not in reads[0][0]
    assert conn.tx == ["begin", "commit"]
    assert c.list_collections()[0].metadata["id_source"] == "first_column"


def test_transient_page_errors_are_retried(monkeypatch):
    _no_sleep(monkeypatch)
    conn = _docs_conn()
    conn.seq.append(("LIMIT %s", [AdminShutdown("server restarting"),
                                  [(1, "a", "t", "[0,1]")]]))
    c = _make_connector(conn)
    assert [ch.id for ch in c.iter_chunks("docs")] == ["1"]
    assert c.read_errors() == []


def test_a_failed_page_is_recorded_and_raised(monkeypatch):
    _no_sleep(monkeypatch)
    conn = _docs_conn()
    conn.seq.append(("LIMIT %s", [InsufficientPrivilege("permission denied: pw=hunter2")]))
    c = _make_connector(conn)
    with pytest.raises(ConnectorAuthError):
        list(c.iter_chunks("docs"))
    [err] = c.read_errors()
    assert err["collection"] == "docs" and err["error_type"] == "ConnectorAuthError"
    assert "hunter2" not in json.dumps(err)


# ---------------------------------------------------- unreadable tables -- #

def test_tables_the_role_cannot_select_are_unreadable_coverage():
    rows = [_vec_row("docs", "embedding"), _vec_row("secret", "embedding", readable=False)]
    conn = _docs_conn(rows)
    c = _make_connector(conn)

    cols = {col.name: col for col in c.list_collections()}
    c.list_collections()  # listed again: still one read error

    secret = cols["secret"]
    assert secret.count == 0 and count_known(secret) is False
    assert secret.metadata["readable"] is False
    assert count_known(cols["docs"]) is True
    errors = c.read_errors()
    assert len(errors) == 1
    assert errors[0]["collection"] == "secret"
    assert errors[0]["error_type"] == "InsufficientPrivilege"

    assert list(c.iter_chunks("secret")) == []
    assert not any('"secret"' in s for s, _p, _n in conn.calls)
    with pytest.raises(ConnectorAuthError):
        c.query("secret", [0.1, 0.2])


def test_row_security_that_filters_the_role_is_partial_coverage():
    """A count that matches a policy-filtered read proves nothing about the table."""
    rows = [_vec_row("docs", "embedding", row_filtered=True), _vec_row("open", "embedding")]
    conn = _docs_conn(rows)
    conn.static.append(('"docs" ORDER BY "id" LIMIT', [(1, "visible row", "acme", "[0.1,0.2]")]))
    c = _make_connector(conn)

    cols = {col.name: col for col in c.list_collections()}
    c.list_collections()  # listed again: still one read error

    docs = cols["docs"].metadata
    assert docs["row_security_filtered"] is True and "row-level security" in docs[
        "row_security_reason"]
    assert "row_security_filtered" not in cols["open"].metadata
    [error] = c.read_errors()
    assert error["collection"] == "docs" and error["error_type"] == "RowSecurityFiltered"

    # Every pass resets read errors after listing; the read records it again
    # and still returns the rows the policies show.
    c.reset_read_errors()
    assert [ch.text for ch in c.iter_chunks("docs")] == ["visible row"]
    assert [e["error_type"] for e in c.read_errors()] == ["RowSecurityFiltered"]


def test_a_row_filtered_table_does_not_scan_as_a_pass():
    from vecshield_platform.scan.engine import scan_store

    c = _make_connector(_docs_conn([_vec_row("docs", "embedding", row_filtered=True)],
                                   count=0))
    c._transport = {"sslmode": None, "source": None}
    c._credentials = {"sources": []}

    job = scan_store(c)

    [outcome] = [o for o in job.stats["check_outcomes"]
                 if o["check"] == "data_classification"]
    assert outcome["outcome"] == "inconclusive"
    assert outcome["coverage"]["complete"] is False
    assert outcome["reason"].startswith("The connector reported content-read failures.")


def test_a_count_that_fails_is_unknown_not_zero(monkeypatch):
    _no_sleep(monkeypatch)
    conn = _docs_conn()
    conn.static.insert(0, ("COUNT(*)", InsufficientPrivilege("denied")))
    c = _make_connector(conn)
    [col] = c.list_collections()
    assert col.count == 0 and count_known(col) is False
    assert col.metadata["count_error"] == "ConnectorAuthError"


def test_a_configured_table_that_is_not_listed_is_a_store_wide_read_error():
    c = _make_connector(_docs_conn())
    c._table_filter = {"docs", "missing"}

    assert [col.name for col in c.list_collections()] == ["docs"]
    c.list_collections()  # listed again: still one read error

    [error] = c.read_errors()
    assert error["collection"] is None and error["table"] == "missing"
    assert error["error_type"] == "TableNotFound" and error["operation"] == "inventory"


def test_a_filter_that_matches_every_table_records_no_read_error():
    c = _make_connector(_docs_conn())
    c._table_filter = {"docs"}
    c.list_collections()
    assert c.read_errors() == []


def test_a_filter_that_matches_nothing_does_not_scan_as_a_pass():
    from vecshield_platform.scan.engine import scan_store

    c = _make_connector(_docs_conn())
    c._table_filter = {"documents"}  # e.g. a partitioned parent, listed as its partitions
    c._transport = {"sslmode": None, "source": None}
    c._credentials = {"sources": []}

    job = scan_store(c)

    assert job.stats["collections"] == 0
    [outcome] = [o for o in job.stats["check_outcomes"]
                 if o["check"] == "data_classification"]
    assert outcome["outcome"] == "inconclusive"
    assert outcome["coverage"]["complete"] is False
    assert any(f.category == "coverage" for f in job.findings)


# ------------------------------------------------------------- deletes -- #

def test_delete_casts_ids_to_a_bigint_key():
    conn = _docs_conn()
    conn.static.append(("DELETE FROM", 2))
    c = _make_connector(conn)
    assert c.delete_chunks("docs", ["1", "2"]) == 2
    sql, params, _ = next(call for call in conn.calls if "DELETE" in call[0])
    assert sql == 'DELETE FROM "public"."docs" WHERE "id" = ANY(%s::bigint[])'
    assert params == [["1", "2"]]
    assert conn.tx == ["begin", "commit"]


def test_delete_casts_ids_to_a_uuid_key():
    conn = _docs_conn(keys=[("id", "uuid")])
    conn.static.append(("DELETE FROM", 1))
    c = _make_connector(conn)
    uid = "5f1d7c3e-1b2a-4c3d-9e8f-0a1b2c3d4e5f"
    assert c.delete_chunks("docs", [uid]) == 1
    sql = next(s for s, _p, _n in conn.calls if "DELETE" in s)
    assert sql.endswith('"id" = ANY(%s::uuid[])')


def test_delete_rolls_back_and_maps_the_error():
    conn = _docs_conn()
    conn.static.append(("DELETE FROM", InsufficientPrivilege("permission denied")))
    c = _make_connector(conn)
    with pytest.raises(ConnectorAuthError):
        c.delete_chunks("docs", ["1"])
    assert conn.tx == ["begin", "rollback"]


def test_delete_without_transaction_support_rolls_back():
    class _Legacy(_FakeConn):
        transaction = None  # a DB-API connection without psycopg's block

        def __init__(self):
            super().__init__()
            self.done: list[str] = []

        def rollback(self):
            self.done.append("rollback")

        def commit(self):
            self.done.append("commit")

    conn = _Legacy()
    conn.static = _docs_conn().static + [("DELETE FROM", InsufficientPrivilege("no"))]
    c = _make_connector(conn)
    with pytest.raises(ConnectorAuthError):
        c.delete_chunks("docs", ["1"])
    assert conn.done == ["rollback"]


def test_delete_with_a_composite_key_matches_every_key_column():
    conn = _docs_conn(keys=[("tenant", "text"), ("doc_id", "bigint")])
    conn.static.append(("DELETE FROM", 2))
    c = _make_connector(conn)
    ids = [json.dumps(["t1", "1"]), json.dumps(["t2", "7"])]
    assert c.delete_chunks("docs", ids) == 2
    sql, params, _ = next(call for call in conn.calls if "DELETE" in call[0])
    assert ('WHERE ("tenant", "doc_id") IN ((%s::text, %s::bigint), '
            '(%s::text, %s::bigint))') in sql
    assert params == ["t1", "1", "t2", "7"]


def test_a_malformed_composite_id_refuses_the_whole_batch():
    conn = _docs_conn(keys=[("tenant", "text"), ("doc_id", "bigint")])
    c = _make_connector(conn)
    with pytest.raises(ValueError):
        c.delete_chunks("docs", [json.dumps(["t1", "1"]), "7"])
    assert not any("DELETE" in s for s, _p, _n in conn.calls)
    assert conn.tx == []


def test_an_unusual_key_type_falls_back_to_text_comparison():
    conn = _docs_conn(keys=[("id", 'public."odd;type"')])
    conn.static.append(("DELETE FROM", 1))
    c = _make_connector(conn)
    c.delete_chunks("docs", ["1"])
    sql = next(s for s, _p, _n in conn.calls if "DELETE" in s)
    assert sql.endswith('"id"::text = ANY(%s::text[])')
    assert "odd;type" not in sql


# ------------------------------------------------- error mapping (real) -- #

def test_real_psycopg_errors_map_onto_the_taxonomy():
    psycopg = pytest.importorskip("psycopg")
    from vecshield_platform.connectors.base import (
        ConnectorNotFound,
        ConnectorUnavailable,
        translate_error,
    )
    from vecshield_platform.connectors.pgvector import _ERRORS

    errors = psycopg.errors
    assert isinstance(translate_error(errors.InsufficientPrivilege("x"), kind="pgvector",
                                      extra=_ERRORS), ConnectorAuthError)
    assert isinstance(translate_error(errors.InvalidPassword("x"), kind="pgvector",
                                      extra=_ERRORS), ConnectorAuthError)
    assert isinstance(translate_error(errors.UndefinedTable("x"), kind="pgvector",
                                      extra=_ERRORS), ConnectorNotFound)
    assert isinstance(translate_error(errors.AdminShutdown("x"), kind="pgvector",
                                      extra=_ERRORS), ConnectorUnavailable)
    data_error = errors.InvalidTextRepresentation("bad uuid")
    assert translate_error(data_error, kind="pgvector", extra=_ERRORS) is data_error


# --------------------------------------------------------- store facts -- #

def test_store_facts_find_halfvec_sparsevec_and_indexed_bit_tables():
    from vecshield_platform.store_facts import pgvector as sf

    conn = _FakeConn()
    conn.static.append(("DISTINCT c.relname", [("docs",)]))
    sf.distance_metric_details(_make_connector(conn))
    sql = next(s for s, _p, _n in conn.calls if "DISTINCT c.relname" in s)
    assert "'halfvec'" in sql and "'sparsevec'" in sql
    assert "bit_hamming_ops" in sql


# --------------------------------------------------------------- access model -- #

_AUDITOR = ("vs_auditor", False, False, False, True, [], [])


def _access_conn(retrieval=None, tables=None, grants=None, schemas=None,
                 me=_AUDITOR, policies=None, ann=None, settings=None, role_settings=None):
    conn = _FakeConn()
    conn.static += [
        ("pg_db_role_setting", role_settings or []),
        ("am.amname IN", ann or []),
        ("current_setting('hnsw.iterative_scan'", settings or []),
        ("WHERE r.rolname = current_user", [me] if me is not None else []),
        ("WHERE r.rolname = %s", [retrieval] if retrieval is not None else []),
        ("c.relforcerowsecurity", tables if tables is not None
         else [("docs", "app_owner", True, False, False)]),
        ("LEFT JOIN pg_policy", policies if policies is not None else [("docs", 2)]),
        ("has_table_privilege(%s, c.oid, 'SELECT')", grants if grants is not None
         else [("docs", True, False, False, False, False)]),
        ("has_schema_privilege", schemas if schemas is not None
         else [("public", False, True, True)]),
        ("p.proleakproof", [(0,)]),
        ("p.prosecdef", []),
        ("a.atttypmod", [_vec_row("docs", "embedding"), _vec_row("other", "embedding")]),
    ]
    return conn


def test_access_model_reads_the_declared_retrieval_role():
    conn = _access_conn(retrieval=("rag_reader", False, True, False, True, [], []))
    c = _make_connector(conn)
    c._retrieval_role = "rag_reader"
    c._table_filter = {"docs"}
    model = c.access_model()
    assert model["observed_as"]["principal"] == "vs_auditor"
    principal = model["retrieval_principal"]
    assert principal["name"] == "rag_reader" and principal["assumed"] is False
    assert principal["bypassrls"] is True and principal["exists"] is True
    assert model["tables"] == [{"table": "docs", "owner": "app_owner", "rls": True,
                                "force_rls": False, "public_select": False, "policies": 2,
                                "retrieval_privileges": ["SELECT"]}]
    assert model["schemas"] == [{"schema": "public", "public_create": False,
                                 "uses": ["vector_extension", "search_path"]}]
    assert model["inventory_complete"] is True
    # The role name travels as a bound parameter, and the table filter holds.
    grants = next((s, p) for s, p, _n in conn.calls if "c.oid, 'INSERT'" in s)
    assert grants[1][:5] == ["rag_reader"] * 5 and grants[1][-1] == ["docs"]


def test_access_model_assumes_the_connecting_role_when_none_is_declared():
    model = _make_connector(_access_conn()).access_model()
    assert model["retrieval_principal"]["name"] == "vs_auditor"
    assert model["retrieval_principal"]["assumed"] is True


def test_access_model_names_a_declared_role_that_does_not_exist():
    c = _make_connector(_access_conn(retrieval=None))
    c._retrieval_role = "typo_role"
    model = c.access_model()
    assert model["retrieval_principal"] == {"name": "typo_role", "assumed": False,
                                            "exists": False}
    assert "typo_role" in model["reasons"]["retrieval_principal"]
    assert model["inventory_complete"] is False


def test_access_model_unreadable_sections_are_reported_not_empty():
    conn = _access_conn()
    conn.static.insert(0, ("LEFT JOIN pg_policy", InsufficientPrivilege("permission denied")))
    model = _make_connector(conn).access_model()
    assert model["sections_readable"]["policies"] is False
    assert "permission denied" in model["reasons"]["policies"]
    assert model["tables"][0]["policies"] is None
    assert model["inventory_complete"] is False


def test_access_model_without_pg_roles_stops_at_roles():
    conn = _access_conn()
    conn.static.insert(0, ("WHERE r.rolname = current_user",
                           InsufficientPrivilege("permission denied")))
    model = _make_connector(conn).access_model()
    assert model["sections_readable"] == {"roles": False}
    assert model["tables"] == [] and model["retrieval_principal"] is None


def test_weak_hba_rules_list_non_local_trust_md5_and_password():
    from vecshield_platform.connectors.pgvector import hba_plaintext_verdict, hba_weak_auth_rules
    rows = [
        (1, "local", "{all}", "{all}", None, None, "trust", None),
        (2, "host", "{all}", "{all}", "127.0.0.1", "255.255.255.255", "trust", None),
        (3, "host", "{all}", "{all}", "10.0.0.0", "255.0.0.0", "md5", None),
        (4, "hostssl", "{all}", "{all}", "0.0.0.0", "0.0.0.0", "trust", None),
        (5, "host", "{all}", "{all}", "all", None, "password", None),
        (6, "host", "{all}", "{all}", "all", None, "scram-sha-256", None),
        (7, "host", "{all}", "{all}", "all", None, "trust", "syntax error"),
    ]
    assert hba_weak_auth_rules(rows) == [
        {"line": 3, "type": "host", "auth_method": "md5"},
        {"line": 4, "type": "hostssl", "auth_method": "trust"},
        {"line": 5, "type": "host", "auth_method": "password"}]
    verdict = hba_plaintext_verdict(rows[:6])
    assert len(verdict["evidence"]["weak_auth_rules"]) == 3


def test_access_model_with_an_unreadable_inventory_is_not_an_empty_one():
    conn = _access_conn()
    conn.static.insert(0, ("a.atttypmod", InsufficientPrivilege("permission denied")))
    model = _make_connector(conn).access_model()
    assert model["sections_readable"]["tables"] is False
    assert "ConnectorAuthError" in model["reasons"]["tables"]
    assert model["inventory_complete"] is False


# ------------------------------------------------- approximate-index search -- #

def _ann_conn(opclass="vector_cosine_ops", method="hnsw", version="0.8.7"):
    conn = _docs_conn()
    conn.static[:0] = [
        ("am.amname IN", [("docs_embedding_idx", method, opclass, False)]),
        ("LEFT JOIN pg_available_extensions", [(version, version)]),
    ]
    return conn


@pytest.mark.parametrize("opclass,operator", [
    ("vector_cosine_ops", "<=>"), ("vector_l2_ops", "<->"), ("halfvec_l2_ops", "<->"),
    ("vector_ip_ops", "<#>"), ("vector_l1_ops", "<+>")])
def test_query_uses_the_operator_the_column_is_indexed_for(opclass, operator):
    conn = _ann_conn(opclass)
    conn.static.append((operator, [(1, "hello", "t1", 0.25)]))
    hits = _make_connector(conn).query("docs", [0.1, 0.2], top_k=3)
    sql = next(s for s, _p, _n in conn.calls if "_distance" in s)
    assert f" {operator} %s::vector" in sql
    assert [h.id for h in hits] == ["1"]


def test_inner_product_scores_are_the_product_not_one_over_distance():
    conn = _ann_conn("vector_ip_ops")
    conn.static.append(("<#>", [(1, "a", "t1", -0.9), (2, "b", "t2", -0.2)]))
    hits = _make_connector(conn).query("docs", [0.1, 0.2])
    assert [h.score for h in hits] == [0.9, 0.2]


def test_query_iterative_sets_the_scan_mode_for_one_read_only_transaction():
    conn = _ann_conn()
    conn.static.append(("<=>", [(1, "hello", "t1", 0.0)]))
    hits = _make_connector(conn).query_iterative("docs", [0.1, 0.2], top_k=4,
                                                 where={"tenant": "t1"})
    assert [h.id for h in hits] == ["1"]
    statements = [s for s, _p, _n in conn.calls]
    start = statements.index("SET TRANSACTION READ ONLY")
    assert statements[start + 1] == "SET LOCAL hnsw.iterative_scan = strict_order"
    assert "_distance" in statements[start + 2]
    assert conn.tx == ["begin", "commit"]


def test_ivfflat_iterates_in_relaxed_order_its_only_mode():
    conn = _ann_conn(method="ivfflat")
    conn.static.append(("<=>", []))
    _make_connector(conn).query_iterative("docs", [0.1, 0.2])
    assert "SET LOCAL ivfflat.iterative_scan = relaxed_order" in [s for s, _p, _n
                                                                   in conn.calls]


@pytest.mark.parametrize("method,version", [(None, "0.8.7"), ("hnsw", "0.7.4")])
def test_query_iterative_is_unsupported_without_an_index_or_before_0_8(method, version):
    conn = _docs_conn() if method is None else _ann_conn(version=version)
    if method is None:
        conn.static.insert(0, ("LEFT JOIN pg_available_extensions", [(version, version)]))
    with pytest.raises(UnsupportedCapability):
        _make_connector(conn).query_iterative("docs", [0.1, 0.2])
    assert not any("SET LOCAL" in s for s, _p, _n in conn.calls)


def test_ann_index_info_prefers_the_retrieval_roles_own_setting():
    conn = _ann_conn()
    conn.static[:0] = [
        ("current_setting('hnsw.iterative_scan'",
         [("off", "40", "20000", "off", "1", "32768")]),
        ("pg_db_role_setting", [("hnsw.iterative_scan=relaxed_order",),
                                ("search_path=app",)]),
    ]
    c = _make_connector(conn)
    assert c.ann_index_info("docs")["iterative_scan"] == "off"  # no role declared
    c._retrieval_role = "rag_reader"
    info = c.ann_index_info("docs")
    assert info["index_type"] == "hnsw" and info["metric"] == "cosine"
    assert info["settings"]["hnsw.ef_search"] == "40"
    assert info["retrieval_role_settings"] == {"hnsw.iterative_scan": "relaxed_order"}
    assert info["iterative_scan"] == "relaxed_order"
    assert info["iterative_scan_supported"] is True


def test_access_model_records_each_tables_approximate_index():
    conn = _access_conn(ann=[("docs_hnsw", "hnsw", "vector_cosine_ops", False)],
                        settings=[("off", "40", "20000", "off", "1", "32768")])
    c = _make_connector(conn)
    c._table_filter = {"docs"}
    docs = c.access_model()["tables"][0]
    assert docs["ann_index"] == {"index": "docs_hnsw", "index_type": "hnsw",
                                 "metric": "cosine"}
    assert docs["iterative_scan"] == "off"
