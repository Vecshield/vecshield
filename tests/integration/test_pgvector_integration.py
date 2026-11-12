"""Example container-backed integration test: pgvector via a real Postgres.

This is the reference pattern for the integration suite (improvement plan 1.10):
spin up a throwaway container, point the real connector at it, and assert the
connector introspects it correctly — no SDK monkeypatching.

Guarded so it skips (never errors) without Docker or the optional deps.
"""

from __future__ import annotations

import pytest

pytest.importorskip("testcontainers")
pytest.importorskip("psycopg")

from testcontainers.postgres import PostgresContainer  # noqa: E402

from vecshield_platform.connectors.pgvector import PgVectorConnector  # noqa: E402

pytestmark = pytest.mark.integration

# The official pgvector image ships the `vector` extension preinstalled.
_PGVECTOR_IMAGE = "pgvector/pgvector:pg16"
#: The two tenants of ``typed.docs``.
TENANT_A = "0f8fad5b-d9cb-469f-a165-70867728950e"
TENANT_B = "7c9e6679-7425-40de-944b-e07fc1f90ae7"


@pytest.fixture
def pg_dsn(docker_available):
    with PostgresContainer(_PGVECTOR_IMAGE) as pg:
        dsn = (
            f"host={pg.get_container_host_ip()} "
            f"port={pg.get_exposed_port(5432)} "
            f"dbname={pg.dbname} user={pg.username} password={pg.password}"
        )
        _seed(dsn)
        yield dsn


def _seed(dsn: str) -> None:
    import psycopg

    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("CREATE EXTENSION IF NOT EXISTS vector")
        cur.execute(
            "CREATE TABLE docs ("
            "  id text PRIMARY KEY,"
            "  content text,"
            "  embedding vector(3),"
            "  tenant_id text"
            ")"
        )
        cur.execute(
            "INSERT INTO docs (id, content, embedding, tenant_id) VALUES "
            "('a', 'hello world', '[0.1,0.2,0.3]', 't1'),"
            "('b', 'benign note', '[0.4,0.5,0.6]', 't2')"
        )
        # A login role with no grants: what a least-privileged auditor sees.
        cur.execute("CREATE ROLE vs_auditor LOGIN PASSWORD 'auditor-pw'")
        # Row security on the vector table, and a retrieval role that only
        # reads it, beside one that can also write it.
        cur.execute("ALTER TABLE docs ENABLE ROW LEVEL SECURITY")
        cur.execute("CREATE POLICY tenant ON docs USING "
                    "(tenant_id = current_setting('app.tenant', true))")
        cur.execute("CREATE ROLE rag_reader LOGIN PASSWORD 'reader-pw'")
        cur.execute("GRANT SELECT ON docs TO rag_reader")
        cur.execute("CREATE ROLE rag_writer LOGIN PASSWORD 'writer-pw'")
        cur.execute("GRANT SELECT, INSERT ON docs TO rag_writer")
        # A shared table on an HNSW (L2) index: one large tenant and one small
        # one, so the small tenant's filtered search competes for the scan.
        cur.execute("CREATE TABLE ann_docs (id int PRIMARY KEY, content text, "
                    "embedding vector(3), tenant_id text)")
        cur.execute("INSERT INTO ann_docs SELECT g, 'big ' || g, "
                    "ARRAY[random(), random(), random()]::vector(3), 'big' "
                    "FROM generate_series(1, 400) g")
        cur.execute("INSERT INTO ann_docs SELECT g, 'small ' || g, "
                    "ARRAY[random(), random(), random()]::vector(3), 'small' "
                    "FROM generate_series(401, 410) g")
        cur.execute("CREATE INDEX ann_docs_hnsw ON ann_docs "
                    "USING hnsw (embedding vector_l2_ops)")
        # Real column types, in their own schema so the access-model tests
        # above see only `public`: a uuid key and tenant, and a date. psycopg
        # returns these as UUID and date objects, not the text seeded above.
        cur.execute("CREATE SCHEMA typed")
        cur.execute("CREATE TABLE typed.docs (id uuid PRIMARY KEY "
                    "DEFAULT gen_random_uuid(), content text, embedding vector(3), "
                    "tenant_id uuid, ingested_on date)")
        cur.execute("INSERT INTO typed.docs (content, embedding, tenant_id, ingested_on) "
                    "SELECT 'note ' || g, ARRAY[random(), random(), random()]::vector(3), "
                    "CASE WHEN g %% 2 = 0 THEN %s::uuid ELSE %s::uuid END, "
                    "DATE '2026-01-01' + g FROM generate_series(1, 12) g",
                    (TENANT_A, TENANT_B))
        conn.commit()


def _as_auditor(dsn: str) -> str:
    parts = dict(p.split("=", 1) for p in dsn.split())
    parts.update(user="vs_auditor", password="auditor-pw")
    return " ".join(f"{k}={v}" for k, v in parts.items())


def test_keyword_dsn_posture_observes_host_and_server_authentication(pg_dsn):
    """A keyword DSN used to leave exposure unknown and authentication unverified."""
    from vecshield_platform.posture import run_posture_audit

    conn = PgVectorConnector(dsn=pg_dsn)
    try:
        session = conn.session_auth_info()
        assert session["observed"] is True
        assert session["auth_method"] == "scram-sha-256"
        job = run_posture_audit(conn, resolve_dns=False, include_cve=False)
        outcomes = {o["check"]: o for o in job.stats["check_outcomes"]}
        assert outcomes["network_exposure"]["outcome"] != "inconclusive"
        assert outcomes["authentication"]["outcome"] == "passed"
        assert outcomes["authentication"]["coverage"]["auth_method"] == "scram-sha-256"
    finally:
        conn.close()


def test_server_info_reports_the_installed_pgvector_package(pg_dsn):
    from vecshield_platform import store_facts

    conn = PgVectorConnector(dsn=pg_dsn)
    try:
        features = store_facts.server_info(conn)["features"]
        assert features["pgvector_package"] == features["pgvector"]
    finally:
        conn.close()


def test_a_role_without_grants_gets_unknowns_never_failures(pg_dsn):
    from vecshield_platform import store_facts

    conn = PgVectorConnector(dsn=_as_auditor(pg_dsn))
    try:
        assert conn.session_auth_info()["auth_method"] == "scram-sha-256"
        info = store_facts.server_info(conn)
        assert info["version"] and info["features"].get("pgvector_package")
        hba = conn.tls_enforcement_info()
        assert hba["readable"] is False and hba["plaintext_accepted"] is None
        docs = {c.name: c for c in conn.describe().collections}["docs"]
        assert docs.metadata.get("readable") is False
    finally:
        conn.close()


def test_access_model_judges_the_declared_retrieval_role_as_a_plain_auditor(pg_dsn):
    """Every access read works for a role with no grants; the reader is verified."""
    from vecshield_platform.access.grants import assess_access_grants

    conn = PgVectorConnector(dsn=_as_auditor(pg_dsn), retrieval_role="rag_reader")
    try:
        model = conn.access_model()
        assert model["observed_as"] == {"principal": "vs_auditor", "superuser": False,
                                        "bypassrls": False, "createrole": False}
        docs = {t["table"]: t for t in model["tables"]}["docs"]
        assert docs["rls"] is True and docs["force_rls"] is False
        assert docs["policies"] == 1 and docs["public_select"] is False
        assert docs["retrieval_privileges"] == ["SELECT"]
        assert model["inventory_complete"] is True, model["reasons"]
        findings, outcome = assess_access_grants(model, conn.describe())
        assert findings == []
        assert outcome["outcome"] == "passed"
        assert outcome["coverage"]["access_state"] == "verified"
    finally:
        conn.close()


def test_a_retrieval_role_that_can_write_fails_access_grants(pg_dsn):
    from vecshield_platform.access.grants import assess_access_grants

    conn = PgVectorConnector(dsn=_as_auditor(pg_dsn), retrieval_role="rag_writer")
    try:
        findings, outcome = assess_access_grants(conn.access_model(), conn.describe())
        assert [f.evidence["rule"] for f in findings] == ["retrieval_can_write"]
        assert outcome["outcome"] == "failed"
    finally:
        conn.close()


def test_auditing_as_the_superuser_is_reported_and_hardening_reads_the_server(pg_dsn):
    """The image's own user is a superuser; its listener is '*' with ssl off."""
    from vecshield_platform.posture import run_posture_audit

    conn = PgVectorConnector(dsn=pg_dsn)
    try:
        job = run_posture_audit(conn, resolve_dns=False, include_cve=False,
                                store_controls=True)
        outcomes = {o["check"]: o for o in job.stats["check_outcomes"]}
        rules = {f.evidence.get("rule") for f in job.findings}
        assert "privileged_auditor" in rules
        assert outcomes["access_grants"]["coverage"]["principal_assumed"] is True
        assert "ssl_off_remote_listener" in rules
        assert outcomes["server_hardening"]["outcome"] == "failed"
    finally:
        conn.close()


def test_a_role_without_grants_leaves_the_hba_rules_unevaluated(pg_dsn):
    from vecshield_platform.posture import run_posture_audit

    conn = PgVectorConnector(dsn=_as_auditor(pg_dsn))
    try:
        job = run_posture_audit(conn, resolve_dns=False, include_cve=False,
                                store_controls=True)
        outcomes = {o["check"]: o for o in job.stats["check_outcomes"]}
        hardening = outcomes["server_hardening"]
        not_evaluated = {r["rule"] for r in hardening["coverage"]["rules_not_evaluated"]}
        assert {"hba_trust_remote", "hba_md5_remote"} <= not_evaluated
        # Never "passed" with rules unread: failed if a readable rule fired
        # (ssl is off in the image), otherwise inconclusive.
        assert hardening["outcome"] in ("failed", "inconclusive")
        assert hardening["coverage"]["complete"] is False
        # No retrieval role declared and an unprivileged auditor: not verified.
        assert outcomes["access_grants"]["outcome"] == "inconclusive"
        assert outcomes["access_grants"]["coverage"]["access_state"] == "not_verified"
    finally:
        conn.close()


def test_an_hnsw_index_sets_the_operator_and_iterative_scans_run_read_only(pg_dsn):
    conn = PgVectorConnector(dsn=pg_dsn)
    try:
        where = {"tenant_id": "small"}
        plain = conn.query("ann_docs", [0.5, 0.5, 0.5], top_k=50, where=where)
        iterative = conn.query_iterative("ann_docs", [0.5, 0.5, 0.5], top_k=50,
                                         where=where)
        # Whatever plan the server picks, the iterative scan never returns
        # less, and with ten small-tenant rows it returns all of them.
        assert len(iterative) == 10 and len(plain) <= 10
        info = conn.ann_index_info("ann_docs")
        assert info["index_type"] == "hnsw" and info["operator"] == "<->"
        assert info["metric"] == "l2" and info["iterative_scan_supported"] is True
        # SET LOCAL ended with its transaction.
        assert info["settings"]["hnsw.iterative_scan"] == "off"
        assert info["iterative_scan"] == "off"
    finally:
        conn.close()


def test_the_isolation_probe_reports_the_approximate_index(pg_dsn):
    from vecshield_platform.access import probe_isolation

    conn = PgVectorConnector(dsn=pg_dsn, tables=["ann_docs"])
    try:
        job = probe_isolation(conn, "ann_docs", tenant_field="tenant_id")
        cov = job.stats["check_outcomes"][0]["coverage"]
        assert cov["ann_index"]["index_type"] == "hnsw"
        assert cov["filter_enforcement"] in ("verified", "partially_verified")
        [low] = [f for f in job.findings if "approximate index" in f.title]
        assert low.evidence["leaks_data"] is False
    finally:
        conn.close()


def test_pgvector_connector_introspects_real_store(pg_dsn):
    conn = PgVectorConnector(dsn=pg_dsn)
    try:
        store = conn.describe()
        collections = {c.name: c for c in store.collections}
        assert "docs" in collections
        docs = collections["docs"]
        assert docs.count == 2
        assert docs.dimension == 3

        chunks = list(conn.iter_chunks("docs"))
        assert {c.id for c in chunks} == {"a", "b"}
        assert any("hello world" in (c.text or "") for c in chunks)
    finally:
        conn.close()


def test_isolation_runs_on_a_uuid_tenant_column(pg_dsn):
    """A string canary against a uuid column was a query error, which ended
    the check in error, and UUID tenants were never queried."""
    from vecshield_platform.access import probe_isolation

    conn = PgVectorConnector(dsn=pg_dsn, schema="typed")
    try:
        job = probe_isolation(conn, "docs", tenant_field="tenant_id")
        [outcome] = job.stats["check_outcomes"]
        assert outcome["outcome"] != "error", outcome["reason"]
        assert outcome["coverage"]["canary"] == "passed"
        assert outcome["coverage"]["filter_enforcement"] == "verified"
    finally:
        conn.close()


def test_a_date_column_is_the_retention_horizon(pg_dsn):
    from vecshield_platform.scan.engine import scan_store

    conn = PgVectorConnector(dsn=pg_dsn, schema="typed")
    try:
        job = scan_store(conn)
        [retention] = [o for o in job.stats["check_outcomes"]
                       if o["check"] == "retention_horizon"]
        assert retention["outcome"] == "passed"
        assert "ingested_on" in retention["reason"]
    finally:
        conn.close()


def test_a_configured_table_that_is_not_there_is_not_a_pass(pg_dsn):
    from vecshield_platform.scan.engine import scan_store

    conn = PgVectorConnector(dsn=pg_dsn, tables=["no_such_table"])
    try:
        job = scan_store(conn)
        [classification] = [o for o in job.stats["check_outcomes"]
                            if o["check"] == "data_classification"]
        assert classification["outcome"] == "inconclusive"
        assert [e["error_type"] for e in conn.read_errors()] == ["TableNotFound"]
    finally:
        conn.close()


def _as(dsn: str, user: str, password: str) -> str:
    parts = dict(p.split("=", 1) for p in dsn.split())
    parts.update(user=user, password=password)
    return " ".join(f"{k}={v}" for k, v in parts.items())


def test_row_security_that_filters_the_scanning_role_is_not_a_pass(pg_dsn):
    """`docs` has row security and rag_reader does not own it, so its policy
    hides every row from rag_reader. Zero rows read is not an empty table:
    the count matched what was read, and both checks used to pass, complete."""
    from vecshield_platform.access import probe_isolation
    from vecshield_platform.scan.engine import scan_store

    conn = PgVectorConnector(dsn=_as(pg_dsn, "rag_reader", "reader-pw"), tables=["docs"])
    try:
        iso = probe_isolation(conn, "docs", tenant_field="tenant_id")
        [outcome] = iso.stats["check_outcomes"]
        assert outcome["outcome"] == "inconclusive", outcome["reason"]
        assert outcome["coverage"]["complete"] is False

        job = scan_store(conn)
        [classification] = [o for o in job.stats["check_outcomes"]
                            if o["check"] == "data_classification"]
        assert classification["outcome"] == "inconclusive"
        assert classification["coverage"]["complete"] is False
        assert "content-read failures" in classification["reason"]
        [error] = conn.read_errors()
        assert error["collection"] == "docs"
        assert error["error_type"] == "RowSecurityFiltered"
    finally:
        conn.close()

    # The owner is not subject to its own table's policies (no FORCE), so
    # it reads every row and nothing is reported.
    owner = PgVectorConnector(dsn=pg_dsn, tables=["docs"])
    try:
        scan_store(owner)
        assert owner.read_errors() == []
    finally:
        owner.close()


def test_the_cli_does_not_pass_a_scan_that_row_security_cut_short(pg_dsn, monkeypatch):
    """The CLI used to print "No findings" and exit 0 for this read."""
    from click.testing import CliRunner

    from vecshield_platform import cli as cli_module
    from vecshield_platform.cli import cli

    monkeypatch.setattr(cli_module.console, "width", 400)

    def scan(dsn):
        return CliRunner().invoke(cli, ["scan", "--connector", "pgvector", "--dsn", dsn,
                                        "--tables", "docs", "--no-nlp"])

    result = scan(_as(pg_dsn, "rag_reader", "reader-pw"))
    assert result.exit_code == 3, result.output
    assert "read shortfall" in result.output
    assert "No findings." not in result.output
    assert scan(pg_dsn).exit_code != 3
