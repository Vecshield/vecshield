"""pgvector connector test against a live Postgres+pgvector.

Gated on a reachable DB at VECSHIELD_PG_DSN (defaults to the local docker
container used in development). Skipped if psycopg is missing or the DB is
unreachable, so the suite stays green without Docker.
"""

from __future__ import annotations

import os

import pytest

DSN = os.environ.get(
    "VECSHIELD_PG_DSN",
    "postgresql://postgres:secret@localhost:55432/postgres",
)


def _db_available() -> bool:
    try:
        import psycopg
    except ImportError:
        return False
    try:
        with psycopg.connect(DSN, connect_timeout=2) as c:
            c.execute("SELECT 1")
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _db_available(), reason="pgvector DB not reachable at VECSHIELD_PG_DSN"
)


@pytest.fixture
def seeded_db():
    import psycopg

    with psycopg.connect(DSN) as conn:
        with conn.cursor() as cur:
            cur.execute("CREATE EXTENSION IF NOT EXISTS vector")
            cur.execute("DROP TABLE IF EXISTS rag_docs")
            cur.execute(
                "CREATE TABLE rag_docs ("
                "  id bigserial PRIMARY KEY,"
                "  content text,"
                "  source text,"
                "  embedding vector(4)"
                ")"
            )
            sensitive = [
                "email john.doe@example.com about the invoice",
                "SSN 123-45-6789 on file",
                "card 4111 1111 1111 1111 charged",
                "leaked AKIAIOSFODNN7EXAMPLE in the repo",
            ]
            clean = ["the otter swims in the river"] * 16
            docs = clean + sensitive  # 20 rows, 4 sensitive (20%)
            for d in docs:
                cur.execute(
                    "INSERT INTO rag_docs (content, source, embedding) "
                    "VALUES (%s, %s, %s)",
                    (d, "doc.txt", "[0.1,0.2,0.3,0.4]"),
                )
        conn.commit()
    yield
    with psycopg.connect(DSN) as conn:
        conn.execute("DROP TABLE IF EXISTS rag_docs")
        conn.commit()


def test_lists_vector_table_with_dimension(seeded_db):
    from vecshield_platform.connectors.pgvector import PgVectorConnector

    with PgVectorConnector(dsn=DSN) as conn:
        store = conn.describe()
    cols = {c.name: c for c in store.collections}
    assert "rag_docs" in cols
    assert cols["rag_docs"].dimension == 4
    assert cols["rag_docs"].count == 20
    assert cols["rag_docs"].metadata["text_column"] == "content"


def test_iter_chunks_returns_text_and_vector(seeded_db):
    from vecshield_platform.connectors.pgvector import PgVectorConnector

    with PgVectorConnector(dsn=DSN) as conn:
        chunks = list(conn.iter_chunks("rag_docs"))
    assert len(chunks) == 20
    assert all(c.text is not None for c in chunks)
    assert all(c.embedding == [0.1, 0.2, 0.3, 0.4] for c in chunks)


def test_scan_flags_pgvector_secret(seeded_db):
    from vecshield.classify import RegexClassifier
    from vecshield_platform.connectors.pgvector import PgVectorConnector
    from vecshield.models import Severity
    from vecshield_platform.scan import scan_store

    with PgVectorConnector(dsn=DSN, tables=["rag_docs"]) as conn:
        job = scan_store(conn, classifier=RegexClassifier())

    # Assert on the rag_docs finding specifically so the test is robust to other
    # vector tables that may exist in the shared dev database.
    rag = next(f for f in job.findings if f.collection == "rag_docs")
    assert rag.evidence["sensitive"] == 4
    assert rag.severity == Severity.CRITICAL  # AWS key present
    assert rag.evidence["sensitivity"]["raw_text_stored"] is True


def test_dsn_credentials_redacted(seeded_db):
    from vecshield_platform.connectors.pgvector import PgVectorConnector

    with PgVectorConnector(dsn=DSN) as conn:
        store = conn.describe()
    assert "secret" not in store.name  # password must not leak into the store name


@pytest.fixture
def tenant_db():
    import psycopg

    with psycopg.connect(DSN) as conn:
        with conn.cursor() as cur:
            cur.execute("CREATE EXTENSION IF NOT EXISTS vector")
            cur.execute("DROP TABLE IF EXISTS tenant_docs")
            cur.execute(
                "CREATE TABLE tenant_docs ("
                "  id bigserial PRIMARY KEY,"
                "  content text,"
                "  tenant text,"
                "  embedding vector(4)"
                ")"
            )
            rows = [
                ("alpha notes", "t1", "[0.1,0.2,0.3,0.4]"),
                ("alpha memo", "t1", "[0.1,0.2,0.3,0.4]"),
                ("beta notes", "t2", "[0.1,0.2,0.3,0.4]"),
                ("beta memo", "t2", "[0.1,0.2,0.3,0.4]"),
            ]
            for content, tenant, emb in rows:
                cur.execute(
                    "INSERT INTO tenant_docs (content, tenant, embedding) "
                    "VALUES (%s, %s, %s)",
                    (content, tenant, emb),
                )
        conn.commit()
    yield
    with psycopg.connect(DSN) as conn:
        conn.execute("DROP TABLE IF EXISTS tenant_docs")
        conn.commit()


def test_query_honors_where_and_powers_isolation_probe(tenant_db):
    """pgvector now supports query() so the isolation prober runs end-to-end."""
    from vecshield.models import Severity
    from vecshield_platform.access import probe_isolation
    from vecshield_platform.connectors.pgvector import PgVectorConnector

    with PgVectorConnector(dsn=DSN, tables=["tenant_docs"]) as conn:
        assert "query" in conn.capabilities()
        # a bare query returns rows across tenants...
        hits = conn.query("tenant_docs", [0.1, 0.2, 0.3, 0.4], top_k=10)
        assert len(hits) == 4
        assert all(h.metadata.get("tenant") in {"t1", "t2"} for h in hits)
        # ...and a tenant-filtered query returns only that tenant.
        t1 = conn.query("tenant_docs", [0.1, 0.2, 0.3, 0.4], top_k=10,
                        where={"tenant": "t1"})
        assert {h.metadata["tenant"] for h in t1} == {"t1"}

        job = probe_isolation(conn, "tenant_docs", tenant_field="tenant")

    # Unfiltered queries bleed across tenants -> HIGH "convention-only" finding.
    # The SQL WHERE is honored, so there's no "filter NOT enforced" CRITICAL.
    assert any(f.severity == Severity.HIGH and f.category == "isolation"
               for f in job.findings)
    assert not any("NOT enforced" in f.title for f in job.findings)



def test_zero_vector_scores_are_not_nan(seeded_db):
    """A zero-norm vector must not produce a NaN score.

    pgvector's cosine distance divides by sqrt(norma * normb) and deliberately
    preserves NaN, so `1/(1+distance)` silently yields NaN for a zero vector on
    either side. A NaN score compares false against every threshold, so a
    caller that filters on score drops the hit while believing it scored it.
    """
    import math

    from vecshield_platform.connectors import build_connector

    conn = build_connector("pgvector", dsn=DSN)
    try:
        # Zero query vector: every distance is NaN.
        hits = conn.query("rag_docs", [0.0, 0.0, 0.0, 0.0], top_k=5)
        assert hits, "expected rows back even for a degenerate query vector"
        assert all(math.isfinite(h.score) for h in hits), \
            [h.score for h in hits]

        # Zero stored vector: only that row's distance is NaN.
        with psycopg_connect() as raw:
            raw.execute("INSERT INTO rag_docs (content, source, embedding) "
                        "VALUES ('zero vector row', 'test', '[0,0,0,0]')")
        hits = conn.query("rag_docs", [1.0, 0.0, 0.0, 0.0], top_k=25)
        assert all(math.isfinite(h.score) for h in hits), \
            [(h.id, h.score) for h in hits if not math.isfinite(h.score)]
    finally:
        conn.close()


def psycopg_connect():
    import psycopg

    return psycopg.connect(DSN, autocommit=True)


def test_query_uses_the_vector_index(seeded_db):
    """The aliased `ORDER BY _distance` must still reach the index.

    pgvector's own guidance is that the ORDER BY has to be the result of a
    distance operator rather than an expression. The connector wraps the
    operator in parentheses and aliases it, a shape the documentation does not
    cover, so this pins down that the planner still resolves it to the index
    rather than falling back to a sequential scan plus sort.
    """
    with psycopg_connect() as raw:
        raw.execute("CREATE INDEX IF NOT EXISTS rag_docs_hnsw ON rag_docs "
                    "USING hnsw (embedding vector_cosine_ops)")
        # The planner only prefers an index scan when a seq scan is not
        # trivially cheaper, which it is for a table of twenty rows. Session
        # scope, not SET LOCAL: the connection is autocommit, so there is no
        # surrounding transaction for LOCAL to apply to.
        raw.execute("SET enable_seqscan = off")
        plan = raw.execute(
            "EXPLAIN SELECT id, (embedding <=> %s::vector) AS _distance "
            "FROM rag_docs ORDER BY _distance LIMIT 3",
            ("[1,0,0,0]",)).fetchall()
    text = "\n".join(row[0] for row in plan)
    assert "rag_docs_hnsw" in text, text
