"""Milvus connector tests via Milvus Lite (local file, no Docker)."""

from __future__ import annotations

import pytest

pytest.importorskip("pymilvus")
pytest.importorskip("milvus_lite")


@pytest.fixture
def lite_db(tmp_path):
    from pymilvus import DataType, MilvusClient

    db = str(tmp_path / "milvus.db")
    try:
        c = MilvusClient(uri=db)
    except Exception as e:  # pragma: no cover - local gRPC can be blocked
        pytest.skip(f"Milvus Lite could not start: {e}")
    schema = MilvusClient.create_schema(auto_id=False, enable_dynamic_field=True)
    schema.add_field("id", DataType.INT64, is_primary=True)
    schema.add_field("vector", DataType.FLOAT_VECTOR, dim=4)
    schema.add_field("content", DataType.VARCHAR, max_length=512)
    schema.add_field("tenant_id", DataType.VARCHAR, max_length=64)
    ip = c.prepare_index_params()
    ip.add_index(field_name="vector", index_type="FLAT", metric_type="L2")
    c.create_collection("kb", schema=schema, index_params=ip)
    rows = [{"id": i, "vector": [0.1 * i, 0.2, 0.3, 0.4], "content": t,
             "tenant_id": "acme" if i % 2 else "globex"}
            for i, t in enumerate(["leaked AKIAIOSFODNN7EXAMPLE", "email a@b.io",
                                   "benign note", "ssn 123-45-6789"])]
    c.insert("kb", rows)
    c.close()
    return db


def test_describe_dim_and_chunks(lite_db):
    from vecshield_platform.connectors.milvus import MilvusConnector

    with MilvusConnector(uri=lite_db) as conn:
        cols = {c.name: c for c in conn.describe().collections}
        assert "kb" in cols and cols["kb"].dimension == 4
        chunks = list(conn.iter_chunks("kb"))
    assert len(chunks) == 4
    assert all(c.text for c in chunks)
    assert all(c.embedding and len(c.embedding) == 4 for c in chunks)


def test_query_and_scan(lite_db):
    from vecshield.classify import RegexClassifier
    from vecshield_platform.connectors.milvus import MilvusConnector
    from vecshield.models import Severity
    from vecshield_platform.scan import scan_store

    with MilvusConnector(uri=lite_db) as conn:
        hits = conn.query("kb", [0.1, 0.2, 0.3, 0.4], top_k=2)
        assert hits and all(h.id for h in hits)
        job = scan_store(conn, classifier=RegexClassifier())
    assert job.max_severity == Severity.CRITICAL  # AWS key
