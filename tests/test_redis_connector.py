"""Redis Vector Search connector — live (gated on Redis Stack at :6380)."""

from __future__ import annotations

import os
import struct

import pytest

pytest.importorskip("redis")

PORT = int(os.environ.get("VECSHIELD_REDIS_PORT", "6380"))


def _up() -> bool:
    try:
        import redis
        redis.Redis(port=PORT, socket_connect_timeout=1).execute_command("FT._LIST")
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _up(), reason="Redis Stack not reachable")


@pytest.fixture
def seeded():
    import redis
    from redis.commands.search.field import TagField, TextField, VectorField
    from redis.commands.search.index_definition import IndexDefinition, IndexType

    r = redis.Redis(port=PORT, decode_responses=False)
    try:
        r.ft("t_idx").dropindex(delete_documents=True)
    except Exception:
        pass
    r.ft("t_idx").create_index(
        [TextField("content"), TagField("tenant_id"),
         VectorField("embedding", "FLAT",
                     {"TYPE": "FLOAT32", "DIM": 4, "DISTANCE_METRIC": "L2"})],
        definition=IndexDefinition(prefix=["tdoc:"], index_type=IndexType.HASH))
    docs = [("leaked AKIAIOSFODNN7EXAMPLE", "acme"), ("email a@b.io", "acme"),
            ("benign", "globex"), ("ssn 123-45-6789", "globex")]
    for i, (t, ten) in enumerate(docs):
        r.hset(f"tdoc:{i}", mapping={"content": t, "tenant_id": ten,
                                     "embedding": struct.pack("4f", 0.1 * i, 0.2, 0.3, 0.4)})
    yield
    r.ft("t_idx").dropindex(delete_documents=True)


def test_describe_iter_query_scan(seeded):
    from vecshield.classify import RegexClassifier
    from vecshield_platform.connectors.redis import RedisConnector
    from vecshield.models import Severity
    from vecshield_platform.scan import scan_store

    with RedisConnector(port=PORT) as conn:
        col = next(c for c in conn.describe().collections if c.name == "t_idx")
        assert col.count == 4 and col.dimension == 4
        chunks = list(conn.iter_chunks("t_idx"))
        assert len(chunks) == 4
        assert all(c.text for c in chunks)
        assert all(c.embedding and len(c.embedding) == 4 for c in chunks)
        hits = conn.query("t_idx", [0.1, 0.2, 0.3, 0.4], top_k=2)
        assert hits and all(h.id for h in hits)
        job = scan_store(conn, classifier=RegexClassifier())
    assert job.max_severity == Severity.CRITICAL
