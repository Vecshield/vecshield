"""Milvus connector audit regressions, against Milvus Lite (a local file).

* Reads past the offset + limit cap of 16,384 (query_iterator, not offset).
* Negative primary keys are read (no ``pk >= 0`` filter).
* The FLOAT_VECTOR field is chosen when a sparse vector field exists, and
  non-float vector fields are not decoded as floats or leaked into metadata.
* An unloaded collection is reported, never loaded.
* Counts that cannot be read are marked unknown; databases left unscanned are
  recorded; pymilvus errors map onto the connector taxonomy.
"""

from __future__ import annotations

import pytest

pytest.importorskip("pymilvus")
pytest.importorskip("milvus_lite")

from vecshield_platform.connectors.base import (  # noqa: E402
    ConnectorAuthError,
    ConnectorNotFound,
    ConnectorUnavailable,
    UnsupportedCapability,
)
from vecshield_platform.coverage import count_known  # noqa: E402

BIG = 16384 + 1200


def _client(path):
    from pymilvus import MilvusClient

    try:
        return MilvusClient(uri=path)
    except Exception as e:  # pragma: no cover - local gRPC can be blocked
        pytest.skip(f"Milvus Lite could not start: {e}")


@pytest.fixture(scope="module")
def lite(tmp_path_factory):
    """One Milvus Lite file with the collections every test reads."""
    from pymilvus import DataType, MilvusClient

    path = str(tmp_path_factory.mktemp("milvus") / "audit.db")
    c = _client(path)

    # big: more rows than one offset window, with negative ids.
    s = MilvusClient.create_schema(auto_id=False)
    s.add_field("id", DataType.INT64, is_primary=True)
    s.add_field("vector", DataType.FLOAT_VECTOR, dim=2)
    s.add_field("content", DataType.VARCHAR, max_length=32)
    ip = c.prepare_index_params()
    ip.add_index("vector", index_type="FLAT", metric_type="L2")
    c.create_collection("big", schema=s, index_params=ip)
    rows = [{"id": i - 50, "vector": [0.5, 0.25], "content": f"row {i}"}
            for i in range(BIG)]
    for start in range(0, len(rows), 5000):
        c.insert("big", rows[start:start + 5000])

    # mixed: a sparse vector field declared before the dense one.
    s = MilvusClient.create_schema(auto_id=False, enable_dynamic_field=True)
    s.add_field("id", DataType.INT64, is_primary=True)
    s.add_field("sparse", DataType.SPARSE_FLOAT_VECTOR)
    s.add_field("dense", DataType.FLOAT_VECTOR, dim=4)
    s.add_field("text", DataType.VARCHAR, max_length=64)
    ip = c.prepare_index_params()
    ip.add_index("dense", index_type="FLAT", metric_type="L2")
    ip.add_index("sparse", index_type="SPARSE_INVERTED_INDEX", metric_type="IP")
    c.create_collection("mixed", schema=s, index_params=ip)
    c.insert("mixed", [{"id": i, "sparse": {3: 0.5, 7: 0.25},
                        "dense": [0.1, 0.2, 0.3, 0.4], "text": f"doc {i}",
                        "tenant": "acme"} for i in range(-3, 3)])

    # sparse_only: no float vector at all.
    s = MilvusClient.create_schema(auto_id=False)
    s.add_field("id", DataType.VARCHAR, is_primary=True, max_length=16)
    s.add_field("sparse", DataType.SPARSE_FLOAT_VECTOR)
    s.add_field("text", DataType.VARCHAR, max_length=64)
    ip = c.prepare_index_params()
    ip.add_index("sparse", index_type="SPARSE_INVERTED_INDEX", metric_type="IP")
    c.create_collection("sparse_only", schema=s, index_params=ip)
    c.insert("sparse_only", [{"id": "", "sparse": {1: 1.0}, "text": "empty-string pk"},
                             {"id": "b", "sparse": {2: 1.0}, "text": "second"}])

    # cold: created and then released, so it is not loaded.
    s = MilvusClient.create_schema(auto_id=False)
    s.add_field("id", DataType.INT64, is_primary=True)
    s.add_field("vector", DataType.FLOAT_VECTOR, dim=2)
    ip = c.prepare_index_params()
    ip.add_index("vector", index_type="FLAT", metric_type="L2")
    c.create_collection("cold", schema=s, index_params=ip)
    c.insert("cold", [{"id": 1, "vector": [1.0, 0.0]}])
    c.release_collection("cold")
    c.close()
    return path


@pytest.fixture
def conn(lite):
    from vecshield_platform.connectors.milvus import MilvusConnector

    connector = MilvusConnector(uri=lite)
    yield connector
    connector.close()


def test_reads_past_the_16384_offset_cap_including_negative_ids(conn):
    ids = [int(c.id) for c in conn.iter_chunks("big", batch_size=2000)]
    assert len(ids) == BIG
    assert len(set(ids)) == BIG
    assert min(ids) == -50
    assert conn.read_errors() == []
    cols = {c.name: c for c in conn.list_collections()}
    assert cols["big"].count == BIG and count_known(cols["big"])


def test_reads_through_the_iterator_never_offset_paging(monkeypatch, conn):
    """Milvus Lite does not enforce the 16,384 offset + limit cap a server
    does, so the read path itself is pinned: no offset query, no filter."""
    def offset_query(*a, **kw):
        raise AssertionError("offset paging stops at 16,384 rows on a server")

    calls = []
    real = conn._client.query_iterator

    def spy(*a, **kw):
        calls.append(kw)
        return real(*a, **kw)

    monkeypatch.setattr(conn._client, "query", offset_query)
    monkeypatch.setattr(conn._client, "query_iterator", spy)
    assert sum(1 for _ in conn.iter_chunks("mixed")) == 6
    assert len(calls) == 1
    assert calls[0]["filter"] == "" and "offset" not in calls[0]
    assert calls[0]["consistency_level"] == "Strong"


def test_float_vector_is_chosen_over_an_earlier_sparse_field(conn):
    chunks = list(conn.iter_chunks("mixed"))
    assert sorted(int(c.id) for c in chunks) == [-3, -2, -1, 0, 1, 2]
    for chunk in chunks:
        assert chunk.embedding is not None and len(chunk.embedding) == 4
        assert all(type(x) is float for x in chunk.embedding)
        # Neither vector reaches the metadata classifiers read.
        assert "sparse" not in chunk.metadata and "dense" not in chunk.metadata
        assert chunk.metadata.get("tenant") == "acme"
    cols = {c.name: c for c in conn.list_collections()}
    assert cols["mixed"].dimension == 4
    assert cols["mixed"].metadata["vector_field"] == "dense"
    assert cols["mixed"].metadata["non_float_vector_fields"] == {"sparse": "SPARSE_FLOAT_VECTOR"}
    hits = conn.query("mixed", [0.1, 0.2, 0.3, 0.4], top_k=3)
    assert len(hits) == 3
    assert all("sparse" not in h.metadata and "dense" not in h.metadata for h in hits)


def test_sparse_only_collection_is_read_without_decoding_floats(conn):
    chunks = {c.id: c for c in conn.iter_chunks("sparse_only")}
    # The empty-string key the old `pk != ""` filter skipped is read too.
    assert set(chunks) == {"", "b"}
    assert all(c.embedding is None for c in chunks.values())
    assert all("sparse" not in c.metadata for c in chunks.values())
    with pytest.raises(UnsupportedCapability):
        conn.query("sparse_only", [0.1, 0.2], top_k=1)


def test_unloaded_collection_is_reported_and_not_loaded(lite, conn):
    from pymilvus import MilvusClient

    assert list(conn.iter_chunks("cold")) == []
    errors = conn.read_errors()
    assert len(errors) == 1
    assert errors[0]["collection"] == "cold"
    assert errors[0]["error_type"] == "CollectionNotLoaded"
    with pytest.raises(UnsupportedCapability):
        conn.query("cold", [1.0, 0.0], top_k=1)
    # Neither call loaded it.
    probe = MilvusClient(uri=lite)
    try:
        assert probe.get_load_state("cold")["state"].name == "NotLoad"
    finally:
        probe.close()


def test_unloaded_collection_downgrades_scan_coverage(conn):
    from vecshield.classify import RegexClassifier
    from vecshield_platform.scan import scan_store

    job = scan_store(conn, classifier=RegexClassifier())
    rows = {o["collection"]: o for o in job.stats["check_outcomes"]
            if o["check"] == "data_classification"}
    assert rows["cold"]["outcome"] != "passed"
    assert rows["cold"]["coverage"]["complete"] is False
    # The read error is scoped: the fully read collection stays complete.
    assert rows["mixed"]["coverage"]["complete"] is True


def test_count_failure_is_unknown_not_zero(monkeypatch, conn):
    def boom(name):
        raise RuntimeError("stats unavailable")

    monkeypatch.setattr(conn._client, "get_collection_stats", boom)
    cols = {c.name: c for c in conn.list_collections()}
    assert cols["big"].count == 0
    assert not count_known(cols["big"])


def test_other_databases_are_recorded_as_not_scanned(monkeypatch, conn):
    monkeypatch.setattr(conn._client, "list_databases", lambda **kw: ["default", "hr", "ops"])
    conn.reset_read_errors()
    conn.list_collections()
    gaps = [e for e in conn.read_errors() if e.get("operation") == "list_databases"]
    assert len(gaps) == 1
    assert gaps[0]["collection"] is None  # store-wide
    assert gaps[0]["databases_not_scanned"] == ["hr", "ops"]


def test_unlistable_databases_are_recorded(monkeypatch, conn):
    def denied(**kw):
        raise RuntimeError("secret-token-in-message")

    monkeypatch.setattr(conn._client, "list_databases", denied)
    conn.reset_read_errors()
    conn.list_collections()
    gaps = [e for e in conn.read_errors() if e.get("operation") == "list_databases"]
    assert len(gaps) == 1
    assert "secret-token-in-message" not in repr(gaps)


# ---- error mapping ------------------------------------------------------- #

def _milvus_exc(cls_name="MilvusException", **kw):
    import pymilvus.exceptions as ex

    return getattr(ex, cls_name)(**kw)


@pytest.mark.parametrize("exc_kw, expected", [
    ({"code": 1, "message": "denied", "compatible_code": 3}, ConnectorAuthError),
    ({"code": 1, "message": "no such thing", "compatible_code": 4}, ConnectorNotFound),
    ({"code": 100, "message": "collection not found"}, ConnectorNotFound),
    ({"code": 1, "message": "busy", "retriable": True}, ConnectorUnavailable),
    ({"code": 8, "message": "rate limited"}, ConnectorUnavailable),
])
def test_milvus_errors_map_onto_the_taxonomy(exc_kw, expected):
    from vecshield_platform.connectors.milvus import _translate

    out = _translate(_milvus_exc(**exc_kw))
    assert isinstance(out, expected)
    assert exc_kw["message"] not in str(out)


def test_milvus_codes_are_not_read_as_http_statuses():
    from vecshield_platform.connectors.milvus import _translate

    # A Milvus code of 401 is a replica error, not "unauthorised".
    exc = _milvus_exc(code=401, message="replica not available")
    assert _translate(exc) is exc


def test_milvus_exception_classes_map():
    from vecshield_platform.connectors.milvus import _translate

    assert isinstance(_translate(_milvus_exc("MilvusUnavailableException")),
                      ConnectorUnavailable)
    assert isinstance(_translate(_milvus_exc("CollectionNotExistException")),
                      ConnectorNotFound)


def test_transient_read_is_retried(monkeypatch, conn):
    real = conn._client.get_collection_stats
    calls = {"n": 0}

    def flaky(name):
        calls["n"] += 1
        if calls["n"] == 1:
            raise _milvus_exc(code=1, message="busy", retriable=True)
        return real(name)

    monkeypatch.setattr(conn._client, "get_collection_stats", flaky)
    monkeypatch.setattr(conn._client, "list_collections", lambda **kw: ["mixed"])
    cols = conn.list_collections()
    assert cols[0].count == 6 and count_known(cols[0])
    assert calls["n"] == 2
