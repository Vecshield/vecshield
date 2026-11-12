"""Qdrant connector audit regressions, against the in-memory qdrant-client.

* Named-vector collections are queried with ``using=`` the dense vector.
* Sparse vectors and multi-vectors are skipped, never decoded as floats.
* 401/403 map to ConnectorAuthError (not retried), 404 to ConnectorNotFound.
* No ``api_keys`` capability: the data-plane client has no keys API.
* A missing points count is unknown, not zero.
"""

from __future__ import annotations

import types

import pytest

pytest.importorskip("qdrant_client")

from vecshield_platform.connectors.base import (  # noqa: E402
    ConnectorAuthError,
    ConnectorNotFound,
    ConnectorTimeout,
    ConnectorUnavailable,
    UnsupportedCapability,
)
from vecshield_platform.connectors.qdrant import (  # noqa: E402
    QdrantConnector,
    _extract_vector,
    _translate,
)
from vecshield_platform.coverage import count_known  # noqa: E402


def _connector(client) -> QdrantConnector:
    conn = QdrantConnector.__new__(QdrantConnector)
    conn._client = client
    conn._endpoint = "memory"
    return conn


@pytest.fixture
def conn():
    from qdrant_client import QdrantClient, models

    client = QdrantClient(":memory:")
    multi = models.MultiVectorConfig(comparator=models.MultiVectorComparator.MAX_SIM)

    # named: a multivector declared before the dense one, plus a sparse vector.
    client.create_collection(
        "named",
        vectors_config={
            "colbert": models.VectorParams(size=2, distance=models.Distance.COSINE,
                                           multivector_config=multi),
            "dense": models.VectorParams(size=4, distance=models.Distance.COSINE),
        },
        sparse_vectors_config={"bm25": models.SparseVectorParams()},
    )
    client.upsert("named", points=[
        models.PointStruct(id=i, payload={"content": f"doc {i}", "tenant": "acme"},
                           vector={"colbert": [[0.1, 0.2], [0.3, 0.4]],
                                   "dense": [0.1 * (i + 1), 0.2, 0.3, 0.4],
                                   "bm25": models.SparseVector(indices=[1, 5],
                                                               values=[0.5, 0.25])})
        for i in range(5)])

    # sparse_only: no dense vector at all.
    client.create_collection("sparse_only", vectors_config={},
                             sparse_vectors_config={"bm25": models.SparseVectorParams()})
    client.upsert("sparse_only", points=[
        models.PointStruct(id=1, payload={"content": "only sparse"},
                           vector={"bm25": models.SparseVector(indices=[2], values=[1.0])})])

    # multi_only: an unnamed multivector.
    client.create_collection("multi_only", vectors_config=models.VectorParams(
        size=2, distance=models.Distance.COSINE, multivector_config=multi))
    client.upsert("multi_only", points=[
        models.PointStruct(id=1, payload={"content": "multi"}, vector=[[0.1, 0.2], [0.2, 0.1]])])

    # plain: the unnamed default dense vector.
    client.create_collection("plain", vectors_config=models.VectorParams(
        size=3, distance=models.Distance.DOT))
    client.upsert("plain", points=[
        models.PointStruct(id=7, payload={"text": "plain"}, vector=[1.0, 0.0, 0.0])])
    yield _connector(client)
    client.close()


def test_named_vectors_are_queried_with_using(monkeypatch, conn):
    seen = []
    real = conn._client.query_points

    def spy(**kw):
        seen.append(kw.get("using"))
        return real(**kw)

    monkeypatch.setattr(conn._client, "query_points", spy)
    hits = conn.query("named", [0.5, 0.2, 0.3, 0.4], top_k=3, where={"tenant": "acme"})
    assert len(hits) == 3
    assert seen == ["dense"]
    assert conn.query("plain", [1.0, 0.0, 0.0], top_k=1)[0].id == "7"
    assert seen[-1] is None  # the unnamed default vector


def test_named_collection_inventory_names_the_dense_vector(conn):
    cols = {c.name: c for c in conn.list_collections()}
    named = cols["named"]
    assert named.dimension == 4 and named.count == 5 and count_known(named)
    assert named.metadata["vector_name"] == "dense"
    assert named.metadata["non_dense_vectors"] == {"colbert": "multivector", "bm25": "sparse"}
    assert cols["sparse_only"].dimension is None


def test_named_chunks_carry_the_dense_embedding_as_floats(conn):
    chunks = list(conn.iter_chunks("named"))
    assert len(chunks) == 5
    for chunk in chunks:
        assert chunk.embedding is not None and len(chunk.embedding) == 4
        assert all(type(x) is float for x in chunk.embedding)


def test_sparse_and_multivector_points_do_not_crash(conn):
    sparse = list(conn.iter_chunks("sparse_only"))
    multi = list(conn.iter_chunks("multi_only"))
    assert [c.text for c in sparse] == ["only sparse"]
    assert [c.text for c in multi] == ["multi"]
    assert sparse[0].embedding is None and multi[0].embedding is None
    for name in ("sparse_only", "multi_only"):
        with pytest.raises(UnsupportedCapability):
            conn.query(name, [0.1, 0.2], top_k=1)
    got = conn.get_chunks("multi_only", ["1"])
    assert got[0].embedding is None


def test_extract_vector_shapes():
    from qdrant_client import models

    assert _extract_vector([1, 2.5]) == [1.0, 2.5]
    assert _extract_vector([[0.1, 0.2], [0.3, 0.4]]) is None
    assert _extract_vector(models.SparseVector(indices=[1], values=[0.5])) is None
    assert _extract_vector({"s": models.SparseVector(indices=[1], values=[0.5]),
                            "d": [0.5, 0.5]}) == [0.5, 0.5]
    assert _extract_vector({"d": [0.5], "e": [0.25]}, "e") == [0.25]
    assert _extract_vector({"m": [[1.0]]}) is None
    assert _extract_vector({}) is None


def test_api_keys_capability_is_not_advertised(conn):
    assert "api_keys" not in conn.capabilities()
    with pytest.raises(UnsupportedCapability):
        conn.list_api_keys()


def test_missing_points_count_is_unknown(monkeypatch, conn):
    real = conn._client.get_collection

    def no_count(name):
        info = real(name)
        return types.SimpleNamespace(config=info.config, points_count=None)

    monkeypatch.setattr(conn._client, "get_collection", no_count)
    cols = {c.name: c for c in conn.list_collections()}
    assert cols["named"].count == 0 and not count_known(cols["named"])


# ---- error mapping ------------------------------------------------------- #

def _unexpected(status: int):
    from httpx import Headers
    from qdrant_client.http.exceptions import UnexpectedResponse

    return UnexpectedResponse(status_code=status, reason_phrase="x",
                              content=b'{"api-key": "sk-SECRET"}', headers=Headers())


@pytest.mark.parametrize("status, expected", [
    (401, ConnectorAuthError), (403, ConnectorAuthError), (404, ConnectorNotFound),
    (429, ConnectorUnavailable), (503, ConnectorUnavailable),
])
def test_http_status_maps_onto_the_taxonomy(status, expected):
    out = _translate(_unexpected(status))
    assert type(out) is expected
    assert "SECRET" not in str(out)


def test_wrapped_transport_errors_map_by_their_source():
    import httpx
    from qdrant_client.http.exceptions import ResponseHandlingException

    refused = ResponseHandlingException(httpx.ConnectError("refused"))
    timed_out = ResponseHandlingException(httpx.ReadTimeout("slow"))
    assert isinstance(_translate(refused), ConnectorUnavailable)
    assert isinstance(_translate(timed_out), ConnectorTimeout)


def test_auth_failure_is_not_retried(monkeypatch, conn):
    calls = {"n": 0}

    def denied():
        calls["n"] += 1
        raise _unexpected(401)

    monkeypatch.setattr(conn._client, "get_collections", denied)
    with pytest.raises(ConnectorAuthError):
        conn.list_collections()
    assert calls["n"] == 1


def test_transient_page_read_is_retried(monkeypatch, conn):
    real = conn._client.scroll
    calls = {"n": 0}

    def flaky(**kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise _unexpected(503)
        return real(**kw)

    monkeypatch.setattr(conn._client, "scroll", flaky)
    assert len(list(conn.iter_chunks("named"))) == 5
    assert calls["n"] == 2

