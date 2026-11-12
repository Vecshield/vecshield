"""Chroma connector audit regressions, against a persistent temp directory.

* add_chunks keeps each chunk's metadata when another chunk in the batch has
  none (it used to drop the whole batch's metadata).
* Embeddings and scores are plain Python floats; score is -distance.
* list_collections is paged; iter_chunks is not bounded by count().
* An unreadable count is unknown, not zero; SDK errors map onto the taxonomy.
* ssl, tenant and database reach the client; header values never reach the
  displayed endpoint, and headers are not accepted from stored config.
* A local path that holds no Chroma store is not found, and nothing is
  created there: a mistyped path used to be audited as an empty, clean store.
"""

from __future__ import annotations

import pytest

pytest.importorskip("chromadb")

from vecshield.models import Chunk  # noqa: E402
from vecshield_platform.connectors import build_connector  # noqa: E402
from vecshield_platform.connectors.base import (  # noqa: E402
    ConnectorAuthError,
    ConnectorNotFound,
    translate_error,
)
from vecshield_platform.connectors.chroma import _ERRORS, ChromaConnector  # noqa: E402
from vecshield_platform.coverage import count_known  # noqa: E402


@pytest.fixture
def conn(tmp_path):
    connector = ChromaConnector(path=str(tmp_path / "chroma"), create=True)
    yield connector
    connector.close()


def _chunk(cid, vec, meta=None, text=None):
    return Chunk(id=cid, collection="kb1", text=text or f"doc {cid}",
                 embedding=vec, metadata=meta or {})


def test_one_empty_metadata_does_not_drop_the_batch(conn):
    conn.add_chunks("kb1", [_chunk("a", [0.1, 0.2, 0.3], {"owner": "acme", "n": 1}),
                          _chunk("b", [0.2, 0.1, 0.3]),
                          _chunk("c", [0.3, 0.2, 0.1], {"owner": "globex"})])
    got = {c.id: c.metadata for c in conn.get_chunks("kb1", ["a", "b", "c"])}
    assert got == {"a": {"owner": "acme", "n": 1}, "b": {}, "c": {"owner": "globex"}}


def test_embeddings_and_scores_are_plain_floats(conn):
    conn.add_chunks("kb1", [_chunk("near", [1.0, 0.0, 0.0]),
                          _chunk("far", [0.0, 0.0, 1.0])])
    chunks = list(conn.iter_chunks("kb1"))
    assert len(chunks) == 2
    for chunk in chunks:
        assert isinstance(chunk.embedding, list)
        assert all(type(x) is float for x in chunk.embedding)
    for chunk in conn.get_chunks("kb1", ["near"]):
        assert all(type(x) is float for x in chunk.embedding)

    col = conn._client.get_collection("kb1")
    raw = col.query(query_embeddings=[[1.0, 0.0, 0.0]], n_results=2,
                    include=["distances"])
    distances = dict(zip(raw["ids"][0], raw["distances"][0]))
    hits = conn.query("kb1", [1.0, 0.0, 0.0], top_k=2)
    assert [h.id for h in hits] == ["near", "far"]
    for hit in hits:
        assert type(hit.score) is float
        assert hit.score == pytest.approx(-float(distances[hit.id]))
    assert hits[0].score > hits[1].score  # higher is closer


def test_list_collections_is_paged(monkeypatch, conn):
    import vecshield_platform.connectors.chroma as chroma_mod

    for i in range(5):
        conn._client.create_collection(f"col{i}")
    monkeypatch.setattr(chroma_mod, "_COLLECTION_PAGE", 2)
    calls = []
    real = conn._client.list_collections

    def spy(limit=None, offset=None):
        calls.append((limit, offset))
        return real(limit=limit, offset=offset)

    monkeypatch.setattr(conn._client, "list_collections", spy)
    names = sorted(c.name for c in conn.list_collections())
    assert names == [f"col{i}" for i in range(5)]
    assert calls == [(2, 0), (2, 2), (2, 4)]


def test_a_name_only_listing_keeps_the_collection_metadata(monkeypatch, conn):
    """chromadb 0.6 lists collection names, not collections: the metadata,
    and the embedding model it declares, must come from the collection."""
    conn._client.create_collection(
        "kb1", metadata={"embedding_model": "text-embedding-3-small"})
    real = conn._client.list_collections
    monkeypatch.setattr(conn._client, "list_collections",
                        lambda limit=None, offset=None: [
                            c.name for c in real(limit=limit, offset=offset)])
    [col] = conn.list_collections()
    assert col.embedding_model == "text-embedding-3-small"
    assert col.metadata["embedding_model"] == "text-embedding-3-small"


def test_iter_chunks_is_not_bounded_by_a_stale_count(monkeypatch, conn):
    from chromadb.api.models.Collection import Collection as ChromaCollection

    conn.add_chunks("kb1", [_chunk(str(i), [float(i), 1.0, 0.0]) for i in range(7)])
    monkeypatch.setattr(ChromaCollection, "count", lambda self: 1)
    assert len(list(conn.iter_chunks("kb1", batch_size=3))) == 7


def test_unreadable_count_is_unknown_not_zero(monkeypatch, conn):
    from chromadb.api.models.Collection import Collection as ChromaCollection

    conn.add_chunks("kb1", [_chunk("a", [0.1, 0.2, 0.3])])

    def boom(self):
        raise RuntimeError("count failed")

    monkeypatch.setattr(ChromaCollection, "count", boom)
    [col] = conn.list_collections()
    assert col.count == 0 and not count_known(col)
    assert col.dimension == 3


def test_missing_collection_maps_to_not_found(conn):
    with pytest.raises(ConnectorNotFound):
        list(conn.iter_chunks("absent"))


@pytest.mark.parametrize("make_dir", [False, True], ids=["missing", "empty-dir"])
def test_a_path_without_a_chroma_store_is_not_found_and_not_created(tmp_path, make_dir):
    path = tmp_path / "typo"
    if make_dir:
        path.mkdir()
    for open_store in (lambda: ChromaConnector(path=str(path)),
                       lambda: build_connector("chroma", path=str(path))):
        with pytest.raises(ConnectorNotFound, match="no Chroma store"):
            open_store()
    assert path.exists() is make_dir
    assert not (path / "chroma.sqlite3").exists()


def test_an_existing_store_opens_and_create_makes_a_new_one(tmp_path):
    path = str(tmp_path / "new")
    with ChromaConnector(path=path, create=True) as c:
        c._client.create_collection("docs")
    with build_connector("chroma", path=path) as c:
        assert [col.name for col in c.list_collections()] == ["docs"]


def test_chroma_auth_errors_map_to_auth():
    from chromadb.errors import AuthorizationError, ChromaAuthError

    for exc in (AuthorizationError("token sk-SECRET"), ChromaAuthError("nope")):
        out = translate_error(exc, kind="chroma", extra=_ERRORS)
        assert isinstance(out, ConnectorAuthError)
        assert "SECRET" not in str(out)


def test_tenant_and_database_reach_the_persistent_client(tmp_path):
    c = ChromaConnector(path=str(tmp_path / "db"), tenant="default_tenant",
                        database="default_database", create=True)
    assert c.list_collections() == []


def test_http_options_reach_the_client_and_headers_stay_out_of_the_endpoint(monkeypatch):
    import chromadb

    seen = {}

    def fake_http_client(**kw):
        seen.update(kw)
        return object()

    monkeypatch.setattr(chromadb, "HttpClient", fake_http_client)
    c = ChromaConnector(host="chroma.internal", port=8443, ssl=True,
                        headers={"X-Chroma-Token": "tok-SECRET"},
                        tenant="acme", database="prod")
    assert seen == {"host": "chroma.internal", "port": 8443, "ssl": True,
                    "headers": {"X-Chroma-Token": "tok-SECRET"},
                    "tenant": "acme", "database": "prod"}
    assert c._endpoint == "https://chroma.internal:8443"
    assert "SECRET" not in c._endpoint


def test_build_connector_passes_scope_but_not_headers(monkeypatch):
    import chromadb

    seen = {}

    def fake_http_client(**kw):
        seen.update(kw)
        return object()

    monkeypatch.setattr(chromadb, "HttpClient", fake_http_client)
    build_connector("chroma", host="h", port=8000, ssl="true", tenant="t",
                    database="d", headers={"Authorization": "Bearer x"})
    assert seen["ssl"] is True and seen["tenant"] == "t" and seen["database"] == "d"
    assert seen["headers"] is None
