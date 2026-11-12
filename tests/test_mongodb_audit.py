"""MongoDB connector against fakes: BSON vectors, filter-field enforcement,
recorded index-listing failures, autoEmbed inventory and _id-ordered reads."""

from __future__ import annotations

import json

import pytest

pytest.importorskip("pymongo")

from bson.binary import Binary, BinaryVectorDtype  # noqa: E402
from pymongo.errors import AutoReconnect, OperationFailure  # noqa: E402

from vecshield_platform.connectors.base import (  # noqa: E402
    ConnectorAuthError,
    UnsupportedCapability,
)
from vecshield_platform.connectors.mongodb import (  # noqa: E402
    MongoDBConnector,
    _decode_vector,
)
from vecshield_platform.coverage import count_known  # noqa: E402


def _vector_index(filters=("tenant_id",), path="embedding"):
    fields = [{"type": "vector", "path": path, "numDimensions": 2, "similarity": "cosine"}]
    fields += [{"type": "filter", "path": f} for f in filters]
    return [{"name": "vec_idx", "type": "vectorSearch",
             "latestDefinition": {"fields": fields}}]


class _Cursor:
    """Yields docs, raising ``fail_after`` (index, exception) once when reached."""

    def __init__(self, docs, fail=None):
        self._docs, self._fail, self._i = list(docs), fail, 0

    def __iter__(self):
        return self

    def __next__(self):
        if self._fail and self._i == self._fail[0]:
            exc, self._fail = self._fail[1], None
            raise exc
        if self._i >= len(self._docs):
            raise StopIteration
        self._i += 1
        return self._docs[self._i - 1]


class _Coll:
    def __init__(self, docs=(), indexes=None, index_error=None, count_error=None,
                 fail=None, other_type=None):
        self.docs = sorted(docs, key=lambda d: d["_id"])
        self.indexes = _vector_index() if indexes is None else indexes
        self.index_error = index_error
        self.count_error = count_error
        self.fail = fail
        self.other_type = other_type
        self.finds: list[tuple] = []
        self.pipelines: list = []

    def list_search_indexes(self):
        if self.index_error is not None:
            raise self.index_error
        return list(self.indexes)

    def estimated_document_count(self):
        if self.count_error is not None:
            raise self.count_error
        return len(self.docs)

    def find_one(self, flt=None, projection=None):
        if flt and "_id" in flt:
            return self.other_type
        return self.docs[0] if self.docs else None

    def find(self, flt=None, sort=None, batch_size=None):
        self.finds.append((flt, sort, batch_size))
        docs = self.docs
        if flt and "_id" in flt:
            docs = [d for d in docs if d["_id"] > flt["_id"]["$gt"]]
        fail, self.fail = self.fail, None
        return _Cursor(docs, fail)

    def aggregate(self, pipeline):
        self.pipelines.append(pipeline)
        return []


class _DB:
    def __init__(self, colls):
        self.colls = colls

    def list_collection_names(self):
        return list(self.colls)

    def __getitem__(self, name):
        return self.colls[name]


class _Client:
    def __init__(self, colls):
        self.dbs = {"app": _DB(colls)}

    def list_database_names(self):
        return list(self.dbs)

    def __getitem__(self, name):
        return self.dbs[name]


def _conn(colls) -> MongoDBConnector:
    c = MongoDBConnector.__new__(MongoDBConnector)
    c._c = _Client(colls)
    c._endpoint = "db:27017"
    c._layout = {}
    return c


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    import vecshield_platform.connectors.base as base
    import vecshield_platform.connectors.mongodb as mongodb
    monkeypatch.setattr(base.time, "sleep", lambda _s: None)
    monkeypatch.setattr(mongodb.time, "sleep", lambda _s: None)


# ------------------------------------------------------------ BSON vectors -- #

def test_bson_vectors_subtype_9_are_decoded():
    f32 = Binary.from_vector([0.5, -1.0], BinaryVectorDtype.FLOAT32)
    i8 = Binary.from_vector([1, -2], BinaryVectorDtype.INT8)
    bits = Binary.from_vector([255, 0], BinaryVectorDtype.PACKED_BIT)
    assert _decode_vector(f32) == [0.5, -1.0]
    assert _decode_vector(i8) == [1.0, -2.0]
    assert _decode_vector(bits) is None              # binary, not a dense vector
    assert _decode_vector(Binary(b"\x01\x02", 0)) is None
    assert _decode_vector([1, 2]) == [1.0, 2.0]


def test_iter_chunks_decodes_bson_vectors_instead_of_iterating_bytes():
    vec = Binary.from_vector([0.5, -1.0], BinaryVectorDtype.FLOAT32)
    coll = _Coll([{"_id": 1, "content": "hello", "embedding": vec, "tenant_id": "a"}])
    [chunk] = list(_conn({"kb": coll}).iter_chunks("app.kb"))
    assert chunk.embedding == [0.5, -1.0]
    assert chunk.metadata == {"content": "hello", "tenant_id": "a"}


# ------------------------------------------------------------- reads -- #

def test_reads_are_sorted_by_id_with_the_batch_size():
    coll = _Coll([{"_id": i, "content": f"c{i}", "embedding": [0.1, 0.2]} for i in (3, 1, 2)])
    chunks = list(_conn({"kb": coll}).iter_chunks("app.kb", batch_size=50))
    assert [c.id for c in chunks] == ["1", "2", "3"]
    assert coll.finds == [({}, [("_id", 1)], 50)]


def test_a_transient_failure_resumes_after_the_last_id():
    coll = _Coll([{"_id": i, "content": "x", "embedding": [0.1, 0.2]} for i in (1, 2, 3)],
                 fail=(1, AutoReconnect("node stepped down")))
    conn = _conn({"kb": coll})
    assert [c.id for c in conn.iter_chunks("app.kb")] == ["1", "2", "3"]
    assert coll.finds[1][0] == {"_id": {"$gt": 1}}
    assert conn.read_errors() == []


def test_no_resume_when_ids_of_another_type_could_be_skipped():
    coll = _Coll([{"_id": i, "content": "x", "embedding": [0.1, 0.2]} for i in (1, 2)],
                 fail=(1, AutoReconnect("down")), other_type={"_id": "a-string-id"})
    conn = _conn({"kb": coll})
    seen = []
    with pytest.raises(Exception) as info:
        for chunk in conn.iter_chunks("app.kb"):
            seen.append(chunk.id)
    assert seen == ["1"]
    assert type(info.value).__name__ == "ConnectorUnavailable"
    [err] = conn.read_errors()
    assert err["collection"] == "app.kb" and err["operation"] == "find"


# ---------------------------------------------------------- inventory -- #

def test_list_search_indexes_failure_is_recorded_not_swallowed():
    denied = _Coll(index_error=OperationFailure("not authorized secret=1", code=13))
    conn = _conn({"kb": _Coll([]), "locked": denied})
    names = [c.name for c in conn.list_collections()]
    conn.list_collections()  # listed again: still one entry
    assert names == ["app.kb"]
    [err] = conn.read_errors()
    assert err["collection"] == "app.locked"
    assert err["operation"] == "list_search_indexes"
    assert err["error_type"] == "ConnectorAuthError"
    assert "secret" not in json.dumps(err)


def test_a_deployment_without_search_is_not_a_read_error():
    unavailable = _Coll(index_error=OperationFailure("search not enabled", code=31082))
    conn = _conn({"plain": unavailable})
    assert conn.list_collections() == []
    assert conn.read_errors() == []


def test_auto_embed_collections_are_in_the_inventory():
    index = [{"name": "auto_idx", "type": "vectorSearch", "latestDefinition": {"fields": [
        {"type": "autoEmbed", "modality": "text", "path": "plot", "model": "voyage-4",
         "numDimensions": 1024, "similarity": "cosine"},
        {"type": "filter", "path": "genre"}]}}]
    coll = _Coll([{"_id": 1, "plot": "a heist", "genre": "crime"}], indexes=index)
    conn = _conn({"movies": coll})
    [col] = conn.list_collections()
    assert col.name == "app.movies" and col.dimension == 1024
    assert col.metadata["auto_embed"]["model"] == "voyage-4"
    assert col.metadata["filter_fields"] == ["genre"]
    [chunk] = list(conn.iter_chunks("app.movies"))
    assert chunk.text == "a heist" and chunk.embedding is None
    with pytest.raises(UnsupportedCapability):
        conn.query("app.movies", [0.1] * 4)


def test_a_failed_count_is_unknown_not_zero():
    coll = _Coll([{"_id": 1, "content": "x", "embedding": [0.1, 0.2]}],
                 count_error=OperationFailure("denied", code=13))
    [col] = _conn({"kb": coll}).list_collections()
    assert col.count == 0 and count_known(col) is False
    assert col.metadata["count_error"] == "ConnectorAuthError"


# ------------------------------------------------------------- queries -- #

def test_tenant_field_not_indexed_as_a_filter_is_unsupported():
    coll = _Coll([{"_id": 1, "content": "x", "embedding": [0.1, 0.2]}], indexes=_vector_index(()))
    conn = _conn({"kb": coll})
    with pytest.raises(UnsupportedCapability, match="tenant_id"):
        conn.query("app.kb", [0.1, 0.2], where={"tenant_id": "acme"})
    assert coll.pipelines == []
    conn.query("app.kb", [0.1, 0.2])  # unfiltered still runs
    assert len(coll.pipelines) == 1


def test_indexed_filter_field_is_passed_to_vector_search():
    coll = _Coll([{"_id": 1, "content": "x", "embedding": [0.1, 0.2]}])
    _conn({"kb": coll}).query("app.kb", [0.1, 0.2], top_k=3, where={"tenant_id": "acme"})
    stage = coll.pipelines[0][0]["$vectorSearch"]
    assert stage["filter"] == {"tenant_id": "acme"}
    assert stage["index"] == "vec_idx" and stage["path"] == "embedding"


def test_operation_failure_codes_are_not_read_as_http_statuses():
    conn = _conn({})
    odd = OperationFailure("x", code=404)  # not an HTTP status here
    assert conn._translate(odd) is odd
    assert isinstance(conn._translate(OperationFailure("x", code=18)), ConnectorAuthError)
