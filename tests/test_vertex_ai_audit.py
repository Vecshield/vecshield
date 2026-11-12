"""Vertex AI Vector Search connector: SDK contract fixes from the scan audit.

Checked against google-cloud-aiplatform 2.3.0: MatchingEngineIndex /
MatchingEngineIndexEndpoint take project/location/credentials, to_dict() is
the camelCase REST resource, find_neighbors() takes Namespace /
NumericNamespace filters and return_full_datapoint, and a neighbour's
restricts come back as Namespace(name, allow_tokens, deny_tokens).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

pytest.importorskip("google.cloud.aiplatform")

from google.cloud import aiplatform  # noqa: E402
from google.cloud.aiplatform.matching_engine.matching_engine_index_endpoint import (  # noqa: E402
    MatchNeighbor,
    Namespace,
    NumericNamespace,
)

from vecshield_platform.connectors.base import (  # noqa: E402
    ConnectorAuthError,
    UnsupportedCapability,
)
from vecshield_platform.connectors.vertex_ai import VertexAIConnector  # noqa: E402
from vecshield_platform.coverage import count_known  # noqa: E402


class _Index:
    def __init__(self, name, plain):
        self.name = name
        self.resource_name = f"projects/1/locations/europe-west4/indexes/{name}"
        self.display_name = name
        self._plain = plain
        self.removed = []

    def to_dict(self):
        return dict(self._plain)

    def remove_datapoints(self, datapoint_ids=None):
        self.removed.extend(datapoint_ids or [])


class _Endpoint:
    def __init__(self, deployed, neighbours):
        self.deployed_indexes = deployed
        self._neighbours = neighbours
        self.calls = []

    def find_neighbors(self, **kw):
        self.calls.append(kw)
        return [list(self._neighbours)]


def _connector(monkeypatch, indexes=(), endpoint=None, list_error=None):
    calls = {"list": [], "get": [], "endpoint": []}

    class MatchingEngineIndex:
        @staticmethod
        def list(**kw):
            calls["list"].append(kw)
            if list_error is not None:
                raise list_error
            return list(indexes)

        def __new__(cls, name, **kw):
            calls["get"].append((name, kw))
            return next(i for i in indexes if i.name == name)

    def make_endpoint(eid, **kw):
        calls["endpoint"].append((eid, kw))
        return endpoint

    def no_init(**_kw):
        raise AssertionError("aiplatform.init sets process-wide state; never call it")

    monkeypatch.setattr(aiplatform, "init", no_init)
    conn = VertexAIConnector(project="proj-a", location="europe-west4",
                             endpoint_id="ep-1" if endpoint is not None else None)
    conn._ai = SimpleNamespace(MatchingEngineIndex=MatchingEngineIndex,
                               MatchingEngineIndexEndpoint=make_endpoint)
    return conn, calls


_SDK_KW = {"project": "proj-a", "location": "europe-west4"}


def test_no_process_wide_init_and_every_call_names_the_project(monkeypatch):
    idx = _Index("i1", {"indexStats": {"vectorsCount": "3", "shardsCount": 1},
                        "indexUpdateMethod": "STREAM_UPDATE"})
    conn, calls = _connector(monkeypatch, [idx])
    conn.list_collections()
    conn.delete_chunks("i1", ["a"])
    assert calls["list"] and all(kw == _SDK_KW for kw in calls["list"])
    assert calls["get"] == [("i1", _SDK_KW)]


def test_count_and_dimension_come_from_to_dict(monkeypatch):
    indexes = [
        _Index("full", {"indexStats": {"vectorsCount": "12", "shardsCount": 1},
                        "metadata": {"config": {"dimensions": 768.0}}}),
        # proto3 drops zero: stats present without vectorsCount is a real zero.
        _Index("empty", {"indexStats": {"shardsCount": 1}}),
        _Index("unknown", {"metadata": {"config": {}}}),
    ]
    conn, _ = _connector(monkeypatch, indexes)
    cols = {c.name: c for c in conn.list_collections()}
    assert (cols["full"].count, cols["full"].dimension) == (12, 768)
    assert count_known(cols["full"]) and count_known(cols["empty"])
    assert cols["empty"].count == 0
    assert cols["unknown"].count == 0 and not count_known(cols["unknown"])
    assert cols["unknown"].dimension is None


def test_unreadable_index_resource_is_a_read_error(monkeypatch):
    class Broken(_Index):
        def to_dict(self):
            raise RuntimeError("secret-bearing message")

    conn, _ = _connector(monkeypatch, [Broken("b", {})])
    cols = conn.list_collections()
    assert not count_known(cols[0])
    errors = conn.read_errors()
    assert errors == [{"collection": "b", "operation": "index.to_dict",
                       "error_type": "RuntimeError",
                       "reason": "the index resource could not be read"}]
    assert "secret" not in repr(errors)


def test_delete_is_advertised_only_for_stream_update_indexes(monkeypatch):
    batch = _Index("batch", {"indexUpdateMethod": "BATCH_UPDATE"})
    unset = _Index("unset", {})
    conn, _ = _connector(monkeypatch, [batch, unset])
    assert "delete" not in conn.capabilities()
    with pytest.raises(UnsupportedCapability):
        conn.delete_chunks("batch", ["x"])
    with pytest.raises(UnsupportedCapability):
        conn.delete_chunks("unset", ["x"])
    assert batch.removed == [] and unset.removed == []

    stream = _Index("stream", {"indexUpdateMethod": "STREAM_UPDATE"})
    conn, _ = _connector(monkeypatch, [batch, stream])
    assert "delete" in conn.capabilities()
    cols = {c.name: c for c in conn.list_collections()}
    assert cols["stream"].metadata["streaming_delete"] is True
    assert cols["batch"].metadata["streaming_delete"] is False
    assert conn.delete_chunks("stream", ["x", "y"]) == 2 and stream.removed == ["x", "y"]


def test_unreadable_index_list_does_not_advertise_delete(monkeypatch):
    class PermissionDenied(Exception):
        code = 403

    conn, _ = _connector(monkeypatch, list_error=PermissionDenied("denied"))
    assert "delete" not in conn.capabilities()
    with pytest.raises(ConnectorAuthError):
        conn.list_collections()


def test_query_resolves_the_deployed_index_id(monkeypatch):
    deployed = [SimpleNamespace(id="other_dep", index="projects/1/locations/x/indexes/i2"),
                SimpleNamespace(id="i1_prod", index="projects/1/locations/x/indexes/i1")]
    endpoint = _Endpoint(deployed, [MatchNeighbor(id="d1", distance=0.5)])
    conn, calls = _connector(monkeypatch, endpoint=endpoint)
    hits = conn.query("i1", [0.1, 0.2], top_k=3)
    assert [h.id for h in hits] == ["d1"]
    assert endpoint.calls[0]["deployed_index_id"] == "i1_prod"
    assert endpoint.calls[0]["return_full_datapoint"] is True
    assert calls["endpoint"] == [("ep-1", _SDK_KW)]


def test_query_on_an_index_not_deployed_to_the_endpoint_is_unsupported(monkeypatch):
    endpoint = _Endpoint([SimpleNamespace(id="d", index="projects/1/locations/x/indexes/i2")],
                         [])
    conn, _ = _connector(monkeypatch, endpoint=endpoint)
    with pytest.raises(UnsupportedCapability):
        conn.query("i1", [0.1], top_k=1)
    assert endpoint.calls == []


def test_where_maps_to_namespace_and_numeric_filters(monkeypatch):
    endpoint = _Endpoint([SimpleNamespace(id="dep", index="projects/1/locations/x/indexes/i1")],
                         [])
    conn, _ = _connector(monkeypatch, endpoint=endpoint)
    conn.query("i1", [0.1], top_k=1, where={"tenant": "acme", "tier": 3,
                                            "region": {"$in": ["eu", "us"]},
                                            "score": 0.5})
    call = endpoint.calls[-1]
    assert call["filter"] == [Namespace(name="tenant", allow_tokens=["acme"]),
                              Namespace(name="region", allow_tokens=["eu", "us"])]
    assert call["numeric_filter"] == [
        NumericNamespace(name="tier", value_int=3, op="EQUAL"),
        NumericNamespace(name="score", value_double=0.5, op="EQUAL")]

    conn.query("i1", [0.1], top_k=1)
    assert "filter" not in endpoint.calls[-1] and "numeric_filter" not in endpoint.calls[-1]

    for where in ({"tenant": {"$ne": "acme"}}, {"flag": True}, {"tenant": None}):
        with pytest.raises(UnsupportedCapability):
            conn.query("i1", [0.1], top_k=1, where=where)


def test_restricts_become_hit_metadata_and_none_distance_is_zero(monkeypatch):
    neighbour = MatchNeighbor(
        id="d1", distance=None,
        restricts=[Namespace(name="tenant", allow_tokens=["acme"]),
                   Namespace(name="tags", allow_tokens=["a", "b"]),
                   Namespace(name="deny_only", allow_tokens=[], deny_tokens=["x"])],
        numeric_restricts=[NumericNamespace(name="tier", value_int=2)])
    endpoint = _Endpoint([SimpleNamespace(id="dep", index="projects/1/locations/x/indexes/i1")],
                         [neighbour])
    conn, _ = _connector(monkeypatch, endpoint=endpoint)
    hit = conn.query("i1", [0.1], top_k=1)[0]
    assert hit.score == 0.0
    assert hit.metadata == {"tenant": "acme", "tags": ["a", "b"], "tier": 2}
