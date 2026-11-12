"""Weaviate connector: multi-tenancy, cloud connect, named vectors, scores, deletes.

No server: the v4 client is replaced by a fake shaped like weaviate-client
4.16 (``collections.list_all/get``, ``with_tenant``, ``tenants.get``,
``query.fetch_objects/near_vector``, ``data.delete_by_id``).
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

weaviate = pytest.importorskip("weaviate")

from weaviate.collections.classes.tenants import TenantActivityStatus  # noqa: E402

from vecshield_platform.connectors import build_connector  # noqa: E402
from vecshield_platform.connectors.base import ConnectorAuthError, ConnectorError  # noqa: E402
from vecshield_platform.connectors.weaviate import TENANT_KEY, WeaviateConnector  # noqa: E402
from vecshield_platform.coverage import count_known  # noqa: E402


def _uid(n: int) -> uuid.UUID:
    return uuid.UUID(int=n)


def _obj(n, text, vector, distance=None):
    return SimpleNamespace(uuid=_uid(n), properties={"content": text}, vector=vector,
                           metadata=SimpleNamespace(distance=distance))


class _Shard:
    """One collection, or one tenant of it, as the client addresses it."""

    def __init__(self, owner, tenant):
        self._owner, self._tenant = owner, tenant
        self.query = self
        self.data = self
        self.aggregate = self

    @property
    def _objects(self):
        if self._owner.mt and self._tenant is None:
            raise RuntimeError("multi-tenancy enabled, but request was without tenant")
        self._owner.touched.append(self._tenant)
        return self._owner.shards.get(self._tenant, [])

    def fetch_objects(self, limit=None, after=None, include_vector=False, **_):
        self._owner.fetch_calls.append({"tenant": self._tenant, "limit": limit,
                                        "after": after, "include_vector": include_vector})
        objs = self._objects
        if after is not None:
            idx = next(i for i, o in enumerate(objs) if o.uuid == after)
            objs = objs[idx + 1:]
        return SimpleNamespace(objects=objs[:limit])

    def near_vector(self, **kwargs):
        self._owner.query_calls.append({"tenant": self._tenant, **kwargs})
        return SimpleNamespace(objects=list(self._objects)[: kwargs.get("limit") or 10])

    def over_all(self, total_count=True):
        return SimpleNamespace(total_count=len(self._objects))

    def delete_by_id(self, key):
        self._owner.deletes.append((self._tenant, key))
        objs = self._objects
        for i, o in enumerate(objs):
            if o.uuid == key:
                del objs[i]
                return True
        return False  # 404 is an "ok" status for the client, returned as False


class _Collection(_Shard):
    def __init__(self, shards, *, mt=False, tenants=None):
        self.shards, self.mt = shards, mt
        self._tenants = tenants or {}
        self.touched: list = []
        self.fetch_calls: list = []
        self.query_calls: list = []
        self.deletes: list = []
        super().__init__(self, None)
        self.tenants = SimpleNamespace(get=lambda: {
            name: SimpleNamespace(name=name, activity_status=state)
            for name, state in self._tenants.items()})

    def with_tenant(self, tenant):
        return _Shard(self, tenant)


def _config(mt=False, named=None):
    return SimpleNamespace(multi_tenancy_config=SimpleNamespace(enabled=mt),
                           vector_config=named)


class _Client:
    def __init__(self, collections, configs):
        self._cols, self._configs = collections, configs
        self.collections = self

    def list_all(self, simple=True):
        return dict(self._configs)

    def get(self, name):
        col = self._cols[name]
        col.config = SimpleNamespace(get=lambda: self._configs[name])
        return col

    def close(self):
        pass


def _connector(collections, configs) -> WeaviateConnector:
    conn = WeaviateConnector.__new__(WeaviateConnector)
    conn._client = _Client(collections, configs)
    conn._endpoint = "http://fake:8080"
    conn._transport = {"tls": False}
    conn._layouts = {}
    conn._read_errors = []
    return conn


def _multi_tenant():
    col = _Collection(
        {"acme": [_obj(1, "acme one", [1.0, 0.0], 0.2), _obj(2, "acme two", [0.9, 0.1], 0.5)],
         "globex": [_obj(1, "globex one", [0.0, 1.0], 0.1)],
         "dormant": [_obj(9, "never read", [0.5, 0.5], 0.0)],
         "archived": [_obj(8, "never read", [0.5, 0.5], 0.0)]},
        mt=True,
        tenants={"acme": TenantActivityStatus.ACTIVE, "globex": TenantActivityStatus.ACTIVE,
                 "dormant": TenantActivityStatus.INACTIVE,
                 "archived": TenantActivityStatus.OFFLOADED})
    return col, _connector({"Docs": col}, {"Docs": _config(mt=True)})


def test_multi_tenant_collection_reads_every_active_tenant():
    col, conn = _multi_tenant()
    chunks = list(conn.iter_chunks("Docs", batch_size=1))
    assert sorted(c.id for c in chunks) == sorted(
        [f"acme:{_uid(1)}", f"acme:{_uid(2)}", f"globex:{_uid(1)}"])
    assert {c.metadata[TENANT_KEY] for c in chunks} == {"acme", "globex"}
    # Paged with the cursor, one page per call.
    acme_pages = [c for c in col.fetch_calls if c["tenant"] == "acme"]
    assert [c["after"] for c in acme_pages] == [None, _uid(1), _uid(2)]


def test_inactive_tenants_are_reported_and_never_touched():
    col, conn = _multi_tenant()
    conn.reset_read_errors()
    list(conn.iter_chunks("Docs"))
    assert "dormant" not in col.touched and "archived" not in col.touched
    errors = conn.read_errors()
    assert sorted((e["tenant"], e["tenant_state"]) for e in errors) == [
        ("archived", "OFFLOADED"), ("dormant", "INACTIVE")]
    assert all(e["collection"] == "Docs" and e["error_type"] == "TenantNotActive"
               for e in errors)
    conn.reset_read_errors()
    assert conn.read_errors() == []


def test_multi_tenant_count_is_unknown_while_a_tenant_is_inactive():
    col, conn = _multi_tenant()
    (c,) = conn.list_collections()
    assert not count_known(c) and c.count == 0
    assert c.metadata["tenants_active"] == 2 and c.metadata["tenants_inactive"] == 2
    assert "dormant" not in col.touched and "archived" not in col.touched


def test_multi_tenant_count_known_when_all_active():
    col = _Collection({"a": [_obj(1, "x", [1.0])], "b": [_obj(2, "y", [1.0])]}, mt=True,
                      tenants={"a": TenantActivityStatus.ACTIVE,
                               "b": TenantActivityStatus.ACTIVE})
    conn = _connector({"Docs": col}, {"Docs": _config(mt=True)})
    (c,) = conn.list_collections()
    assert count_known(c) and c.count == 2 and c.dimension == 1


def test_count_failure_is_unknown_not_zero():
    col = _Collection({None: [_obj(1, "x", [1.0])]})

    def boom(total_count=True):
        raise RuntimeError("aggregate failed")
    col.over_all = boom
    conn = _connector({"Docs": col}, {"Docs": _config()})
    (c,) = conn.list_collections()
    assert c.count == 0 and not count_known(c)


def test_query_routes_tenant_and_fans_out_without_one():
    col, conn = _multi_tenant()
    hits = conn.query("Docs", [1.0, 0.0], top_k=2, where={TENANT_KEY: "acme"})
    assert {h.metadata[TENANT_KEY] for h in hits} == {"acme"}
    assert col.query_calls[-1]["tenant"] == "acme" and col.query_calls[-1]["filters"] is None
    # A tenant that does not exist has no shard: nothing comes back.
    assert conn.query("Docs", [1.0, 0.0], where={TENANT_KEY: "nobody"}) == []
    # An inactive tenant is refused, not activated.
    with pytest.raises(ConnectorError):
        conn.query("Docs", [1.0, 0.0], where={TENANT_KEY: "dormant"})
    assert "dormant" not in col.touched
    merged = conn.query("Docs", [1.0, 0.0], top_k=10)
    assert [h.id for h in merged] == [f"globex:{_uid(1)}", f"acme:{_uid(1)}",
                                      f"acme:{_uid(2)}"]


def test_tenant_aware_delete_counts_only_confirmed_deletes():
    col, conn = _multi_tenant()
    ids = [f"acme:{_uid(1)}",      # deleted from acme only
           f"acme:{_uid(77)}",     # not there: delete_by_id returns False
           str(_uid(1)),           # bare uuid: tenant unknown, never guessed
           f"dormant:{_uid(9)}"]   # inactive tenant: not touched
    assert conn.delete_chunks("Docs", ids) == 1
    assert col.deletes == [("acme", _uid(1)), ("acme", _uid(77))]
    assert [o.uuid for o in col.shards["globex"]] == [_uid(1)]  # same uuid, other tenant
    assert "dormant" not in col.touched


def test_delete_count_ignores_false_results():
    col = _Collection({None: [_obj(1, "x", [1.0])]})
    conn = _connector({"Docs": col}, {"Docs": _config()})
    assert conn.delete_chunks("Docs", [str(_uid(1)), str(_uid(2)), "not-a-uuid"]) == 1


def test_delete_stops_on_auth_failure():
    from weaviate.exceptions import AuthenticationFailedError
    col = _Collection({None: [_obj(1, "x", [1.0])]})

    def denied(key):
        raise AuthenticationFailedError("bad key")
    col.delete_by_id = denied
    conn = _connector({"Docs": col}, {"Docs": _config()})
    with pytest.raises(ConnectorAuthError):
        conn.delete_chunks("Docs", [str(_uid(1))])


def _named():
    multi = SimpleNamespace(vector_index_config=SimpleNamespace(multi_vector=object()))
    dense = SimpleNamespace(vector_index_config=SimpleNamespace(multi_vector=None))
    return {"colbert": multi, "body": dense, "title": dense}


def test_named_vectors_use_the_first_dense_one():
    col = _Collection({None: [_obj(1, "x", {"colbert": [[0.1, 0.2], [0.3, 0.4]],
                                            "body": [1.0, 2.0, 3.0],
                                            "title": [9.0, 9.0]}, 0.3)]})
    conn = _connector({"Docs": col}, {"Docs": _config(named=_named())})
    (c,) = conn.list_collections()
    assert c.dimension == 3
    (chunk,) = list(conn.iter_chunks("Docs"))
    assert chunk.embedding == [1.0, 2.0, 3.0]
    assert col.fetch_calls[-1]["include_vector"] == ["body"]
    conn.query("Docs", [1.0, 2.0, 3.0], top_k=1)
    assert col.query_calls[-1]["target_vector"] == "body"


def test_unnamed_vector_sends_no_target_vector():
    col = _Collection({None: [_obj(1, "x", {"default": [1.0, 2.0]}, 0.1)]})
    conn = _connector({"Docs": col}, {"Docs": _config()})
    conn.query("Docs", [1.0, 2.0])
    assert "target_vector" not in col.query_calls[-1]
    assert list(conn.iter_chunks("Docs"))[0].embedding == [1.0, 2.0]


def test_score_is_negated_distance_including_dot():
    # Dot distance is -(a.b): zero and negative values are normal.
    col = _Collection({None: [_obj(1, "a", [1.0], -1.0), _obj(2, "b", [1.0], 0.0),
                              _obj(3, "c", [1.0], 0.25)]})
    conn = _connector({"Docs": col}, {"Docs": _config()})
    hits = conn.query("Docs", [1.0], top_k=3)
    assert [h.score for h in hits] == [1.0, -0.0, -0.25]
    assert hits[0].score > hits[1].score > hits[2].score


# ---- connect --------------------------------------------------------------- #

@pytest.fixture
def connects(monkeypatch):
    calls = []
    for name in ("connect_to_weaviate_cloud", "connect_to_custom", "connect_to_local"):
        monkeypatch.setattr(weaviate, name,
                            lambda _n=name, **kw: calls.append((_n, kw)) or SimpleNamespace())
    return calls


def test_cloud_host_uses_wcd_connect(connects):
    conn = WeaviateConnector(url="https://abc123.c0.europe-west3.gcp.weaviate.cloud",
                             api_key="k")
    (name, kw), = connects
    assert name == "connect_to_weaviate_cloud"
    assert kw["cluster_url"] == "abc123.c0.europe-west3.gcp.weaviate.cloud"
    assert conn._transport["tls"] is True
    assert conn._endpoint == "https://abc123.c0.europe-west3.gcp.weaviate.cloud"


def test_bare_cloud_hostname_and_legacy_network_domain(connects):
    WeaviateConnector(url="sandbox-x.weaviate.network", api_key="k")
    assert connects[-1][0] == "connect_to_weaviate_cloud"
    assert connects[-1][1]["cluster_url"] == "sandbox-x.weaviate.network"


def test_custom_url_takes_a_grpc_host(connects):
    build_connector("weaviate", url="https://vec.example.com", grpc_host="grpc.example.com",
                    grpc_port=443, api_key="k")
    (name, kw), = connects
    assert name == "connect_to_custom"
    assert kw["http_host"] == "vec.example.com" and kw["grpc_host"] == "grpc.example.com"
    assert kw["grpc_secure"] is True and kw["grpc_port"] == 443


def test_custom_url_defaults_grpc_host_to_http_host(connects):
    WeaviateConnector(url="http://10.0.0.5:8080")
    (name, kw), = connects
    assert name == "connect_to_custom" and kw["grpc_host"] == "10.0.0.5"


def test_explicit_grpc_host_overrides_cloud_derivation(connects):
    WeaviateConnector(url="https://abc.weaviate.cloud", grpc_host="grpc-proxy.internal")
    assert connects[-1][0] == "connect_to_custom"
    assert connects[-1][1]["grpc_host"] == "grpc-proxy.internal"


def test_local_with_separate_grpc_host(connects):
    WeaviateConnector(host="web", grpc_host="grpc")
    (name, kw), = connects
    assert name == "connect_to_custom" and kw["grpc_host"] == "grpc"
    assert kw["http_secure"] is False


def test_plain_local_connect_unchanged(connects):
    conn = WeaviateConnector(host="localhost", port=8090)
    assert connects[-1][0] == "connect_to_local"
    assert conn._endpoint == "http://localhost:8090"
