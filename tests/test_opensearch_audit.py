"""OpenSearch connector fixes from the scan audit (fake client, no server).

* certificates are verified by default on TLS connections;
* the tenant filter field is chosen from the index mapping, not by always
  appending ``.keyword`` (which matched nothing on a ``keyword`` field, so
  every tenant-filtered query came back empty and looked isolated);
* effective roles come from ``rolesmapping``, not from backend role names;
* ``knn_vector`` fields inside ``nested`` properties are found and read.
"""

from __future__ import annotations

import sys
import types

import pytest

from vecshield_platform.connectors.base import (
    ConnectorAuthError,
    UnsupportedCapability,
)
from vecshield_platform.coverage import count_known


class _Indices:
    def __init__(self, fake):
        self._fake = fake

    def get(self, index=None):
        return {name: {} for name in self._fake.mappings}

    def get_mapping(self, index=None):
        if index in self._fake.mapping_errors:
            raise self._fake.mapping_errors[index]
        return {index: {"mappings": {"properties": self._fake.mappings[index]}}}


class _Transport:
    def __init__(self, fake):
        self._fake = fake

    def perform_request(self, method, path, body=None):
        value = self._fake.security.get(path)
        if isinstance(value, Exception):
            raise value
        if value is None:
            raise _HttpError(404)
        return value


class _HttpError(Exception):
    def __init__(self, status):
        super().__init__(status)
        self.status_code = status


class _FakeOS:
    instances: list["_FakeOS"] = []

    def __init__(self, *args, **kwargs):
        self.kwargs = kwargs
        self.mappings: dict = {}
        self.mapping_errors: dict = {}
        self.counts: dict = {}
        self.docs: dict = {}
        self.security: dict = {}
        self.searches: list = []
        self.indices = _Indices(self)
        self.transport = _Transport(self)
        _FakeOS.instances.append(self)

    def count(self, index=None):
        value = self.counts.get(index, 0)
        if isinstance(value, Exception):
            raise value
        return {"count": value}

    def search(self, index=None, body=None, scroll=None):
        self.searches.append(body)
        if scroll:
            return {"_scroll_id": None, "hits": {"hits": self.docs.get(index, [])}}
        return {"hits": {"hits": self.docs.get(index, [])}}

    def clear_scroll(self, body=None):
        pass


@pytest.fixture
def fake_module(monkeypatch):
    mod = types.ModuleType("opensearchpy")
    mod.OpenSearch = _FakeOS
    monkeypatch.setitem(sys.modules, "opensearchpy", mod)
    _FakeOS.instances.clear()
    return mod


def _conn(**kw):
    from vecshield_platform.connectors.opensearch import OpenSearchConnector

    return OpenSearchConnector(**kw)


# ---- certificate verification --------------------------------------------- #

def test_tls_connections_verify_certificates_by_default(fake_module):
    tls = _conn(host="os", port=9200, use_ssl=True)
    assert tls._c.kwargs["verify_certs"] is True
    assert tls._transport["verify_certs"] is True
    assert "certificate_verification" not in tls._transport

    https = _conn(url="https://os.example:9200")
    assert https._c.kwargs["verify_certs"] is True

    opted_out = _conn(host="os", port=9200, use_ssl=True, verify_certs=False)
    assert opted_out._c.kwargs["verify_certs"] is False
    assert opted_out._transport["certificate_verification"] is False

    plain = _conn(host="os", port=9200)  # no TLS: no certificate to verify
    assert plain._c.kwargs["verify_certs"] is False


# ---- tenant filter field from the mapping ---------------------------------- #

_MAPPING = {
    "embedding": {"type": "knn_vector", "dimension": 3},
    "content": {"type": "text"},
    "tenant_kw": {"type": "keyword"},
    "tenant_text": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
    "tenant_raw": {"type": "text", "fields": {"raw": {"type": "keyword"}}},
    "tenant_analysed": {"type": "text"},
    "tier": {"type": "integer"},
    "acl": {"type": "nested", "properties": {"group": {"type": "keyword"}}},
}


def _filter_of(conn, where):
    conn.query("idx", [0.1, 0.2, 0.3], top_k=2, where=where)
    return conn._c.searches[-1]["query"]["bool"]["filter"]


def test_tenant_filter_uses_the_field_its_mapping_allows(fake_module):
    conn = _conn(host="os")
    conn._c.mappings = {"idx": _MAPPING}
    assert _filter_of(conn, {"tenant_kw": "acme"}) == [{"term": {"tenant_kw": "acme"}}]
    assert _filter_of(conn, {"tenant_text": "acme"}) == [
        {"term": {"tenant_text.keyword": "acme"}}]
    assert _filter_of(conn, {"tenant_raw": "acme"}) == [{"term": {"tenant_raw.raw": "acme"}}]
    assert _filter_of(conn, {"tier": 3}) == [{"term": {"tier": 3}}]
    assert _filter_of(conn, {"acl.group": "eng"}) == [
        {"nested": {"path": "acl", "query": {"term": {"acl.group": "eng"}}}}]
    # Unmapped: used as named; no document holds it, so nothing matches.
    assert _filter_of(conn, {"missing": "x"}) == [{"term": {"missing": "x"}}]


def test_analysed_text_without_keyword_subfield_is_refused(fake_module):
    conn = _conn(host="os")
    conn._c.mappings = {"idx": _MAPPING}
    before = len(conn._c.searches)
    with pytest.raises(UnsupportedCapability):
        conn.query("idx", [0.1, 0.2, 0.3], top_k=2, where={"tenant_analysed": "acme"})
    assert len(conn._c.searches) == before  # never run with a filter matching nothing


# ---- effective roles through rolesmapping ---------------------------------- #

_USERS = {
    "alice": {"backend_roles": ["admin"], "attributes": {}},
    "bob": {"backend_roles": ["readwrite"], "attributes": {}},
    "svc-indexer": {"backend_roles": [], "opendistro_security_roles": [],
                    "attributes": {}},
    "carol": {"backend_roles": ["team-a", "writers"], "attributes": {}},
}
_ROLESMAPPING = {
    "all_access": {"backend_roles": ["admin"], "users": [], "hosts": []},
    "readall": {"backend_roles": ["readwrite"], "users": []},
    "crud": {"users": ["svc-*"], "backend_roles": []},
    "kibana_all_write": {"and_backend_roles": ["team-*", "writers"], "users": []},
}


def test_effective_roles_come_from_rolesmapping(fake_module):
    conn = _conn(host="os")
    conn._c.security = {"/_plugins/_security/api/internalusers": _USERS,
                        "/_plugins/_security/api/rolesmapping": _ROLESMAPPING}
    keys = {k.id: k for k in conn.list_api_keys()}
    assert keys["alice"].metadata["effective_roles"] == ["all_access"]
    assert "admin" in keys["alice"].actions
    # "readwrite" is a backend role mapped to readall: read only, not write.
    assert keys["bob"].metadata["effective_roles"] == ["readall"]
    assert keys["bob"].actions == ["read"]
    assert keys["svc-indexer"].metadata["effective_roles"] == ["crud"]
    assert "write" in keys["svc-indexer"].actions
    assert keys["carol"].metadata["effective_roles"] == ["kibana_all_write"]
    assert all(k.metadata["roles_resolved"] is True for k in keys.values())


def test_unreadable_rolesmapping_is_reported_on_each_key(fake_module):
    conn = _conn(host="os")
    conn._c.security = {"/_plugins/_security/api/internalusers": _USERS,
                        "/_plugins/_security/api/rolesmapping": _HttpError(403)}
    keys = conn.list_api_keys()
    assert all(k.metadata["roles_resolved"] is False for k in keys)
    assert {k.metadata["rolesmapping_error"] for k in keys} == {"ConnectorAuthError"}


def test_missing_security_plugin_is_unsupported_without_echoing_the_error(fake_module):
    conn = _conn(host="os")
    with pytest.raises(UnsupportedCapability) as info:
        conn.list_api_keys()
    assert str(info.value) == ("OpenSearch security plugin not available "
                               "(ConnectorNotFound)")


# ---- nested knn_vector fields --------------------------------------------- #

_NESTED = {
    "title": {"type": "text"},
    "tenant": {"type": "keyword"},
    "passages": {"type": "nested", "properties": {
        "text": {"type": "text"},
        "vector": {"type": "knn_vector", "dimension": 3}}},
}


def test_nested_knn_vector_index_is_a_collection_and_is_read(fake_module):
    conn = _conn(host="os")
    conn._c.mappings = {"docs": _NESTED, "plain": {"title": {"type": "text"}}}
    conn._c.counts = {"docs": 1}
    conn._c.docs = {"docs": [{"_id": "1", "_source": {
        "title": "t", "tenant": "acme",
        "passages": [{"text": "p1", "vector": [0.1, 0.2, 0.3]},
                     {"text": "p2", "vector": [0.4, 0.5, 0.6]}]}}]}
    cols = {c.name: c for c in conn.list_collections()}
    assert set(cols) == {"docs"}  # "plain" holds no vector
    assert cols["docs"].dimension == 3
    assert cols["docs"].metadata["vector_field"] == "passages.vector"
    assert cols["docs"].metadata["vector_nested_path"] == "passages"

    chunk = next(iter(conn.iter_chunks("docs")))
    assert chunk.embedding == [0.1, 0.2, 0.3]
    assert chunk.metadata["passages"] == [{"text": "p1"}, {"text": "p2"}]
    assert chunk.metadata["tenant"] == "acme"

    conn.query("docs", [0.1, 0.2, 0.3], top_k=2, where={"tenant": "acme"})
    query = conn._c.searches[-1]["query"]["bool"]
    assert query["must"] == [{"nested": {"path": "passages", "query": {
        "knn": {"passages.vector": {"vector": [0.1, 0.2, 0.3], "k": 2}}}}}]
    assert query["filter"] == [{"term": {"tenant": "acme"}}]


# ---- unreadable counts and mappings are unknown, not zero ------------------ #

def test_count_and_mapping_failures_are_unknown_not_zero(fake_module):
    class AuthorizationException(Exception):
        status_code = 403

    conn = _conn(host="os")
    conn._c.mappings = {"counted": _MAPPING, "secret": _MAPPING}
    conn._c.counts = {"counted": AuthorizationException()}
    conn._c.mapping_errors = {"secret": AuthorizationException()}
    cols = {c.name: c for c in conn.list_collections()}
    assert not count_known(cols["counted"])
    assert cols["counted"].metadata["count_error"] == "ConnectorAuthError"
    assert not count_known(cols["secret"])
    assert conn.read_errors() == [{
        "collection": "secret", "operation": "get_mapping",
        "error_type": "ConnectorAuthError",
        "reason": "the index mapping could not be read, so whether it holds vectors "
                  "is unknown"}]


def test_sdk_errors_map_to_the_taxonomy(fake_module):
    class AuthenticationException(Exception):
        pass

    conn = _conn(host="os")

    def denied(index=None):
        raise AuthenticationException("bad password for admin:hunter2")

    conn._c.indices.get = denied
    with pytest.raises(ConnectorAuthError) as info:
        conn.list_collections()
    assert "hunter2" not in str(info.value)
