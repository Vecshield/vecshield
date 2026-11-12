"""Tests for OpenSearch delete_chunks and list_api_keys (live container at :9201)."""

from __future__ import annotations

import pytest


def _check_opensearch() -> bool:
    try:
        import socket
        s = socket.create_connection(("localhost", 9201), timeout=0.5)
        s.close()
        return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not _check_opensearch(),
    reason="OpenSearch container not running at :9201",
)


@pytest.fixture(scope="module")
def os_conn():
    from vecshield_platform.connectors.opensearch import OpenSearchConnector
    conn = OpenSearchConnector(host="localhost", port=9201)
    yield conn
    conn._c.close()


def test_delete_chunks_removes_documents(os_conn):
    """Seed a document, delete it by id, confirm it's gone."""
    idx = "vs-delete-test"
    try:
        os_conn._c.indices.delete(index=idx, ignore_unavailable=True)
        os_conn._c.indices.create(index=idx, body={
            "mappings": {"properties": {
                "content": {"type": "text"},
                "vec": {"type": "knn_vector", "dimension": 2}
            }}
        })
        os_conn._c.index(index=idx, id="del1",
                         body={"content": "test doc", "vec": [0.1, 0.2]})
        os_conn._c.indices.refresh(index=idx)

        n = os_conn.delete_chunks(idx, ["del1"])
        assert n == 1

        os_conn._c.indices.refresh(index=idx)
        count = os_conn._c.count(index=idx).get("count", -1)
        assert count == 0
    finally:
        os_conn._c.indices.delete(index=idx, ignore_unavailable=True)


def test_list_api_keys_raises_when_no_security_plugin(os_conn):
    """OSS OpenSearch without security plugin → UnsupportedCapability."""
    from vecshield_platform.connectors.base import UnsupportedCapability
    with pytest.raises(UnsupportedCapability):
        os_conn.list_api_keys()


def test_delete_and_api_keys_capability_advertised(os_conn):
    caps = os_conn.capabilities()
    assert "delete" in caps
    assert "api_keys" in caps
