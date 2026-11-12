"""Qdrant payload writes, against a fake SDK client.

The live-server test (tests/test_qdrant.py) and the container test
(tests/integration/test_qdrant_integration.py) cover the real thing; this covers
the parts that are easy to get silently wrong — the id round-trip and the
merge/verified-count contract — without needing a server.
"""

import pytest

pytest.importorskip("qdrant_client")

from vecshield_platform.connectors.qdrant import (  # noqa: E402
    QdrantConnector, _point_id, _text_key,
)


class _Point:
    def __init__(self, pid, payload=None, vector=None):
        self.id = pid
        self.payload = payload or {}
        self.vector = vector


class _FakeClient:
    """Records calls and models Qdrant's server-side payload merge."""

    def __init__(self, points):
        self.points = {p.id: p for p in points}
        self.set_payload_calls = []
        self.deleted = []

    def retrieve(self, collection_name, ids, with_payload=True, with_vectors=True):
        return [self.points[i] for i in ids if i in self.points]

    def set_payload(self, collection_name, payload, points):
        self.set_payload_calls.append((collection_name, dict(payload), list(points)))
        for pid in points:
            # Qdrant sets the named keys and leaves the rest of the payload.
            self.points[pid].payload.update(payload)

    def delete(self, collection_name, points_selector):
        self.deleted.append(points_selector)

    def close(self):
        pass


def _connector(points, monkeypatch):
    conn = QdrantConnector.__new__(QdrantConnector)
    conn._client = _FakeClient(points)
    conn._endpoint = "http://localhost:6333"
    return conn


# --- the id round-trip -------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("42", 42), (42, 42), ("0", 0),
    ("9f8e7d6c-1234-4321-abcd-000000000001", "9f8e7d6c-1234-4321-abcd-000000000001"),
    ("doc-7", "doc-7"),
])
def test_point_id_restores_the_native_type(raw, expected):
    assert _point_id(raw) == expected


def test_integer_ids_survive_a_write(monkeypatch):
    """iter_chunks stringifies ids; handing "1" back to the SDK would no-op."""
    conn = _connector([_Point(1, {"content": "a"}), _Point(2, {"content": "b"})],
                      monkeypatch)
    changed = conn.set_chunk_metadata("c", {"1": {"vecshield_excluded": True}})

    assert changed == 1
    collection, payload, points = conn._client.set_payload_calls[0]
    assert points == [1]           # int, not "1"
    assert payload == {"vecshield_excluded": True}


def test_write_merges_and_does_not_destroy_customer_metadata(monkeypatch):
    conn = _connector([_Point(1, {"content": "a", "tenant_id": "acme"})], monkeypatch)
    conn.set_chunk_metadata("c", {"1": {"vecshield_sensitivity": "high"}})

    assert conn._client.points[1].payload == {
        "content": "a", "tenant_id": "acme", "vecshield_sensitivity": "high"}


def test_absent_ids_are_not_counted(monkeypatch):
    """A caller must not be told it marked a point that was not there."""
    conn = _connector([_Point(1, {"content": "a"})], monkeypatch)
    changed = conn.set_chunk_metadata("c", {"1": {"x": 1}, "404": {"x": 1}})

    assert changed == 1
    assert all(404 not in points for _, _, points in conn._client.set_payload_calls)


def test_identical_updates_are_written_in_one_call(monkeypatch):
    conn = _connector([_Point(i, {"content": "x"}) for i in (1, 2, 3)], monkeypatch)
    mark = {"vecshield_excluded": True}
    changed = conn.set_chunk_metadata("c", {"1": mark, "2": mark, "3": dict(mark)})

    assert changed == 3
    assert len(conn._client.set_payload_calls) == 1
    assert sorted(conn._client.set_payload_calls[0][2]) == [1, 2, 3]


def test_empty_update_writes_nothing(monkeypatch):
    conn = _connector([_Point(1)], monkeypatch)
    assert conn.set_chunk_metadata("c", {}) == 0
    assert conn._client.set_payload_calls == []


def test_missing_collection_content_returns_zero(monkeypatch):
    conn = _connector([], monkeypatch)
    assert conn.set_chunk_metadata("c", {"1": {"x": 1}}) == 0


# --- redaction ---------------------------------------------------------------

def test_replace_text_writes_the_text_key_and_never_the_vector(monkeypatch):
    conn = _connector([_Point(1, {"content": "secret", "tenant_id": "acme"},
                              vector=[0.1, 0.2])], monkeypatch)
    assert conn.replace_chunk_text("c", "1", "[redacted]") is True

    _, payload, points = conn._client.set_payload_calls[0]
    assert payload == {"content": "[redacted]"}
    assert points == [1]
    assert conn._client.points[1].vector == [0.1, 0.2]   # untouched
    assert conn._client.points[1].payload["tenant_id"] == "acme"


def test_replace_text_on_an_absent_point_is_false_not_an_error(monkeypatch):
    conn = _connector([], monkeypatch)
    assert conn.replace_chunk_text("c", "1", "x") is False


def test_replace_text_refuses_to_invent_a_text_field(monkeypatch):
    from vecshield_platform.connectors.base import UnsupportedCapability
    conn = _connector([_Point(1, {"tenant_id": "acme"})], monkeypatch)
    with pytest.raises(UnsupportedCapability, match="no recognised text field"):
        conn.replace_chunk_text("c", "1", "x")


def test_text_key_prefers_content_over_later_candidates():
    assert _text_key({"body": "b", "content": "c"}) == "content"
    assert _text_key({"tenant": 1}) is None


# --- capability declaration --------------------------------------------------

def test_capabilities_now_include_the_write_verbs(monkeypatch):
    conn = _connector([], monkeypatch)
    assert {"metadata_write", "redact"} <= conn.capabilities()


def test_declared_capabilities_are_all_actually_implemented(monkeypatch):
    """The gate that stops a connector claiming a verb it inherited as a stub."""
    from vecshield_platform.actions import CAPABILITY_METHODS
    from vecshield_platform.connectors.base import Connector

    conn = _connector([], monkeypatch)
    for capability in conn.capabilities():
        name = CAPABILITY_METHODS.get(capability)
        if not name:
            continue
        assert getattr(type(conn), name) is not getattr(Connector, name), (
            f"qdrant declares {capability!r} but inherits {name}()")


def test_redaction_is_not_supported_without_add_chunks(monkeypatch):
    """Redaction copies the original aside first, so it needs ``write`` too.

    Qdrant can replace text but has no add_chunks(), so it must read as
    unsupported at staging rather than halting when the plan runs.
    """
    from vecshield_platform.actions import ACTION_TEMPLATES, capability_verdict

    conn = _connector([], monkeypatch)
    supported, reason = capability_verdict(conn, ACTION_TEMPLATES["redact_text"])
    assert supported is False
    assert "write" in reason


def test_delete_also_restores_native_ids(monkeypatch):
    conn = _connector([_Point(1), _Point(2)], monkeypatch)
    conn.delete_chunks("c", ["1", "2"])
    assert conn._client.deleted[0].points == [1, 2]


def test_get_chunks_addresses_points_directly(monkeypatch):
    conn = _connector([_Point(1, {"content": "a"}, vector=[0.5])], monkeypatch)
    chunks = conn.get_chunks("c", ["1"])
    assert [c.id for c in chunks] == ["1"]
    assert chunks[0].text == "a"
    assert chunks[0].embedding == [0.5]
    assert conn.get_chunks("c", []) == []
