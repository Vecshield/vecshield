"""F5: Redis deletes only keys under the index's own prefixes. F6: OpenAI
File-object deletion is opt-in and the erasure receipt says what happened."""

from __future__ import annotations

import pytest

from vecshield_platform.connectors.redis import RedisConnector, RedisDeleteRefused


class _FT:
    def __init__(self, info):
        self._info = info

    def info(self):
        if isinstance(self._info, Exception):
            raise self._info
        return self._info


class _Pipe:
    def __init__(self, types):
        self._types = types
        self._keys: list[str] = []

    def type(self, key):
        self._keys.append(key)

    def execute(self):
        return [self._types.get(k, b"none") for k in self._keys]


class _FakeRedis:
    def __init__(self, info, types=None):
        self.info = info
        self.types = types or {}
        self.deleted: list[tuple] = []

    def ft(self, index):
        return _FT(self.info)

    def pipeline(self):
        return _Pipe(self.types)

    def delete(self, *keys):
        self.deleted.append(keys)
        return len(keys)


def _conn(fake):
    c = object.__new__(RedisConnector)
    c._r = fake
    c._layout = {}
    c._endpoint = "redis://fake"
    return c


def _info(prefixes, key_type=b"HASH"):
    return {"index_name": b"kb",
            "index_definition": [b"key_type", key_type, b"prefixes", prefixes,
                                 b"default_score", b"1"]}


def test_ids_under_the_index_prefix_are_deleted():
    fake = _FakeRedis(_info([b"doc:", b"kb:"]))
    assert _conn(fake).delete_chunks("kb", ["doc:1", "kb:2"]) == 2
    assert fake.deleted == [("doc:1", "kb:2")]


def test_a_foreign_key_refuses_the_whole_batch():
    fake = _FakeRedis(_info([b"doc:"]))
    with pytest.raises(RedisDeleteRefused) as ei:
        _conn(fake).delete_chunks("kb", ["doc:1", "session:abc", "other:2"])
    assert ei.value.refused == 2 and ei.value.requested == 3
    assert "refused 2 of 3" in str(ei.value) and "doc:" in str(ei.value)
    assert fake.deleted == []


def test_an_unreadable_definition_deletes_nothing():
    fake = _FakeRedis(RuntimeError("NOPERM"))
    with pytest.raises(RedisDeleteRefused, match="could not be read"):
        _conn(fake).delete_chunks("kb", ["doc:1"])
    assert fake.deleted == []


def test_a_definition_without_prefixes_deletes_nothing():
    fake = _FakeRedis({"index_definition": [b"key_type", b"HASH"]})
    with pytest.raises(RedisDeleteRefused, match="no key prefixes"):
        _conn(fake).delete_chunks("kb", ["doc:1"])
    assert fake.deleted == []


def test_dict_shaped_definition_is_understood():
    fake = _FakeRedis({"index_definition": {"key_type": "HASH", "prefixes": ["doc:"]}})
    assert _conn(fake).delete_chunks("kb", ["doc:1"]) == 1


def test_catch_all_prefix_requires_the_index_key_type():
    fake = _FakeRedis(_info([b""]), types={"doc:1": b"hash", "cfg": b"string"})
    with pytest.raises(RedisDeleteRefused, match="not HASH keys"):
        _conn(fake).delete_chunks("kb", ["doc:1", "cfg"])
    assert fake.deleted == []
    assert _conn(fake).delete_chunks("kb", ["doc:1"]) == 1


def test_erasure_records_a_refused_redis_delete_as_an_error():
    """The refusal surfaces as an erasure error, not a silent partial delete."""
    from vecshield_platform.compliance.erasure import ErasureExecution
    fake = _FakeRedis(_info([b"doc:"]))
    execution = ErasureExecution(subject="s", executed_at="now")
    try:
        _conn(fake).delete_chunks("kb", ["x:1"])
    except RedisDeleteRefused as exc:
        execution.errors["kb"] = str(exc)
    assert not execution.ok and "refused 1 of 1" in execution.errors["kb"]


# --------------------------------------------------------------------------- #
# F6: OpenAI                                                                  #
# --------------------------------------------------------------------------- #

class _VSFiles:
    def __init__(self, removed):
        self.removed = removed

    def delete(self, vector_store_id=None, file_id=None):
        self.removed.append(file_id)


class _Files:
    def __init__(self, deleted, fail=()):
        self.deleted = deleted
        self.fail = set(fail)

    def delete(self, fid):
        if fid in self.fail:
            raise RuntimeError("in use")
        self.deleted.append(fid)


def _openai(flag, fail=()):
    from vecshield_platform.connectors.openai_vs import OpenAIVectorStoreConnector
    c = object.__new__(OpenAIVectorStoreConnector)
    removed, deleted = [], []

    class _VS:
        files = _VSFiles(removed)

    class _Client:
        vector_stores = _VS()
        files = _Files(deleted, fail)

    c._c = _Client()
    c._read_errors = []
    c.delete_file_objects = flag
    c._file_deletions = {"attempted": 0, "deleted": 0, "failed": 0}
    return c, removed, deleted


def test_file_objects_are_kept_by_default():
    c, removed, deleted = _openai(False)
    assert c.delete_chunks("KB (vs_1)", ["f1", "f2"]) == 2
    assert removed == ["f1", "f2"] and deleted == []
    notes = c.erasure_notes()
    assert notes["file_objects_deleted"] is False
    assert "not deleted" in notes["statement"] and notes["limitation"]


def test_file_object_deletion_is_opt_in_and_counted():
    c, removed, deleted = _openai(True, fail={"f2"})
    assert c.delete_chunks("vs_1", ["f1", "f2"]) == 2
    assert deleted == ["f1"]
    notes = c.erasure_notes()
    assert notes["file_objects_deleted"] is True
    assert notes["file_object_deletions"] == {"attempted": 2, "deleted": 1, "failed": 1}
    assert "1 of 2" in notes["statement"] and notes["limitation"]


def test_flag_parses_config_strings(monkeypatch):
    pytest.importorskip("openai")
    import openai
    from vecshield_platform.connectors.openai_vs import OpenAIVectorStoreConnector
    monkeypatch.setattr(openai, "OpenAI", lambda api_key=None: object())
    assert OpenAIVectorStoreConnector(api_key="k").delete_file_objects is False
    assert OpenAIVectorStoreConnector(api_key="k", delete_file_objects="true").delete_file_objects
    assert not OpenAIVectorStoreConnector(api_key="k", delete_file_objects="false").delete_file_objects


def test_receipt_states_whether_file_objects_were_deleted(tmp_path, monkeypatch):
    """Through the API: the sealed receipt carries the connector's note and
    its hash still covers every field."""
    pytest.importorskip("fastapi")
    pytest.importorskip("chromadb")
    import hashlib
    import json

    import chromadb
    from fastapi.testclient import TestClient

    from vecshield_platform.api import StoreRegistry, create_app
    from vecshield_platform.compliance import AuditLog
    from vecshield_platform.connectors.chroma import ChromaConnector

    monkeypatch.setenv("VECSHIELD_SAFE_MODE", "0")
    path = str(tmp_path / "chroma")
    chromadb.PersistentClient(path=path).create_collection("support").add(
        ids=["1"], documents=["from jane@example.com"], embeddings=[[0.1, 0.2]],
        metadatas=[{"x": 1}])
    monkeypatch.setattr(ChromaConnector, "erasure_notes", lambda self: {
        "file_objects_deleted": False, "statement": "File objects: not deleted.",
        "limitation": "File objects: not deleted."}, raising=False)
    reg = StoreRegistry()
    reg.register("docs", "chroma", path=path)
    log = AuditLog()
    app = create_app(reg, audit_log=log, serve_ui=False)
    try:
        r = TestClient(app).post("/stores/docs/erasure/execute",
                                 json={"subject": "jane@example.com"})
        assert r.status_code == 200, r.text
        receipt = r.json()["receipt"]
        assert receipt["connector_notes"]["file_objects_deleted"] is False
        assert "File objects: not deleted." in receipt["limitations"]
        body = {k: v for k, v in receipt.items() if k != "receipt_hash"}
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
        assert hashlib.sha256(canonical.encode()).hexdigest() == receipt["receipt_hash"]
        executed = [e for e in log.entries if e.action == "erasure_executed"][-1]
        assert executed.details["connector_notes"]["file_objects_deleted"] is False
    finally:
        app.state.jobs.shutdown(wait=False)
