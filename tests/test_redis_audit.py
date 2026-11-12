"""Redis connector against a fake client: JSON indexes, typed vectors, SCAN
enumeration and typed, aliased filters (no Redis Stack needed)."""

from __future__ import annotations

import json
import struct

import pytest

from vecshield_platform.connectors.base import ConnectorAuthError, UnsupportedCapability
from vecshield_platform.connectors.redis import (
    RedisConnector,
    decode_vector,
    encode_vector,
    parse_index_info,
)
from vecshield_platform.coverage import count_known


# ------------------------------------------------------------------ fakes -- #

class _Pipe:
    def __init__(self, r: "_FakeRedis") -> None:
        self._r = r
        self._ops: list[tuple] = []

    def hgetall(self, key):
        self._ops.append(("HGETALL", key))

    def execute_command(self, *args):
        self._ops.append(args)

    def execute(self, raise_on_error=True):
        out = []
        for op in self._ops:
            self._r.commands.append(op)
            key = op[1]
            name = key.decode() if isinstance(key, bytes) else key
            if name in self._r.broken:
                out.append(self._r.broken[name])
            elif op[0] == "HGETALL":
                out.append(dict(self._r.hashes.get(name, {})))
            else:  # JSON.GET key $ paths...
                doc = self._r.docs.get(name)
                if doc is None:
                    out.append(None)
                    continue
                reply = {"$": [doc]}
                for path in op[3:]:
                    reply[path] = [doc[path[2:]]] if path[2:] in doc else []
                out.append(json.dumps(reply).encode())
        return out


class _FT:
    def __init__(self, r: "_FakeRedis", index: str) -> None:
        self._r, self._index = r, index

    def info(self):
        info = self._r.infos[self._index]
        if isinstance(info, Exception):
            raise info
        return info

    def search(self, query, query_params=None):
        self._r.searches.append((query.query_string(), query_params))
        return type("Res", (), {"docs": []})()


class _FakeRedis:
    def __init__(self, infos, *, hashes=None, docs=None, scan_pages=None, broken=None,
                 scan_error=None):
        self.infos = infos
        self.hashes = hashes or {}
        self.docs = docs or {}
        self.scan_pages = scan_pages or {}
        self.broken = broken or {}
        self.scan_error = scan_error
        self.scans: list[dict] = []
        self.searches: list[tuple] = []
        self.commands: list[tuple] = []

    def execute_command(self, *args):
        assert args == ("FT._LIST",)
        return [name.encode() for name in self.infos]

    def ft(self, index):
        return _FT(self, index)

    def scan(self, cursor=0, match=None, count=None, _type=None):
        self.scans.append({"cursor": cursor, "match": match, "count": count, "type": _type})
        if self.scan_error is not None:
            raise self.scan_error
        pages = self.scan_pages[match]
        page = pages[int(cursor)]
        nxt = int(cursor) + 1
        return (nxt if nxt < len(pages) else 0), page

    def pipeline(self, transaction=True):
        return _Pipe(self)


def _conn(fake) -> RedisConnector:
    c = object.__new__(RedisConnector)
    c._r = fake
    c._layout = {}
    c._endpoint = "redis://fake"
    return c


def _hash_info(prefixes=(b"doc:",), data_type=b"FLOAT32", num_docs=b"2", extra=()):
    info = {
        "index_name": b"kb",
        "index_definition": [b"key_type", b"HASH", b"prefixes", list(prefixes),
                             b"default_score", b"1"],
        "attributes": [
            [b"identifier", b"content", b"attribute", b"content", b"type", b"TEXT",
             b"WEIGHT", b"1"],
            [b"identifier", b"tenant_id", b"attribute", b"tenant", b"type", b"TAG",
             b"SEPARATOR", b","],
            [b"identifier", b"year", b"attribute", b"year", b"type", b"NUMERIC"],
            [b"identifier", b"embedding", b"attribute", b"vec", b"type", b"VECTOR",
             b"algorithm", b"FLAT", b"data_type", data_type, b"dim", 2,
             b"distance_metric", b"COSINE"],
            *extra,
        ],
    }
    if num_docs is not None:
        info["num_docs"] = num_docs
    return info


def _json_info():
    return {
        "index_name": "kbj",
        "index_definition": ["key_type", "JSON", "prefixes", ["jdoc:"]],
        "num_docs": "1",
        "attributes": [
            ["identifier", "$.content", "attribute", "content", "type", "TEXT"],
            ["identifier", "$.tenant_id", "attribute", "tenant", "type", "TAG"],
            ["identifier", "$.embedding", "attribute", "embedding", "type", "VECTOR",
             "algorithm", "HNSW", "data_type", "FLOAT32", "dim", 3,
             "distance_metric", "L2"],
        ],
    }


# ------------------------------------------------------- vector codecs -- #

@pytest.mark.parametrize("dtype, values, first_bytes", [
    ("FLOAT32", [1.0, -2.5], struct.pack("<f", 1.0)),
    ("FLOAT64", [1.0, -2.5], struct.pack("<d", 1.0)),
    ("FLOAT16", [1.0, -2.5], b"\x00\x3c"),
    ("BFLOAT16", [1.0, -2.5], b"\x80\x3f"),
    ("INT8", [-1.0, 2.0], b"\xff"),
    ("UINT8", [255.0, 2.0], b"\xff"),
])
def test_vectors_round_trip_by_declared_type_little_endian(dtype, values, first_bytes):
    blob = encode_vector(values, dtype)
    assert blob.startswith(first_bytes)
    assert decode_vector(blob, dtype) == values


def test_bfloat16_decodes_by_shifting_into_float32():
    # 0x3FC0 is bfloat16 1.5; 0xC020 is -2.5.
    assert decode_vector(b"\xc0\x3f\x20\xc0", "BFLOAT16") == [1.5, -2.5]
    # Rounding to nearest: 1.00390625 (between two bfloat16 values) rounds to even.
    assert decode_vector(encode_vector([1.00390625], "BFLOAT16"), "BFLOAT16") == [1.0]


def test_float32_bytes_are_not_misread_as_float16():
    blob = encode_vector([0.5, 0.25], "FLOAT16")
    assert len(blob) == 4
    assert decode_vector(blob, "FLOAT16") == [0.5, 0.25]
    assert decode_vector(blob, "FLOAT32") != [0.5, 0.25]


def test_undecodable_blobs_and_out_of_range_query_vectors():
    assert decode_vector(b"\x00\x00\x00", "FLOAT32") is None
    assert decode_vector("not bytes", "FLOAT32") is None
    with pytest.raises(ValueError):
        encode_vector([300.0], "INT8")
    with pytest.raises(ValueError):
        encode_vector([1e6], "FLOAT16")


# ----------------------------------------------------------- HASH reads -- #

def test_hash_index_reads_float16_vectors_by_declared_type():
    blob = encode_vector([0.5, 0.25], "FLOAT16")
    fake = _FakeRedis({"kb": _hash_info(data_type=b"FLOAT16")},
                      hashes={"doc:1": {b"content": b"hello", b"tenant_id": b"acme",
                                        b"embedding": blob}},
                      scan_pages={"doc:*": [[b"doc:1"]]})
    [chunk] = list(_conn(fake).iter_chunks("kb"))
    assert chunk.embedding == [0.5, 0.25]
    assert chunk.text == "hello"
    assert chunk.metadata == {"tenant_id": "acme"}


def test_scan_enumerates_each_prefix_with_type_and_deduplicates():
    vec = encode_vector([0.1, 0.2], "FLOAT32")
    hashes = {k: {b"content": k.encode(), b"embedding": vec}
              for k in ("doc:1", "doc:2", "doc:a:3")}
    fake = _FakeRedis(
        {"kb": _hash_info(prefixes=(b"doc:", b"doc:a:"))}, hashes=hashes,
        scan_pages={"doc:*": [[b"doc:1", b"doc:2"], [b"doc:2", b"doc:a:3"]],
                    "doc:a:*": [[b"doc:a:3"]]})
    chunks = list(_conn(fake).iter_chunks("kb", batch_size=2))
    assert sorted(c.id for c in chunks) == ["doc:1", "doc:2", "doc:a:3"]
    assert {(s["match"], s["type"], s["count"]) for s in fake.scans} == {
        ("doc:*", "hash", 2), ("doc:a:*", "hash", 2)}
    reads = [op for op in fake.commands if op[0] == "HGETALL"]
    assert len(reads) == 3  # a key returned twice by SCAN is read once


def test_scan_patterns_escape_glob_characters_in_prefixes():
    fake = _FakeRedis({"kb": _hash_info(prefixes=(b"a*b?:",))},
                      scan_pages={r"a\*b\?:*": [[]]})
    assert list(_conn(fake).iter_chunks("kb")) == []
    assert fake.scans[0]["match"] == r"a\*b\?:*"


def test_an_unreadable_key_is_recorded_not_skipped_silently():
    vec = encode_vector([0.1, 0.2], "FLOAT32")
    fake = _FakeRedis({"kb": _hash_info()},
                      hashes={"doc:1": {b"content": b"ok", b"embedding": vec}},
                      broken={"doc:2": RuntimeError("WRONGTYPE secret=1")},
                      scan_pages={"doc:*": [[b"doc:1", b"doc:2", b"doc:gone"]]})
    conn = _conn(fake)
    assert [c.id for c in conn.iter_chunks("kb")] == ["doc:1"]
    [err] = conn.read_errors()
    assert err["collection"] == "kb" and err["item_id"] == "doc:2"
    assert "secret" not in json.dumps(err)


def test_scan_errors_are_mapped_and_recorded():
    pytest.importorskip("redis")
    from redis.exceptions import NoPermissionError

    fake = _FakeRedis({"kb": _hash_info()}, scan_error=NoPermissionError("NOPERM"))
    conn = _conn(fake)
    with pytest.raises(ConnectorAuthError):
        list(conn.iter_chunks("kb"))
    assert conn.read_errors()[0]["collection"] == "kb"


# ----------------------------------------------------------- JSON reads -- #

def test_json_index_is_read_with_json_get_and_attribute_paths():
    doc = {"content": "card 4111 1111 1111 1111", "tenant_id": "acme",
           "embedding": [0.1, 0.2, 0.3], "notes": "free text"}
    fake = _FakeRedis({"kbj": _json_info()}, docs={"jdoc:1": doc},
                      scan_pages={"jdoc:*": [[b"jdoc:1"]]})
    conn = _conn(fake)
    [col] = conn.list_collections()
    assert col.metadata["key_type"] == "JSON" and col.dimension == 3

    [chunk] = list(conn.iter_chunks("kbj"))
    assert chunk.text == doc["content"]
    assert chunk.embedding == [0.1, 0.2, 0.3]
    assert chunk.metadata == {"tenant_id": "acme", "notes": "free text"}
    assert fake.scans[0]["type"] == "ReJSON-RL"
    [op] = [op for op in fake.commands if op[0] == "JSON.GET"]
    assert op[2:] == ("$", "$.embedding", "$.content")
    assert not any(op[0] == "HGETALL" for op in fake.commands)


# --------------------------------------------------------------- counts -- #

def test_missing_num_docs_and_failed_info_are_unknown_counts():
    fake = _FakeRedis({"kb": _hash_info(num_docs=None), "bad": RuntimeError("boom")})
    conn = _conn(fake)
    cols = {c.name: c for c in conn.list_collections()}
    assert count_known(cols["kb"]) is False and count_known(cols["bad"]) is False
    assert [e["collection"] for e in conn.read_errors()] == ["bad"]


# ------------------------------------------------------------- queries -- #

def test_tag_filter_uses_the_alias_and_escapes_the_value():
    pytest.importorskip("redis")
    fake = _FakeRedis({"kb": _hash_info(data_type=b"FLOAT16")})
    _conn(fake).query("kb", [0.5, 0.25], top_k=3, where={"tenant": "acme} | @x:{y"})
    [(qs, params)] = fake.searches
    assert qs.startswith(r"(@tenant:{acme\}\ \|\ \@x\:\{y})=>[KNN 3 @vec $vec AS _score]")
    assert params["vec"] == encode_vector([0.5, 0.25], "FLOAT16")


def test_filter_by_identifier_resolves_to_the_alias():
    pytest.importorskip("redis")
    fake = _FakeRedis({"kb": _hash_info()})
    _conn(fake).query("kb", [0.1, 0.2], where={"tenant_id": "acme"})
    assert fake.searches[0][0].startswith("(@tenant:{acme})")


def test_numeric_filter_uses_range_syntax():
    pytest.importorskip("redis")
    fake = _FakeRedis({"kb": _hash_info()})
    _conn(fake).query("kb", [0.1, 0.2], where={"year": 2024})
    assert fake.searches[0][0].startswith("(@year:[2024 2024])")
    with pytest.raises(ValueError):
        _conn(fake).query("kb", [0.1, 0.2], where={"year": "2024) | (*"})


def test_filters_that_cannot_be_applied_exactly_are_unsupported():
    pytest.importorskip("redis")
    fake = _FakeRedis({"kb": _hash_info()})
    with pytest.raises(UnsupportedCapability):
        _conn(fake).query("kb", [0.1, 0.2], where={"not_indexed": "x"})
    with pytest.raises(UnsupportedCapability):
        _conn(fake).query("kb", [0.1, 0.2], where={"content": "x"})  # TEXT
    assert fake.searches == []


def test_json_alias_with_punctuation_is_escaped():
    pytest.importorskip("redis")
    info = parse_index_info({
        "index_definition": ["key_type", "JSON", "prefixes", ["j:"]],
        "attributes": [["identifier", "$.t", "attribute", "$.t", "type", "TAG"],
                       ["identifier", "$.v", "attribute", "$.v", "type", "VECTOR",
                        "data_type", "FLOAT32", "dim", 2]]})
    fake = _FakeRedis({"kbj": info})
    conn = _conn(fake)
    conn._layout["kbj"] = info
    conn.query("kbj", [0.1, 0.2], where={"t": "a"})
    assert fake.searches[0][0].startswith(r"(@\$\.t:{a})=>[KNN 10 @\$\.v $vec")


def test_resp3_dict_attributes_are_parsed():
    info = parse_index_info({
        "index_definition": {"key_type": "HASH", "prefixes": ["d:"]},
        "num_docs": 5,
        "attributes": [{"identifier": "emb", "attribute": "emb", "type": "VECTOR",
                        "data_type": "INT8", "dim": 8, "flags": []}]})
    assert info["vec"]["data_type"] == "INT8" and info["dim"] == 8
    assert info["num"] == 5 and info["prefixes"] == ["d:"]
