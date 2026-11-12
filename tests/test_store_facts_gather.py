"""store_facts.gather / summarize / fill_distance_metrics, and the server_info
feature keys the advisory overlay decides applicability on (Redis, MongoDB,
Chroma). Fakes only; no live store."""

from __future__ import annotations

import json
from types import SimpleNamespace

from vecshield_platform import store_facts as sf
from vecshield_platform.connectors.base import ConnectorAuthError, UnsupportedCapability
from vecshield_platform.connectors.chroma import ChromaConnector
from vecshield_platform.connectors.mongodb import MongoDBConnector
from vecshield_platform.connectors.redis import RedisConnector
from vecshield.models import Collection

SECRET = "sk-live-DO-NOT-LEAK-0123456789"


# ------------------------------------------------------------------ gather #

class _Facts:
    """A connector that answers each store fact itself (connector override)."""

    kind = "customkind"

    def __init__(self, **answers):
        self.answers = answers
        self.calls: list[str] = []

    def _answer(self, name):
        self.calls.append(name)
        value = self.answers.get(name)
        if isinstance(value, BaseException):
            raise value
        return value

    def server_info(self):
        return self._answer("server_info")

    def store_location(self):
        return self._answer("store_location")

    def list_aliases(self):
        return self._answer("list_aliases")

    def model_integrations(self):
        return self._answer("model_integrations")


def test_gather_reads_each_fact_once_and_records_failures_without_raising():
    conn = _Facts(
        server_info={"product": "qdrant", "version": "1.13.0", "edition": None,
                     "managed": False, "source": "GET /",
                     "features": {"commit": "abc", "api_key": SECRET}},
        store_location=ConnectorAuthError(f"403 for https://u:{SECRET}@host"),
        list_aliases=UnsupportedCapability("no aliases"),
        model_integrations=RuntimeError(f"boom {SECRET}"))
    facts = sf.gather(conn)
    assert conn.calls == list(sf.FACT_NAMES)
    assert facts.status["server_info"] == {"state": "observed"}
    assert facts.status["store_location"]["state"] == "denied"
    assert facts.status["list_aliases"]["state"] == "unsupported"
    assert facts.status["model_integrations"]["state"] == "error"
    assert facts.get("store_location") is None
    # A reader replays the stored failure, so a consumer classifies it itself.
    try:
        facts.reader("store_location")()
    except ConnectorAuthError:
        pass
    else:  # pragma: no cover
        raise AssertionError("the stored failure was not replayed")
    summary = sf.summarize(facts)
    text = json.dumps(summary)
    assert SECRET not in text
    assert summary["server"]["product"] == "qdrant"
    assert summary["server"]["feature_keys"] == ["api_key", "commit"]  # keys only
    assert "location" not in summary and "aliases" not in summary


def test_summarize_counts_integrations_without_copying_evidence():
    facts = sf.GatheredFacts()
    facts.record("model_integrations", {
        "observable": True, "source": "schema",
        "integrations": [{"collection": "docs", "provider": "openai",
                          "evidence": {"header": SECRET}},
                         {"collection": None, "provider": "cohere"}]})
    facts.record("list_aliases", {"live": "docs_v2"})
    summary = sf.summarize(facts)
    assert summary["model_integrations"] == {"observable": True, "count": 2,
                                             "providers": ["cohere", "openai"],
                                             "source": "schema"}
    assert summary["aliases"] == {"count": 1}
    assert SECRET not in json.dumps(summary)
    assert sf.summarize(None) == {"gathered": False}


def test_fill_distance_metrics_only_fills_missing_and_normalises(monkeypatch):
    cols = [Collection(name="a"), Collection(name="b", distance_metric="dot"),
            Collection(name="c")]
    monkeypatch.setattr(sf, "distance_metric_details", lambda conn: {
        "a": {"metric": "l2"}, "b": {"metric": "cosine"}, "c": {"metric": "hamming"}})
    record = sf.fill_distance_metrics(object(), cols)
    assert [c.distance_metric for c in cols] == ["euclidean", "dot", None]
    assert record == {"state": "observed", "filled": ["a"], "unreported": ["c"]}


def test_fill_distance_metrics_never_raises():
    def boom(conn):
        raise RuntimeError("down")

    cols = [Collection(name="a")]
    import vecshield_platform.store_facts as module

    original = module.distance_metric_details
    module.distance_metric_details = boom
    try:
        record = sf.fill_distance_metrics(object(), cols)
    finally:
        module.distance_metric_details = original
    assert record["state"] == "error" and record["unreported"] == ["a"]
    assert cols[0].distance_metric is None


# ------------------------------------------------------------ Redis feature #

class _Redis:
    def __init__(self, replication=None, config=None, config_exc=None):
        self._replication = replication or {}
        self._config = config
        self._config_exc = config_exc
        self.connection_pool = SimpleNamespace(connection_kwargs={"host": "localhost"})

    def info(self, section=None):
        if section == "replication":
            return dict(self._replication)
        return {"redis_version": "7.4.1"}

    def execute_command(self, *args):
        return []

    def config_get(self, name):
        if self._config_exc:
            raise self._config_exc
        return self._config or {}


def _redis(r):
    c = RedisConnector.__new__(RedisConnector)
    c._r = r
    c._endpoint = "redis://localhost:6379/0"
    return c


def test_redis_replica_read_only_from_replication_then_config():
    replica = sf.server_info(_redis(_Redis(replication={"role": "slave",
                                                        "slave_read_only": 0})))
    assert replica["features"]["replica_read_only"] == "no"
    primary = sf.server_info(_redis(_Redis(replication={"role": "master"},
                                           config={"replica-read-only": "yes"})))
    assert primary["features"]["replica_read_only"] == "yes"
    refused = sf.server_info(_redis(_Redis(replication={"role": "master"},
                                           config_exc=Exception("NOPERM config"))))
    assert "replica_read_only" not in refused["features"]
    assert refused["version"] == "7.4.1"


# ---------------------------------------------------------- MongoDB feature #

class _Admin:
    def __init__(self, answers):
        self.answers = answers

    def command(self, name):
        value = self.answers.get(name)
        if isinstance(value, Exception):
            raise value
        if value is None:
            raise Exception(f"no such command {name}")
        return value


def _mongo(answers):
    c = MongoDBConnector.__new__(MongoDBConnector)
    c._c = SimpleNamespace(admin=_Admin(answers))
    c._endpoint = "localhost:27017"
    c._layout = {}
    return c


def test_mongo_network_compressors_explicit_default_and_refused():
    build = {"version": "7.0.12", "modules": []}
    explicit = sf.server_info(_mongo({"buildInfo": build, "getCmdLineOpts": {
        "argv": ["mongod", "--keyFile", "/etc/secret"],
        "parsed": {"net": {"compression": {"compressors": "snappy,zstd"}},
                   "security": {"keyFile": "/etc/secret"}}}}))
    assert explicit["features"]["network_compressors"] == ["snappy", "zstd"]
    assert "/etc/secret" not in json.dumps(explicit)
    default = sf.server_info(_mongo({"buildInfo": build,
                                     "getCmdLineOpts": {"parsed": {"net": {}}}}))
    assert default["features"]["network_compressors"] == ["snappy", "zstd", "zlib"]
    disabled = sf.server_info(_mongo({"buildInfo": build, "getCmdLineOpts": {
        "parsed": {"net": {"compression": {"compressors": "disabled"}}}}}))
    assert disabled["features"]["network_compressors"] == []
    refused = sf.server_info(_mongo({"buildInfo": build,
                                     "getCmdLineOpts": Exception("not authorized")}))
    assert "network_compressors" not in refused["features"]
    assert refused["version"] == "7.0.12"


# ----------------------------------------------------------- Chroma feature #

class _Chroma:
    def __init__(self, version):
        self.version = version

    def get_version(self):
        return self.version


def _chroma(version, endpoint="http://localhost:8000"):
    c = ChromaConnector.__new__(ChromaConnector)
    c._client = _Chroma(version)
    c._endpoint = endpoint
    return c


def test_chroma_server_implementation_only_where_the_version_settles_it():
    assert sf.server_info(_chroma("0.6.3"))["features"] == {
        "server_implementation": "python"}
    assert sf.server_info(_chroma("1.0.20"))["features"] == {}
    assert sf.server_info(_chroma("0.6.3", "file:///data"))["features"] == {}
