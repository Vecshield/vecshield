"""Tests for observability (improvement plan 1.4): structured logging, the
metrics registry, and the /livez, /readyz, /metrics endpoints."""

from __future__ import annotations

import io
import json
import logging

import pytest

from vecshield_platform import metrics
from vecshield_platform.logging_config import (
    JsonFormatter,
    configure_logging,
    get_logger,
)


# --------------------------------------------------------------------------- #
# Metrics registry                                                            #
# --------------------------------------------------------------------------- #

def test_counter_render_and_value():
    reg = metrics.Registry()
    c = reg.counter("thing_total", "A thing.", ["kind"])
    c.inc(kind="a")
    c.inc(2, kind="a")
    c.inc(kind="b")
    assert c.value(kind="a") == 3
    text = reg.render()
    assert "# TYPE thing_total counter" in text
    assert 'thing_total{kind="a"} 3' in text
    assert 'thing_total{kind="b"} 1' in text


def test_counter_rejects_negative():
    c = metrics.Counter("c_total", "c")
    with pytest.raises(ValueError):
        c.inc(-1)


def test_counter_wrong_labels_raise():
    c = metrics.Counter("c_total", "c", ["a"])
    with pytest.raises(ValueError):
        c.inc()  # missing label
    with pytest.raises(ValueError):
        c.inc(a="1", b="2")  # unexpected label


def test_unlabeled_counter_renders_zero():
    reg = metrics.Registry()
    reg.counter("empty_total", "empty")
    assert "empty_total 0" in reg.render()


def test_gauge_up_and_down():
    g = metrics.Gauge("g", "g")
    g.set(5)
    g.inc(2)
    g.inc(-3)
    assert g.value() == 4


def test_histogram_buckets_are_cumulative():
    reg = metrics.Registry()
    h = reg.histogram("dur_seconds", "durations", buckets=(0.1, 1.0))
    h.observe(0.05)
    h.observe(0.5)
    h.observe(10.0)
    text = reg.render()
    assert "# TYPE dur_seconds histogram" in text
    assert 'dur_seconds_bucket{le="0.1"} 1' in text
    assert 'dur_seconds_bucket{le="1"} 2' in text
    assert 'dur_seconds_bucket{le="+Inf"} 3' in text
    assert "dur_seconds_count 3" in text
    assert "dur_seconds_sum 10.55" in text


def test_record_findings_counts_by_severity():
    class F:
        def __init__(self, sev):
            self.severity = sev

    class Sev:
        def __init__(self, v):
            self.value = v

    before = metrics.FINDINGS_TOTAL.value(severity="high")
    metrics.record_findings([F(Sev("high")), F(Sev("high")), F("low")])
    assert metrics.FINDINGS_TOTAL.value(severity="high") == before + 2
    assert metrics.FINDINGS_TOTAL.value(severity="low") >= 1


def test_label_escaping():
    c = metrics.Counter("x_total", "x", ["path"])
    c.inc(path='a"b\\c')
    line = "\n".join(c.render())
    assert 'path="a\\"b\\\\c"' in line


# --------------------------------------------------------------------------- #
# Logging                                                                     #
# --------------------------------------------------------------------------- #

def test_configure_logging_is_idempotent():
    stream = io.StringIO()
    configure_logging("DEBUG", json_format=False, stream=stream)
    configure_logging("DEBUG", json_format=False, stream=stream)
    root = logging.getLogger("vecshield_platform")
    ours = [h for h in root.handlers if getattr(h, "_vecshield_handler", False)]
    assert len(ours) == 1


def test_json_formatter_emits_valid_json():
    record = logging.LogRecord(
        name="vecshield_platform.x", level=logging.INFO, pathname=__file__,
        lineno=1, msg="hello %s", args=("world",), exc_info=None,
    )
    payload = json.loads(JsonFormatter().format(record))
    assert payload["message"] == "hello world"
    assert payload["level"] == "INFO"
    assert payload["logger"] == "vecshield_platform.x"


def test_get_logger_prefixes_under_tree():
    assert get_logger("runtime.engine").name == "vecshield_platform.runtime.engine"
    assert get_logger("vecshield.runtime").name == "vecshield.runtime"


def test_configured_logger_writes_to_stream():
    stream = io.StringIO()
    configure_logging("INFO", json_format=True, stream=stream)
    logging.getLogger("vecshield_platform.test").warning("boom")
    out = stream.getvalue()
    assert '"message": "boom"' in out
    assert '"level": "WARNING"' in out


# --------------------------------------------------------------------------- #
# API endpoints                                                               #
# --------------------------------------------------------------------------- #

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from vecshield_platform.api import create_app  # noqa: E402
from vecshield_platform.api.config_store import ConfigStore  # noqa: E402
from vecshield_platform.history import ScanHistory  # noqa: E402


@pytest.fixture
def chroma_path(tmp_path):
    import chromadb

    client = chromadb.PersistentClient(path=str(tmp_path / "chroma"))
    col = client.create_collection("prod-kb")
    col.add(ids=["a", "b"],
            documents=["contact jane@example.com about the invoice", "benign note"],
            embeddings=[[0.1, 0.2]] * 2,
            metadatas=[{"tenant_id": "t1"}, {"tenant_id": "t2"}])
    return str(tmp_path / "chroma")


@pytest.fixture
def client(tmp_path, chroma_path):
    cfg = ConfigStore(path=str(tmp_path / "config.json"))
    app = create_app(config_store=cfg, scan_history=ScanHistory(), serve_ui=False)
    c = TestClient(app)
    c.post("/admin/stores", json={"store_id": "prod", "kind": "chroma",
                                  "conn": {"path": chroma_path}})
    yield c
    app.state.jobs.shutdown(wait=False)


def test_livez(client):
    r = client.get("/livez")
    assert r.status_code == 200
    assert r.json()["status"] == "alive"


def test_readyz_ready(client):
    r = client.get("/readyz")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ready"
    assert body["checks"]["registry"] == "ok"
    assert body["checks"]["history"] == "ok"


def test_readyz_without_history_reports_disabled(tmp_path, chroma_path):
    cfg = ConfigStore(path=str(tmp_path / "config.json"))
    app = create_app(config_store=cfg, scan_history=None, serve_ui=False)
    c = TestClient(app)
    r = c.get("/readyz")
    assert r.status_code == 200
    assert r.json()["checks"]["history"] == "disabled"
    app.state.jobs.shutdown(wait=False)


def test_metrics_endpoint_exposition(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    assert "vecshield_findings_total" in r.text
    assert "# TYPE vecshield_operation_duration_seconds histogram" in r.text


def test_metrics_reflect_a_scan(client):
    before = metrics.SCANS_TOTAL.value(op="scan")
    r = client.post("/stores/prod/scan")
    assert r.status_code == 200
    assert metrics.SCANS_TOTAL.value(op="scan") == before + 1
    # The scan should have counted at least the PII finding by severity.
    text = client.get("/metrics").text
    assert "vecshield_operations_total" in text


def test_probes_are_unauthenticated(tmp_path, monkeypatch):
    monkeypatch.delenv("VECSHIELD_METRICS_PUBLIC", raising=False)
    cfg = ConfigStore(path=str(tmp_path / "config.json"))
    app = create_app(config_store=cfg, auth_token="secret", serve_ui=False)
    c = TestClient(app)
    assert c.get("/livez").status_code == 200
    assert c.get("/readyz").status_code == 200
    # F8: /metrics needs a credential whenever auth is on...
    assert c.get("/metrics").status_code == 401
    assert c.get("/metrics", headers={"Authorization": "Bearer secret"}).status_code == 200
    # A guarded route still requires the token.
    assert c.get("/stores").status_code == 401
    app.state.jobs.shutdown(wait=False)
