"""Tests for API surface hardening (improvement plan 1.9): ingest payload caps,
body-size limit, per-caller rate limiting, and CORS allow-list."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from vecshield_platform.api import create_app  # noqa: E402
from vecshield_platform.api.app import MAX_INGEST_CHUNKS  # noqa: E402
from vecshield_platform.api.config_store import ConfigStore  # noqa: E402
from vecshield_platform.api.middleware import RateLimiter  # noqa: E402


def _client(tmp_path, **kwargs):
    cfg = ConfigStore(path=str(tmp_path / "config.json"))
    app = create_app(config_store=cfg, serve_ui=False, **kwargs)
    return TestClient(app), app


# --------------------------------------------------------------------------- #
# Ingest payload caps                                                         #
# --------------------------------------------------------------------------- #

def test_ingest_chunk_cap_rejects_oversized_batch(tmp_path):
    c, app = _client(tmp_path)
    chunks = [{"id": str(i), "text": "x"} for i in range(MAX_INGEST_CHUNKS + 1)]
    r = c.post("/ingest/gate", json={"chunks": chunks})
    assert r.status_code == 422
    app.state.jobs.shutdown(wait=False)


def test_ingest_within_cap_ok(tmp_path):
    c, app = _client(tmp_path)
    r = c.post("/ingest/gate", json={"chunks": [{"id": "1", "text": "hi"}]})
    assert r.status_code == 200
    app.state.jobs.shutdown(wait=False)


def test_ingest_text_cap(tmp_path):
    c, app = _client(tmp_path)
    from vecshield_platform.api.app import MAX_CHUNK_TEXT_CHARS
    big = "a" * (MAX_CHUNK_TEXT_CHARS + 1)
    r = c.post("/ingest/gate", json={"chunks": [{"id": "1", "text": big}]})
    assert r.status_code == 422
    app.state.jobs.shutdown(wait=False)


# --------------------------------------------------------------------------- #
# Body-size limit                                                             #
# --------------------------------------------------------------------------- #

def test_body_size_limit_413(tmp_path):
    c, app = _client(tmp_path, max_body_bytes=200)
    payload = {"chunks": [{"id": "1", "text": "a" * 5000}]}
    r = c.post("/ingest/gate", json=payload)
    assert r.status_code == 413
    assert "too large" in r.json()["detail"]
    app.state.jobs.shutdown(wait=False)


def test_body_size_small_request_ok(tmp_path):
    c, app = _client(tmp_path, max_body_bytes=1_000_000)
    r = c.post("/ingest/gate", json={"chunks": [{"id": "1", "text": "hi"}]})
    assert r.status_code == 200
    app.state.jobs.shutdown(wait=False)


# --------------------------------------------------------------------------- #
# Rate limiting                                                               #
# --------------------------------------------------------------------------- #

def test_rate_limiter_unit():
    ticks = [0.0]
    rl = RateLimiter(2, 10.0, clock=lambda: ticks[0])
    assert rl.check("k")[0] is True
    assert rl.check("k")[0] is True
    ok, retry = rl.check("k")
    assert ok is False and retry > 0
    # A different key has its own bucket.
    assert rl.check("other")[0] is True
    # Window rolls over.
    ticks[0] = 11.0
    assert rl.check("k")[0] is True


def test_rate_limit_middleware_429(tmp_path):
    c, app = _client(tmp_path, rate_limit=2)
    assert c.get("/stores").status_code == 200
    assert c.get("/stores").status_code == 200
    r = c.get("/stores")
    assert r.status_code == 429
    assert "retry-after" in {k.lower() for k in r.headers}
    app.state.jobs.shutdown(wait=False)


def test_rate_limit_exempts_probes(tmp_path):
    c, app = _client(tmp_path, rate_limit=1)
    for _ in range(5):
        assert c.get("/livez").status_code == 200
        assert c.get("/healthz").status_code == 200
        assert c.get("/metrics").status_code == 200
    app.state.jobs.shutdown(wait=False)


# --------------------------------------------------------------------------- #
# CORS                                                                        #
# --------------------------------------------------------------------------- #

def test_cors_allows_configured_origin(tmp_path):
    c, app = _client(tmp_path, cors_origins=["https://ui.example.com"])
    r = c.get("/stores", headers={"Origin": "https://ui.example.com"})
    assert r.status_code == 200
    assert r.headers.get("access-control-allow-origin") == "https://ui.example.com"
    app.state.jobs.shutdown(wait=False)


def test_cors_preflight(tmp_path):
    c, app = _client(tmp_path, cors_origins=["https://ui.example.com"])
    r = c.options("/stores", headers={
        "Origin": "https://ui.example.com",
        "Access-Control-Request-Method": "GET",
    })
    assert r.status_code == 200
    assert r.headers.get("access-control-allow-origin") == "https://ui.example.com"
    app.state.jobs.shutdown(wait=False)


def test_no_cors_headers_when_unconfigured(tmp_path):
    c, app = _client(tmp_path)
    r = c.get("/stores", headers={"Origin": "https://evil.example.com"})
    assert "access-control-allow-origin" not in r.headers
    app.state.jobs.shutdown(wait=False)
