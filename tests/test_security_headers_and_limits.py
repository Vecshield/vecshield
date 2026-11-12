"""F8 (headers, streamed body limit, /metrics auth), F10 (audit log mode,
legacy layout warning) and C-8 (exception approval needs a reason)."""

from __future__ import annotations

import os
import stat

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from vecshield_platform.api import create_app  # noqa: E402
from vecshield_platform.api.config_store import ConfigStore  # noqa: E402
from vecshield_platform.api.middleware import DEFAULT_CSP, REPORT_CSP  # noqa: E402


def _app(tmp_path, **kw):
    cfg = ConfigStore(path=str(tmp_path / "config.json"))
    return create_app(config_store=cfg, serve_ui=kw.pop("serve_ui", False), **kw)


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.delenv("VECSHIELD_HSTS", raising=False)
    app = _app(tmp_path)
    yield TestClient(app)
    app.state.jobs.shutdown(wait=False)


# --------------------------------------------------------------------------- #
# Headers                                                                     #
# --------------------------------------------------------------------------- #

def test_json_responses_carry_the_baseline_headers(client):
    r = client.get("/stores")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["content-security-policy"] == DEFAULT_CSP
    assert "strict-transport-security" not in r.headers


def test_errors_and_probes_carry_them_too(client):
    assert client.get("/nope").headers["x-content-type-options"] == "nosniff"
    assert client.get("/healthz").headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in client.get("/stores/x/report").headers[
        "content-security-policy"]


def test_html_reports_get_a_no_script_csp(tmp_path, chroma_store):
    app = _app(tmp_path)
    c = TestClient(app)
    try:
        c.post("/admin/stores", json={"store_id": "prod", "kind": "chroma",
                                      "conn": {"path": chroma_store}})
        r = c.get("/stores/prod/report")
        assert r.status_code == 200 and "text/html" in r.headers["content-type"]
        csp = r.headers["content-security-policy"]
        assert csp == REPORT_CSP
        assert "script-src" not in csp and "default-src 'none'" in csp
    finally:
        app.state.jobs.shutdown(wait=False)


def test_console_keeps_its_own_csp(tmp_path):
    from vecshield_platform.api.app import _DASHBOARD_CSP, _STATIC_DIR
    if not os.path.isdir(_STATIC_DIR):
        pytest.skip("console assets not built")
    app = _app(tmp_path, serve_ui=True)
    try:
        r = TestClient(app).get("/")
        assert r.headers["content-security-policy"] == _DASHBOARD_CSP
        assert r.headers["x-frame-options"] == "DENY"
    finally:
        app.state.jobs.shutdown(wait=False)


def test_api_docs_are_exempt_from_the_csp(client):
    r = client.get("/docs")
    if r.status_code == 404:
        pytest.skip("docs disabled")
    assert "content-security-policy" not in r.headers
    assert r.headers["x-content-type-options"] == "nosniff"


def test_hsts_over_https_or_when_forced(tmp_path, monkeypatch):
    monkeypatch.delenv("VECSHIELD_HSTS", raising=False)
    app = _app(tmp_path)
    try:
        https = TestClient(app, base_url="https://testserver")
        assert "max-age=" in https.get("/healthz").headers["strict-transport-security"]
    finally:
        app.state.jobs.shutdown(wait=False)
    monkeypatch.setenv("VECSHIELD_HSTS", "1")
    forced = _app(tmp_path)
    try:
        assert "strict-transport-security" in TestClient(forced).get("/healthz").headers
    finally:
        forced.state.jobs.shutdown(wait=False)


# --------------------------------------------------------------------------- #
# Body limit: counted, not only declared                                      #
# --------------------------------------------------------------------------- #

def test_chunked_body_without_length_is_cut_off(tmp_path):
    app = _app(tmp_path, max_body_bytes=200)
    c = TestClient(app)
    try:
        def stream():
            payload = b'{"chunks": [{"id": "1", "text": "' + b"a" * 5000 + b'"}]}'
            for i in range(0, len(payload), 100):
                yield payload[i:i + 100]

        r = c.post("/ingest/gate", content=stream(),
                   headers={"content-type": "application/json"})
        assert r.status_code == 413
        assert "too large" in r.json()["detail"]
        assert r.headers["x-content-type-options"] == "nosniff"
    finally:
        app.state.jobs.shutdown(wait=False)


def test_understated_content_length_does_not_bypass_the_count():
    import asyncio

    from vecshield_platform.api.middleware import MaxBodySizeMiddleware

    seen = {}

    async def app(scope, receive, send):
        body = b""
        try:
            while True:
                m = await receive()
                body += m.get("body", b"")
                if not m.get("more_body"):
                    break
        except Exception as exc:  # noqa: BLE001
            seen["error"] = type(exc).__name__
            await send({"type": "http.response.start", "status": 400, "headers": []})
            await send({"type": "http.response.body", "body": b"parse error"})
            return
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    messages = [{"type": "http.request", "body": b"x" * 60, "more_body": True},
                {"type": "http.request", "body": b"x" * 60, "more_body": False}]
    sent = []

    async def receive():
        return messages.pop(0)

    async def send(message):
        sent.append(message)

    mw = MaxBodySizeMiddleware(app, max_bytes=100)
    scope = {"type": "http", "headers": [(b"content-length", b"10")]}
    asyncio.run(mw(scope, receive, send))
    statuses = [m["status"] for m in sent if m["type"] == "http.response.start"]
    assert statuses == [413]  # the app's own 400 was discarded
    assert seen["error"] == "_BodyTooLarge"


def test_small_bodies_still_pass(tmp_path):
    app = _app(tmp_path, max_body_bytes=10_000)
    try:
        r = TestClient(app).post("/ingest/gate", json={"chunks": [{"id": "1", "text": "hi"}]})
        assert r.status_code == 200
    finally:
        app.state.jobs.shutdown(wait=False)


# --------------------------------------------------------------------------- #
# /metrics                                                                    #
# --------------------------------------------------------------------------- #

def test_metrics_need_auth_when_auth_is_on(tmp_path, monkeypatch):
    monkeypatch.delenv("VECSHIELD_METRICS_PUBLIC", raising=False)
    app = _app(tmp_path, auth_token="read", admin_token="admin")
    try:
        c = TestClient(app)
        assert c.get("/metrics").status_code == 401
        assert c.get("/metrics", headers={"Authorization": "Bearer read"}).status_code == 200
    finally:
        app.state.jobs.shutdown(wait=False)


def test_metrics_public_opt_out(tmp_path, monkeypatch):
    monkeypatch.setenv("VECSHIELD_METRICS_PUBLIC", "1")
    app = _app(tmp_path, auth_token="read")
    try:
        assert TestClient(app).get("/metrics").status_code == 200
    finally:
        app.state.jobs.shutdown(wait=False)


# --------------------------------------------------------------------------- #
# F10: audit log file mode and the legacy layout                              #
# --------------------------------------------------------------------------- #

@pytest.mark.skipif(os.name != "posix", reason="POSIX modes")
def test_audit_log_is_created_owner_only(tmp_path):
    from vecshield_platform.compliance import AuditLog
    old = os.umask(0o000)
    try:
        path = tmp_path / "audit.jsonl"
        log = AuditLog.open(str(path))
        log.append("a", "x", "t", {})
        log.close()
    finally:
        os.umask(old)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


@pytest.mark.skipif(os.name != "posix", reason="POSIX modes")
def test_an_existing_world_readable_log_is_tightened(tmp_path, caplog):
    from vecshield_platform.compliance import AuditLog
    path = tmp_path / "audit.jsonl"
    path.write_bytes(b"")
    os.chmod(path, 0o644)
    with caplog.at_level("WARNING"):
        AuditLog.open(str(path)).close()
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert any("readable beyond its owner" in r.getMessage() for r in caplog.records)


def test_legacy_layout_warns(tmp_path, caplog):
    from vecshield_platform.api.state import resolve_state_paths
    with caplog.at_level("WARNING"):
        paths = resolve_state_paths(tmp_path / "vecshield.json")
    assert paths.legacy is True
    assert any("--state-dir" in r.getMessage() for r in caplog.records)
    caplog.clear()
    with caplog.at_level("WARNING"):
        resolve_state_paths(tmp_path / "vecshield.json", tmp_path / "state")
    assert not any("--state-dir" in r.getMessage() for r in caplog.records)


# --------------------------------------------------------------------------- #
# C-8: an exception is approved with a reason                                 #
# --------------------------------------------------------------------------- #

def test_approve_exception_requires_a_reason():
    from vecshield_platform.evidence import EvidenceError, RiskException, approve_exception
    pending = RiskException(id="e1", criterion_id="C", scope="s", rationale="r",
                            requested_by="alice", expires_at="2999-01-01")
    for blank in ("", "   ", "\n"):
        with pytest.raises(EvidenceError, match="needs a reason"):
            approve_exception(pending, approver="bob", reason=blank)
    approved = approve_exception(pending, approver="bob", reason="  Compensating control.  ")
    assert approved.approval_reason == "Compensating control."
    assert approved.to_dict()["approval_reason"] == "Compensating control."
    with pytest.raises(EvidenceError, match="already approved"):
        approve_exception(approved, approver="carol", reason="again")


def test_api_refuses_an_approval_without_a_reason(tmp_path):
    from vecshield_platform.compliance import AuditLog
    from vecshield_platform.history import ScanHistory
    log = AuditLog()
    app = create_app(scan_history=ScanHistory(), audit_log=log, serve_ui=False)
    c = TestClient(app)
    try:
        body = c.post("/compliance/exceptions", json={
            "criterion_id": "HIPAA-1", "scope": "prod", "rationale": "Compensating control.",
            "expires_at": "2999-01-01T00:00:00+00:00"}).json()
        url = f"/compliance/exceptions/{body['id']}/approve"
        for payload in (None, {}, {"reason": ""}, {"reason": "   "}):
            r = c.post(url, json=payload) if payload is not None else c.post(url)
            assert r.status_code == 422, (payload, r.text)
            assert "needs a reason" in str(r.json()["detail"])
        assert c.get("/compliance/exceptions").json()["pending_approval"] == 1
        assert not [e for e in log.entries if e.action == "exception_approved"]
        r = c.post(url, json={"reason": "Vendor fix lands next sprint."})
        assert r.status_code == 200, r.text
        assert r.json()["approval_reason"] == "Vendor fix lands next sprint."
        entry = [e for e in log.entries if e.action == "exception_approved"][-1]
        assert entry.details["reason"] == "Vendor fix lands next sprint."
        listed = c.get("/compliance/exceptions").json()["exceptions"][0]
        assert listed["approval_reason"] == "Vendor fix lands next sprint."
    finally:
        app.state.jobs.shutdown(wait=False)


@pytest.fixture
def chroma_store(tmp_path):
    chromadb = pytest.importorskip("chromadb")
    path = str(tmp_path / "chroma")
    chromadb.PersistentClient(path=path).create_collection("support").add(
        ids=["1"], documents=["hello"], embeddings=[[0.1, 0.2]], metadatas=[{"a": 1}])
    return path
