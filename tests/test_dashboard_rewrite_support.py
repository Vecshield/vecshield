from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("numpy")

from vecshield_platform.api.config_store import ConfigStore  # noqa: E402
from vecshield_platform.api.state import resolve_state_paths  # noqa: E402
from vecshield_platform.runtime.detectors import BulkVolumeDetector  # noqa: E402


def test_state_dir_places_sqlite_and_audit_under_root(tmp_path):
    paths = resolve_state_paths(tmp_path / "vecshield.json", tmp_path / "state")

    assert paths.legacy is False
    assert paths.history_db == tmp_path / "state" / "sqlite" / "history.db"
    assert paths.alerts_db == tmp_path / "state" / "sqlite" / "alerts.db"
    assert paths.audit_log == tmp_path / "state" / "audit" / "audit.jsonl"
    assert paths.history_db.parent.is_dir()
    assert paths.audit_log.parent.is_dir()


def test_state_paths_remain_legacy_without_state_dir(tmp_path):
    paths = resolve_state_paths(tmp_path / "vecshield.json")

    assert paths.legacy is True
    assert paths.history_db == tmp_path / "vecshield.history.db"
    assert paths.alerts_db == tmp_path / "vecshield.alerts.db"
    assert paths.audit_log == tmp_path / "vecshield.audit.jsonl"


def test_dashboard_dist_is_the_served_ui_root(tmp_path):
    TestClient, create_app = _api_test_tools()
    cfg = ConfigStore(path=str(tmp_path / "config.json"))
    app = create_app(config_store=cfg, serve_ui=True)
    c = TestClient(app)
    try:
        r = c.get("/")
        assert r.status_code == 200
        assert 'src="/static/assets/dashboard.js"' in r.text
        assert 'href="/static/assets/dashboard.css"' in r.text
        assert "Content-Security-Policy" in r.headers

        js = c.get("/static/assets/dashboard.js")
        assert js.status_code == 200
        assert "createElementNS" in js.text
        assert "syncThemeIcon" in js.text

        # The theme is applied by a same-origin script before the stylesheet,
        # so the console never paints the wrong one under script-src 'self'.
        assert 'src="/static/assets/theme.js"' in r.text
        assert r.text.index("/static/assets/theme.js") < r.text.index("/static/assets/dashboard.css")
        theme = c.get("/static/assets/theme.js")
        assert theme.status_code == 200
        assert "javascript" in theme.headers["content-type"]
        assert "prefers-color-scheme" in theme.text
    finally:
        app.state.jobs.shutdown(wait=False)


def test_console_fonts_are_served_as_woff2(tmp_path):
    # Every response carries `nosniff`, so a font served without its type is
    # refused by the browser and the console silently falls back.
    TestClient, create_app = _api_test_tools()
    cfg = ConfigStore(path=str(tmp_path / "config.json"))
    app = create_app(config_store=cfg, serve_ui=True)
    c = TestClient(app)
    try:
        for name in ("inter-latin-var.woff2", "jetbrains-mono-latin-var.woff2"):
            r = c.get(f"/static/assets/fonts/{name}")
            assert r.status_code == 200, name
            assert r.headers["content-type"] == "font/woff2", name
            assert r.content[:4] == b"wOF2", name
    finally:
        app.state.jobs.shutdown(wait=False)


def test_store_connector_open_failure_is_json_not_500(tmp_path):
    TestClient, create_app = _api_test_tools()
    from vecshield_platform.api.registry import StoreRegistry

    reg = StoreRegistry()

    def broken_factory():
        raise ImportError("demo connector dependency missing")

    reg.register("broken", "qdrant", factory=broken_factory)
    app = create_app(reg, serve_ui=False)
    c = TestClient(app)
    try:
        test_response = c.post("/admin/stores/broken/test")
        assert test_response.status_code == 503
        assert "connector unavailable" in test_response.json()["detail"]

        audit_response = c.post("/stores/broken/audit", json={})
        assert audit_response.status_code == 503
        assert "demo connector dependency missing" in audit_response.json()["detail"]
    finally:
        app.state.jobs.shutdown(wait=False)


def test_full_audit_connector_runtime_failure_is_json_not_500():
    TestClient, create_app = _api_test_tools()
    from vecshield_platform.api.registry import StoreRegistry

    class BrokenConnector:
        kind = "broken"

        def describe(self):
            raise RuntimeError("vector database is not reachable")

        def close(self):
            pass

    reg = StoreRegistry()
    reg.register("broken-runtime", "qdrant", factory=BrokenConnector)
    app = create_app(reg, serve_ui=False)
    c = TestClient(app)
    try:
        response = c.post("/stores/broken-runtime/audit", json={})
        assert response.status_code == 400
        assert "audit failed" in response.json()["detail"]
        # Category and type only: a connector's own message can carry a credential.
        assert "RuntimeError" in response.json()["detail"]
        assert "vector database is not reachable" not in response.json()["detail"]
    finally:
        app.state.jobs.shutdown(wait=False)


def test_detector_settings_persist_and_validate(tmp_path):
    path = tmp_path / "config.json"
    cfg = ConfigStore(path=str(path))
    cfg.set_detector_settings(
        bulk_volume={"threshold": 3},
        enumeration={"enabled": False},
        cooldown_s=42,
    )

    reloaded = ConfigStore(path=str(path))
    data = reloaded.get_detector_settings().to_dict()
    assert data["bulk_volume"]["threshold"] == 3
    assert data["enumeration"]["enabled"] is False
    assert data["cooldown_s"] == 42

    with pytest.raises(ValueError):
        cfg.set_detector_settings(collection_sweep={"fraction": 2.0})


def test_customer_support_demo_config_and_manifest_are_loadable(tmp_path):
    demo_dir = Path(__file__).resolve().parent.parent / "examples" / "customer_support_email_demo"
    cfg_path = demo_dir / "stores.qdrant.json"
    manifest_path = demo_dir / "injected_risks_manifest.json"
    points_path = demo_dir / "qdrant_points.jsonl"

    cfg = ConfigStore(path=str(cfg_path))
    stores = list(cfg.stores.values())
    assert stores[0].store_id == "support-email-qdrant"
    assert stores[0].tenant_field == "tenant_id"
    assert len(cfg.policies) >= 5
    assert cfg.get_detector_settings().to_dict()["bulk_volume"]["threshold"] == 5

    manifest = json.loads(manifest_path.read_text())
    assert manifest["synthetic_only"] is True
    assert len(manifest["cases"]) == 10
    assert manifest["primary_subject"]["email"] == "maya.brooks@example-customer.test"

    first_point = json.loads(points_path.read_text().splitlines()[0])
    assert first_point["collection"] == "support_ticket_rag"
    assert len(first_point["vector"]) == 384
    assert "content" in first_point["payload"]


def test_detector_settings_api_rebuilds_runtime_engine(tmp_path):
    TestClient, create_app = _api_test_tools()
    cfg = ConfigStore(path=str(tmp_path / "config.json"))
    app = create_app(config_store=cfg, serve_ui=False)
    c = TestClient(app)
    try:
        r = c.put("/admin/detectors", json={
            "bulk_volume": {"threshold": 2},
            "collection_sweep": {"enabled": False},
            "enumeration": {"enabled": False},
            "rate_baseline": {"enabled": False},
            "cooldown_s": 7,
        })
        assert r.status_code == 200
        assert app.state.runtime_engine.cooldown_s == 7
        assert len(app.state.runtime_engine.detectors) == 1
        assert isinstance(app.state.runtime_engine.detectors[0], BulkVolumeDetector)
        assert app.state.runtime_engine.detectors[0].threshold == 2
    finally:
        app.state.jobs.shutdown(wait=False)


def test_policy_templates_are_enriched_for_dashboard(tmp_path):
    TestClient, create_app = _api_test_tools()
    cfg = ConfigStore(path=str(tmp_path / "config.json"))
    app = create_app(config_store=cfg, serve_ui=False)
    c = TestClient(app)
    try:
        r = c.get("/admin/policy-templates")
        assert r.status_code == 200
        template = r.json()["templates"][0]
        assert "rule" in template
        assert template["rule"] == template["when"]
        assert template["attribution"]["framework"] == template["regulation"]
    finally:
        app.state.jobs.shutdown(wait=False)


def test_version_endpoint_reports_runtime_state(tmp_path):
    TestClient, create_app = _api_test_tools()
    cfg = ConfigStore(path=str(tmp_path / "config.json"))
    app = create_app(config_store=cfg, serve_ui=False)
    c = TestClient(app)
    try:
        r = c.get("/version")
        assert r.status_code == 200
        body = r.json()
        assert body["version"]
        assert body["admin_enabled"] is True
        assert "bulk_volume" in body["detectors"]
    finally:
        app.state.jobs.shutdown(wait=False)


def _api_test_tools():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from vecshield_platform.api import create_app

    return TestClient, create_app
