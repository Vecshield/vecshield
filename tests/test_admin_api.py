"""Admin control-plane tests: config store + admin API + scoped policies."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from vecshield_platform.api import create_app  # noqa: E402
from vecshield_platform.api.config_store import ConfigStore  # noqa: E402


@pytest.fixture
def chroma_path(tmp_path):
    import chromadb

    client = chromadb.PersistentClient(path=str(tmp_path / "chroma"))
    col = client.create_collection("prod-kb")
    col.add(ids=["a", "b"],
            documents=["Leaked AKIAIOSFODNN7EXAMPLE", "benign note"],
            embeddings=[[0.1, 0.2]] * 2,
            metadatas=[{"tenant_id": "t1"}, {"tenant_id": "t2"}])
    return str(tmp_path / "chroma")


@pytest.fixture
def client(tmp_path):
    cfg = ConfigStore(path=str(tmp_path / "config.json"))
    app = create_app(config_store=cfg, serve_ui=False)
    return TestClient(app), cfg


def test_ui_assets_served():
    # serve_ui defaults on; index should be reachable
    app = create_app(config_store=ConfigStore(), serve_ui=True)
    c = TestClient(app)
    r = c.get("/")
    assert r.status_code == 200 and "VecShield" in r.text


def test_add_test_and_audit_store(client, chroma_path):
    c, _ = client
    # add a store via admin API
    r = c.post("/admin/stores", json={
        "store_id": "prod", "kind": "chroma",
        "conn": {"path": chroma_path}, "tenant_field": "tenant_id"})
    assert r.status_code == 200 and r.json()["store_id"] == "prod"

    # secret-free connection echo (path is fine; dsn/password would be masked)
    assert c.get("/admin/stores").json()["stores"][0]["conn"]["path"] == chroma_path

    # test connection -> discovers collections
    t = c.post("/admin/stores/prod/test").json()
    assert t["ok"] and any(col["name"] == "prod-kb" for col in t["collections"])

    # audit the store
    a = c.post("/stores/prod/audit", json={}).json()
    assert a["summary"]["critical"] >= 1


def test_policy_from_template_scoped(client, chroma_path):
    c, cfg = client
    c.post("/admin/stores", json={"store_id": "prod", "kind": "chroma",
                                  "conn": {"path": chroma_path}})
    # instantiate a template scoped to a collection
    r = c.post("/admin/policies", json={
        "template_id": "soc2-injection", "scope_store": "prod",
        "scope_collection": "prod-kb"})
    assert r.status_code == 200
    pol = r.json()
    assert pol["template_id"] == "soc2-injection"
    assert pol["scope_collection"] == "prod-kb"
    # it reaches the runtime as a Policy with collection folded into the matcher
    eff = cfg.effective_policies("prod")
    assert any(p.when.get("collection") == "prod-kb" for p in eff)


def test_policy_from_template_can_be_customized(client, chroma_path):
    c, _ = client
    c.post("/admin/stores", json={"store_id": "prod", "kind": "chroma",
                                  "conn": {"path": chroma_path}})
    r = c.post("/admin/policies", json={
        "template_id": "soc2-injection",
        "name": "Strict prompt injection",
        "description": "Tightened for support data.",
        "severity": "critical",
        "action": "quarantine_and_ticket",
        "when": {"category": "rag_integrity", "min_severity": "medium"},
        "scope_store": "prod",
    })
    assert r.status_code == 200
    pol = r.json()
    assert pol["template_id"] == "soc2-injection"
    assert pol["name"] == "Strict prompt injection"
    assert pol["severity"] == "critical"
    assert pol["action"] == "quarantine_and_ticket"
    assert pol["when"]["min_severity"] == "medium"


def test_disabled_policy_excluded_from_effective(client, chroma_path):
    c, cfg = client
    c.post("/admin/stores", json={"store_id": "prod", "kind": "chroma",
                                  "conn": {"path": chroma_path}})
    pid = c.post("/admin/policies",
                 json={"template_id": "sec-secrets"}).json()["id"]
    assert len(cfg.effective_policies("prod")) == 1
    c.patch(f"/admin/policies/{pid}", json={"enabled": False})
    assert len(cfg.effective_policies("prod")) == 0


def test_full_policy_edit(client, chroma_path):
    """PATCH can edit name/description/when/action/severity, not just enabled."""
    c, cfg = client
    c.post("/admin/stores", json={"store_id": "prod", "kind": "chroma",
                                  "conn": {"path": chroma_path}})
    pid = c.post("/admin/policies", json={
        "name": "orig", "description": "orig desc",
        "when": {"category": "secret"}, "action": "flag",
        "severity": "medium", "scope_store": "prod"}).json()["id"]

    r = c.patch(f"/admin/policies/{pid}", json={
        "name": "renamed", "description": "new desc",
        "when": {"category": "pii"}, "action": "block", "severity": "high"})
    assert r.status_code == 200
    body = r.json()
    assert body["name"] == "renamed"
    assert body["description"] == "new desc"
    assert body["when"] == {"category": "pii"}
    assert body["action"] == "block"
    assert body["severity"] == "high"

    # changes reach the runtime policy view
    eff = cfg.effective_policies("prod")
    assert len(eff) == 1
    assert eff[0].when.get("category") == "pii"
    assert eff[0].action == "block"


def test_patch_unknown_policy_404(client):
    c, _ = client
    r = c.patch("/admin/policies/pol-does-not-exist", json={"enabled": False})
    assert r.status_code == 404


def test_custom_policy_requires_fields(client):
    c, _ = client
    r = c.post("/admin/policies", json={"description": "no name/when/action"})
    assert r.status_code == 422


def test_persistence_across_reload(tmp_path, chroma_path):
    path = str(tmp_path / "config.json")
    cfg = ConfigStore(path=path)
    app = create_app(config_store=cfg, serve_ui=False)
    c = TestClient(app)
    c.post("/admin/stores", json={"store_id": "prod", "kind": "chroma",
                                  "conn": {"path": chroma_path}})
    c.post("/admin/policies", json={"template_id": "ccpa-personal-info"})

    # reload from disk -> same state
    cfg2 = ConfigStore(path=path)
    assert "prod" in cfg2.stores and len(cfg2.policies) == 1


def test_delete_store_cascades_policies(client, chroma_path):
    c, cfg = client
    c.post("/admin/stores", json={"store_id": "prod", "kind": "chroma",
                                  "conn": {"path": chroma_path}})
    c.post("/admin/policies", json={"template_id": "soc2-injection",
                                    "scope_store": "prod"})
    assert len(cfg.policies) == 1
    c.delete("/admin/stores/prod")
    assert len(cfg.policies) == 0 and "prod" not in cfg.stores


def test_get_single_store(client, chroma_path):
    """GET /admin/stores/{id} returns one store, masking secrets."""
    c, _ = client
    c.post("/admin/stores", json={
        "store_id": "prod", "kind": "chroma",
        "conn": {"path": chroma_path, "api_key": "sk-secret"},
        "tenant_field": "tenant_id", "description": "prod kb"})
    r = c.get("/admin/stores/prod")
    assert r.status_code == 200
    body = r.json()
    assert body["store_id"] == "prod"
    assert body["tenant_field"] == "tenant_id"
    assert body["description"] == "prod kb"
    assert body["conn"]["path"] == chroma_path
    assert body["conn"]["api_key"] == "***"   # secret masked

    assert c.get("/admin/stores/nope").status_code == 404


def test_update_store_edits_fields(client, chroma_path):
    """PUT /admin/stores/{id} edits config in place."""
    c, cfg = client
    c.post("/admin/stores", json={"store_id": "prod", "kind": "chroma",
                                  "conn": {"path": chroma_path},
                                  "description": "old"})
    r = c.put("/admin/stores/prod", json={
        "kind": "chroma", "conn": {"path": chroma_path},
        "tenant_field": "org_id", "description": "new"})
    assert r.status_code == 200
    assert r.json()["tenant_field"] == "org_id"
    assert r.json()["description"] == "new"
    assert cfg.stores["prod"].tenant_field == "org_id"

    assert c.put("/admin/stores/nope",
                 json={"kind": "chroma", "conn": {}}).status_code == 404


def test_update_store_preserves_masked_secret(client, chroma_path):
    """A PUT echoing back the '***' mask must not clobber the stored secret."""
    c, cfg = client
    c.post("/admin/stores", json={
        "store_id": "prod", "kind": "chroma",
        "conn": {"path": chroma_path, "api_key": "sk-real"}})
    # client re-submits the masked value it received from GET
    c.put("/admin/stores/prod", json={
        "kind": "chroma", "conn": {"path": chroma_path, "api_key": "***"},
        "description": "edited"})
    assert cfg.stores["prod"].conn["api_key"] == "sk-real"
    assert cfg.stores["prod"].description == "edited"


def test_update_store_preserves_scoped_policies(client, chroma_path):
    """Editing a store keeps its scoped policies."""
    c, cfg = client
    c.post("/admin/stores", json={"store_id": "prod", "kind": "chroma",
                                  "conn": {"path": chroma_path}})
    c.post("/admin/policies", json={"template_id": "soc2-injection",
                                    "scope_store": "prod"})
    assert len(cfg.policies) == 1
    c.put("/admin/stores/prod", json={
        "kind": "chroma", "conn": {"path": chroma_path}, "description": "edited"})
    assert len(cfg.policies) == 1
    assert len(cfg.effective_policies("prod")) == 1


def test_per_store_cve_scan(client, chroma_path):
    """GET /stores/{id}/cves scans only that store's connector kind."""
    c, _ = client
    c.post("/admin/stores", json={"store_id": "prod", "kind": "chroma",
                                  "conn": {"path": chroma_path}})
    r = c.get("/stores/prod/cves?offline=true")
    assert r.status_code == 200
    assert "findings" in r.json()
    # unknown store -> 404
    assert c.get("/stores/nope/cves?offline=true").status_code == 404


def test_secret_masking_in_store_listing(client, monkeypatch):
    c, _ = client
    monkeypatch.setenv("VECSHIELD_STORE_PG_PASSWORD", "secret")
    c.post("/admin/stores", json={
        "store_id": "masked", "kind": "chroma",
        "conn": {"path": "/data/chroma",
                 "dsn": "postgresql://u:secret@h/db",
                 "token": "raw-token",
                 "password_env": "VECSHIELD_STORE_PG_PASSWORD"}})
    stores = c.get("/admin/stores").json()["stores"]
    conn = next(s for s in stores if s["store_id"] == "masked")["conn"]
    assert conn["dsn"] == "***"  # never echo the real DSN
    assert conn["token"] == "***"
    assert conn["password_env"] == "VECSHIELD_STORE_PG_PASSWORD"


def test_unknown_store_kind_rejected_before_persistence(client):
    c, cfg = client
    r = c.post("/admin/stores", json={"store_id": "bad", "kind": "unknown"})
    assert r.status_code == 409
    assert "bad" not in cfg.stores


def test_missing_secret_env_rolls_back_store(client):
    c, cfg = client
    r = c.post("/admin/stores", json={
        "store_id": "pc", "kind": "pinecone",
        "conn": {"api_key_env": "VECSHIELD_STORE_TEST_MISSING_KEY"}})
    assert r.status_code == 400
    assert "environment variable not set" in r.json()["detail"]
    assert "pc" not in cfg.stores


def test_report_get_matches_dashboard_link(client, chroma_path):
    c, _ = client
    c.post("/admin/stores", json={"store_id": "prod", "kind": "chroma",
                                  "conn": {"path": chroma_path}})
    r = c.get("/stores/prod/report")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "VecShield" in r.text
