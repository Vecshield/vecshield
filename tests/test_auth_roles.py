"""Role-split bearer auth: read-only token vs admin token (401/403 separation).

Read routes accept either token; state-changing routes require the admin token.
A single token (no admin token) grants both roles (backward compatible), and no
token at all disables auth (loopback/dev use).
"""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from vecshield_platform.api import create_app  # noqa: E402
from vecshield_platform.api.config_store import ConfigStore  # noqa: E402

ADMIN = {"Authorization": "Bearer admin-tok"}
READ = {"Authorization": "Bearer read-tok"}
BAD = {"Authorization": "Bearer nope"}


@pytest.fixture
def client():
    app = create_app(config_store=ConfigStore(), serve_ui=False,
                     auth_token="read-tok", admin_token="admin-tok")
    return TestClient(app)


# ---- read routes: either token works; missing/bad -> 401 -------------------

def test_healthz_is_open(client):
    assert client.get("/healthz").status_code == 200


def test_reader_and_admin_can_read(client):
    assert client.get("/admin/policies", headers=READ).status_code == 200
    assert client.get("/admin/policies", headers=ADMIN).status_code == 200


def test_read_without_token_is_401(client):
    assert client.get("/admin/policies").status_code == 401


def test_read_with_bad_token_is_401(client):
    assert client.get("/admin/policies", headers=BAD).status_code == 401


# ---- write routes: admin only; reader -> 403; missing/bad -> 401 -----------

def test_admin_can_create_policy(client):
    r = client.post("/admin/policies", json={"template_id": "sec-secrets"},
                    headers=ADMIN)
    assert r.status_code == 200 and r.json()["id"]


def test_reader_cannot_create_policy_403(client):
    r = client.post("/admin/policies", json={"template_id": "sec-secrets"},
                    headers=READ)
    assert r.status_code == 403


def test_write_without_token_is_401(client):
    r = client.post("/admin/policies", json={"template_id": "sec-secrets"})
    assert r.status_code == 401


def test_reader_cannot_patch_policy_but_admin_can(client):
    pid = client.post("/admin/policies", json={"template_id": "sec-secrets"},
                      headers=ADMIN).json()["id"]
    assert client.patch(f"/admin/policies/{pid}", json={"enabled": False},
                        headers=READ).status_code == 403
    assert client.patch(f"/admin/policies/{pid}", json={"enabled": False},
                        headers=ADMIN).status_code == 200


def test_reader_cannot_delete_store_403(client):
    # Auth dependency rejects before the (missing) store is ever looked up.
    assert client.delete("/admin/stores/whatever", headers=READ).status_code == 403
    assert client.delete("/admin/stores/whatever").status_code == 401


def test_erasure_execute_requires_admin(client):
    body = {"subject": "a@b.io"}
    assert client.post("/stores/x/erasure/execute", json=body,
                       headers=READ).status_code == 403
    assert client.post("/stores/x/erasure/execute", json=body).status_code == 401


# ---- backward compatibility ------------------------------------------------

def test_single_token_grants_both_roles():
    app = create_app(config_store=ConfigStore(), serve_ui=False,
                     auth_token="solo")
    c = TestClient(app)
    h = {"Authorization": "Bearer solo"}
    assert c.get("/admin/policies", headers=h).status_code == 200
    assert c.post("/admin/policies", json={"template_id": "sec-secrets"},
                  headers=h).status_code == 200
    assert c.get("/admin/policies").status_code == 401


def test_no_token_disables_auth():
    app = create_app(config_store=ConfigStore(), serve_ui=False)
    c = TestClient(app)
    assert c.get("/admin/policies").status_code == 200
    assert c.post("/admin/policies",
                  json={"template_id": "sec-secrets"}).status_code == 200
