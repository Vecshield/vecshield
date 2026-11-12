"""Rate limiting, CORS and JWT hardening (bug hunt authz F6, F9, F11)."""
from __future__ import annotations

import time

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from test_auth import make_jwt  # noqa: E402

from vecshield_platform.api import create_app  # noqa: E402
from vecshield_platform.api.auth import AuthError, JWTAuthenticator  # noqa: E402
from vecshield_platform.api.config_store import ConfigStore  # noqa: E402
from vecshield_platform.api.users import UserStore  # noqa: E402
from vecshield_platform.compliance import AuditLog  # noqa: E402

SECRET = "hardening-secret"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in ("VECSHIELD_CORS_ORIGINS", "VECSHIELD_RATE_LIMIT", "VECSHIELD_JWT_SECRET",
                 "VECSHIELD_JWT_MAX_LIFETIME", "VECSHIELD_INITIAL_ADMIN_PASSWORD"):
        monkeypatch.delenv(name, raising=False)


def _client(**kw):
    app = create_app(config_store=ConfigStore(), serve_ui=False, audit_log=AuditLog(), **kw)
    return TestClient(app), app


# --------------------------------------------------------------------------- #
# Rate limiting                                                               #
# --------------------------------------------------------------------------- #

def test_rotating_junk_authorization_headers_share_the_ip_bucket():
    c, app = _client(admin_token="adm", rate_limit=3)
    try:
        codes = [c.get("/stores", headers={"Authorization": f"Bearer junk-{i}"}).status_code
                 for i in range(6)]
        assert codes[:3] == [401, 401, 401]
        assert codes[3:] == [429, 429, 429]
    finally:
        app.state.jobs.shutdown(wait=False)


def test_a_valid_credential_gets_its_own_bucket():
    c, app = _client(admin_token="adm", rate_limit=2)
    try:
        for i in range(2):
            c.get("/stores", headers={"Authorization": f"Bearer junk-{i}"})
        assert c.get("/stores").status_code == 429  # same IP, no credential
        good = {"Authorization": "Bearer adm"}
        assert [c.get("/stores", headers=good).status_code for _ in range(3)] == [200, 200, 429]
    finally:
        app.state.jobs.shutdown(wait=False)


def test_sign_in_is_always_limited_by_ip():
    c, app = _client(admin_token="adm", rate_limit=2, user_store=UserStore())
    try:
        body = {"username": "admin", "password": "wrong"}
        codes = [c.post("/auth/login", json=body,
                        headers={"Authorization": "Bearer adm"}).status_code
                 for _ in range(3)]
        assert codes[-1] == 429
    finally:
        app.state.jobs.shutdown(wait=False)


# --------------------------------------------------------------------------- #
# CORS                                                                        #
# --------------------------------------------------------------------------- #

def test_wildcard_cors_never_allows_credentials(monkeypatch):
    monkeypatch.setenv("VECSHIELD_CORS_ORIGINS", "*")
    c, app = _client(user_store=UserStore())
    try:
        pre = c.options("/admin/policies", headers={
            "Origin": "https://evil.example", "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "x-vecshield-csrf,content-type"})
        assert pre.headers.get("access-control-allow-credentials") != "true"
        assert pre.headers.get("access-control-allow-origin") in ("*", None)
        simple = c.get("/auth/session", headers={"Origin": "https://evil.example",
                                                 "Cookie": "vecshield_session=x"})
        assert simple.headers.get("access-control-allow-origin") != "https://evil.example"
        assert simple.headers.get("access-control-allow-credentials") != "true"
    finally:
        app.state.jobs.shutdown(wait=False)


def test_explicit_cors_origin_keeps_credentials():
    c, app = _client(cors_origins=["https://ui.example.com"])
    try:
        r = c.get("/auth/session", headers={"Origin": "https://ui.example.com"})
        assert r.headers.get("access-control-allow-origin") == "https://ui.example.com"
        assert r.headers.get("access-control-allow-credentials") == "true"
    finally:
        app.state.jobs.shutdown(wait=False)


# --------------------------------------------------------------------------- #
# JWT                                                                         #
# --------------------------------------------------------------------------- #

def test_jwt_without_exp_or_subject_is_refused():
    c, app = _client(jwt_secret=SECRET, admin_token="adm")
    try:
        no_exp = make_jwt({"sub": "alice", "roles": ["admin"], "exp": None}, SECRET)
        no_sub = make_jwt({"roles": ["admin"]}, SECRET)
        blank_sub = make_jwt({"sub": " ", "roles": ["admin"]}, SECRET)
        for token in (no_exp, no_sub, blank_sub):
            r = c.get("/auth/session", headers={"Authorization": f"Bearer {token}"}).json()
            assert r["authenticated"] is False
            assert c.get("/stores", headers={"Authorization": f"Bearer {token}"}).status_code == 401
        ok = make_jwt({"sub": "alice", "roles": ["viewer"]}, SECRET)
        who = c.get("/auth/session", headers={"Authorization": f"Bearer {ok}"}).json()
        assert who["user"]["username"] == "alice" and who["user"]["source"] == "jwt"
    finally:
        app.state.jobs.shutdown(wait=False)


def test_jwt_max_lifetime(monkeypatch):
    now = time.time()
    auth = JWTAuthenticator(SECRET, max_lifetime_s=3600, leeway=0)
    short = make_jwt({"sub": "a", "iat": now, "exp": now + 1800}, SECRET)
    assert auth.authenticate(f"Bearer {short}").subject == "a"
    long_lived = make_jwt({"sub": "a", "iat": now, "exp": now + 30 * 86400}, SECRET)
    with pytest.raises(AuthError, match="lifetime"):
        auth.authenticate(f"Bearer {long_lived}")
    monkeypatch.setenv("VECSHIELD_JWT_MAX_LIFETIME", "3600")
    c, app = _client(jwt_secret=SECRET)
    try:
        assert c.get("/stores", headers={"Authorization": f"Bearer {long_lived}"}).status_code == 401
        assert c.get("/stores", headers={"Authorization": f"Bearer {short}"}).status_code == 200
    finally:
        app.state.jobs.shutdown(wait=False)


def test_user_management_audit_names_the_credential_type():
    log = AuditLog()
    app = create_app(config_store=ConfigStore(), serve_ui=False, audit_log=log,
                     user_store=UserStore(), jwt_secret=SECRET)
    c = TestClient(app)
    try:
        # A JWT whose subject is "admin" is not the bootstrap account.
        token = make_jwt({"sub": "admin", "roles": ["admin"]}, SECRET)
        r = c.post("/auth/users", headers={"Authorization": f"Bearer {token}"},
                   json={"username": "carol", "password": "carol-password-1",
                         "roles": ["viewer"]})
        assert r.status_code == 201, r.text
        entry = [e for e in log.entries if e.action == "user.created"][-1]
        assert entry.actor == "admin" and entry.details["actor_source"] == "jwt"
    finally:
        app.state.jobs.shutdown(wait=False)
