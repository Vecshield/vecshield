"""Tests for pluggable auth & RBAC (improvement plan 1.1): the auth backends
(static token + HS256 JWT), the role hierarchy, and endpoint gating."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import pytest

from vecshield_platform.api.auth import (
    ADMIN,
    COMPLIANCE,
    OPERATOR,
    VIEWER,
    AuthError,
    CompositeAuthenticator,
    JWTAuthenticator,
    StaticTokenAuthenticator,
    decode_jwt_hs256,
    expand_roles,
    normalize_roles,
)


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_jwt(claims: dict, secret: str, *, alg: str = "HS256") -> str:
    # ``exp`` is required; tests that are not about expiry get an hour.
    if "exp" not in claims:
        claims = {**claims, "exp": time.time() + 3600}
    header = _b64url(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    payload = _b64url(json.dumps(claims).encode())
    signing_input = f"{header}.{payload}".encode("ascii")
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64url(sig)}"


# --------------------------------------------------------------------------- #
# Role hierarchy                                                              #
# --------------------------------------------------------------------------- #

def test_admin_implies_all_roles():
    roles = expand_roles({ADMIN})
    assert roles == {ADMIN, COMPLIANCE, OPERATOR, VIEWER}


def test_compliance_implies_viewer_only():
    assert expand_roles({COMPLIANCE}) == {COMPLIANCE, VIEWER}


def test_normalize_roles_parses_and_filters():
    assert normalize_roles(["admin", "bogus"]) == {"admin"}
    assert normalize_roles("compliance viewer") == {"compliance", "viewer"}
    assert normalize_roles("operator,admin") == {"operator", "admin"}
    assert normalize_roles(None) == set()
    assert normalize_roles(42) == set()


# --------------------------------------------------------------------------- #
# JWT decode                                                                  #
# --------------------------------------------------------------------------- #

def test_decode_jwt_valid():
    tok = make_jwt({"sub": "alice", "roles": ["admin"]}, "s3cret")
    claims = decode_jwt_hs256(tok, "s3cret")
    assert claims["sub"] == "alice"


def test_decode_jwt_bad_signature():
    tok = make_jwt({"sub": "alice"}, "s3cret")
    with pytest.raises(AuthError, match="signature"):
        decode_jwt_hs256(tok, "wrong-secret")


def test_decode_jwt_expired():
    tok = make_jwt({"sub": "a", "exp": time.time() - 3600}, "s3cret")
    with pytest.raises(AuthError, match="expired"):
        decode_jwt_hs256(tok, "s3cret", leeway=0)


def test_decode_jwt_not_yet_valid():
    tok = make_jwt({"sub": "a", "nbf": time.time() + 3600}, "s3cret")
    with pytest.raises(AuthError, match="not yet valid"):
        decode_jwt_hs256(tok, "s3cret", leeway=0)


def test_decode_jwt_wrong_audience():
    tok = make_jwt({"sub": "a", "aud": "other"}, "s3cret")
    with pytest.raises(AuthError, match="audience"):
        decode_jwt_hs256(tok, "s3cret", audience="vecshield")


def test_decode_jwt_wrong_issuer():
    tok = make_jwt({"sub": "a", "iss": "evil"}, "s3cret")
    with pytest.raises(AuthError, match="issuer"):
        decode_jwt_hs256(tok, "s3cret", issuer="okta")


def test_decode_jwt_rejects_non_hs256():
    header = _b64url(json.dumps({"alg": "none"}).encode())
    payload = _b64url(json.dumps({"sub": "a"}).encode())
    tok = f"{header}.{payload}."
    with pytest.raises(AuthError, match="alg"):
        decode_jwt_hs256(tok, "s3cret")


# --------------------------------------------------------------------------- #
# Authenticators                                                              #
# --------------------------------------------------------------------------- #

def test_static_authenticator_admin_and_reader():
    a = StaticTokenAuthenticator("adm", "rdr")
    admin = a.authenticate("Bearer adm")
    reader = a.authenticate("Bearer rdr")
    assert admin.subject == "admin" and admin.has_role(ADMIN)
    assert reader.subject == "reader" and reader.has_role(VIEWER)
    assert not reader.has_role(ADMIN)
    assert a.authenticate("Bearer nope") is None
    assert a.authenticate(None) is None


def test_jwt_authenticator_extracts_subject_and_roles():
    auth = JWTAuthenticator("s3cret")
    tok = make_jwt({"sub": "bob", "roles": ["compliance"]}, "s3cret")
    p = auth.authenticate(f"Bearer {tok}")
    assert p.subject == "bob"
    assert p.has_role(COMPLIANCE) and p.has_role(VIEWER)
    assert not p.has_role(ADMIN)
    assert p.source == "jwt"


def test_jwt_authenticator_defaults_to_viewer():
    auth = JWTAuthenticator("s3cret")
    tok = make_jwt({"sub": "bob"}, "s3cret")  # no roles claim
    p = auth.authenticate(f"Bearer {tok}")
    assert p.roles == {VIEWER}


def test_jwt_authenticator_ignores_non_jwt():
    auth = JWTAuthenticator("s3cret")
    assert auth.authenticate("Bearer opaque-static-token") is None


def test_composite_static_then_jwt():
    tok = make_jwt({"sub": "carol", "roles": ["operator"]}, "s3cret")
    comp = CompositeAuthenticator([
        StaticTokenAuthenticator("adm", "rdr"),
        JWTAuthenticator("s3cret"),
    ])
    assert comp.authenticate("Bearer adm").subject == "admin"
    assert comp.authenticate(f"Bearer {tok}").subject == "carol"
    assert comp.authenticate(None) is None


# --------------------------------------------------------------------------- #
# API endpoint gating                                                         #
# --------------------------------------------------------------------------- #

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from vecshield_platform.api import create_app  # noqa: E402
from vecshield_platform.api.config_store import ConfigStore  # noqa: E402
from vecshield_platform.history import ScanHistory  # noqa: E402

SECRET = "jwt-signing-secret"


@pytest.fixture
def chroma_path(tmp_path):
    import chromadb

    client = chromadb.PersistentClient(path=str(tmp_path / "chroma"))
    col = client.create_collection("prod-kb")
    col.add(ids=["a"], documents=["Email dsar@test.com"],
            embeddings=[[0.1, 0.2]], metadatas=[{"from": "dsar@test.com"}])
    return str(tmp_path / "chroma")


@pytest.fixture
def jwt_client(tmp_path, chroma_path):
    cfg = ConfigStore(path=str(tmp_path / "config.json"))
    app = create_app(config_store=cfg, scan_history=ScanHistory(),
                     admin_token="admin-tok", auth_token="read-tok",
                     jwt_secret=SECRET, serve_ui=False)
    c = TestClient(app)
    # Seed a store using the admin token.
    r = c.post("/admin/stores",
               json={"store_id": "prod", "kind": "chroma",
                     "conn": {"path": chroma_path}},
               headers={"Authorization": "Bearer admin-tok"})
    assert r.status_code == 200
    yield c
    app.state.jobs.shutdown(wait=False)


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_viewer_jwt_can_read_but_not_manage(jwt_client):
    tok = make_jwt({"sub": "viewer-user", "roles": ["viewer"]}, SECRET)
    # read allowed
    assert jwt_client.get("/admin/stores", headers=_auth(tok)).status_code == 200
    # store management denied
    r = jwt_client.delete("/admin/stores/prod", headers=_auth(tok))
    assert r.status_code == 403


def test_compliance_jwt_can_execute_dsar_but_not_manage_stores(jwt_client, monkeypatch):
    monkeypatch.setenv("VECSHIELD_SAFE_MODE", "0")  # execution obeys safe mode
    tok = make_jwt({"sub": "dpo@corp", "roles": ["compliance"]}, SECRET)
    second = make_jwt({"sub": "dpo2@corp", "roles": ["compliance"]}, SECRET)
    # Opening a DSAR is a compliance action.
    r = jwt_client.post("/admin/dsar", json={"subject": "dsar@test.com"},
                        headers=_auth(tok))
    assert r.status_code == 200
    dsar_id = r.json()["id"]
    # Whoever opened it cannot also execute it...
    own = jwt_client.post(f"/admin/dsar/{dsar_id}/execute", json={"verify": True},
                          headers=_auth(tok))
    assert own.status_code == 403
    # ...a second compliance officer can.
    ex = jwt_client.post(f"/admin/dsar/{dsar_id}/execute", json={"verify": True},
                         headers=_auth(second))
    assert ex.status_code == 200
    # ...but cannot manage stores (admin-only).
    d = jwt_client.delete("/admin/stores/prod", headers=_auth(tok))
    assert d.status_code == 403


def test_admin_jwt_has_full_access(jwt_client):
    tok = make_jwt({"sub": "root@corp", "roles": ["admin"]}, SECRET)
    assert jwt_client.get("/admin/stores", headers=_auth(tok)).status_code == 200
    # admin can delete stores
    assert jwt_client.delete("/admin/stores/prod",
                             headers=_auth(tok)).status_code == 200


def test_invalid_jwt_is_rejected(jwt_client):
    bad = make_jwt({"sub": "x", "roles": ["admin"]}, "wrong-secret")
    r = jwt_client.get("/admin/stores", headers=_auth(bad))
    assert r.status_code == 401


def test_subject_is_recorded_in_audit(tmp_path, chroma_path):
    from vecshield_platform.compliance import AuditLog

    cfg = ConfigStore(path=str(tmp_path / "config.json"))
    audit = AuditLog()
    app = create_app(config_store=cfg, scan_history=ScanHistory(),
                     audit_log=audit, admin_token="admin-tok",
                     jwt_secret=SECRET, serve_ui=False)
    c = TestClient(app)
    tok = make_jwt({"sub": "alice@corp", "roles": ["admin"]}, SECRET)
    c.post("/admin/stores",
           json={"store_id": "prod", "kind": "chroma", "conn": {"path": chroma_path}},
           headers=_auth(tok))
    try:
        actors = {e.actor for e in audit.entries}
        assert "alice@corp" in actors
    finally:
        app.state.jobs.shutdown(wait=False)


def test_open_mode_still_works(tmp_path):
    cfg = ConfigStore(path=str(tmp_path / "config.json"))
    app = create_app(config_store=cfg, serve_ui=False)  # no tokens, no jwt
    c = TestClient(app)
    try:
        assert c.get("/admin/stores").status_code == 200
    finally:
        app.state.jobs.shutdown(wait=False)
