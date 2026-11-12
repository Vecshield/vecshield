"""Local accounts, console sign-in, and session handling (ADR 0002)."""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from vecshield_platform.api import create_app  # noqa: E402
from vecshield_platform.api.config_store import ConfigStore  # noqa: E402
from vecshield_platform.api.users import (  # noqa: E402
    AccountGuardError,
    PasswordPolicyError,
    UserStore,
    hash_password,
    verify_password,
)
from vecshield_platform.compliance import AuditLog  # noqa: E402

CSRF = {"X-VecShield-CSRF": "1"}
NEW_ADMIN_PW = "correct horse battery"
ALICE_PW = "alice-initial-pw-1"
ALICE_NEW_PW = "alice-chosen-pw-22"


class Clock:
    def __init__(self, t: float = 1_700_000_000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in ("VECSHIELD_INITIAL_ADMIN_PASSWORD", "VECSHIELD_SESSION_IDLE_MINUTES",
                 "VECSHIELD_SESSION_MAX_HOURS", "VECSHIELD_LOGIN_MAX_ATTEMPTS",
                 "VECSHIELD_LOGIN_LOCKOUT_MINUTES", "VECSHIELD_COOKIE_SECURE",
                 "VECSHIELD_SEPARATION_OF_DUTIES", "VECSHIELD_JWT_SECRET"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def store(clock):
    return UserStore(clock=clock)


@pytest.fixture
def audit():
    return AuditLog()


def _app(store, audit, **kw):
    return create_app(config_store=ConfigStore(), serve_ui=False,
                      user_store=store, audit_log=audit, **kw)


@pytest.fixture
def client(store, audit):
    return TestClient(_app(store, audit))


def _login(c, username="admin", password="admin"):
    return c.post("/auth/login", json={"username": username, "password": password})


def _admin_ready(c):
    """Sign in as the bootstrap admin and complete the forced change."""
    assert _login(c).status_code == 200
    r = c.post("/auth/password", headers=CSRF,
               json={"current_password": "admin", "new_password": NEW_ADMIN_PW})
    assert r.status_code == 200, r.text
    return c


def _actions(audit):
    return [e.action for e in audit.entries]


# ---- store-level ---------------------------------------------------------- #

def test_password_hash_format_and_verify():
    encoded = hash_password("s3cret-password")
    scheme, n, r, p, salt, key = encoded.split("$")
    assert (scheme, n, r, p) == ("scrypt", str(2 ** 14), "8", "1")
    assert verify_password("s3cret-password", encoded)
    assert not verify_password("s3cret-passworD", encoded)
    assert hash_password("s3cret-password") != encoded  # salted
    assert not verify_password("x", "not-a-hash")


def test_bootstrap_creates_single_admin(store, caplog):
    users = store.list_users()
    assert [u.username for u in users] == ["admin"]
    admin = users[0]
    assert admin.roles == ("admin",)
    assert admin.must_change_password is True
    assert admin.created_by == "bootstrap"
    assert store.default_admin_password_active()


def test_bootstrap_logs_warning(caplog, clock):
    with caplog.at_level("WARNING"):
        UserStore(clock=clock)
    assert any("default password" in r.getMessage() for r in caplog.records)


def test_bootstrap_password_from_env(monkeypatch, clock):
    monkeypatch.setenv("VECSHIELD_INITIAL_ADMIN_PASSWORD", "from-env-password-9")
    s = UserStore(clock=clock)
    assert s.authenticate("admin", "from-env-password-9").username == "admin"
    assert not s.default_admin_password_active()


def test_bootstrap_only_when_empty(tmp_path, clock):
    db = tmp_path / "users.db"
    first = UserStore(db, clock=clock)
    first.create_user("alice", ALICE_PW, ["viewer"], created_by="admin")
    first.close()
    second = UserStore(db, clock=clock)
    assert second.bootstrapped is False
    assert {u.username for u in second.list_users()} == {"admin", "alice"}


def test_password_policy(store):
    for bad, msg in [("short", "at least 12"), ("x" * 257, "at most 256"),
                     ("alice.smith1", "username"), ("password1234", "common")]:
        with pytest.raises(PasswordPolicyError, match=msg):
            store.create_user("alice.smith1", bad, ["viewer"], created_by="admin")


def test_username_and_roles_validation(client):
    _admin_ready(client)
    for body in ({"username": "-bad", "password": ALICE_PW, "roles": ["viewer"]},
                 {"username": "a", "password": ALICE_PW, "roles": ["viewer"]},
                 {"username": "alice", "password": ALICE_PW, "roles": []},
                 {"username": "alice", "password": ALICE_PW, "roles": ["root"]}):
        r = client.post("/auth/users", headers=CSRF, json=body)
        assert r.status_code == 400, body
    r = client.post("/auth/users", headers=CSRF,
                    json={"username": "Alice@Example.com", "password": ALICE_PW,
                          "roles": ["viewer"]})
    assert r.status_code == 201
    assert r.json()["user"]["username"] == "alice@example.com"


# ---- sign-in, forced change, cookie --------------------------------------- #

def test_session_before_login(client):
    body = client.get("/auth/session").json()
    assert body == {"login_enabled": True, "authenticated": False, "user": None,
                    "password_policy": {"min_length": 12}}
    assert client.get("/stores").status_code == 401


def test_bootstrap_login_forces_password_change(client, audit):
    r = _login(client)
    assert r.status_code == 200
    user = r.json()["user"]
    assert user == {"username": "admin", "roles": ["admin"],
                    "effective_roles": ["admin", "compliance", "operator", "viewer"],
                    "must_change_password": True, "source": "session"}
    # Every protected endpoint is closed until the password changes.
    for path in ("/stores", "/version", "/auth/users"):
        r = client.get(path)
        assert r.status_code == 403
        assert r.json()["detail"] == "password change required"
    # The session endpoint still answers.
    assert client.get("/auth/session").json()["user"]["must_change_password"] is True

    r = client.post("/auth/password", headers=CSRF,
                    json={"current_password": "admin", "new_password": "admin"})
    assert r.status_code == 400
    r = client.post("/auth/password", headers=CSRF,
                    json={"current_password": "wrong", "new_password": NEW_ADMIN_PW})
    assert r.status_code == 401
    r = client.post("/auth/password", headers=CSRF,
                    json={"current_password": "admin", "new_password": NEW_ADMIN_PW})
    assert r.status_code == 200
    assert r.json()["user"]["must_change_password"] is False
    assert client.get("/stores").status_code == 200
    v = client.get("/version").json()
    assert v["auth_enabled"] is True and v["login_enabled"] is True
    assert v["approvals"]["separation_of_duties"] == "required"
    assert "auth.login" in _actions(audit)
    assert "auth.password_changed" in _actions(audit)
    assert NEW_ADMIN_PW not in str([e.details for e in audit.entries])


def test_cookie_flags(store, audit):
    c = TestClient(_app(store, audit), base_url="https://testserver")
    r = _login(c)
    header = r.headers["set-cookie"]
    lowered = header.lower()
    assert header.startswith("vecshield_session=")
    assert "httponly" in lowered
    assert "samesite=strict" in lowered
    assert "path=/" in lowered
    assert "secure" in lowered
    assert f"max-age={12 * 3600}" in lowered


def test_cookie_not_secure_over_http_unless_forced(store, audit, monkeypatch):
    c = TestClient(_app(store, audit))
    assert "secure" not in _login(c).headers["set-cookie"].lower()
    monkeypatch.setenv("VECSHIELD_COOKIE_SECURE", "1")
    c2 = TestClient(_app(store, audit))
    assert "secure" in _login(c2).headers["set-cookie"].lower()


def test_login_failures_are_generic(client, store, audit):
    store.create_user("alice", ALICE_PW, ["viewer"], created_by="admin")
    for username, password in (("alice", "wrong-password-x"), ("nobody", "whatever"),
                               ("", "")):
        r = _login(client, username, password)
        assert r.status_code == 401
        assert r.json() == {"detail": "invalid username or password"}
    failed = [e for e in audit.entries if e.action == "auth.login_failed"]
    assert [e.actor for e in failed] == ["alice", "unknown", "unknown"]
    # Passwords never reach the audit trail.
    assert "wrong-password-x" not in str([e.details for e in audit.entries])


def test_disabled_user_cannot_login(client, store):
    store.create_user("alice", ALICE_PW, ["viewer"], created_by="admin")
    store.update_user("alice", disabled=True)
    assert _login(client, "alice", ALICE_PW).status_code == 401


def test_logout(client, audit, store):
    _admin_ready(client)
    assert client.get("/stores").status_code == 200
    token = client.cookies.get("vecshield_session")
    assert client.post("/auth/logout").status_code == 403  # CSRF applies
    r = client.post("/auth/logout", headers=CSRF)
    assert r.status_code == 200 and r.json() == {"ok": True}
    assert store.resolve_session(token) is None
    assert client.get("/stores").status_code == 401
    assert client.get("/auth/session").json()["authenticated"] is False
    assert "auth.logout" in _actions(audit)


def test_login_disabled_returns_404(audit):
    c = TestClient(create_app(config_store=ConfigStore(), serve_ui=False, audit_log=audit))
    assert _login(c).status_code == 404


# ---- CSRF ----------------------------------------------------------------- #

def test_csrf_required_for_cookie_unsafe_methods(client):
    _admin_ready(client)
    body = {"username": "bob.ops", "password": "bob-password-123", "roles": ["operator"]}
    r = client.post("/auth/users", json=body)
    assert r.status_code == 403
    assert r.json()["detail"] == "missing CSRF header"
    r = client.post("/auth/users", json=body, headers={"X-VecShield-CSRF": "yes"})
    assert r.status_code == 403
    # Safe methods need no header.
    assert client.get("/auth/users").status_code == 200
    assert client.post("/auth/users", json=body, headers=CSRF).status_code == 201


def test_bearer_requests_are_csrf_exempt(store, audit):
    c = TestClient(_app(store, audit, admin_token="admin-tok"))
    r = c.post("/auth/users", headers={"Authorization": "Bearer admin-tok"},
               json={"username": "bot", "password": "bot-password-123", "roles": ["viewer"]})
    assert r.status_code == 201
    assert r.json()["user"]["created_by"] == "admin"


# ---- lockout -------------------------------------------------------------- #

def test_lockout_after_five_failures(client, store, clock, audit):
    store.create_user("alice", ALICE_PW, ["viewer"], created_by="admin")
    for _ in range(5):
        assert _login(client, "alice", "wrong-password-x").status_code == 401
    r = _login(client, "alice", ALICE_PW)
    assert r.status_code == 429
    assert "try again in 15 minutes" in r.json()["detail"]
    assert int(r.headers["retry-after"]) > 0
    clock.advance(15 * 60 + 1)
    assert _login(client, "alice", ALICE_PW).status_code == 200


def test_success_resets_failure_count(client, store):
    store.create_user("alice", ALICE_PW, ["viewer"], created_by="admin")
    for _ in range(4):
        _login(client, "alice", "wrong-password-x")
    assert _login(client, "alice", ALICE_PW).status_code == 200
    for _ in range(4):
        assert _login(client, "alice", "wrong-password-x").status_code == 401
    assert _login(client, "alice", ALICE_PW).status_code == 200


# ---- session lifetime ----------------------------------------------------- #

def test_session_idle_timeout(client, clock):
    _admin_ready(client)
    clock.advance(59 * 60)
    assert client.get("/stores").status_code == 200  # touches last_seen
    clock.advance(59 * 60)
    assert client.get("/stores").status_code == 200
    clock.advance(61 * 60)
    assert client.get("/stores").status_code == 401
    assert client.get("/auth/session").json()["authenticated"] is False


def test_session_absolute_lifetime(client, clock):
    _admin_ready(client)
    for _ in range(13):  # 13 x 55 min = 11 h 55 min, never idle
        clock.advance(55 * 60)
        assert client.get("/stores").status_code == 200
    clock.advance(10 * 60)  # past the 12 h absolute lifetime
    assert client.get("/stores").status_code == 401


def test_session_token_stored_hashed(store):
    session = store.create_session("admin")
    rows = store._conn.execute("SELECT token_sha256 FROM sessions").fetchall()
    assert [r[0] for r in rows] != [session.token]
    assert len(rows[0][0]) == 64


# ---- user management + roles ---------------------------------------------- #

def test_admin_creates_user_and_roles_are_enforced(store, audit):
    admin = _admin_ready(TestClient(_app(store, audit)))
    r = admin.post("/auth/users", headers=CSRF,
                   json={"username": "alice", "password": ALICE_PW, "roles": ["viewer"]})
    assert r.status_code == 201
    created = r.json()["user"]
    assert created["must_change_password"] is True
    assert created["created_by"] == "admin"
    assert created["roles"] == ["viewer"]
    assert created["created_at"].endswith("Z")
    r = admin.post("/auth/users", headers=CSRF,
                   json={"username": "alice", "password": ALICE_PW, "roles": ["viewer"]})
    assert r.status_code == 409
    listing = admin.get("/auth/users").json()["users"]
    assert {u["username"] for u in listing} == {"admin", "alice"}
    assert set(listing[0]) == {"username", "roles", "disabled", "must_change_password",
                               "created_at", "created_by", "last_login_at"}

    viewer = TestClient(_app(store, audit))
    assert _login(viewer, "alice", ALICE_PW).status_code == 200
    assert viewer.get("/stores").status_code == 403  # must change first
    r = viewer.post("/auth/password", headers=CSRF,
                    json={"current_password": ALICE_PW, "new_password": ALICE_NEW_PW})
    assert r.status_code == 200
    assert viewer.get("/stores").status_code == 200
    assert viewer.get("/auth/users").status_code == 403
    r = viewer.post("/auth/users", headers=CSRF,
                    json={"username": "mallory", "password": "mallory-pw-1234",
                          "roles": ["admin"]})
    assert r.status_code == 403
    assert viewer.post("/admin/stores", headers=CSRF,
                       json={"store_id": "x", "kind": "chroma", "conn": {}}).status_code == 403
    assert "user.created" in _actions(audit)


def test_role_change_applies_to_live_session(store, audit):
    admin = _admin_ready(TestClient(_app(store, audit)))
    store.create_user("alice", ALICE_PW, ["viewer"], created_by="admin")
    store.change_password("alice", ALICE_PW, ALICE_NEW_PW)
    alice = TestClient(_app(store, audit))
    _login(alice, "alice", ALICE_NEW_PW)
    assert alice.get("/auth/users").status_code == 403
    r = admin.patch("/auth/users/alice", headers=CSRF, json={"roles": ["admin"]})
    assert r.status_code == 200 and r.json()["user"]["roles"] == ["admin"]
    assert alice.get("/auth/users").status_code == 200
    assert "user.updated" in _actions(audit)


def test_last_admin_and_self_disable_guards(store, audit):
    admin = _admin_ready(TestClient(_app(store, audit)))
    assert admin.patch("/auth/users/nobody", headers=CSRF,
                       json={"disabled": True}).status_code == 404
    r = admin.patch("/auth/users/admin", headers=CSRF, json={"roles": ["viewer"]})
    assert r.status_code == 409
    assert "last enabled admin" in r.json()["detail"]
    r = admin.patch("/auth/users/admin", headers=CSRF, json={"disabled": True})
    assert r.status_code == 409
    admin.post("/auth/users", headers=CSRF,
               json={"username": "second", "password": "second-admin-pw1",
                     "roles": ["admin"]})
    # Still cannot disable yourself, even with another admin around.
    r = admin.patch("/auth/users/admin", headers=CSRF, json={"disabled": True})
    assert r.status_code == 409
    assert "your own" in r.json()["detail"]
    # With a second admin, demoting yourself is allowed.
    r = admin.patch("/auth/users/admin", headers=CSRF, json={"roles": ["viewer"]})
    assert r.status_code == 200
    # ...and now "second" is the last admin.
    assert admin.get("/auth/users").status_code == 403  # no longer an admin
    with pytest.raises(AccountGuardError):
        store.update_user("second", disabled=True)


def test_disable_revokes_sessions(store, audit):
    admin = _admin_ready(TestClient(_app(store, audit)))
    store.create_user("alice", ALICE_PW, ["viewer"], created_by="admin")
    store.change_password("alice", ALICE_PW, ALICE_NEW_PW)
    alice = TestClient(_app(store, audit))
    _login(alice, "alice", ALICE_NEW_PW)
    assert alice.get("/stores").status_code == 200
    admin.patch("/auth/users/alice", headers=CSRF, json={"disabled": True})
    assert alice.get("/stores").status_code == 401
    assert store.session_count("alice") == 0


def test_reset_revokes_sessions_and_forces_change(store, audit):
    admin = _admin_ready(TestClient(_app(store, audit)))
    store.create_user("alice", ALICE_PW, ["viewer"], created_by="admin")
    store.change_password("alice", ALICE_PW, ALICE_NEW_PW)
    alice = TestClient(_app(store, audit))
    _login(alice, "alice", ALICE_NEW_PW)
    assert alice.get("/stores").status_code == 200
    r = admin.post("/auth/users/alice/password", headers=CSRF,
                   json={"new_password": "short"})
    assert r.status_code == 400
    r = admin.post("/auth/users/alice/password", headers=CSRF,
                   json={"new_password": "reset-by-admin-1"})
    assert r.status_code == 200
    assert r.json()["user"]["must_change_password"] is True
    assert alice.get("/stores").status_code == 401
    assert _login(alice, "alice", ALICE_NEW_PW).status_code == 401
    assert _login(alice, "alice", "reset-by-admin-1").status_code == 200
    assert alice.get("/stores").json()["detail"] == "password change required"
    assert "user.password_reset" in _actions(audit)


def test_password_change_keeps_current_session_only(store, audit, clock):
    a = _admin_ready(TestClient(_app(store, audit)))
    b = TestClient(_app(store, audit))
    assert _login(b, "admin", NEW_ADMIN_PW).status_code == 200
    assert b.get("/stores").status_code == 200
    r = a.post("/auth/password", headers=CSRF,
               json={"current_password": NEW_ADMIN_PW, "new_password": "another-admin-pw-3"})
    assert r.status_code == 200
    assert a.get("/stores").status_code == 200
    assert b.get("/stores").status_code == 401


# ---- self-service sessions ------------------------------------------------ #

def _two_admin_sessions(store, audit):
    a = _admin_ready(TestClient(_app(store, audit), headers={"user-agent": "browser-a"}))
    b = TestClient(_app(store, audit), headers={"user-agent": "browser-b"})
    assert _login(b, "admin", NEW_ADMIN_PW).status_code == 200
    return a, b


def test_list_own_sessions_marks_current_and_hides_hash(store, audit):
    a, b = _two_admin_sessions(store, audit)
    r = a.get("/auth/sessions")
    assert r.status_code == 200
    assert r.headers["cache-control"] == "no-store"
    body = r.json()
    sessions = body["sessions"]
    assert {s["user_agent"] for s in sessions} == {"browser-a", "browser-b"}
    assert set(sessions[0]) == {"id", "created_at", "last_seen_at", "expires_at",
                                "user_agent"}
    assert all(len(s["id"]) == 16 for s in sessions)
    hashes = {row[0] for row in store._conn.execute("SELECT token_sha256 FROM sessions")}
    assert not any(h in r.text for h in hashes)
    current = [s for s in sessions if s["id"] == body["current"]]
    assert [s["user_agent"] for s in current] == ["browser-a"]
    assert b.get("/auth/sessions").json()["current"] != body["current"]


def test_sessions_list_skips_expired(store, audit, clock):
    a, b = _two_admin_sessions(store, audit)
    clock.advance(30 * 60)
    assert a.get("/stores").status_code == 200  # keeps a alive
    clock.advance(31 * 60)
    sessions = a.get("/auth/sessions").json()["sessions"]
    assert [s["user_agent"] for s in sessions] == ["browser-a"]


def test_revoke_one_session(store, audit):
    a, b = _two_admin_sessions(store, audit)
    body = a.get("/auth/sessions").json()
    other = next(s["id"] for s in body["sessions"] if s["id"] != body["current"])
    assert a.delete(f"/auth/sessions/{other}").status_code == 403  # CSRF
    r = a.delete(f"/auth/sessions/{other}", headers=CSRF)
    assert r.status_code == 200 and r.json() == {"ok": True, "current": False}
    assert b.get("/stores").status_code == 401
    assert a.get("/stores").status_code == 200
    entry = [e for e in audit.entries if e.action == "auth.session_revoked"][-1]
    assert entry.actor == "admin" and entry.details["session"] == other
    assert a.delete(f"/auth/sessions/{other}", headers=CSRF).status_code == 404


def test_revoking_current_session_signs_out(store, audit):
    a, _b = _two_admin_sessions(store, audit)
    current = a.get("/auth/sessions").json()["current"]
    r = a.delete(f"/auth/sessions/{current}", headers=CSRF)
    assert r.status_code == 200 and r.json()["current"] is True
    assert "vecshield_session=" in r.headers["set-cookie"]
    assert a.get("/auth/session").json()["authenticated"] is False


def test_revoke_other_sessions(store, audit):
    a, b = _two_admin_sessions(store, audit)
    c = TestClient(_app(store, audit))
    assert _login(c, "admin", NEW_ADMIN_PW).status_code == 200
    assert a.post("/auth/sessions/revoke-others").status_code == 403  # CSRF
    r = a.post("/auth/sessions/revoke-others", headers=CSRF)
    assert r.status_code == 200 and r.json() == {"revoked": 2}
    assert a.get("/stores").status_code == 200
    assert b.get("/stores").status_code == 401
    assert c.get("/stores").status_code == 401
    entry = [e for e in audit.entries if e.action == "auth.sessions_revoked_others"][-1]
    assert entry.details["count"] == 2


def test_cannot_list_or_revoke_another_users_sessions(store, audit):
    admin, _b = _two_admin_sessions(store, audit)
    admin.post("/auth/users", headers=CSRF,
               json={"username": "alice", "password": ALICE_PW, "roles": ["viewer"]})
    alice = TestClient(_app(store, audit))
    assert _login(alice, "alice", ALICE_PW).status_code == 200
    # Forced password change still comes first.
    assert alice.get("/auth/sessions").status_code == 403
    alice.post("/auth/password", headers=CSRF,
               json={"current_password": ALICE_PW, "new_password": ALICE_NEW_PW})
    mine = alice.get("/auth/sessions").json()["sessions"]
    assert len(mine) == 1
    admin_ids = [s["id"] for s in admin.get("/auth/sessions").json()["sessions"]]
    for sid in admin_ids:
        assert alice.delete(f"/auth/sessions/{sid}", headers=CSRF).status_code == 404
    assert alice.post("/auth/sessions/revoke-others",
                      headers=CSRF).json() == {"revoked": 0}
    assert len(admin.get("/auth/sessions").json()["sessions"]) == 2


def test_sessions_need_a_local_session(store, audit):
    c = TestClient(_app(store, audit, auth_token="read-tok", admin_token="admin-tok"))
    assert c.get("/auth/sessions").status_code == 401
    bearer = {"Authorization": "Bearer admin-tok"}
    assert c.get("/auth/sessions", headers=bearer).status_code == 400
    assert c.post("/auth/sessions/revoke-others", headers=bearer).status_code == 400
    assert c.delete("/auth/sessions/0123456789abcdef", headers=bearer).status_code == 400
    open_app = TestClient(create_app(config_store=ConfigStore(), serve_ui=False,
                                     audit_log=audit))
    assert open_app.get("/auth/sessions").status_code == 404


# ---- coexistence with bearer tokens and open mode ------------------------- #

def test_bearer_tokens_still_work_with_login(store, audit):
    c = TestClient(_app(store, audit, auth_token="read-tok", admin_token="admin-tok"))
    assert c.get("/stores").status_code == 401
    assert c.get("/stores", headers={"Authorization": "Bearer read-tok"}).status_code == 200
    s = c.get("/auth/session", headers={"Authorization": "Bearer admin-tok"}).json()
    assert s["authenticated"] is True
    assert s["user"]["source"] == "static" and s["user"]["roles"] == ["admin"]
    s = c.get("/auth/session", headers={"Authorization": "Bearer read-tok"}).json()
    assert s["user"]["roles"] == ["viewer"]
    # A bad bearer is a 401, not the synthetic admin.
    assert c.get("/stores", headers={"Authorization": "Bearer nope"}).status_code == 401
    # Bearer-only callers have no local password to change.
    r = c.post("/auth/password", headers={"Authorization": "Bearer admin-tok"},
               json={"current_password": "x", "new_password": "y" * 12})
    assert r.status_code == 400


def test_login_only_never_uses_open_admin(store, audit):
    c = TestClient(_app(store, audit))
    assert c.get("/version").status_code == 401
    assert c.get("/stores", headers={"Authorization": "Bearer anything"}).status_code == 401


def test_session_endpoint_with_login_disabled():
    c = TestClient(create_app(config_store=ConfigStore(), serve_ui=False))
    body = c.get("/auth/session").json()
    assert body["login_enabled"] is False
    assert body["authenticated"] is True
    assert body["user"]["source"] == "open"
    assert body["user"]["roles"] == ["admin"]
    v = c.get("/version").json()
    assert v["login_enabled"] is False and v["auth_enabled"] is False


def test_session_endpoint_with_static_token_only():
    c = TestClient(create_app(config_store=ConfigStore(), serve_ui=False,
                              admin_token="admin-tok"))
    body = c.get("/auth/session").json()
    assert body["login_enabled"] is False and body["authenticated"] is False
    assert c.post("/auth/logout").json() == {"ok": True}


def test_invalid_cookie_is_unauthenticated_not_error(client):
    client.cookies.set("vecshield_session", "forged-value")
    r = client.get("/auth/session")
    assert r.status_code == 200 and r.json()["authenticated"] is False
    assert client.get("/stores").status_code == 401


def test_session_principal_identity_reaches_audit(store, audit):
    admin = _admin_ready(TestClient(_app(store, audit)))
    admin.post("/auth/users", headers=CSRF,
               json={"username": "carol", "password": "carol-password-1",
                     "roles": ["compliance"]})
    created = [e for e in audit.entries if e.action == "user.created"][0]
    assert created.actor == "admin" and created.target == "carol"
    # The credential type travels with the actor: a JWT can carry sub=admin too.
    assert created.details == {"roles": ["compliance"], "actor_source": "session"}


def test_login_rejects_form_encoded_bodies(client):
    """Sign-in is not header-gated; a cross-site form still cannot post it."""
    r = client.post("/auth/login", data={"username": "admin", "password": "admin"})
    assert r.status_code == 422
    r = client.post("/auth/login", content='{"username":"admin","password":"admin"}',
                    headers={"content-type": "text/plain"})
    assert r.status_code == 422
    assert "set-cookie" not in r.headers
