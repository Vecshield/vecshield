"""CLI-level regression tests for the ``vecshield-platform`` commands.

These lock in the behaviour of the fixes wired into the Click CLI:
  * the ``posture`` alias for ``posture-check``
  * ``serve`` refusing to expose an unauthenticated API on a public interface
  * ``monitor-replay`` running the collection-sweep detector when sizes are given
"""
from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from vecshield_platform.cli import cli


def test_posture_alias_registered():
    """`posture` is an alias for `posture-check` (Fix #7)."""
    assert "posture" in cli.commands
    assert "posture-check" in cli.commands
    # Both names resolve to the same underlying command callback.
    assert cli.commands["posture"].callback is cli.commands["posture-check"].callback


def test_serve_refuses_public_bind_without_token(tmp_path):
    """`serve` must not expose an unauthenticated API off loopback (Fix #8).

    Local sign-in counts as authentication, so the guard applies once it is
    turned off.
    """
    config = tmp_path / "config.json"
    result = CliRunner().invoke(
        cli, ["serve", "--config", str(config), "--host", "0.0.0.0", "--no-login"]
    )
    assert result.exit_code == 1
    assert "Refusing to bind" in result.output
    # The guard must fire before any server/config side effects.
    assert not config.exists()


def test_serve_env_can_turn_login_off(monkeypatch, tmp_path):
    monkeypatch.setenv("VECSHIELD_LOGIN", "off")
    config = tmp_path / "config.json"
    result = CliRunner().invoke(
        cli, ["serve", "--config", str(config), "--host", "0.0.0.0"]
    )
    assert result.exit_code == 1
    assert "Refusing to bind" in result.output


STRONG_PASSWORD = "initial-bootstrap-pass-71"


def _stub_uvicorn(monkeypatch):
    import uvicorn

    started = {}
    monkeypatch.setattr(
        uvicorn, "run",
        lambda app, host=None, port=None: started.update(
            host=host, login=app.state.user_store is not None),
    )
    return started


def _serve(tmp_path, host):
    return CliRunner().invoke(cli, [
        "serve", "--config", str(tmp_path / "config.json"),
        "--state-dir", str(tmp_path / "state"), "--host", host,
    ])


def _text(result):
    """The output with Rich's line wrapping undone."""
    return " ".join(result.output.split())


def _users_db(tmp_path):
    return tmp_path / "state" / "sqlite" / "users.db"


@pytest.fixture
def sign_in_env(monkeypatch):
    monkeypatch.delenv("VECSHIELD_LOGIN", raising=False)
    monkeypatch.delenv("VECSHIELD_INITIAL_ADMIN_PASSWORD", raising=False)
    return monkeypatch


def test_serve_with_local_sign_in_creates_accounts(sign_in_env, tmp_path):
    """Local sign-in is on by default: a public bind with an initial password
    starts, and the accounts DB lands in the state dir."""
    sign_in_env.setenv("VECSHIELD_INITIAL_ADMIN_PASSWORD", STRONG_PASSWORD)
    started = _stub_uvicorn(sign_in_env)
    result = _serve(tmp_path, "0.0.0.0")
    assert result.exit_code == 0, result.output
    assert started == {"host": "0.0.0.0", "login": True}
    assert _users_db(tmp_path).exists()
    assert "admin / admin" not in _text(result)
    assert STRONG_PASSWORD not in _text(result)


def test_serve_refuses_public_first_start_with_default_admin(sign_in_env, tmp_path):
    """Without an initial password a public first start would create
    admin / admin; refuse before any account exists."""
    started = _stub_uvicorn(sign_in_env)
    result = _serve(tmp_path, "0.0.0.0")
    assert result.exit_code == 1
    assert "Refusing to bind" in _text(result)
    assert "VECSHIELD_INITIAL_ADMIN_PASSWORD" in _text(result)
    assert started == {}
    assert not _users_db(tmp_path).exists()


@pytest.mark.parametrize("host", ["0.0.0.0", "127.0.0.1"])
@pytest.mark.parametrize("weak", ["admin", "short-pw", "changeme1234"])
def test_serve_refuses_first_start_with_weak_initial_password(
        sign_in_env, tmp_path, weak, host):
    """On any host: the restart check only recognises the password admin, so a
    weak initial password accepted on loopback would pass a later public bind."""
    sign_in_env.setenv("VECSHIELD_INITIAL_ADMIN_PASSWORD", weak)
    started = _stub_uvicorn(sign_in_env)
    result = _serve(tmp_path, host)
    assert result.exit_code == 1
    assert "not an acceptable password" in _text(result)
    assert weak not in _text(result).replace("VECSHIELD_INITIAL_ADMIN_PASSWORD", "")
    assert started == {}
    assert not _users_db(tmp_path).exists()


def test_serve_refusal_survives_markup_in_the_host(sign_in_env, tmp_path):
    started = _stub_uvicorn(sign_in_env)
    result = _serve(tmp_path, "[/x]")
    assert result.exit_code == 1
    assert "Refusing to bind [/x]:8088" in _text(result)
    assert started == {}


def test_serve_refuses_public_restart_while_admin_password_unchanged(sign_in_env, tmp_path):
    """An existing deployment still on admin / admin is refused too, even once
    the initial-password variable is set (it only applies to a first start)."""
    from vecshield_platform.api.users import UserStore

    db = _users_db(tmp_path)
    db.parent.mkdir(parents=True)
    UserStore(db).close()  # bootstrapped with the default password
    sign_in_env.setenv("VECSHIELD_INITIAL_ADMIN_PASSWORD", STRONG_PASSWORD)
    started = _stub_uvicorn(sign_in_env)
    result = _serve(tmp_path, "0.0.0.0")
    assert result.exit_code == 1
    assert "still has the default password" in _text(result)
    assert started == {}


def test_serve_allows_public_restart_once_admin_password_changed(sign_in_env, tmp_path):
    from vecshield_platform.api.users import UserStore

    db = _users_db(tmp_path)
    db.parent.mkdir(parents=True)
    store = UserStore(db)
    store.change_password("admin", "admin", STRONG_PASSWORD)
    store.close()
    started = _stub_uvicorn(sign_in_env)
    result = _serve(tmp_path, "0.0.0.0")
    assert result.exit_code == 0, result.output
    assert started == {"host": "0.0.0.0", "login": True}


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.2", "::1", "localhost"])
def test_serve_allows_loopback_with_default_admin(sign_in_env, tmp_path, host):
    """On loopback the default account is allowed, and still called out."""
    started = _stub_uvicorn(sign_in_env)
    result = _serve(tmp_path, host)
    assert result.exit_code == 0, result.output
    assert started == {"host": host, "login": True}
    assert "admin / admin is still in effect" in _text(result)


def test_serve_allows_loopback_without_token(monkeypatch, tmp_path):
    """Loopback binds stay allowed without a token; uvicorn.run is stubbed out."""
    import uvicorn

    started = {}
    monkeypatch.setattr(
        uvicorn, "run",
        lambda app, host=None, port=None: started.update(host=host, port=port),
    )
    config = tmp_path / "config.json"
    result = CliRunner().invoke(
        cli, ["serve", "--config", str(config), "--host", "127.0.0.1"]
    )
    assert result.exit_code == 0, result.output
    assert started == {"host": "127.0.0.1", "port": 8088}


def test_monitor_replay_collection_sweep(tmp_path):
    """A single principal reading most of a small collection trips the sweep
    detector, which is HIGH severity and exits 2 (Fix #9)."""
    events = tmp_path / "events.jsonl"
    sizes = tmp_path / "sizes.json"

    # Collection "kb" has 10 vectors; one principal pulls 8 distinct ids (80%).
    lines = []
    for i in range(8):
        lines.append(json.dumps({
            "principal": "svc-exfil",
            "collection": "kb",
            "timestamp": 1000.0 + i,
            "result_ids": [f"v{i}"],
        }))
    events.write_text("\n".join(lines) + "\n")
    sizes.write_text(json.dumps({"kb": 10}))

    result = CliRunner().invoke(cli, [
        "monitor-replay",
        "--events", str(events),
        "--sizes", str(sizes),
    ])

    assert result.exit_code == 2, result.output
    assert "COLLECTION_SWEEP" in result.output.upper()
    assert "svc-exfil" in result.output


def test_monitor_replay_no_sizes_skips_sweep(tmp_path):
    """Without --sizes the sweep detector cannot fire (no false positives)."""
    events = tmp_path / "events.jsonl"
    lines = [
        json.dumps({
            "principal": "svc-exfil",
            "collection": "kb",
            "timestamp": 1000.0 + i,
            "result_ids": [f"v{i}"],
        })
        for i in range(8)
    ]
    events.write_text("\n".join(lines) + "\n")

    result = CliRunner().invoke(cli, ["monitor-replay", "--events", str(events)])
    assert result.exit_code == 0, result.output
    assert "COLLECTION_SWEEP" not in result.output.upper()


def test_connector_from_opts_forwards_all_credentials(monkeypatch):
    """Every connector kind now receives its credentials from the CLI.

    ``_connector_from_opts`` must forward the collected options to
    ``build_connector`` untouched (aside from popping ``kind``).
    """
    from vecshield_platform import cli as cli_mod

    captured = {}

    def _fake_build(kind, **kwargs):
        captured["kind"] = kind
        captured["kwargs"] = kwargs
        return object()

    monkeypatch.setattr(cli_mod, "build_connector", _fake_build)

    cli_mod._connector_from_opts({
        "kind": "pinecone", "host": None, "port": None, "path": None,
        "dsn": None, "api_key": "pc-secret", "uri": None, "endpoint": None,
    })

    assert captured["kind"] == "pinecone"
    assert captured["kwargs"]["api_key"] == "pc-secret"
    # kind is consumed, never forwarded as a kwarg.
    assert "kind" not in captured["kwargs"]


def test_connector_from_opts_applies_chroma_defaults(monkeypatch):
    """Bare `--connector chroma` still defaults to localhost:8000 (regression)."""
    from vecshield_platform import cli as cli_mod

    captured = {}
    monkeypatch.setattr(
        cli_mod, "build_connector",
        lambda kind, **kwargs: captured.update(kind=kind, **kwargs) or object(),
    )

    cli_mod._connector_from_opts({"kind": "chroma", "host": None, "path": None, "port": None})

    assert captured["host"] == "localhost"
    assert captured["port"] == 8000


def test_build_connector_splits_tables_string(monkeypatch):
    """A comma-separated --tables string is normalized to a list."""
    from vecshield_platform import connectors as conn_mod

    captured = {}

    class _Capture:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(conn_mod, "get_connector", lambda kind: _Capture)

    conn_mod.build_connector("pgvector", dsn="postgresql://x", tables="a, b ,c")
    assert captured["tables"] == ["a", "b", "c"]


def test_build_connector_keeps_tables_list(monkeypatch):
    """A list --tables value passes through unchanged."""
    from vecshield_platform import connectors as conn_mod

    captured = {}

    class _Capture:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(conn_mod, "get_connector", lambda kind: _Capture)

    conn_mod.build_connector("pgvector", dsn="postgresql://x", tables=["t1", "t2"])
    assert captured["tables"] == ["t1", "t2"]


def test_discover_rejects_non_integer_ports():
    """`discover --ports` reports a clean error instead of a raw ValueError."""
    result = CliRunner().invoke(
        cli, ["discover", "--targets", "127.0.0.1", "--ports", "8000,notaport"]
    )
    assert result.exit_code != 0
    assert "invalid port" in result.output
    assert "notaport" in result.output
