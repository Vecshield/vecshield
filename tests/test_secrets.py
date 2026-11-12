"""Tests for secret handling (improvement plan 1.3): pluggable resolution of
``*_env`` / ``*_file`` references and plaintext-secret rejection."""

from __future__ import annotations

import pytest

from vecshield_platform.api import secrets
from vecshield_platform.api.config_store import ConfigStore, _is_secret_key


# --------------------------------------------------------------------------- #
# Resolver                                                                    #
# --------------------------------------------------------------------------- #

def test_resolve_env(monkeypatch):
    monkeypatch.setenv("VECSHIELD_STORE_PG_PW", "s3cret")
    out = secrets.resolve_conn({"host": "db", "password_env": "VECSHIELD_STORE_PG_PW"})
    assert out == {"host": "db", "password": "s3cret"}


def test_resolve_env_missing_fails_closed(monkeypatch):
    monkeypatch.delenv("VECSHIELD_STORE_NOPE", raising=False)
    with pytest.raises(secrets.SecretResolutionError):
        secrets.resolve_conn({"password_env": "VECSHIELD_STORE_NOPE"})


def test_resolve_file(tmp_path, monkeypatch):
    monkeypatch.setenv("VECSHIELD_SECRET_FILE_ROOTS", str(tmp_path))
    f = tmp_path / "key"
    f.write_text("filekey\n")  # trailing newline should be stripped
    out = secrets.resolve_conn({"api_key_file": str(f)})
    assert out == {"api_key": "filekey"}


def test_resolve_file_missing_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("VECSHIELD_SECRET_FILE_ROOTS", str(tmp_path))
    with pytest.raises(secrets.SecretResolutionError, match="unreadable"):
        secrets.resolve_conn({"token_file": str(tmp_path / "absent")})


def test_is_reference_key():
    assert secrets.is_reference_key("password_env")
    assert secrets.is_reference_key("api_key_file")
    assert not secrets.is_reference_key("password")


def test_register_custom_resolver():
    secrets.register_resolver("_upper", lambda ref: ref.upper())
    try:
        out = secrets.resolve_conn({"token_upper": "abc"})
        assert out == {"token": "ABC"}
    finally:
        secrets._RESOLVERS.pop("_upper", None)
        secrets.REFERENCE_SUFFIXES = tuple(secrets._RESOLVERS.keys())


def test_reference_keys_are_not_treated_as_secret():
    assert not _is_secret_key("password_env")
    assert not _is_secret_key("api_key_file")
    assert _is_secret_key("password")
    assert _is_secret_key("api_key")


# --------------------------------------------------------------------------- #
# ConfigStore integration                                                     #
# --------------------------------------------------------------------------- #

def test_permissive_by_default_allows_plaintext(tmp_path):
    cfg = ConfigStore(path=str(tmp_path / "c.json"))
    assert cfg.reject_plaintext_secrets is False
    # chroma has no secrets; use a kind that accepts an api_key-ish field via conn.
    s = cfg.add_store("s1", "chroma", conn={"path": str(tmp_path / "db"), "token": "raw"})
    assert s.conn["token"] == "raw"


def test_strict_mode_rejects_plaintext_secret(tmp_path):
    cfg = ConfigStore(path=str(tmp_path / "c.json"), reject_plaintext_secrets=True)
    with pytest.raises(ValueError) as ei:
        cfg.add_store("s1", "chroma", conn={"path": "x", "password": "raw"})
    assert "plaintext secret" in str(ei.value)


def test_strict_mode_allows_reference(tmp_path):
    cfg = ConfigStore(path=str(tmp_path / "c.json"), reject_plaintext_secrets=True)
    s = cfg.add_store("s1", "chroma", conn={"path": "x", "password_env": "VECSHIELD_STORE_PG_PW"})
    assert s.conn["password_env"] == "VECSHIELD_STORE_PG_PW"


def test_strict_mode_env_toggle(tmp_path, monkeypatch):
    monkeypatch.setenv("VECSHIELD_REJECT_PLAINTEXT_SECRETS", "1")
    cfg = ConfigStore(path=str(tmp_path / "c.json"))
    assert cfg.reject_plaintext_secrets is True


def test_masked_value_preserved_on_update(tmp_path):
    cfg = ConfigStore(path=str(tmp_path / "c.json"))
    cfg.add_store("s1", "chroma", conn={"path": "x", "password": "raw"})
    # A masked update keeps the prior secret and must not trip the check.
    s = cfg.update_store("s1", kind="chroma", conn={"path": "x", "password": "***"})
    assert s.conn["password"] == "raw"


def test_public_dict_masks_plaintext_but_not_reference(tmp_path):
    cfg = ConfigStore(path=str(tmp_path / "c.json"))
    s = cfg.add_store("s1", "chroma",
                      conn={"path": "x", "token": "raw", "api_key_env": "VECSHIELD_STORE_K"})
    pub = s.public_dict()
    assert pub["conn"]["token"] == "***"
    assert pub["conn"]["api_key_env"] == "VECSHIELD_STORE_K"
