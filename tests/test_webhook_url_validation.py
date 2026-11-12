"""F2: webhook URLs are https-only and never reach internal or metadata
addresses, checked when saved and again at each delivery (DNS rebinding)."""

from __future__ import annotations

import socket

import pytest

from vecshield.models import Severity
from vecshield_platform.api.config_store import ConfigStore
from vecshield_platform.runtime.events import Alert
from vecshield_platform.runtime import sinks as sinks_mod
from vecshield_platform.runtime.sinks import (
    WebhookSink,
    WebhookURLError,
    _generic_payload,
    _no_redirect_opener,
    _pagerduty_payload,
    _slack_payload,
    validate_webhook_url,
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in ("VECSHIELD_ALLOW_HTTP_WEBHOOKS", "VECSHIELD_WEBHOOK_HOST_ALLOW",
                 "VECSHIELD_WEBHOOK_USE_ENV_PROXY"):
        monkeypatch.delenv(name, raising=False)


def _fake_dns(monkeypatch, mapping):
    def fake_getaddrinfo(host, port, *args, **kwargs):
        if host not in mapping:
            raise socket.gaierror("no such host")
        return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM,
                 6, "", (ip, port)) for ip in mapping[host]]
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)


@pytest.mark.parametrize("url", ["ftp://hooks.example.com/x", "file:///etc/passwd",
                                 "gopher://x/", "hooks.example.com/x"])
def test_only_https_schemes(url):
    with pytest.raises(WebhookURLError, match="https"):
        validate_webhook_url(url, resolve=False)


def test_http_needs_explicit_opt_in(monkeypatch):
    with pytest.raises(WebhookURLError, match="VECSHIELD_ALLOW_HTTP_WEBHOOKS"):
        validate_webhook_url("http://hooks.example.com/x", resolve=False)
    monkeypatch.setenv("VECSHIELD_ALLOW_HTTP_WEBHOOKS", "1")
    validate_webhook_url("http://hooks.example.com/x", resolve=False)


@pytest.mark.parametrize("host", [
    "127.0.0.1", "[::1]", "169.254.169.254", "10.0.0.5", "172.16.3.4", "192.168.1.1",
    "[fd00:ec2::254]", "[fe80::1]", "100.100.100.200", "0.0.0.0", "[::ffff:127.0.0.1]",
    "localhost", "api.localhost",
])
def test_internal_literal_hosts_are_refused(host):
    with pytest.raises(WebhookURLError, match="refused|loopback"):
        validate_webhook_url(f"https://{host}/hook", resolve=False)


def test_metadata_is_named(monkeypatch):
    with pytest.raises(WebhookURLError, match="metadata"):
        validate_webhook_url("https://169.254.169.254/latest", resolve=False)


def test_names_resolving_inside_are_refused(monkeypatch):
    _fake_dns(monkeypatch, {"hooks.corp.example": ["10.1.2.3"],
                            "mixed.example": ["93.184.216.34", "127.0.0.1"],
                            "public.example": ["93.184.216.34"]})
    with pytest.raises(WebhookURLError, match="private-network"):
        validate_webhook_url("https://hooks.corp.example/x")
    with pytest.raises(WebhookURLError, match="loopback"):
        validate_webhook_url("https://mixed.example/x")
    validate_webhook_url("https://public.example/x")


def test_unresolvable_name_is_accepted_at_save_but_not_at_delivery(monkeypatch):
    _fake_dns(monkeypatch, {})
    validate_webhook_url("https://not-yet.example/x")
    with pytest.raises(WebhookURLError, match="does not resolve"):
        validate_webhook_url("https://not-yet.example/x", require_resolution=True)


def test_host_allowlist(monkeypatch):
    _fake_dns(monkeypatch, {"alerts.internal.example": ["10.9.9.9"]})
    monkeypatch.setenv("VECSHIELD_WEBHOOK_HOST_ALLOW", ".internal.example, 192.168.50.0/24")
    validate_webhook_url("https://alerts.internal.example/x")
    validate_webhook_url("https://192.168.50.7/x", resolve=False)
    with pytest.raises(WebhookURLError):
        validate_webhook_url("https://192.168.51.7/x", resolve=False)


def test_refusal_never_echoes_the_path_credential():
    with pytest.raises(WebhookURLError) as ei:
        validate_webhook_url("https://10.0.0.1/services/T000/B000/SECRETPATH", resolve=False)
    assert "SECRETPATH" not in str(ei.value)


# --------------------------------------------------------------------------- #
# Save time                                                                   #
# --------------------------------------------------------------------------- #

def test_set_alerting_refuses_internal_and_cleartext_urls(tmp_path, monkeypatch):
    _fake_dns(monkeypatch, {"hooks.slack.com": ["52.1.2.3"]})
    cfg = ConfigStore(str(tmp_path / "c.json"))
    for bad in ("http://hooks.slack.com/x", "https://169.254.169.254/x",
                "https://127.0.0.1:8088/admin/stores"):
        with pytest.raises(ValueError):
            cfg.set_alerting(webhooks=[{"url": bad}])
    assert cfg.alerting.webhooks == []
    cfg.set_alerting(webhooks=[{"url": "https://hooks.slack.com/services/T/B/X"}])
    assert cfg.alerting.webhooks[0]["url"].startswith("https://hooks.slack.com/")


def test_api_refuses_a_metadata_webhook(tmp_path):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from vecshield_platform.api import create_app

    cfg = ConfigStore(str(tmp_path / "c.json"))
    app = create_app(config_store=cfg, serve_ui=False)
    try:
        r = TestClient(app).put("/admin/alerting", json={
            "webhooks": [{"url": "https://169.254.169.254/latest/meta-data/"}]})
        assert r.status_code in (400, 422)
        assert "metadata" in r.json()["detail"]
    finally:
        app.state.jobs.shutdown(wait=False)


def test_stored_legacy_webhook_loads_with_a_warning(tmp_path, caplog):
    import json
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"alerting": {"enabled": True, "webhooks": [
        {"url": "http://10.0.0.8/hook/SECRET", "style": "generic"}]}}))
    with caplog.at_level("WARNING"):
        cfg = ConfigStore(str(path))
    assert cfg.alerting.webhooks  # loading never fails
    text = " ".join(r.getMessage() for r in caplog.records)
    assert "will not receive alerts" in text and "SECRET" not in text


# --------------------------------------------------------------------------- #
# Delivery time                                                               #
# --------------------------------------------------------------------------- #

def _alert():
    return Alert(rule="bulk_volume", severity=Severity.HIGH, principal="svc",
                 timestamp=1.0, message="600 queries in 600s", dedup_key="svc:bulk")


def test_delivery_rechecks_after_dns_rebinding(monkeypatch):
    # Saved while public; now resolves to the metadata service.
    _fake_dns(monkeypatch, {"hooks.example.com": ["169.254.169.254"]})
    errors = []
    sink = WebhookSink("https://hooks.example.com/x", timeout=1.0, on_error=errors.append)
    sink.emit(_alert())
    assert sink.failed == 1 and sink.delivered == 0
    assert isinstance(errors[0], WebhookURLError)


def test_connection_is_pinned_to_the_checked_address(monkeypatch):
    """The socket opens to an address that passed the check, even if a
    second lookup would answer differently (rebinding between check and
    connect)."""
    answers = iter([["93.184.216.34"], ["127.0.0.1"]])

    def rebinding(host, port, *a, **k):
        ips = next(answers)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in ips]

    monkeypatch.setattr(socket, "getaddrinfo", rebinding)
    connected = []
    monkeypatch.setattr(socket, "create_connection",
                        lambda addr, *a, **k: connected.append(addr) or (_ for _ in ()).throw(
                            OSError("stop here")))
    with pytest.raises(OSError, match="stop here"):
        sinks_mod._guarded_create_connection(("hooks.example.com", 443), 1.0)
    assert connected == [("93.184.216.34", 443)]


def test_guarded_connection_refuses_internal_answers(monkeypatch):
    _fake_dns(monkeypatch, {"evil.example": ["10.0.0.1"]})
    with pytest.raises(WebhookURLError, match="at delivery"):
        sinks_mod._guarded_create_connection(("evil.example", 443), 1.0)


def test_opener_has_only_http_handlers():
    import urllib.request
    opener = _no_redirect_opener()
    kinds = {type(h).__mro__[1].__name__ for h in opener.handlers} | \
        {type(h).__name__ for h in opener.handlers}
    assert not any(isinstance(h, (urllib.request.FileHandler, urllib.request.FTPHandler,
                                  urllib.request.DataHandler, urllib.request.ProxyHandler))
                   for h in opener.handlers)
    assert "HTTPSHandler" in kinds and "HTTPHandler" in kinds
    with pytest.raises(urllib.error.URLError):
        opener.open("file:///etc/passwd", timeout=1)


def test_env_proxy_is_opt_in(monkeypatch):
    import urllib.request
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.corp.example:3128")
    assert not any(isinstance(h, urllib.request.ProxyHandler)
                   for h in _no_redirect_opener().handlers)
    monkeypatch.setenv("VECSHIELD_WEBHOOK_USE_ENV_PROXY", "1")
    assert any(isinstance(h, urllib.request.ProxyHandler)
               for h in _no_redirect_opener().handlers)


# --------------------------------------------------------------------------- #
# What an alert carries                                                       #
# --------------------------------------------------------------------------- #

def test_alert_payloads_carry_no_matched_values():
    """Audit alerts carry the policy violation (ids, severity, scope), never
    the matched text; see the security report for F2."""
    from vecshield_platform.compliance.policy import PolicyViolation
    v = PolicyViolation(policy_id="p1", action="alert", severity=Severity.HIGH,
                        description="PII in KB", finding_id="f-1", store="s",
                        collection="kb")
    alert = Alert(rule="policy:p1", severity=Severity.HIGH, principal="audit", timestamp=1.0,
                  message="PII in KB in 's/kb'", dedup_key="audit:s:p1:kb",
                  collection="kb", evidence=v.to_dict())
    for payload in (_slack_payload(alert), _generic_payload(alert),
                    _pagerduty_payload("RK")(alert)):
        text = str(payload)
        assert "matched" not in text and "value" not in text
