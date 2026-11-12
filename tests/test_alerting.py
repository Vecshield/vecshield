"""Alert delivery wiring.

Covers the config-store alerting section, sink construction (Slack / PagerDuty
Events v2 / generic), severity-filtered dispatch from an audit, and the admin
API surface for managing delivery.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from vecshield.models import Severity
from vecshield_platform.api.config_store import AlertingConfig, ConfigStore
from vecshield_platform.compliance.policy import PolicyViolation
from vecshield_platform.orchestrator import AuditResult, dispatch_alerts
from vecshield_platform.runtime.events import Alert
from vecshield_platform.runtime.sinks import (
    ConsoleSink, InMemorySink, WebhookSink, build_sinks,
    _generic_payload, _slack_payload,
)


def _alert(sev=Severity.HIGH) -> Alert:
    return Alert(rule="policy:p1", severity=sev, principal="audit",
                 timestamp=1000.0, message="secret in 'store/kb'",
                 dedup_key="audit:store:p1:kb", collection="kb",
                 evidence={"finding_id": "f1"})


# --------------------------------------------------------------------------- #
# AlertingConfig + ConfigStore persistence
# --------------------------------------------------------------------------- #

def test_alerting_config_normalizes_bare_url():
    a = AlertingConfig.from_dict({"webhooks": ["https://hooks.slack.com/x/y/z"]})
    assert a.webhooks == [{"url": "https://hooks.slack.com/x/y/z", "style": "slack"}]


def test_alerting_config_rejects_bad_severity():
    with pytest.raises(ValueError):
        AlertingConfig.from_dict({"min_severity": "nope"})


def test_config_store_alerting_roundtrip(tmp_path):
    path = str(tmp_path / "config.json")
    cfg = ConfigStore(path=path)
    cfg.set_alerting(enabled=True, min_severity="critical", console=True,
                     webhooks=[{"url": "https://events.pagerduty.com/v2/enqueue",
                                "style": "pagerduty", "routing_key": "RK"}])
    # persisted + reloaded
    reloaded = ConfigStore(path=path)
    a = reloaded.get_alerting()
    assert a.enabled is True
    assert a.min_severity == "critical"
    assert a.console is True
    assert a.webhooks[0]["style"] == "pagerduty"
    assert a.webhooks[0]["routing_key"] == "RK"


def test_config_store_set_alerting_validates(tmp_path):
    cfg = ConfigStore(path=str(tmp_path / "config.json"))
    with pytest.raises(ValueError):
        cfg.set_alerting(min_severity="bogus")


# --------------------------------------------------------------------------- #
# build_sinks + payload formatters
# --------------------------------------------------------------------------- #

def test_build_sinks_selects_formatters_and_console():
    cfg = AlertingConfig.from_dict({
        "enabled": True,
        "console": True,
        "webhooks": [
            {"url": "https://hooks.slack.com/a", "style": "slack"},
            {"url": "https://example.com/generic", "style": "generic"},
            {"url": "https://events.pagerduty.com/v2/enqueue",
             "style": "pagerduty", "routing_key": "RK"},
        ],
    })
    sinks = build_sinks(cfg)
    # 3 webhooks + 1 console, and never an InMemorySink in production.
    assert sum(isinstance(s, WebhookSink) for s in sinks) == 3
    assert sum(isinstance(s, ConsoleSink) for s in sinks) == 1
    assert not any(isinstance(s, InMemorySink) for s in sinks)

    webhooks = [s for s in sinks if isinstance(s, WebhookSink)]
    assert webhooks[0].formatter is _slack_payload
    assert webhooks[1].formatter is _generic_payload
    # pagerduty is a closure producing a valid Events v2 trigger payload
    pd = webhooks[2].formatter(_alert())
    assert pd["routing_key"] == "RK"
    assert pd["event_action"] == "trigger"
    assert pd["dedup_key"] == "audit:store:p1:kb"
    assert pd["payload"]["severity"] == "error"  # HIGH -> error


def test_build_sinks_empty_when_no_webhooks():
    assert build_sinks(AlertingConfig()) == []


def test_generic_payload_is_raw_alert():
    alert = _alert()
    assert _generic_payload(alert) == alert.to_dict()
    assert _generic_payload(alert)["rule"] == "policy:p1"


# --------------------------------------------------------------------------- #
# dispatch_alerts
# --------------------------------------------------------------------------- #

def _result_with(*severities) -> AuditResult:
    r = AuditResult(id="a1", store="store",
                    finished_at=datetime.now(timezone.utc).isoformat())
    for i, sev in enumerate(severities):
        r.violations.append(PolicyViolation(
            policy_id=f"p{i}", action="restrict", severity=sev,
            description="d", finding_id=f"f{i}", store="store", collection="kb"))
    return r


def test_dispatch_alerts_filters_below_min_severity():
    result = _result_with(Severity.HIGH, Severity.LOW, Severity.CRITICAL)
    sink = InMemorySink()
    n = dispatch_alerts(result, [sink], min_severity=Severity.HIGH)
    assert n == 2  # HIGH + CRITICAL, LOW filtered out
    assert len(sink) == 2
    assert {a.severity for a in sink.alerts} == {Severity.HIGH, Severity.CRITICAL}
    assert all(a.rule.startswith("policy:") for a in sink.alerts)


def test_dispatch_alerts_empty_sinks_is_noop():
    assert dispatch_alerts(_result_with(Severity.CRITICAL), []) == 0


def test_dispatch_alerts_dedup_key_is_stable():
    result = _result_with(Severity.HIGH)
    sink = InMemorySink()
    dispatch_alerts(result, [sink], min_severity=Severity.HIGH)
    assert sink.alerts[0].dedup_key == "audit:store:p0:kb"


# --------------------------------------------------------------------------- #
# run_full_audit sink wiring (integration)
# --------------------------------------------------------------------------- #

@pytest.fixture
def secret_store(tmp_path):
    import chromadb

    client = chromadb.PersistentClient(path=str(tmp_path / "chroma"))
    col = client.create_collection("prod-kb")
    col.add(ids=["a", "b"],
            documents=["Leaked AKIAIOSFODNN7EXAMPLE in a log", "benign note"],
            embeddings=[[0.1, 0.2]] * 2,
            metadatas=[{"tenant_id": "t1"}, {"tenant_id": "t2"}])
    return str(tmp_path / "chroma")


def test_run_full_audit_dispatches_to_sink(secret_store):
    from vecshield.classify import RegexClassifier
    from vecshield_platform.connectors.chroma import ChromaConnector
    from vecshield_platform.orchestrator import run_full_audit

    sink = InMemorySink()
    with ChromaConnector(path=secret_store) as conn:
        result = run_full_audit(conn, classifier=RegexClassifier(), sinks=[sink])

    assert result.alerts_dispatched >= 1
    assert len(sink) == result.alerts_dispatched
    assert any(a.severity == Severity.CRITICAL for a in sink.alerts)


def test_run_full_audit_without_sinks_dispatches_nothing(secret_store):
    from vecshield.classify import RegexClassifier
    from vecshield_platform.connectors.chroma import ChromaConnector
    from vecshield_platform.orchestrator import run_full_audit

    with ChromaConnector(path=secret_store) as conn:
        result = run_full_audit(conn, classifier=RegexClassifier())
    assert result.alerts_dispatched == 0


# --------------------------------------------------------------------------- #
# Admin API surface
# --------------------------------------------------------------------------- #

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from vecshield_platform.api import create_app  # noqa: E402


def test_admin_alerting_get_put_and_mask(tmp_path):
    cfg = ConfigStore(path=str(tmp_path / "config.json"))
    app = create_app(config_store=cfg, auth_token="read-tok",
                     admin_token="admin-tok", serve_ui=False)
    c = TestClient(app)
    admin = {"Authorization": "Bearer admin-tok"}
    read = {"Authorization": "Bearer read-tok"}

    # reader cannot change delivery config
    assert c.put("/admin/alerting", json={"enabled": True}, headers=read).status_code == 403

    # admin enables a Slack webhook
    r = c.put("/admin/alerting", headers=admin, json={
        "enabled": True, "min_severity": "high",
        "webhooks": [{"url": "https://hooks.slack.com/services/T/B/secret",
                      "style": "slack"}]})
    assert r.status_code == 200
    body = r.json()
    assert body["enabled"] is True
    # secret path masked, host preserved
    assert body["webhooks"][0]["url"] == "https://hooks.slack.com/…"
    assert "secret" not in body["webhooks"][0]["url"]

    # GET reflects it (masked), and it persisted
    got = c.get("/admin/alerting", headers=admin).json()
    assert got["enabled"] is True and got["min_severity"] == "high"
    assert ConfigStore(path=str(tmp_path / "config.json")).get_alerting().enabled is True


def test_admin_alerting_put_rejects_bad_severity(tmp_path):
    cfg = ConfigStore(path=str(tmp_path / "config.json"))
    app = create_app(config_store=cfg, admin_token="admin-tok", serve_ui=False)
    c = TestClient(app)
    r = c.put("/admin/alerting", headers={"Authorization": "Bearer admin-tok"},
              json={"min_severity": "definitely-not-valid"})
    assert r.status_code == 422


def test_api_audit_dispatches_alerts(tmp_path):
    import chromadb

    chroma_dir = str(tmp_path / "chroma")
    client = chromadb.PersistentClient(path=chroma_dir)
    col = client.create_collection("prod-kb")
    col.add(ids=["a", "b"],
            documents=["Leaked AKIAIOSFODNN7EXAMPLE", "benign note"],
            embeddings=[[0.1, 0.2]] * 2, metadatas=[{"t": "1"}, {"t": "2"}])

    cfg = ConfigStore(path=str(tmp_path / "config.json"))
    app = create_app(config_store=cfg, serve_ui=False)
    c = TestClient(app)
    c.post("/admin/stores", json={"store_id": "prod", "kind": "chroma",
                                  "conn": {"path": chroma_dir}})
    # console sink keeps it network-free while still exercising dispatch
    c.put("/admin/alerting", json={"enabled": True, "console": True,
                                   "min_severity": "high"})

    a = c.post("/stores/prod/audit", json={}).json()
    assert a["alerts_dispatched"] >= 1


def test_saving_the_masked_list_back_keeps_the_real_webhooks(tmp_path):
    """A settings screen round-trips the masked GET; secrets must survive it."""
    cfg = ConfigStore(path=str(tmp_path / "config.json"))
    app = create_app(config_store=cfg, auth_token="read-tok",
                     admin_token="admin-tok", serve_ui=False)
    c = TestClient(app)
    admin = {"Authorization": "Bearer admin-tok"}
    slack = "https://hooks.slack.com/services/T/B/secret"
    pager = "https://events.pagerduty.com/v2/enqueue"
    c.put("/admin/alerting", headers=admin, json={
        "enabled": True, "min_severity": "high",
        "webhooks": [{"url": slack, "style": "slack"},
                     {"url": pager, "style": "pagerduty", "routing_key": "rk-secret"}]})

    shown = c.get("/admin/alerting", headers=admin).json()
    assert all("secret" not in w["url"] for w in shown["webhooks"])
    # Change only the threshold, sending the masked list back as a screen would.
    r = c.put("/admin/alerting", headers=admin,
              json={"min_severity": "critical", "webhooks": shown["webhooks"]})
    assert r.status_code == 200
    stored = ConfigStore(path=str(tmp_path / "config.json")).alerting.webhooks
    assert [w["url"] for w in stored] == [slack, pager]
    assert stored[1]["routing_key"] == "rk-secret"

    # Adding a new webhook alongside the masked ones works; a mask with no
    # stored counterpart is refused rather than saved as a broken URL.
    added = c.put("/admin/alerting", headers=admin, json={
        "webhooks": [*shown["webhooks"], {"url": "https://example.test/hook"}]})
    assert added.status_code == 200
    assert len(ConfigStore(path=str(tmp_path / "config.json")).alerting.webhooks) == 3
    bogus = c.put("/admin/alerting", headers=admin, json={
        "webhooks": [{"url": "https://unknown.example/\u2026"}]})
    assert bogus.status_code == 422
