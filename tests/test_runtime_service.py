"""Tests for the productionized runtime monitor (improvement plan 1.5):
persistent AlertStore, PersistentAlertSink, and the /runtime/* API surface."""

from __future__ import annotations

import pytest

from vecshield.models import Severity
from vecshield_platform.runtime import (
    AlertStore,
    BulkVolumeDetector,
    MonitorEngine,
    PersistentAlertSink,
    QueryEvent,
    default_detectors,
)
from vecshield_platform.runtime.events import Alert


def _alert(rule="bulk_volume", sev=Severity.HIGH, principal="svc",
           ts=1.0, coll="kb"):
    return Alert(rule=rule, severity=sev, principal=principal, timestamp=ts,
                 collection=coll, message=f"{rule} fired", dedup_key=f"{principal}:{rule}")


# --------------------------------------------------------------------------- #
# AlertStore                                                                  #
# --------------------------------------------------------------------------- #

def test_store_save_and_get():
    store = AlertStore()
    a = _alert()
    store.save(a)
    got = store.get_alert(a.id)
    assert got is not None
    assert got["rule"] == "bulk_volume"
    assert got["severity"] == "high"
    assert isinstance(got["evidence"], dict)


def test_store_get_missing_returns_none():
    assert AlertStore().get_alert("nope") is None


def test_store_list_filters():
    store = AlertStore()
    store.save(_alert(rule="bulk_volume", sev=Severity.HIGH, principal="a"))
    store.save(_alert(rule="enumeration", sev=Severity.MEDIUM, principal="b"))
    store.save(_alert(rule="bulk_volume", sev=Severity.HIGH, principal="b"))

    assert len(store.list_alerts()) == 3
    assert len(store.list_alerts(rule="bulk_volume")) == 2
    assert len(store.list_alerts(severity="medium")) == 1
    assert len(store.list_alerts(principal="b")) == 2
    assert len(store.list_alerts(rule="bulk_volume", principal="b")) == 1


def test_store_since_filter():
    store = AlertStore()
    store.save(_alert(ts=100.0))
    store.save(_alert(ts=200.0, principal="svc2"))
    recent = store.list_alerts(since=150.0)
    assert len(recent) == 1 and recent[0]["timestamp"] == 200.0


def test_store_limit_offset():
    store = AlertStore()
    for i in range(5):
        store.save(_alert(principal=f"p{i}", ts=float(i)))
    assert len(store.list_alerts(limit=2)) == 2
    assert store.count() == 5


def test_store_stats():
    store = AlertStore()
    store.save(_alert(rule="bulk_volume", sev=Severity.HIGH))
    store.save(_alert(rule="bulk_volume", sev=Severity.HIGH, principal="svc2"))
    store.save(_alert(rule="enumeration", sev=Severity.MEDIUM, principal="svc3"))
    s = store.stats()
    assert s["total"] == 3
    assert s["by_severity"] == {"high": 2, "medium": 1}
    assert s["by_rule"] == {"bulk_volume": 2, "enumeration": 1}


def test_store_persists_to_file(tmp_path):
    path = tmp_path / "alerts.db"
    with AlertStore(path) as store:
        store.save(_alert())
    # Reopen: the alert survives.
    with AlertStore(path) as store2:
        assert store2.count() == 1


def test_store_ping_ok():
    AlertStore().ping()  # must not raise


# --------------------------------------------------------------------------- #
# PersistentAlertSink + engine                                                #
# --------------------------------------------------------------------------- #

def test_persistent_sink_writes():
    store = AlertStore()
    sink = PersistentAlertSink(store)
    sink.emit(_alert())
    assert sink.persisted == 1 and sink.failed == 0
    assert store.count() == 1


def test_persistent_sink_swallows_errors():
    class Boom:
        def save(self, _alert):
            raise RuntimeError("db down")

    sink = PersistentAlertSink(Boom())
    sink.emit(_alert())  # must not raise
    assert sink.failed == 1 and sink.persisted == 0


def test_engine_persists_emitted_alerts():
    store = AlertStore()
    engine = MonitorEngine(
        detectors=[BulkVolumeDetector(threshold=3, window_s=600.0)],
        sinks=[PersistentAlertSink(store)],
    )
    emitted = []
    for i in range(3):
        emitted += engine.process(QueryEvent(principal="scraper", collection="kb",
                                              timestamp=float(i)))
    assert emitted  # threshold tripped
    assert store.count() >= 1
    rows = store.list_alerts(rule="bulk_volume")
    assert rows and rows[0]["principal"] == "scraper"


def test_default_detectors_shape():
    dets = default_detectors()
    names = {d.name for d in dets}
    assert names == {"bulk_volume", "collection_sweep", "enumeration", "rate_baseline"}


# --------------------------------------------------------------------------- #
# API surface                                                                 #
# --------------------------------------------------------------------------- #

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from vecshield_platform.api import create_app  # noqa: E402
from vecshield_platform.api.config_store import ConfigStore  # noqa: E402
from vecshield_platform.compliance import AuditLog  # noqa: E402


@pytest.fixture
def client(tmp_path):
    cfg = ConfigStore(path=str(tmp_path / "config.json"))
    audit = AuditLog()
    app = create_app(config_store=cfg, audit_log=audit, serve_ui=False)
    c = TestClient(app)
    yield c, app, audit
    app.state.jobs.shutdown(wait=False)


def _event(principal="svc", collection="kb", **kw):
    return {"principal": principal, "collection": collection, **kw}


def test_runtime_alerts_empty_initially(client):
    c, _, _ = client
    r = c.get("/runtime/alerts")
    assert r.status_code == 200 and r.json()["alerts"] == []


def test_post_event_no_alert(client):
    c, _, _ = client
    r = c.post("/runtime/events", json=_event(timestamp=1.0))
    assert r.status_code == 200
    body = r.json()
    assert body["processed"] == 1 and body["alerts"] == []


def test_post_events_trip_threshold_and_persist(tmp_path):
    # Small bulk threshold via a custom engine so a few events raise an alert.
    cfg = ConfigStore(path=str(tmp_path / "config.json"))
    store = AlertStore()
    engine = MonitorEngine(
        detectors=[BulkVolumeDetector(threshold=3, window_s=600.0)],
        sinks=[PersistentAlertSink(store)],
    )
    app = create_app(config_store=cfg, alert_store=store, runtime_engine=engine,
                     serve_ui=False)
    c = TestClient(app)
    try:
        alerted = False
        for i in range(3):
            r = c.post("/runtime/events", json=_event(principal="bot", timestamp=float(i)))
            assert r.status_code == 200
            if r.json()["alerts"]:
                alerted = True
        assert alerted
        # Now visible through the read API.
        alerts = c.get("/runtime/alerts").json()["alerts"]
        assert alerts and alerts[0]["rule"] == "bulk_volume"
        assert alerts[0]["principal"] == "bot"
        # And filterable.
        assert c.get("/runtime/alerts", params={"rule": "bulk_volume"}).json()["alerts"]
        assert c.get("/runtime/alerts", params={"rule": "enumeration"}).json()["alerts"] == []
        # stats endpoint
        stats = c.get("/runtime/alerts/stats").json()
        assert stats["total"] >= 1 and "high" in stats["by_severity"]
        # single-alert fetch
        aid = alerts[0]["id"]
        assert c.get(f"/runtime/alerts/{aid}").json()["id"] == aid
        assert c.get("/runtime/alerts/does-not-exist").status_code == 404
    finally:
        app.state.jobs.shutdown(wait=False)


def test_runtime_alert_is_audited(client):
    c, app, audit = client
    # Custom engine that fires immediately.
    class AlwaysAlert:
        def process(self, event):
            a = _alert(principal=event.principal, coll=event.collection)
            app.state.alert_store.save(a)
            return [a]

    app.state.runtime_engine = AlwaysAlert()
    r = c.post("/runtime/events", json=_event(principal="svc", collection="kb", timestamp=1.0))
    assert r.status_code == 200 and r.json()["alerts"]
    assert any(e.action == "runtime_alert" for e in audit.entries)


def test_post_events_requires_operator_role(tmp_path):
    # A read-only token maps to the viewer role: it can read alerts but not
    # push events (that needs the operator role; admin implies operator).
    cfg = ConfigStore(path=str(tmp_path / "config.json"))
    app = create_app(config_store=cfg, admin_token="admin-tok",
                     auth_token="read-tok", serve_ui=False)
    c = TestClient(app)
    try:
        read = {"Authorization": "Bearer read-tok"}
        admin = {"Authorization": "Bearer admin-tok"}
        # viewer can read
        assert c.get("/runtime/alerts", headers=read).status_code == 200
        # viewer cannot push events
        assert c.post("/runtime/events", json=_event(timestamp=1.0),
                      headers=read).status_code == 403
        # admin can push events
        assert c.post("/runtime/events", json=_event(timestamp=1.0),
                      headers=admin).status_code == 200
    finally:
        app.state.jobs.shutdown(wait=False)


def test_readyz_includes_alert_store(client):
    c, _, _ = client
    body = c.get("/readyz").json()
    assert body["checks"].get("alert_store") == "ok"
