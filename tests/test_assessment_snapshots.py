"""Regression contracts for persisted evidence and effective audit settings."""

from datetime import datetime, timezone
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from vecshield.models import Finding, ScanJob, Severity
from vecshield_platform.api import create_app
from vecshield_platform.api.config_store import ConfigStore
from vecshield_platform.api.registry import StoreRegistry
from vecshield_platform.assessment_settings import resolve_audit_settings
from vecshield_platform.history import ScanHistory
from vecshield_platform.orchestrator import AuditResult


def audit_result(audit_id="audit-1", job_id="job-1", severity=Severity.HIGH):
    job = ScanJob(id=job_id, store="fake://observed")
    job.add(Finding(id=f"finding-{job_id}", title="Synthetic finding",
                    severity=severity, category="data_classification", store=job.store))
    job.finished_at = datetime.now(timezone.utc)
    return AuditResult(id=audit_id, store=job.store, jobs=[job],
                       started_at=job.started_at.isoformat(),
                       finished_at=job.finished_at.isoformat())


def test_snapshot_survives_restart_and_refuses_rewrite(tmp_path):
    path = tmp_path / "history.db"
    result = audit_result()
    result.scope = {"store_id": "registered", "include_integrity": False}
    with ScanHistory(path) as history:
        history.save_audit(result, store_id="registered")
        original = history.get_audit_report(store_id="registered")
        history.save_audit(result, store_id="registered")
        assert history.get_job("job-1")["audit_id"] == "audit-1"
        with pytest.raises(ValueError, match="immutable"):
            history.save_job(result.jobs[0])
        result.scope["include_integrity"] = True
        with pytest.raises(ValueError, match="immutable"):
            history.save_audit(result, store_id="registered")
    with ScanHistory(path) as history:
        assert history.get_audit_report(store_id="registered") == original
        assert history.get_audit("audit-1")["scope"]["include_integrity"] is False
        assert history.get_audit_report(store_id="other", audit_id="audit-1") is None
        assert "Coverage unknown" in original or "unknown" in original


def test_snapshot_and_children_are_atomic(tmp_path):
    with ScanHistory(tmp_path / "history.db") as history:
        result = audit_result()
        history._conn.execute("""CREATE TRIGGER reject_child BEFORE INSERT ON jobs
                              BEGIN SELECT RAISE(ABORT, 'simulated storage failure'); END""")
        with pytest.raises(sqlite3.IntegrityError):
            history.save_audit(result, store_id="registered")
        assert history.get_audit(result.id) is None
        assert history.list_jobs() == []


def test_legacy_migration_does_not_infer_audit_identity(tmp_path):
    path = tmp_path / "legacy.db"
    connection = sqlite3.connect(path)
    connection.execute("""CREATE TABLE jobs (id TEXT PRIMARY KEY, store TEXT NOT NULL,
                       kind TEXT, started_at TEXT, finished_at TEXT, max_severity TEXT,
                       stats TEXT, created_at TEXT)""")
    connection.execute("INSERT INTO jobs (id, store) VALUES ('old', 'legacy')")
    connection.commit()
    connection.close()
    for _ in range(2):
        with ScanHistory(path) as history:
            assert history.get_job("old")["audit_id"] is None
            assert history.list_audits() == []


def test_daily_trend_uses_maximum_severity_with_deterministic_order():
    with ScanHistory() as history:
        history.save_job(audit_result(job_id="critical", severity=Severity.CRITICAL).jobs[0])
        history.save_job(audit_result(job_id="low", severity=Severity.LOW).jobs[0])
        trend = history.severity_trend(store="fake://observed")
        assert len(trend) == 1
        assert trend[0]["max_severity"] == "critical"
        assert trend[0]["findings"] == 2


def test_report_api_reads_frozen_snapshot_without_opening_connector():
    registry = StoreRegistry()

    def cannot_open():
        raise AssertionError("report download must not contact source systems")

    registry.register("registered", "fake", factory=cannot_open)
    with ScanHistory() as history:
        app = create_app(registry=registry, scan_history=history, serve_ui=False)
        with TestClient(app) as client:
            # With nothing frozen there is nothing to serve: the download runs a
            # real audit and fails loudly rather than inventing a clean report.
            assert client.get("/stores/registered/report").status_code == 400
            history.save_audit(audit_result(), store_id="registered")
            # Once a snapshot exists every download is served from it.
            assert client.get("/stores/registered/report").status_code == 200
            report = client.get("/stores/registered/report?audit_id=audit-1")
            assert report.status_code == 200
            assert report.text == client.post("/stores/registered/report", json={
                "audit_id": "audit-1"}).text
            assert "audit-1" in report.text
            assert client.get("/stores/wrong/report?audit_id=audit-1").status_code == 404
            assert client.post("/stores/registered/report", json={
                "include_integrity": False}).status_code == 422
            assert client.get("/admin/history/audits").json()["audits"][0]["id"] == "audit-1"
            assert client.get("/admin/history/audits/audit-1").json()["jobs"][0]["id"] == "job-1"


def test_findings_pagination_exposes_all_rows():
    with ScanHistory() as history:
        result = audit_result()
        job = result.jobs[0]
        for index in range(206):
            job.add(Finding(id=f"extra-{index:03}", title="Extra", severity=Severity.LOW,
                            category="test", store=job.store))
        history.save_job(job)
        with TestClient(create_app(scan_history=history, serve_ui=False)) as client:
            first = client.get(f"/admin/history/{job.id}").json()
            assert len(first["findings"]) == 200 and first["has_more"]
            second = client.get(f"/admin/history/{job.id}?offset={first['next_offset']}").json()
            assert len(second["findings"]) == 7 and not second["has_more"]
            assert len({f["id"] for f in first["findings"] + second["findings"]}) == 207
            assert client.get("/admin/history?limit=-1").status_code == 422
            assert client.get(f"/admin/history/{job.id}?offset=-1").status_code == 422


def test_effective_settings_respect_empty_policy_set_and_freeze_config(tmp_path):
    config = ConfigStore(path=str(tmp_path / "config.json"))
    registry = StoreRegistry()
    store = registry.register("registered", "fake", factory=lambda: None,
                              tenant_field="tenant_from_config")
    config.policies.clear()
    settings = resolve_audit_settings(config, store)
    assert settings.policies == []
    assert settings.tenant_field == "tenant_from_config"
    assert resolve_audit_settings(config, store, tenant_field="override").tenant_field == "override"
    before = json.dumps(settings.scope, sort_keys=True)
    config.allowlist.clear()
    assert json.dumps(settings.scope, sort_keys=True) == before
    assert "conn" not in settings.scope
