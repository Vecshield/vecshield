"""Tests for the SQLite-backed ScanHistory store."""

from __future__ import annotations

from datetime import datetime, timezone


from vecshield_platform.history import ScanHistory
from vecshield.models import Finding, ScanJob, Severity


def _job(store: str = "test-store", sev: Severity = Severity.HIGH) -> ScanJob:
    job = ScanJob(id=f"scan-{store}-1", store=store)
    job.add(Finding(
        id=f"find-{store}-1",
        title="Test finding",
        severity=sev,
        category="data_classification",
        store=store,
        description="A test finding.",
        remediation="Fix it.",
    ))
    job.finished_at = datetime.now(timezone.utc)
    return job


def test_save_and_list_jobs():
    with ScanHistory() as h:
        h.save_job(_job("store-a"))
        h.save_job(_job("store-b"))
        jobs = h.list_jobs()
    assert len(jobs) == 2
    assert {j["store"] for j in jobs} == {"store-a", "store-b"}


def test_list_jobs_filtered_by_store():
    with ScanHistory() as h:
        h.save_job(_job("alpha"))
        h.save_job(_job("beta"))
        jobs = h.list_jobs(store="alpha")
    assert len(jobs) == 1
    assert jobs[0]["store"] == "alpha"


def test_get_job_returns_findings():
    with ScanHistory() as h:
        job = _job("prod")
        h.save_job(job)
        result = h.get_job(job.id)
    assert result is not None
    assert result["id"] == job.id


def test_get_job_with_findings():
    with ScanHistory() as h:
        job = _job("prod")
        h.save_job(job)
        findings = h.list_findings(job_id=job.id)
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"


def test_list_findings_filtered_by_severity():
    with ScanHistory() as h:
        h.save_job(_job("x", Severity.HIGH))
        h.save_job(_job("y", Severity.LOW))
        high = h.list_findings(severity="high")
        low = h.list_findings(severity="low")
    assert len(high) == 1
    assert len(low) == 1


def test_stats_counts():
    with ScanHistory() as h:
        h.save_job(_job("a", Severity.CRITICAL))
        h.save_job(_job("b", Severity.HIGH))
        s = h.stats()
    assert s["total_jobs"] == 2
    assert s["total_findings"] == 2
    assert s["by_severity"]["critical"] == 1
    assert s["by_severity"]["high"] == 1


def test_save_job_is_idempotent():
    with ScanHistory() as h:
        job = _job("store-c")
        h.save_job(job)
        h.save_job(job)  # INSERT OR REPLACE
        assert h.stats()["total_jobs"] == 1


def test_severity_trend_returns_rows():
    with ScanHistory() as h:
        h.save_job(_job("trend-store"))
        trend = h.severity_trend(days=7)
    assert isinstance(trend, list)
