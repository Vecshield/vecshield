"""HTML report generator tests."""

from __future__ import annotations


from vecshield_platform.compliance import build_report
from vecshield.models import Finding, ScanJob, Severity


def _job():
    job = ScanJob(id="j1", store="chroma://demo")
    job.add(Finding(id="f1", title="SECRET in 'kb'", severity=Severity.CRITICAL,
                    category="data_classification", store="chroma://demo",
                    collection="kb", description="aws key found"))
    job.add(Finding(id="f2", title="PII in 'kb'", severity=Severity.MEDIUM,
                    category="data_classification", store="chroma://demo",
                    collection="kb", description="emails found"))
    return job


def test_report_contains_core_sections():
    html = build_report([_job()], title="Test Report", generated_at="2026-06-30")
    assert "Test Report" in html
    assert "Risk heatmap" in html
    assert "Findings" in html
    assert "SECRET in &#x27;kb&#x27;" in html or "SECRET in 'kb'" in html
    assert "CRITICAL" in html and "MEDIUM" in html


def test_report_escapes_html():
    job = ScanJob(id="j", store="s")
    job.add(Finding(id="x", title="<script>alert(1)</script>", severity=Severity.LOW,
                    category="data_classification", store="s", collection="c"))
    html = build_report([job])
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_report_includes_erasure_and_violations():
    from vecshield_platform.compliance import default_policies, evaluate_policies

    job = _job()
    # secret finding needs label_counts for the policy to match
    job.findings[0].evidence = {"label_counts": {"secret": 1}}
    violations = evaluate_policies(default_policies(), job.findings)

    class _Erasure:
        def to_dict(self):
            return {"subject": "bob@x.io", "chunks_to_delete": 4,
                    "collections_affected": {"kb": 4}, "reindex_chunk_cost": 100,
                    "collections_to_reindex": ["kb"]}

    html = build_report([job], violations=violations, erasure=_Erasure())
    assert "Policy violations" in html
    assert "GDPR erasure impact" in html
    assert "bob@x.io" in html
