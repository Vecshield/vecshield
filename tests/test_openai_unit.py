"""Unit tests for the OpenAI Vector Store connector's read-error surfacing.

No network: the OpenAI client is swapped for a fake. Validates that a file
whose content can't be retrieved is recorded in read_errors() (instead of
silently yielding empty text) and that scan_store turns that into an explicit
coverage finding.
"""
from __future__ import annotations

import pytest

from vecshield.classify import RegexClassifier
from vecshield_platform.connectors.openai_vs import OpenAIVectorStoreConnector
from vecshield_platform.scan import scan_store


class _Files:
    def list(self, vector_store_id=None, **_):
        return [{"id": "f1", "status": "completed"},
                {"id": "f2", "status": "completed"}]

    def content(self, vector_store_id=None, file_id=None):
        if file_id == "f2":
            raise RuntimeError("content endpoint 500")
        return [{"text": "benign content"}]


class _VectorStores:
    files = _Files()

    def list(self, **_):
        return [{"id": "vs_123", "name": "docs",
                 "file_counts": {"total": 2}}]


class _FakeClient:
    vector_stores = _VectorStores()


def _make_connector() -> OpenAIVectorStoreConnector:
    pytest.importorskip("openai")
    conn = OpenAIVectorStoreConnector(api_key="sk-test")  # no network at construct
    conn._c = _FakeClient()
    return conn


def test_read_failure_recorded_not_silently_empty():
    conn = _make_connector()
    chunks = list(conn.iter_chunks("docs (vs_123)"))

    assert [c.id for c in chunks] == ["f1", "f2"]
    # f1 read fine, f2 failed -> text None + flagged + recorded
    f2 = next(c for c in chunks if c.id == "f2")
    assert f2.text is None
    assert f2.metadata.get("content_unreadable") is True
    errs = conn.read_errors()
    assert len(errs) == 1 and errs[0]["file_id"] == "f2"
    assert errs[0]["collection"] == "docs (vs_123)"
    # The type, never the SDK message, which can echo request details.
    assert errs[0]["error_type"] == "RuntimeError"
    assert "error" not in errs[0] and "500" not in str(errs[0])


def test_scan_emits_coverage_finding_for_unreadable_file():
    conn = _make_connector()
    job = scan_store(conn, classifier=RegexClassifier())

    coverage = [f for f in job.findings
                if f.category == "coverage" and "could not be read" in f.title]
    assert len(coverage) == 1
    assert coverage[0].evidence["count"] == 1
    assert job.stats["content_read_errors"] == 1
