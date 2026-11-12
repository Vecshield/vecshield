"""Tests: ingest gate, boundary analyzer, redaction, framework adapters."""

from __future__ import annotations

import pytest

from vecshield.classify import RegexClassifier
from vecshield.ingest import (
    ChunkBoundaryAnalyzer,
    IngestGate,
    PiiDetectedError,
)
from vecshield.ingest.adapters import guarded_ingest
from vecshield.models import Chunk


def _batch(n=100, pii_every=10):
    out = []
    for i in range(n):
        is_pii = pii_every > 0 and i % pii_every == 0
        text = "ssn 123-45-6789" if is_pii else f"benign chunk {i}"
        out.append(Chunk(id=str(i), collection="kb", text=text))
    return out


# ---------------- gate ----------------


def test_gate_blocks_exactly_pii_chunks():
    gate = IngestGate(classifier=RegexClassifier(), mode="soft")
    chunks = _batch(100, pii_every=10)
    report = gate.inspect(chunks)
    assert len(report.blocked_chunks) == 10
    assert len(report.allowed_chunks) == 90
    blocked_ids = {c.id for c in report.blocked_chunks}
    assert blocked_ids == {str(i) for i in range(0, 100, 10)}
    assert abs(report.pii_density - 0.10) < 1e-9


def test_gate_hard_mode_raises():
    gate = IngestGate(classifier=RegexClassifier(), mode="hard")
    with pytest.raises(PiiDetectedError) as ei:
        gate.check(_batch(20, pii_every=10))
    assert len(ei.value.report.blocked_chunks) == 2


def test_gate_soft_mode_never_raises():
    gate = IngestGate(classifier=RegexClassifier(), mode="soft")
    report = gate.check(_batch(20, pii_every=10))  # check() must not raise in soft
    assert report.blocked


def test_gate_clean_batch_all_allowed():
    gate = IngestGate(classifier=RegexClassifier())
    chunks = [Chunk(id=str(i), collection="kb", text=f"benign {i}") for i in range(10)]
    report = gate.inspect(chunks)
    assert not report.blocked
    assert len(report.allowed_chunks) == 10


# ---------------- redaction ----------------


def test_gate_redacts_pii_spans():
    gate = IngestGate(classifier=RegexClassifier())
    clean, n = gate.redact([Chunk(id="0", collection="kb", text="SSN 123-45-6789")])
    assert n == 1
    assert "123-45-6789" not in clean[0].text
    assert "[REDACTED:PII]" in clean[0].text


# ---------------- boundary analyzer ----------------


def test_boundary_catches_split_ssn():
    a = Chunk(id="a", collection="kb", text="my social security number is 123-45")
    b = Chunk(id="b", collection="kb", text="-6789 please keep it safe")
    clf = RegexClassifier()
    assert not clf.classify(a.text).is_sensitive
    assert not clf.classify(b.text).is_sensitive

    analyzer = ChunkBoundaryAnalyzer(classifier=clf, zone_chars=20)
    findings = analyzer.analyze([a, b])
    assert len(findings) == 1
    assert findings[0].category == "boundary_pii"
    assert findings[0].evidence["left_chunk"] == "a"
    assert findings[0].evidence["right_chunk"] == "b"


def test_boundary_no_false_positive_when_whole():
    a = Chunk(id="a", collection="kb", text="nothing sensitive here at all")
    b = Chunk(id="b", collection="kb", text="still nothing to see")
    analyzer = ChunkBoundaryAnalyzer(classifier=RegexClassifier(), zone_chars=20)
    assert analyzer.analyze([a, b]) == []


# ---------------- generic adapter ----------------


def test_guarded_ingest_dry_run():
    gate = IngestGate(classifier=RegexClassifier())
    result = guarded_ingest(_batch(30, pii_every=10), gate=gate, connector=None)
    assert result.blocked == 3
    assert result.ingested == 0
    assert result.report.total == 30


def test_guarded_ingest_writes_clean_to_connector():
    written = {}

    class _FakeConn:
        kind = "fake"

        def add_chunks(self, collection, chunks):
            written[collection] = [c.id for c in chunks]
            return len(chunks)

    gate = IngestGate(classifier=RegexClassifier())
    result = guarded_ingest(
        _batch(30, pii_every=10), gate=gate, connector=_FakeConn(), collection="kb"
    )
    assert result.ingested == 27  # 30 - 3 blocked
    assert len(written["kb"]) == 27


# ---------------- langchain adapter ----------------


def test_langchain_handler_filters_pii_docs():
    from vecshield.ingest.adapters.langchain import VecShieldCallbackHandler

    class _Doc:
        def __init__(self, pc, meta):
            self.page_content = pc
            self.metadata = meta

    docs = [
        _Doc("clean content one", {"id": "1"}),
        _Doc("leak ssn 123-45-6789", {"id": "2"}),
        _Doc("clean content three", {"id": "3"}),
    ]
    handler = VecShieldCallbackHandler(IngestGate(classifier=RegexClassifier()))
    kept = handler.filter_documents(docs)
    kept_ids = {d.metadata["id"] for d in kept}
    assert kept_ids == {"1", "3"}
    assert len(handler.last_report.blocked_chunks) == 1
