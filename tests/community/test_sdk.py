"""Tests for the public SDK: check_text/check_chunks/check_dataset/redact_text."""

from __future__ import annotations

import json

import vecshield
from vecshield import check_chunks, check_dataset, check_text, redact_text


def test_check_text_detects_email():
    r = check_text("ping alice@corp.io", use_nlp=False)
    assert r.has_pii
    assert r.label == "pii"
    assert r.to_dict()["has_pii"] is True


def test_check_text_clean_passes():
    r = check_text("the otter swam happily in the river", use_nlp=False)
    assert not r.has_pii
    assert r.label == "none"


def test_check_chunks_accepts_strings():
    report = check_chunks(["benign text", "SSN 123-45-6789"], use_nlp=False)
    assert report.blocked
    assert len(report.blocked_chunks) == 1
    assert abs(report.pii_density - 0.5) < 1e-9


def test_check_chunks_accepts_dicts():
    report = check_chunks(
        [{"id": "a", "text": "clean"}, {"id": "b", "text": "card 4111 1111 1111 1111"}],
        use_nlp=False,
    )
    assert {c.id for c in report.blocked_chunks} == {"b"}


def test_check_chunks_hard_mode_raises():
    import pytest

    from vecshield.ingest import PiiDetectedError

    with pytest.raises(PiiDetectedError):
        check_chunks(["SSN 123-45-6789"], use_nlp=False, mode="hard")


def test_redact_text_masks_pii():
    out = redact_text("SSN 123-45-6789", use_nlp=False)
    assert "123-45-6789" not in out
    assert "[REDACTED:PII]" in out


def test_check_dataset_summary_and_density(tmp_path):
    p = tmp_path / "d.jsonl"
    with open(p, "w") as f:
        for i in range(10):
            text = "SSN 123-45-6789" if i < 3 else f"benign {i}"
            f.write(json.dumps({"text": text}) + "\n")

    report = check_dataset(str(tmp_path), use_nlp=False)
    assert report.records_scanned == 10
    assert report.sensitive_records == 3
    assert abs(report.density - 0.3) < 1e-9
    assert report.has_pii
    assert report.to_dict()["records_scanned"] == 10


def test_public_api_surface():
    for name in (
        "check_text",
        "check_chunks",
        "check_dataset",
        "redact_text",
        "CheckResult",
        "DatasetReport",
        "Chunk",
        "Severity",
    ):
        assert hasattr(vecshield, name)
