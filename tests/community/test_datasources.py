"""Tests: local datasource readers, format autodetect, training-scan recall."""

from __future__ import annotations

import json
import random

import pytest

from vecshield.classify import RegexClassifier
from vecshield.datascan import scan_datasource
from vecshield.datasources import build_datasource, format_for
from vecshield.datasources.formats import read_records
from vecshield.models import Severity

# ---------------- format autodetect ----------------


@pytest.mark.parametrize(
    "name,expected",
    [
        ("a.jsonl", "jsonl"),
        ("b.ndjson", "jsonl"),
        ("c.json", "jsonl"),
        ("d.csv", "csv"),
        ("e.tsv", "csv"),
        ("f.parquet", "parquet"),
        ("g.pq", "parquet"),
        ("h.txt", "text"),
        ("i.md", "text"),
        ("j.pdf", "pdf"),
        ("k.bin", "unknown"),
    ],
)
def test_format_autodetect(name, expected):
    assert format_for(name) == expected


# ---------------- format readers (no I/O) ----------------


def test_jsonl_reader_text_field():
    data = b'{"text":"hello AKIAIOSFODNN7EXAMPLE","id":1}\n{"text":"clean"}\n'
    recs = list(read_records("jsonl", data, text_field="text"))
    assert len(recs) == 2
    assert "AKIA" in recs[0][0]
    assert recs[0][1].get("id") == 1  # non-text fields become metadata


def test_csv_reader_joins_columns():
    data = b"name,ssn\nAlice,123-45-6789\n"
    recs = list(read_records("csv", data))
    assert len(recs) == 1
    assert "123-45-6789" in recs[0][0]


def test_text_reader_paragraph_chunks():
    data = b"para one\n\npara two\n\n\npara three"
    recs = list(read_records("text", data))
    assert len(recs) == 3
    assert recs[1][0] == "para two"


# ---------------- local source + training scan recall ----------------


def _seed_jsonl(path, n=200, pii_fraction=0.10, seed=7):
    rng = random.Random(seed)
    pii_lines = set(rng.sample(range(n), int(n * pii_fraction)))
    with open(path, "w") as f:
        for i in range(n):
            if i in pii_lines:
                rec = {"text": f"Customer SSN 123-45-6789 email user{i}@acme.com"}
            else:
                rec = {"text": f"benign product description number {i}"}
            f.write(json.dumps(rec) + "\n")
    return pii_lines


def test_local_datasource_lists_and_reads(tmp_path):
    p = tmp_path / "train.jsonl"
    _seed_jsonl(str(p), n=20)
    src = build_datasource("local", path=str(tmp_path))
    datasets = src.describe().datasets
    assert len(datasets) == 1
    assert datasets[0].format == "jsonl"
    recs = list(src.iter_records(datasets[0].name))
    assert len(recs) == 20
    assert all(r.embedding is None for r in recs)


def test_training_scan_critical_and_recall(tmp_path):
    p = tmp_path / "finetune.jsonl"
    pii_lines = _seed_jsonl(str(p), n=200, pii_fraction=0.10)
    src = build_datasource("local", path=str(tmp_path))

    job = scan_datasource(src, classifier=RegexClassifier())
    # training-data PII escalates to CRITICAL
    assert job.max_severity == Severity.CRITICAL
    finding = job.findings[0]
    assert finding.category == "training_data_classification"

    # recall: detected sensitive >= 85% of seeded PII records
    detected = finding.evidence["sensitive"]
    assert detected >= len(pii_lines) * 0.85


def test_local_requires_existing_dir(tmp_path):
    with pytest.raises(ValueError):
        build_datasource("local", path=str(tmp_path / "missing"))


def test_remote_sources_are_not_local_datasources():
    for kind in ("s3", "gcs", "azure_blob", "huggingface"):
        with pytest.raises(ValueError):
            build_datasource(kind, bucket="x")
