"""CLI behavior tests, including CI-friendly exit codes."""

from __future__ import annotations

import json

from click.testing import CliRunner

from vecshield.cli import cli


def _run(args):
    return CliRunner().invoke(cli, args)


def test_detect_finds_pii_and_json():
    res = _run(["detect", "email jane@acme.com", "--no-nlp", "--json"])
    assert res.exit_code == 0
    payload = json.loads(res.output)
    assert payload["has_pii"] is True


def test_detect_clean_text():
    res = _run(["detect", "the otter swam happily", "--no-nlp"])
    assert res.exit_code == 0
    assert "No PII" in res.output


def test_detect_fail_on_pii_exits_2():
    res = _run(["detect", "SSN 123-45-6789", "--no-nlp", "--fail-on-pii"])
    assert res.exit_code == 2


def test_ingest_check_blocks_and_exits_2(tmp_path):
    p = tmp_path / "chunks.jsonl"
    with open(p, "w") as f:
        f.write(json.dumps({"text": "clean chunk"}) + "\n")
        f.write(json.dumps({"text": "SSN 123-45-6789"}) + "\n")
    res = _run(["ingest-check", str(p), "--no-nlp"])
    assert res.exit_code == 2


def test_ingest_check_clean_passes(tmp_path):
    p = tmp_path / "chunks.jsonl"
    with open(p, "w") as f:
        f.write(json.dumps({"text": "clean chunk one"}) + "\n")
        f.write(json.dumps({"text": "clean chunk two"}) + "\n")
    res = _run(["ingest-check", str(p), "--no-nlp"])
    assert res.exit_code == 0


def test_ingest_check_json_output():
    res = _run(["ingest-check", "SSN 123-45-6789", "--no-nlp", "--json"])
    payload = json.loads(res.output)
    assert payload["blocked"] == 1
    assert res.exit_code == 2


def test_training_check_summary_and_exit(tmp_path):
    p = tmp_path / "d.jsonl"
    with open(p, "w") as f:
        f.write(json.dumps({"text": "SSN 123-45-6789"}) + "\n")
        f.write(json.dumps({"text": "benign"}) + "\n")
    res = _run(["training-check", str(tmp_path), "--no-nlp", "--json"])
    payload = json.loads(res.output)
    assert payload["records_scanned"] == 2
    assert payload["sensitive_records"] == 1
    assert res.exit_code == 2  # training PII escalates to CRITICAL


def test_redact_preview_masks():
    res = _run(["redact-preview", "SSN 123-45-6789", "--no-nlp"])
    assert res.exit_code == 0
    assert "123-45-6789" not in res.output
    assert "REDACTED" in res.output
