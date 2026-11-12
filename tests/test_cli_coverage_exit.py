"""The scan-family CLI commands report coverage, and a partial read is not a pass.

Exit 2 is a high or critical finding. Exit 3 is a run with none, but where
part of the store went unread or a check failed: a CI step must not read that
as clean. Checks inconclusive by their nature keep exit 0 and are listed.
"""
from __future__ import annotations

import pytest
from click.testing import CliRunner

from vecshield.models import Finding, ScanJob, Severity
from vecshield_platform import cli as cli_module
from vecshield_platform.coverage import (COUNT_UNKNOWN_REASON, check_outcome,
                                           job_read_shortfalls, read_shortfall,
                                           set_job_coverage)

chromadb = pytest.importorskip("chromadb")

# Synthetic content. None of it is real.
CLEAN = [f"The cafeteria menu for day {i} lists soup and bread." for i in range(6)]
SENSITIVE = [f"Customer SSN on file: 123-45-678{i} for verification." for i in range(6)]


@pytest.fixture(autouse=True)
def _wide_console(monkeypatch):
    # Keep reasons on one line so the assertions can find them.
    monkeypatch.setattr(cli_module.console, "width", 400)


def _outcome(outcome="inconclusive", **coverage):
    return check_outcome("data_classification", "s", "kb", outcome=outcome,
                         reason="r", complete=False, **coverage)


@pytest.mark.parametrize("item", [
    _outcome("error"),
    _outcome(limit_reached=True),
    _outcome(enumeration_capped=True),
    _outcome(content_read_errors=1),
    _outcome(short_read="Enumeration returned 2 chunks of the 6 the inventory reports."),
    _outcome(chunks_scanned=2, chunks_expected=6),
])
def test_an_unread_part_or_a_failed_check_is_a_shortfall(item):
    assert read_shortfall(item)


@pytest.mark.parametrize("item", [
    # Read in full, inconclusive by nature.
    _outcome(chunks_scanned=6, chunks_expected=6, nlp_status="disabled"),
    _outcome(chunks_scanned=6, chunks_expected=6, vectors_scored=0),
    check_outcome("tenant_isolation", "s", outcome="skipped", reason="No tenant field."),
    check_outcome("cve", "s", outcome="inconclusive", reason="Not consulted."),
    # No count to fall short of.
    _outcome(short_read=COUNT_UNKNOWN_REASON, chunks_scanned=4),
    _outcome(chunks_scanned=4, chunks_expected=None),
])
def test_a_check_that_read_everything_is_not_a_shortfall(item):
    assert not read_shortfall(item)


def test_read_errors_recorded_once_for_a_job_make_each_of_its_outcomes_a_shortfall():
    job = ScanJob(id="j", store="s")
    set_job_coverage(job, [_outcome(chunks_scanned=6, chunks_expected=6),
                           _outcome("passed", chunks_scanned=6, chunks_expected=6)],
                     content_read_errors=1)
    assert len(job_read_shortfalls(job)) == 2


def _store(path, docs):
    client = chromadb.PersistentClient(path=str(path))
    col = client.get_or_create_collection("kbdocs")
    col.add(ids=[f"d{i}" for i in range(len(docs))], documents=list(docs),
            embeddings=[[float(i), 1.0, 0.5] for i in range(len(docs))],
            metadatas=[{"source": "kb.txt"} for _ in docs])
    return str(path)


def _scan(path, *extra):
    return CliRunner().invoke(cli_module.cli,
                              ["scan", "--path", path, "--no-nlp", *extra])


def test_a_full_read_with_no_findings_exits_0_and_shows_its_coverage(tmp_path):
    result = _scan(_store(tmp_path / "db", CLEAN))
    assert result.exit_code == 0, result.output
    assert "Coverage: partial" in result.output
    # NLP is off: listed with its reason, but the store was read.
    assert "nlp_classification" in result.output
    assert "read shortfall" not in result.output
    assert "not a clean result" in result.output


def test_a_chunk_limit_that_leaves_chunks_unread_exits_3(tmp_path):
    result = _scan(_store(tmp_path / "db", CLEAN), "--max-chunks", "2")
    assert result.exit_code == 3, result.output
    assert "read shortfall" in result.output
    assert "chunk limit was reached" in result.output
    assert "exit 3" in result.output


def test_items_the_connector_could_not_read_exit_3(tmp_path, monkeypatch):
    from vecshield_platform.connectors.chroma import ChromaConnector

    path = _store(tmp_path / "db", CLEAN)
    real = cli_module._connector_from_opts

    def hiding(conn):
        connector = real(conn)
        assert isinstance(connector, ChromaConnector)
        # What row-level security or an unreadable item leaves behind: the
        # count matches what was read, and the connector says items were hidden.
        connector.read_errors = lambda: [{"collection": "kbdocs",
                                          "operation": "row_security",
                                          "error_type": "RowSecurityFiltered"}]
        return connector

    monkeypatch.setattr(cli_module, "_connector_from_opts", hiding)
    result = _scan(path)
    assert result.exit_code == 3, result.output
    assert "content-read failures" in result.output


def test_a_high_finding_still_exits_2_when_the_read_was_also_short(tmp_path):
    result = _scan(_store(tmp_path / "db", SENSITIVE), "--max-chunks", "2")
    assert result.exit_code == 2, result.output


def test_audit_lists_incomplete_checks_and_exits_3_on_a_short_read(tmp_path,
                                                                    monkeypatch):
    from vecshield_platform import orchestrator

    path = _store(tmp_path / "db", CLEAN)
    args = ["audit", "--path", path, "--no-nlp", "--no-posture", "--no-integrity"]
    result = CliRunner().invoke(cli_module.cli, args)
    assert result.exit_code == 0, result.output
    assert "Incomplete checks" in result.output
    assert "tenant_isolation" in result.output

    run_full_audit = orchestrator.run_full_audit
    monkeypatch.setattr(orchestrator, "run_full_audit", lambda *a, **kw: run_full_audit(
        *a, **{**kw, "max_chunks_per_collection": 2}))
    result = CliRunner().invoke(cli_module.cli, args)
    assert result.exit_code == 3, result.output
    assert "read shortfall" in result.output


def test_a_job_without_recorded_coverage_keeps_its_old_exit_code():
    # scan-dataset records no structured coverage: nothing to judge, no change.
    job = ScanJob(id="j", store="s")
    job.add(Finding(id="f", title="t", severity=Severity.LOW, category="c",
                    store="s", description="d"))
    assert job_read_shortfalls(job) == []
    cli_module._exit_for_job(job)  # returns: no SystemExit
