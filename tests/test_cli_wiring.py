"""CLI wiring for the engines that had no command of their own.

Covers the three surfaces that had real engines but no command:
  * ``ChromaConnector.add_chunks`` — the write hook ``guarded_ingest`` needs.
  * ``gate-ingest --redact / --write`` — redact-to-store instead of dry-run only.
  * ``ingest-monitor`` — real-time IngestMonitor replay.
  * ``monitor-live`` — MonitoredConnector driving live queries through detectors.
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from vecshield_platform.cli import cli
from vecshield_platform.connectors.chroma import ChromaConnector
from vecshield.models import Chunk


def _emb(seed: int, dim: int = 16) -> list[float]:
    return [((seed * (i + 3)) % 50) / 50.0 for i in range(dim)]


# --------------------------------------------------------------------------- #
# ChromaConnector.add_chunks
# --------------------------------------------------------------------------- #

def test_chroma_advertises_write_capability(tmp_path):
    conn = ChromaConnector(path=str(tmp_path / "chroma"), create=True)
    assert "write" in conn.capabilities()


def test_chroma_add_chunks_roundtrip(tmp_path):
    """add_chunks persists chunks (with explicit embeddings) and iter_chunks reads them back."""
    conn = ChromaConnector(path=str(tmp_path / "chroma"), create=True)
    chunks = [
        Chunk(id=f"c{i}", collection="kbdocs", text=f"doc {i}",
              embedding=_emb(i + 1), metadata={"source": "unit"})
        for i in range(3)
    ]
    written = conn.add_chunks("kbdocs", chunks)
    assert written == 3

    got = {c.id: c for c in conn.iter_chunks("kbdocs")}
    assert set(got) == {"c0", "c1", "c2"}
    assert got["c1"].text == "doc 1"
    assert got["c1"].metadata.get("source") == "unit"
    assert len(got["c1"].embedding) == 16


def test_chroma_add_chunks_empty_is_noop(tmp_path):
    conn = ChromaConnector(path=str(tmp_path / "chroma"), create=True)
    assert conn.add_chunks("kbdocs", []) == 0


# --------------------------------------------------------------------------- #
# gate-ingest --redact / --write
# --------------------------------------------------------------------------- #

def _write_local_doc(tmp_path, name, text):
    d = tmp_path / "data"
    d.mkdir(exist_ok=True)
    (d / name).write_text(text)
    return str(d)


def test_gate_ingest_blocks_pii_by_default(tmp_path):
    """A chunk containing an SSN (PII -> HIGH) is blocked in the dry run."""
    data_dir = _write_local_doc(tmp_path, "hr.txt",
                                "Employee SSN is 123-45-6789 and is on file.")
    out = tmp_path / "report.json"
    result = CliRunner().invoke(cli, [
        "gate-ingest", "--source", "local", "--path", data_dir,
        "--no-nlp", "--json", str(out),
    ])
    assert result.exit_code == 0, result.output
    data = json.loads(out.read_text())
    assert data["blocked"] >= 1
    assert data["ingested"] == 0  # dry run: no connector


def test_gate_ingest_redact_unblocks_and_counts_spans(tmp_path):
    """--redact masks the SSN in place so nothing is blocked and hard mode passes."""
    data_dir = _write_local_doc(tmp_path, "hr.txt",
                                "Employee SSN is 123-45-6789 and is on file.")
    out = tmp_path / "report.json"
    result = CliRunner().invoke(cli, [
        "gate-ingest", "--source", "local", "--path", data_dir,
        "--no-nlp", "--redact", "--mode", "hard", "--json", str(out),
    ])
    assert result.exit_code == 0, result.output  # hard mode: 0 because nothing blocked
    data = json.loads(out.read_text())
    assert data["blocked"] == 0
    assert data["spans_redacted"] >= 1
    assert "redacted in place" in result.output


def test_gate_ingest_hard_mode_exits_two_when_blocked(tmp_path):
    data_dir = _write_local_doc(tmp_path, "hr.txt",
                                "Employee SSN is 123-45-6789 and is on file.")
    result = CliRunner().invoke(cli, [
        "gate-ingest", "--source", "local", "--path", data_dir,
        "--no-nlp", "--mode", "hard",
    ])
    assert result.exit_code == 2, result.output


def test_gate_ingest_write_persists_allowed_chunks(tmp_path, monkeypatch):
    """--write routes allowed chunks to a target connector's add_chunks()."""
    from vecshield_platform import cli as cli_mod

    class _FakeWriteConn:
        kind = "chroma"

        def __init__(self):
            self.written: list[tuple[str, list]] = []

        def add_chunks(self, collection, chunks):
            self.written.append((collection, list(chunks)))
            return len(chunks)

    fake = _FakeWriteConn()
    monkeypatch.setattr(cli_mod, "build_connector", lambda kind, **kw: fake)

    data_dir = _write_local_doc(tmp_path, "clean.txt",
                                "The quarterly report covers roadmap items.")
    result = CliRunner().invoke(cli, [
        "gate-ingest", "--source", "local", "--path", data_dir,
        "--no-nlp", "--write", "--target", "chroma", "--collection", "kb",
    ])
    assert result.exit_code == 0, result.output
    assert fake.written, "connector.add_chunks was never called"
    assert fake.written[0][0] == "kb"
    assert len(fake.written[0][1]) >= 1
    assert "written to chroma 'kb'" in result.output


def test_gate_ingest_write_can_start_a_new_local_chroma_store(tmp_path, monkeypatch):
    """A write target may be new; only stores being assessed must exist."""
    written = []
    # The ingested text has no vectors, and Chroma's default embedding
    # function would download a model; only where the write lands matters here.
    monkeypatch.setattr(ChromaConnector, "add_chunks",
                        lambda self, collection, chunks: written.append(collection)
                        or len(chunks))
    data_dir = _write_local_doc(tmp_path, "clean.txt",
                                "The quarterly report covers roadmap items.")
    target = tmp_path / "new-store"
    result = CliRunner().invoke(cli, [
        "gate-ingest", "--source", "local", "--path", data_dir, "--no-nlp",
        "--write", "--target", "chroma", "--target-path", str(target),
        "--collection", "kbdocs",
    ])
    assert result.exit_code == 0, result.output
    assert written == ["kbdocs"]
    assert (target / "chroma.sqlite3").is_file()


def test_gate_ingest_write_rejects_connector_without_add_chunks(tmp_path, monkeypatch):
    from vecshield_platform import cli as cli_mod

    class _NoWrite:
        kind = "readonly"

    monkeypatch.setattr(cli_mod, "build_connector", lambda kind, **kw: _NoWrite())
    data_dir = _write_local_doc(tmp_path, "clean.txt", "roadmap items only.")
    result = CliRunner().invoke(cli, [
        "gate-ingest", "--source", "local", "--path", data_dir,
        "--no-nlp", "--write", "--target", "chroma",
    ])
    assert result.exit_code == 1
    assert "no add_chunks" in result.output


# --------------------------------------------------------------------------- #
# ingest-monitor
# --------------------------------------------------------------------------- #

def test_ingest_monitor_alerts_on_blocked_batch(tmp_path):
    events = tmp_path / "events.jsonl"
    events.write_text("\n".join([
        json.dumps({"principal": "svc", "dataset": "kb", "timestamp": 1.0,
                    "chunks": [{"id": "a", "text": "harmless product note"}]}),
        json.dumps({"principal": "svc", "dataset": "kb", "timestamp": 2.0,
                    "chunks": [{"id": "b", "text": "SSN 123-45-6789 leaked here"}]}),
    ]) + "\n")

    result = CliRunner().invoke(cli, ["ingest-monitor", "--events", str(events),
                                      "--no-nlp"])
    assert result.exit_code == 2, result.output  # blocked PII -> HIGH alert
    assert "Observed 2 batch(es)" in result.output
    assert "ingest_pii" in result.output


def test_ingest_monitor_clean_batches_no_alert(tmp_path):
    events = tmp_path / "events.jsonl"
    events.write_text(json.dumps({
        "principal": "svc", "dataset": "kb", "timestamp": 1.0,
        "chunks": [{"id": "a", "text": "harmless product note"}],
    }) + "\n")

    result = CliRunner().invoke(cli, ["ingest-monitor", "--events", str(events),
                                      "--no-nlp"])
    assert result.exit_code == 0, result.output
    assert "0 with blocked PII" in result.output


# --------------------------------------------------------------------------- #
# monitor-live
# --------------------------------------------------------------------------- #

@pytest.fixture
def seeded_chroma(tmp_path):
    conn = ChromaConnector(path=str(tmp_path / "chroma"), create=True)
    chunks = [
        Chunk(id=f"v{i}", collection="kbdocs", text=f"entry {i}",
              embedding=_emb(i + 1), metadata={"source": "seed"})
        for i in range(6)
    ]
    conn.add_chunks("kbdocs", chunks)
    return str(tmp_path / "chroma")


def test_monitor_live_bulk_alert(seeded_chroma):
    """Low bulk threshold + several sample queries trips the HIGH bulk detector."""
    result = CliRunner().invoke(cli, [
        "monitor-live", "--connector", "chroma", "--path", seeded_chroma,
        "--collection", "kbdocs", "--samples", "6",
        "--bulk-threshold", "3", "--bulk-window", "100000",
    ])
    assert result.exit_code == 2, result.output
    assert "Issued 6 live queries" in result.output
    assert "BULK" in result.output.upper()


def test_monitor_live_high_threshold_no_alert(seeded_chroma):
    """Quiet config (few narrow queries, high thresholds) raises no HIGH alert."""
    result = CliRunner().invoke(cli, [
        "monitor-live", "--connector", "chroma", "--path", seeded_chroma,
        "--collection", "kbdocs", "--samples", "2", "--top-k", "1",
        "--bulk-threshold", "500", "--bulk-window", "100000",
    ])
    assert result.exit_code == 0, result.output
    assert "Issued 2 live queries" in result.output
