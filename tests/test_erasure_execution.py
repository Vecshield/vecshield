"""Tests for erasure execution: plan_erasure, execute_erasure, delete_chunks."""

from __future__ import annotations

import pytest
from vecshield_platform.compliance import (
    ErasureExecution,
    ErasurePlan,
    erasure_impact,
    execute_erasure,
    plan_erasure,
)
from vecshield_platform.connectors.base import UnsupportedCapability
from vecshield_platform.connectors.chroma import ChromaConnector


@pytest.fixture(autouse=True)
def writes_permitted(monkeypatch):
    """These tests execute erasures, which safe mode refuses (see
    test_erasure_coverage for the refusal itself)."""
    monkeypatch.setenv("VECSHIELD_SAFE_MODE", "0")


@pytest.fixture
def subject_chroma(tmp_path):
    import chromadb

    client = chromadb.PersistentClient(path=str(tmp_path / "chroma"))
    col = client.create_collection("support")
    col.add(
        ids=["t1", "t2", "t3", "t4"],
        documents=[
            "Ticket from jane@example.com about billing.",
            "Follow-up with the team.",
            "Re: jane@example.com account closure.",
            "Unrelated document about cloud costs.",
        ],
        embeddings=[[0.1, 0.2]] * 4,
        metadatas=[
            {"reporter": "jane@example.com"},
            {"reporter": "other@example.com"},
            {"reporter": "jane@example.com"},
            {"reporter": "ops@example.com"},
        ],
    )
    return str(tmp_path / "chroma")


def test_plan_erasure_groups_by_collection(subject_chroma):
    with ChromaConnector(path=subject_chroma) as conn:
        report = erasure_impact(conn, "jane@example.com")
    plan = plan_erasure(report)
    assert isinstance(plan, ErasurePlan)
    assert plan.total_chunks == report.chunks_to_delete
    assert "support" in plan.by_collection
    assert set(plan.by_collection["support"]) == {"t1", "t3"}


def test_execute_erasure_deletes_and_verifies(subject_chroma):
    with ChromaConnector(path=subject_chroma) as conn:
        report = erasure_impact(conn, "jane@example.com")
        plan = plan_erasure(report)
        assert plan.total_chunks == 2

        execution = execute_erasure(conn, plan, verify=True)

    assert isinstance(execution, ErasureExecution)
    assert execution.total_deleted == 2
    assert not execution.errors
    assert execution.verification is not None
    assert execution.verification.ok
    assert execution.ok


def test_execute_erasure_no_verify(subject_chroma):
    with ChromaConnector(path=subject_chroma) as conn:
        report = erasure_impact(conn, "jane@example.com")
        plan = plan_erasure(report)
        execution = execute_erasure(conn, plan, verify=False)
    assert execution.total_deleted == 2
    assert execution.verification is None


def test_execute_erasure_residual_check(subject_chroma):
    """After delete, subject should not appear in a fresh scan."""
    with ChromaConnector(path=subject_chroma) as conn:
        report = erasure_impact(conn, "jane@example.com")
        plan = plan_erasure(report)
        execute_erasure(conn, plan, verify=False)
        residual = erasure_impact(conn, "jane@example.com")
    assert residual.chunks_to_delete == 0


def test_execute_erasure_unsupported_connector():
    """A connector that doesn't advertise 'delete' raises UnsupportedCapability."""
    from vecshield_platform.connectors.base import Connector
    from vecshield.models import Collection, VectorStore

    class NoDeleteConnector(Connector):
        kind = "nodele"
        def describe(self):
            return VectorStore(kind="nodele", name="test", endpoint="test",
                               collections=[Collection(name="c", count=0)])
        def list_collections(self):
            return [Collection(name="c", count=0)]
        def iter_chunks(self, collection, batch_size=256):
            return iter([])

    from vecshield_platform.compliance.erasure import ErasureReport, ErasureMatch, ErasurePlan
    from datetime import datetime, timezone
    report = ErasureReport(subject="x", generated_at=datetime.now(timezone.utc).isoformat(),
                           matches=[ErasureMatch("id1", "c", "text", "preview")])
    plan = ErasurePlan(report=report, by_collection={"c": ["id1"]})
    with pytest.raises(UnsupportedCapability):
        execute_erasure(NoDeleteConnector(), plan)
