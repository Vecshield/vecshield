"""The estate answers 'what do we have, and how much of it can we inspect'."""

from __future__ import annotations

import datetime

import pytest

from vecshield.models import Chunk, Collection, Finding, ScanJob, Severity, VectorStore
from vecshield_platform.connectors.base import Connector
from vecshield_platform.history import ScanHistory

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from vecshield_platform.api import create_app  # noqa: E402
from vecshield_platform.api.registry import StoreRegistry  # noqa: E402


class FakeConnector(Connector):
    kind = "fake"
    content_enumerable = True

    def __init__(self, *, caps=("query", "delete"), enumerable=True, broken=False):
        self._caps = set(caps)
        self.content_enumerable = enumerable
        self._broken = broken

    def describe(self):
        if self._broken:
            raise RuntimeError("vector database is not reachable")
        return VectorStore(kind=self.kind, name="fake", endpoint="fake://",
                           collections=self.list_collections())

    def list_collections(self):
        return [Collection(name="docs", count=10), Collection(name="logs", count=5)]

    def capabilities(self):
        return set(self._caps)

    def iter_chunks(self, collection, batch_size=256):
        yield Chunk(id="c1", collection=collection, text="hello", metadata={})


def history_with_finding():
    h = ScanHistory()
    job = ScanJob(id="j1", store="prod")
    job.add(Finding(id="f1", title="PII", severity=Severity.HIGH,
                    category="data_classification", store="prod", collection="docs"))
    job.finished_at = datetime.datetime.now(datetime.timezone.utc)
    h.save_job(job)
    return h


@pytest.fixture
def client():
    registry = StoreRegistry()
    registry.register("prod", "fake", factory=FakeConnector)
    registry.register("cold", "fake", factory=lambda: FakeConnector(broken=True))
    registry.register("managed", "fake",
                      factory=lambda: FakeConnector(caps=(), enumerable=False))
    history = history_with_finding()
    app = create_app(registry=registry, scan_history=history, serve_ui=False)
    c = TestClient(app)
    yield c, history
    app.state.jobs.shutdown(wait=False)


def test_summary_answers_in_one_call_without_touching_the_stores(client):
    c, _ = client
    body = c.get("/admin/estate").json()
    assert body["probed"] is False
    assert len(body["stores"]) == 3
    prod = next(s for s in body["stores"] if s["store_id"] == "prod")
    assert prod["findings"] == {"high": 1}
    assert prod["findings_total"] == 1
    assert prod["cases"] == {"new": 1}


def test_unprobed_capabilities_are_unknown_not_absent(client):
    c, _ = client
    body = c.get("/admin/estate").json()
    for store in body["stores"]:
        assert store["probe"]["probed"] is False
        assert store["probe"]["capabilities"] is None, "unknown, not an empty set"
        assert store["probe"]["reachable"] is None
    assert "not the same as absent" in body["note"]


def test_probing_reports_what_a_connector_can_actually_do(client):
    c, _ = client
    stores = {s["store_id"]: s for s in c.get("/admin/estate?probe=true").json()["stores"]}

    prod = stores["prod"]["probe"]
    assert prod["reachable"] is True
    assert prod["capabilities"] == ["delete", "query"]
    assert prod["content_enumerable"] is True
    assert prod["collections"] == 2 and prod["chunks"] == 15

    managed = stores["managed"]["probe"]
    assert managed["capabilities"] == []
    assert managed["content_enumerable"] is False, (
        "an inventory-only store cannot be content-scanned, and must say so")


def test_one_unreachable_store_does_not_fail_the_estate(client):
    c, _ = client
    stores = {s["store_id"]: s for s in c.get("/admin/estate?probe=true").json()["stores"]}
    assert stores["cold"]["probe"]["reachable"] is False
    # Category and type only: a connector's own message can carry a credential.
    assert stores["cold"]["probe"]["error"] == "error: RuntimeError"
    assert "not reachable" not in stores["cold"]["probe"]["error"]
    assert stores["prod"]["probe"]["reachable"] is True, "its neighbours still report"


def test_a_store_never_assessed_reports_no_last_assessed(client):
    c, _ = client
    stores = {s["store_id"]: s for s in c.get("/admin/estate").json()["stores"]}
    assert stores["cold"]["last_assessed"] is None
    assert stores["cold"]["findings"] == {}
    assert stores["cold"]["findings_total"] == 0


def test_last_assessed_and_its_coverage_come_from_the_saved_audit(client):
    import sys
    sys.path.insert(0, "tests")
    from test_assessment_snapshots import audit_result

    c, history = client
    history.save_audit(audit_result(), store_id="prod")
    prod = next(s for s in c.get("/admin/estate").json()["stores"]
                if s["store_id"] == "prod")
    assert prod["last_assessed"]
    assert prod["last_audit_id"] == "audit-1"
    assert prod["coverage"]["status"] in ("complete", "partial", "unknown")


def test_summary_without_history_says_so_rather_than_reporting_zero():
    registry = StoreRegistry()
    registry.register("prod", "fake", factory=FakeConnector)
    app = create_app(registry=registry, serve_ui=False)
    c = TestClient(app)
    try:
        store = c.get("/admin/estate").json()["stores"][0]
        assert store["history_available"] is False
        assert store["last_assessed"] is None
        assert store["findings"] == {}
    finally:
        app.state.jobs.shutdown(wait=False)


def test_findings_are_attributed_through_the_name_the_connector_reports(client):
    """Findings record the connector's own name; the registry uses a store id.

    Without the bridge that audits provide, every store reports zero findings —
    which is how a real demo first surfaced this.
    """
    import datetime
    import sys
    sys.path.insert(0, "tests")
    from test_assessment_snapshots import audit_result

    c, history = client
    job = ScanJob(id="j-observed", store="file:///var/lib/chroma")
    job.add(Finding(id="f-observed", title="Secret", severity=Severity.CRITICAL,
                    category="data_classification", store="file:///var/lib/chroma"))
    job.finished_at = datetime.datetime.now(datetime.timezone.utc)
    history.save_job(job)

    # Before an audit links the two names, the finding cannot be attributed.
    stores = {s["store_id"]: s for s in c.get("/admin/estate").json()["stores"]}
    assert stores["prod"]["findings"] == {"high": 1}, "its own same-named finding"

    result = audit_result()
    result.store = "file:///var/lib/chroma"
    history.save_audit(result, store_id="prod")

    stores = {s["store_id"]: s for s in c.get("/admin/estate").json()["stores"]}
    assert stores["prod"]["findings"].get("critical") == 1, (
        "the audit bridges store id and connector name")
    assert c.get("/admin/findings?store=prod").json()["total"] >= 1


def test_a_chroma_collection_reports_the_embedding_model_it_declares(tmp_path):
    """Without it the inversion scorer uses its cautious 0.55 default, which is
    below every threshold that asks about invertibility — so a collection that
    said which model it used was scored as though it had not."""
    import chromadb

    from vecshield_platform.connectors import build_connector

    client = chromadb.PersistentClient(path=str(tmp_path / "chroma"))
    client.create_collection("declared", metadata={"embedding_model": "text-embedding-ada-002"})
    client.create_collection("silent")
    for name in ("declared", "silent"):
        client.get_collection(name).add(
            ids=["a"], documents=["x"], embeddings=[[0.1] * 768])

    conn = build_connector("chroma", path=str(tmp_path / "chroma"))
    try:
        by_name = {c.name: c for c in conn.list_collections()}
    finally:
        conn.close()
    assert by_name["declared"].embedding_model == "text-embedding-ada-002"
    assert by_name["silent"].embedding_model is None

    from vecshield.score.inversion import inversion_risk

    assert inversion_risk(by_name["declared"].embedding_model, 768) > 0.7
    assert inversion_risk(by_name["silent"].embedding_model, 768) < 0.7
