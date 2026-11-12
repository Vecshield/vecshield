"""The subject index through the API: built by a scan, erased with the subject."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from vecshield_platform.api import StoreRegistry, create_app  # noqa: E402
from vecshield_platform.compliance import AuditLog  # noqa: E402
from vecshield_platform.history import ScanHistory  # noqa: E402

SUBJECT = "maya.brooks@example-customer.test"


@pytest.fixture
def store_path(tmp_path):
    import chromadb

    client = chromadb.PersistentClient(path=str(tmp_path / "chroma"))
    col = client.create_collection("tickets")
    col.add(
        ids=["t1", "t2", "t3"],
        documents=[f"Ticket from {SUBJECT} about billing.",
                   "A runbook paragraph with nothing identifying in it.",
                   f"Follow-up: {SUBJECT.upper()} asked for deletion."],
        embeddings=[[0.1, 0.2], [0.9, 0.1], [0.12, 0.22]],
        metadatas=[{"tenant_id": "acme"}, {"tenant_id": "acme"},
                   {"tenant_id": "acme"}],
    )
    return str(tmp_path / "chroma")


@pytest.fixture
def client(store_path):
    reg = StoreRegistry()
    reg.register("docs", "chroma", path=store_path)
    app = create_app(reg, audit_log=AuditLog(), scan_history=ScanHistory())
    return TestClient(app)


def test_a_scan_builds_the_index(client):
    assert client.get("/admin/subject-index").json()["locations"] == 0

    client.post("/stores/docs/scan")

    stats = client.get("/admin/subject-index").json()
    assert stats["subjects"] == 1
    assert stats["locations"] == 2          # two chunks name the same person
    assert stats["stores"][0]["store_id"] == "docs"


def test_the_stats_never_carry_a_subject_identifier(client):
    client.post("/stores/docs/scan")
    body = client.get("/admin/subject-index").text.lower()
    assert "maya" not in body and "example-customer" not in body


def test_the_endpoint_publishes_its_own_limits(client):
    limits = client.get("/admin/subject-index").json()["limits"]
    assert any("not evidence the subject is absent" in x for x in limits)
    assert any("Identifiers are not stored" in x for x in limits)


def test_case_differences_index_to_one_subject(client):
    """t1 and t3 write the address differently; one person, two locations."""
    client.post("/stores/docs/scan")
    assert client.get("/admin/subject-index").json()["subjects"] == 1


def test_erasing_a_subject_removes_their_index_rows(client, monkeypatch):
    monkeypatch.setenv("VECSHIELD_SAFE_MODE", "0")  # execution obeys safe mode
    client.post("/stores/docs/scan")
    assert client.get("/admin/subject-index").json()["locations"] == 2

    r = client.post("/stores/docs/erasure/execute", json={"subject": SUBJECT})
    receipt = r.json()["receipt"]

    assert receipt["verification_outcome"] == "passed"
    assert receipt["index_rows_removed"] == 2
    assert client.get("/admin/subject-index").json()["locations"] == 0


def test_the_removal_count_is_inside_the_receipt_hash(client):
    from vecshield_platform.compliance import build_erasure_receipt, ErasureExecution

    execution = ErasureExecution(subject=SUBJECT, executed_at="t", deleted={"c": 1})
    with_index = build_erasure_receipt(execution, store="docs", actor="a",
                                       index_rows_removed=2)
    without = build_erasure_receipt(execution, store="docs", actor="a",
                                    index_rows_removed=None)
    assert with_index["receipt_hash"] != without["receipt_hash"]


def test_the_index_requires_the_compliance_role(store_path):
    """How many distinct people are recorded here is not a viewer's number."""
    reg = StoreRegistry()
    reg.register("docs", "chroma", path=store_path)
    # A separate admin token makes auth_token the read-only one, which is the
    # deployment shape where a viewer actually exists.
    app = create_app(reg, audit_log=AuditLog(), scan_history=ScanHistory(),
                     auth_token="viewer-token", admin_token="admin-token")
    client = TestClient(app)

    denied = client.get("/admin/subject-index",
                        headers={"Authorization": "Bearer viewer-token"})
    assert denied.status_code == 403
    assert "compliance" in denied.json()["detail"]

    allowed = client.get("/admin/subject-index",
                         headers={"Authorization": "Bearer admin-token"})
    assert allowed.status_code == 200


def test_a_deployment_without_history_says_so_rather_than_failing(store_path):
    reg = StoreRegistry()
    reg.register("docs", "chroma", path=store_path)
    client = TestClient(create_app(reg, audit_log=AuditLog()))

    assert client.post("/stores/docs/scan").status_code == 200   # scan still works
    r = client.get("/admin/subject-index")
    assert r.status_code == 409
    assert "scan history" in r.json()["detail"]
