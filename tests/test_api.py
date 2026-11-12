"""REST API tests via FastAPI TestClient (no network/server needed)."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from vecshield_platform.api import StoreRegistry, create_app  # noqa: E402
from vecshield_platform.compliance import AuditLog  # noqa: E402


@pytest.fixture
def chroma_path(tmp_path):
    import chromadb

    client = chromadb.PersistentClient(path=str(tmp_path / "chroma"))
    col = client.create_collection("docs")
    col.add(
        ids=["a", "b", "c"],
        documents=["Leaked AKIAIOSFODNN7EXAMPLE here",
                   "ticket from john.doe@example.com",
                   "benign content"],
        embeddings=[[0.1, 0.2]] * 3,
        metadatas=[{"tenant_id": "t1"}, {"tenant_id": "t1"}, {"tenant_id": "t2"}],
    )
    return str(tmp_path / "chroma")


@pytest.fixture
def client(chroma_path):
    reg = StoreRegistry()
    reg.register("docs-store", "chroma", path=chroma_path, tenant_field="tenant_id")
    app = create_app(reg, audit_log=AuditLog())
    return TestClient(app)


def test_healthz_and_store_listing(client):
    assert client.get("/healthz").json()["status"] == "ok"
    stores = client.get("/stores").json()["stores"]
    assert stores[0]["store_id"] == "docs-store"
    # credentials/paths are NOT exposed in the public store listing
    assert "path" not in stores[0] and "factory" not in stores[0]


def test_scan_endpoint_finds_secret(client):
    r = client.post("/stores/docs-store/scan")
    assert r.status_code == 200
    body = r.json()
    assert body["max_severity"] == "critical"


def test_erasure_endpoint(client):
    r = client.post("/stores/docs-store/erasure",
                    json={"subject": "john.doe@example.com"})
    assert r.status_code == 200
    assert r.json()["chunks_to_delete"] == 1


def test_erasure_rejects_empty_subject(client):
    r = client.post("/stores/docs-store/erasure", json={"subject": ""})
    assert r.status_code == 422  # pydantic min_length


def test_full_audit_endpoint(client):
    r = client.post("/stores/docs-store/audit", json={"tenant_field": "tenant_id"})
    assert r.status_code == 200
    body = r.json()
    assert body["summary"]["critical"] >= 1
    assert any(v["policy_id"] == "secrets-never-embedded"
               for v in body["violations"])


def test_report_endpoint_returns_html(client):
    r = client.post("/stores/docs-store/report")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "Risk heatmap" in r.text


def test_unknown_store_404(client):
    assert client.post("/stores/nope/scan").status_code == 404


def test_audit_log_records_and_verifies(client):
    client.post("/stores/docs-store/scan")
    client.post("/stores/docs-store/erasure", json={"subject": "x@y.io"})
    r = client.get("/audit-log").json()
    assert r["verified"] is True
    actions = [e["action"] for e in r["entries"]]
    assert "scan" in actions and "erasure_assessment" in actions


def test_auth_token_enforced(chroma_path):
    reg = StoreRegistry()
    reg.register("docs-store", "chroma", path=chroma_path)
    app = create_app(reg, auth_token="s3cret")
    c = TestClient(app)
    assert c.post("/stores/docs-store/scan").status_code == 401
    ok = c.post("/stores/docs-store/scan",
                headers={"Authorization": "Bearer s3cret"})
    assert ok.status_code == 200
    # health check stays open (no auth) for liveness probes
    assert c.get("/healthz").status_code == 200
