"""HTTP endpoints for the engines that were reachable only from the CLI.

Covers the thin routes that reuse existing functions: standalone isolation
probe, API-key audit, RBAC diff, live store validation, and stateless
datasource scan. Discovery stays CLI-only by design (documented, no route).
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("chromadb")
from fastapi.testclient import TestClient  # noqa: E402

from vecshield_platform.api import create_app  # noqa: E402
from vecshield_platform.api.config_store import ConfigStore  # noqa: E402


@pytest.fixture
def chroma_dir(tmp_path):
    import chromadb

    path = str(tmp_path / "chroma")
    client = chromadb.PersistentClient(path=path)
    col = client.create_collection("prod-kb")
    col.add(
        ids=["a1", "a2", "b1", "b2"],
        documents=["acme note one", "acme note two",
                   "globex note one", "globex note two"],
        embeddings=[[0.10, 0.20, 0.30], [0.11, 0.19, 0.31],
                    [0.90, 0.80, 0.70], [0.89, 0.81, 0.69]],
        metadatas=[{"tenant_id": "acme"}, {"tenant_id": "acme"},
                   {"tenant_id": "globex"}, {"tenant_id": "globex"}],
    )
    return path


@pytest.fixture
def client(tmp_path, chroma_dir):
    cfg = ConfigStore(path=str(tmp_path / "config.json"))
    app = create_app(config_store=cfg, serve_ui=False)
    c = TestClient(app)
    r = c.post("/admin/stores", json={"store_id": "prod", "kind": "chroma",
                                      "conn": {"path": chroma_dir},
                                      "tenant_field": "tenant_id"})
    assert r.status_code == 200
    return c


# --------------------------------------------------------------------------- #
# probe-isolation
# --------------------------------------------------------------------------- #

def test_probe_isolation_runs(client):
    r = client.post("/stores/prod/probe-isolation",
                    params={"collection": "prod-kb", "tenant_field": "tenant_id"})
    assert r.status_code == 200
    job = r.json()
    assert job["stats"]["tenant_field"] == "tenant_id"
    # a queryable, enumerable chroma store is actually probed (not skipped)
    assert job["stats"].get("skipped") is not True
    assert set(job["stats"]["tenants"]) == {"acme", "globex"}
    # The engine records its own outcome: the store's filter is verified for
    # both tenants, and the shared collection itself is the failing condition.
    [outcome] = job["stats"]["check_outcomes"]
    assert outcome["check"] == "tenant_isolation"
    assert outcome["outcome"] == "failed"
    assert outcome["coverage"]["complete"] is True
    assert outcome["coverage"]["filter_enforcement"] == "verified"
    # The route's legacy top_k does not shrink the queries below the collection.
    r = client.post("/stores/prod/probe-isolation",
                    params={"collection": "prod-kb", "tenant_field": "tenant_id",
                            "top_k": 1})
    assert r.json()["stats"]["check_outcomes"][0]["coverage"]["complete"] is True


def test_probe_isolation_unknown_store_404(client):
    r = client.post("/stores/nope/probe-isolation",
                    params={"collection": "x", "tenant_field": "t"})
    assert r.status_code == 404


# --------------------------------------------------------------------------- #
# audit-keys
# --------------------------------------------------------------------------- #

def test_audit_keys_flags_overprivilege(client):
    r = client.post("/stores/prod/audit-keys", json={"keys": [
        {"id": "k1", "name": "root", "actions": ["admin"], "namespaces": ["*"]},
        {"id": "k2", "name": "reader", "actions": ["read"], "namespaces": ["kb"]},
    ]})
    assert r.status_code == 200
    findings = r.json()["findings"]
    assert any(f["severity"] == "high" for f in findings)
    assert all(f["store"] == "prod" for f in findings)


def test_audit_keys_unknown_store_404(client):
    r = client.post("/stores/nope/audit-keys", json={"keys": []})
    assert r.status_code == 404


# --------------------------------------------------------------------------- #
# rbac-diff
# --------------------------------------------------------------------------- #

def test_rbac_diff_reports_over_grant(client):
    r = client.post("/admin/rbac-diff", json={
        "store_name": "prod",
        "intended": [{"principal": "svc", "action": "read", "namespace": "kb"}],
        "actual": [
            {"principal": "svc", "action": "read", "namespace": "kb"},
            {"principal": "svc", "action": "delete", "namespace": "kb"},
        ],
    })
    assert r.status_code == 200
    findings = r.json()["findings"]
    over = [f for f in findings if f["evidence"]["action"] == "delete"]
    assert over and over[0]["severity"] == "high"


def test_rbac_diff_rejects_malformed_grant(client):
    r = client.post("/admin/rbac-diff",
                    json={"actual": [{"principal": "x"}]})  # no action
    assert r.status_code == 422


# --------------------------------------------------------------------------- #
# validate
# --------------------------------------------------------------------------- #

def test_validate_registered_store(client):
    r = client.post("/admin/validate", json={})
    assert r.status_code == 200
    results = r.json()["results"]
    assert len(results) == 1
    res = results[0]
    assert res["store_id"] == "prod"
    assert res["ok"] is True
    names = {c["name"] for c in res["checks"]}
    assert {"describe", "sample_chunks", "classification_scan"} <= names


def test_validate_unknown_store_filter_404(client):
    r = client.post("/admin/validate", json={"store_id": "ghost"})
    assert r.status_code == 404


# --------------------------------------------------------------------------- #
# datasource scan (stateless)
# --------------------------------------------------------------------------- #

def test_datasource_scan_local(client, tmp_path):
    data_dir = tmp_path / "dataset"
    data_dir.mkdir()
    with open(data_dir / "train.jsonl", "w") as f:
        f.write(json.dumps({"text": "Customer SSN 123-45-6789"}) + "\n")
        f.write(json.dumps({"text": "benign note"}) + "\n")

    r = client.post("/datasources/scan", json={
        "kind": "local", "path": str(data_dir),
        "text_field": "text", "no_nlp": True})
    assert r.status_code == 200
    job = r.json()
    assert len(job["findings"]) >= 1


def test_datasource_scan_bad_spec_400(client):
    r = client.post("/datasources/scan",
                    json={"kind": "local", "path": "/no/such/dir/xyz"})
    assert r.status_code == 400
