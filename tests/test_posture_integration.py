"""Posture inside run_full_audit, and its API routes."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from vecshield_platform.api.app import create_app
from vecshield.classify import RegexClassifier
from vecshield_platform.orchestrator import run_full_audit
from vecshield_platform.posture import run_posture_audit


@pytest.fixture
def chroma_conn(tmp_path):
    import chromadb
    from vecshield_platform.connectors.chroma import ChromaConnector
    path = str(tmp_path / "chroma")
    client = chromadb.PersistentClient(path=path)
    col = client.create_collection("knowledge")
    col.add(ids=["1"], documents=["benign product doc"],
            embeddings=[[0.1, 0.2]], metadatas=[{"source": "catalog"}])
    return ChromaConnector(path=path)


def test_posture_audit_produces_job(chroma_conn):
    job = run_posture_audit(chroma_conn, cve_offline=True)
    assert job.id.startswith("posture-")
    cats = {f.category for f in job.findings}
    # file-backed chroma => local/no-network, cve offline => INFO cve note
    assert "cve" in cats


def test_unreachable_osv_leaves_the_cve_check_inconclusive(chroma_conn, monkeypatch):
    # The "could not reach OSV" notice is itself a `cve` finding; it must not
    # be read as proof that the database answered.
    import urllib.error

    from vecshield_platform.posture import cve as cve_mod

    def boom(name, version, *, timeout):
        raise urllib.error.URLError("no route to host")

    monkeypatch.setattr(cve_mod, "_query_osv", boom)
    job = run_posture_audit(chroma_conn, resolve_dns=False, auth_probe=False)
    cve = [o for o in job.stats["check_outcomes"] if o["check"] == "cve"][0]
    assert cve["outcome"] == "inconclusive"
    assert "chromadb" in cve["reason"]


def test_reachable_osv_with_no_advisories_passes(chroma_conn, monkeypatch):
    from vecshield_platform.posture import cve as cve_mod

    monkeypatch.setattr(cve_mod, "_query_osv", lambda name, version, *, timeout: [])
    job = run_posture_audit(chroma_conn, resolve_dns=False, auth_probe=False)
    cve = [o for o in job.stats["check_outcomes"] if o["check"] == "cve"][0]
    assert cve["outcome"] == "passed"


def test_full_audit_includes_posture(chroma_conn):
    result = run_full_audit(chroma_conn, classifier=RegexClassifier(),
                            cve_offline=True)
    assert any(j.id.startswith("posture-") for j in result.jobs)
    # A file-backed store has no listener: nothing is exposed, and that is a
    # pass the run recorded, not an absence of findings.
    outcomes = {o["check"]: o["outcome"] for o in result.all_check_outcomes()
                if o["collection"] is None}
    assert outcomes["network_exposure"] == "passed"
    assert "network_exposure" not in {f.category for f in result.all_findings()}
    assert outcomes["cve"] == "inconclusive"  # offline: the database was not consulted


def test_full_audit_can_skip_posture(chroma_conn):
    result = run_full_audit(chroma_conn, classifier=RegexClassifier(),
                            include_posture=False)
    assert not any(j.id.startswith("posture-") for j in result.jobs)


@pytest.fixture
def client():
    return TestClient(create_app())


def test_ingest_redact_endpoint(client):
    body = {"chunks": [
        {"id": "1", "text": "ssn 123-45-6789 here"},
        {"id": "2", "text": "clean"},
    ]}
    resp = client.post("/ingest/redact", json=body)
    assert resp.status_code == 200
    data = resp.json()
    assert data["spans_redacted"] == 1
    assert "123-45-6789" not in data["chunks"][0]["text"]
    assert "[REDACTED" in data["chunks"][0]["text"]


def test_ingest_redact_can_hide_preview(client):
    body = {
        "show_preview": False,
        "chunks": [{"id": "1", "text": "ssn 123-45-6789 here"}],
    }
    resp = client.post("/ingest/redact", json=body)
    assert resp.status_code == 200
    data = resp.json()
    assert data["spans_redacted"] == 1
    assert "chunks" not in data


def test_security_cves_endpoint_offline(client):
    resp = client.get("/security/cves?offline=true")
    assert resp.status_code == 200
    assert "findings" in resp.json()
