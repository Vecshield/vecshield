"""The ingest API: /ingest/gate and /ingest/analyze-boundaries."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from vecshield_platform.api.app import create_app


@pytest.fixture
def client():
    return TestClient(create_app())


def test_ingest_gate_endpoint(client):
    body = {
        "chunks": [
            {"id": "1", "text": "clean text"},
            {"id": "2", "text": "leak ssn 123-45-6789"},
            {"id": "3", "text": "also clean"},
        ],
        "mode": "soft",
    }
    resp = client.post("/ingest/gate", json=body)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 3
    assert data["blocked"] == 1
    assert data["allowed"] == 2
    assert "2" in data["blocked_chunk_ids"]


def test_ingest_gate_bad_severity(client):
    resp = client.post("/ingest/gate", json={"chunks": [], "block_severity": "nope"})
    assert resp.status_code == 400


def test_analyze_boundaries_endpoint(client):
    body = {
        "chunks": [
            {"id": "a", "text": "my social is 123-45"},
            {"id": "b", "text": "-6789 done"},
        ],
        "zone_chars": 20,
    }
    resp = client.post("/ingest/analyze-boundaries", json=body)
    assert resp.status_code == 200
    data = resp.json()
    assert data["chunks"] == 2
    assert len(data["findings"]) == 1
    assert data["findings"][0]["category"] == "boundary_pii"
