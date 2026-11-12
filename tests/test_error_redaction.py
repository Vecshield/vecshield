"""Connector error text never reaches an API caller.

An SDK's exception message can echo a DSN, URL or key, and ``translate_error``
passes exceptions it does not recognise through unchanged. Every route that
reports a connector failure says its category and exception type instead; the
full message goes to the server log only. Regression tests for the routes that
used to return ``str(e)``: validation, the estate probe, schema discovery, the
audit (inline and as a background job).
"""

from __future__ import annotations

import time
from typing import Iterator

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from vecshield.models import Chunk, Collection, VectorStore  # noqa: E402
from vecshield_platform.api import create_app  # noqa: E402
from vecshield_platform.api.registry import StoreRegistry  # noqa: E402
from vecshield_platform.connectors.base import Connector  # noqa: E402

SECRET = "hunter2"
LEAKY = f"could not connect to postgresql://svc:{SECRET}@db.internal:5432/rag"

VIEWER = {"Authorization": "Bearer read-tok"}
OPERATOR_ADMIN = {"Authorization": "Bearer admin-tok"}


class _BrokenRead(Connector):
    """Opens and describes itself, then fails reading content."""

    kind = "fake"

    def capabilities(self) -> set[str]:
        return set()

    def describe(self) -> VectorStore:
        return VectorStore(kind=self.kind, name="fake://store", endpoint="fake://store",
                           collections=[Collection(name="docs", count=1)])

    def list_collections(self) -> list[Collection]:
        return self.describe().collections

    def iter_chunks(self, collection: str, batch_size: int = 256) -> Iterator[Chunk]:
        raise RuntimeError(LEAKY)

    def query(self, collection, vector, top_k=10, where=None):
        return []


class _BrokenDescribe(_BrokenRead):
    def describe(self) -> VectorStore:
        raise RuntimeError(LEAKY)


def _cannot_open():
    raise RuntimeError(LEAKY)


@pytest.fixture
def client():
    reg = StoreRegistry()
    reg.register("cannot-open", "fake", factory=_cannot_open)
    reg.register("broken-describe", "fake", factory=_BrokenDescribe)
    reg.register("broken-read", "fake", factory=_BrokenRead)
    app = create_app(reg, serve_ui=False, auth_token="read-tok", admin_token="admin-tok")
    c = TestClient(app)
    yield c
    app.state.jobs.shutdown(wait=False)


def test_validate_reports_type_not_text(client):
    r = client.post("/admin/validate", json={}, headers=VIEWER)
    assert r.status_code == 200, r.text
    assert SECRET not in r.text
    results = {row["store_id"]: row for row in r.json()["results"]}
    assert results["cannot-open"]["error"] == "open failed: error: RuntimeError"
    assert results["broken-describe"]["error"] == "error: RuntimeError"
    sample = next(c for c in results["broken-read"]["checks"]
                  if c["name"] == "sample_chunks")
    assert sample["detail"] == "docs: error: RuntimeError"


def test_estate_probe_reports_type_not_text(client):
    r = client.get("/admin/estate?probe=true", headers=VIEWER)
    assert r.status_code == 200, r.text
    assert SECRET not in r.text


def test_schema_discovery_reports_type_not_text(client):
    r = client.get("/stores/broken-describe/schema", headers=VIEWER)
    assert r.status_code == 400
    assert SECRET not in r.text
    assert "RuntimeError" in r.json()["detail"]


def test_audit_reports_type_not_text_inline_and_in_background(client):
    r = client.post("/stores/broken-describe/audit", json={}, headers=OPERATOR_ADMIN)
    assert r.status_code == 400
    assert SECRET not in r.text

    queued = client.post("/stores/broken-describe/audit?background=true", json={},
                         headers=OPERATOR_ADMIN)
    assert queued.status_code == 202, queued.text
    job_id = queued.json()["job_id"]
    for _ in range(100):
        job = client.get(f"/admin/jobs/{job_id}", headers=VIEWER).json()
        if job["status"] in ("succeeded", "failed"):
            break
        time.sleep(0.05)
    assert job["status"] == "failed"
    assert job["error"] and SECRET not in job["error"]
