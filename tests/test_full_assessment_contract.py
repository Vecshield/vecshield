"""The assessment contract, end to end on a real (embedded) Chroma store.

A full audit runs through the API over the seeded scenario in
``assessment_contract``. The run must report what each check concluded, not
only which findings exist, and those outcomes must survive unchanged into the
saved history and the frozen HTML report. The same contract runs against
container stores in ``tests/integration``.
"""

from __future__ import annotations

import pytest

pytest.importorskip("chromadb")
pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from assessment_contract import (  # noqa: E402
    AUDIT_REQUEST,
    CLEAN,
    PLANTED,
    assert_capped,
    assert_contract,
    report_rows,
    scenario,
)
from vecshield_platform.api import create_app  # noqa: E402
from vecshield_platform.api.config_store import ConfigStore  # noqa: E402
from vecshield_platform.history import ScanHistory  # noqa: E402
from vecshield_platform.integrity.records import DetectorReport  # noqa: E402

STORE_ID = "contract-chroma"

#: What an embedded Chroma store's own facts decide.
CHROMA_OUTCOMES = {
    # A filesystem store has no network listener or transport.
    "network_exposure": "passed",
    "transport_encryption": "passed",
    "transport_tls_enforcement": "passed",
    "query_result_ceiling": "passed",
    "model_egress": "passed",
    # Chroma's API offers no way to report these.
    "at_rest_encryption": "unsupported",
    "field_encryption": "unsupported",
    "access_grants": "unsupported",
    "data_residency": "unsupported",
    "server_support_status": "unsupported",
    "server_hardening": "unsupported",
    # Access to an embedded store is governed by file permissions, not a
    # service credential.
    "authentication": "unsupported",
    # Decided by the installed chromadb against the bundled advisory feed.
    "server_vulnerability": ("passed", "failed"),
    # Filters are honoured, but every caller must supply one: convention-only.
    ("tenant_isolation", CLEAN): "failed",
    ("tenant_isolation", PLANTED): "failed",
}

#: Unsupported without a capability limit: an embedded store has no service
#: credential to observe, so authentication is recorded as a coverage gap and
#: is the one store-specific reason a Chroma run is partial.
CHROMA_UNEXPLAINED = frozenset({"authentication"})


def _seed(path: str) -> None:
    import chromadb

    client = chromadb.PersistentClient(path=path)
    for name, chunks in scenario().collections.items():
        col = client.create_collection(name, configuration={"hnsw": {"space": "cosine"}})
        col.add(ids=[c.id for c in chunks], documents=[c.text for c in chunks],
                embeddings=[c.embedding for c in chunks],
                metadatas=[c.metadata for c in chunks])


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    root = tmp_path_factory.mktemp("contract")
    _seed(str(root / "chroma"))
    app = create_app(config_store=ConfigStore(path=str(root / "config.json")),
                     scan_history=ScanHistory(), serve_ui=False)
    c = TestClient(app)
    created = c.post("/admin/stores", json={"store_id": STORE_ID, "kind": "chroma",
                                            "conn": {"path": str(root / "chroma")}})
    assert created.status_code == 200, created.text
    return c


@pytest.fixture(scope="module")
def audit(client) -> dict:
    response = client.post(f"/stores/{STORE_ID}/audit", json=AUDIT_REQUEST)
    assert response.status_code == 200, response.text
    return response.json()


def test_a_full_audit_meets_the_contract(audit):
    assert audit["scope"]["cve_offline"] is True
    assert audit["scope"]["detection"]["classifier"] == "regex"
    assert_contract(audit, store_outcomes=CHROMA_OUTCOMES, store_incomplete=CHROMA_UNEXPLAINED,
                    allowed_unsupported=CHROMA_UNEXPLAINED)


def test_the_saved_audit_reads_back_unchanged(client, audit):
    saved = client.get(f"/admin/history/audits/{audit['id']}")
    assert saved.status_code == 200
    snapshot = saved.json()
    for key in ("check_outcomes", "coverage", "status", "summary", "violations"):
        assert snapshot[key] == audit[key], key
    listed = client.get("/admin/history/audits", params={"store_id": STORE_ID}).json()
    assert audit["id"] in [a["id"] for a in listed["audits"]]


def test_the_report_states_every_check_outcome(client, audit):
    page = client.get(f"/stores/{STORE_ID}/report", params={"audit_id": audit["id"]})
    assert page.status_code == 200
    assert f"execution {audit['status']}" in page.text
    assert report_rows(page.text) == [
        (o["check"], o["collection"] or "(store)", o["outcome"])
        for o in audit["check_outcomes"]]


def test_a_capped_run_is_partial_and_never_passes(client):
    response = client.post(f"/stores/{STORE_ID}/audit",
                           json={**AUDIT_REQUEST, "max_chunks_per_collection": 50})
    assert response.status_code == 200, response.text
    assert_capped(response.json(), limit=50, allowed_unsupported=CHROMA_UNEXPLAINED)


def test_the_contract_catches_a_silenced_detector(client, monkeypatch):
    # A hubness detector that reports nothing must break the contract: the
    # planted hub would otherwise pass as clean.
    monkeypatch.setattr("vecshield_platform.integrity.engine.analyze_hubness",
                        lambda **_: DetectorReport(check="retrieval_hubness"))
    silenced = client.post(f"/stores/{STORE_ID}/audit", json=AUDIT_REQUEST).json()
    with pytest.raises(AssertionError, match="retrieval_hubness"):
        assert_contract(silenced, store_outcomes=CHROMA_OUTCOMES,
                        store_incomplete=CHROMA_UNEXPLAINED,
                        allowed_unsupported=CHROMA_UNEXPLAINED)
