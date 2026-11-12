"""F3: DSAR reads, the full audit log and DSAR job details are compliance
reads, and the audit log names a subject only by a keyed hash."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("chromadb")

from fastapi.testclient import TestClient  # noqa: E402

from test_auth import make_jwt  # noqa: E402

from vecshield_platform.api import StoreRegistry, create_app  # noqa: E402
from vecshield_platform.compliance import AuditLog  # noqa: E402
from vecshield_platform.history import ScanHistory  # noqa: E402

SECRET = "f3-secret"
SUBJECT = "Maya.Brooks@Example.test"


def tok(sub, *roles):
    return {"Authorization": "Bearer " + make_jwt({"sub": sub, "roles": list(roles)}, SECRET)}


VIEWER = tok("vera", "viewer")
OPERATOR = tok("otto", "operator")
ALICE = tok("alice", "compliance")
BOB = tok("bob", "compliance")
ADMIN = tok("root", "admin")


@pytest.fixture
def env(tmp_path, monkeypatch):
    import chromadb
    for name in ("VECSHIELD_SAFE_MODE", "VECSHIELD_SEPARATION_OF_DUTIES"):
        monkeypatch.delenv(name, raising=False)
    path = str(tmp_path / "chroma")
    col = chromadb.PersistentClient(path=path).create_collection("tickets")
    col.add(ids=["a", "b"], documents=[f"Ticket from {SUBJECT.lower()}", "unrelated"],
            embeddings=[[0.1, 0.2], [0.9, 0.1]], metadatas=[{"t": 1}, {"t": 2}])
    reg = StoreRegistry()
    reg.register("demo", "chroma", path=path)
    hist = ScanHistory(str(tmp_path / "history.db"))
    log = AuditLog()
    app = create_app(reg, scan_history=hist, audit_log=log, serve_ui=False,
                     jwt_secret=SECRET)
    yield TestClient(app), hist, log, app
    app.state.jobs.shutdown(wait=False)


def _raw_subject_anywhere(log) -> bool:
    import json
    blob = json.dumps([e.to_dict() for e in log.entries]).lower()
    return SUBJECT.lower() in blob


@pytest.mark.parametrize("headers", [VIEWER, OPERATOR])
def test_dsar_reads_need_compliance(env, headers):
    client, *_ = env
    d = client.post("/admin/dsar", headers=ALICE, json={"subject": SUBJECT}).json()
    for url in ("/admin/dsar", f"/admin/dsar/{d['id']}", f"/admin/dsar/{d['id']}/evidence"):
        r = client.get(url, headers=headers)
        assert r.status_code == 403, url
        assert r.json()["detail"] == "requires role: compliance"
    assert client.get("/admin/dsar", headers=BOB).status_code == 200
    assert client.get(f"/admin/dsar/{d['id']}", headers=ADMIN).json()["subject"] == SUBJECT


def test_audit_log_details_are_compliance_only(env):
    client, *_ = env
    client.post("/admin/dsar", headers=ALICE, json={"subject": SUBJECT})
    viewer = client.get("/audit-log", headers=VIEWER).json()
    assert viewer["details_withheld"] is True and viewer["verified"] is True
    assert all(e["details"] is None for e in viewer["entries"])
    assert any(e["action"] == "dsar_created" for e in viewer["entries"])
    full = client.get("/audit-log", headers=ALICE).json()
    assert full["details_withheld"] is False
    created = next(e for e in full["entries"] if e["action"] == "dsar_created")
    assert created["details"]["subject_key"].startswith("subject-key:")


def test_the_audit_log_never_holds_the_raw_subject(env, monkeypatch):
    client, hist, log, _ = env
    monkeypatch.setenv("VECSHIELD_SAFE_MODE", "0")
    client.post("/stores/demo/erasure", headers=ALICE, json={"subject": SUBJECT})
    d = client.post("/admin/dsar", headers=ALICE, json={"subject": SUBJECT}).json()
    r = client.post(f"/admin/dsar/{d['id']}/execute", headers=BOB, json={})
    assert r.status_code == 200, r.text
    assert not _raw_subject_anywhere(log)


def test_direct_erasure_receipt_uses_the_subject_key(env, monkeypatch):
    client, hist, log, _ = env
    monkeypatch.setenv("VECSHIELD_SAFE_MODE", "0")
    r = client.post("/stores/demo/erasure/execute", headers=ADMIN, json={"subject": SUBJECT})
    assert r.status_code == 200, r.text
    receipt = r.json()["receipt"]
    assert receipt["subject"].startswith("subject-key:")
    assert not _raw_subject_anywhere(log)


def test_subject_key_is_stable_normalized_and_keyed(env, tmp_path):
    client, hist, log, _ = env
    for subject in (SUBJECT, "  maya.brooks@example.TEST "):
        client.post("/stores/demo/erasure", headers=ALICE, json={"subject": subject})
    keys = [e.details["subject_key"] for e in log.entries
            if e.action == "erasure_assessment"]
    assert len(keys) == 2 and keys[0] == keys[1]
    # A different deployment key gives a different subject key.
    other = create_app(StoreRegistry(), scan_history=ScanHistory(str(tmp_path / "h2.db")),
                       audit_log=(log2 := AuditLog()), serve_ui=False, jwt_secret=SECRET)
    try:
        TestClient(other).post("/admin/dsar", headers=ALICE, json={"subject": SUBJECT})
        assert log2.entries[-1].details["subject_key"] != keys[0]
    finally:
        other.state.jobs.shutdown(wait=False)


def test_dsar_job_is_restricted_for_non_compliance(env):
    import time
    client, *_ = env
    r = client.post("/admin/dsar?background=true", headers=ALICE, json={"subject": SUBJECT})
    assert r.status_code == 202
    job_id = r.json()["job_id"]
    for _ in range(100):
        job = client.get(f"/admin/jobs/{job_id}", headers=ALICE).json()
        if job["status"] in ("succeeded", "failed"):
            break
        time.sleep(0.05)
    assert job["status"] == "succeeded"
    # The stored resource is a key, never the subject.
    assert job["resource"].startswith("subject-key:")
    assert job["result"]["subject"] == SUBJECT  # compliance sees the result
    viewer = client.get(f"/admin/jobs/{job_id}", headers=VIEWER).json()
    assert viewer["restricted"] is True
    assert viewer["result"] is None and viewer["resource"] == "(restricted)"
    listed = client.get("/admin/jobs", headers=VIEWER).json()["jobs"]
    assert SUBJECT not in str(listed) and SUBJECT.lower() not in str(listed).lower()
