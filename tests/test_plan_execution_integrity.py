"""Executing an approved plan: one run per plan, a record that survives the
read-back, separation of duties re-checked at run time, and intent logged
before anything irreversible (bug hunt approvals M1, M2, L1; audit contract).
"""
from __future__ import annotations

import json
import threading

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("chromadb")

from fastapi.testclient import TestClient  # noqa: E402

from test_auth import make_jwt  # noqa: E402

from vecshield_platform.api import StoreRegistry, create_app  # noqa: E402
from vecshield_platform.compliance import AuditLog  # noqa: E402
from vecshield_platform.history import ScanHistory  # noqa: E402

SECRET = "plan-exec-secret"
SUBJECT = "jane@example.com"


def tok(sub, *roles):
    return {"Authorization": "Bearer " + make_jwt({"sub": sub, "roles": list(roles)}, SECRET)}


ALICE = tok("alice", "compliance")
BOB = tok("bob", "compliance")
ADMIN = tok("root", "admin")


class IntentFailingLog(AuditLog):
    """An audit log whose disk write fails for intent entries."""

    def append(self, actor, action, target, details=None):
        if action.endswith("_started"):
            raise OSError("disk full")
        return super().append(actor, action, target, details)


def _chroma(path):
    import chromadb
    col = chromadb.PersistentClient(path=path).create_collection("runbooks")
    col.add(ids=["c1", "c2", "c3"],
            documents=["rotate AKIAIOSFODNN7EXAMPLE tonight", "benign note",
                       f"Ticket from {SUBJECT} re billing"],
            embeddings=[[0.1, 0.2], [0.9, 0.1], [0.3, 0.3]],
            metadatas=[{"team": "sre"}, {"team": "sre"}, {"team": "billing"}])


def _col(path):
    import chromadb
    return chromadb.PersistentClient(path=path).get_collection("runbooks")


def _seed_finding(hist):
    evidence = {"labels": {"SECRET": 1}, "sensitive_chunks": 40,
                "examples": [{"chunk_id": "c1", "label": "SECRET",
                              "detectors": ["aws_access_key"]}]}
    with hist._lock, hist._conn:
        hist._conn.execute(
            "INSERT INTO findings (id, job_id, store, collection, title, severity, "
            "category, description, evidence, remediation, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("f1", "job-seed", "demo", "runbooks", "SECRET detected", "critical",
             "data_classification", "", json.dumps(evidence), "", "2026-09-18T00:00:00Z"))


@pytest.fixture
def env(tmp_path, monkeypatch):
    for name in ("VECSHIELD_SAFE_MODE", "VECSHIELD_SEPARATION_OF_DUTIES"):
        monkeypatch.delenv(name, raising=False)
    path = str(tmp_path / "chroma")
    _chroma(path)
    reg = StoreRegistry()
    reg.register("demo", "chroma", path=path)
    hist = ScanHistory(str(tmp_path / "history.db"))
    _seed_finding(hist)
    apps = []

    def make(log=None, **kw):
        app = create_app(reg, scan_history=hist, audit_log=log or AuditLog(),
                         serve_ui=False, jwt_secret=SECRET, **kw)
        apps.append(app)
        return TestClient(app), app.state.audit_log

    yield make, hist, path
    for app in apps:
        app.state.jobs.shutdown(wait=False)


def _stage_and_approve(client, *, stager=ALICE, approver=BOB):
    plan = client.post("/stores/demo/actions/plans", headers=stager, json={"suggestions": [{
        "id": "s1", "action": "tag_exclude", "finding_id": "f1",
        "collection": "runbooks", "chunk_ids": ["c1"], "rests_on": ["aws_access_key"],
        "observed_chunks": 40, "named_chunks": 1}]})
    assert plan.status_code == 200, plan.text
    plan = plan.json()
    appr = client.post(f"/actions/plans/{plan['id']}/approve", headers=approver,
                       json={"reason": "reviewed the diff"})
    assert appr.status_code == 200, appr.text
    return plan, appr.json()


def test_staging_refuses_a_finding_the_store_never_recorded(env):
    make, hist, path = env
    client, _ = make()
    r = client.post("/stores/demo/actions/plans", headers=ALICE, json={"suggestions": [{
        "id": "s1", "action": "tag_exclude", "finding_id": "made-up",
        "collection": "runbooks", "chunk_ids": ["c2"]}]})
    assert r.status_code == 400
    assert "not a stored finding" in r.json()["detail"]


def test_concurrent_executions_run_the_plan_once(env, monkeypatch):
    make, hist, path = env
    client, log = make()
    plan, appr = _stage_and_approve(client)
    monkeypatch.setenv("VECSHIELD_SAFE_MODE", "0")

    import vecshield_platform.actions as actions_mod
    real = actions_mod.plan_from_body
    barrier = threading.Barrier(2, timeout=10)

    def both_read_staged(body):
        out = real(body)
        barrier.wait()      # both requests have read "staged" before either claims
        return out

    monkeypatch.setattr(actions_mod, "plan_from_body", both_read_staged)
    results = []

    def run():
        r = client.post(f"/actions/plans/{plan['id']}/execute", headers=BOB,
                        json={"approval_id": appr["id"]})
        results.append((r.status_code, r.json()))

    threads = [threading.Thread(target=run) for _ in range(2)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sorted(code for code, _ in results) == [200, 409], results
    refused = [body for code, body in results if code == 409][0]
    assert "already executing" in refused["detail"] or "already executed" in refused["detail"]
    assert len(hist.list_executions(plan_id=plan["id"])) == 1
    assert hist.get_plan(plan["id"])["state"] == "executed"


def test_a_failed_read_back_keeps_the_execution_record(env, monkeypatch):
    make, hist, path = env
    client, log = make()
    plan, appr = _stage_and_approve(client)
    monkeypatch.setenv("VECSHIELD_SAFE_MODE", "0")
    import vecshield_platform.execution as execution_mod

    def broken_verify(*a, **k):
        raise ConnectionError("store went away during the read-back")

    monkeypatch.setattr(execution_mod, "verify_plan", broken_verify)
    r = client.post(f"/actions/plans/{plan['id']}/execute", headers=BOB,
                    json={"approval_id": appr["id"]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["verification"]["outcome"] == "inconclusive"
    assert "ConnectionError" in body["verification"]["reason"]
    execs = hist.list_executions(plan_id=plan["id"])
    assert len(execs) == 1
    stored = hist.get_execution(execs[0]["id"])
    assert stored["verification"]["outcome"] == "inconclusive"
    assert hist.get_plan(plan["id"])["state"] == "executed"
    assert [e for e in log.entries if e.action == "action_plan_executed"]
    assert _col(path).get(ids=["c1"])["metadatas"] != [{"team": "sre"}]  # it was written
    # The plan cannot be run again as if nothing happened.
    again = client.post(f"/actions/plans/{plan['id']}/execute", headers=BOB,
                        json={"approval_id": appr["id"]})
    assert again.status_code == 409


def test_a_refused_execution_releases_the_claim(env):
    make, hist, path = env
    client, log = make()
    plan, appr = _stage_and_approve(client)
    r = client.post(f"/actions/plans/{plan['id']}/execute", headers=BOB,
                    json={"approval_id": appr["id"]})
    assert r.status_code == 409 and "safe mode" in r.json()["detail"]
    assert hist.get_plan(plan["id"])["state"] == "staged"


def test_separation_of_duties_is_rechecked_when_the_plan_runs(env, monkeypatch):
    make, hist, path = env
    loose, _ = make(separation_of_duties="off")
    plan, appr = _stage_and_approve(loose, stager=ALICE, approver=ALICE)
    assert appr["self_approved"] is True
    strict, _ = make(separation_of_duties="admin_may_self_approve")
    monkeypatch.setenv("VECSHIELD_SAFE_MODE", "0")
    r = strict.post(f"/actions/plans/{plan['id']}/execute", headers=ALICE,
                    json={"approval_id": appr["id"]})
    assert r.status_code == 409, r.text
    assert hist.list_executions(plan_id=plan["id"]) == []
    assert hist.get_plan(plan["id"])["state"] == "staged"


def test_plan_execution_is_refused_when_its_intent_cannot_be_logged(env, monkeypatch):
    make, hist, path = env
    client, log = make(IntentFailingLog())
    plan, appr = _stage_and_approve(client)
    monkeypatch.setenv("VECSHIELD_SAFE_MODE", "0")
    r = client.post(f"/actions/plans/{plan['id']}/execute", headers=BOB,
                    json={"approval_id": appr["id"]})
    assert r.status_code == 503
    assert "audit log could not be written" in r.json()["detail"]
    assert "not executed" in r.json()["detail"]
    assert hist.list_executions(plan_id=plan["id"]) == []
    assert hist.get_plan(plan["id"])["state"] == "staged"
    assert _col(path).get(ids=["c1"])["metadatas"] == [{"team": "sre"}]  # untouched


def test_erasure_is_refused_when_its_intent_cannot_be_logged(env, monkeypatch):
    make, hist, path = env
    client, log = make(IntentFailingLog())
    monkeypatch.setenv("VECSHIELD_SAFE_MODE", "0")
    r = client.post("/stores/demo/erasure/execute", headers=ADMIN, json={"subject": SUBJECT})
    assert r.status_code == 503 and "nothing was deleted" in r.json()["detail"]
    assert "c3" in _col(path).get()["ids"]


def test_dsar_execution_is_refused_when_its_intent_cannot_be_logged(env, monkeypatch):
    make, hist, path = env
    client, log = make(IntentFailingLog())
    d = client.post("/admin/dsar", headers=ALICE, json={"subject": SUBJECT}).json()
    monkeypatch.setenv("VECSHIELD_SAFE_MODE", "0")
    r = client.post(f"/admin/dsar/{d['id']}/execute", headers=BOB, json={})
    assert r.status_code == 503 and "nothing was deleted" in r.json()["detail"]
    assert "c3" in _col(path).get()["ids"]


def test_a_plan_left_executing_by_a_dead_process_is_halted_at_startup(env):
    make, hist, _ = env
    client, _log = make()
    plan, appr = _stage_and_approve(client)
    assert hist.claim_plan(plan["id"])  # the process that claimed it then died
    _client2, log2 = make()
    assert hist.get_plan(plan["id"])["state"] == "halted"
    assert any(e.action == "action_plan_halted" and e.target == plan["id"]
               for e in log2.entries)
    again = _client2.post(f"/actions/plans/{plan['id']}/execute", headers=ALICE,
                          json={"approval_id": appr["id"]})
    assert again.status_code == 409, again.text
