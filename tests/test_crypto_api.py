"""The Crypto Posture routes read saved audits; they never scan."""

from __future__ import annotations

import sys
import types

from test_assessment_snapshots import audit_result
from test_criteria import api_client
from test_crypto_view import full_outcomes

from vecshield_platform.compliance.crypto_basis import crypto_basis


def _save(history, audit_id, *, outcomes, store_id="prod"):
    result = audit_result(audit_id=audit_id, job_id=f"job-{audit_id}")
    result.check_outcomes.extend(outcomes)
    history.save_audit(result, store_id=store_id)
    return result.id


def test_crypto_basis_route_serves_the_basis_table(tmp_path):
    client, history, app = api_client(tmp_path)
    try:
        body = client.get("/compliance/crypto-basis").json()
        assert body == {"basis": crypto_basis()}
        ai_act = next(r for r in body["basis"] if r["framework"] == "EU AI Act")
        assert ai_act["criteria"] == [] and ai_act["relationship"] == "supporting"
    finally:
        app.state.jobs.shutdown(wait=False)
        history.close()


def test_crypto_posture_reads_the_latest_audit_and_the_one_before(tmp_path,
                                                                  monkeypatch):
    compared = []
    monkeypatch.setitem(sys.modules, "vecshield_platform.drift",
                        types.SimpleNamespace(diff_snapshots=lambda before, after: (
                            compared.append((before["id"], after["id"]))
                            or {"checks": []})))
    client, history, app = api_client(tmp_path)
    try:
        assert client.get("/stores/prod/crypto-posture").status_code == 409
        assert client.get("/stores/nope/crypto-posture").status_code == 404

        first = _save(history, "audit-a", outcomes=[])
        body = client.get("/stores/prod/crypto-posture").json()
        assert body["audit_id"] == first and body["store_id"] == "prod"
        assert body["drift"] == {"previous_audit_id": None, "compared": False,
                                 "changes": []}
        assert all(row["outcome"] == "not_run"
                   for layer in body["layers"] for row in layer["rows"])

        second = _save(history, "audit-b", outcomes=full_outcomes())
        _save(history, "audit-z", outcomes=[], store_id="other")
        body = client.get("/stores/prod/crypto-posture").json()
        assert body["audit_id"] == second
        assert body["drift"]["previous_audit_id"] == first
        assert compared[-1] == (first, second)
        assert [layer["layer"] for layer in body["layers"]] == [
            "transport", "storage", "data", "retrieval"]
        assert "%" not in str(body)

        pinned = client.get(f"/stores/prod/crypto-posture?audit_id={first}").json()
        assert pinned["audit_id"] == first
        assert pinned["drift"]["previous_audit_id"] is None
    finally:
        app.state.jobs.shutdown(wait=False)
        history.close()


def test_crypto_posture_rejects_missing_and_foreign_audits(tmp_path):
    client, history, app = api_client(tmp_path)
    try:
        foreign = _save(history, "audit-other", outcomes=[], store_id="other")
        assert client.get("/stores/prod/crypto-posture").status_code == 409
        assert client.get(
            "/stores/prod/crypto-posture?audit_id=missing").status_code == 404
        response = client.get(f"/stores/prod/crypto-posture?audit_id={foreign}")
        assert response.status_code == 404
        assert "not from store" in response.json()["detail"]
    finally:
        app.state.jobs.shutdown(wait=False)
        history.close()
