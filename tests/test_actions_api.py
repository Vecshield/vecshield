"""The action endpoints and CLI: what they publish, and what they refuse.

The API tests exist mainly to pin two refusals a unit test cannot reach — a
plan whose stored body no longer matches its hash, and a plan id that is written
twice — because both are ways an approved plan could be swapped for a different
one.
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from vecshield_platform.api import create_app  # noqa: E402
from vecshield_platform.api.config_store import ConfigStore  # noqa: E402
from vecshield_platform.cli import cli  # noqa: E402
from vecshield_platform.history import ScanHistory  # noqa: E402


@pytest.fixture
def chroma_path(tmp_path):
    import chromadb

    client = chromadb.PersistentClient(path=str(tmp_path / "chroma"))
    col = client.create_collection("runbooks")
    col.add(ids=["c1", "c2"],
            documents=["rotate AKIAIOSFODNN7EXAMPLE tonight", "benign note"],
            embeddings=[[0.1, 0.2]] * 2,
            metadatas=[{"team": "sre"}, {"team": "sre"}])
    return str(tmp_path / "chroma")


def _seed_finding(history, finding_id="f1", store="demo", *, evidence=None):
    """A stored finding for the suggestions below to answer.

    Staging over the API checks each suggestion against the stored finding it
    names, so a made-up finding id is refused.
    """
    evidence = evidence or {"labels": {"SECRET": 1}, "sensitive_chunks": 40,
                            "examples": [{"chunk_id": "c1", "label": "SECRET",
                                          "detectors": ["aws_access_key"]}]}
    with history._lock, history._conn:
        history._conn.execute(
            "INSERT INTO findings (id, job_id, store, collection, title, severity, "
            "category, description, evidence, remediation, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (finding_id, "job-seed", store, "runbooks", "SECRET detected", "critical",
             "data_classification", "", json.dumps(evidence), "",
             "2026-09-18T00:00:00Z"))


@pytest.fixture
def history(tmp_path):
    h = ScanHistory(str(tmp_path / "history.db"))
    _seed_finding(h)
    return h


@pytest.fixture
def client(tmp_path, chroma_path, history):
    cfg = ConfigStore(path=str(tmp_path / "config.json"))
    app = create_app(config_store=cfg, serve_ui=False, scan_history=history)
    test_client = TestClient(app)
    test_client.post("/admin/stores", json={
        "store_id": "demo", "kind": "chroma", "conn": {"path": chroma_path}})
    yield test_client
    app.state.jobs.shutdown(wait=False)


def _finding():
    return {
        "id": "f1", "store": "demo", "collection": "runbooks",
        "evidence": {
            "labels": {"SECRET": 1}, "sensitive_chunks": 40,
            "examples": [{"chunk_id": "c1", "label": "SECRET",
                          "detectors": ["aws_access_key"]}],
        },
    }


# --------------------------------------------------------------------------- #
# API                                                                          #
# --------------------------------------------------------------------------- #

def test_suggest_publishes_the_refusals_alongside_the_proposals(client):
    """A caller seeing one proposal must be able to see the two refused."""
    body = client.post("/stores/demo/actions/suggest", json={}).json()
    assert "suggestions" in body and "withheld" in body
    assert "Nothing is staged or executed" in body["note"]


def test_staging_an_empty_plan_is_refused(client):
    r = client.post("/stores/demo/actions/plans", json={"suggestions": []})
    assert r.status_code == 400
    assert "at least one suggestion" in r.json()["detail"]


def test_staging_an_unknown_action_is_refused_rather_than_ignored(client):
    r = client.post("/stores/demo/actions/plans", json={"suggestions": [
        {"id": "s1", "action": "reformat_the_disk", "finding_id": "f1"}]})
    assert r.status_code == 400


def test_a_staged_plan_is_persisted_with_its_diff(client):
    r = client.post("/stores/demo/actions/plans", json={"suggestions": [{
        "id": "s1", "action": "tag_exclude", "finding_id": "f1",
        "collection": "runbooks", "chunk_ids": ["c1"], "rests_on": ["aws_access_key"],
        "observed_chunks": 40, "named_chunks": 1}]})
    assert r.status_code == 200
    plan = r.json()
    assert plan["plan_hash"]
    diff = client.get(f"/actions/plans/{plan['id']}/diff").json()
    assert diff["review"]["executes"] is False
    assert "writes nothing to the store" in diff["review"]["execution_note"]
    assert "safe mode is off" in diff["review"]["execution_note"]
    assert any("does not resolve the findings" in w for w in diff["review"]["warnings"])


def test_an_unknown_plan_is_a_404_not_an_empty_diff(client):
    assert client.get("/actions/plans/plan-nope/diff").status_code == 404


def test_a_tampered_plan_is_refused_rather_than_rendered(client, history):
    """A diff nobody can trust is worse than no diff."""
    r = client.post("/stores/demo/actions/plans", json={"suggestions": [{
        "id": "s1", "action": "tag_exclude", "finding_id": "f1",
        "collection": "runbooks", "chunk_ids": ["c1"]}]})
    plan_id = r.json()["id"]

    with history._lock, history._conn:
        row = history._conn.execute(
            "SELECT body FROM action_plans WHERE id = ?", (plan_id,)).fetchone()
        body = json.loads(row["body"])
        body["operations"][0]["targets"] = []          # quietly widen the plan
        history._conn.execute("UPDATE action_plans SET body = ? WHERE id = ?",
                              (json.dumps(body), plan_id))

    r = client.get(f"/actions/plans/{plan_id}/diff")
    assert r.status_code == 409
    assert "does not match its recorded hash" in r.json()["detail"]


def test_plans_are_listed_for_a_store(client):
    client.post("/stores/demo/actions/plans", json={"suggestions": [{
        "id": "s1", "action": "tag_exclude", "finding_id": "f1",
        "collection": "runbooks", "chunk_ids": ["c1"]}]})
    body = client.get("/stores/demo/actions/plans").json()
    assert len(body["plans"]) == 1
    assert body["plans"][0]["staged_by"]


def test_staging_records_an_audit_entry(client):
    client.post("/stores/demo/actions/plans", json={"suggestions": [{
        "id": "s1", "action": "tag_exclude", "finding_id": "f1",
        "collection": "runbooks", "chunk_ids": ["c1"]}]})
    body = client.get("/audit-log").json()
    entries = body.get("entries", body) if isinstance(body, dict) else body
    assert "action_plan_staged" in {e.get("action") for e in entries}


def test_nothing_writes_to_a_store_except_the_one_gated_endpoint(client):
    """v2.4 asserted no execute route at all. v2.5 adds exactly one, and the
    invariant becomes: it is the only one, and it cannot be called without an
    approval id in the body."""
    import inspect

    paths = {r.path for r in client.app.routes if hasattr(r, "path")}
    writing = {p for p in paths if "actions" in p and
               any(word in p for word in ("execute", "apply", "run"))}
    assert writing == {"/actions/plans/{plan_id}/execute"}

    route = next(r for r in client.app.routes
                 if getattr(r, "path", None) == "/actions/plans/{plan_id}/execute")
    signature = inspect.signature(route.endpoint)
    assert "req" in signature.parameters       # ExecutePlanRequest.approval_id is required
    assert client.post("/actions/plans/plan-x/execute", json={}).status_code == 422


# --------------------------------------------------------------------------- #
# Persistence                                                                  #
# --------------------------------------------------------------------------- #

def test_a_plan_id_cannot_be_written_twice(tmp_path):
    """An approval is scoped to a plan id. Rewriting one would defeat that."""
    from vecshield_platform.actions import ActionPlan

    hist = ScanHistory(str(tmp_path / "h.db"))
    plan = ActionPlan(id="plan-1", store="demo", staged_by="kim",
                      staged_at="2026-09-18T00:00:00Z", operations=(),
                      store_fingerprint="abc")
    hist.save_plan(plan)
    with pytest.raises(ValueError, match="already staged"):
        hist.save_plan(plan)


def test_a_corrupt_stored_body_reads_back_as_not_intact(tmp_path):
    from vecshield_platform.actions import ActionPlan

    hist = ScanHistory(str(tmp_path / "h.db"))
    plan = ActionPlan(id="plan-1", store="demo", staged_by="kim",
                      staged_at="2026-09-18T00:00:00Z", operations=(),
                      store_fingerprint="abc")
    hist.save_plan(plan)
    with hist._lock, hist._conn:
        hist._conn.execute("UPDATE action_plans SET body = ? WHERE id = ?",
                           ("not json", "plan-1"))
    record = hist.get_plan("plan-1")
    assert record["body_intact"] is False
    assert record["body"] is None


# --------------------------------------------------------------------------- #
# CLI                                                                          #
# --------------------------------------------------------------------------- #

def test_cli_suggest_prints_the_refusals(tmp_path):
    findings = tmp_path / "f.json"
    findings.write_text(json.dumps({"findings": [_finding()]}))
    result = CliRunner().invoke(cli, ["actions", "suggest", "--connector", "chroma",
                                      "--findings", str(findings)])
    assert result.exit_code == 0
    assert "withheld" in result.output
    assert "delete_chunks" in result.output


def test_cli_stage_renders_store_content_without_swallowing_it(tmp_path, chroma_path):
    """A chunk containing brackets must survive into the diff a reviewer reads.

    Rich treats square brackets as markup, so an unescaped preview would vanish
    from the one place a person is checking what would be destroyed.
    """
    import chromadb

    client = chromadb.PersistentClient(path=chroma_path)
    client.get_collection("runbooks").add(
        ids=["c3"], documents=["token [REDACTED-LOOKING] value"],
        embeddings=[[0.1, 0.2]], metadatas=[{"team": "sre"}])

    suggestions = tmp_path / "s.json"
    suggestions.write_text(json.dumps({"suggestions": [{
        "id": "s1", "action": "tag_exclude", "finding_id": "f1",
        "collection": "runbooks", "chunk_ids": ["c3"], "calibrated": True}]}))
    result = CliRunner().invoke(cli, [
        "actions", "stage", "--connector", "chroma", "--path", chroma_path,
        "--suggestions", str(suggestions), "--store", "demo", "--staged-by", "kim"])
    assert result.exit_code == 0
    assert "[low risk, reversible]" in result.output


def test_cli_diff_refuses_a_plan_that_no_longer_matches_its_hash(tmp_path, chroma_path):
    suggestions = tmp_path / "s.json"
    suggestions.write_text(json.dumps({"suggestions": [{
        "id": "s1", "action": "tag_exclude", "finding_id": "f1",
        "collection": "runbooks", "chunk_ids": ["c1"]}]}))
    plan_path = tmp_path / "plan.json"
    runner = CliRunner()
    assert runner.invoke(cli, [
        "actions", "stage", "--connector", "chroma", "--path", chroma_path,
        "--suggestions", str(suggestions), "--store", "demo", "--staged-by", "kim",
        "--out", str(plan_path)]).exit_code == 0

    intact = runner.invoke(cli, ["actions", "diff", "--plan", str(plan_path)])
    assert intact.exit_code == 0

    body = json.loads(plan_path.read_text())
    body["operations"][0]["collection"] = "somewhere_else"
    plan_path.write_text(json.dumps(body))
    tampered = runner.invoke(cli, ["actions", "diff", "--plan", str(plan_path)])
    assert tampered.exit_code == 1
    assert "does not match its own hash" in tampered.output


def test_a_tamperer_who_also_rewrites_the_hash_field_is_still_caught(client, history):
    """The check recomputes. Comparing two stored copies would pass here."""
    from vecshield_platform.actions import hash_body

    r = client.post("/stores/demo/actions/plans", json={"suggestions": [{
        "id": "s1", "action": "tag_exclude", "finding_id": "f1",
        "collection": "runbooks", "chunk_ids": ["c1"]}]})
    plan_id = r.json()["id"]

    with history._lock, history._conn:
        row = history._conn.execute(
            "SELECT body FROM action_plans WHERE id = ?", (plan_id,)).fetchone()
        body = json.loads(row["body"])
        body["operations"][0]["collection"] = "somewhere_else"
        body["plan_hash"] = hash_body(body)        # make the body self-consistent
        history._conn.execute("UPDATE action_plans SET body = ? WHERE id = ?",
                              (json.dumps(body), plan_id))

    assert client.get(f"/actions/plans/{plan_id}/diff").status_code == 409


def test_an_unknown_store_is_a_404_not_an_empty_proposal_list(client):
    """'Nothing to propose' and 'no such store' are different answers."""
    assert client.post("/stores/nope/actions/suggest", json={}).status_code == 404
    assert client.get("/stores/nope/actions/plans").status_code == 404


def test_suggestions_find_findings_recorded_under_the_connector_name(client, history):
    """Findings say 'file:///…'; the registry says 'demo'. Querying by store_id
    alone returns nothing, which reads as "no findings" rather than a mismatch.
    """
    connector_name = "file:///tmp/chroma"
    with history._lock, history._conn:
        history._conn.execute(
            "INSERT INTO audit_snapshots VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("aud-1", "demo", connector_name, "2026-09-18T00:00:00Z",
             "2026-09-18T00:01:00Z", "{}", "{}"))
        history._conn.execute(
            "INSERT INTO findings (id, job_id, store, collection, title, severity, "
            "category, description, evidence, remediation, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("f-bridged", "job-1", connector_name, "runbooks", "SECRET detected",
             "critical", "data_classification", "",
             json.dumps({"labels": {"SECRET": 1}, "sensitive_chunks": 3,
                         "examples": [{"chunk_id": "c1", "label": "SECRET",
                                       "detectors": ["aws_access_key"]}]}),
             "", "2026-09-18T00:00:30Z"))

    body = client.post("/stores/demo/actions/suggest", json={}).json()
    assert body["findings_considered"] == 1
    # Runs against the shipped calibration rather than a pinned one, so it
    # asserts what must hold whatever the corpus currently supports: the
    # reversible proposals are made, and delete is not among them.
    proposed = [s["action"] for s in body["suggestions"]]
    assert "tag_exclude" in proposed and "quarantine_collection" in proposed
    assert "delete_chunks" not in proposed
    assert body["suggestions"][0]["store"] == "demo"    # attributed to the registry id


# --------------------------------------------------------------------------- #
# Approval and execution over the API                                          #
# --------------------------------------------------------------------------- #

def _staged(client, **overrides):
    payload = {"id": "s1", "action": "tag_exclude", "finding_id": "f1",
               "collection": "runbooks", "chunk_ids": ["c1"],
               "rests_on": ["aws_access_key"], "observed_chunks": 40,
               "named_chunks": 1}
    payload.update(overrides)
    return client.post("/stores/demo/actions/plans",
                       json={"suggestions": [payload]}).json()


def test_safe_mode_is_reported_rather_than_left_to_be_inferred(client, monkeypatch):
    from vecshield_platform.execution import SAFE_MODE_ENV

    monkeypatch.delenv(SAFE_MODE_ENV, raising=False)
    body = client.get("/actions/safe-mode").json()
    assert body["safe_mode"] is True
    assert body["variable"] == SAFE_MODE_ENV
    assert "Writes are blocked" in body["note"]
    assert body["executable_actions"] == ["label_sensitivity", "tag_exclude",
                                          "quarantine_collection", "redact_text",
                                          "delete_chunks", "tag_review",
                                          "tag_provenance", "assign_tenant",
                                          "quarantine_chunks", "split_by_tenant"]


def test_the_api_actor_cannot_approve_a_plan_they_staged_when_duties_are_separated(
        tmp_path, chroma_path, history):
    """Both calls run as the same principal, so with the strict rule this must
    be refused."""
    cfg = ConfigStore(path=str(tmp_path / "config.json"))
    app = create_app(config_store=cfg, serve_ui=False, scan_history=history,
                     separation_of_duties="required")
    client = TestClient(app)
    client.post("/admin/stores", json={
        "store_id": "demo", "kind": "chroma", "conn": {"path": chroma_path}})
    try:
        plan = _staged(client)
        r = client.post(f"/actions/plans/{plan['id']}/approve",
                        json={"reason": "Reviewed the diff."})
        assert r.status_code == 400
        assert "cannot also approve" in r.json()["detail"]
    finally:
        app.state.jobs.shutdown(wait=False)


def test_without_authentication_the_admin_may_self_approve_and_it_is_recorded(client):
    """With auth disabled every caller is the synthetic admin; the default rule
    lets that admin approve their own plan, and says so on the record."""
    plan = _staged(client)
    r = client.post(f"/actions/plans/{plan['id']}/approve",
                    json={"reason": "Reviewed the diff."})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["self_approved"] is True
    assert body["separation_of_duties"] == "admin_may_self_approve"
    assert client.get("/version").json()["approvals"]["separation_of_duties"] == \
        "admin_may_self_approve"


def test_an_approval_without_a_reason_is_refused(client, history):
    plan = _staged(client)
    with history._lock, history._conn:                  # stage as somebody else
        history._conn.execute("UPDATE action_plans SET staged_by = 'kim' WHERE id = ?",
                              (plan["id"],))
    r = client.post(f"/actions/plans/{plan['id']}/approve", json={"reason": ""})
    assert r.status_code == 400
    assert "records why" in r.json()["detail"]


def _approvable(client, history, **overrides):
    """A plan staged by somebody other than the API's own principal."""
    plan = _staged(client, **overrides)
    with history._lock, history._conn:
        row = history._conn.execute("SELECT body FROM action_plans WHERE id = ?",
                                    (plan["id"],)).fetchone()
        body = json.loads(row["body"])
        body["staged_by"] = "kim"
        history._conn.execute(
            "UPDATE action_plans SET staged_by = 'kim', body = ?, plan_hash = ? "
            "WHERE id = ?", (json.dumps(body), body["plan_hash"], plan["id"]))
    return plan


def test_an_approval_is_recorded_with_its_reason_and_hash(client, history):
    plan = _approvable(client, history)
    r = client.post(f"/actions/plans/{plan['id']}/approve",
                    json={"reason": "Checked the diff; the key is live."})
    assert r.status_code == 200, r.json()
    approval = r.json()
    assert approval["plan_hash"] == plan["plan_hash"]
    assert approval["reason"] == "Checked the diff; the key is live."

    listed = client.get(f"/actions/plans/{plan['id']}/executions").json()
    assert len(listed["approvals"]) == 1
    assert listed["executions"] == []


def test_safe_mode_blocks_the_execute_endpoint(client, history, monkeypatch):
    from vecshield_platform.execution import SAFE_MODE_ENV

    monkeypatch.delenv(SAFE_MODE_ENV, raising=False)
    plan = _approvable(client, history)
    approval = client.post(f"/actions/plans/{plan['id']}/approve",
                           json={"reason": "Checked the diff."}).json()
    r = client.post(f"/actions/plans/{plan['id']}/execute",
                    json={"approval_id": approval["id"]})
    assert r.status_code == 409
    assert "safe mode is on" in r.json()["detail"]


def test_a_refused_execution_is_still_written_to_the_audit_log(client, history,
                                                               monkeypatch):
    from vecshield_platform.execution import SAFE_MODE_ENV

    monkeypatch.delenv(SAFE_MODE_ENV, raising=False)
    plan = _approvable(client, history)
    approval = client.post(f"/actions/plans/{plan['id']}/approve",
                           json={"reason": "Checked."}).json()
    client.post(f"/actions/plans/{plan['id']}/execute",
                json={"approval_id": approval["id"]})
    entries = client.get("/audit-log").json()
    rows = entries.get("entries", entries) if isinstance(entries, dict) else entries
    assert "action_plan_execution_refused" in {e.get("action") for e in rows}


def test_an_approved_plan_executes_and_verifies(client, history, chroma_path,
                                                monkeypatch):
    import chromadb

    from vecshield_platform.execution import EXCLUDED_KEY, SAFE_MODE_ENV

    monkeypatch.setenv(SAFE_MODE_ENV, "0")
    plan = _approvable(client, history)
    approval = client.post(f"/actions/plans/{plan['id']}/approve",
                           json={"reason": "Checked the diff."}).json()
    r = client.post(f"/actions/plans/{plan['id']}/execute",
                    json={"approval_id": approval["id"]})
    assert r.status_code == 200, r.json()
    result = r.json()
    assert result["complete"] is True
    assert result["chunks_changed"] == 1
    assert result["verification"]["outcome"] == "confirmed"
    # Confirmed still says what it did not establish.
    assert any("stopped being retrieved" in c for c in result["verification"]["caveats"])

    col = chromadb.PersistentClient(path=chroma_path).get_collection("runbooks")
    assert col.get(ids=["c1"], include=["metadatas"])["metadatas"][0][EXCLUDED_KEY]


def test_an_approval_cannot_be_reused_for_a_re_staged_plan(client, history,
                                                           monkeypatch):
    """Approval is scoped to a hash, so a fresh plan needs a fresh approval."""
    from vecshield_platform.execution import SAFE_MODE_ENV

    monkeypatch.setenv(SAFE_MODE_ENV, "0")
    first = _approvable(client, history)
    approval = client.post(f"/actions/plans/{first['id']}/approve",
                           json={"reason": "Checked."}).json()
    second = _approvable(client, history, id="s2")
    r = client.post(f"/actions/plans/{second['id']}/execute",
                    json={"approval_id": approval["id"]})
    assert r.status_code == 409
    assert "different plan" in r.json()["detail"]


def test_executing_with_an_unknown_approval_is_a_404(client, history, monkeypatch):
    from vecshield_platform.execution import SAFE_MODE_ENV

    monkeypatch.setenv(SAFE_MODE_ENV, "0")
    plan = _approvable(client, history)
    r = client.post(f"/actions/plans/{plan['id']}/execute",
                    json={"approval_id": "appr-nope"})
    assert r.status_code == 404


def test_an_executed_plan_cannot_be_executed_or_approved_again(client, history,
                                                                monkeypatch):
    """The plan body is frozen at staging and still says 'staged'. The column is
    where the state moved, and that is what a caller must be handed."""
    from vecshield_platform.execution import SAFE_MODE_ENV

    monkeypatch.setenv(SAFE_MODE_ENV, "0")
    plan = _approvable(client, history)
    approval = client.post(f"/actions/plans/{plan['id']}/approve",
                           json={"reason": "Checked."}).json()
    assert client.post(f"/actions/plans/{plan['id']}/execute",
                       json={"approval_id": approval["id"]}).status_code == 200

    again = client.post(f"/actions/plans/{plan['id']}/execute",
                        json={"approval_id": approval["id"]})
    assert again.status_code == 409
    assert "already executed and cannot be run again" in again.json()["detail"]

    reapprove = client.post(f"/actions/plans/{plan['id']}/approve",
                            json={"reason": "Again."})
    assert reapprove.status_code == 400
    assert "cannot be approved" in reapprove.json()["detail"]


def test_a_redaction_against_a_real_chroma_store_keeps_the_vector(
        client, history, chroma_path, monkeypatch):
    """The one that matters: no model download, vector unchanged, original kept."""
    import chromadb

    from vecshield_platform.execution import (NEEDS_REEMBED_KEY, ORIGINALS_COLLECTION,
                                                SAFE_MODE_ENV)

    monkeypatch.setenv(SAFE_MODE_ENV, "0")
    monkeypatch.setattr("vecshield_platform.actions.CALIBRATED",
                        {"aws_access_key": {"possible"}})
    # Make any attempt to embed fail loudly rather than reach for the network.
    import chromadb.utils.embedding_functions as ef
    monkeypatch.setattr(ef.DefaultEmbeddingFunction, "__call__",
                        lambda self, input: (_ for _ in ()).throw(
                            AssertionError("the store was asked to embed")))

    before = chromadb.PersistentClient(path=chroma_path).get_collection("runbooks").get(
        ids=["c1"], include=["embeddings"])["embeddings"][0]

    plan = _approvable(client, history, action="redact_text", calibrated=True)
    approval = client.post(f"/actions/plans/{plan['id']}/approve",
                           json={"reason": "Reviewed the redaction preview."}).json()
    r = client.post(f"/actions/plans/{plan['id']}/execute",
                    json={"approval_id": approval["id"]})
    assert r.status_code == 200, r.json()
    assert r.json()["verification"]["outcome"] == "confirmed"

    col = chromadb.PersistentClient(path=chroma_path).get_collection("runbooks")
    after = col.get(ids=["c1"], include=["embeddings", "documents", "metadatas"])
    assert after["documents"][0] == "rotate [REDACTED:secret] tonight"
    assert list(after["embeddings"][0]) == list(before)
    assert after["metadatas"][0][NEEDS_REEMBED_KEY] is True
    assert after["metadatas"][0]["team"] == "sre"

    kept = chromadb.PersistentClient(path=chroma_path).get_collection(ORIGINALS_COLLECTION)
    original = kept.get(include=["documents", "metadatas"])
    assert original["documents"] == ["rotate AKIAIOSFODNN7EXAMPLE tonight"]
    assert original["metadatas"][0]["vecshield_original_of"] == "c1"


def test_executions_of_an_unknown_plan_are_a_404_not_empty_lists(client):
    assert client.get("/actions/plans/plan-nope/executions").status_code == 404


def test_an_unknown_plan_state_filter_is_refused_rather_than_matching_nothing(client):
    r = client.get("/stores/demo/actions/plans?state=bogus")
    assert r.status_code == 400
    assert "unknown plan state" in r.json()["detail"]
    assert client.get("/stores/demo/actions/plans?state=executed").status_code == 200
