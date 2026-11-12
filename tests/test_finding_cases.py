"""A finding is an observation; a case is what people decided about it."""

from __future__ import annotations

import datetime

import pytest

from vecshield.models import Finding, ScanJob, Severity
from vecshield_platform.cases import (
    ALLOWED_TRANSITIONS,
    CASE_STATES,
    CaseState,
    CaseTransitionError,
    assign,
    summarize,
    transition,
)
from vecshield_platform.history import ScanHistory


def case(state="new", **kwargs):
    return CaseState(finding_id="f1", state=state, **kwargs)


# ------------------------------- state machine ------------------------------ #

def test_a_case_starts_new_and_records_who_changed_it():
    state, event = transition(case(), to_state="triaged", actor="alice@example.test")
    assert state.state == "triaged"
    assert event.from_state == "new" and event.to_state == "triaged"
    assert event.actor == "alice@example.test"
    assert state.updated_at


def test_every_change_needs_an_actor():
    with pytest.raises(CaseTransitionError, match="who made it"):
        transition(case(), to_state="triaged", actor="")


def test_illegal_transitions_are_refused_with_the_allowed_set():
    with pytest.raises(CaseTransitionError, match="allowed: closed, reopened"):
        transition(case("verified"), to_state="in_progress", actor="me")
    with pytest.raises(CaseTransitionError, match="already triaged"):
        transition(case("triaged"), to_state="triaged", actor="me")
    with pytest.raises(CaseTransitionError, match="unknown case state"):
        transition(case(), to_state="resolved-ish", actor="me")


def test_assignment_needs_an_owner():
    with pytest.raises(CaseTransitionError, match="needs an owner"):
        transition(case("triaged"), to_state="assigned", actor="me")
    state, _ = transition(case("triaged"), to_state="assigned", actor="me", owner="bob")
    assert state.owner == "bob"


def test_resolution_claims_need_a_stated_reason():
    for target in ("false_positive", "duplicate", "risk_accepted"):
        with pytest.raises(CaseTransitionError, match="needs a stated reason"):
            transition(case(), to_state=target, actor="me")
    state, _ = transition(case(), to_state="false_positive", actor="me",
                          reason="Test fixture data, not a real key.")
    assert state.state == "false_positive"
    assert state.to_dict()["is_resolved_claim"] is True


def test_verification_needs_an_observation_not_an_absence():
    with pytest.raises(CaseTransitionError, match="absence of recent findings is not verification"):
        transition(case("awaiting_verification"), to_state="verified", actor="me")

    by_run, _ = transition(case("awaiting_verification"), to_state="verified",
                           actor="me", verified_by_job_id="job-9")
    assert by_run.verified_by_job_id == "job-9"

    by_hand, _ = transition(case("awaiting_verification"), to_state="verified",
                            actor="me", reason="Confirmed by hand against the store.")
    assert by_hand.state == "verified"


def test_verification_can_fail_and_send_the_case_back_to_work():
    assert "in_progress" in ALLOWED_TRANSITIONS["awaiting_verification"]
    state, _ = transition(case("awaiting_verification"), to_state="in_progress", actor="me")
    assert state.state == "in_progress"


def test_reopening_drops_the_claim_that_it_was_verified():
    verified = case("verified", verified_by_job_id="job-9")
    reopened, event = transition(verified, to_state="reopened", actor="me")
    assert reopened.state == "reopened"
    assert reopened.verified_by_job_id is None, "a reopened case is not verified by anything"
    assert event.from_state == "verified"


def test_every_resolution_state_can_be_reopened_by_a_recurrence():
    for state in ("verified", "closed", "false_positive", "duplicate", "risk_accepted"):
        assert "reopened" in ALLOWED_TRANSITIONS[state], state


def test_assigning_a_case_already_past_assignment_does_not_rewind_it():
    state, event = assign(case("in_progress", owner="bob"), owner="carol", actor="me")
    assert state.state == "in_progress", "handing over work does not undo it"
    assert state.owner == "carol"
    assert event.from_state == event.to_state == "in_progress"


def test_summary_counts_resolution_claims_apart_from_verified_work():
    summary = summarize([{"state": "verified"}, {"state": "closed"},
                         {"state": "false_positive"}, {"state": "risk_accepted"},
                         {"state": "new"}, {"state": "reopened"}])
    assert summary["verified_or_closed"] == 2
    assert summary["resolution_claims"] == 2
    assert summary["open"] == 2
    assert "assert something about the world" in summary["note"]


def test_the_documented_states_are_the_implemented_states():
    assert set(ALLOWED_TRANSITIONS) <= set(CASE_STATES)
    for state, targets in ALLOWED_TRANSITIONS.items():
        for target in targets:
            assert target in CASE_STATES, f"{state} -> {target}"


# --------------------------------- storage ---------------------------------- #

def job_with(findings):
    job = ScanJob(id="j1", store="fake://store")
    for f in findings:
        job.add(f)
    job.finished_at = datetime.datetime.now(datetime.timezone.utc)
    return job


def finding(fid, severity=Severity.HIGH, collection="docs", category="data_classification",
            title="PII detected"):
    return Finding(id=fid, title=title, severity=severity, category=category,
                   store="fake://store", collection=collection)


@pytest.fixture
def history():
    with ScanHistory() as h:
        h.save_job(job_with([
            finding("f-crit", Severity.CRITICAL, title="Secret embedded"),
            finding("f-high"),
            finding("f-low", Severity.LOW, collection="logs", category="rag_integrity"),
        ]))
        yield h


def test_findings_start_with_an_open_case(history):
    result = history.query_findings()
    assert result["total"] == 3
    assert {f["case"]["state"] for f in result["findings"]} == {"new"}
    assert all(f["case"]["owner"] is None for f in result["findings"])


def test_query_reports_the_true_total_not_the_page_size(history):
    page = history.query_findings(limit=2)
    assert len(page["findings"]) == 2
    assert page["total"] == 3, "the denominator is everything matching, not the page"
    assert page["has_more"] is True and page["next_offset"] == 2
    rest = history.query_findings(limit=2, offset=2)
    assert len(rest["findings"]) == 1 and rest["has_more"] is False


def test_filters_narrow_in_sql_and_facets_describe_what_matched(history):
    assert history.query_findings(min_severity="high")["total"] == 2
    assert history.query_findings(severity="low")["total"] == 1
    assert history.query_findings(collection="logs")["total"] == 1
    assert history.query_findings(category="rag_integrity")["total"] == 1
    assert history.query_findings(search="Secret")["total"] == 1
    facets = history.query_findings()["facets"]
    assert facets["severity"] == {"critical": 1, "high": 1, "low": 1}
    assert facets["case_state"] == {"new": 3}


def test_sorting_is_restricted_to_known_columns(history):
    by_severity = history.query_findings(sort="severity", direction="desc")["findings"]
    assert [f["severity"] for f in by_severity] == ["critical", "high", "low"]
    with pytest.raises(ValueError, match="cannot sort findings by"):
        history.query_findings(sort="id; DROP TABLE findings")
    with pytest.raises(ValueError, match="unknown sort direction"):
        history.query_findings(direction="sideways")


def test_a_case_change_is_persisted_with_its_trail(history):
    state, event = transition(CaseState(**history.get_case("f-high")),
                              to_state="triaged", actor="alice")
    history.save_case(state, event)
    state, event = assign(CaseState(**history.get_case("f-high")), owner="bob", actor="alice")
    history.save_case(state, event)

    stored = history.get_case("f-high")
    assert stored["state"] == "assigned" and stored["owner"] == "bob"
    events = history.case_events("f-high")
    assert [e["to_state"] for e in events] == ["triaged", "assigned"]
    assert all(e["actor"] == "alice" for e in events)


def test_saving_a_case_for_an_unknown_finding_is_refused(history):
    state, event = transition(CaseState(finding_id="nope"), to_state="triaged", actor="me")
    with pytest.raises(KeyError):
        history.save_case(state, event)


def test_filtering_by_case_state_and_owner(history):
    state, event = transition(CaseState(**history.get_case("f-crit")),
                              to_state="assigned", actor="me", owner="bob")
    history.save_case(state, event)
    assert history.query_findings(case_state="assigned")["total"] == 1
    assert history.query_findings(owner="bob")["total"] == 1
    assert history.query_findings(case_state="new")["total"] == 2
    assert history.case_summary() == {"new": 2, "assigned": 1}


def test_suppression_and_case_state_are_independent(history):
    """Suppressing hides a finding; it never claims the work was done."""
    result = history.query_findings()
    assert all("suppressed" in f and "case" in f for f in result["findings"])
    state, event = transition(CaseState(**history.get_case("f-low")),
                              to_state="risk_accepted", actor="me",
                              reason="Accepted for this quarter.")
    history.save_case(state, event)
    accepted = history.query_findings(case_state="risk_accepted")["findings"][0]
    assert accepted["case"]["state"] == "risk_accepted"
    assert accepted["suppressed"] is False, "accepting risk does not hide the finding"


def test_legacy_findings_migrate_to_an_open_case(tmp_path):
    import sqlite3

    path = tmp_path / "legacy.db"
    conn = sqlite3.connect(path)
    conn.execute("""CREATE TABLE findings (id TEXT PRIMARY KEY, job_id TEXT NOT NULL,
                 store TEXT, collection TEXT, category TEXT, severity TEXT, title TEXT,
                 description TEXT, evidence TEXT, remediation TEXT, created_at TEXT)""")
    conn.execute("""CREATE TABLE jobs (id TEXT PRIMARY KEY, store TEXT NOT NULL,
                 kind TEXT, started_at TEXT, finished_at TEXT, max_severity TEXT,
                 stats TEXT, created_at TEXT)""")
    conn.execute("INSERT INTO findings (id, job_id, severity) VALUES ('old', 'j', 'high')")
    conn.commit()
    conn.close()

    for _ in range(2):  # migration is idempotent
        with ScanHistory(path) as h:
            assert h.get_case("old") == {
                "finding_id": "old", "state": "new", "owner": None, "reason": "",
                "updated_at": None, "verified_by_job_id": None}
            assert h.case_events("old") == []


# ----------------------------------- API ------------------------------------ #

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from vecshield_platform.api import create_app  # noqa: E402


@pytest.fixture
def client(history):
    app = create_app(scan_history=history, serve_ui=False)
    c = TestClient(app)
    yield c
    app.state.jobs.shutdown(wait=False)


def test_findings_endpoint_filters_and_reports_the_true_total(client):
    body = client.get("/admin/findings?limit=2").json()
    assert body["total"] == 3 and len(body["findings"]) == 2
    assert body["has_more"] is True
    assert body["facets"]["severity"]["critical"] == 1

    narrowed = client.get("/admin/findings?min_severity=high").json()
    assert narrowed["total"] == 2
    assert client.get("/admin/findings?search=Secret").json()["total"] == 1


def test_findings_endpoint_rejects_an_unknown_sort(client):
    assert client.get("/admin/findings?sort=id;DROP").status_code == 422
    assert client.get("/admin/findings?direction=sideways").status_code == 422
    assert client.get("/admin/findings?limit=9000").status_code == 422


def test_a_case_moves_through_the_workflow_and_keeps_its_trail(client):
    assert client.post("/admin/findings/f-high/case",
                       json={"to_state": "triaged"}).status_code == 200
    assigned = client.post("/admin/findings/f-high/case",
                           json={"to_state": "assigned", "owner": "bob"}).json()
    assert assigned["state"] == "assigned" and assigned["owner"] == "bob"

    client.post("/admin/findings/f-high/case", json={"to_state": "in_progress"})
    client.post("/admin/findings/f-high/case", json={"to_state": "awaiting_verification"})
    verified = client.post("/admin/findings/f-high/case",
                           json={"to_state": "verified", "verified_by_job_id": "j1"}).json()
    assert verified["state"] == "verified"
    assert [e["to_state"] for e in verified["events"]] == [
        "triaged", "assigned", "in_progress", "awaiting_verification", "verified"]

    case = client.get("/admin/findings/f-high/case").json()
    assert case["allowed_transitions"] == ["closed", "reopened"]
    assert case["is_open"] is False


def test_a_refused_transition_is_a_conflict_with_the_reason(client):
    r = client.post("/admin/findings/f-high/case", json={"to_state": "verified"})
    assert r.status_code == 409
    assert "cannot move a case from new to verified" in r.json()["detail"]

    client.post("/admin/findings/f-high/case", json={"to_state": "triaged"})
    client.post("/admin/findings/f-high/case", json={"to_state": "assigned", "owner": "b"})
    client.post("/admin/findings/f-high/case", json={"to_state": "in_progress"})
    r = client.post("/admin/findings/f-high/case", json={"to_state": "awaiting_verification"})
    assert r.status_code == 200
    r = client.post("/admin/findings/f-high/case", json={"to_state": "verified"})
    assert r.status_code == 409
    assert "not verification" in r.json()["detail"]


def test_a_resolution_claim_without_a_reason_is_refused(client):
    r = client.post("/admin/findings/f-low/case", json={"to_state": "false_positive"})
    assert r.status_code == 409 and "needs a stated reason" in r.json()["detail"]
    ok = client.post("/admin/findings/f-low/case",
                     json={"to_state": "false_positive", "reason": "Fixture data."})
    assert ok.status_code == 200 and ok.json()["is_resolved_claim"] is True


def test_an_empty_case_change_is_rejected(client):
    assert client.post("/admin/findings/f-low/case", json={}).status_code == 422
    assert client.post("/admin/findings/nope/case",
                       json={"to_state": "triaged"}).status_code == 404
    assert client.post("/admin/findings/f-low/case",
                       json={"to_state": "triaged", "nonsense": 1}).status_code == 422


def test_bulk_changes_report_each_outcome_rather_than_all_or_nothing(client):
    # f-high is closed out as a false positive, so it cannot be assigned; f-crit
    # is untouched and can. A bulk action must report both, not average them.
    client.post("/admin/findings/f-high/case",
                json={"to_state": "false_positive", "reason": "Fixture data."})
    body = client.post("/admin/findings/cases", json={
        "finding_ids": ["f-crit", "f-high", "nope"],
        "to_state": "assigned", "owner": "carol"}).json()

    assert body["applied"] == 1, "only the open case could be assigned"
    assert body["refused"] == 2
    assert body["ok"] is False
    refusals = {r["finding_id"]: r for r in body["refusals"]}
    assert refusals["nope"]["status"] == 404
    assert "cannot move a case from false_positive to assigned" in refusals["f-high"]["reason"]
    assert client.get("/admin/findings?owner=carol").json()["total"] == 1


def test_bulk_assignment_across_ready_cases_succeeds_cleanly(client):
    for fid in ("f-crit", "f-high", "f-low"):
        client.post(f"/admin/findings/{fid}/case", json={"to_state": "triaged"})
    body = client.post("/admin/findings/cases", json={
        "finding_ids": ["f-crit", "f-high", "f-low"],
        "to_state": "assigned", "owner": "dana"}).json()
    assert body["ok"] is True and body["applied"] == 3
    assert client.get("/admin/findings?case_state=assigned").json()["total"] == 3


def test_case_summary_keeps_resolution_claims_separate(client):
    client.post("/admin/findings/f-low/case",
                json={"to_state": "risk_accepted", "reason": "Accepted this quarter."})
    summary = client.get("/admin/findings/summary").json()
    assert summary["resolution_claims"] == 1
    assert summary["verified_or_closed"] == 0
    assert summary["open"] == 2
    assert "assert something about the world" in summary["note"]


def test_case_changes_are_written_to_the_audit_log(client):
    client.post("/admin/findings/f-high/case", json={"to_state": "triaged"})
    entries = client.get("/audit-log").json()["entries"]
    assert any(e["action"] == "finding_case_changed" for e in entries)


def test_findings_endpoints_need_history(tmp_path):
    app = create_app(serve_ui=False)
    c = TestClient(app)
    try:
        assert c.get("/admin/findings").status_code == 409
        assert c.post("/admin/findings/x/case", json={"to_state": "triaged"}).status_code == 409
    finally:
        app.state.jobs.shutdown(wait=False)
