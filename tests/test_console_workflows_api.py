"""Batch 2 of the console roadmap: the backend the workflows finish on.

Pins four contracts the console builds against:

* a reviewer decision is stored, attributed to the authenticated caller,
  audit-logged, applied by criterion evaluation over a caller's what-if, and
  never applied to a criterion whose pack or wording changed after it;
* applicability answers are stored per store and used unless a request
  overrides them for a what-if;
* the home summary counts distinct open findings from each store's latest
  audit only, keeps suppressed ones apart, and never logs a gate decision;
* the approval queue lists staged plans across stores and says, per caller,
  whether they may approve or need a second person.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from vecshield.models import Finding, ScanJob, Severity  # noqa: E402
from vecshield_platform.api import create_app  # noqa: E402
from vecshield_platform.api.auth import (  # noqa: E402
    COMPLIANCE, VIEWER, Principal, expand_roles)
from vecshield_platform.api.registry import StoreRegistry  # noqa: E402
from vecshield_platform.compliance.criteria import PACK_VERSION  # noqa: E402
from vecshield_platform.compliance.decisions import (  # noqa: E402
    criterion_digest, merge_answers)
from vecshield_platform.compliance.packs import get_criterion  # noqa: E402
from vecshield_platform.coverage import check_outcome, set_job_coverage  # noqa: E402
from vecshield_platform.crypto import crypto_outcome  # noqa: E402
from vecshield_platform.evidence import EvidenceReview, RiskException  # noqa: E402
from vecshield_platform.history import ScanHistory  # noqa: E402
from vecshield_platform.home import summarize_open_findings  # noqa: E402
from vecshield_platform.orchestrator import AuditResult  # noqa: E402

ACCESS = "HIPAA-164-312-A1-ACCESS-CONTROL-01"
RETIRED_ACCESS = "HIPAA-SEC" + "-ACCESS-01"
APPLIES = {"covered_entity_or_business_associate": "yes", "system_handles_ephi": "yes"}
EVIDENCE = {"authorized_access_policy": "accepted", "access_review_record": "accepted"}
PASSING = [check_outcome("tenant_isolation", "fake://observed", "docs",
                         outcome="passed", complete=True),
           check_outcome("configuration_posture", "fake://observed",
                         outcome="passed", complete=True)]


# --------------------------------------------------------------------------- #
# Fixtures                                                                     #
# --------------------------------------------------------------------------- #

@dataclass
class _Users:
    """Bearer token -> principal. Stands in for a real identity provider."""

    table: dict

    def authenticate(self, authorization):
        token = (authorization or "").removeprefix("Bearer ").strip()
        return self.table.get(token)


USERS = _Users({
    "alice": Principal("alice", expand_roles({COMPLIANCE}), source="test"),
    "bob": Principal("bob", expand_roles({COMPLIANCE}), source="test"),
    "vera": Principal("vera", expand_roles({VIEWER}), source="test"),
})


def _as(user: str) -> dict:
    return {"Authorization": f"Bearer {user}"}


@pytest.fixture
def rig(tmp_path):
    registry = StoreRegistry()
    for store_id in ("prod", "staging", "empty"):
        registry.register(store_id, "fake", factory=lambda: None)
    history = ScanHistory(tmp_path / "history.db")
    app = create_app(registry=registry, scan_history=history, serve_ui=False,
                     authenticator=USERS, separation_of_duties="required")
    client = TestClient(app)
    yield client, history, app
    app.state.jobs.shutdown(wait=False)
    history.close()


def _audit(history, *, store_id="prod", audit_id="audit-1", findings=(),
           outcomes=PASSING, complete=True, extra_outcomes=()):
    """Save an audit for ``store_id``.

    ``findings`` are (id, title, severity, suppressed[, evidence]) tuples.
    """
    job = ScanJob(id=f"job-{audit_id}", store=f"fake://{store_id}")
    for finding_id, title, severity, suppressed, *extra in findings:
        evidence = dict(extra[0]) if extra else {}
        if suppressed:
            evidence["suppressed"] = True
        job.add(Finding(id=finding_id, title=title, severity=severity,
                        category="data_classification", store=job.store,
                        collection="docs", evidence=evidence))
    set_job_coverage(job, [check_outcome("scan", job.store, "docs",
                                         outcome="passed", complete=complete)])
    job.finished_at = datetime.now(timezone.utc)
    result = AuditResult(id=audit_id, store=job.store, jobs=[job],
                         started_at=job.started_at.isoformat(),
                         finished_at=job.finished_at.isoformat())
    result.check_outcomes.extend(outcomes)
    result.check_outcomes.extend(extra_outcomes)
    history.save_audit(result, store_id=store_id)
    return audit_id


def _events(app, action):
    return [e for e in app.state.audit_log.entries if e.action == action]


def _assessment(body, criterion_id=ACCESS):
    return next(a for a in body["assessments"] if a["criterion_id"] == criterion_id)


# --------------------------------------------------------------------------- #
# Stored reviewer decisions                                                    #
# --------------------------------------------------------------------------- #

def test_a_decision_is_stored_as_the_caller_and_audit_logged(rig):
    client, history, app = rig
    audit_id = _audit(history)
    r = client.post(f"/stores/prod/criteria/{ACCESS}/decision", headers=_as("alice"),
                    json={"conclusion": "satisfied", "rationale": "  Reviewed for Q3. ",
                          "period": "2026-Q3"})
    assert r.status_code == 200, r.text
    decision = r.json()["decision"]
    assert decision["reviewer"] == "alice"
    assert decision["rationale"] == "Reviewed for Q3."
    assert decision["audit_id"] == audit_id
    assert decision["pack_version"] == PACK_VERSION
    assert decision["stale"] is False and decision["period"] == "2026-Q3"

    event = _events(app, "reviewer_decision_recorded")[-1]
    assert event.actor == "alice" and event.target == "prod"
    assert event.details["conclusion"] == "satisfied"
    assert event.details["decision_id"] == decision["id"]


def test_the_reviewer_cannot_be_named_in_the_body_and_viewers_cannot_decide(rig):
    client, history, _ = rig
    _audit(history)
    url = f"/stores/prod/criteria/{ACCESS}/decision"
    body = {"conclusion": "satisfied", "rationale": "ok"}
    assert client.post(url, json=body).status_code == 401
    assert client.post(url, json=body, headers=_as("vera")).status_code == 403
    assert client.post(url, headers=_as("alice"),
                       json={**body, "reviewer": "someone-else"}).status_code == 422
    assert client.post(url, headers=_as("alice"),
                       json={"conclusion": "satisfied", "rationale": "   "}).status_code == 422
    assert client.post(url, headers=_as("alice"),
                       json={"conclusion": "looks fine", "rationale": "x"}).status_code == 422
    assert client.post("/stores/prod/criteria/NOPE-01/decision", headers=_as("alice"),
                       json=body).status_code == 404
    assert client.post(f"/stores/nope/criteria/{ACCESS}/decision", headers=_as("alice"),
                       json=body).status_code == 404
    assert client.post(url, headers=_as("alice"),
                       json={**body, "audit_id": "missing"}).status_code == 404
    assert history.list_reviewer_decisions("prod") == []


def test_a_decision_needs_a_saved_audit_to_be_made_against(rig):
    client, _, _ = rig
    r = client.post(f"/stores/prod/criteria/{ACCESS}/decision", headers=_as("alice"),
                    json={"conclusion": "gap", "rationale": "No audit yet."})
    assert r.status_code == 409


def test_a_decision_filed_under_a_retired_id_is_stored_against_its_successor(rig):
    client, history, app = rig
    _audit(history)
    r = client.post(f"/stores/prod/criteria/{RETIRED_ACCESS}/decision",
                    headers=_as("alice"), json={"conclusion": "gap", "rationale": "x"})
    assert r.status_code == 200
    assert r.json()["decision"]["criterion_id"] == ACCESS
    assert _events(app, "reviewer_decision_recorded")[-1].details[
        "requested_criterion_id"] == RETIRED_ACCESS
    listed = client.get(f"/stores/prod/criteria/decisions?criterion_id={RETIRED_ACCESS}",
                        headers=_as("vera")).json()
    assert [d["criterion_id"] for d in listed["decisions"]] == [ACCESS]


def test_evaluation_applies_the_newest_stored_decision_over_a_what_if(rig):
    client, history, app = rig
    audit_id = _audit(history)
    url = f"/stores/prod/criteria/{ACCESS}/decision"
    client.post(url, headers=_as("alice"), json={"conclusion": "gap", "rationale": "First look."})
    client.post(url, headers=_as("bob"), json={"conclusion": "satisfied",
                                               "rationale": "Re-reviewed with the access log."})

    body = client.post("/stores/prod/criteria", headers=_as("vera"), json={
        "framework": "HIPAA", "applicability": APPLIES, "evidence": EVIDENCE,
        "reviewer_decisions": {ACCESS: {
            "reviewer": "what-if", "conclusion": "gap", "rationale": "hypothetical",
            "decided_at": "2026-09-01"}}}).json()
    access = _assessment(body)
    assert access["status"] == "satisfied_for_scope"
    assert access["reviewer"]["reviewer"] == "bob"
    assert access["reviewer"]["scope"] == "prod"
    assert access["decision_source"] == "stored"
    assert access["what_if_ignored"] is True
    assert access["stored_decision"]["applied"] is True
    assert access["stored_decision"]["audit_id"] == audit_id
    assert access["stored_decision"]["carried_forward"] is False
    assert body["inputs"]["decisions"]["stored_applied"] == 1
    assert body["inputs"]["decisions"]["what_if_ignored"] == 1
    assert any("ignored" in n for n in body["inputs"]["notes"])

    listed = client.get("/stores/prod/criteria/decisions", headers=_as("vera")).json()
    assert [d["reviewer"] for d in listed["decisions"]] == ["bob", "alice"]
    assert [d["current"] for d in listed["decisions"]] == [True, False]
    assert listed["current"] == 1 and listed["current_stale"] == 0

    # A later audit does not erase the decision, but says it was carried over.
    _audit(history, audit_id="audit-2")
    later = client.post("/stores/prod/criteria", headers=_as("vera"), json={
        "framework": "HIPAA", "applicability": APPLIES, "evidence": EVIDENCE}).json()
    assert _assessment(later)["stored_decision"]["carried_forward"] is True
    assert _events(app, "criteria_evaluated")[-1].details["decisions"]["stored_applied"] == 1


def test_a_decision_from_an_older_pack_is_reported_stale_and_not_applied(rig):
    client, history, _ = rig
    audit_id = _audit(history)
    history.save_reviewer_decision({
        "id": "dec-old", "store_id": "prod", "criterion_id": ACCESS,
        "conclusion": "satisfied", "rationale": "Signed off under draft-2.",
        "reviewer": "carol", "decided_at": "2026-01-01T00:00:00+00:00",
        "audit_id": audit_id, "period": "", "pack_version": "vecshield-vector-store-draft-2",
        "criterion_digest": "whatever-it-was"})

    body = client.post("/stores/prod/criteria", headers=_as("vera"), json={
        "framework": "HIPAA", "applicability": APPLIES, "evidence": EVIDENCE}).json()
    access = _assessment(body)
    assert access["status"] == "under_review"          # not satisfied_for_scope
    assert access["reviewer"] is None
    assert access["decision_source"] is None
    stale = access["stored_decision"]
    assert stale["stale"] is True and stale["applied"] is False
    assert stale["stale_reason"] == "pack_version_changed"
    assert "draft-2" in stale["stale_note"]
    assert body["inputs"]["decisions"]["stale_not_applied"] == 1
    assert any("not applied" in n for n in body["inputs"]["notes"])

    # With no current stored decision, a what-if still works.
    what_if = client.post("/stores/prod/criteria", headers=_as("vera"), json={
        "framework": "HIPAA", "applicability": APPLIES, "evidence": EVIDENCE,
        "reviewer_decisions": {ACCESS: {"reviewer": "x", "conclusion": "satisfied",
                                        "rationale": "if", "decided_at": "2026-09-01"}}}).json()
    assert _assessment(what_if)["decision_source"] == "what_if"
    assert _assessment(what_if)["status"] == "satisfied_for_scope"

    listed = client.get("/stores/prod/criteria/decisions", headers=_as("vera")).json()
    assert listed["current_stale"] == 1


def test_a_decision_on_reworded_criterion_in_the_same_pack_is_stale(rig):
    client, history, _ = rig
    audit_id = _audit(history)
    history.save_reviewer_decision({
        "id": "dec-reworded", "store_id": "prod", "criterion_id": ACCESS,
        "conclusion": "satisfied", "rationale": "old wording", "reviewer": "carol",
        "decided_at": "2026-09-01T00:00:00+00:00", "audit_id": audit_id, "period": "",
        "pack_version": PACK_VERSION, "criterion_digest": "0" * 64})
    body = client.post("/stores/prod/criteria", headers=_as("vera"), json={
        "framework": "HIPAA", "applicability": APPLIES, "evidence": EVIDENCE}).json()
    assert _assessment(body)["stored_decision"]["stale_reason"] == "criterion_changed"
    assert _assessment(body)["status"] == "under_review"


def test_a_stored_satisfied_never_hides_an_observed_failure(rig):
    client, history, _ = rig
    _audit(history, outcomes=[
        check_outcome("tenant_isolation", "fake://observed", "docs",
                      outcome="failed", complete=True),
        check_outcome("configuration_posture", "fake://observed",
                      outcome="passed", complete=True)])
    client.post(f"/stores/prod/criteria/{ACCESS}/decision", headers=_as("alice"),
                json={"conclusion": "satisfied", "rationale": "Looked fine to me."})
    body = client.post("/stores/prod/criteria", headers=_as("vera"), json={
        "framework": "HIPAA", "applicability": APPLIES, "evidence": EVIDENCE}).json()
    assert _assessment(body)["status"] == "gap_identified"


def test_the_digest_ignores_aliases_but_not_wording():
    criterion = get_criterion(ACCESS)
    from dataclasses import replace

    assert criterion_digest(replace(criterion, aliases=[])) == criterion_digest(criterion)
    assert criterion_digest(replace(criterion, paraphrase="Different.")) != \
        criterion_digest(criterion)


# --------------------------------------------------------------------------- #
# Stored applicability                                                         #
# --------------------------------------------------------------------------- #

def test_applicability_is_stored_validated_and_audit_logged(rig):
    client, history, app = rig
    url = "/stores/prod/applicability"
    assert client.post(url, headers=_as("vera"),
                       json={"answers": {"system_handles_ephi": "yes"}}).status_code == 403
    assert client.post(url, headers=_as("alice"),
                       json={"answers": {"is_this_a_question": "yes"}}).status_code == 422
    assert client.post(url, headers=_as("alice"),
                       json={"answers": {"system_handles_ephi": "maybe"}}).status_code == 422
    assert client.post(url, headers=_as("alice"), json={"answers": {}}).status_code == 422

    r = client.post(url, headers=_as("alice"), json={"answers": APPLIES})
    assert r.status_code == 200, r.text
    view = client.get(url, headers=_as("vera")).json()
    assert view["answers"]["system_handles_ephi"]["answer"] == "yes"
    assert view["answers"]["system_handles_ephi"]["answered_by"] == "alice"
    question = next(q for q in view["questions"] if q["question"] == "system_handles_ephi")
    assert question["answered"] is True and ACCESS in question["criteria"]
    unanswered = [q for q in view["questions"] if not q["answered"]]
    assert unanswered and all(q["answer"] == "requires_confirmation" for q in unanswered)

    # A second answer to one question replaces it and leaves the others.
    client.post(url, headers=_as("bob"), json={"answers": {"system_handles_ephi": "no"}})
    view = client.get(url, headers=_as("vera")).json()
    assert view["answers"]["system_handles_ephi"] == {
        **view["answers"]["system_handles_ephi"], "answer": "no", "answered_by": "bob"}
    assert view["answers"]["covered_entity_or_business_associate"]["answer"] == "yes"

    events = _events(app, "applicability_answered")
    assert [e.actor for e in events] == ["alice", "bob"]
    assert events[-1].details["answers"] == {"system_handles_ephi": "no"}
    assert client.get("/stores/nope/applicability", headers=_as("vera")).status_code == 404


def test_evaluation_uses_stored_answers_and_a_caller_overrides_per_question(rig):
    client, history, _ = rig
    _audit(history)
    client.post("/stores/prod/applicability", headers=_as("alice"), json={"answers": APPLIES})

    stored = client.post("/stores/prod/criteria", headers=_as("vera"), json={
        "framework": "HIPAA", "evidence": EVIDENCE}).json()
    assert _assessment(stored)["status"] == "under_review"   # applicability confirmed
    assert stored["inputs"]["applicability"]["sources"]["system_handles_ephi"] == "stored"

    what_if = client.post("/stores/prod/criteria", headers=_as("vera"), json={
        "framework": "HIPAA", "evidence": EVIDENCE,
        "applicability": {"system_handles_ephi": "requires_confirmation"}}).json()
    assert _assessment(what_if)["status"] == "not_assessed"
    sources = what_if["inputs"]["applicability"]["sources"]
    assert sources == {"covered_entity_or_business_associate": "stored",
                       "system_handles_ephi": "what_if"}
    assert any("what-if" in n for n in what_if["inputs"]["notes"])
    # The what-if did not change the record.
    assert history.applicability_answers("prod")["system_handles_ephi"]["answer"] == "yes"


def test_merge_answers_is_stored_then_caller():
    merged, sources = merge_answers({"a": "yes", "b": "no"}, {"b": "yes"})
    assert merged == {"a": "yes", "b": "yes"}
    assert sources == {"a": "stored", "b": "what_if"}


# --------------------------------------------------------------------------- #
# Home summary                                                                 #
# --------------------------------------------------------------------------- #

def test_open_findings_are_distinct_fingerprints_from_the_latest_audit_only(rig):
    client, history, app = rig
    _audit(history, audit_id="audit-1", findings=[
        ("f-1a", "Email addresses in 'docs'", Severity.HIGH, False),
        ("f-1b", "Credit card numbers in 'docs'", Severity.CRITICAL, False)])
    # Re-run: the same email finding again, twice over, and the card finding gone.
    _audit(history, audit_id="audit-2", findings=[
        ("f-2a", "Email addresses in 'docs'", Severity.HIGH, False),
        ("f-2b", "Email addresses in 'docs'", Severity.HIGH, False),
        ("f-2c", "Phone numbers in 'docs'", Severity.MEDIUM, True)])

    body = client.get("/admin/home", headers=_as("vera")).json()
    counts = body["open_findings"]
    assert counts["total"] == 1
    assert counts["by_severity"] == {"critical": 0, "high": 1, "medium": 0,
                                     "low": 0, "info": 0}
    assert counts["suppressed"] == 1
    assert counts["stores"] == 1 and counts["stores_assessed"] == 1
    assert counts["stores_never_assessed"] == 2

    # A third identical run changes nothing.
    _audit(history, audit_id="audit-3", findings=[
        ("f-3a", "Email addresses in 'docs'", Severity.HIGH, False),
        ("f-3c", "Phone numbers in 'docs'", Severity.MEDIUM, True)])
    again = client.get("/admin/home", headers=_as("vera")).json()["open_findings"]
    assert (again["total"], again["suppressed"]) == (1, 1)


def test_a_fingerprint_live_anywhere_in_the_audit_is_open_not_suppressed():
    rows = [{"audit_id": "a", "fingerprint": "fp", "severities": ["low"], "suppressed": True},
            {"audit_id": "a", "fingerprint": "fp", "severities": ["high"], "suppressed": False},
            {"audit_id": "old", "fingerprint": "x", "severities": ["critical"],
             "suppressed": False}]
    summary = summarize_open_findings(rows, {"a": "prod"})
    assert summary["total"] == 1 and summary["suppressed"] == 0
    assert summary["by_severity"]["high"] == 1 and summary["by_severity"]["critical"] == 0


def test_home_lists_what_needs_a_person_without_logging_a_gate_decision(rig):
    client, history, app = rig
    # prod: complete coverage, with a full PAN observed, so the gate blocks.
    _audit(history, store_id="prod", audit_id="audit-prod",
           findings=[("f-p", "PCI", Severity.HIGH, False, {"label_counts": {"pci": 2}})],
           extra_outcomes=[crypto_outcome(
               "pan_representation", "prod", "cards", state="observed_exposure",
               outcome="failed", complete=True, reason="2 full PANs")])
    # staging: an audit that did not see its whole scope.
    _audit(history, store_id="staging", audit_id="audit-staging", complete=False,
           outcomes=[check_outcome("tenant_isolation", "fake://staging", "docs",
                                   outcome="inconclusive", complete=False)])
    now = datetime.now(timezone.utc)
    history.save_exception(RiskException(
        id="exc-soon", criterion_id=ACCESS, scope="prod", rationale="r",
        requested_by="alice", expires_at=(now + timedelta(days=3)).isoformat(),
        approved_by="bob", approved_at=now.isoformat()))
    history.save_exception(RiskException(
        id="exc-late", criterion_id=ACCESS, scope="prod", rationale="r",
        requested_by="alice", expires_at=(now + timedelta(days=90)).isoformat(),
        approved_by="bob", approved_at=now.isoformat()))
    history.save_exception(RiskException(
        id="exc-gone", criterion_id=ACCESS, scope="prod", rationale="r",
        requested_by="alice", expires_at=(now - timedelta(days=1)).isoformat(),
        approved_by="bob", approved_at=(now - timedelta(days=30)).isoformat()))
    history.save_review(EvidenceReview(id="rev-1", artifact_id="ev-1",
                                       criterion_id=ACCESS, state="submitted"))
    history.save_review(EvidenceReview(id="rev-2", artifact_id="ev-1",
                                       criterion_id=ACCESS, state="accepted"))
    history.save_plan(_plan("plan-1", staged_by="alice"))

    before = len(app.state.audit_log.entries)
    body = client.get("/admin/home", headers=_as("bob")).json()
    assert len(app.state.audit_log.entries) == before
    assert not _events(app, "crypto_gate_decided")

    needs = {item["kind"]: item for item in body["needs_you"]}
    assert needs["plans_awaiting_approval"]["count"] == 1
    assert needs["plans_awaiting_approval"]["you_may_approve"] == 1   # bob, not alice
    assert needs["plans_awaiting_approval"]["target"]["view"] == "actions"
    assert needs["evidence_reviews_awaiting_decision"]["count"] == 1
    assert needs["exceptions_expiring"]["count"] == 1
    assert needs["exceptions_expired"]["count"] == 1
    assert needs["crypto_gate_blocks"]["stores"] == ["prod"]
    assert needs["crypto_gate_blocks"]["target"] == {"view": "crypto",
                                                     "params": {"store": "prod"}}
    assert needs["stores_never_assessed"]["stores"] == ["empty"]
    assert needs["stores_never_assessed"]["target"] == {"view": "assess",
                                                        "params": {"store": "empty"}}
    assert needs["stores_partial_coverage"]["stores"] == ["staging"]
    assert "exceptions_awaiting_approval" not in needs      # zero counts are omitted
    assert "exceptions_awaiting_approval" in body["checked"]
    assert body["stores"] == {"total": 3, "assessed": 2, "never_assessed": 1,
                              "partial_coverage": 1,
                              "coverage_status": {"complete": 1, "unavailable": 1}}
    # "Not complete" covers partial, unavailable and unknown alike, and says which.
    assert needs["stores_partial_coverage"]["by_status"] == {"unavailable": 1}

    alice = client.get("/admin/home", headers=_as("alice")).json()
    plans = next(i for i in alice["needs_you"] if i["kind"] == "plans_awaiting_approval")
    assert plans["you_may_approve"] == 0 and plans["needs_second_person"] == 1

    # Counts only: no key names a score or a ratio, and no number is fractional.
    keys, numbers = _walk(body)
    assert not [k for k in keys if any(w in k.lower() for w in ("score", "percent",
                                                                  "ratio", "pct"))]
    assert all(isinstance(n, int) for n in numbers)


def _walk(value, keys=None, numbers=None):
    keys = [] if keys is None else keys
    numbers = [] if numbers is None else numbers
    if isinstance(value, dict):
        for key, item in value.items():
            keys.append(str(key))
            _walk(item, keys, numbers)
    elif isinstance(value, list):
        for item in value:
            _walk(item, keys, numbers)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        numbers.append(value)
    return keys, numbers


def test_home_requires_authentication(rig):
    client, _, _ = rig
    assert client.get("/admin/home").status_code == 401
    assert client.get("/actions/queue").status_code == 401


# --------------------------------------------------------------------------- #
# Cross-store approval queue                                                   #
# --------------------------------------------------------------------------- #

def _plan(plan_id, *, store="prod", staged_by="alice", action="tag_exclude",
          staged_at=None):
    """A staged plan with one runnable operation, hashed like a real one."""
    from vecshield_platform.actions import hash_body

    body = {"id": plan_id, "store": store, "staged_by": staged_by,
            "staged_at": staged_at or datetime.now(timezone.utc).isoformat(),
            "state": "staged", "note": "", "store_fingerprint": "fp",
            "operations": [{"action": action, "collection": "docs", "finding_id": "f1",
                            "supported": True, "resolved": 1, "targets": []}]}
    body["plan_hash"] = hash_body(body)

    class _Plan:
        id = plan_id
        state = "staged"
        note = ""
        store_fingerprint = "fp"
        plan_hash = body["plan_hash"]

        def to_dict(self):
            return dict(body)

    plan = _Plan()
    plan.store, plan.staged_by, plan.staged_at = store, staged_by, body["staged_at"]
    return plan


def test_the_queue_says_who_may_approve_under_separation_of_duties(rig):
    client, history, _ = rig
    history.save_plan(_plan("plan-a", staged_by="alice", staged_at="2026-09-01T00:00:00+00:00"))
    history.save_plan(_plan("plan-d", store="staging", staged_by="bob",
                            action="delete_chunks", staged_at="2026-09-02T00:00:00+00:00"))

    alice = client.get("/actions/queue", headers=_as("alice")).json()
    assert [p["plan_id"] for p in alice["plans"]] == ["plan-a", "plan-d"]   # oldest first
    own, other = alice["plans"]
    assert own["store"] == "prod" and own["staged_by"] == "alice"
    assert own["operations"] == 1 and own["irreversible"] is False
    assert own["you"]["may_approve"] is False and own["you"]["needs_second_person"] is True
    assert "cannot also approve" in own["you"]["reason"]
    assert other["irreversible"] is True and other["you"]["requires_typed_store_id"] is True
    assert other["you"]["may_approve"] is True
    assert alice["counts"] == {"awaiting_approval": 2, "awaiting_execution": 0,
                               "you_may_approve": 1, "needs_second_person": 1}
    assert alice["separation_of_duties"]["separation_of_duties"] == "required"

    viewer = client.get("/actions/queue", headers=_as("vera")).json()
    assert all(not p["you"]["may_approve"] for p in viewer["plans"])
    assert "compliance role" in viewer["plans"][0]["you"]["reason"]

    # The preview agrees with the approve endpoint.
    assert client.post("/actions/plans/plan-a/approve", headers=_as("alice"),
                       json={"reason": "mine"}).status_code == 400
    r = client.post("/actions/plans/plan-a/approve", headers=_as("bob"),
                    json={"reason": "Read the diff."})
    assert r.status_code == 200, r.text

    after = client.get("/actions/queue", headers=_as("bob")).json()
    assert [p["plan_id"] for p in after["plans"]] == ["plan-d"]
    assert after["counts"]["awaiting_execution"] == 1
    everything = client.get("/actions/queue?include_approved=true",
                            headers=_as("bob")).json()
    approved = next(p for p in everything["plans"] if p["plan_id"] == "plan-a")
    assert approved["awaiting"] == "execution" and approved["approvals"] == 1


def test_a_tampered_plan_in_the_queue_cannot_be_approved(rig):
    client, history, _ = rig
    history.save_plan(_plan("plan-t", staged_by="alice"))
    with history._lock, history._conn:
        history._conn.execute("UPDATE action_plans SET plan_hash = 'x' WHERE id = 'plan-t'")
    entry = client.get("/actions/queue", headers=_as("bob")).json()["plans"][0]
    assert entry["intact"] is False and entry["you"]["may_approve"] is False


def test_a_history_file_from_before_these_tables_gains_them_in_place(tmp_path):
    path = tmp_path / "old.db"
    with ScanHistory(path) as history:
        history._conn.execute("DROP TABLE reviewer_decisions")
        history._conn.execute("DROP TABLE store_applicability")
        history._conn.execute("DROP TABLE store_retirements")
        # The first shape of the decisions table, with no write sequence.
        history._conn.execute("""CREATE TABLE reviewer_decisions (
            id TEXT PRIMARY KEY, store_id TEXT NOT NULL, criterion_id TEXT NOT NULL,
            conclusion TEXT NOT NULL, rationale TEXT NOT NULL, reviewer TEXT NOT NULL,
            decided_at TEXT NOT NULL, audit_id TEXT, period TEXT NOT NULL DEFAULT '',
            pack_version TEXT NOT NULL, criterion_digest TEXT)""")
        history._conn.execute(
            "INSERT INTO reviewer_decisions VALUES "
            "('dec-0', 'prod', ?, 'gap', 'r', 'bob', 's', NULL, '', ?, NULL)",
            (ACCESS, PACK_VERSION))
        history._conn.commit()
    with ScanHistory(path) as history:
        assert [d["id"] for d in history.list_reviewer_decisions("prod")] == ["dec-0"]
        history.save_applicability_answers("prod", {"system_handles_ephi": "yes"},
                                           answered_by="alice", answered_at="t")
        history.save_reviewer_decision({
            "id": "dec-1", "store_id": "prod", "criterion_id": ACCESS,
            "conclusion": "gap", "rationale": "r", "reviewer": "alice",
            "decided_at": "t", "audit_id": None, "period": "",
            "pack_version": PACK_VERSION, "criterion_digest": None})
        with pytest.raises(ValueError, match="already exists"):
            history.save_reviewer_decision({"id": "dec-1", "store_id": "prod"})
        assert history.applicability_answers("prod")["system_handles_ephi"]["answer"] == "yes"
        assert [d["id"] for d in history.list_reviewer_decisions("prod")] == ["dec-1", "dec-0"]
        assert history.retire_store_records("prod", retired_by="root", retired_at="u") == {
            "reviewer_decisions": 2, "applicability_answers": 1}
        assert history.list_reviewer_decisions("prod") == []


# --------------------------------------------------------------------------- #
# Which audit a decision may be applied to                                     #
# --------------------------------------------------------------------------- #

def test_a_decision_is_not_applied_to_an_audit_that_finished_before_its_own(rig):
    client, history, _ = rig
    older = _audit(history, audit_id="audit-older")
    decided_on = _audit(history, audit_id="audit-decided")
    r = client.post(f"/stores/prod/criteria/{ACCESS}/decision", headers=_as("alice"),
                    json={"conclusion": "satisfied", "rationale": "Reviewed.",
                          "audit_id": decided_on})
    assert r.status_code == 200 and r.json()["decision"]["audit_id"] == decided_on
    request = {"framework": "HIPAA", "applicability": APPLIES, "evidence": EVIDENCE}

    # Backwards in time: not applied, and it says why.
    back = client.post("/stores/prod/criteria", headers=_as("vera"),
                       json={**request, "audit_id": older}).json()
    access = _assessment(back)
    assert back["audit_id"] == older
    assert access["status"] == "under_review" and access["reviewer"] is None
    assert access["decision_source"] is None
    assert access["stored_decision"]["applied"] is False
    assert access["stored_decision"]["stale"] is False
    assert access["stored_decision"]["not_applied_reason"] == "made_against_later_audit"
    assert "finished after" in access["stored_decision"]["not_applied_note"]
    assert access["stored_decision"]["carried_forward"] is False
    assert back["inputs"]["decisions"]["later_audit_not_applied"] == 1
    assert any("later audit" in n for n in back["inputs"]["notes"])

    # The same audit: applied, not carried forward.
    same = _assessment(client.post("/stores/prod/criteria", headers=_as("vera"),
                                   json={**request, "audit_id": decided_on}).json())
    assert same["status"] == "satisfied_for_scope"
    assert same["stored_decision"]["carried_forward"] is False
    assert same["stored_decision"]["not_applied_reason"] is None

    # Forwards in time: applied, and marked as carried forward.
    newer = _audit(history, audit_id="audit-newer")
    fwd = _assessment(client.post("/stores/prod/criteria", headers=_as("vera"),
                                  json={**request, "audit_id": newer}).json())
    assert fwd["status"] == "satisfied_for_scope"
    assert fwd["stored_decision"]["carried_forward"] is True


def test_a_decision_whose_audit_cannot_be_placed_is_not_applied(rig):
    client, history, _ = rig
    _audit(history)
    history.save_reviewer_decision({
        "id": "dec-orphan", "store_id": "prod", "criterion_id": ACCESS,
        "conclusion": "satisfied", "rationale": "r", "reviewer": "carol",
        "decided_at": "2026-09-01T00:00:00+00:00", "audit_id": "audit-never-saved",
        "period": "", "pack_version": PACK_VERSION,
        "criterion_digest": criterion_digest(get_criterion(ACCESS))})
    body = client.post("/stores/prod/criteria", headers=_as("vera"), json={
        "framework": "HIPAA", "applicability": APPLIES, "evidence": EVIDENCE}).json()
    assert _assessment(body)["stored_decision"]["not_applied_reason"] == \
        "decision_audit_unknown"
    assert _assessment(body)["status"] == "under_review"


# --------------------------------------------------------------------------- #
# Deregistering a store retires what was recorded about it                     #
# --------------------------------------------------------------------------- #

def test_a_store_re_registered_under_the_same_id_inherits_nothing(tmp_path):
    from vecshield_platform.api.config_store import ConfigStore

    history = ScanHistory(tmp_path / "history.db")
    cfg = ConfigStore(path=str(tmp_path / "config.json"))
    app = create_app(config_store=cfg, scan_history=history, serve_ui=False,
                     authenticator=_Users({**USERS.table, "root": Principal(
                         "root", expand_roles({"admin"}), source="test")}))
    client = TestClient(app)
    store = {"store_id": "prod", "kind": "chroma",
             "conn": {"path": str(tmp_path / "chroma")}}
    try:
        assert client.post("/admin/stores", headers=_as("root"), json=store).status_code == 200
        _audit(history, audit_id="audit-first")
        client.post("/stores/prod/applicability", headers=_as("alice"),
                    json={"answers": APPLIES})
        client.post(f"/stores/prod/criteria/{ACCESS}/decision", headers=_as("alice"),
                    json={"conclusion": "satisfied", "rationale": "First system."})
        client.post(f"/stores/prod/criteria/{ACCESS}/decision", headers=_as("bob"),
                    json={"conclusion": "gap", "rationale": "Changed my mind."})

        removed = client.delete("/admin/stores/prod", headers=_as("root")).json()
        assert removed["retired"] == {"reviewer_decisions": 2, "applicability_answers": 2}
        event = [e for e in app.state.audit_log.entries if e.action == "store_removed"][-1]
        assert event.details["retired"] == removed["retired"]

        assert client.post("/admin/stores", headers=_as("root"), json=store).status_code == 200
        _audit(history, audit_id="audit-second")
        assert client.get("/stores/prod/criteria/decisions",
                          headers=_as("vera")).json()["decisions"] == []
        assert client.get("/stores/prod/applicability",
                          headers=_as("vera")).json()["answers"] == {}
        body = client.post("/stores/prod/criteria", headers=_as("vera"),
                           json={"framework": "HIPAA", "evidence": EVIDENCE}).json()
        access = _assessment(body)
        assert access["stored_decision"] is None and access["reviewer"] is None
        assert access["status"] == "not_assessed"            # applicability unanswered
        assert body["inputs"]["applicability"]["stored"] == {}

        # The rows are kept as history, and the new registration records afresh.
        assert history._conn.execute(
            "SELECT COUNT(*) FROM reviewer_decisions").fetchone()[0] == 2
        client.post(f"/stores/prod/criteria/{ACCESS}/decision", headers=_as("alice"),
                    json={"conclusion": "gap", "rationale": "Second system."})
        listed = client.get("/stores/prod/criteria/decisions", headers=_as("vera")).json()
        assert [d["rationale"] for d in listed["decisions"]] == ["Second system."]

        # Deleting again retires only what the second registration recorded.
        again = client.delete("/admin/stores/prod", headers=_as("root")).json()
        assert again["retired"] == {"reviewer_decisions": 1, "applicability_answers": 0}
    finally:
        app.state.jobs.shutdown(wait=False)
        history.close()


# --------------------------------------------------------------------------- #
# Findings over time                                                           #
# --------------------------------------------------------------------------- #

def test_the_trend_splits_recorded_findings_by_severity_and_says_what_it_counts(rig):
    client, history, _ = rig
    _audit(history, audit_id="audit-1", findings=[
        ("f-1a", "Email addresses in 'docs'", Severity.HIGH, False),
        ("f-1b", "Credit card numbers in 'docs'", Severity.CRITICAL, False)])
    _audit(history, audit_id="audit-2", findings=[
        ("f-2a", "Email addresses in 'docs'", Severity.HIGH, False),
        ("f-2c", "Phone numbers in 'docs'", Severity.MEDIUM, True)])

    body = client.get("/admin/history/trend", headers=_as("vera")).json()
    assert body["available"] is True
    assert "not distinct open findings" in body["note"]
    row = next(r for r in body["trend"] if r["store"] == "fake://prod")
    assert set(row) >= {"day", "store", "max_severity", "findings", "by_severity"}
    # Recorded counts across both runs, suppressed included: the re-detected
    # email finding counts twice here, unlike on the home summary.
    assert row["by_severity"] == {"critical": 1, "high": 2, "medium": 1,
                                  "low": 0, "info": 0}
    assert sum(row["by_severity"].values()) == row["findings"] == 4
    assert row["max_severity"] == "critical"


def test_a_connection_can_be_tried_before_it_is_saved(tmp_path, chroma_path):
    """The edit form's pre-save test: nothing persists, secrets never echo."""
    from fastapi.testclient import TestClient

    from vecshield_platform.api import create_app
    from vecshield_platform.api.config_store import ConfigStore

    cfg = ConfigStore(path=str(tmp_path / "config.json"))
    cfg.add_store("docs", "chroma", conn={"path": chroma_path})
    app = create_app(config_store=cfg, auth_token="read-tok",
                     admin_token="admin-tok", serve_ui=False)
    client = TestClient(app)
    admin = {"Authorization": "Bearer admin-tok"}

    # A reader cannot probe arbitrary connections.
    assert client.post("/admin/stores/test-connection", json={
        "kind": "chroma", "conn": {"path": chroma_path}},
        headers={"Authorization": "Bearer read-tok"}).status_code == 403

    # A masked value resolves to the stored one, as a save would.
    ok = client.post("/admin/stores/test-connection", headers=admin, json={
        "store_id": "docs", "kind": "chroma", "conn": {"path": "***"}}).json()
    assert ok["ok"] is True and {c["name"] for c in ok["collections"]} >= {"prod-docs"}

    # A mask with nothing stored behind it is refused, not sent literally.
    assert client.post("/admin/stores/test-connection", headers=admin, json={
        "kind": "chroma", "conn": {"path": "***"}}).status_code == 422

    # A failure reports its category, never the exception text (which can carry
    # a credential-bearing URL).
    secret_url = "http://user:hunter2@127.0.0.1:1"
    failed = client.post("/admin/stores/test-connection", headers=admin, json={
        "kind": "qdrant", "conn": {"url": secret_url}}).json()
    assert failed["ok"] is False and failed["category"]
    assert "hunter2" not in str(failed)

    # Nothing was saved, and each try is audit-logged.
    assert ConfigStore(path=str(tmp_path / "config.json")).get_store("docs").conn == {
        "path": chroma_path}
    tries = [e for e in app.state.audit_log.entries
             if e.action == "store_connection_tested"]
    assert len(tries) == 2 and "hunter2" not in str([t.details for t in tries])


# --------------------------------------------------------------------------- #
# Findings list scoped to the latest audits                                    #
# --------------------------------------------------------------------------- #

def _latest_rig(history):
    """Two stores, re-run audits, and fingerprints both live and suppressed."""
    _audit(history, store_id="prod", audit_id="p-1", findings=[
        ("p1-email", "Email addresses in 'docs'", Severity.HIGH, False),
        ("p1-card", "Credit card numbers in 'docs'", Severity.CRITICAL, False)])
    _audit(history, store_id="prod", audit_id="p-2", findings=[
        ("p2-email", "Email addresses in 'docs'", Severity.HIGH, False),
        ("p2-email-x", "Email addresses in 'docs'", Severity.CRITICAL, True),
        ("p2-phone", "Phone numbers in 'docs'", Severity.MEDIUM, True),
        ("p2-ssn", "Social security numbers in 'docs'", Severity.CRITICAL, False)])
    _audit(history, store_id="staging", audit_id="s-1", findings=[
        ("s1-email", "Email addresses in 'docs'", Severity.LOW, False),
        ("s1-name", "Person names in 'docs'", Severity.INFO, False)])


def test_latest_scope_agrees_with_the_home_summary(rig):
    client, history, _ = rig
    _latest_rig(history)
    home = client.get("/admin/home", headers=_as("vera")).json()["open_findings"]

    live = client.get("/admin/findings?scope=latest&suppressed=false&limit=500",
                      headers=_as("vera")).json()
    assert live["scope"] == "latest"
    assert live["total"] == home["total"] == 4
    by_severity = {name: live["facets"]["severity"].get(name, 0)
                   for name in home["by_severity"]}
    assert by_severity == home["by_severity"]
    assert "latest saved audit" in live["note"]
    assert (live["stores_assessed"], live["stores_never_assessed"]) == (2, 1)
    # The email fingerprint is live, so it is open at its live severity, and
    # the row is that occurrence from the latest audit.
    email = next(f for f in live["findings"] if f["store"] == "fake://prod"
                 and f["title"].startswith("Email"))
    assert email["id"] == "p2-email" and email["severity"] == "high"
    assert "p1-card" not in {f["id"] for f in live["findings"]}   # older audit

    hidden = client.get("/admin/findings?scope=latest&suppressed=true",
                        headers=_as("vera")).json()
    assert hidden["total"] == home["suppressed"] == 1
    assert [f["id"] for f in hidden["findings"]] == ["p2-phone"]

    everything = client.get("/admin/findings?scope=latest", headers=_as("vera")).json()
    assert everything["total"] == home["total"] + home["suppressed"]


def test_latest_scope_applies_filters_sort_and_paging_on_top(rig):
    client, history, _ = rig
    _latest_rig(history)
    headers = _as("vera")
    prod = client.get("/admin/findings?scope=latest&store=prod&suppressed=false",
                      headers=headers).json()
    assert {f["id"] for f in prod["findings"]} == {"p2-email", "p2-ssn"}

    critical = client.get("/admin/findings?scope=latest&severity=critical",
                          headers=headers).json()
    assert [f["id"] for f in critical["findings"]] == ["p2-ssn"]

    first = client.get("/admin/findings?scope=latest&sort=severity&direction=desc"
                       "&limit=2", headers=headers).json()
    second = client.get("/admin/findings?scope=latest&sort=severity&direction=desc"
                        "&limit=2&offset=2", headers=headers).json()
    assert first["total"] == second["total"] == 5
    assert first["has_more"] is True and second["next_offset"] == 4
    assert first["findings"][0]["id"] == "p2-ssn"
    ids = [f["id"] for f in first["findings"] + second["findings"]]
    assert len(ids) == len(set(ids)) == 4


def test_the_default_scope_is_every_recorded_finding(rig):
    client, history, _ = rig
    _latest_rig(history)
    body = client.get("/admin/findings?limit=500", headers=_as("vera")).json()
    assert body["scope"] == "all" and body["total"] == 8 and "note" not in body
    assert client.get("/admin/findings?scope=newest",
                      headers=_as("vera")).status_code == 422


def test_latest_scope_with_no_saved_audit_is_empty_and_says_why(rig):
    client, _, _ = rig
    body = client.get("/admin/findings?scope=latest", headers=_as("vera")).json()
    assert body["total"] == 0 and body["findings"] == []
    assert body["stores_assessed"] == 0 and body["stores_never_assessed"] == 3
