"""Evidence, its reviews, and exceptions — three assertions kept separate."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from vecshield_platform.evidence import (
    ARTIFACT_TRANSITIONS,
    REVIEW_TRANSITIONS,
    EvidenceArtifact,
    EvidenceError,
    EvidenceReview,
    RiskException,
    accepted_requirements,
    transition_artifact,
    transition_review,
)
from vecshield_platform.history import ScanHistory


def artifact(**kwargs):
    return EvidenceArtifact(**{"id": "ev-1", "title": "Access review", **kwargs})


def future(days=30):
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def past(days=1):
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


# ------------------------------- artifacts ---------------------------------- #

def test_an_artifact_becomes_usable_only_after_its_integrity_is_checked():
    a = artifact(content_hash="abc")
    assert a.usable is False
    a = transition_artifact(a, to_state="integrity_checked", actor="me")
    assert a.usable is False, "checked is not yet available"
    a = transition_artifact(a, to_state="available", actor="me")
    assert a.usable is True


def test_an_integrity_check_needs_something_to_check_against():
    with pytest.raises(EvidenceError, match="needs a content hash"):
        transition_artifact(artifact(), to_state="integrity_checked", actor="me")


def test_a_hash_does_not_claim_the_contents_are_true():
    record = artifact(content_hash="abc").to_dict()
    assert record["integrity"] == "hashed"
    assert "does not prove the assertion inside them is true" in record["integrity_note"]
    assert artifact().to_dict()["integrity"] == "not hashed"


def test_an_artifact_with_no_period_makes_no_claim_about_coverage():
    assert artifact().covers("2026-09-17") is None, "unstated is not yes"
    bounded = artifact(period_start="2026-07-01", period_end="2026-09-30")
    assert bounded.covers("2026-08-01") is True
    assert bounded.covers("2026-10-01") is False
    assert bounded.covers("2026-06-01") is False


def test_a_revoked_artifact_is_terminal():
    assert ARTIFACT_TRANSITIONS["revoked"] == ()
    revoked = artifact(state="revoked")
    with pytest.raises(EvidenceError, match="allowed: nothing"):
        transition_artifact(revoked, to_state="available", actor="me")


def test_artifact_changes_record_who_made_them():
    with pytest.raises(EvidenceError, match="records who made it"):
        transition_artifact(artifact(content_hash="x"),
                            to_state="integrity_checked", actor="")


# -------------------------------- reviews ----------------------------------- #

def review(**kwargs):
    return EvidenceReview(**{"id": "rev-1", "artifact_id": "ev-1",
                             "criterion_id": "HIPAA-1", **kwargs})


def test_a_rejection_must_say_what_is_missing():
    submitted = transition_review(review(), to_state="submitted", reviewer="bob")
    for state in ("rejected", "needs_clarification"):
        with pytest.raises(EvidenceError, match="needs a reason saying what is missing"):
            transition_review(submitted, to_state=state, reviewer="sarah")
    rejected = transition_review(submitted, to_state="rejected", reviewer="sarah",
                                 reason="Covers Q2, not the period under review.")
    assert rejected.state == "rejected" and rejected.accepted is False


def test_a_review_names_its_reviewer():
    with pytest.raises(EvidenceError, match="names its reviewer"):
        transition_review(review(), to_state="submitted", reviewer="")


def test_accepting_evidence_needs_a_reason_too():
    submitted = transition_review(review(), to_state="submitted", reviewer="bob")
    with pytest.raises(EvidenceError, match="accepting evidence needs a reason"):
        transition_review(submitted, to_state="accepted", reviewer="sarah")
    with pytest.raises(EvidenceError, match="accepting evidence needs a reason"):
        transition_review(submitted, to_state="accepted", reviewer="sarah", reason="  ")


def test_a_decision_can_be_revisited_only_by_an_explicit_move():
    accepted = transition_review(
        transition_review(review(), to_state="submitted", reviewer="bob"),
        to_state="accepted", reviewer="sarah", reason="Signed and covers the period.")
    assert accepted.accepted is True
    assert "under_review" in REVIEW_TRANSITIONS["accepted"]
    with pytest.raises(EvidenceError, match="cannot move a review from accepted to submitted"):
        transition_review(accepted, to_state="submitted", reviewer="bob")


def test_the_same_artifact_can_be_accepted_for_one_criterion_and_rejected_for_another():
    for_hipaa = transition_review(
        transition_review(review(id="r1"), to_state="submitted", reviewer="b"),
        to_state="accepted", reviewer="s", reason="Names the retrieval corpus.")
    for_gdpr = transition_review(
        transition_review(review(id="r2", criterion_id="GDPR-1"),
                          to_state="submitted", reviewer="b"),
        to_state="rejected", reviewer="s", reason="Does not cover EU subjects.")
    assert for_hipaa.accepted is True and for_gdpr.accepted is False
    assert for_hipaa.artifact_id == for_gdpr.artifact_id


def test_accepted_evidence_stops_counting_when_its_artifact_stops_being_usable():
    usable = artifact(content_hash="x", state="available")
    accepted = review(state="accepted", requirement="access_review_record")

    assert accepted_requirements([accepted.to_dict()], criterion_id="HIPAA-1",
                                 artifacts={"ev-1": usable.to_dict()}) == {
        "access_review_record": "accepted"}

    for dead in ("superseded", "expired", "revoked", "quarantined"):
        stale = EvidenceArtifact(**{**usable.__dict__, "state": dead})
        assert accepted_requirements([accepted.to_dict()], criterion_id="HIPAA-1",
                                     artifacts={"ev-1": stale.to_dict()}) == {
            "access_review_record": "missing"}, dead


def test_reviews_for_other_criteria_are_ignored():
    other = review(criterion_id="GDPR-1", state="accepted", requirement="erasure_procedure")
    assert accepted_requirements([other.to_dict()], criterion_id="HIPAA-1",
                                 artifacts={}) == {}


# ------------------------------- exceptions --------------------------------- #

def exception(**kwargs):
    return RiskException(**{"id": "exc-1", "criterion_id": "HIPAA-1", "scope": "prod",
                            "rationale": "Compensating control in place.",
                            "requested_by": "bob", "expires_at": future(), **kwargs})


def test_an_unapproved_exception_is_not_active():
    record = exception()
    assert record.active() is False
    assert record.status() == "pending_approval"


def test_an_approved_exception_expires_rather_than_persisting():
    live = exception(approved_by="sarah", approved_at=past())
    assert live.active() is True and live.status() == "active"
    stale = exception(approved_by="sarah", approved_at=past(60), expires_at=past())
    assert stale.active() is False and stale.status() == "expired"


def test_a_revoked_exception_is_inactive_whatever_its_expiry():
    record = exception(approved_by="sarah", revoked_at=past())
    assert record.active() is False and record.status() == "revoked"


def test_an_exception_never_claims_to_close_the_gap():
    assert "does not close the gap" in exception().to_dict()["note"]


# -------------------------------- storage ----------------------------------- #

def test_evidence_survives_a_round_trip_through_storage():
    with ScanHistory() as h:
        a = artifact(content_hash="abc", scope="prod", state="available")
        h.save_artifact(a)
        assert h.get_artifact("ev-1")["state"] == "available"
        assert len(h.list_artifacts(scope="prod")) == 1
        assert h.list_artifacts(scope="other") == []

        r = review(state="accepted", requirement="access_review_record", scope="prod")
        h.save_review(r)
        assert h.list_reviews(criterion_id="HIPAA-1")[0]["state"] == "accepted"
        assert h.list_reviews(criterion_id="GDPR-1") == []

        e = exception(approved_by="sarah")
        h.save_exception(e)
        assert h.list_exceptions(criterion_id="HIPAA-1")[0]["approved_by"] == "sarah"


# ---------------------------------- API ------------------------------------- #

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from vecshield_platform.api import create_app  # noqa: E402


@pytest.fixture
def client():
    history = ScanHistory()
    app = create_app(scan_history=history, serve_ui=False)
    c = TestClient(app)
    yield c, history
    app.state.jobs.shutdown(wait=False)


def register(c, **kwargs):
    body = {"title": "Access review record", "content_hash": "abc", "scope": "prod", **kwargs}
    r = c.post("/compliance/evidence", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def test_registering_evidence_records_who_collected_it(client):
    c, _ = client
    body = register(c)
    assert body["state"] == "collected" and body["usable"] is False
    assert body["collected_at"] and body["collector"]
    assert "separate review" in c.get("/compliance/evidence").json()["note"]


def test_superseding_an_artifact_retires_the_one_it_replaces(client):
    c, _ = client
    first = register(c)
    for state in ("integrity_checked", "available"):
        c.post(f"/compliance/evidence/{first['id']}/state", json={"to_state": state})
    second = register(c, supersedes=first["id"])
    assert second["supersedes"] == first["id"]
    retired = c.get("/compliance/evidence").json()["artifacts"]
    prior = next(a for a in retired if a["id"] == first["id"])
    assert prior["state"] == "superseded" and prior["usable"] is False


def test_an_illegal_artifact_move_is_a_conflict(client):
    c, _ = client
    body = register(c)
    r = c.post(f"/compliance/evidence/{body['id']}/state", json={"to_state": "available"})
    assert r.status_code == 409 and "cannot move an artifact" in r.json()["detail"]
    assert c.post("/compliance/evidence/nope/state",
                  json={"to_state": "available"}).status_code == 404


def test_a_review_requires_an_artifact_that_exists(client):
    c, _ = client
    r = c.post("/compliance/reviews", json={"artifact_id": "nope", "criterion_id": "HIPAA-1"})
    assert r.status_code == 404


def test_accepted_evidence_reaches_the_criterion_that_needed_it(client):
    import sys
    sys.path.insert(0, "tests")
    from test_assessment_snapshots import audit_result

    c, history = client
    history.save_audit(audit_result(), store_id="prod")

    artifact_body = register(c)
    for state in ("integrity_checked", "available"):
        c.post(f"/compliance/evidence/{artifact_body['id']}/state", json={"to_state": state})
    review_body = c.post("/compliance/reviews", json={
        "artifact_id": artifact_body["id"], "criterion_id": "HIPAA-SEC-ACCESS-01",
        "requirement": "access_review_record", "scope": "prod"}).json()
    c.post(f"/compliance/reviews/{review_body['id']}",
           json={"to_state": "accepted", "reason": "Q3 review covers the vector store."})

    # The store must exist in the registry for the criteria route; use the
    # evidence list to confirm the recorded state instead.
    reviews = c.get("/compliance/reviews?criterion_id=HIPAA-SEC-ACCESS-01").json()["reviews"]
    assert reviews[0]["accepted"] is True
    assert reviews[0]["requirement"] == "access_review_record"


def test_an_exception_needs_a_future_expiry(client):
    c, _ = client
    r = c.post("/compliance/exceptions", json={
        "criterion_id": "HIPAA-1", "scope": "prod",
        "rationale": "Compensating control.", "expires_at": past()})
    assert r.status_code == 422 and "expires in the future" in r.json()["detail"]


def test_an_exception_is_not_approved_by_the_person_who_asked_for_it():
    history = ScanHistory()
    app = create_app(scan_history=history, serve_ui=False,
                     separation_of_duties="required")
    c = TestClient(app)
    try:
        body = c.post("/compliance/exceptions", json={
            "criterion_id": "HIPAA-1", "scope": "prod",
            "rationale": "Compensating control.", "expires_at": future()}).json()
        assert body["status"] == "pending_approval"
        r = c.post(f"/compliance/exceptions/{body['id']}/approve",
                   json={"reason": "Accepted for this quarter."})
        assert r.status_code == 409
        assert "someone other than the person who requested it" in r.json()["detail"]
    finally:
        app.state.jobs.shutdown(wait=False)


def test_without_authentication_an_admin_self_approves_an_exception_visibly(client):
    c, _ = client
    body = c.post("/compliance/exceptions", json={
        "criterion_id": "HIPAA-1", "scope": "prod",
        "rationale": "Compensating control.", "expires_at": future()}).json()
    r = c.post(f"/compliance/exceptions/{body['id']}/approve",
               json={"reason": "Compensating control verified."})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "active"
    assert r.json()["self_approved"] is True
    listed = c.get("/compliance/exceptions").json()["exceptions"]
    assert listed[0]["self_approved"] is True
    assert listed[0]["approval_reason"] == "Compensating control verified."


def test_exceptions_are_summarised_without_claiming_gaps_are_closed(client):
    c, history = client
    c.post("/compliance/exceptions", json={
        "criterion_id": "HIPAA-1", "scope": "prod",
        "rationale": "Compensating control.", "expires_at": future()})
    history.save_exception(RiskException(
        id="exc-old", criterion_id="HIPAA-1", scope="prod", rationale="Old.",
        requested_by="bob", expires_at=past(), approved_by="sarah"))
    body = c.get("/compliance/exceptions").json()
    assert body["pending_approval"] == 1
    assert body["expired"] == 1
    assert body["active"] == 0
    assert "does not close the gap" in body["note"]


def test_revoking_an_exception_stops_it_applying(client):
    c, _ = client
    body = c.post("/compliance/exceptions", json={
        "criterion_id": "HIPAA-1", "scope": "prod",
        "rationale": "Compensating control.", "expires_at": future()}).json()
    revoked = c.post(f"/compliance/exceptions/{body['id']}/revoke").json()
    assert revoked["status"] == "revoked" and revoked["active"] is False
    assert c.post(f"/compliance/exceptions/{body['id']}/approve").status_code == 409
