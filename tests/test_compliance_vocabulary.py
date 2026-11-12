"""Every identifier the pack shows a reader has words behind it.

Criteria, artifact types and applicability questions are identifiers in the
pack. A reader should never have to decode one: each criterion carries a
plain-language title, and every artifact type and question a criterion names
is explained, with examples, in one catalogue the console reads.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from vecshield_platform.compliance.criteria import (
    DETERMINATION_KEYS,
    SPECIFICATION_KINDS,
)
from vecshield_platform.compliance.decisions import criterion_digest
from vecshield_platform.compliance.packs import CRITERIA, get_criterion
from vecshield_platform.compliance.vocabulary import (
    APPLICABILITY_QUESTIONS,
    EVIDENCE_TYPES,
    REVIEWER_CHECKLIST,
    SPECIFICATION_NOTES,
    vocabulary,
)
from vecshield_platform.evidence import (
    ARTIFACT_STATES,
    ARTIFACT_TRANSITIONS,
    REVIEW_STATES,
    REVIEW_TRANSITIONS,
    lifecycle_reference,
)


def test_every_criterion_has_a_plain_title_that_is_not_its_id():
    titles = [c.title for c in CRITERIA]
    assert all(titles), "a criterion without a title shows its id instead"
    assert len(set(titles)) == len(titles), "two criteria must not read the same"
    for c in CRITERIA:
        assert c.title != c.id
        assert "_" not in c.title and len(c.title) <= 80, c.title
        assert c.title[0].isupper() and not c.title.endswith(".")


def test_every_artifact_a_criterion_asks_for_is_explained_with_examples():
    named = {name for c in CRITERIA for name in c.manual_evidence + c.fallback_evidence}
    named |= set(DETERMINATION_KEYS.values())
    missing = sorted(named - set(EVIDENCE_TYPES))
    assert not missing, f"artifact types with no explanation: {missing}"
    for key, spec in EVIDENCE_TYPES.items():
        assert spec.label and "_" not in spec.label, key
        assert spec.what.endswith("."), key
        assert spec.examples and all(e and not e.endswith(".") for e in spec.examples), key
        assert spec.reviewer_checks, key


def test_every_applicability_question_is_a_question():
    named = {q for c in CRITERIA for q in c.applicability_questions}
    assert named <= set(APPLICABILITY_QUESTIONS), sorted(named - set(APPLICABILITY_QUESTIONS))
    for key, q in APPLICABILITY_QUESTIONS.items():
        assert q.question.endswith("?"), key
        assert q.help, key


def test_every_specification_kind_says_it_is_not_optional_where_that_matters():
    assert set(SPECIFICATION_NOTES) == set(SPECIFICATION_KINDS)
    assert "not optional" in SPECIFICATION_NOTES["addressable"]
    assert "not optional" in SPECIFICATION_NOTES["risk_based"]


def test_the_vocabulary_never_claims_compliance():
    text = repr(vocabulary()).lower()
    for claim in ("compliant", "certif", "guarantee", "ensures compliance"):
        assert claim not in text, claim
    assert any("hash only proves" in item for item in REVIEWER_CHECKLIST)


def test_retitling_a_criterion_does_not_make_stored_decisions_stale():
    criterion = get_criterion("GDPR-ERASURE-01")
    assert criterion_digest(replace(criterion, title="Anything else")) == \
        criterion_digest(criterion)
    # The obligation's wording still binds the decision.
    assert criterion_digest(replace(criterion, paraphrase="Different.")) != \
        criterion_digest(criterion)


def test_the_digest_is_what_it_was_before_titles_existed():
    """Decisions stored before titles were added must keep applying."""
    import hashlib
    import json
    from dataclasses import asdict

    criterion = get_criterion("GDPR-ERASURE-01")
    # The declared lifecycle came later and is left out for the same reason.
    before = {k: v for k, v in asdict(criterion).items()
              if k not in ("aliases", "title", "lifecycle")}
    expected = hashlib.sha256(json.dumps(
        before, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    assert criterion_digest(criterion) == expected


def test_lifecycle_reference_explains_every_state_and_mirrors_the_machine():
    ref = lifecycle_reference()
    assert set(ref["artifact_states"]) == set(ARTIFACT_STATES)
    assert set(ref["review_states"]) == set(REVIEW_STATES)
    for state, row in ref["artifact_states"].items():
        assert row["meaning"], state
        assert row["next"] == list(ARTIFACT_TRANSITIONS.get(state, ()))
    for state, row in ref["review_states"].items():
        assert row["meaning"], state
        assert row["next"] == list(REVIEW_TRANSITIONS.get(state, ()))
    assert [s for s, row in ref["artifact_states"].items() if row["usable"]] == ["available"]
    assert "stop counting" in ref["artifact_states"]["superseded"]["meaning"]


def _client(tmp_path):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from vecshield_platform.api import create_app
    from vecshield_platform.api.registry import StoreRegistry
    from vecshield_platform.history import ScanHistory

    registry = StoreRegistry()
    registry.register("prod", "fake", factory=lambda: None)
    history = ScanHistory(tmp_path / "history.db")
    app = create_app(registry=registry, scan_history=history, serve_ui=False)
    return TestClient(app), history, app


def test_the_criteria_endpoint_serves_titles_and_the_vocabulary(tmp_path):
    client, history, app = _client(tmp_path)
    try:
        body = client.get("/compliance/criteria").json()
        erasure = next(c for c in body["criteria"] if c["criterion_id"] == "GDPR-ERASURE-01")
        assert erasure["title"] == get_criterion("GDPR-ERASURE-01").title
        assert body["evidence_types"]["business_associate_agreements"]["examples"]
        assert body["applicability_questions"]["system_handles_ephi"]["question"].endswith("?")
        assert body["reviewer_checklist"] and body["specification_notes"]["addressable"]
        evidence = client.get("/compliance/evidence").json()
        assert evidence["lifecycle"]["artifact_states"]["collected"]["next"]
    finally:
        app.state.jobs.shutdown(wait=False)
        history.close()
