"""Embedding consistency, result ceiling, and credential identity hygiene.

Three checks that read what the client already has. What they must not do is
overclaim: two of them make no control statement at all, and the tests below
pin that as hard as they pin the detection.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from vecshield.models import ApiKey, Collection
from vecshield_platform.access.keyaudit import (
    SHARED_KEY_NAME_HINTS,
    audit_api_keys,
    shared_name_hint,
)
from vecshield_platform.posture.limits import observe_result_ceiling
from vecshield_platform.scan.embedding_consistency import (
    KNOWN_DIMENSIONS,
    check_embedding_consistency,
    invertible_models,
)

NOW = datetime(2026, 9, 25, tzinfo=timezone.utc)


def _days_ago(n: int) -> datetime:
    return NOW - timedelta(days=n)


# ------------------------------------------------- embedding consistency
def test_a_declared_model_that_contradicts_the_width_is_reported():
    result = check_embedding_consistency(
        [Collection("kb", 10, 1536, "all-MiniLM-L6-v2")])
    assert result.status == "contradicted"
    assert not result.consistent
    assert "384" in result.issues[0] and "1536" in result.issues[0]


def test_agreement_is_not_reported_as_proof():
    """A matching width does not establish that the model produced them."""
    result = check_embedding_consistency([Collection("kb", 10, 384, "all-minilm-l6-v2")])
    assert result.status == "consistent"
    assert "not prove" in result.to_dict()["note"]


def test_a_vendor_prefixed_model_name_is_normalised():
    result = check_embedding_consistency(
        [Collection("kb", 10, 384, "sentence-transformers/all-MiniLM-L6-v2")])
    assert result.consistent, "a HuggingFace org prefix must not read as a new model"


def test_an_unlabelled_collection_says_why_it_matters():
    result = check_embedding_consistency([Collection("kb", 10, 768, None)])
    assert result.status == "undeclared"
    assert "benign end" in result.summary(), (
        "the consequence — inversion risk defaulting low — is the point")


def test_an_unknown_model_name_is_not_treated_as_a_contradiction():
    """We do not know every model; silence is not evidence of a mismatch."""
    result = check_embedding_consistency([Collection("kb", 10, 999, "some-new-model")])
    assert result.consistent


def test_a_missing_or_zero_dimension_does_not_contradict_anything():
    for dimension in (None, 0, -1):
        result = check_embedding_consistency(
            [Collection("kb", 10, dimension, "all-minilm-l6-v2")])
        assert result.consistent


def test_no_collections_is_stated_rather_than_passed_silently():
    result = check_embedding_consistency([])
    assert "no collections" in result.summary().lower()


def test_invertible_models_are_reported_as_context_only():
    result = check_embedding_consistency(
        [Collection("kb", 10, 1536, "text-embedding-ada-002")])
    assert invertible_models(result) == ["text-embedding-ada-002"]
    assert result.consistent, "invertibility is not an inconsistency"


def test_every_known_dimension_entry_is_a_positive_integer():
    assert all(isinstance(v, int) and v > 0 for v in KNOWN_DIMENSIONS.values())


# ------------------------------------------------------- result ceiling
class _Conn:
    kind = "demo"

    def __init__(self, max_top_k=None):
        self.max_top_k = max_top_k


class _Store:
    def __init__(self, *sizes):
        self.collections = [Collection(f"c{i}", n) for i, n in enumerate(sizes)]


def test_no_documented_ceiling_is_reported_without_a_verdict():
    ceiling = observe_result_ceiling(_Conn(None), _Store(5000))
    assert ceiling.status == "no_documented_ceiling"
    assert ceiling.whole_collection_in_one_query
    assert "not a finding" in ceiling.summary()


def test_a_ceiling_below_the_largest_collection_is_reported_as_bounded():
    ceiling = observe_result_ceiling(_Conn(100), _Store(5000))
    assert ceiling.status == "bounded"
    assert not ceiling.whole_collection_in_one_query


def test_a_ceiling_above_the_collection_reaches_the_whole_of_it():
    ceiling = observe_result_ceiling(_Conn(10_000), _Store(5000))
    assert ceiling.status == "high_ceiling"
    assert ceiling.whole_collection_in_one_query


def test_the_check_never_claims_to_be_a_control():
    payload = observe_result_ceiling(_Conn(None), _Store(1)).to_dict()
    assert "Reviewer context only" in payload["note"]
    for banned in ("violation", "insecure", "vulnerable", "must"):
        assert banned not in payload["summary"].lower()


def test_an_empty_store_cannot_have_a_whole_collection_returned():
    assert not observe_result_ceiling(_Conn(None), _Store()).whole_collection_in_one_query


# ------------------------------------------- credential identity hygiene
@pytest.mark.parametrize("name", ["default", "shared-key", "team_key", "admin", "svc"])
def test_generic_principal_names_are_flagged(name):
    assert shared_name_hint(name) is not None


@pytest.mark.parametrize("name", [
    "ingest-worker-a", "alice-laptop", "svcatalog", "prodigy", "administrator-jane",
    "", "rag-2026",
])
def test_specific_names_and_near_misses_are_not_flagged(name):
    assert shared_name_hint(name) is None


def test_environment_words_are_not_evidence_of_sharing():
    """"svc-ingest-prod" says where a key runs, not that two people hold it."""
    for word in ("prod", "staging", "backup", "migration", "temp"):
        assert word not in SHARED_KEY_NAME_HINTS


def test_a_shared_name_produces_a_medium_finding_that_admits_uncertainty():
    keys = [ApiKey(id="k", name="default", actions=["read"], namespaces=["kb"],
                   last_used=_days_ago(1))]
    findings = [f for f in audit_api_keys(keys, now=NOW) if "shared" in f.title]
    assert len(findings) == 1
    assert findings[0].severity.value == "medium"
    assert "not proof of it" in findings[0].description
    assert "8.2.1" in findings[0].description


def test_a_key_past_the_rotation_interval_is_flagged_and_says_what_it_cannot_see():
    keys = [ApiKey(id="k", name="ingest-worker-a", actions=["read"],
                   namespaces=["kb"], last_used=_days_ago(1),
                   created_at=_days_ago(400))]
    findings = [f for f in audit_api_keys(keys, now=NOW) if "rotated" in f.title]
    assert len(findings) == 1
    assert "not rotation history" in findings[0].description


def test_the_rotation_interval_is_configurable_rather_than_asserted():
    keys = [ApiKey(id="k", name="ingest-worker-a", actions=["read"],
                   namespaces=["kb"], last_used=_days_ago(1),
                   created_at=_days_ago(400))]
    assert not [f for f in audit_api_keys(keys, now=NOW, rotation_days=500)
                if "rotated" in f.title]


def test_a_key_with_no_creation_date_produces_no_rotation_finding():
    keys = [ApiKey(id="k", name="ingest-worker-a", actions=["read"],
                   namespaces=["kb"], last_used=_days_ago(1))]
    assert not [f for f in audit_api_keys(keys, now=NOW) if "rotated" in f.title]
