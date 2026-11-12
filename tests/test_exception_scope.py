"""The exceptions scope filter distinguishes "no filter" from "estate-wide".

`scope` is NOT NULL, and an exception that applies to the whole estate is
stored with an empty scope. A truthiness test could not tell that apart from
"no filter given", so asking for the estate-wide ones returned the entire
table — and the criteria view, which asks for this store's plus the estate's,
rendered every store-scoped exception twice.
"""

from __future__ import annotations

import pytest

from vecshield_platform.evidence import RiskException
from vecshield_platform.history import ScanHistory


@pytest.fixture
def history(tmp_path):
    h = ScanHistory(str(tmp_path / "history.db"))
    for eid, criterion, scope in (
        ("exc-store", "HIPAA-164-312-A1-ACCESS-CONTROL-01", "clinical-rag"),
        ("exc-global", "HIPAA-164-312-B-AUDIT-01", ""),
        ("exc-other", "GDPR-ERASURE-01", "customer-360"),
    ):
        h.save_exception(RiskException(
            id=eid, criterion_id=criterion, scope=scope,
            rationale="tolerated while the control is built",
            requested_by="lead@example.test", expires_at="2027-01-01",
            created_at="2026-01-01"))
    return h


def test_an_empty_scope_returns_only_the_estate_wide_exception(history):
    assert [e["id"] for e in history.list_exceptions(scope="")] == ["exc-global"]


def test_no_scope_argument_returns_everything(history):
    assert len(history.list_exceptions()) == 3


def test_a_store_scope_returns_only_that_store(history):
    assert [e["id"] for e in history.list_exceptions(scope="clinical-rag")] == [
        "exc-store"
    ]


def test_store_plus_estate_wide_does_not_duplicate(history):
    """The shape of the call the criteria view makes."""
    combined = (history.list_exceptions(scope="clinical-rag")
                + history.list_exceptions(scope=""))
    ids = [e["id"] for e in combined]
    assert ids == ["exc-store", "exc-global"]
    assert len(ids) == len(set(ids)), "an exception was returned twice"


def test_criterion_filter_is_unaffected(history):
    assert [e["id"] for e in
            history.list_exceptions(criterion_id="GDPR-ERASURE-01")] == ["exc-other"]
