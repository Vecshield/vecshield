"""Separation of duties as a stated policy rather than a constant."""

import pytest

from vecshield_platform.approvals import (SEPARATION_ENV, SeparationError,
                                            SeparationOfDuties)


def test_the_default_is_strict_with_identities_and_workable_without(monkeypatch):
    monkeypatch.delenv(SEPARATION_ENV, raising=False)
    assert SeparationOfDuties.resolve(auth_enabled=True).mode == "required"
    assert SeparationOfDuties.resolve(auth_enabled=False).mode == "admin_may_self_approve"


def test_an_explicit_setting_beats_the_environment_beats_the_default(monkeypatch):
    monkeypatch.setenv(SEPARATION_ENV, "off")
    assert SeparationOfDuties.resolve(auth_enabled=True).mode == "off"
    assert SeparationOfDuties.resolve("required", auth_enabled=False).mode == "required"


def test_an_unknown_mode_is_refused():
    with pytest.raises(SeparationError):
        SeparationOfDuties("sometimes")


def test_only_admins_self_approve_and_never_an_irreversible_change():
    policy = SeparationOfDuties("admin_may_self_approve")
    assert policy.allows_self_approval({"admin", "compliance"})
    assert not policy.allows_self_approval({"compliance"})
    assert not policy.allows_self_approval({"admin"}, irreversible=True)
    assert "irreversible" in policy.refusal(proposer="a", irreversible=True)
    assert SeparationOfDuties("off").allows_self_approval({"compliance"}, irreversible=True)
    assert not SeparationOfDuties("required").allows_self_approval({"admin"})


def test_a_self_approval_is_recorded_as_one():
    from vecshield_platform.actions import hash_body
    from vecshield_platform.execution import ApprovalError, approve

    body = {"id": "p1", "store": "demo", "staged_by": "sarah", "state": "staged",
            "operations": [{"action": "tag_exclude", "supported": True, "resolved": True,
                            "collection": "docs", "finding_id": "f1"}]}
    body["plan_hash"] = hash_body(body)

    with pytest.raises(ApprovalError, match="cannot also approve"):
        approve(body, approver="sarah", reason="Reviewed.")

    relaxed = SeparationOfDuties("admin_may_self_approve")
    record = approve(body, approver="sarah", reason="Reviewed.",
                     roles={"admin"}, separation=relaxed)
    assert record.self_approved is True
    assert record.separation_of_duties == "admin_may_self_approve"
    assert record.to_dict()["self_approved"] is True

    other = approve(body, approver="bob", reason="Reviewed.",
                    roles={"admin"}, separation=relaxed)
    assert other.self_approved is False
