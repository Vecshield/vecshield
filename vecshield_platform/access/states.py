"""Evidence states and check names for access-control posture.

An access observation carries one of the states below as ``access_state``
inside an ordinary check outcome's coverage details, exactly as crypto checks
carry ``crypto_state`` (:mod:`vecshield_platform.crypto.states`). The outcome
itself stays in :data:`vecshield_platform.coverage.OUTCOMES`.

``not_observable`` — the store has no interface for the property, or
VecShield's credential may not read it — becomes ``unsupported`` and never
``failed``. ``observed_exposure`` has no default outcome: a retrieval role that
bypasses row security is a failure, a schema anyone may create objects in is a
weakness whose weight depends on who connects, so the caller states which.
``application_enforced`` means the only boundary is a filter the application
sends, which the store cannot vouch for; it is ``inconclusive``.
"""

from __future__ import annotations

from typing import Optional

from vecshield_platform.coverage import check_outcome

VERIFIED = "verified"
OBSERVED_EXPOSURE = "observed_exposure"
APPLICATION_ENFORCED = "application_enforced"
NOT_VERIFIED = "not_verified"
NOT_OBSERVABLE = "not_observable"
NOT_APPLICABLE = "not_applicable"

ACCESS_STATES = (VERIFIED, OBSERVED_EXPOSURE, APPLICATION_ENFORCED, NOT_VERIFIED,
                 NOT_OBSERVABLE, NOT_APPLICABLE)

#: The outcome a state implies when the caller does not choose one.
#: ``not_applicable`` is ``passed``, not ``skipped``, for the reason given in
#: crypto/states.py: a skipped sibling would downgrade a criterion.
_DEFAULT_OUTCOME = {
    VERIFIED: "passed",
    NOT_APPLICABLE: "passed",
    APPLICATION_ENFORCED: "inconclusive",
    NOT_VERIFIED: "inconclusive",
    NOT_OBSERVABLE: "unsupported",
}

# ---- Check names, as they appear in check outcomes and criteria ----------

ACCESS_GRANTS = "access_grants"

ACCESS_CHECKS = (ACCESS_GRANTS,)

#: Privilege classes a grant is normalised to (RBAC evaluation plan).
#: ``access_admin`` — can create roles or assign them — is treated as full
#: data access, since such a role can grant itself anything.
PRIVILEGE_CLASSES = ("read", "write", "schema_admin", "access_admin", "cluster_ops")


def access_outcome(check: str, store: str, collection: Optional[str] = None, *,
                   state: str, reason: str = "", complete: bool = False,
                   outcome: Optional[str] = None, **coverage) -> dict:
    """A check outcome that also records its access-control evidence state."""
    if state not in ACCESS_STATES:
        raise ValueError(f"unknown access state: {state}")
    if outcome is None:
        if state not in _DEFAULT_OUTCOME:
            raise ValueError(f"{state} needs an explicit outcome: failed where the "
                             "exposure breaches a stated rule, inconclusive where "
                             "its weight depends on who connects")
        outcome = _DEFAULT_OUTCOME[state]
    if state == NOT_OBSERVABLE and outcome == "failed":
        raise ValueError("a property the store does not expose cannot fail")
    return check_outcome(check, store, collection, outcome=outcome, reason=reason,
                         complete=complete, access_state=state, **coverage)
