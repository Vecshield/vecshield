"""Evidence states and check names for cryptographic posture.

A crypto observation carries one of the states below as ``crypto_state``
inside an ordinary check outcome's coverage details. The outcome itself stays
in :data:`vecshield_platform.coverage.OUTCOMES`, so coverage summaries and
criterion evaluation read crypto checks exactly as they read every other check.

The mapping is deliberately asymmetric. ``not_observable`` becomes
``unsupported`` — the store's interface cannot answer — and never ``failed``.
``observed_exposure`` has no default outcome: readable full PAN, or a protection
mechanism applied inconsistently, is a failure; sensitive text that is simply
plaintext is an observed fact whose significance depends on risk, so it is
``inconclusive``. The caller states which.
"""

from __future__ import annotations

from typing import Optional

from vecshield_platform.coverage import check_outcome

VERIFIED = "verified"
OBSERVED_EXPOSURE = "observed_exposure"
PROTECTED_REPRESENTATION = "protected_representation"
NOT_VERIFIED = "not_verified"
NOT_OBSERVABLE = "not_observable"
NOT_APPLICABLE = "not_applicable"

CRYPTO_STATES = (VERIFIED, OBSERVED_EXPOSURE, PROTECTED_REPRESENTATION,
                 NOT_VERIFIED, NOT_OBSERVABLE, NOT_APPLICABLE)

#: The outcome a state implies when the caller does not choose one.
#: ``not_applicable`` is ``passed``, not ``skipped``: beside a passed sibling,
#: a skipped outcome would downgrade a criterion to inconclusive.
_DEFAULT_OUTCOME = {
    VERIFIED: "passed",
    PROTECTED_REPRESENTATION: "passed",
    NOT_APPLICABLE: "passed",
    NOT_VERIFIED: "inconclusive",
    NOT_OBSERVABLE: "unsupported",
}

# ---- Check names, as they appear in check outcomes and criteria ----------

TRANSPORT_ENCRYPTION = "transport_encryption"
TLS_ENFORCEMENT = "transport_tls_enforcement"
AT_REST_ENCRYPTION = "at_rest_encryption"
FIELD_ENCRYPTION = "field_encryption"
DATA_REPRESENTATION = "data_representation"
PAN_REPRESENTATION = "pan_representation"
RETRIEVAL_EXPOSURE = "retrieval_exposure"
DIRECT_IDENTIFIER_EXPOSURE = "direct_identifier_exposure"

CRYPTO_CHECKS = (TRANSPORT_ENCRYPTION, TLS_ENFORCEMENT, AT_REST_ENCRYPTION,
                 FIELD_ENCRYPTION, DATA_REPRESENTATION, PAN_REPRESENTATION,
                 RETRIEVAL_EXPOSURE, DIRECT_IDENTIFIER_EXPOSURE)

#: The control layer each check belongs to, in the order the console shows
#: them. Layers are never collapsed into one "encryption" verdict.
LAYERS = {
    "transport": (TRANSPORT_ENCRYPTION, TLS_ENFORCEMENT),
    "storage": (AT_REST_ENCRYPTION,),
    "data": (FIELD_ENCRYPTION, DATA_REPRESENTATION, PAN_REPRESENTATION,
             DIRECT_IDENTIFIER_EXPOSURE),
    "retrieval": (RETRIEVAL_EXPOSURE,),
}

#: The proposal's control ids, for traceability back to the plan.
CONTROL_IDS = {
    TRANSPORT_ENCRYPTION: "VCR-01",
    TLS_ENFORCEMENT: "VCR-02",
    DATA_REPRESENTATION: "VCR-03/04/05/08/09",
    PAN_REPRESENTATION: "VCR-06",
    DIRECT_IDENTIFIER_EXPOSURE: "VCR-07",
    FIELD_ENCRYPTION: "VCR-10",
    AT_REST_ENCRYPTION: "VCR-11/13",
    RETRIEVAL_EXPOSURE: "retrieval probe",
}


def crypto_outcome(check: str, store: str, collection: Optional[str] = None, *,
                   state: str, reason: str = "", complete: bool = False,
                   outcome: Optional[str] = None, **coverage) -> dict:
    """A check outcome that also records its cryptographic evidence state."""
    if state not in CRYPTO_STATES:
        raise ValueError(f"unknown crypto state: {state}")
    if outcome is None:
        if state not in _DEFAULT_OUTCOME:
            raise ValueError(f"{state} needs an explicit outcome: failed where the "
                             "exposure breaches a stated rule, inconclusive where "
                             "its significance depends on risk")
        outcome = _DEFAULT_OUTCOME[state]
    if state == NOT_OBSERVABLE and outcome == "failed":
        raise ValueError("a property the store does not expose cannot fail")
    return check_outcome(check, store, collection, outcome=outcome, reason=reason,
                         complete=complete, crypto_state=state,
                         control=CONTROL_IDS.get(check, ""), **coverage)
