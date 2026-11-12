"""Evidence artifacts, their reviews, and the exceptions attached to gaps.

Three records, deliberately separate, because collapsing any two of them would
let the product claim more than it knows:

**Artifact** — a thing that exists: a config export, an attestation, a ticket, a
test result. Its lifecycle (`collected → integrity_checked → available`, later
`quarantined`, `superseded`, `expired`, `revoked`) says whether the file is fit
to look at. It says nothing about whether it proves anything.

**Review** — a judgement about one artifact *for one criterion, scope, and
period*. The same artifact can be accepted for one assessment and rejected for
another, so review is its own record keyed by all four, never a flag on the
artifact.

**Exception** — a decision to tolerate a gap. It attaches to the gap and never
replaces it: an accepted risk is still a gap, and an expired exception stops
applying rather than quietly persisting.

A content hash proves bytes have not changed. It does not prove the assertion
inside them is true, and nothing here pretends otherwise.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

#: Whether the artifact is fit to be looked at.
ARTIFACT_STATES = ("collected", "integrity_checked", "available",
                   "quarantined", "superseded", "expired", "revoked")

#: States from which an artifact can still be reviewed as evidence.
USABLE_ARTIFACT_STATES = ("available",)

#: A judgement about one artifact for one criterion, scope, and period.
REVIEW_STATES = ("requested", "submitted", "under_review",
                 "accepted", "rejected", "needs_clarification")

#: Only this one means the evidence was accepted.
ACCEPTED_REVIEW_STATES = ("accepted",)

ARTIFACT_TRANSITIONS: dict[str, tuple[str, ...]] = {
    "collected": ("integrity_checked", "quarantined", "revoked"),
    "integrity_checked": ("available", "quarantined", "revoked"),
    "available": ("superseded", "expired", "revoked", "quarantined"),
    "quarantined": ("integrity_checked", "revoked"),
    "superseded": ("revoked",),
    "expired": ("revoked", "superseded"),
    "revoked": (),
}

REVIEW_TRANSITIONS: dict[str, tuple[str, ...]] = {
    "requested": ("submitted", "rejected"),
    "submitted": ("under_review", "accepted", "rejected", "needs_clarification"),
    "under_review": ("accepted", "rejected", "needs_clarification"),
    "needs_clarification": ("submitted", "rejected"),
    # A decision can be revisited, but only by an explicit move back.
    "accepted": ("under_review", "rejected"),
    "rejected": ("under_review", "submitted"),
}

# A decision either way is a claim about the artifact, so each one carries its
# reason; an acceptance without one could not be checked by the next reviewer.
REASON_REQUIRED_FOR = ("accepted", "rejected", "needs_clarification")


#: What each artifact state means to the person looking at the register.
ARTIFACT_STATE_NOTES: dict[str, str] = {
    "collected": ("Registered, not yet checked. Confirm its content hash before "
                  "it can be made available for review."),
    "integrity_checked": ("Its content hash was confirmed, so the bytes are the "
                          "ones registered. Not yet released for review."),
    "available": "Fit to be reviewed as evidence for a criterion.",
    "quarantined": ("Held back while something about the file is investigated. "
                    "Not usable until it is checked again."),
    "superseded": ("Replaced by a newer version. Acceptances that rested on it "
                   "stop counting; review the replacement instead."),
    "expired": ("Past its validity. Acceptances that rested on it stop counting "
                "until a current version is reviewed."),
    "revoked": "Withdrawn for good. It can never be used as evidence again.",
}

#: What each review state means.
REVIEW_STATE_NOTES: dict[str, str] = {
    "requested": "Evidence has been asked for but no artifact put forward yet.",
    "submitted": "An artifact was put forward for this requirement and awaits a reviewer.",
    "under_review": "A reviewer is looking at it.",
    "needs_clarification": ("The reviewer needs more before deciding; the reason "
                            "says what."),
    "accepted": ("A named reviewer decided this artifact satisfies this "
                 "requirement for this scope and period."),
    "rejected": ("A named reviewer decided this artifact does not satisfy this "
                 "requirement; the reason says why."),
}


def lifecycle_reference() -> dict[str, Any]:
    """The artifact and review state machines, explained, for a console to show."""
    return {
        "artifact_states": {
            state: {"meaning": ARTIFACT_STATE_NOTES[state],
                    "usable": state in USABLE_ARTIFACT_STATES,
                    "next": list(ARTIFACT_TRANSITIONS.get(state, ()))}
            for state in ARTIFACT_STATES},
        "review_states": {
            state: {"meaning": REVIEW_STATE_NOTES[state],
                    "accepted": state in ACCEPTED_REVIEW_STATES,
                    "next": list(REVIEW_TRANSITIONS.get(state, ()))}
            for state in REVIEW_STATES},
        "reason_required_for": list(REASON_REQUIRED_FOR),
        "integrity_needs_hash": True,
    }


class EvidenceError(ValueError):
    """A refused evidence or exception operation, with the reason why."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class EvidenceArtifact:
    """Something collected. Its state describes the file, not its truth."""

    id: str
    title: str
    media_type: str = "application/octet-stream"
    state: str = "collected"
    content_hash: Optional[str] = None
    size_bytes: Optional[int] = None
    collector: str = ""
    collected_at: Optional[str] = None
    #: What the artifact is about: a store, a collection, a system.
    scope: str = ""
    #: The window it covers; evidence for Q2 does not evidence Q3.
    period_start: Optional[str] = None
    period_end: Optional[str] = None
    supersedes: Optional[str] = None
    note: str = ""

    def __post_init__(self) -> None:
        if self.state not in ARTIFACT_STATES:
            raise EvidenceError(f"unknown artifact state: {self.state}")

    @property
    def usable(self) -> bool:
        """Whether this artifact may currently be reviewed as evidence."""
        return self.state in USABLE_ARTIFACT_STATES

    def covers(self, at: str) -> Optional[bool]:
        """Whether the artifact's period covers ``at``; None when unstated.

        Unstated is not "yes": an artifact with no period makes no claim about
        which window it evidences, and a reviewer has to decide.
        """
        if not self.period_start and not self.period_end:
            return None
        if self.period_start and at < self.period_start:
            return False
        if self.period_end and at > self.period_end:
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "title": self.title, "media_type": self.media_type,
            "state": self.state, "content_hash": self.content_hash,
            "size_bytes": self.size_bytes, "collector": self.collector,
            "collected_at": self.collected_at, "scope": self.scope,
            "period_start": self.period_start, "period_end": self.period_end,
            "supersedes": self.supersedes, "note": self.note,
            "usable": self.usable,
            "integrity": ("hashed" if self.content_hash else "not hashed"),
            "integrity_note": ("A content hash proves the bytes are unchanged. It does "
                               "not prove the assertion inside them is true."),
        }


@dataclass(frozen=True)
class EvidenceReview:
    """A judgement about one artifact for one criterion, scope, and period."""

    id: str
    artifact_id: str
    criterion_id: str
    scope: str = ""
    period: str = ""
    state: str = "requested"
    reviewer: Optional[str] = None
    reason: str = ""
    decided_at: Optional[str] = None
    requirement: str = ""

    def __post_init__(self) -> None:
        if self.state not in REVIEW_STATES:
            raise EvidenceError(f"unknown review state: {self.state}")

    @property
    def accepted(self) -> bool:
        return self.state in ACCEPTED_REVIEW_STATES

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "artifact_id": self.artifact_id,
            "criterion_id": self.criterion_id, "scope": self.scope,
            "period": self.period, "state": self.state, "reviewer": self.reviewer,
            "reason": self.reason, "decided_at": self.decided_at,
            "requirement": self.requirement, "accepted": self.accepted,
        }


@dataclass(frozen=True)
class RiskException:
    """A decision to tolerate a gap. It never closes the gap."""

    id: str
    criterion_id: str
    scope: str
    rationale: str
    requested_by: str
    expires_at: str
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    revoked_at: Optional[str] = None
    created_at: Optional[str] = None
    #: The requester approved their own exception, which a relaxed
    #: separation-of-duties mode permits and never hides.
    self_approved: bool = False
    #: Why the approver accepted the gap (C-8). Required to approve; None on
    #: pending exceptions and on rows stored before reasons were recorded.
    approval_reason: Optional[str] = None

    def active(self, at: Optional[str] = None) -> bool:
        """Approved, not revoked, and not past its expiry."""
        now = at or _now()
        return bool(self.approved_by and not self.revoked_at and self.expires_at > now)

    def status(self, at: Optional[str] = None) -> str:
        now = at or _now()
        if self.revoked_at:
            return "revoked"
        if not self.approved_by:
            return "pending_approval"
        return "active" if self.expires_at > now else "expired"

    def to_dict(self, at: Optional[str] = None) -> dict[str, Any]:
        return {
            "id": self.id, "criterion_id": self.criterion_id, "scope": self.scope,
            "rationale": self.rationale, "requested_by": self.requested_by,
            "expires_at": self.expires_at, "approved_by": self.approved_by,
            "approved_at": self.approved_at, "revoked_at": self.revoked_at,
            "created_at": self.created_at, "status": self.status(at),
            "active": self.active(at), "self_approved": bool(self.self_approved),
            "approval_reason": self.approval_reason,
            "note": ("An exception records that a gap is tolerated. It does not close "
                     "the gap, and it stops applying when it expires."),
        }


#: Longest approval reason kept; longer text is refused, not truncated.
MAX_APPROVAL_REASON_CHARS = 2000


def approve_exception(exception: RiskException, *, approver: str, reason: str,
                      self_approved: bool = False,
                      at: Optional[str] = None) -> RiskException:
    """Approve a pending exception, recording who approved it and why (C-8).

    Tolerating a gap is a decision, and a decision without a stated reason
    cannot be reviewed later, so an empty or whitespace-only reason is
    refused. State checks (revoked, already approved) come first so the
    caller hears the more fundamental problem.
    """
    if exception.revoked_at:
        raise EvidenceError("a revoked exception cannot be approved")
    if exception.approved_by:
        raise EvidenceError(
            f"this exception is already approved by {exception.approved_by}; "
            "revoke it and request a new one to change the approval")
    if not approver:
        raise EvidenceError("every approval records who made it")
    text = (reason or "").strip()
    if not text:
        raise EvidenceError(
            "approving an exception needs a reason: say why the gap may be "
            "tolerated until it expires")
    if len(text) > MAX_APPROVAL_REASON_CHARS:
        raise EvidenceError(
            f"the approval reason is longer than {MAX_APPROVAL_REASON_CHARS} characters")
    return RiskException(**{**exception.__dict__, "approved_by": approver,
                            "approved_at": at or _now(),
                            "self_approved": bool(self_approved),
                            "approval_reason": text})


def transition_artifact(artifact: EvidenceArtifact, *, to_state: str,
                        actor: str, reason: str = "") -> EvidenceArtifact:
    if to_state not in ARTIFACT_STATES:
        raise EvidenceError(f"unknown artifact state: {to_state}")
    if not actor:
        raise EvidenceError("every artifact change records who made it")
    allowed = ARTIFACT_TRANSITIONS.get(artifact.state, ())
    if to_state not in allowed:
        raise EvidenceError(
            f"cannot move an artifact from {artifact.state} to {to_state}; "
            f"allowed: {', '.join(allowed) or 'nothing'}")
    if to_state == "integrity_checked" and not artifact.content_hash:
        raise EvidenceError("an integrity check needs a content hash to check against")
    return EvidenceArtifact(**{**artifact.__dict__, "state": to_state,
                               "note": reason or artifact.note})


def transition_review(review: EvidenceReview, *, to_state: str, reviewer: str,
                      reason: str = "", at: Optional[str] = None) -> EvidenceReview:
    if to_state not in REVIEW_STATES:
        raise EvidenceError(f"unknown review state: {to_state}")
    if not reviewer:
        raise EvidenceError("every review decision names its reviewer")
    allowed = REVIEW_TRANSITIONS.get(review.state, ())
    if to_state not in allowed:
        raise EvidenceError(
            f"cannot move a review from {review.state} to {to_state}; "
            f"allowed: {', '.join(allowed) or 'nothing'}")
    if to_state in REASON_REQUIRED_FOR and not reason.strip():
        raise EvidenceError(
            "accepting evidence needs a reason saying why it satisfies the requirement"
            if to_state == "accepted" else
            f"moving a review to {to_state} needs a reason saying what is missing")
    return EvidenceReview(**{**review.__dict__, "state": to_state, "reviewer": reviewer,
                             "reason": reason or review.reason,
                             "decided_at": at or _now()})


def accepted_requirements(reviews: list[dict[str, Any]], *, criterion_id: str,
                          artifacts: dict[str, dict[str, Any]]) -> dict[str, str]:
    """Reduce reviews to the evidence states the criterion evaluator understands.

    An accepted review only counts while its artifact is still usable: evidence
    that was superseded, expired, quarantined, or revoked is not accepted
    evidence, however it was once judged.
    """
    states: dict[str, str] = {}
    for review in reviews:
        if review.get("criterion_id") != criterion_id:
            continue
        requirement = review.get("requirement")
        if not requirement:
            continue
        artifact = artifacts.get(review.get("artifact_id", ""), {})
        state = review.get("state", "requested")
        if state == "accepted" and not artifact.get("usable", False):
            states[requirement] = "missing"
            continue
        states[requirement] = {
            "accepted": "accepted", "rejected": "rejected",
            "submitted": "submitted", "under_review": "submitted",
        }.get(state, "missing")
    return states
