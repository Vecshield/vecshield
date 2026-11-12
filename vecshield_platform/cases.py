"""Finding case state: who owns an observation, and what has been decided about it.

A finding is an observation. A *case* is what an organization did about it, and
the two are deliberately separate records: re-running a scan produces new
observations, and must never silently reopen or close a decision somebody made.

The rules here have teeth, because each one exists to stop a specific way of
claiming more than the evidence supports:

* **Suppression is not a case state.** Suppressing a finding changes what is
  shown and what is notified. It does not mean the problem was fixed, and it
  never satisfies a criterion. The two fields live side by side and neither
  implies the other.
* **Resolution requires a reason.** `false_positive`, `duplicate`, and
  `risk_accepted` are claims about the world, so they carry a rationale and the
  person who made them.
* **Verification requires an observation.** A case reaches `verified` only when
  a later run is named as the thing that confirmed it, or when a person states
  in writing that they verified it by other means. "Nobody has seen it lately"
  is not verification.
* **Risk acceptance does not close a gap.** It records that the gap is
  tolerated, and the gap stays visible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

#: The working path, plus the alternatives a case can end on.
CASE_STATES = (
    "new", "triaged", "assigned", "in_progress", "awaiting_verification",
    "verified", "closed", "false_positive", "duplicate", "risk_accepted", "reopened",
)

#: States that assert something about the world rather than about our progress.
#: Each needs a rationale from a named person.
RESOLUTION_STATES = ("false_positive", "duplicate", "risk_accepted", "closed")

#: States from which a recurrence, or a changed mind, can reopen the case.
REOPENABLE = ("verified", "closed", "false_positive", "duplicate", "risk_accepted")

_WORKING = ("triaged", "assigned", "in_progress")
_ALTERNATIVES = ("false_positive", "duplicate", "risk_accepted")

ALLOWED_TRANSITIONS: dict[str, tuple[str, ...]] = {
    "new": (*_WORKING, *_ALTERNATIVES),
    "triaged": ("assigned", "in_progress", *_ALTERNATIVES),
    "assigned": ("in_progress", "triaged", *_ALTERNATIVES),
    "in_progress": ("awaiting_verification", "assigned", "triaged", *_ALTERNATIVES),
    # Verification can fail, which sends the case back to work rather than on.
    "awaiting_verification": ("verified", "in_progress", *_ALTERNATIVES),
    "verified": ("closed", "reopened"),
    "closed": ("reopened",),
    "false_positive": ("reopened",),
    "duplicate": ("reopened",),
    "risk_accepted": ("reopened",),
    "reopened": (*_WORKING, *_ALTERNATIVES),
}


class CaseTransitionError(ValueError):
    """A transition that the state machine refuses, with the reason why."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class CaseEvent:
    """One recorded change to a case. Append-only: the trail is the evidence."""

    finding_id: str
    actor: str
    at: str
    from_state: str
    to_state: str
    owner: Optional[str] = None
    reason: str = ""
    verified_by_job_id: Optional[str] = None
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id, "actor": self.actor, "at": self.at,
            "from_state": self.from_state, "to_state": self.to_state,
            "owner": self.owner, "reason": self.reason,
            "verified_by_job_id": self.verified_by_job_id, "detail": dict(self.detail),
        }


@dataclass(frozen=True)
class CaseState:
    """The current case for one finding."""

    finding_id: str
    state: str = "new"
    owner: Optional[str] = None
    reason: str = ""
    updated_at: Optional[str] = None
    verified_by_job_id: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id, "state": self.state, "owner": self.owner,
            "reason": self.reason, "updated_at": self.updated_at,
            "verified_by_job_id": self.verified_by_job_id,
            "is_open": self.state not in ("verified", "closed", *_ALTERNATIVES),
            "is_resolved_claim": self.state in _ALTERNATIVES,
        }


def transition(current: CaseState, *, to_state: str, actor: str,
               owner: Optional[str] = None, reason: str = "",
               verified_by_job_id: Optional[str] = None,
               at: Optional[str] = None) -> tuple[CaseState, CaseEvent]:
    """Move a case to ``to_state``, or refuse and say why.

    Pure: it returns the new state and the event to record, and touches nothing.
    """
    if to_state not in CASE_STATES:
        raise CaseTransitionError(f"unknown case state: {to_state}")
    if not actor:
        raise CaseTransitionError("every case change records who made it")

    allowed = ALLOWED_TRANSITIONS.get(current.state, ())
    if to_state == current.state:
        raise CaseTransitionError(f"the case is already {to_state}")
    if to_state not in allowed:
        raise CaseTransitionError(
            f"cannot move a case from {current.state} to {to_state}; "
            f"allowed: {', '.join(allowed) or 'nothing'}")

    if to_state == "assigned" and not (owner or current.owner):
        raise CaseTransitionError("assigning a case needs an owner")
    if to_state in RESOLUTION_STATES and not reason.strip():
        raise CaseTransitionError(f"moving a case to {to_state} needs a stated reason")
    if to_state == "verified" and not (verified_by_job_id or reason.strip()):
        raise CaseTransitionError(
            "verification names the run that confirmed it, or states how it was "
            "verified by other means; an absence of recent findings is not verification")

    stamp = at or _now()
    state = CaseState(
        finding_id=current.finding_id,
        state=to_state,
        owner=owner if owner is not None else current.owner,
        reason=reason or ("" if to_state in ("reopened",) else current.reason),
        updated_at=stamp,
        # A reopened case is no longer verified by anything.
        verified_by_job_id=(verified_by_job_id if to_state == "verified"
                            else None if to_state == "reopened"
                            else current.verified_by_job_id),
    )
    event = CaseEvent(
        finding_id=current.finding_id, actor=actor, at=stamp,
        from_state=current.state, to_state=to_state, owner=state.owner,
        reason=reason, verified_by_job_id=verified_by_job_id)
    return state, event


#: States where naming an owner *is* the act of assigning. Past these, work has
#: started or finished, and handing it to someone else must not rewind it.
_PRE_WORK = ("new", "triaged", "reopened")


def assign(current: CaseState, *, owner: str, actor: str,
           at: Optional[str] = None) -> tuple[CaseState, CaseEvent]:
    """Give a case an owner.

    Before work starts, naming an owner moves the case to ``assigned``. Once it
    is under way or resolved, this is a hand-over: the owner changes and the
    case keeps its state, because reassigning is not undoing.
    """
    if not owner:
        raise CaseTransitionError("assigning a case needs an owner")
    if current.state in _PRE_WORK:
        return transition(current, to_state="assigned", actor=actor, owner=owner, at=at)
    stamp = at or _now()
    state = CaseState(
        finding_id=current.finding_id, state=current.state, owner=owner,
        reason=current.reason, updated_at=stamp,
        verified_by_job_id=current.verified_by_job_id)
    event = CaseEvent(
        finding_id=current.finding_id, actor=actor, at=stamp,
        from_state=current.state, to_state=current.state, owner=owner,
        reason="owner changed")
    return state, event


def summarize(states: list[dict[str, Any]]) -> dict[str, Any]:
    """Counts by state. Not a score, and resolution claims are counted apart."""
    counts = {name: 0 for name in CASE_STATES}
    for item in states:
        counts[item.get("state", "new")] = counts.get(item.get("state", "new"), 0) + 1
    resolved_claims = sum(counts[name] for name in _ALTERNATIVES)
    return {
        "by_state": counts,
        "open": sum(counts[n] for n in ("new", "triaged", "assigned", "in_progress",
                                        "awaiting_verification", "reopened")),
        "verified_or_closed": counts["verified"] + counts["closed"],
        "resolution_claims": resolved_claims,
        "note": ("Resolution claims (false positive, duplicate, risk accepted) are "
                 "counted apart from verified work: they assert something about the "
                 "world rather than record a fix."),
    }
