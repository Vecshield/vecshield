"""The console's home summary and cross-store approval queue, as pure functions.

Two reads the console needs on its first screen:

* **What needs a person.** Plans waiting for approval, evidence reviews waiting
  for a decision, exceptions that are lapsing or have lapsed, stores the crypto
  gate would block, stores never assessed, and stores whose latest audit did
  not see its whole scope. Counts only.
* **What is open.** Distinct findings by fingerprint, taken from each store's
  latest saved audit only, so re-running an audit does not inflate the number.
  Suppressed findings are counted separately, never folded in.

Nothing here computes a percentage or a score, and a store with no saved audit
is reported as never assessed rather than as a store with zero findings.

The API gathers the rows (one snapshot read per store, one findings query for
all latest audits) and these functions reduce them.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

#: Severity keys always present in a count, highest first.
SEVERITIES = ("critical", "high", "medium", "low", "info")
_RANK = {name: index for index, name in enumerate(reversed(SEVERITIES))}

#: How far ahead an exception's expiry counts as "expiring".
EXPIRY_WINDOW_DAYS = 14

#: Evidence review states in which a reviewer has something to decide.
REVIEW_WAITING_STATES = ("submitted", "under_review")

OPEN_FINDINGS_NOTE = (
    "Distinct findings by fingerprint from each store's latest saved audit. "
    "Suppressed findings are counted separately. A finding's case state is not "
    "considered, so one marked false positive still counts until it is "
    "suppressed or no longer observed. Stores never assessed are not counted "
    "and are not zero.")


#: The findings list's ``scope=latest`` counts the same rows as open_findings.
LATEST_FINDINGS_NOTE = (
    "Distinct findings from each store's latest saved audit, one per "
    "fingerprint. Suppressed findings are included unless suppressed=false; "
    "with suppressed=false these are the home summary's open findings. A "
    "finding's case state is not considered. Stores never assessed contribute "
    "nothing, which is not the same as zero.")


def _highest(severities: Iterable[str]) -> str:
    known = [s for s in severities if s in _RANK]
    return max(known, key=_RANK.__getitem__) if known else "info"


def summarize_open_findings(rows: Iterable[dict[str, Any]],
                            audit_store: dict[str, str],
                            *, never_assessed: int = 0) -> dict[str, Any]:
    """Reduce (audit, fingerprint) rows to distinct open findings per store.

    ``audit_store`` maps each latest audit id to its store id; rows for any
    other audit are ignored, so an older audit can never contribute.
    """
    open_by_key: dict[tuple[str, str], str] = {}
    suppressed_keys: set[tuple[str, str]] = set()
    for row in rows:
        store_id = audit_store.get(row.get("audit_id") or "")
        if store_id is None:
            continue
        key = (store_id, row["fingerprint"])
        if row.get("suppressed"):
            suppressed_keys.add(key)
            continue
        severity = _highest([*row.get("severities", []), open_by_key.get(key, "info")])
        open_by_key[key] = severity
    # A fingerprint seen both suppressed and not is open: one live occurrence
    # is enough for the observation to stand.
    suppressed_keys -= set(open_by_key)
    by_severity = {name: 0 for name in SEVERITIES}
    for severity in open_by_key.values():
        by_severity[severity] += 1
    return {
        "by_severity": by_severity,
        "total": len(open_by_key),
        "stores": len({store for store, _ in open_by_key}),
        "stores_assessed": len(set(audit_store.values())),
        "stores_never_assessed": never_assessed,
        "suppressed": len(suppressed_keys),
        "note": OPEN_FINDINGS_NOTE,
    }


def coverage_status(snapshot: dict[str, Any]) -> str:
    """The latest audit's coverage status: complete, partial, unavailable, unknown."""
    coverage = snapshot.get("coverage") or {}
    if coverage.get("complete") is True:
        return "complete"
    return str(coverage.get("status") or "unknown")


def exception_buckets(exceptions: Iterable[dict[str, Any]], *,
                      now: Optional[datetime] = None,
                      window_days: int = EXPIRY_WINDOW_DAYS) -> dict[str, list[dict]]:
    """Exceptions that need attention, by why.

    ``expiring``: approved, not revoked, lapsing within the window.
    ``expired``: approved, not revoked, already lapsed — the gap is no longer
    tolerated, and someone must renew, remediate, or revoke.
    ``awaiting_approval``: requested and neither approved nor revoked.

    Input rows are :meth:`RiskException.to_dict` output.
    """
    now = now or datetime.now(timezone.utc)
    horizon = (now + timedelta(days=window_days)).isoformat()
    buckets: dict[str, list[dict]] = {"expiring": [], "expired": [],
                                      "awaiting_approval": []}
    for item in exceptions:
        status = item.get("status")
        if status == "active" and item.get("expires_at", "") <= horizon:
            buckets["expiring"].append(item)
        elif status == "expired":
            buckets["expired"].append(item)
        elif status == "pending_approval":
            buckets["awaiting_approval"].append(item)
    return buckets


def plan_queue_entry(record: dict[str, Any], *, actor: str, roles: Iterable[str],
                     has_approving_role: bool, separation: Any,
                     approvals: int, store_registered: bool) -> dict[str, Any]:
    """One staged plan as the approval queue shows it, with the actor's standing.

    Mirrors the refusals in :func:`execution.approve` so the console can say
    "you can approve" or "needs a second person" before anyone clicks. The
    server still decides at approval time; this is a preview of that decision.
    """
    from vecshield_platform.actions import ACTION_TEMPLATES
    from vecshield_platform.execution import executable_operations

    body = record.get("body") or {}
    intact = bool(record.get("body_intact"))
    state = record.get("state")
    runnable, _refused = executable_operations(body) if intact else ([], [])
    irreversible = [op for op in runnable
                    if not ACTION_TEMPLATES[op["action"]].reversible]
    staged_by = record.get("staged_by")
    self_proposed = staged_by == actor

    may_approve, needs_second_person, reason = True, False, None
    if not has_approving_role:
        may_approve, reason = False, "Approving a plan requires the compliance role."
    elif not intact:
        may_approve, reason = False, ("This plan's stored body does not match its "
                                      "recorded hash. Re-stage it.")
    elif state != "staged":
        may_approve, reason = False, f"This plan is {state} and cannot be approved."
    elif not runnable:
        may_approve, reason = False, ("Nothing in this plan can run in this build, "
                                      "so there is nothing to approve.")
    elif self_proposed and not separation.allows_self_approval(
            roles, irreversible=bool(irreversible)):
        may_approve, needs_second_person = False, True
        reason = separation.refusal(proposer=actor, what="this plan",
                                    irreversible=bool(irreversible))

    operations = body.get("operations") or []
    return {
        "plan_id": record.get("id"),
        "store": record.get("store"),
        "store_registered": store_registered,
        "staged_by": staged_by,
        "staged_at": record.get("staged_at"),
        "note": record.get("note") or "",
        "state": state,
        "intact": intact,
        "operations": len(operations),
        "executable": len(runnable),
        "irreversible": bool(irreversible),
        "irreversible_operations": len(irreversible),
        "approvals": approvals,
        "awaiting": "execution" if approvals else "approval",
        "you": {
            "may_approve": may_approve,
            "self_proposed": self_proposed,
            "would_be_self_approval": bool(may_approve and self_proposed),
            "needs_second_person": needs_second_person,
            "requires_typed_store_id": bool(irreversible),
            "reason": reason,
        },
    }


def needs_item(kind: str, title: str, count: int, *, view: str,
               params: Optional[dict[str, Any]] = None,
               stores: Optional[list[str]] = None,
               **extra: Any) -> dict[str, Any]:
    item = {"kind": kind, "title": title, "count": count,
            "target": {"view": view, "params": dict(params or {})}}
    if stores is not None:
        item["stores"] = sorted(stores)
    item.update(extra)
    return item


def store_target(stores: list[str], *, view: str,
                 fallback_view: str = "stores") -> dict[str, Any]:
    """A deep link: the store itself when there is one, else the list."""
    if len(stores) == 1:
        return {"view": view, "params": {"store": stores[0]}}
    return {"view": fallback_view, "params": {}}
