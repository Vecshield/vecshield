"""Approving a staged plan, carrying it out, and checking what it did.

[actions.py](actions.py) proposes and freezes. This module is the only place in
the product that changes a customer's vector store on the product's own
initiative, and it is deliberately small and deliberately obstructive.

The rules, each of which refuses something a caller might reasonably want:

* **Nothing runs without an explicit approval of that exact plan.** Approval is
  scoped to the plan hash. A re-staged plan is a different plan and needs a
  fresh approval; there are no standing approvals and no auto-apply.
* **The approver is not the stager.** The same rule the exception model already
  applies, for the same reason: one person should not be able to both propose
  and authorize a change to customer data. How strictly this holds is a stated
  deployment policy (:mod:`vecshield_platform.approvals`); when it is relaxed
  the approval record says ``self_approved`` and so does the audit log.
* **Safe mode blocks execution, and is on by default.** Suggesting, staging,
  reviewing and approving all work in safe mode. Only the write is blocked, and
  turning it off is an explicit deployment decision that is recorded on every
  execution record.
* **A plan staged against a store that has since changed is refused.** Not
  re-resolved, not partially applied — refused, because the diff a person
  approved no longer describes the store.
* **Execution stops on the first failure.** A half-applied plan is bad; a
  half-applied plan that kept going and hid the failure is worse.
* **Delete is gated where it is proposed.** ``delete_chunks`` runs only from a
  plan whose suggestion cleared the 'likely' confidence bar, needs the store id
  typed by the approver, and is never offered for retention findings (those
  stay a guided step until a legal hold is ruled out).
* **Zero remaining matches over incomplete coverage is inconclusive.** The same
  rule erasure verification already applies. "We looked at part of it and found
  nothing" is not "it is gone".

One thing this module is careful never to claim: that tagging removed anything.
A metadata write marks a chunk. Whether a retriever honours the mark is a
property of the customer's application, not of this write, and the verification
record says so in those words.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from vecshield_platform.actions import (ACTION_TEMPLATES, content_hash, hash_body,
                                          tenant_type, verify_body)
from vecshield_platform.approvals import STRICT, SeparationOfDuties

#: The actions this build will carry out.
#:
#: ``delete_chunks`` is executable *code*, but it is not offered today: it
#: needs every detector behind it measured at 'likely', and no detector on the
#: current corpus is. That gate is checked where the suggestion is made, so no
#: delete plan reaches this module — which is why the path below is written and
#: tested against a gate nobody can presently open. Retention findings do not
#: propose it at all.
EXECUTABLE_ACTIONS = ("label_sensitivity", "tag_exclude", "quarantine_collection",
                      "redact_text", "delete_chunks",
                      # Remediations for non-classification findings. Each writes
                      # only through a declared capability and is read back.
                      "tag_review", "tag_provenance", "assign_tenant",
                      "quarantine_chunks", "split_by_tenant")

#: The actions whose whole effect is a set of metadata fields computed at
#: staging and frozen into the plan. One writer and one checker serve them all.
FIELD_ACTIONS = ("tag_review", "tag_provenance", "assign_tenant")

#: Where quarantine_chunks moves a chunk. Separate from the redaction originals
#: so a reader can tell "withdrawn pending review" from "original of a redacted
#: chunk" without reading metadata.
QUARANTINE_COLLECTION = "vecshield_quarantine"

#: Where a redacted chunk's original goes: a collection in the same store,
#: marked quarantined, holding the original text and the original vector under
#: an id that names the plan. It is still in the store — a retriever that
#: queries every collection will see it — and that is said on every
#: verification rather than assumed away.
ORIGINALS_COLLECTION = "vecshield_originals"
NEEDS_REEMBED_KEY = "vecshield_needs_reembed"
REDACTED_KEY = "vecshield_redacted"

#: Metadata this product writes. Namespaced so it can never collide with the
#: customer's own fields, and readable so somebody finding one in their store
#: can tell where it came from.
EXCLUDED_KEY = "vecshield_excluded"
QUARANTINED_KEY = "vecshield_quarantined"
PLAN_KEY = "vecshield_plan_id"
MARKED_AT_KEY = "vecshield_marked_at"

#: Written by label_sensitivity. Scalars only: several stores restrict metadata
#: values to strings, numbers and booleans, so the category list is joined
#: rather than nested. SENSITIVITY_KEY holds the highest label observed on the
#: chunk; CATEGORIES_KEY holds every one of them.
SENSITIVITY_KEY = "vecshield_sensitivity"
CATEGORIES_KEY = "vecshield_categories"
LABELLED_AT_KEY = "vecshield_labelled_at"

#: Environment variable that permits writes. Absent or anything other than an
#: explicit off value means safe mode, so a deployment that never thought about
#: it cannot be written to.
SAFE_MODE_ENV = "VECSHIELD_SAFE_MODE"
_OFF = {"0", "false", "no", "off"}


class ApprovalError(ValueError):
    """An approval the module refuses to record, with the reason."""


class ExecutionError(RuntimeError):
    """An execution the module refuses to start, with the reason."""


class SafeModeRefused(ExecutionError):
    """A write refused because the deployment is in safe mode.

    Raised by every path that deletes or changes customer data: an approved
    plan, an erasure, a DSAR execution. Safe mode is a deployment switch, not a
    permission, so it binds every caller, administrators included.
    """


def safe_mode() -> bool:
    """Whether writes are blocked. True unless explicitly turned off."""
    return os.environ.get(SAFE_MODE_ENV, "1").strip().lower() not in _OFF


def refuse_in_safe_mode(what: str = "nothing is written to the store") -> None:
    """Raise :class:`SafeModeRefused` when safe mode is on; otherwise return.

    ``what`` completes the sentence "safe mode is on, so ...".
    """
    if safe_mode():
        raise SafeModeRefused(
            f"safe mode is on, so {what}. Set {SAFE_MODE_ENV}=0 in the deployment "
            "to permit writes. Staging, review, approval and impact assessment are "
            "unaffected.")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# Approve                                                                      #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Approval:
    """One person authorizing one exact plan.

    ``plan_hash`` is what the approval is scoped to, not ``plan_id``: an id
    could in principle be reused, and a hash could not. Checking the hash again
    at execution is what stops an approved plan being swapped for another.
    """

    id: str
    plan_id: str
    plan_hash: str
    approver: str
    reason: str
    approved_at: str
    typed_store_id: str = ""
    operations: tuple[str, ...] = ()
    #: True when the approver is the person who staged the plan. Allowed only
    #: under a relaxed separation-of-duties mode, and never silent.
    self_approved: bool = False
    #: The mode in force when this approval was given.
    separation_of_duties: str = "required"

    def to_dict(self) -> dict:
        return {"id": self.id, "plan_id": self.plan_id, "plan_hash": self.plan_hash,
                "approver": self.approver, "reason": self.reason,
                "approved_at": self.approved_at, "typed_store_id": self.typed_store_id,
                "operations": list(self.operations),
                "self_approved": self.self_approved,
                "separation_of_duties": self.separation_of_duties}


def executable_operations(body: dict) -> tuple[list[dict], list[dict]]:
    """Split a plan's operations into the ones this build runs and the rest.

    Returns ``(runnable, refused)``. Every refused operation carries a
    ``refusal`` saying why, because an operation that silently does not run is
    indistinguishable from one that ran and did nothing.
    """
    runnable: list[dict] = []
    refused: list[dict] = []
    for op in body.get("operations") or []:
        action = op.get("action")
        template = ACTION_TEMPLATES.get(action)
        if template is None:
            refused.append({**op, "refusal": f"Unknown action: {action}."})
        elif not op.get("supported"):
            refused.append({**op, "refusal": op.get("support_reason")
                            or "The connector cannot perform this."})
        elif action not in EXECUTABLE_ACTIONS:
            refused.append({**op, "refusal": (
                f"{template.title} is not executable in this build. It is "
                f"{'irreversible' if not template.reversible else 'higher-impact'} "
                f"and waits behind its own gate: {template.gate}.")})
        elif template.scope == "collection":
            runnable.append(op)
        elif not op.get("resolved"):
            refused.append({**op, "refusal": (
                "None of its targets are still in the store, so there is "
                "nothing for it to do.")})
        else:
            runnable.append(op)
    return runnable, refused


def approve(body: dict, *, approver: str, reason: str,
            typed_store_id: str = "",
            roles: Iterable[str] = (),
            separation: SeparationOfDuties = STRICT) -> Approval:
    """Record an authorization for this exact plan.

    Refuses rather than warns, in every case: an approval that was recorded
    with a reservation attached is an approval, and the reservation is not what
    gets checked at execution time.

    ``separation`` is the deployment's separation-of-duties rule and ``roles``
    are the approver's; together they decide whether the person who staged the
    plan may approve it. Callers that pass neither get the strict rule.
    """
    if not approver:
        raise ApprovalError("an approval records who gave it")
    if not reason or not reason.strip():
        raise ApprovalError(
            "an approval records why it was given. This is a change to customer "
            "data, and 'approved' on its own is not a reason.")
    if not verify_body(body):
        raise ApprovalError(
            "this plan does not match its own hash, so what would be approved is "
            "not what was staged. Re-stage it.")
    if body.get("state") not in (None, "staged"):
        raise ApprovalError(
            f"this plan is {body.get('state')} and cannot be approved.")

    runnable, refused = executable_operations(body)
    if not runnable:
        detail = "; ".join(op.get("refusal", "") for op in refused) or "it has no operations"
        raise ApprovalError(
            f"there is nothing in this plan to approve: {detail}")

    irreversible = [op for op in runnable
                    if not ACTION_TEMPLATES[op["action"]].reversible]

    self_approved = approver == body.get("staged_by")
    if self_approved and not separation.allows_self_approval(
            roles, irreversible=bool(irreversible)):
        raise ApprovalError(separation.refusal(
            proposer=approver, what="this plan", irreversible=bool(irreversible)))

    if irreversible and typed_store_id != body.get("store"):
        raise ApprovalError(
            "this plan contains an irreversible operation, so the approver must "
            f"type the store id ({body.get('store')}) to confirm it.")

    return Approval(
        id=f"appr-{uuid.uuid4().hex[:12]}",
        plan_id=str(body.get("id") or ""),
        plan_hash=hash_body(body),
        approver=approver,
        reason=reason.strip(),
        approved_at=_now(),
        typed_store_id=typed_store_id,
        operations=tuple(op["action"] for op in runnable),
        self_approved=self_approved,
        separation_of_duties=separation.mode,
    )


# --------------------------------------------------------------------------- #
# Execute                                                                      #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class OperationOutcome:
    """What one operation did, or why it did not run.

    ``changed`` is what the store reported back, not what was asked for. The
    two differ when a chunk went away between staging and execution, and
    reporting the request as the result is how a product comes to believe it
    fixed something it did not.
    """

    action: str
    collection: Optional[str]
    finding_id: str
    outcome: str                 # applied | skipped | failed
    requested: int
    changed: int
    detail: str = ""

    def to_dict(self) -> dict:
        return {"action": self.action, "collection": self.collection,
                "finding_id": self.finding_id, "outcome": self.outcome,
                "requested": self.requested, "changed": self.changed,
                "detail": self.detail}


@dataclass(frozen=True)
class Execution:
    """The record of one attempt to carry out one approved plan."""

    id: str
    plan_id: str
    plan_hash: str
    store: str
    executed_by: str
    approval_id: str
    started_at: str
    finished_at: str
    outcomes: tuple[OperationOutcome, ...]
    refused: tuple[dict, ...] = ()
    safe_mode: bool = True
    halted: bool = False
    halt_reason: str = ""

    @property
    def applied(self) -> int:
        # A failed operation can still have written some chunks before it
        # stopped; those writes are in the store and are counted.
        return sum(o.changed for o in self.outcomes if o.outcome in ("applied", "failed"))

    @property
    def complete(self) -> bool:
        """Every runnable operation applied in full, and nothing stopped it."""
        return (not self.halted
                and bool(self.outcomes)
                and all(o.outcome == "applied" and o.changed >= o.requested
                        for o in self.outcomes))

    def to_dict(self) -> dict:
        return {
            "id": self.id, "plan_id": self.plan_id, "plan_hash": self.plan_hash,
            "store": self.store, "executed_by": self.executed_by,
            "approval_id": self.approval_id, "started_at": self.started_at,
            "finished_at": self.finished_at, "safe_mode": self.safe_mode,
            "halted": self.halted, "halt_reason": self.halt_reason,
            "complete": self.complete, "chunks_changed": self.applied,
            "outcomes": [o.to_dict() for o in self.outcomes],
            "refused": [dict(r) for r in self.refused],
        }


def _marks(plan_id: str) -> dict[str, Any]:
    return {PLAN_KEY: plan_id, MARKED_AT_KEY: _now()}


def _highest_label(labels: list[str]) -> str:
    """The most serious label observed, for the single-value field.

    Ordered by what a reader would act on first. An unrecognised label sorts
    below every known one rather than being dropped: a field the scan produced
    and this function does not know is still the scan's finding.
    """
    order = ("SECRET", "PCI", "PHI", "PII", "INJECTION")
    known = [label for label in order if label in labels]
    return known[0] if known else sorted(labels)[0]


def _apply(op: dict, connector: Any, plan_id: str) -> OperationOutcome:
    """Carry out one operation. Never raises: a failure is an outcome."""
    action = op["action"]
    collection = op.get("collection")
    finding_id = op.get("finding_id", "")
    try:
        if action == "quarantine_collection":
            written = connector.set_collection_metadata(
                collection, {QUARANTINED_KEY: True, **_marks(plan_id)})
            return OperationOutcome(
                action, collection, finding_id,
                "applied" if written else "skipped", 1, 1 if written else 0,
                "" if written else "The store did not record the change.")

        ids = [t["chunk_id"] for t in op.get("targets") or [] if t.get("present")]
        if not ids:
            return OperationOutcome(action, collection, finding_id, "skipped", 0, 0,
                                    "No targets are still present in the store.")

        if action == "redact_text":
            return _apply_redaction(op, connector, plan_id, ids)

        if action == "quarantine_chunks":
            return _apply_quarantine(op, connector, plan_id, ids)

        if action == "split_by_tenant":
            return _apply_split(op, connector, plan_id, ids)

        if action in FIELD_ACTIONS:
            fields = dict((op.get("params") or {}).get("fields") or {})
            if not fields:
                return OperationOutcome(action, collection, finding_id, "skipped",
                                        len(ids), 0,
                                        "The operation carries no fields to write.")
            changed = int(connector.set_chunk_metadata(
                collection, {cid: {**fields, **_marks(plan_id)} for cid in ids}))
            return OperationOutcome(
                action, collection, finding_id,
                "applied" if changed else "skipped", len(ids), changed,
                (f"{len(ids) - changed} target(s) were no longer in the collection "
                 "and were not written." if changed < len(ids) else ""))

        if action == "delete_chunks":
            # Nothing is marked and nothing is kept. The count is what the store
            # reported removing, and the caveat about copies outside this store
            # travels with the verification rather than being implied away here.
            removed = int(connector.delete_chunks(collection, ids))
            return OperationOutcome(
                action, collection, finding_id, "applied" if removed else "skipped",
                len(ids), removed,
                (f"{len(ids) - removed} target(s) were not removed." if removed < len(ids)
                 else ""))

        if action == "label_sensitivity":
            # What the scan observed, written where the data lives. The fields
            # are merged in, so the customer's own metadata survives, and the
            # write is not a claim that anything now filters on them.
            labels = [str(x) for x in (op.get("labels") or [])]
            if not labels:
                return OperationOutcome(action, collection, finding_id, "skipped",
                                        len(ids), 0,
                                        "The operation names no label to write.")
            fields: dict[str, Any] = {
                SENSITIVITY_KEY: _highest_label(labels),
                CATEGORIES_KEY: ",".join(sorted(labels)),
                LABELLED_AT_KEY: _now(),
                PLAN_KEY: plan_id,
            }
            updates = {cid: dict(fields) for cid in ids}
        else:
            updates = {cid: {EXCLUDED_KEY: True, **_marks(plan_id)} for cid in ids}
        changed = int(connector.set_chunk_metadata(collection, updates))
        if changed < len(ids):
            # Fewer than asked is not a failure, but it is not success either:
            # the missing ones were not marked and must not be counted. And
            # zero changed is not "applied" at all — an earlier version said
            # it was, so a plan that touched nothing read as done.
            return OperationOutcome(
                action, collection, finding_id,
                "applied" if changed else "skipped", len(ids), changed,
                f"{len(ids) - changed} target(s) were no longer in the collection "
                "and were not marked.")
        return OperationOutcome(action, collection, finding_id, "applied",
                                len(ids), changed)
    except Exception as exc:
        return OperationOutcome(action, collection, finding_id, "failed",
                                len(op.get("targets") or []), 0,
                                f"{type(exc).__name__}: {exc}")


def _failed_part_way(action: str, collection: Any, finding_id: str, requested: int,
                     changed: int, skipped: list[str], exc: Exception) -> OperationOutcome:
    """A batch writer that raised after some chunks were already written.

    The outcome is still ``failed``, so the plan halts, but it keeps the count
    of what had changed: reporting zero would hide writes that are in the store.
    """
    detail = f"{type(exc).__name__}: {exc}"
    if changed:
        detail += (f"; {changed} of {requested} were already written before it failed "
                   "and are not rolled back")
    if skipped:
        detail += "; " + "; ".join(skipped[:20])
    return OperationOutcome(action, collection, finding_id, "failed", requested, changed, detail)


#: Said when a chunk changed between the staleness check and the write.
CHANGED_SINCE_CHECK = ("changed since the plan was checked against the store, so the "
                       "approved change no longer describes it; left as it is. "
                       "Re-stage to act on it")


def _changed_since_staging(chunk: Any, target: Optional[dict]) -> bool:
    """Whether ``chunk``, just read back, differs from what the plan staged.

    The staleness check runs before execution starts, and a writer can land
    in between. Re-hashing the copy about to be written from narrows that
    window to the store's own read-then-write, instead of a whole request.
    A target recorded without a hash (a plan from an older build) is not
    second-guessed here: the staleness check already covered it.
    """
    staged = (target or {}).get("content_hash")
    return bool(staged) and content_hash(chunk) != staged


def _apply_redaction(op: dict, connector: Any, plan_id: str,
                     ids: list[str]) -> OperationOutcome:
    """Copy each original aside, then replace its text. In that order.

    The copy goes first so that a failure between the two steps leaves an
    unredacted chunk with a spare copy, never a redacted chunk with no way
    back. The vector is carried over unchanged: see the template's caveat.
    """
    from vecshield.models import Chunk

    collection = op.get("collection")
    finding_id = op.get("finding_id", "")
    by_id = {t["chunk_id"]: t for t in op.get("targets") or [] if t.get("present")}
    originals = {c.id: c for c in connector.get_chunks(collection, ids)}
    changed, skipped = 0, []
    try:
        for cid in ids:
            target = by_id.get(cid)
            original = originals.get(cid)
            replacement = (target or {}).get("redacted_text")
            if original is None:
                skipped.append(f"{cid}: no longer in the store")
                continue
            if _changed_since_staging(original, target):
                skipped.append(f"{cid}: {CHANGED_SINCE_CHECK}")
                continue
            if replacement is None or replacement == original.text:
                skipped.append(f"{cid}: nothing to redact in its current text")
                continue
            if original.embedding is None:
                skipped.append(f"{cid}: has no stored vector, so its text cannot be "
                               "replaced without the store embedding it")
                continue
            # 1. Retain the original, vector and all, under an id that names the plan.
            connector.add_chunks(ORIGINALS_COLLECTION, [Chunk(
                id=f"{plan_id}:{collection}:{cid}", collection=ORIGINALS_COLLECTION,
                text=original.text, embedding=list(original.embedding),
                metadata={**(original.metadata or {}), "vecshield_original_of": cid,
                          "vecshield_original_collection": collection,
                          PLAN_KEY: plan_id, MARKED_AT_KEY: _now()})])
            # 2. Only then replace the text, carrying the vector over.
            written = connector.replace_chunk_text(
                collection, cid, replacement,
                {REDACTED_KEY: True, NEEDS_REEMBED_KEY: True, **_marks(plan_id)})
            if written:
                changed += 1
            else:
                skipped.append(f"{cid}: the store did not record the replacement")
    except Exception as exc:  # noqa: BLE001 — report what was done before it failed
        return _failed_part_way("redact_text", collection, finding_id, len(ids), changed,
                                skipped, exc)
    try:
        connector.set_collection_metadata(
            ORIGINALS_COLLECTION, {QUARANTINED_KEY: True, PLAN_KEY: plan_id})
    except Exception:  # noqa: BLE001 — the copy is made; the mark is advisory
        skipped.append(f"{ORIGINALS_COLLECTION} could not be marked quarantined")
    detail = "; ".join(skipped)
    outcome = "applied" if changed else "skipped"
    return OperationOutcome(action="redact_text", collection=collection,
                            finding_id=finding_id, outcome=outcome,
                            requested=len(ids), changed=changed, detail=detail)


def _apply_quarantine(op: dict, connector: Any, plan_id: str,
                      ids: list[str]) -> OperationOutcome:
    """Copy each chunk aside, confirm the copy, then remove the original.

    Copy first, confirm, then delete — so the failure between two steps is a
    spare copy, never a chunk that is gone from both places. A chunk with no
    stored vector is left where it is: writing it elsewhere would need the
    store to embed it with a model nobody chose.
    """
    from vecshield.models import Chunk

    collection = op.get("collection")
    finding_id = op.get("finding_id", "")
    by_id = {t["chunk_id"]: t for t in op.get("targets") or [] if t.get("present")}
    originals = {c.id: c for c in connector.get_chunks(collection, ids)}
    moved, skipped = 0, []
    try:
        for cid in ids:
            original = originals.get(cid)
            if original is None:
                skipped.append(f"{cid}: no longer in the store")
                continue
            if _changed_since_staging(original, by_id.get(cid)):
                skipped.append(f"{cid}: {CHANGED_SINCE_CHECK}")
                continue
            if original.embedding is None:
                skipped.append(f"{cid}: has no stored vector, so it cannot be copied "
                               "without the store embedding it; left in place")
                continue
            copy_id = f"{plan_id}:{collection}:{cid}"
            connector.add_chunks(QUARANTINE_COLLECTION, [Chunk(
                id=copy_id, collection=QUARANTINE_COLLECTION, text=original.text,
                embedding=list(original.embedding),
                metadata={**(original.metadata or {}),
                          "vecshield_quarantined_from": str(collection),
                          "vecshield_original_id": cid, **_marks(plan_id)})])
            copies = connector.get_chunks(QUARANTINE_COLLECTION, [copy_id])
            if not copies or copies[0].text != original.text:
                skipped.append(f"{cid}: the quarantine copy could not be confirmed, so the "
                               "original was left in place")
                continue
            removed = int(connector.delete_chunks(collection, [cid]))
            if removed:
                moved += 1
            else:
                skipped.append(f"{cid}: copied, but the store did not report removing the "
                               "original")
    except Exception as exc:  # noqa: BLE001 — report what was done before it failed
        return _failed_part_way("quarantine_chunks", collection, finding_id, len(ids), moved,
                                skipped, exc)
    _mark_collection(connector, QUARANTINE_COLLECTION,
                     {QUARANTINED_KEY: True, PLAN_KEY: plan_id}, skipped)
    return OperationOutcome("quarantine_chunks", collection, finding_id,
                            "applied" if moved else "skipped", len(ids), moved,
                            "; ".join(skipped))


def _apply_split(op: dict, connector: Any, plan_id: str,
                 ids: list[str]) -> OperationOutcome:
    """Copy each tenant's chunks into the collection the approved plan names.

    A chunk is routed by the tenant value it carries *now*; the staleness check
    has already refused a plan whose chunks changed since staging, so that is
    the value the reviewer saw. A tenant the plan does not name is not given a
    collection on the fly.
    """
    from vecshield.models import Chunk

    collection = op.get("collection")
    finding_id = op.get("finding_id", "")
    params = op.get("params") or {}
    field_name = str(params.get("tenant_field") or "")
    partitions = params.get("partitions") or {}
    by_id = {t["chunk_id"]: t for t in op.get("targets") or [] if t.get("present")}
    copied, skipped = 0, []
    routed: dict[str, list] = {}
    for start in range(0, len(ids), 256):
        for chunk in connector.get_chunks(collection, ids[start:start + 256]):
            if _changed_since_staging(chunk, by_id.get(chunk.id)):
                skipped.append(f"{chunk.id}: {CHANGED_SINCE_CHECK}")
                continue
            tenant = (chunk.metadata or {}).get(field_name)
            part = partitions.get(str(tenant)) if tenant is not None else None
            if part is not None and part.get("type") and part["type"] != tenant_type(tenant):
                # 1 and "1" are different tenants to a store that filters by
                # value; the plan named one of them, not both.
                part = None
            if part is None:
                skipped.append(f"{chunk.id}: tenant {tenant!r} is not in the approved plan")
                continue
            if chunk.embedding is None:
                skipped.append(f"{chunk.id}: has no stored vector to copy")
                continue
            routed.setdefault(str(tenant), []).append(Chunk(
                id=chunk.id, collection=part["collection"], text=chunk.text,
                embedding=list(chunk.embedding), metadata=dict(chunk.metadata or {})))
    try:
        for tenant in sorted(routed):
            name = partitions[tenant]["collection"]
            connector.create_collection_like(
                collection, name,
                {"vecshield_split_of": str(collection), "vecshield_tenant": tenant,
                 "vecshield_tenant_field": field_name, PLAN_KEY: plan_id,
                 **({"vecshield_tenant_type": partitions[tenant]["type"]}
                    if partitions[tenant].get("type") else {})})
            items = routed[tenant]
            for start in range(0, len(items), 256):
                copied += int(connector.add_chunks(name, items[start:start + 256]))
    except Exception as exc:  # noqa: BLE001 — report what was done before it failed
        return _failed_part_way("split_by_tenant", collection, finding_id, len(ids), copied,
                                skipped, exc)
    return OperationOutcome("split_by_tenant", collection, finding_id,
                            "applied" if copied else "skipped", len(ids), copied,
                            "; ".join(skipped[:20])
                            + (f"; and {len(skipped) - 20} more" if len(skipped) > 20 else ""))


def _mark_collection(connector: Any, name: str, fields: dict, notes: list[str]) -> None:
    """Best-effort collection mark. The data change is made; the mark is advisory."""
    try:
        if "collection_metadata_write" in set(connector.capabilities()):
            connector.set_collection_metadata(name, fields)
    except Exception:  # noqa: BLE001
        notes.append(f"{name} could not be marked quarantined")


def execute(body: dict, approval: Approval, *, connector: Any, executed_by: str,
            staleness: Optional[tuple[bool, str]] = None,
            separation: Optional[SeparationOfDuties] = None,
            executor_roles: Optional[Iterable[str]] = None) -> Execution:
    """Carry out an approved plan, one operation at a time, stopping on failure.

    ``staleness`` is the caller's ``actions.is_stale`` result. It is required
    rather than computed here so the caller cannot skip it by omission: pass it,
    or the execution is refused.

    ``separation`` is the deployment's separation-of-duties rule. One person
    staging, approving and running a plan is refused unless the approval was
    recorded as a self-approval under a rule that permits it, and the
    deployment still has such a rule. Callers that pass nothing get the
    strict rule.

    ``executor_roles`` are the roles of the person running it now. Given with
    ``separation``, a self-approved plan run by the person who approved it is
    re-checked against the rule in force *now*: an approval recorded under a
    looser rule does not outlive the deployment tightening it.
    """
    rule = separation or STRICT
    refuse_in_safe_mode("nothing is written to the store")
    if not executed_by:
        raise ExecutionError("an execution records who ran it")
    if not verify_body(body):
        raise ExecutionError(
            "this plan does not match its own hash and cannot be executed.")
    if hash_body(body) != approval.plan_hash:
        raise ExecutionError(
            "the approval is for a different version of this plan. Approvals are "
            "scoped to a plan hash; re-stage and get a fresh approval.")
    if approval.plan_id != body.get("id"):
        raise ExecutionError("the approval is for a different plan.")
    if executed_by == body.get("staged_by") and executed_by == approval.approver:
        # approve() already refused a self-approval the rule did not allow, and
        # recorded the ones it did. Refusing to run those would make the
        # relaxed rule approve plans that nobody can ever execute.
        permitted = (approval.self_approved
                     and approval.separation_of_duties != STRICT.mode
                     and rule.mode != STRICT.mode)
        if not permitted:
            raise ExecutionError(
                "the same person staged, approved and ran this plan. A second person "
                "has to approve it, or run it, under this deployment's separation of "
                "duties.")
    self_approval = approval.self_approved or approval.approver == body.get("staged_by")
    if (executor_roles is not None and separation is not None and self_approval
            and executed_by == approval.approver):
        runnable_now, _ = executable_operations(body)
        irreversible = any(not ACTION_TEMPLATES[op["action"]].reversible
                           for op in runnable_now)
        if not separation.allows_self_approval(executor_roles, irreversible=irreversible):
            raise ExecutionError(
                f"this plan was approved by the person who staged it, under the "
                f"'{approval.separation_of_duties}' rule, and the rule in force now is "
                f"'{separation.mode}'. "
                + separation.refusal(proposer=executed_by, what="this plan",
                                     irreversible=irreversible)
                + " Get a fresh approval from a second person.")
    if body.get("state") not in (None, "staged"):
        # Stated rather than left to the staleness check. That check refuses a
        # replay only because the first run changed the content hashes it was
        # comparing, which is incidental; a plan that ran must not depend on a
        # side effect to stop it running again.
        raise ExecutionError(
            f"this plan is already {body.get('state')} and cannot be run again. "
            "Stage a fresh plan.")
    if staleness is None:
        raise ExecutionError(
            "a plan must be checked against the store before it is executed.")
    stale, why = staleness
    if stale:
        raise ExecutionError(
            f"the store has changed since this plan was staged, so the diff that "
            f"was approved no longer describes it: {why}")

    runnable, refused = executable_operations(body)
    if not runnable:
        raise ExecutionError("this plan has no operations this build can run.")

    started = _now()
    outcomes: list[OperationOutcome] = []
    halted, halt_reason = False, ""
    for op in runnable:
        outcome = _apply(op, connector, str(body.get("id") or ""))
        outcomes.append(outcome)
        if outcome.outcome == "failed":
            # Stop rather than carry on. The operations that did not run are in
            # the plan, and the record says where it stopped.
            halted = True
            halt_reason = (f"Stopped after {op['action']} on "
                           f"{op.get('collection') or 'the store'} failed: "
                           f"{outcome.detail}")
            break

    return Execution(
        id=f"exec-{uuid.uuid4().hex[:12]}",
        plan_id=str(body.get("id") or ""), plan_hash=approval.plan_hash,
        store=str(body.get("store") or ""), executed_by=executed_by,
        approval_id=approval.id, started_at=started, finished_at=_now(),
        outcomes=tuple(outcomes), refused=tuple(refused),
        safe_mode=False, halted=halted, halt_reason=halt_reason,
    )


# --------------------------------------------------------------------------- #
# Verify                                                                       #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Verification:
    """An observation of the store after an execution.

    ``outcome`` is one of ``confirmed``, ``partial``, ``inconclusive`` or
    ``failed``. ``inconclusive`` exists because a check that could not see
    everything it needed to has not established anything, and calling that
    success is the specific dishonesty this record is built to prevent.
    """

    execution_id: str
    plan_id: str
    store: str
    checked_at: str
    outcome: str
    expected: int
    observed: int
    unreadable: int = 0
    reason: str = ""
    caveats: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        return {"execution_id": self.execution_id, "plan_id": self.plan_id,
                "store": self.store, "checked_at": self.checked_at,
                "outcome": self.outcome, "expected": self.expected,
                "observed": self.observed, "unreadable": self.unreadable,
                "reason": self.reason, "caveats": list(self.caveats)}


#: Said on every verification of a delete, because "confirmed" here means only
#: that this store no longer returns those ids.
DELETION_CAVEAT = (
    "This confirms the store no longer returns those chunks. Backups, replicas, "
    "snapshots, and any copy taken downstream are outside this store and were "
    "not touched, and anything already retrieved is not recalled.")

#: Said on every verification of a redaction. The text is gone from the chunk;
#: the vector is not, and the original is still in the store.
REDACTION_CAVEAT = (
    "This confirms the stored text was replaced. The chunk's vector was not "
    "changed and still encodes the original text; re-embedding needs the model "
    "the collection was built with, and the chunk is marked for the pipeline "
    "that has it. The original is retained in the quarantine collection, which "
    "is still in this store: a retriever that queries every collection will "
    "see it.")

#: Said on every verification of a marking action, because a reader who sees
#: "confirmed" will otherwise conclude the content is no longer reachable.
MARKING_CAVEAT = (
    "This confirms the mark was written. It does not establish that anything "
    "stopped being retrieved: whether a retriever honours the field is a "
    "property of the application querying this store, not of this write.")


#: Said on every verification of a labelling action. "Confirmed" here means the
#: field is on the chunk, and nothing more: this product does not control the
#: application doing the retrieving and cannot make a label bind it.
LABELLING_CAVEAT = (
    "This confirms the label was written. A label does not restrict retrieval: "
    "whether anything filters on it is a property of the application querying "
    "this store, not of this write.")


#: Said on every verification of a review flag or provenance tag.
FLAGGING_CAVEAT = (
    "This confirms the field was written. A review flag or provenance tag records "
    "what a scan observed; it does not restrict retrieval, and it does not supply "
    "a missing source.")

#: Said on every verification of a tenant assignment.
TENANT_CAVEAT = (
    "This confirms the tenant value is on each chunk. Queries filtered to that "
    "tenant now return them and other tenants' filtered queries do not; a query "
    "that omits the filter still returns them. Re-run the isolation check to see "
    "the collection as a whole.")

#: Said on every verification of a move to quarantine.
QUARANTINE_CAVEAT = (
    "This confirms the source collection no longer returns the chunks and that "
    "vecshield_quarantine holds each one unchanged. The quarantine collection is "
    "in the same store: a retriever that queries every collection still sees it. "
    "Anything already retrieved is not recalled.")

#: Said on every verification of a split.
SPLIT_CAVEAT = (
    "This confirms each per-tenant collection holds its tenant's chunks and no "
    "other tenant's. The shared collection is unchanged and still mixes tenants: "
    "isolation improves only when the application queries the per-tenant "
    "collections instead, and the shared one is retired.")

_FIELD_CAVEATS = {"tag_review": FLAGGING_CAVEAT, "tag_provenance": FLAGGING_CAVEAT,
                  "assign_tenant": TENANT_CAVEAT}


def expected_fields(body: dict) -> dict[str, dict[str, dict]]:
    """Per collection, chunk id -> the fields an executed plan wrote on it."""
    wanted: dict[str, dict[str, dict]] = {}
    runnable, _ = executable_operations(body)
    for op in runnable:
        if op["action"] not in FIELD_ACTIONS or not op.get("collection"):
            continue
        fields = dict((op.get("params") or {}).get("fields") or {})
        for t in op.get("targets") or []:
            if t.get("present"):
                wanted.setdefault(op["collection"], {}).setdefault(
                    t["chunk_id"], {}).update(fields)
    return wanted


def expected_quarantine(body: dict) -> dict[str, list[str]]:
    """The chunk ids an executed plan should have moved, by source collection."""
    wanted: dict[str, list[str]] = {}
    runnable, _ = executable_operations(body)
    for op in runnable:
        if op["action"] != "quarantine_chunks" or not op.get("collection"):
            continue
        wanted.setdefault(op["collection"], []).extend(
            t["chunk_id"] for t in op.get("targets") or [] if t.get("present"))
    return wanted


def expected_partitions(body: dict) -> list[dict]:
    """For each split: the source, the tenant field, the partitions and the ids."""
    out: list[dict] = []
    runnable, _ = executable_operations(body)
    for op in runnable:
        if op["action"] != "split_by_tenant" or not op.get("collection"):
            continue
        params = op.get("params") or {}
        out.append({"collection": op["collection"],
                    "tenant_field": params.get("tenant_field"),
                    "partitions": params.get("partitions") or {},
                    "ids": [t["chunk_id"] for t in op.get("targets") or []
                            if t.get("present")]})
    return out


def _check_fields(connector: Any, expected: dict[str, dict[str, dict]]
                  ) -> tuple[int, int, int, list[str]]:
    """Read each chunk back; it counts only when every field holds the approved value."""
    total, observed, unreadable = 0, 0, 0
    reasons: list[str] = []
    for collection, by_id in expected.items():
        total += len(by_id)
        try:
            chunks = {c.id: c for c in connector.get_chunks(collection, list(by_id))}
        except Exception as exc:
            unreadable += len(by_id)
            reasons.append(f"Could not read {collection} back ({type(exc).__name__}), "
                           f"so {len(by_id)} chunk(s) were not checked.")
            continue
        for cid, fields in by_id.items():
            chunk = chunks.get(cid)
            if chunk is None:
                unreadable += 1
                reasons.append(f"{cid} in {collection} was not returned by the store.")
                continue
            meta = chunk.metadata or {}
            wrong = [k for k, v in fields.items() if meta.get(k) != v]
            if wrong:
                reasons.append(f"{cid} in {collection} does not hold the approved "
                               f"{', '.join(wrong)}.")
                continue
            observed += 1
    return total, observed, unreadable, reasons


def _check_quarantine(connector: Any, plan_id: str, moved: dict[str, list[str]]
                      ) -> tuple[int, int, int, list[str]]:
    """Gone from the source, and present unchanged in quarantine. Both, or neither counts."""
    total, observed, unreadable = 0, 0, 0
    reasons: list[str] = []
    for collection, ids in moved.items():
        wanted = set(ids)
        total += len(wanted)
        still: set[str] = set()
        try:
            for chunk in connector.iter_chunks(collection):
                if chunk.id in wanted:
                    still.add(chunk.id)
            copies = {c.metadata.get("vecshield_original_id"): c
                      for c in connector.get_chunks(
                          QUARANTINE_COLLECTION,
                          [f"{plan_id}:{collection}:{cid}" for cid in wanted])
                      if c.metadata}
        except Exception as exc:
            unreadable += len(wanted)
            reasons.append(f"Could not read {collection} or {QUARANTINE_COLLECTION} back "
                           f"({type(exc).__name__}); whether {len(wanted)} chunk(s) moved "
                           "is unknown.")
            continue
        for cid in sorted(wanted):
            if cid in still:
                reasons.append(f"{cid} is still returned by {collection}.")
            elif cid not in copies:
                reasons.append(f"{cid} is gone from {collection} but no quarantine copy "
                               "was found.")
            else:
                observed += 1
    return total, observed, unreadable, reasons


def _check_partitions(connector: Any, splits: list[dict]
                      ) -> tuple[int, int, int, list[str]]:
    """Every planned chunk in its tenant's collection, and nobody else's there.

    A chunk counts only when it is in its own tenant's collection *and* that
    collection holds no other tenant's chunk: a partition that leaks has not
    isolated anything, whatever its counts say.
    """
    total, observed, unreadable = 0, 0, 0
    reasons: list[str] = []
    for split in splits:
        field_name = split["tenant_field"]
        wanted = set(split["ids"])
        total += len(wanted)
        placed: set[str] = set()
        seen: set[str] = set()
        for tenant, part in sorted(split["partitions"].items()):
            name = part["collection"]
            own: set[str] = set()
            foreign = 0
            typed = part.get("type")
            try:
                for chunk in connector.iter_chunks(name):
                    if chunk.id in wanted:
                        seen.add(chunk.id)
                    value = (chunk.metadata or {}).get(field_name)
                    if str(value) != tenant or (typed and tenant_type(value) != typed):
                        foreign += 1
                    elif chunk.id in wanted:
                        own.add(chunk.id)
            except Exception as exc:
                reasons.append(f"Could not read {name} back ({type(exc).__name__}), so "
                               f"tenant {tenant}'s chunks were not checked.")
                unreadable += int(part.get("chunks") or 0)
                continue
            if foreign:
                reasons.append(f"{name} holds {foreign} chunk(s) that are not "
                               f"{tenant}'s, so it is not isolated.")
                continue
            placed |= own
        observed += len(placed)
        missing = wanted - seen
        if missing:
            reasons.append(f"{len(missing)} planned chunk(s) from {split['collection']} "
                           "are in no per-tenant collection.")
    return total, observed, unreadable, reasons


def expected_labels(body: dict) -> dict[str, list[str]]:
    """The chunk ids an executed plan should have labelled, by collection."""
    wanted: dict[str, list[str]] = {}
    runnable, _ = executable_operations(body)
    for op in runnable:
        if op["action"] != "label_sensitivity" or not op.get("collection"):
            continue
        ids = [t["chunk_id"] for t in op.get("targets") or [] if t.get("present")]
        wanted.setdefault(op["collection"], []).extend(ids)
    return wanted


def expected_redactions(body: dict) -> dict[str, dict[str, str]]:
    """Per collection, the chunk id -> redacted text an executed plan wrote."""
    wanted: dict[str, dict[str, str]] = {}
    runnable, _ = executable_operations(body)
    for op in runnable:
        if op["action"] != "redact_text" or not op.get("collection"):
            continue
        for t in op.get("targets") or []:
            if t.get("present") and t.get("redacted_text") is not None:
                wanted.setdefault(op["collection"], {})[t["chunk_id"]] = t["redacted_text"]
    return wanted


def _check_redactions(connector: Any, redactions: dict[str, dict[str, str]],
                      classifier: Any = None) -> tuple[int, int, int, list[str]]:
    """Read each redacted chunk back and confirm two things.

    That the stored text is the approved replacement, and that the classifier
    no longer finds a span in it. The second is the one that matters: a
    replacement that still contains the secret is not a redaction.
    """
    if redactions and classifier is None:
        from vecshield_platform.detection import build_classifier
        classifier = build_classifier()
    expected, observed, unreadable = 0, 0, 0
    reasons: list[str] = []
    for collection, wanted in redactions.items():
        expected += len(wanted)
        try:
            chunks = {c.id: c for c in connector.get_chunks(collection, list(wanted))}
        except Exception as exc:
            unreadable += len(wanted)
            reasons.append(f"Could not read {collection} back ({type(exc).__name__}), "
                           f"so {len(wanted)} redaction(s) were not checked.")
            continue
        for cid, replacement in wanted.items():
            chunk = chunks.get(cid)
            if chunk is None:
                unreadable += 1
                reasons.append(f"{cid} in {collection} was not returned by the store.")
                continue
            if chunk.text != replacement:
                reasons.append(f"{cid} in {collection} does not hold the approved text.")
                continue
            still = classifier.classify(chunk.text or "")
            if still.spans:
                reasons.append(f"{cid} in {collection} still matches "
                               f"{', '.join(sorted({s.get('detector', '?') for s in still.spans}))} "
                               "after redaction.")
                continue
            if not (chunk.metadata or {}).get(REDACTED_KEY):
                reasons.append(f"{cid} in {collection} holds the text but not the mark.")
                continue
            observed += 1
    return expected, observed, unreadable, reasons


def verify_plan(execution: Execution, body: dict, *, connector: Any) -> Verification:
    """Verify every kind of operation a plan can contain.

    The API and CLI originally called ``verify`` with only the marking inputs,
    so a delete executed through either was verified against nothing and read
    'inconclusive' for the wrong reason. This gathers all three so a caller
    cannot forget one.
    """
    return verify(execution, connector=connector,
                  expected_ids=expected_marks(body),
                  labelled_ids=expected_labels(body),
                  removed_ids=expected_removals(body),
                  redacted=expected_redactions(body),
                  fields=expected_fields(body),
                  quarantined=expected_quarantine(body),
                  partitions=expected_partitions(body),
                  field_actions=sorted({op["action"] for op in executable_operations(body)[0]
                                        if op["action"] in FIELD_ACTIONS}))


def expected_removals(body: dict) -> dict[str, list[str]]:
    """The chunk ids an executed plan should have deleted, by collection."""
    wanted: dict[str, list[str]] = {}
    runnable, _ = executable_operations(body)
    for op in runnable:
        if op["action"] != "delete_chunks" or not op.get("collection"):
            continue
        ids = [t["chunk_id"] for t in op.get("targets") or [] if t.get("present")]
        wanted.setdefault(op["collection"], []).extend(ids)
    return wanted


def _check_removals(connector: Any, removals: dict[str, list[str]]
                    ) -> tuple[int, int, int, list[str]]:
    """Confirm the store no longer returns the deleted ids.

    Absence is only evidence when the collection could be read through. A
    collection that raised part way has not established that anything is gone,
    and its ids are counted unreadable — the rule erasure verification already
    applies, and the one this check exists to not break.
    """
    expected, observed, unreadable = 0, 0, 0
    reasons: list[str] = []
    for collection, ids in removals.items():
        wanted = set(ids)
        expected += len(wanted)
        still_there: set[str] = set()
        try:
            for chunk in connector.iter_chunks(collection):
                if chunk.id in wanted:
                    still_there.add(chunk.id)
        except Exception as exc:
            unreadable += len(wanted)
            reasons.append(
                f"Could not read {collection} back ({type(exc).__name__}), so whether "
                f"{len(wanted)} chunk(s) are gone is unknown. Not seeing them here is "
                "not evidence that they were removed.")
            continue
        observed += len(wanted - still_there)
        if still_there:
            reasons.append(
                f"{len(still_there)} chunk(s) in {collection} are still returned by "
                "the store and were not removed.")
    return expected, observed, unreadable, reasons


def _check_written_field(connector: Any, expected: dict[str, list[str]], key: str,
                         noun: str) -> tuple[int, int, list[str]]:
    """Read chunks back and count the ones actually carrying ``key``.

    A chunk that could not be read is unreadable, never marked and never
    missing: both of those would be claims the observation does not support.
    Each action checks its own field — letting a label satisfy the exclusion
    mark's check would report a write that never happened.
    """
    observed, unreadable = 0, 0
    reasons: list[str] = []
    for collection, ids in expected.items():
        wanted = set(ids)
        try:
            for chunk in connector.iter_chunks(collection):
                if chunk.id in wanted:
                    wanted.discard(chunk.id)
                    if (chunk.metadata or {}).get(key):
                        observed += 1
                    else:
                        reasons.append(
                            f"{chunk.id} in {collection} does not carry {noun}.")
                    if not wanted:
                        break
        except Exception as exc:
            unreadable += len(wanted)
            reasons.append(
                f"Could not read {collection} back ({type(exc).__name__}), so "
                f"{len(wanted)} chunk(s) were not checked.")
            continue
        if wanted:
            unreadable += len(wanted)
            reasons.append(
                f"{len(wanted)} chunk(s) in {collection} were not returned by the "
                f"store, so whether they carry {noun} is unknown.")
    return observed, unreadable, reasons


def verify(execution: Execution, *, connector: Any,
           expected_ids: Optional[dict[str, Iterable[str]]] = None,
           removed_ids: Optional[dict[str, Iterable[str]]] = None,
           redacted: Optional[dict[str, dict[str, str]]] = None,
           labelled_ids: Optional[dict[str, Iterable[str]]] = None,
           fields: Optional[dict[str, dict[str, dict]]] = None,
           quarantined: Optional[dict[str, list[str]]] = None,
           partitions: Optional[list[dict]] = None,
           field_actions: Iterable[str] = ()) -> Verification:
    """Read the store back and report what is actually marked.

    Counts only chunks the store returned carrying the mark. A chunk that could
    not be read is counted as unreadable, never as marked and never as missing,
    because both of those would be claims the observation does not support.
    """
    expected_by_collection: dict[str, list[str]] = {
        str(k): [str(i) for i in v] for k, v in (expected_ids or {}).items()}
    expected = sum(len(v) for v in expected_by_collection.values())
    observed, unreadable = 0, 0
    reasons: list[str] = []
    caveats = [MARKING_CAVEAT]

    if redacted:
        caveats.insert(0, REDACTION_CAVEAT)
        r_expected, r_observed, r_unreadable, r_reasons = _check_redactions(connector, redacted)
        expected += r_expected
        observed += r_observed
        unreadable += r_unreadable
        reasons.extend(r_reasons)
    deletions = {str(k): [str(i) for i in v] for k, v in (removed_ids or {}).items()}
    if deletions:
        caveats.insert(0, DELETION_CAVEAT)
        gone_expected, gone_observed, gone_unreadable, gone_reasons = _check_removals(
            connector, deletions)
        expected += gone_expected
        observed += gone_observed
        unreadable += gone_unreadable
        reasons.extend(gone_reasons)
    if not expected_by_collection and not any(
            o.action in ("tag_exclude", "quarantine_collection")
            for o in execution.outcomes):
        # A plan that marked nothing gets no marking caveat: it would be
        # describing a write that did not happen.
        caveats = [c for c in caveats if c != MARKING_CAVEAT]

    quarantines = [o for o in execution.outcomes
                   if o.action == "quarantine_collection" and o.outcome == "applied"]
    for outcome in quarantines:
        expected += 1
        try:
            found = any(
                c.name == outcome.collection
                and bool((getattr(c, "metadata", None) or {}).get(QUARANTINED_KEY))
                for c in connector.list_collections())
            observed += 1 if found else 0
            if not found:
                reasons.append(f"{outcome.collection} does not report the quarantine mark.")
        except Exception as exc:
            unreadable += 1
            reasons.append(f"Could not re-read collections ({type(exc).__name__}).")

    m_observed, m_unreadable, m_reasons = _check_written_field(
        connector, expected_by_collection, EXCLUDED_KEY, "the mark")
    observed += m_observed
    unreadable += m_unreadable
    reasons.extend(m_reasons)

    labelled = {str(k): [str(i) for i in v] for k, v in (labelled_ids or {}).items()}
    # The caveat follows the run, not only the caller's arguments: an execution
    # that attempted a label still needs the note saying what a label does not
    # do, even when it failed before writing one.
    if labelled or any(o.action == "label_sensitivity" for o in execution.outcomes):
        caveats.insert(0, LABELLING_CAVEAT)
    if labelled:
        expected += sum(len(v) for v in labelled.values())
        l_observed, l_unreadable, l_reasons = _check_written_field(
            connector, labelled, SENSITIVITY_KEY, "the label")
        observed += l_observed
        unreadable += l_unreadable
        reasons.extend(l_reasons)

    for action in dict.fromkeys(field_actions):
        caveat = _FIELD_CAVEATS.get(action)
        if caveat and caveat not in caveats:
            caveats.insert(0, caveat)
    for got in ((_check_fields(connector, fields) if fields else None),
                (_check_quarantine(connector, execution.plan_id, quarantined)
                 if quarantined else None),
                (_check_partitions(connector, partitions) if partitions else None)):
        if got is None:
            continue
        g_expected, g_observed, g_unreadable, g_reasons = got
        expected += g_expected
        observed += g_observed
        unreadable += g_unreadable
        reasons.extend(g_reasons)
    if quarantined:
        caveats.insert(0, QUARANTINE_CAVEAT)
    if partitions:
        caveats.insert(0, SPLIT_CAVEAT)

    if execution.halted:
        outcome = "failed"
        reasons.insert(0, execution.halt_reason)
    elif unreadable:
        # The rule erasure verification already applies: a check that could not
        # see everything has not established anything about what it missed.
        outcome = "inconclusive"
    elif expected and observed == expected:
        outcome = "confirmed"
    elif observed:
        outcome = "partial"
    else:
        outcome = "inconclusive"
        reasons.append("Nothing was observed to check against.")

    return Verification(
        execution_id=execution.id, plan_id=execution.plan_id, store=execution.store,
        checked_at=_now(), outcome=outcome, expected=expected, observed=observed,
        unreadable=unreadable, reason=" ".join(reasons), caveats=tuple(caveats),
    )


def expected_marks(body: dict) -> dict[str, list[str]]:
    """The chunk ids an executed plan should have marked, by collection."""
    wanted: dict[str, list[str]] = {}
    runnable, _ = executable_operations(body)
    for op in runnable:
        if op["action"] != "tag_exclude" or not op.get("collection"):
            continue
        ids = [t["chunk_id"] for t in op.get("targets") or [] if t.get("present")]
        wanted.setdefault(op["collection"], []).extend(ids)
    return wanted


def format_execution(execution: Execution, verification: Optional[Verification]) -> str:
    """The record as text, leading with anything that went wrong."""
    lines = [f"Execution {execution.id} of plan {execution.plan_id}",
             f"Store: {execution.store}  run by {execution.executed_by}  "
             f"approval {execution.approval_id}", ""]
    if execution.halted:
        lines += [f"  ! {execution.halt_reason}", ""]
    for outcome in execution.outcomes:
        lines.append(f"  {outcome.outcome:8} {outcome.action} on "
                     f"{outcome.collection or '(store)'}: "
                     f"{outcome.changed} of {outcome.requested} changed")
        if outcome.detail:
            lines.append(f"           {outcome.detail}")
    for refusal in execution.refused:
        lines.append(f"  refused  {refusal.get('action')}: {refusal.get('refusal')}")
    if verification is not None:
        lines += ["", f"Verification: {verification.outcome} "
                      f"({verification.observed} of {verification.expected} observed"
                      + (f", {verification.unreadable} unreadable" if verification.unreadable else "")
                      + ")"]
        if verification.reason:
            lines.append(f"  {verification.reason}")
        for caveat in verification.caveats:
            lines.append(f"  Note: {caveat}")
    return "\n".join(lines)


__all__ = [
    "ApprovalError", "ExecutionError", "SafeModeRefused", "refuse_in_safe_mode",
    "Approval", "Execution", "OperationOutcome",
    "Verification", "EXECUTABLE_ACTIONS", "EXCLUDED_KEY", "QUARANTINED_KEY",
    "MARKING_CAVEAT", "LABELLING_CAVEAT", "expected_labels", "SAFE_MODE_ENV", "safe_mode", "approve", "execute", "verify",
    "expected_marks", "expected_removals", "expected_redactions", "verify_plan",
    "executable_operations", "format_execution", "REDACTION_CAVEAT",
    "ORIGINALS_COLLECTION", "NEEDS_REEMBED_KEY", "REDACTED_KEY",
    "FIELD_ACTIONS", "QUARANTINE_COLLECTION", "expected_fields", "expected_quarantine",
    "expected_partitions", "FLAGGING_CAVEAT", "TENANT_CAVEAT", "QUARANTINE_CAVEAT",
    "SPLIT_CAVEAT",
]
