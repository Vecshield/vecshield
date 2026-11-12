"""Stored reviewer decisions and applicability answers, and how they are applied.

A reviewer decision is the last of the four inputs :mod:`criteria` keeps
separate: a named person's conclusion that a criterion is satisfied, a gap, or
not applicable for one store. Until now it existed only for the length of one
request. This module holds the rules for the stored version; the storage is in
:mod:`vecshield_platform.history` and the routes are in the API.

The rules, each of which exists to stop a stored record claiming more than it
can:

* **The reviewer is the person who recorded it.** The API takes the reviewer
  from the authenticated principal, never from the request body.
* **A decision is bound to the criterion it was made about.** Each one records
  the pack version and a digest of the criterion's definition. When either no
  longer matches, the decision is *stale*: it is reported, and it is not
  applied. A pack that rewrote a criterion must not inherit a conclusion
  somebody reached about the old wording. A decision recorded under an older,
  known pack version is carried forward only when the criterion's definition
  is exactly what it was under that version — the digest recomputed with the
  old version reproduces the stored one.
* **Stored decisions win over caller-supplied ones.** A caller may still send
  decisions for a what-if evaluation, and they apply only where no current
  stored decision exists. This mirrors how recorded evidence reviews win over
  caller-supplied evidence states.
* **Applicability answers go the other way.** Stored answers are the default,
  and a caller's answers override them question by question, so a reviewer can
  ask "what if this store did not handle ePHI?" without changing the record.

Everything here is pure; :func:`criteria.evaluate_criterion` is unchanged and
still receives one :class:`ReviewerDecision` or ``None``.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, replace
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Optional

from vecshield_platform.compliance.criteria import (
    APPLICABILITY_ANSWERS,
    KNOWN_PACK_VERSIONS,
    NON_MATERIAL_FIELDS,
    Criterion,
    ReviewerDecision,
)

#: What a reviewer may conclude. Mirrors the branches evaluate_criterion reads.
CONCLUSIONS = ("satisfied", "gap", "not_applicable")

#: Why a stored decision is not applied.
STALE_REASONS = {
    "criterion_retired": (
        "The criterion this decision was recorded against is no longer in the "
        "pack, so the decision is not applied to anything."),
    "pack_version_changed": (
        "Recorded against pack {recorded}; this criterion is now evaluated under "
        "{current}. The decision is not applied. Record it again against the "
        "current criterion."),
    "criterion_changed": (
        "The criterion's definition changed after this decision was recorded. "
        "The decision is not applied. Record it again against the current "
        "criterion."),
}

#: Why a decision that is not stale is still not applied to this evaluation.
NOT_APPLIED_REASONS = {
    "made_against_later_audit": (
        "This decision was made against an audit that finished after the one "
        "being evaluated, with information this audit did not have, so it is "
        "not applied here."),
    "decision_audit_unknown": (
        "The audit this decision was made against cannot be placed in time "
        "relative to the one being evaluated, so it is not applied."),
}

DECISION_NOTE = ("A reviewer decision is one person's recorded conclusion for "
                 "one store. It is not a certification, and it never overrides "
                 "an observed failure: a failed check stays a gap.")


def criterion_digest(criterion: Criterion) -> str:
    """A stable digest of what a criterion asks, excluding non-material fields.

    Aliases are left out because absorbing a retired id does not change the
    obligation a reviewer concluded about; the plain-language title is left
    out because renaming an obligation for readability does not change it
    either; the declared lifecycle is left out because it describes the
    mapping's review state, not the obligation. See
    :data:`criteria.NON_MATERIAL_FIELDS`. The pack version *is* part of the
    digest.
    """
    material = {k: v for k, v in asdict(criterion).items()
                if k not in NON_MATERIAL_FIELDS}
    blob = json.dumps(material, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def criterion_digest_as_of(criterion: Criterion, pack_version: str) -> str:
    """The digest this criterion would have had if published under ``pack_version``.

    Equal to a decision's stored digest exactly when the criterion's
    definition has not changed since that pack.
    """
    return criterion_digest(replace(criterion, pack_version=pack_version))


def staleness(record: dict[str, Any],
              criterion: Optional[Criterion]) -> Optional[str]:
    """Why a stored decision must not be applied, or None when it may be."""
    if criterion is None:
        return "criterion_retired"
    recorded = record.get("criterion_digest")
    recorded_pack = record.get("pack_version")
    if recorded_pack != criterion.pack_version:
        # Carried forward only when the definition is provably unchanged: the
        # older pack is one this build knows, the decision stored a digest,
        # and that digest is reproduced with the older version substituted.
        if (recorded and recorded_pack in KNOWN_PACK_VERSIONS
                and recorded == criterion_digest_as_of(criterion, recorded_pack)):
            return None
        return "pack_version_changed"
    if recorded and recorded != criterion_digest(criterion):
        return "criterion_changed"
    return None


def annotate(record: dict[str, Any], *,
             resolve: Callable[[str], Optional[str]],
             lookup: Callable[[str], Optional[Criterion]]) -> dict[str, Any]:
    """A stored decision as the API reports it: current id, and whether stale.

    ``resolve`` maps a possibly-retired criterion id to the current one;
    ``lookup`` returns the current criterion for an id.
    """
    stored_id = record.get("criterion_id") or ""
    current_id = resolve(stored_id)
    criterion = lookup(current_id) if current_id else None
    reason = staleness(record, criterion)
    out = {**record, "criterion_id": current_id or stored_id}
    if current_id and current_id != stored_id:
        out["original_criterion_id"] = stored_id
    out["stale"] = reason is not None
    out["stale_reason"] = reason
    # A decision recorded under an older pack about an unchanged criterion.
    out["carried_from_pack_version"] = (
        record.get("pack_version")
        if reason is None and criterion is not None
        and record.get("pack_version") != criterion.pack_version else None)
    out["stale_note"] = (STALE_REASONS[reason].format(
        recorded=record.get("pack_version"),
        current=criterion.pack_version if criterion else None)
        if reason else None)
    return out


def latest_per_criterion(annotated: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """The newest decision per current criterion id. Input is newest first."""
    latest: dict[str, dict[str, Any]] = {}
    for record in annotated:
        latest.setdefault(record["criterion_id"], record)
    return latest


def to_reviewer_decision(record: dict[str, Any]) -> ReviewerDecision:
    return ReviewerDecision(
        reviewer=record["reviewer"], conclusion=record["conclusion"],
        rationale=record["rationale"], decided_at=record["decided_at"],
        scope=record.get("store_id") or "")


def _instant(value: Optional[str]) -> Optional[datetime]:
    """Parse an ISO timestamp for ordering; naive values are read as UTC."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def audit_relation(decision_audit_id: Optional[str], *,
                   audit_id: Optional[str], audit_finished_at: Optional[str],
                   finished_at: dict[str, Optional[str]]) -> str:
    """How the audit being evaluated relates to the one a decision was made against.

    ``same``, ``later`` (the evaluated audit finished after it, or at the same
    instant), ``earlier`` (it finished before: the decision was made with
    information that audit did not have), or ``unknown`` when either time
    cannot be established.
    """
    if decision_audit_id and decision_audit_id == audit_id:
        return "same"
    decided_on = _instant(finished_at.get(decision_audit_id or ""))
    evaluated = _instant(audit_finished_at)
    if decided_on is None or evaluated is None:
        return "unknown"
    return "earlier" if evaluated < decided_on else "later"


def choose_decisions(criteria: Iterable[Criterion], *,
                     stored_latest: dict[str, dict[str, Any]],
                     what_if: dict[str, ReviewerDecision],
                     audit_id: Optional[str],
                     audit_finished_at: Optional[str] = None,
                     decision_audits_finished_at: Optional[dict[str, Optional[str]]] = None,
                     ) -> tuple[dict[str, ReviewerDecision], dict[str, dict[str, Any]]]:
    """Pick the decision each criterion is evaluated with, and say why.

    Returns ``(applied, provenance)``. ``applied`` feeds evaluate_pack.
    ``provenance[criterion_id]`` carries:

    ``decision_source``
        ``"stored"``, ``"what_if"``, or None when no decision applies.
    ``stored_decision``
        The newest stored decision for the criterion, annotated with
        ``applied``, ``not_applied_reason`` and ``not_applied_note`` (set
        when it is stale, was made against a later audit, or its audit cannot
        be placed in time), and ``carried_forward`` (applied to an audit that
        finished after the one it was made against), or None.
    ``what_if_ignored``
        True when the caller sent a decision that a stored one outranked.

    A stored decision is never applied to an audit that finished before the
    audit it was made against: the reviewer knew things that audit did not.
    """
    finished = decision_audits_finished_at or {}
    applied: dict[str, ReviewerDecision] = {}
    provenance: dict[str, dict[str, Any]] = {}
    for criterion in criteria:
        stored = stored_latest.get(criterion.id)
        caller = what_if.get(criterion.id)
        source: Optional[str] = None
        record = None
        if stored is not None:
            relation = audit_relation(stored.get("audit_id"), audit_id=audit_id,
                                      audit_finished_at=audit_finished_at,
                                      finished_at=finished)
            reason: Optional[str] = stored.get("stale_reason") if stored["stale"] else None
            if reason is None and relation == "earlier":
                reason = "made_against_later_audit"
            elif reason is None and relation == "unknown":
                reason = "decision_audit_unknown"
            note = (stored.get("stale_note") if stored["stale"]
                    else NOT_APPLIED_REASONS.get(reason or ""))
            record = {**stored, "applied": reason is None,
                      "not_applied_reason": reason, "not_applied_note": note,
                      "carried_forward": reason is None and relation == "later"}
            if reason is None:
                applied[criterion.id] = to_reviewer_decision(stored)
                source = "stored"
        if source is None and caller is not None:
            applied[criterion.id] = caller
            source = "what_if"
        provenance[criterion.id] = {
            "decision_source": source,
            "stored_decision": record,
            "what_if_ignored": bool(caller is not None and source == "stored"),
        }
    return applied, provenance


# --------------------------------------------------------------------------- #
# Applicability                                                                #
# --------------------------------------------------------------------------- #

def known_questions(criteria: Iterable[Criterion]) -> dict[str, list[str]]:
    """Every applicability question in the pack, with the criteria that ask it."""
    questions: dict[str, list[str]] = {}
    for criterion in criteria:
        for question in criterion.applicability_questions:
            questions.setdefault(question, []).append(criterion.id)
    return dict(sorted(questions.items()))


def validate_answers(answers: dict[str, str], known: Iterable[str]) -> list[str]:
    """Problems with a set of answers; empty when they can be stored."""
    known = set(known)
    problems = [f"unknown applicability question: {q}" for q in answers if q not in known]
    problems += [f"unknown applicability answer for {q}: {a}"
                 for q, a in answers.items() if a not in APPLICABILITY_ANSWERS]
    return problems


def merge_answers(stored: dict[str, str],
                  what_if: dict[str, str]) -> tuple[dict[str, str], dict[str, str]]:
    """Stored answers overlaid with the caller's. Returns (answers, source per question)."""
    merged = dict(stored)
    sources = {question: "stored" for question in stored}
    for question, answer in what_if.items():
        merged[question] = answer
        sources[question] = "what_if"
    return merged, sources
