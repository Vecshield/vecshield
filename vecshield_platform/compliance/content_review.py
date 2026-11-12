"""Content reviews: the only route by which pack content becomes "reviewed".

Two kinds of review exist in this product, and they must never be confused:

``ReviewerDecision`` (``compliance.criteria``, stored per store by the API)
    A customer's named person concluding that *their store* satisfies, fails
    or is outside one criterion. It is about the customer's system.
:class:`ContentReview` (this module)
    A qualified outside reviewer — counsel, a QSA, a CPA firm's SOC practice —
    signing off that *VecShield's mapping* of a provision to checks and
    evidence is a fair reading. It is about VecShield's content, and says
    nothing about any customer's store.

A criterion's effective lifecycle is ``regulatory_reviewed`` only when a
content review covers it **and** the digest the reviewer saw is the digest the
criterion has now. Any change to what the criterion asks (its paraphrase,
sources, checks, evidence, limitations, specification, or pack version)
changes the digest, and the review stops applying until it is renewed. A
changed title does not, for the same reason it does not stale a reviewer
decision.

:data:`CONTENT_REVIEWS` is empty. No content review has taken place, and none
may be added to this tuple without the signed review behind it. Fabricating
one would be the overclaim this module exists to prevent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Any, Iterable, Optional

from vecshield_platform.compliance.criteria import Criterion
from vecshield_platform.compliance.sources import (
    LIFECYCLE_LABELS,
    least_advanced,
)

#: Who is qualified to review which slice, from the plan's §4A.4. Shown to
#: whoever commissions a review; not enforced against the free-text
#: ``qualification``, which records what the reviewer actually holds.
QUALIFIED_REVIEWER = {
    "EU": "EU privacy counsel or a CIPP/E holder",
    "HIPAA": "US health-privacy counsel",
    "CCPA/CPRA": "California counsel",
    "PCI-DSS": "A PCI Qualified Security Assessor (QSA)",
    "SOC 2": "A CPA firm's SOC practice",
}

#: The permanent hint every mapping-status line carries, reviewed or not.
MAPPING_HINT = ("A reviewed mapping describes what VecShield checks. It does not "
                "mean a store meets the law.")


def _iso_date(value: str, name: str) -> date:
    try:
        return date.fromisoformat(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be an ISO date (YYYY-MM-DD): {value!r}") from None


@dataclass(frozen=True)
class ContentReview:
    """One qualified reviewer's sign-off on a set of criteria, as worded then."""

    id: str
    reviewer: str
    firm: str
    qualification: str
    jurisdictions: tuple[str, ...]
    #: criterion id -> the criterion digest the reviewer reviewed.
    criterion_digests: dict[str, str]
    reviewed_on: str
    next_review: str
    #: Conflicts of interest declared by the reviewer. "None declared" must be
    #: written out; an empty string is not a declaration.
    conflicts: str
    pack_version: str
    scope_note: str = ""
    criterion_ids: tuple[str, ...] = field(init=False)

    def __post_init__(self) -> None:
        for name in ("id", "reviewer", "firm", "qualification", "conflicts",
                     "pack_version"):
            if not str(getattr(self, name) or "").strip():
                raise ValueError(f"a content review needs {name}")
        if not self.jurisdictions:
            raise ValueError("a content review names the jurisdictions it covers")
        if not self.criterion_digests:
            raise ValueError("a content review covers at least one criterion")
        for criterion_id, digest in self.criterion_digests.items():
            if not criterion_id or len(str(digest)) != 64:
                raise ValueError(
                    f"criterion {criterion_id!r} needs the 64-character digest "
                    "the reviewer saw")
        reviewed = _iso_date(self.reviewed_on, "reviewed_on")
        if _iso_date(self.next_review, "next_review") <= reviewed:
            raise ValueError("next_review must come after reviewed_on")
        object.__setattr__(self, "criterion_ids",
                           tuple(sorted(self.criterion_digests)))

    def covers(self, criterion: Criterion) -> bool:
        """True when this review saw exactly the criterion as it is now."""
        from vecshield_platform.compliance.decisions import criterion_digest

        return self.criterion_digests.get(criterion.id) == criterion_digest(criterion)

    def summary(self, *, today: Optional[date] = None) -> dict[str, Any]:
        today = today or date.today()
        return {"id": self.id, "reviewer": self.reviewer, "firm": self.firm,
                "qualification": self.qualification,
                "jurisdictions": list(self.jurisdictions),
                "criterion_ids": list(self.criterion_ids),
                "reviewed_on": self.reviewed_on, "next_review": self.next_review,
                "review_overdue": date.fromisoformat(self.next_review) < today,
                "conflicts": self.conflicts, "pack_version": self.pack_version,
                "scope_note": self.scope_note}


#: No content review has taken place. Do not add one without the signed
#: review it records.
CONTENT_REVIEWS: tuple[ContentReview, ...] = ()


def criterion_lifecycle(criterion: Criterion,
                        reviews: Optional[Iterable[ContentReview]] = None,
                        *, today: Optional[date] = None) -> dict[str, Any]:
    """A criterion's effective lifecycle and the review behind it, if any.

    ``regulatory_reviewed`` comes only from a review whose stored digest is
    the criterion's current digest. A review of an earlier wording is
    reported under ``stale_reviews`` and changes nothing.
    """
    reviews = CONTENT_REVIEWS if reviews is None else tuple(reviews)
    matching = [r for r in reviews if r.covers(criterion)]
    stale = [r.id for r in reviews
             if criterion.id in r.criterion_digests and not r.covers(criterion)]
    if matching and criterion.lifecycle != "superseded":
        review = max(matching, key=lambda r: r.reviewed_on)
        state = "regulatory_reviewed"
        summary: Optional[dict[str, Any]] = review.summary(today=today)
    else:
        state = criterion.lifecycle
        summary = None
    return {"state": state, "label": LIFECYCLE_LABELS[state], "review": summary,
            "stale_reviews": stale}


def pack_lifecycle(criteria: Iterable[Criterion],
                   reviews: Optional[Iterable[ContentReview]] = None,
                   *, today: Optional[date] = None) -> dict[str, Any]:
    """The pack's lifecycle: its least-advanced criterion's, never higher.

    Superseded criteria are left out of the minimum, since a pack is not held
    back by content it has already replaced; a pack made only of superseded
    criteria is superseded.
    """
    reviews = CONTENT_REVIEWS if reviews is None else tuple(reviews)
    per = {c.id: criterion_lifecycle(c, reviews, today=today) for c in criteria}
    live = [v["state"] for v in per.values() if v["state"] != "superseded"]
    state = (least_advanced(live) if live
             else ("superseded" if per else "draft"))
    by_state: dict[str, int] = {}
    for value in per.values():
        by_state[value["state"]] = by_state.get(value["state"], 0) + 1
    applied = sorted({v["review"]["id"] for v in per.values() if v["review"]})
    return {"state": state, "label": LIFECYCLE_LABELS[state],
            "by_state": dict(sorted(by_state.items())),
            "content_reviews": [r.summary(today=today) for r in reviews
                                if r.id in applied],
            "hint": MAPPING_HINT}
