"""Whether one query can return the whole collection.

Retrieval access control usually rests on a metadata filter. That filter is
only half the control: if the store places no ceiling on how many results a
single query may return, then one authorised query can drain a collection.
The difference matters for an application that is compromised rather than
absent — the filter still applies, and the entire tenant's data leaves in one
response.

`Connector.max_top_k` already records what each store's API documents, and it
is currently used only to *size* the isolation probe. This reads it as a
control instead.

**This is context for a reviewer, not a control statement, and it is reported
that way.** VecShield does not set the application's page size, cannot see how
the application batches, and a ceiling in the database constrains neither. It
raises no finding. It answers one question — "could a single query take
everything?" — and leaves the judgement where it belongs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

#: A ceiling at or below this is a meaningful constraint on bulk extraction in
#: a single call. Above it, the cap exists but does not limit much. Chosen to
#: be explainable rather than tuned: it is roughly a page of results.
MEANINGFUL_CEILING = 1000


@dataclass(frozen=True)
class ResultCeiling:
    """What the store documents about its maximum result size."""

    kind: str
    max_top_k: Optional[int] = None
    collection_sizes: tuple[int, ...] = ()

    @property
    def status(self) -> str:
        if self.max_top_k is None:
            return "no_documented_ceiling"
        return ("bounded" if self.max_top_k <= MEANINGFUL_CEILING
                else "high_ceiling")

    @property
    def largest_collection(self) -> int:
        return max(self.collection_sizes, default=0)

    @property
    def whole_collection_in_one_query(self) -> bool:
        """True when a single query could return an entire collection."""
        if self.max_top_k is None:
            return bool(self.collection_sizes)
        return self.max_top_k >= self.largest_collection > 0

    def summary(self) -> str:
        if self.status == "no_documented_ceiling":
            return (f"The {self.kind} client records no documented maximum "
                    "result size, so a single query may be able to return a "
                    "whole collection. This is context for a reviewer, not a "
                    "finding: the application's own page size is what applies "
                    "in practice, and VecShield cannot see it.")
        reach = ("which is at or above the largest collection here "
                 f"({self.largest_collection} vectors)"
                 if self.whole_collection_in_one_query
                 else f"below the largest collection here ({self.largest_collection} vectors)")
        return (f"The {self.kind} client documents a maximum of "
                f"{self.max_top_k} results per query, {reach}.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "max_top_k": self.max_top_k,
            "largest_collection": self.largest_collection,
            "whole_collection_in_one_query": self.whole_collection_in_one_query,
            "summary": self.summary(),
            "note": ("Reviewer context only. A ceiling in the database does "
                     "not constrain an application that paginates, and "
                     "VecShield neither sets nor observes the application's "
                     "page size. No finding is raised from this check."),
        }


def observe_result_ceiling(connector, store) -> ResultCeiling:
    """Read the documented ceiling and the collection sizes it applies to."""
    sizes = tuple(int(c.count) for c in getattr(store, "collections", [])
                  if isinstance(getattr(c, "count", None), int) and c.count > 0)
    ceiling = getattr(connector, "max_top_k", None)
    return ResultCeiling(
        kind=getattr(connector, "kind", "unknown"),
        max_top_k=ceiling if isinstance(ceiling, int) and ceiling > 0 else None,
        collection_sizes=sizes)
