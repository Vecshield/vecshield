"""Canonical schema shared by every benchmark adapter.

Adapters transform a dataset's native format into a list of :class:`EvalSample`.
VecShield predictions are converted into the same :class:`Annotation` type so the
metrics code stays benchmark-agnostic.

The four top-level categories mirror VecShield's ``SensitivityLabel``:
``PII``, ``PHI``, ``PCI``, ``SECRET``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# The only entity types the metrics layer understands. Adapters MUST map every
# source label to exactly one of these, or drop the annotation.
CATEGORIES = ("PII", "PHI", "PCI", "SECRET")


@dataclass
class Annotation:
    """A single labelled span inside a text."""

    start: int  # char offset, inclusive
    end: int  # char offset, exclusive
    entity_type: str  # one of CATEGORIES
    subtype: str = ""  # finer label ("EMAIL", "SSN", or the fired detector name)
    text: str = ""  # literal matched string (may be empty)
    score: float = 1.0  # confidence; gold spans default to 1.0

    def overlaps(self, other: Annotation) -> bool:
        """True when the two character intervals intersect."""
        return self.start < other.end and self.end > other.start

    def __post_init__(self) -> None:
        if self.entity_type not in CATEGORIES:
            raise ValueError(
                f"entity_type must be one of {CATEGORIES}, got {self.entity_type!r}"
            )


@dataclass
class EvalSample:
    """One unit of evaluation (a sentence, document, or chunk)."""

    id: str
    text: str
    gold: list[Annotation] = field(default_factory=list)
    pred: list[Annotation] = field(default_factory=list)
    source: str = ""
    split: str = "test"

    @property
    def has_gold(self) -> bool:
        return len(self.gold) > 0

    @property
    def has_pred(self) -> bool:
        return len(self.pred) > 0

    @property
    def pred_score(self) -> float:
        """Document-level confidence = max predicted span score (0.0 if none)."""
        return max((p.score for p in self.pred), default=0.0)
