"""Scoring, with the distinction the headline number hides.

Three results are reported separately and never summed:

``found`` / ``missed``
    The classifier has a label for this category and did, or did not, find the
    span. This is the only part that is an accuracy claim.

``cannot_express``
    The classifier has no label for the category at all. Counting these as
    misses would report a vocabulary limit as an accuracy failure, which
    flatters every other row it has. They are held apart and named.

``over_flagged``
    Spans predicted on a hard negative. A compliance tool that produces
    spurious findings stops being read, so this is reported per case with the
    bait it fell for, not as an aggregate rate.

Matching is overlap-based on character offsets and category. A prediction that
overlaps a gold span but calls it the wrong category is not a hit: for this
corpus the category *is* the answer, because it decides which regime applies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from benchmarks.ai4privacy.normalize.schema import Annotation, EvalSample
from benchmarks.regulatory_coverage.corpus import Case, case_index
from benchmarks.regulatory_coverage.runners import Runner


@dataclass
class CategoryScore:
    category: str
    gold: int = 0
    found: int = 0
    missed: int = 0
    cannot_express: int = 0

    @property
    def recall(self) -> float | None:
        """Recall over the spans the classifier could in principle express."""
        scorable = self.found + self.missed
        return (self.found / scorable) if scorable else None

    def to_dict(self) -> dict[str, Any]:
        return {"category": self.category, "gold": self.gold, "found": self.found,
                "missed": self.missed, "cannot_express": self.cannot_express,
                "recall": None if self.recall is None else round(self.recall, 3)}


@dataclass
class RunnerReport:
    runner: str
    available: bool
    reason: str = ""
    by_category: dict[str, CategoryScore] = field(default_factory=dict)
    by_regulation: dict[str, dict[str, int]] = field(default_factory=dict)
    over_flagged: list[dict[str, str]] = field(default_factory=list)
    negatives: int = 0

    @property
    def clean_negatives(self) -> int:
        return self.negatives - len(self.over_flagged)

    def to_dict(self) -> dict[str, Any]:
        return {
            "runner": self.runner, "available": self.available, "reason": self.reason,
            "by_category": {k: v.to_dict() for k, v in sorted(self.by_category.items())},
            "by_regulation": dict(sorted(self.by_regulation.items())),
            "hard_negatives": self.negatives,
            "clean_negatives": self.clean_negatives,
            "over_flagged": self.over_flagged,
            "note": ("`cannot_express` is held apart from `missed`: a category "
                     "the classifier has no label for is a vocabulary limit, "
                     "not an accuracy result, and folding the two together "
                     "would flatter every other row."),
        }


def _hit(gold: Annotation, preds: list[Annotation]) -> bool:
    return any(p.entity_type == gold.entity_type and p.overlaps(gold) for p in preds)


def score(runner: Runner, samples: list[EvalSample],
          predictions: list[list[Annotation]]) -> RunnerReport:
    """Score one runner's predictions against the corpus."""
    cases: dict[str, Case] = case_index()
    expressible = runner.expressible()
    report = RunnerReport(runner=runner.name, available=True)

    for sample, preds in zip(samples, predictions):
        case = cases[sample.id]
        if case.is_negative:
            report.negatives += 1
            # A negative names the categories it must not provoke. Anything
            # else the classifier reports is not this case's business: the
            # IMEI case is a claim about the PCI label, and reporting the IMEI
            # as a device identifier is the right answer, not a miss.
            banned = set(case.must_not)
            offending = [p for p in preds
                         if not banned or p.entity_type in banned]
            if offending:
                report.over_flagged.append({
                    "case": case.id, "regulation": case.regulation,
                    "bait": case.bait,
                    "predicted": ", ".join(
                        sorted({f"{p.entity_type}:{p.subtype or '?'}"
                                for p in offending})),
                })
            continue

        bucket = report.by_regulation.setdefault(
            case.regulation, {"gold": 0, "found": 0, "missed": 0, "cannot_express": 0})
        for gold in sample.gold:
            cat = report.by_category.setdefault(
                gold.entity_type, CategoryScore(gold.entity_type))
            cat.gold += 1
            bucket["gold"] += 1
            if gold.entity_type not in expressible:
                cat.cannot_express += 1
                bucket["cannot_express"] += 1
            elif _hit(gold, preds):
                cat.found += 1
                bucket["found"] += 1
            else:
                cat.missed += 1
                bucket["missed"] += 1
    return report


def run(runner: Runner, samples: list[EvalSample]) -> RunnerReport:
    """Check availability, predict, and score. Never raises for a missing dep."""
    availability = runner.availability()
    if not availability.ok:
        return RunnerReport(runner=runner.name, available=False,
                            reason=availability.reason)
    predictions = runner.predict([s.text for s in samples])
    if len(predictions) != len(samples):
        raise ValueError(
            f"{runner.name} returned {len(predictions)} predictions for "
            f"{len(samples)} samples")
    return score(runner, samples, predictions)


def render(report: RunnerReport) -> str:
    """A human-readable block. Deliberately has no single headline number."""
    if not report.available:
        return f"{report.runner}: not run — {report.reason}"
    lines = [f"{report.runner}"]
    lines.append(f"  {'category':18} {'gold':>5} {'found':>6} {'missed':>7} "
                 f"{'n/a':>5}  recall")
    for cat in sorted(report.by_category.values(), key=lambda c: c.category):
        recall = "  —  " if cat.recall is None else f"{cat.recall:.2f} "
        lines.append(f"  {cat.category:18} {cat.gold:5} {cat.found:6} "
                     f"{cat.missed:7} {cat.cannot_express:5}  {recall}")
    lines.append(f"  hard negatives: {report.clean_negatives}/{report.negatives} clean")
    for miss in report.over_flagged:
        lines.append(f"    over-flagged {miss['case']}: {miss['predicted']} "
                     f"(bait: {miss['bait']})")
    return "\n".join(lines)
