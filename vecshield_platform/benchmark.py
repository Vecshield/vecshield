"""Measure the detectors against a labelled corpus, and report the failures.

What this produces is evidence about *the corpus*, and the report says so. The
rules it follows exist because a benchmark is easy to quote and hard to read:

* **No single headline number.** Results are per label and per detector. An
  aggregate would average a detector that is excellent at card numbers with one
  that is poor at prompt injection and hide both.
* **Intervals, not point estimates.** Forty items cannot support "94% precise".
  Every rate is reported with a Wilson interval, and a rate from fewer than
  five observations is reported as unmeasured rather than as a number.
* **Failures are part of the result**, in the same artifact, not an appendix.
* **Counter-signals are scored separately.** A detector that flags a published
  example *and says so* is behaving correctly; one that flags it silently is
  not. The two must not average together.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

import yaml

from vecshield.classify import Classifier
from vecshield_platform.detection import build_classifier
from vecshield_platform.explain import counter_signals

#: Below this many observations a rate is noise, and is reported as such.
MIN_OBSERVATIONS = 5


#: Which detector an item exercises. Asking the classifier about a prompt
#: injection and recording a false negative would measure the wrong thing: the
#: first draft of this harness did exactly that and reported 0% injection
#: recall for a detector it had never called.
FAMILIES = ("classification", "injection")


@dataclass(frozen=True)
class CorpusItem:
    """One labelled piece of text, and why it is labelled that way."""

    id: str
    text: str
    expect: str                      # "sensitive" | "clean"
    group: str = ""
    family: str = "classification"
    labels: list[str] = field(default_factory=list)
    disputed_by: list[str] = field(default_factory=list)
    collection: str = ""
    reason: str = ""
    decided_by: str = ""
    #: Items sharing a ``variant_of`` are rephrasings of one underlying case.
    #: They count as **one** observation, because forty wrappings of the same
    #: secret are forty chances to look right about one thing, not forty
    #: independent measurements. Defaults to the item's own id, so an item that
    #: declares nothing is its own case.
    variant_of: str = ""

    @property
    def case(self) -> str:
        return self.variant_of or self.id

    def __post_init__(self) -> None:
        if self.expect not in ("sensitive", "clean"):
            raise ValueError(f"{self.id}: expect must be 'sensitive' or 'clean'")
        if self.family not in FAMILIES:
            raise ValueError(f"{self.id}: unknown detector family {self.family!r}")
        if not self.reason:
            raise ValueError(f"{self.id}: every label carries the reason it was given")


def load_corpus(root: Path) -> list[CorpusItem]:
    """Read every corpus file except the manifest."""
    items: list[CorpusItem] = []
    seen: set[str] = set()
    for path in sorted(Path(root).glob("*.yaml")):
        if path.name == "manifest.yaml":
            continue
        document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        # A file may declare the detector family once for all of its items.
        default_family = document.get("family", "classification")
        for raw in document.get("items", []):
            item = CorpusItem(group=path.stem,
                              **{"family": default_family, **raw})
            if item.id in seen:
                raise ValueError(f"duplicate corpus id: {item.id}")
            seen.add(item.id)
            items.append(item)
    if not items:
        raise ValueError(f"no corpus items under {root}")
    return items


def wilson(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """A Wilson interval, which stays sensible at small n and at 0% or 100%."""
    if total <= 0:
        return (0.0, 1.0)
    p = successes / total
    denominator = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denominator
    spread = (z / denominator) * math.sqrt(
        p * (1 - p) / total + z * z / (4 * total * total))
    return (max(0.0, centre - spread), min(1.0, centre + spread))


def rate(successes: int, total: int) -> dict[str, Any]:
    """A rate with its interval, or an honest refusal to state one."""
    if total < MIN_OBSERVATIONS:
        return {"observations": total, "measured": False,
                "note": f"Fewer than {MIN_OBSERVATIONS} observations; no rate is reported."}
    low, high = wilson(successes, total)
    return {"observations": total, "measured": True,
            "value": round(successes / total, 3),
            "interval": [round(low, 3), round(high, 3)],
            "successes": successes}


@dataclass
class ItemResult:
    """What the detectors did with one item, and whether that was right."""

    item: CorpusItem
    flagged: bool
    labels: list[str]
    detectors: list[str]
    signals: list[str]
    outcome: str                     # true_positive | false_positive | ...
    missing_counter_signals: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.item.id, "group": self.item.group,
            "expect": self.item.expect, "outcome": self.outcome,
            "flagged": self.flagged, "labels": self.labels,
            "detectors": self.detectors, "counter_signals": self.signals,
            "missing_counter_signals": self.missing_counter_signals,
            "reason": self.item.reason,
        }


def evaluate_item(item: CorpusItem, classifier: Classifier) -> ItemResult:
    """Run the detector that owns this item, and judge the outcome.

    Routing matters: the content classifier knows nothing about prompt
    injection, and the injection scanner knows nothing about card numbers.
    Asking the wrong one produces a number that looks like a measurement.
    """
    if item.family == "injection":
        from vecshield_platform.integrity.injection import scan_text

        result = scan_text(item.text)
        spans = list(getattr(result, "spans", []) or [])
        # The scanner's own threshold: a supporting phrase that is recorded
        # but never reported must not count as a detection here either.
        flagged = bool(result.is_injection)
        labels = sorted({"injection"} if flagged else set())
        # Categories recorded on an unreported chunk did not fire: crediting
        # them would charge a supporting phrase with a false positive the
        # scanner never raised.
        detectors = sorted({str(c) for c in getattr(result, "categories", []) or []}
                           if flagged else set())
    else:
        result = classifier.classify(item.text)
        spans = list(result.spans or [])
        flagged = bool(result.is_sensitive)
        labels = sorted({str(s.get("label")) for s in spans if s.get("label")}
                        or ({result.label.value} if flagged else set()))
        detectors = sorted(set(result.detectors or []))

    signals = sorted({
        signal.code
        for span in spans
        for signal in counter_signals(
            item.text[span["start"]:span["end"]]
            if isinstance(span.get("start"), int) and isinstance(span.get("end"), int)
            else "",
            text=item.text, collection=item.collection)
    })

    if flagged and item.expect == "sensitive":
        outcome = "true_positive"
    elif flagged and item.expect == "clean":
        outcome = "false_positive"
    elif not flagged and item.expect == "sensitive":
        outcome = "false_negative"
    else:
        outcome = "true_negative"

    # A detector that flags a published example *and says so* is behaving
    # correctly. One that flags it silently is the thing that erodes trust.
    missing = [expected for expected in item.disputed_by if expected not in signals]
    return ItemResult(item=item, flagged=flagged, labels=labels, detectors=detectors,
                      signals=signals, outcome=outcome, missing_counter_signals=missing)


def run(corpus: Iterable[CorpusItem], classifier: Optional[Classifier] = None) -> dict[str, Any]:
    """Score the corpus and report per group, per label, and per detector."""
    classifier = classifier or build_classifier()
    results = [evaluate_item(item, classifier) for item in corpus]

    def score(subset: list[ItemResult]) -> dict[str, Any]:
        tp = sum(1 for r in subset if r.outcome == "true_positive")
        fp = sum(1 for r in subset if r.outcome == "false_positive")
        fn = sum(1 for r in subset if r.outcome == "false_negative")
        tn = sum(1 for r in subset if r.outcome == "true_negative")
        return {
            "items": len(subset),
            "true_positive": tp, "false_positive": fp,
            "false_negative": fn, "true_negative": tn,
            "precision": rate(tp, tp + fp),
            "recall": rate(tp, tp + fn),
        }

    groups = sorted({r.item.group for r in results})
    by_group = {g: score([r for r in results if r.item.group == g]) for g in groups}

    families = sorted({r.item.family for r in results})
    by_family = {f: score([r for r in results if r.item.family == f]) for f in families}

    # Per detector, because a confidence class is a claim about one detector.
    # "The classifier is 92% precise" tells you nothing about whether to
    # believe the card-number detector specifically.
    detectors = sorted({d for r in results for d in r.detectors})
    by_detector = {}
    for detector in detectors:
        fired = [r for r in results if detector in r.detectors]
        # Counted over cases, not items. A case counts as a false positive if
        # *any* of its variants is one: a detector that fires wrongly on one
        # phrasing of a case is wrong about that case, and averaging across the
        # phrasings would buy back the error with near-duplicates.
        cases: dict[str, bool] = {}
        for result in fired:
            wrong = result.item.expect == "clean"
            cases[result.item.case] = cases.get(result.item.case, False) or wrong
        tp = sum(1 for wrong in cases.values() if not wrong)
        fp = sum(1 for wrong in cases.values() if wrong)
        by_detector[detector] = {
            "fired_on": len(fired), "cases": len(cases),
            "true_positive": tp, "false_positive": fp,
            "precision": rate(tp, tp + fp),
        }

    labels = sorted({label for r in results for label in r.item.labels})
    by_label = {}
    for label in labels:
        expected = [r for r in results if label in r.item.labels]
        caught = sum(1 for r in expected if label in r.labels)
        by_label[label] = {
            "expected": len(expected),
            "detected_as_this_label": caught,
            "label_recall": rate(caught, len(expected)),
        }

    # Counter-signals scored on their own: did the detector say what argues
    # against its own finding?
    disputed = [r for r in results if r.item.disputed_by]
    explained = [r for r in disputed if not r.missing_counter_signals]
    counter_signal_score = {
        "items_needing_a_counter_signal": len(disputed),
        "explained": len(explained),
        "coverage": rate(len(explained), len(disputed)),
        "unexplained": [r.item.id for r in disputed if r.missing_counter_signals],
    }

    failures = [r.to_dict() for r in results
                if r.outcome in ("false_positive", "false_negative")
                or r.missing_counter_signals]

    return {
        "items": len(results),
        "overall_note": (
            "Scores are reported per group, per label, and per detector. There is "
            "no single number: an aggregate would average unlike detectors and "
            "hide the one that matters."),
        "by_group": by_group,
        "by_family": by_family,
        "by_detector": by_detector,
        "by_label": by_label,
        "counter_signals": counter_signal_score,
        "failures": failures,
        "results": [r.to_dict() for r in results],
    }


def compare(baseline: dict[str, Any], candidate: dict[str, Any],
            *, tolerance: float = 0.0) -> dict[str, Any]:
    """Regressions between two runs, per group.

    A drop beyond ``tolerance`` in precision or recall is a regression, and a
    group that stops being measured at all is also a regression — losing the
    measurement is not an improvement.
    """
    regressions: list[dict[str, Any]] = []
    improvements: list[dict[str, Any]] = []
    for group, before in (baseline.get("by_group") or {}).items():
        after = (candidate.get("by_group") or {}).get(group)
        if after is None:
            regressions.append({"group": group, "metric": "presence",
                                "detail": "the candidate does not measure this group"})
            continue
        for metric in ("precision", "recall"):
            old, new = before.get(metric, {}), after.get(metric, {})
            if not old.get("measured"):
                continue
            if not new.get("measured"):
                regressions.append({"group": group, "metric": metric,
                                    "detail": "no longer measured"})
                continue
            delta = round(new["value"] - old["value"], 3)
            if delta < -tolerance:
                regressions.append({"group": group, "metric": metric,
                                    "before": old["value"], "after": new["value"],
                                    "delta": delta})
            elif delta > 0:
                improvements.append({"group": group, "metric": metric, "delta": delta})
    return {"regressions": regressions, "improvements": improvements,
            "ok": not regressions}


def format_report(results: dict[str, Any], *, manifest: Optional[dict[str, Any]] = None) -> str:
    """A plain-text report that leads with the limitations and the failures.

    Deliberately not a dashboard: a benchmark result is most often pasted into
    a review, and what belongs at the top is what the number does not cover.
    """
    lines: list[str] = ["VecShield detector benchmark", "=" * 30, ""]

    if manifest:
        lines += ["What this corpus is not", "-" * 23]
        lines += [f"  - {limit}" for limit in manifest.get("limitations", [])]
        if manifest.get("not_a_claim"):
            lines += ["", f"  {' '.join(manifest['not_a_claim'].split())}"]
        lines.append("")

    lines += [f"Items: {results['items']}", "",
              "By detector family", "-" * 18]
    for family, score in (results.get("by_family") or {}).items():
        lines.append(f"  {family}")
        for metric in ("precision", "recall"):
            value = score[metric]
            if value.get("measured"):
                low, high = value["interval"]
                lines.append(f"    {metric:10} {value['value']:.3f}  "
                             f"[{low:.3f}, {high:.3f}]  n={value['observations']}")
            else:
                lines.append(f"    {metric:10} not reported — {value['note']}")
        lines.append(f"    counts     tp={score['true_positive']} fp={score['false_positive']} "
                     f"fn={score['false_negative']} tn={score['true_negative']}")
    lines.append("")

    signals = results.get("counter_signals") or {}
    lines += ["Counter-signals", "-" * 15,
              f"  {signals.get('explained', 0)} of "
              f"{signals.get('items_needing_a_counter_signal', 0)} items that need a "
              "counter-signal received one."]
    if signals.get("unexplained"):
        lines.append(f"  Unexplained: {', '.join(signals['unexplained'])}")
    lines.append("")

    failures = results.get("failures") or []
    lines += [f"Failures ({len(failures)})", "-" * 20]
    if not failures:
        lines.append("  None.")
    for failure in failures:
        lines.append(f"  {failure['outcome']:15} {failure['id']}")
        lines.append(f"      {' '.join(failure['reason'].split())}")
        if failure.get("missing_counter_signals"):
            lines.append(f"      missing counter-signals: "
                         f"{', '.join(failure['missing_counter_signals'])}")
    lines += ["", results["overall_note"]]
    return "\n".join(lines)


def load_manifest(root: Path) -> dict[str, Any]:
    path = Path(root) / "manifest.yaml"
    return yaml.safe_load(path.read_text()) if path.exists() else {}


#: A detector may claim a class only when the *lower bound* of its measured
#: precision clears the threshold. Using the point estimate would let a
#: flattering small sample buy a confident label; using the lower bound means
#: the claim is what the evidence supports at its worst reading.
CONFIDENCE_THRESHOLDS = (("likely", 0.90), ("possible", 0.50))


def calibration(results: dict[str, Any]) -> dict[str, Any]:
    """Which confidence class each detector has earned, and why.

    A detector with too few observations earns nothing. This is expected on a
    small corpus, and the right outcome: the alternative is a system that
    upgrades its own confidence on the strength of a dozen examples.
    """
    earned: dict[str, dict[str, Any]] = {}
    for detector, score in (results.get("by_detector") or {}).items():
        precision = score.get("precision", {})
        if not precision.get("measured"):
            earned[detector] = {
                "class": "uncertain",
                "reason": (f"Only {precision.get('observations', 0)} independent case(s); "
                           "too few to measure a precision."),
            }
            continue
        low, _high = precision["interval"]
        claim = next((name for name, floor in CONFIDENCE_THRESHOLDS if low >= floor), None)
        if claim is None:
            earned[detector] = {
                "class": "uncertain",
                "reason": (f"Measured precision {precision['value']} but its interval "
                           f"reaches down to {low}, below the {CONFIDENCE_THRESHOLDS[-1][1]} "
                           "floor for any claim."),
                "precision": precision,
            }
        else:
            earned[detector] = {
                "class": claim,
                "reason": (f"Precision {precision['value']} with a lower bound of {low}, "
                           f"at or above the {dict(CONFIDENCE_THRESHOLDS)[claim]} floor "
                           f"for '{claim}'."),
                "precision": precision,
            }
    return {
        "thresholds": dict(CONFIDENCE_THRESHOLDS),
        "detectors": earned,
        "note": ("A class is earned from the lower bound of a measured precision, "
                 "not its point estimate. A detector that has earned nothing "
                 "reports 'uncertain' and says why."),
    }
