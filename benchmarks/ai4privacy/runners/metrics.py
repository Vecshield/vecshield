"""Detection metrics for the VecShield benchmark harness.

Given ``EvalSample`` objects whose ``gold`` and ``pred`` annotations are already
populated, compute the standard metrics used in PII/PHI/PCI detection papers:

* **exact**        — span boundaries *and* category must match.
* **partial**      — any character overlap *and* category match.
* **type_relaxed** — any character overlap, category ignored.
* **binary_doc**   — per-document "any sensitive data?" classification, plus
  ROC-AUC over the document confidence score.

For every match mode we also break results down per category
(``ALL`` / ``PII`` / ``PHI`` / ``PCI`` / ``SECRET``). Each combination yields one
:class:`MetricsResult` row.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from benchmarks.ai4privacy.normalize.schema import CATEGORIES, Annotation, EvalSample

SPAN_MATCH_MODES = ("exact", "partial", "type_relaxed")
ALL_MATCH_MODES = (*SPAN_MATCH_MODES, "binary_doc")
ENTITY_VIEWS = ("ALL", *CATEGORIES)


@dataclass
class MetricsResult:
    benchmark: str
    vecshield_mode: str  # "regex" | "nlp"
    match_mode: str  # exact | partial | type_relaxed | binary_doc
    entity_type: str  # ALL | PII | PHI | PCI | SECRET
    n_samples: int
    n_gold_spans: int
    n_pred_spans: int
    tp: int
    fp: int
    fn: int
    precision: float
    recall: float
    f1: float
    f05: float
    f2: float
    support: int = field(default=0)
    roc_auc: float | None = None

    def to_row(self) -> dict:
        return asdict(self)


# ── helpers ────────────────────────────────────────────────────────────────
def _fbeta(precision: float, recall: float, beta: float) -> float:
    if precision <= 0 and recall <= 0:
        return 0.0
    b2 = beta * beta
    denom = b2 * precision + recall
    if denom <= 0:
        return 0.0
    return (1 + b2) * precision * recall / denom


def _prf(tp: int, fp: int, fn: int) -> tuple[float, float, float, float, float]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = _fbeta(precision, recall, 1.0)
    f05 = _fbeta(precision, recall, 0.5)
    f2 = _fbeta(precision, recall, 2.0)
    return precision, recall, f1, f05, f2


def _filter(anns: list[Annotation], entity_type: str) -> list[Annotation]:
    if entity_type == "ALL":
        return list(anns)
    return [a for a in anns if a.entity_type == entity_type]


def dedup_overlapping(anns: list[Annotation]) -> list[Annotation]:
    """Drop overlapping predictions, keeping the highest-scoring span.

    Predictions from different detectors frequently cover the same characters;
    counting each as a separate hit would distort precision. Sort by score
    (desc) then keep a span only if it does not overlap an already-kept span.
    """
    kept: list[Annotation] = []
    for ann in sorted(anns, key=lambda a: (-a.score, a.start, a.end)):
        if any(ann.overlaps(k) for k in kept):
            continue
        kept.append(ann)
    return kept


# ── span matching ────────────────────────────────────────────────────────
def _match_spans(
    gold: list[Annotation],
    pred: list[Annotation],
    match_mode: str,
) -> tuple[int, int, int]:
    """Return (tp, fp, fn) for one sample under the given match mode.

    Greedy one-to-one matching: every gold and every predicted span is consumed
    at most once, so double-counting cannot inflate the score.
    """
    check_type = match_mode != "type_relaxed"

    def is_match(g: Annotation, p: Annotation) -> bool:
        if check_type and g.entity_type != p.entity_type:
            return False
        if match_mode == "exact":
            return g.start == p.start and g.end == p.end
        return g.overlaps(p)  # partial / type_relaxed

    used_pred: set[int] = set()
    tp = 0
    for g in gold:
        for j, p in enumerate(pred):
            if j in used_pred:
                continue
            if is_match(g, p):
                used_pred.add(j)
                tp += 1
                break
    fp = len(pred) - len(used_pred)
    fn = len(gold) - tp
    return tp, fp, fn


def _span_metrics(
    samples: list[EvalSample],
    match_mode: str,
    entity_type: str,
    *,
    benchmark: str,
    mode: str,
    dedup: bool,
) -> MetricsResult:
    tp = fp = fn = n_gold = n_pred = 0
    for s in samples:
        gold = _filter(s.gold, entity_type)
        pred = _filter(s.pred, entity_type)
        if dedup:
            pred = dedup_overlapping(pred)
        n_gold += len(gold)
        n_pred += len(pred)
        s_tp, s_fp, s_fn = _match_spans(gold, pred, match_mode)
        tp += s_tp
        fp += s_fp
        fn += s_fn
    precision, recall, f1, f05, f2 = _prf(tp, fp, fn)
    return MetricsResult(
        benchmark=benchmark,
        vecshield_mode=mode,
        match_mode=match_mode,
        entity_type=entity_type,
        n_samples=len(samples),
        n_gold_spans=n_gold,
        n_pred_spans=n_pred,
        tp=tp,
        fp=fp,
        fn=fn,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1=round(f1, 4),
        f05=round(f05, 4),
        f2=round(f2, 4),
        support=n_gold,
    )


# ── document-level binary classification ───────────────────────────────────
def _roc_auc(labels: list[int], scores: list[float]) -> float | None:
    """Rank-based ROC-AUC (Mann–Whitney). Returns None if only one class."""
    pos = [sc for lbl, sc in zip(labels, scores, strict=True) if lbl == 1]
    neg = [sc for lbl, sc in zip(labels, scores, strict=True) if lbl == 0]
    if not pos or not neg:
        return None
    ranked = sorted(zip(scores, labels, strict=True), key=lambda x: x[0])
    # Assign average ranks to handle ties.
    ranks = [0.0] * len(ranked)
    i = 0
    while i < len(ranked):
        j = i
        while j + 1 < len(ranked) and ranked[j + 1][0] == ranked[i][0]:
            j += 1
        avg_rank = (i + j) / 2.0 + 1.0  # ranks are 1-based
        for k in range(i, j + 1):
            ranks[k] = avg_rank
        i = j + 1
    sum_pos_ranks = sum(
        r for r, (_, lbl) in zip(ranks, ranked, strict=True) if lbl == 1
    )
    n_pos, n_neg = len(pos), len(neg)
    auc = (sum_pos_ranks - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)
    return round(auc, 4)


def _binary_doc_metrics(
    samples: list[EvalSample],
    entity_type: str,
    *,
    benchmark: str,
    mode: str,
) -> MetricsResult:
    def has(anns: list[Annotation]) -> bool:
        return len(_filter(anns, entity_type)) > 0

    tp = fp = fn = tn = 0
    labels: list[int] = []
    scores: list[float] = []
    for s in samples:
        gold_pos = has(s.gold)
        pred_pos = has(s.pred)
        if gold_pos and pred_pos:
            tp += 1
        elif not gold_pos and pred_pos:
            fp += 1
        elif gold_pos and not pred_pos:
            fn += 1
        else:
            tn += 1
        labels.append(1 if gold_pos else 0)
        filtered = _filter(s.pred, entity_type)
        scores.append(max((p.score for p in filtered), default=0.0))

    precision, recall, f1, f05, f2 = _prf(tp, fp, fn)
    return MetricsResult(
        benchmark=benchmark,
        vecshield_mode=mode,
        match_mode="binary_doc",
        entity_type=entity_type,
        n_samples=len(samples),
        n_gold_spans=sum(labels),
        n_pred_spans=tp + fp,
        tp=tp,
        fp=fp,
        fn=fn,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1=round(f1, 4),
        f05=round(f05, 4),
        f2=round(f2, 4),
        support=sum(labels),
        roc_auc=_roc_auc(labels, scores),
    )


# ── public entry point ──────────────────────────────────────────────────────
def evaluate(
    samples: list[EvalSample],
    *,
    benchmark: str,
    mode: str,
    match_modes: tuple[str, ...] = ALL_MATCH_MODES,
    entity_views: tuple[str, ...] = ENTITY_VIEWS,
    dedup: bool = True,
) -> list[MetricsResult]:
    """Compute every (match_mode × entity_view) MetricsResult for one run."""
    results: list[MetricsResult] = []
    for match_mode in match_modes:
        for entity_type in entity_views:
            if match_mode == "binary_doc":
                results.append(
                    _binary_doc_metrics(
                        samples, entity_type, benchmark=benchmark, mode=mode
                    )
                )
            else:
                results.append(
                    _span_metrics(
                        samples,
                        match_mode,
                        entity_type,
                        benchmark=benchmark,
                        mode=mode,
                        dedup=dedup,
                    )
                )
    return results


def false_positive_by_detector(samples: list[EvalSample]) -> dict[str, int]:
    """Count predicted spans (partial mode) that match no gold span, per detector.

    Useful for spotting noisy rules. A predicted span is a false positive when it
    does not overlap any gold span of the same category.
    """
    counts: dict[str, int] = {}
    for s in samples:
        pred = dedup_overlapping(s.pred)
        for p in pred:
            matched = any(
                p.entity_type == g.entity_type and p.overlaps(g) for g in s.gold
            )
            if not matched:
                key = p.subtype or "unknown"
                counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


def results_to_dataframe(results: list[MetricsResult]):
    """Return a tidy pandas DataFrame (imported lazily)."""
    import pandas as pd

    return pd.DataFrame([r.to_row() for r in results])
