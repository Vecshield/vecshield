"""CLI entry point for the ASQ-PHI benchmark.

Usage::

    python -m benchmarks.asq_phi.run_asq_phi --mode regex
    python -m benchmarks.asq_phi.run_asq_phi --mode regex cascade nlp --max-samples 0

Outputs (under ``--output-dir``, default ``benchmarks/asq_phi/results``):

* ``asq_phi_<mode>.csv``                   — one row per (match_mode × entity_type).
* ``asq_phi_summary.md``                   — headline table across all modes.
* ``asq_phi_false_positives_<mode>.csv``   — FP counts per detector (over-redaction).

The dataset is fully synthetic and MIT-licensed; on first run the loader will
fetch ``synthetic_clinical_queries.txt`` from GitHub if it is not already
bundled under ``benchmarks/asq_phi/data/``.

Metric note: ASQ-PHI gold spans are all ``PHI`` (every HIPAA identifier type).
The ``partial`` column requires VecShield to *also* label the span ``PHI``; in
regex-only mode VecShield labels an email/phone/SSN ``PII``, so ``type_relaxed``
(category-ignored overlap) is the fairer view of raw span recall there. The NLP
modes apply VecShield's PHI-context upgrade and score well under ``partial``.
"""

from __future__ import annotations

import argparse
import csv
import datetime
import sys
from pathlib import Path

from benchmarks.asq_phi.normalize.asq_phi import (
    load_asq_phi,
    unmapped_labels,
    unresolved_values,
)
from benchmarks.asq_phi.runners import metrics as M
from benchmarks.asq_phi.runners.vecshield_runner import MODES, run_vecshield

DEFAULT_OUTPUT = Path("benchmarks/asq_phi/results")


def _write_csv(rows: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("")
        return
    with path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def _over_redaction(samples) -> dict:
    """Over-redaction on the hard negatives (gold-empty queries).

    ASQ's 219 hard negatives carry no HIPAA identifier by construction, so any
    prediction on them is an over-redaction. We report two rates: ``any`` counts
    a query flagged if it got *any* predicted span (the strict safe-handoff
    view, where even a PII age hit would trigger redaction) and ``phi`` counts
    only queries flagged with a ``PHI``-labelled span (the view that matches
    ASQ's PHI-only gold — a PII-only hit such as ``age_context`` is not a PHI
    false positive).
    """
    negs = [s for s in samples if not s.gold]
    n = len(negs)
    if n == 0:
        return {"n_neg": 0, "overred_any": 0.0, "overred_phi": 0.0}
    any_flag = sum(1 for s in negs if s.pred)
    phi_flag = sum(1 for s in negs if any(p.entity_type == "PHI" for p in s.pred))
    return {
        "n_neg": n,
        "overred_any": round(any_flag / n, 4),
        "overred_phi": round(phi_flag / n, 4),
    }


def _apply_min_score(samples, min_score: float) -> None:
    """Drop predicted spans scoring below ``min_score`` (document-decision knob)."""
    if min_score <= 0:
        return
    for s in samples:
        s.pred = [p for p in s.pred if p.score >= min_score]


def _row(
    results: list[M.MetricsResult], match_mode: str, entity: str
) -> M.MetricsResult:
    return next(
        r
        for r in results
        if r.match_mode == match_mode and r.entity_type == entity
    )


def _headline(results: list[M.MetricsResult], mode: str, overred: dict) -> dict:
    partial = _row(results, "partial", "ALL")
    relaxed = _row(results, "type_relaxed", "ALL")
    binary = _row(results, "binary_doc", "ALL")
    return {
        "mode": mode,
        "n_samples": partial.n_samples,
        "gold_spans": partial.n_gold_spans,
        "partial_P": partial.precision,
        "partial_R": partial.recall,
        "partial_F1": partial.f1,
        "relaxed_P": relaxed.precision,
        "relaxed_R": relaxed.recall,
        "relaxed_F1": relaxed.f1,
        "doc_P": binary.precision,
        "doc_R": binary.recall,
        "doc_F1": binary.f1,
        "doc_AUC": binary.roc_auc,
        "overred_any": overred["overred_any"],
        "overred_phi": overred["overred_phi"],
    }


def _write_summary_md(headlines: list[dict], meta: dict, path: Path) -> None:
    lines = [
        "# ASQ-PHI — VecShield Benchmark",
        "",
        "- Dataset: ASQ-PHI (Adversarial Synthetic Queries for PHI), "
        "`synthetic_clinical_queries.txt`",
        f"- Samples evaluated: {meta['n_samples']} "
        f"({meta['n_negatives']} hard negatives)",
        f"- Gold PHI spans: {meta['n_gold_spans']}",
        f"- Generated: {meta['timestamp']}",
        "",
        "## Headline results",
        "",
        "| Mode | Samples | Gold spans | Partial P | Partial R | Partial F1 "
        "| Relaxed P | Relaxed R | Relaxed F1 "
        "| Doc P | Doc R | Doc F1 | Doc AUC | OverRed any | OverRed PHI |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- "
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for h in headlines:
        lines.append(
            f"| {h['mode']} | {h['n_samples']} | {h['gold_spans']} "
            f"| {h['partial_P']} | {h['partial_R']} | {h['partial_F1']} "
            f"| {h['relaxed_P']} | {h['relaxed_R']} | {h['relaxed_F1']} "
            f"| {h['doc_P']} | {h['doc_R']} | {h['doc_F1']} | {h['doc_AUC']} "
            f"| {h['overred_any']} | {h['overred_phi']} |"
        )
    lines += [
        "",
        "*Partial = character-overlap span match **with** PHI-category "
        "agreement. Relaxed = overlap, category ignored (fairer for regex-only, "
        "which labels emails/phones/SSNs as PII not PHI). Doc = per-query 'any "
        "PHI?' classification. OverRed = fraction of the hard negatives flagged "
        "— `any` counts any predicted span, `PHI` counts only PHI-labelled "
        "predictions (age/other PII-only hits excluded, matching ASQ's PHI-only "
        "gold).*",
        "",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run VecShield against ASQ-PHI.")
    parser.add_argument(
        "--mode",
        nargs="+",
        choices=MODES,
        default=["regex"],
        help="VecShield mode(s) to evaluate (default: regex).",
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        default=0,
        help="Max samples to evaluate (0 = all 1,051 rows, the default).",
    )
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--min-score",
        type=float,
        default=0.0,
        help=(
            "Drop predicted spans scoring below this threshold before scoring "
            "(document-decision knob for trading recall against over-redaction; "
            "0 = keep all, the default)."
        ),
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=32,
        help="spaCy batch size for the NLP leg of nlp/cascade/ensemble modes.",
    )
    parser.add_argument(
        "--no-download",
        action="store_true",
        help="Fail instead of fetching the dataset if it is not present locally.",
    )
    args = parser.parse_args(argv)

    print("Loading ASQ-PHI ...")
    samples = load_asq_phi(
        max_samples=args.max_samples,
        download=not args.no_download,
        seed=args.seed,
    )
    if not samples:
        print("No samples loaded. Aborting.", file=sys.stderr)
        return 1

    n_gold = sum(len(s.gold) for s in samples)
    n_neg = sum(1 for s in samples if not s.gold)
    print(
        f"Loaded {len(samples)} samples ({n_neg} hard negatives) "
        f"with {n_gold} gold spans."
    )
    if unmapped_labels():
        print(f"Unmapped identifier types skipped: {unmapped_labels()}")
    if unresolved_values():
        print(f"Unresolved gold values dropped: {unresolved_values()}")

    meta = {
        "n_samples": len(samples),
        "n_negatives": n_neg,
        "n_gold_spans": n_gold,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(
            timespec="seconds"
        ),
    }

    headlines: list[dict] = []
    for mode in args.mode:
        print(f"\nRunning VecShield in '{mode}' mode ...")
        for s in samples:
            s.pred = []
        run_vecshield(samples, mode=mode, batch_size=args.batch_size)
        _apply_min_score(samples, args.min_score)

        overred = _over_redaction(samples)
        results = M.evaluate(samples, benchmark="asq_phi", mode=mode)
        _write_csv(
            [r.to_row() for r in results],
            args.output_dir / f"asq_phi_{mode}.csv",
        )
        fp_counts = M.false_positive_by_detector(samples)
        _write_csv(
            [{"detector": k, "false_positives": v} for k, v in fp_counts.items()],
            args.output_dir / f"asq_phi_false_positives_{mode}.csv",
        )
        headlines.append(_headline(results, mode, overred))

        head = headlines[-1]
        print(
            f"  [{mode}] partial F1={head['partial_F1']} "
            f"| relaxed F1={head['relaxed_F1']} "
            f"| doc F1={head['doc_F1']} | doc AUC={head['doc_AUC']} "
            f"| over-redaction any={head['overred_any']} "
            f"phi={head['overred_phi']}"
        )

    _write_summary_md(headlines, meta, args.output_dir / "asq_phi_summary.md")
    print(f"\nWrote results to {args.output_dir}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
