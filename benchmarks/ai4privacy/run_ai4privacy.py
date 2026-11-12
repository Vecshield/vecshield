"""CLI entry point for the ai4privacy PII-masking benchmark.

Usage::

    python -m benchmarks.ai4privacy.run_ai4privacy --mode regex --max-samples 2000
    python -m benchmarks.ai4privacy.run_ai4privacy --mode regex nlp --max-samples 5000

Outputs (under ``--output-dir``, default ``benchmarks/ai4privacy/results``):

* ``ai4privacy_<mode>.csv``     — one row per (match_mode × entity_type).
* ``ai4privacy_summary.md``     — headline table across all requested modes.
* ``ai4privacy_false_positives_<mode>.csv`` — FP counts per detector.
"""

from __future__ import annotations

import argparse
import csv
import datetime
import sys
from pathlib import Path

from benchmarks.ai4privacy.normalize.ai4privacy import load_ai4privacy, unmapped_labels
from benchmarks.ai4privacy.runners import metrics as M
from benchmarks.ai4privacy.runners.vecshield_runner import MODES, run_vecshield

DEFAULT_OUTPUT = Path("benchmarks/ai4privacy/results")


def _write_csv(rows: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("")
        return
    with path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def _headline(results: list[M.MetricsResult], mode: str) -> dict:
    """Pick the ALL/partial and binary_doc rows for the summary table."""
    partial = next(
        r for r in results if r.match_mode == "partial" and r.entity_type == "ALL"
    )
    binary = next(
        r for r in results if r.match_mode == "binary_doc" and r.entity_type == "ALL"
    )
    return {
        "mode": mode,
        "n_samples": partial.n_samples,
        "gold_spans": partial.n_gold_spans,
        "partial_P": partial.precision,
        "partial_R": partial.recall,
        "partial_F1": partial.f1,
        "doc_P": binary.precision,
        "doc_R": binary.recall,
        "doc_F1": binary.f1,
        "doc_AUC": binary.roc_auc,
    }


def _write_summary_md(headlines: list[dict], meta: dict, path: Path) -> None:
    lines = [
        "# ai4privacy/pii-masking-200k — VecShield Benchmark",
        "",
        f"- Dataset: `ai4privacy/pii-masking-200k` (split: `{meta['split']}`)",
        f"- Samples evaluated: {meta['n_samples']}",
        f"- Gold spans: {meta['n_gold_spans']}",
        f"- Generated: {meta['timestamp']}",
        "",
        "## Headline results",
        "",
        "| Mode | Samples | Gold spans | Partial P | Partial R | Partial F1 "
        "| Doc P | Doc R | Doc F1 | Doc AUC |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for h in headlines:
        lines.append(
            f"| {h['mode']} | {h['n_samples']} | {h['gold_spans']} "
            f"| {h['partial_P']} | {h['partial_R']} | {h['partial_F1']} "
            f"| {h['doc_P']} | {h['doc_R']} | {h['doc_F1']} | {h['doc_AUC']} |"
        )
    lines += [
        "",
        "*Partial = character-overlap span match with category agreement. "
        "Doc = per-document 'any sensitive data?' classification.*",
        "",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run VecShield against ai4privacy/pii-masking-200k."
    )
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
        default=5000,
        help="Max samples to evaluate (0 = all). Default 5000.",
    )
    parser.add_argument("--split", default="validation")
    parser.add_argument(
        "--all-languages",
        action="store_true",
        help="Keep non-English rows (default: English only).",
    )
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)

    print(f"Loading {args.split} split of ai4privacy/pii-masking-200k ...")
    samples = load_ai4privacy(
        max_samples=args.max_samples,
        split=args.split,
        english_only=not args.all_languages,
        seed=args.seed,
    )
    if not samples:
        print("No samples loaded (dataset unavailable?). Aborting.", file=sys.stderr)
        return 1

    n_gold = sum(len(s.gold) for s in samples)
    print(f"Loaded {len(samples)} samples with {n_gold} gold spans.")
    if unmapped_labels():
        print(f"Unmapped labels skipped: {unmapped_labels()}")

    meta = {
        "split": args.split,
        "n_samples": len(samples),
        "n_gold_spans": n_gold,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(
            timespec="seconds"
        ),
    }

    headlines: list[dict] = []
    for mode in args.mode:
        print(f"\nRunning VecShield in '{mode}' mode ...")
        # Reset predictions between modes so runs are independent.
        for s in samples:
            s.pred = []
        run_vecshield(samples, mode=mode)

        results = M.evaluate(samples, benchmark="ai4privacy", mode=mode)
        _write_csv(
            [r.to_row() for r in results],
            args.output_dir / f"ai4privacy_{mode}.csv",
        )
        fp_counts = M.false_positive_by_detector(samples)
        _write_csv(
            [{"detector": k, "false_positives": v} for k, v in fp_counts.items()],
            args.output_dir / f"ai4privacy_false_positives_{mode}.csv",
        )
        headlines.append(_headline(results, mode))

        head = headlines[-1]
        print(
            f"  [{mode}] partial F1={head['partial_F1']} "
            f"| doc F1={head['doc_F1']} | doc AUC={head['doc_AUC']}"
        )

    _write_summary_md(headlines, meta, args.output_dir / "ai4privacy_summary.md")
    print(f"\nWrote results to {args.output_dir}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
