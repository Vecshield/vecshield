"""Detection ablation on ai4privacy: spaCy model × detection strategy.

The ablation is the **product** of two axes:

* **Model** (NER backbone): ``en_core_web_sm`` · ``en_core_web_md`` ·
  ``en_core_web_lg``. Larger = better NER, slower on CPU.
* **Mode** (detection strategy):
    - ``regex``   — ``RegexClassifier`` only (model-independent baseline).
    - ``cascade`` — regex first; run the spaCy pass **only** on documents where
      regex found nothing (regex-miss fallback).
    - ``nlp``     — ``PresidioClassifier`` alone (pure NLP, no regex).

For each of the (models × modes) cells we record accuracy (partial-span P/R/F1
and per-document P/R/F1/AUC) and cost (wall-clock seconds, docs/sec, and the
number of documents that actually reached the spaCy pass).

Outputs (under ``--output-dir``, default ``benchmarks/ai4privacy/results``):

* ``ablation.csv``         — one row per (model, mode): accuracy + timing.
* ``ablation_detail.csv``  — every metric row (match_mode × entity_type) per cell.
* ``ablation_summary.md``  — pivot grids (Doc AUC / Doc F1 / throughput) + table.

Usage::

    PYTHONHASHSEED=0 python -m benchmarks.ai4privacy.run_ablation --max-samples 5000
    PYTHONHASHSEED=0 python -m benchmarks.ai4privacy.run_ablation --max-samples 0
    PYTHONHASHSEED=0 python -m benchmarks.ai4privacy.run_ablation --models sm lg \\
        --modes regex nlp
"""

from __future__ import annotations

import argparse
import datetime
import sys
import time
from pathlib import Path

from benchmarks.ai4privacy.normalize.ai4privacy import load_ai4privacy, unmapped_labels
from benchmarks.ai4privacy.run_ai4privacy import _headline, _write_csv
from benchmarks.ai4privacy.runners import metrics as M
from benchmarks.ai4privacy.runners.vecshield_runner import run_vecshield

DEFAULT_OUTPUT = Path("benchmarks/ai4privacy/results")

# Model axis. Short aliases map to the full spaCy package names.
_MODEL_ALIAS = {
    "sm": "en_core_web_sm",
    "md": "en_core_web_md",
    "lg": "en_core_web_lg",
}
_SHORT = {v: k for k, v in _MODEL_ALIAS.items()}
ALL_MODELS = ("en_core_web_sm", "en_core_web_md", "en_core_web_lg")
ALL_MODES = ("regex", "cascade", "nlp")


def _reset(samples) -> None:
    for s in samples:
        s.pred = []


def _short(model: str) -> str:
    return _SHORT.get(model, model)


def _cell_row(
    head: dict, *, model: str, mode: str, seconds: float, nlp_calls: int
) -> dict:
    """Flatten a headline + timing into one ablation.csv row."""
    n = head["n_samples"] or 1
    return {
        "model": _short(model),
        "mode": mode,
        "n_samples": head["n_samples"],
        "gold_spans": head["gold_spans"],
        "partial_P": head["partial_P"],
        "partial_R": head["partial_R"],
        "partial_F1": head["partial_F1"],
        "doc_P": head["doc_P"],
        "doc_R": head["doc_R"],
        "doc_F1": head["doc_F1"],
        "doc_AUC": head["doc_AUC"],
        "nlp_calls": nlp_calls,
        "wall_s": round(seconds, 2),
        "docs_per_s": round(n / seconds, 1) if seconds > 0 else 0.0,
    }


def _detail_rows(results, *, model: str) -> list[dict]:
    rows = []
    for r in results:
        rows.append({"model": _short(model), **r.to_row()})
    return rows


def _grid(
    rows: list[dict], metric: str, models: list[str], modes: list[str]
) -> list[str]:
    """Pivot table: rows = model, columns = mode, cells = ``metric``."""
    by_key = {(r["model"], r["mode"]): r for r in rows}
    header = "| Model | " + " | ".join(modes) + " |"
    sep = "| --- | " + " | ".join(["---"] * len(modes)) + " |"
    lines = [header, sep]
    for model in models:
        short = _short(model)
        cells = []
        for mode in modes:
            r = by_key.get((short, mode))
            cells.append("—" if r is None else str(r.get(metric, "—")))
        lines.append(f"| {short} | " + " | ".join(cells) + " |")
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="3×3 detection ablation (spaCy model × mode) on ai4privacy."
    )
    parser.add_argument(
        "--models",
        nargs="+",
        default=list(ALL_MODELS),
        help="spaCy models (full name or sm/md/lg). Default: sm md lg.",
    )
    parser.add_argument(
        "--modes",
        nargs="+",
        choices=ALL_MODES,
        default=list(ALL_MODES),
        help="Detection modes. Default: regex cascade nlp.",
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
    parser.add_argument(
        "--batch-size",
        type=int,
        default=1,
        help=(
            "spaCy nlp.pipe batch size for the NLP leg (cascade/nlp). >1 enables "
            "batched inference (B1) — a ~1.7x CPU speedup, identical results. "
            "Default 1 (per-document, reproduces the original ablation)."
        ),
    )
    parser.add_argument(
        "--min-nlp-chars",
        type=int,
        default=0,
        help=(
            "In cascade mode, skip the NLP leg for regex-miss docs shorter than "
            "this many characters (B2). Default 0 (disabled)."
        ),
    )
    args = parser.parse_args(argv)

    models = [_MODEL_ALIAS.get(m, m) for m in args.models]
    modes = list(args.modes)
    nlp_modes = [m for m in modes if m in ("cascade", "nlp")]

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

    ablation_rows: list[dict] = []
    detail_rows: list[dict] = []
    notes: list[str] = []

    # ── regex is model-independent: compute once, reuse for every model row ──
    regex_head: dict | None = None
    regex_seconds = 0.0
    regex_miss = 0  # documents where regex found nothing → cascade NLP calls
    if "regex" in modes:
        print("\n[regex] running once (model-independent) ...")
        _reset(samples)
        t0 = time.perf_counter()
        run_vecshield(samples, mode="regex", progress_every=0)
        regex_seconds = time.perf_counter() - t0
        regex_miss = sum(1 for s in samples if not s.pred)
        regex_results = M.evaluate(samples, benchmark="ai4privacy", mode="regex")
        regex_head = _headline(regex_results, "regex")
        print(
            f"  regex: partial F1={regex_head['partial_F1']} "
            f"| doc F1={regex_head['doc_F1']} | doc AUC={regex_head['doc_AUC']} "
            f"| {regex_seconds:.1f}s | regex-miss docs={regex_miss}"
        )
    elif "cascade" in modes:
        # Need the regex-miss count even if the regex row itself isn't requested.
        _reset(samples)
        run_vecshield(samples, mode="regex", progress_every=0)
        regex_miss = sum(1 for s in samples if not s.pred)

    # ── model axis: build each spaCy model once, reuse for cascade + nlp ──
    for model in models:
        nlp_clf = None
        if nlp_modes:
            print(f"\n=== model: {model} ===")
            try:
                from vecshield.classify.presidio_classifier import PresidioClassifier

                t0 = time.perf_counter()
                nlp_clf = PresidioClassifier(model=model)
                print(f"  loaded {model} in {time.perf_counter() - t0:.1f}s")
            except Exception as exc:  # model not installed / load failure
                msg = f"could not load {model}: {exc}"
                print(f"  !! {msg}; skipping its NLP modes", file=sys.stderr)
                notes.append(msg)

        # regex row (identical numbers across models; timing is the single run)
        if regex_head is not None:
            ablation_rows.append(
                _cell_row(
                    regex_head,
                    model=model,
                    mode="regex",
                    seconds=regex_seconds,
                    nlp_calls=0,
                )
            )

        for mode in nlp_modes:
            if nlp_clf is None:
                continue
            print(f"[{_short(model)}/{mode}] running ...")
            _reset(samples)
            t0 = time.perf_counter()
            run_vecshield(
                samples,
                mode=mode,
                model=model,
                nlp_classifier=nlp_clf,
                progress_every=0,
                batch_size=args.batch_size,
                min_nlp_chars=args.min_nlp_chars,
            )
            seconds = time.perf_counter() - t0
            results = M.evaluate(samples, benchmark="ai4privacy", mode=mode)
            head = _headline(results, mode)
            nlp_calls = regex_miss if mode == "cascade" else len(samples)
            ablation_rows.append(
                _cell_row(
                    head, model=model, mode=mode, seconds=seconds, nlp_calls=nlp_calls
                )
            )
            detail_rows.extend(_detail_rows(results, model=model))
            print(
                f"  {_short(model)}/{mode}: partial F1={head['partial_F1']} "
                f"| doc F1={head['doc_F1']} | doc AUC={head['doc_AUC']} "
                f"| {seconds:.1f}s ({ablation_rows[-1]['docs_per_s']} docs/s)"
            )

    # regex detail rows (once, model-independent) appended for completeness.
    if regex_head is not None:
        detail_rows = _detail_rows(regex_results, model="—") + detail_rows

    # ── write outputs ──
    args.output_dir.mkdir(parents=True, exist_ok=True)
    _write_csv(ablation_rows, args.output_dir / "ablation.csv")
    _write_csv(detail_rows, args.output_dir / "ablation_detail.csv")

    meta = {
        "split": args.split,
        "n_samples": len(samples),
        "n_gold_spans": n_gold,
        "regex_miss": regex_miss,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(
            timespec="seconds"
        ),
    }
    _write_summary_md(
        ablation_rows,
        meta,
        models,
        modes,
        notes,
        args.output_dir / "ablation_summary.md",
    )
    print(
        f"\nWrote ablation.csv, ablation_detail.csv, ablation_summary.md "
        f"to {args.output_dir}"
    )
    return 0


def _write_summary_md(
    rows: list[dict],
    meta: dict,
    models: list[str],
    modes: list[str],
    notes: list[str],
    path: Path,
) -> None:
    lines = [
        "# ai4privacy — Detection Ablation (model × mode)",
        "",
        f"- Dataset: `ai4privacy/pii-masking-200k` (split: `{meta['split']}`)",
        f"- Samples evaluated: {meta['n_samples']}",
        f"- Gold spans: {meta['n_gold_spans']}",
        f"- Regex-miss documents (cascade NLP calls): {meta['regex_miss']}",
        f"- Generated: {meta['timestamp']}",
        "",
        "Models: `sm`=en_core_web_sm · `md`=en_core_web_md · `lg`=en_core_web_lg.  ",
        "Modes: `regex` (baseline, model-independent) · `cascade` "
        "(regex→NLP on misses) · `nlp` (NLP only).",
        "",
        "## Doc AUC (per-document ranking quality)",
        "",
    ]
    lines += _grid(rows, "doc_AUC", models, modes)
    lines += ["", "## Doc F1 (per-document detection)", ""]
    lines += _grid(rows, "doc_F1", models, modes)
    lines += ["", "## Doc recall", ""]
    lines += _grid(rows, "doc_R", models, modes)
    lines += ["", "## Partial-span F1", ""]
    lines += _grid(rows, "partial_F1", models, modes)
    lines += ["", "## Throughput (docs/sec)", ""]
    lines += _grid(rows, "docs_per_s", models, modes)

    lines += [
        "",
        "## Full results",
        "",
        "| Model | Mode | Partial P | Partial R | Partial F1 | Doc P | Doc R "
        "| Doc F1 | Doc AUC | NLP calls | Wall s | Docs/s |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in rows:
        lines.append(
            f"| {r['model']} | {r['mode']} | {r['partial_P']} | {r['partial_R']} "
            f"| {r['partial_F1']} | {r['doc_P']} | {r['doc_R']} | {r['doc_F1']} "
            f"| {r['doc_AUC']} | {r['nlp_calls']} | {r['wall_s']} | {r['docs_per_s']} |"
        )
    lines += [
        "",
        "*Partial = character-overlap span match with category agreement. "
        "Doc = per-document 'any sensitive data?' classification. `regex` rows "
        "are identical across models (regex does not use spaCy).*",
    ]
    if notes:
        lines += ["", "### Notes", ""]
        lines += [f"- {n}" for n in notes]
    lines.append("")
    path.write_text("\n".join(lines))


if __name__ == "__main__":
    raise SystemExit(main())
