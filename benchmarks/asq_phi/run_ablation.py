"""Detection ablation on ASQ-PHI: spaCy model × detection strategy.

The ablation is the **product** of two axes:

* **Model** (NER backbone): ``en_core_web_sm`` · ``en_core_web_md`` ·
  ``en_core_web_lg``. Larger = better NER, slower on CPU.
* **Mode** (detection strategy):
    - ``regex``    — ``RegexClassifier`` only (model-independent baseline).
    - ``cascade``  — regex first; spaCy pass **only** on regex-miss docs.
    - ``nlp``      — ``PresidioClassifier`` alone (pure NLP, no regex).
    - ``ensemble`` — regex **∪** NLP on every doc (the shipped pipeline).

Per (model × mode) cell we record span accuracy (partial + relaxed P/R/F1),
per-document accuracy (P/R/F1/AUC), the **over-redaction** rate on the 219 hard
negatives (``any`` and ``PHI``-labelled), and cost (wall-clock, docs/sec).

Outputs (under ``--output-dir``, default ``benchmarks/asq_phi/results``):

* ``ablation.csv``          — one row per (model, mode): accuracy + over-redaction.
* ``ablation_detail.csv``   — every metric row (match_mode × entity_type) per cell.
* ``ablation_by_subtype.csv`` — relaxed recall per HIPAA identifier type.
* ``ablation_summary.md``   — pivot grids + full table + per-subtype recall.

Usage::

    PYTHONHASHSEED=0 python -m benchmarks.asq_phi.run_ablation
    PYTHONHASHSEED=0 python -m benchmarks.asq_phi.run_ablation \\
        --models sm lg --modes regex ensemble
"""

from __future__ import annotations

import argparse
import datetime
import sys
import time
from collections import Counter
from pathlib import Path

from benchmarks.asq_phi.normalize.asq_phi import load_asq_phi, unresolved_values
from benchmarks.asq_phi.run_asq_phi import _headline, _over_redaction, _write_csv
from benchmarks.asq_phi.runners import metrics as M
from benchmarks.asq_phi.runners.vecshield_runner import run_vecshield

DEFAULT_OUTPUT = Path("benchmarks/asq_phi/results")

_MODEL_ALIAS = {
    "sm": "en_core_web_sm",
    "md": "en_core_web_md",
    "lg": "en_core_web_lg",
}
_SHORT = {v: k for k, v in _MODEL_ALIAS.items()}
ALL_MODELS = ("en_core_web_sm", "en_core_web_md", "en_core_web_lg")
ALL_MODES = ("regex", "cascade", "nlp", "ensemble")

# The single cell whose per-subtype recall is written out (best operating point).
HEADLINE_MODEL = "en_core_web_lg"
HEADLINE_MODE = "ensemble"


def _reset(samples) -> None:
    for s in samples:
        s.pred = []


def _short(model: str) -> str:
    return _SHORT.get(model, model)


def _cell_row(
    head: dict, *, model: str, mode: str, seconds: float, nlp_calls: int
) -> dict:
    n = head["n_samples"] or 1
    return {
        "model": _short(model),
        "mode": mode,
        "n_samples": head["n_samples"],
        "gold_spans": head["gold_spans"],
        "partial_P": head["partial_P"],
        "partial_R": head["partial_R"],
        "partial_F1": head["partial_F1"],
        "relaxed_P": head["relaxed_P"],
        "relaxed_R": head["relaxed_R"],
        "relaxed_F1": head["relaxed_F1"],
        "doc_P": head["doc_P"],
        "doc_R": head["doc_R"],
        "doc_F1": head["doc_F1"],
        "doc_AUC": head["doc_AUC"],
        "overred_any": head["overred_any"],
        "overred_phi": head["overred_phi"],
        "nlp_calls": nlp_calls,
        "wall_s": round(seconds, 2),
        "docs_per_s": round(n / seconds, 1) if seconds > 0 else 0.0,
    }


def _subtype_recall(samples) -> list[dict]:
    """Relaxed (category-ignored) recall per gold HIPAA identifier subtype."""
    gold: Counter[str] = Counter()
    hit: Counter[str] = Counter()
    for s in samples:
        for g in s.gold:
            gold[g.subtype] += 1
            if any(p.start < g.end and p.end > g.start for p in s.pred):
                hit[g.subtype] += 1
    rows = []
    for sub, n in gold.most_common():
        rows.append(
            {
                "subtype": sub,
                "gold": n,
                "detected": hit[sub],
                "recall": round(hit[sub] / n, 4),
            }
        )
    total = sum(gold.values())
    rows.append(
        {
            "subtype": "TOTAL",
            "gold": total,
            "detected": sum(hit.values()),
            "recall": round(sum(hit.values()) / total, 4) if total else 0.0,
        }
    )
    return rows


def _grid(
    rows: list[dict], metric: str, models: list[str], modes: list[str]
) -> list[str]:
    by_key = {(r["model"], r["mode"]): r for r in rows}
    lines = [
        "| Model | " + " | ".join(modes) + " |",
        "| --- | " + " | ".join(["---"] * len(modes)) + " |",
    ]
    for model in models:
        short = _short(model)
        cells = [
            "—"
            if (short, mode) not in by_key
            else str(by_key[(short, mode)].get(metric, "—"))
            for mode in modes
        ]
        lines.append(f"| {short} | " + " | ".join(cells) + " |")
    return lines


def _run_cell(samples, mode, model, nlp_clf, batch_size):
    _reset(samples)
    t0 = time.perf_counter()
    run_vecshield(
        samples,
        mode=mode,
        model=model,
        nlp_classifier=nlp_clf,
        progress_every=0,
        batch_size=batch_size,
    )
    seconds = time.perf_counter() - t0
    results = M.evaluate(samples, benchmark="asq_phi", mode=mode)
    head = _headline(results, mode, _over_redaction(samples))
    return head, results, seconds


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detection ablation (spaCy model × mode) on ASQ-PHI."
    )
    parser.add_argument("--models", nargs="+", default=list(ALL_MODELS))
    parser.add_argument(
        "--modes", nargs="+", choices=ALL_MODES, default=list(ALL_MODES)
    )
    parser.add_argument("--max-samples", type=int, default=0)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--no-download", action="store_true")
    args = parser.parse_args(argv)

    models = [_MODEL_ALIAS.get(m, m) for m in args.models]
    modes = list(args.modes)
    nlp_modes = [m for m in modes if m in ("cascade", "nlp", "ensemble")]

    print("Loading ASQ-PHI ...")
    samples = load_asq_phi(
        max_samples=args.max_samples, download=not args.no_download, seed=args.seed
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
    if unresolved_values():
        print(f"Unresolved gold values dropped: {unresolved_values()}")

    ablation_rows: list[dict] = []
    detail_rows: list[dict] = []
    subtype_rows: list[dict] = []
    notes: list[str] = []

    # regex is model-independent — compute once, reuse for every model row.
    regex_head = regex_results = None
    regex_seconds = 0.0
    regex_miss = 0
    if "regex" in modes or "cascade" in modes:
        _reset(samples)
        t0 = time.perf_counter()
        run_vecshield(samples, mode="regex", progress_every=0)
        regex_seconds = time.perf_counter() - t0
        regex_miss = sum(1 for s in samples if not s.pred)
        if "regex" in modes:
            regex_results = M.evaluate(samples, benchmark="asq_phi", mode="regex")
            regex_head = _headline(regex_results, "regex", _over_redaction(samples))
            print(
                f"[regex] relaxed F1={regex_head['relaxed_F1']} "
                f"| doc AUC={regex_head['doc_AUC']}"
            )

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
            head, results, seconds = _run_cell(
                samples, mode, model, nlp_clf, args.batch_size
            )
            nlp_calls = regex_miss if mode == "cascade" else len(samples)
            ablation_rows.append(
                _cell_row(
                    head, model=model, mode=mode, seconds=seconds, nlp_calls=nlp_calls
                )
            )
            detail_rows.extend({"model": _short(model), **r.to_row()} for r in results)
            if model == HEADLINE_MODEL and mode == HEADLINE_MODE:
                subtype_rows = _subtype_recall(samples)
            print(
                f"[{_short(model)}/{mode}] relaxed F1={head['relaxed_F1']} "
                f"| doc F1={head['doc_F1']} | doc AUC={head['doc_AUC']} "
                f"| overred PHI={head['overred_phi']} | {seconds:.1f}s"
            )

    if regex_results is not None:
        detail_rows = [
            {"model": "—", **r.to_row()} for r in regex_results
        ] + detail_rows

    args.output_dir.mkdir(parents=True, exist_ok=True)
    _write_csv(ablation_rows, args.output_dir / "ablation.csv")
    _write_csv(detail_rows, args.output_dir / "ablation_detail.csv")
    _write_csv(subtype_rows, args.output_dir / "ablation_by_subtype.csv")

    meta = {
        "n_samples": len(samples),
        "n_negatives": n_neg,
        "n_gold_spans": n_gold,
        "regex_miss": regex_miss,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(
            timespec="seconds"
        ),
    }
    _write_summary_md(
        ablation_rows,
        subtype_rows,
        meta,
        models,
        modes,
        notes,
        args.output_dir / "ablation_summary.md",
    )
    print(
        f"\nWrote ablation.csv, ablation_detail.csv, ablation_by_subtype.csv, "
        f"ablation_summary.md to {args.output_dir}"
    )
    return 0


def _write_summary_md(
    rows, subtype_rows, meta, models, modes, notes, path: Path
) -> None:
    lines = [
        "# ASQ-PHI — Detection Ablation (model × mode)",
        "",
        "- Dataset: ASQ-PHI (`synthetic_clinical_queries.txt`)",
        f"- Samples evaluated: {meta['n_samples']} "
        f"({meta['n_negatives']} hard negatives)",
        f"- Gold PHI spans: {meta['n_gold_spans']}",
        f"- Regex-miss documents (cascade NLP calls): {meta['regex_miss']}",
        f"- Generated: {meta['timestamp']}",
        "",
        "Models: `sm`=en_core_web_sm · `md`=en_core_web_md · `lg`=en_core_web_lg.  ",
        "Modes: `regex` · `cascade` (regex→NLP on misses) · `nlp` (NLP only) · "
        "`ensemble` (regex ∪ NLP, the shipped pipeline).",
        "",
        "## Relaxed-span recall (category-ignored detection)",
        "",
    ]
    lines += _grid(rows, "relaxed_R", models, modes)
    lines += ["", "## Partial-span F1 (PHI-category agreement)", ""]
    lines += _grid(rows, "partial_F1", models, modes)
    lines += ["", "## Doc F1 (per-query detection)", ""]
    lines += _grid(rows, "doc_F1", models, modes)
    lines += ["", "## Doc AUC (per-query ranking quality)", ""]
    lines += _grid(rows, "doc_AUC", models, modes)
    lines += ["", "## Over-redaction on hard negatives (PHI-labelled)", ""]
    lines += _grid(rows, "overred_phi", models, modes)

    lines += [
        "",
        "## Full results",
        "",
        "| Model | Mode | Partial F1 | Relaxed R | Relaxed F1 | Doc R | Doc F1 "
        "| Doc AUC | OverRed any | OverRed PHI | Docs/s |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in rows:
        lines.append(
            f"| {r['model']} | {r['mode']} | {r['partial_F1']} | {r['relaxed_R']} "
            f"| {r['relaxed_F1']} | {r['doc_R']} | {r['doc_F1']} | {r['doc_AUC']} "
            f"| {r['overred_any']} | {r['overred_phi']} | {r['docs_per_s']} |"
        )

    if subtype_rows:
        lines += [
            "",
            f"## Relaxed recall by HIPAA identifier type (`{_SHORT[HEADLINE_MODEL]}`/"
            f"`{HEADLINE_MODE}`)",
            "",
            "| Identifier type | Gold | Detected | Recall |",
            "| --- | --- | --- | --- |",
        ]
        for r in subtype_rows:
            lines.append(
                f"| {r['subtype']} | {r['gold']} | {r['detected']} | {r['recall']} |"
            )

    lines += [
        "",
        "*Relaxed = character-overlap span match, category ignored (raw detection). "
        "Partial additionally requires PHI-category agreement. Doc = per-query "
        "'any PHI?' classification; OverRed = fraction of the hard negatives "
        "flagged.*",
    ]
    if notes:
        lines += ["", "### Notes", ""] + [f"- {n}" for n in notes]
    lines.append("")
    path.write_text("\n".join(lines))


if __name__ == "__main__":
    raise SystemExit(main())
