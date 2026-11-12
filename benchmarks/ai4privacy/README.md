# VecShield Benchmarks — ai4privacy/pii-masking-200k

Reproducible evaluation of VecShield's detection engine against the public
[`ai4privacy/pii-masking-200k`](https://huggingface.co/datasets/ai4privacy/pii-masking-200k)
dataset (~200k rows of text with character-level PII spans, no registration
required).

> **Licence — read before using this at work.** An earlier version of this file
> described the dataset as "Apache-2.0 / MIT licensed". That is wrong, and the
> error is corrected here rather than quietly deleted because it was also
> published in `docs/library/benchmarks/ai4privacy_ablation.md`.
>
> The dataset ships its own
> [LICENSE](https://huggingface.co/datasets/ai4privacy/pii-masking-200k/raw/main/LICENSE),
> which grants free use to an individual, a for-profit entity **with a staff
> count of up to 3**, or a non-profit — and states that it is "not permissible
> to duplicate or alter Ai4Privacy's code with the intention to distribute,
> sell, rent, license, re-license, or sublicense your own derivative". Larger
> organisations are directed to a paid company licence.
>
> The Hugging Face card carries no licence tag, so it renders as "not
> specified"; that is the likely origin of the mistake. An absent tag is not a
> permissive licence.
>
> This is a reading of the primary source, not legal advice. The practical
> consequences for this repository: results computed from it are fine to
> publish, the data must not be vendored here, and anyone running this
> benchmark inside a company larger than three people should check the licence
> first. `ai4privacy/openpii-1m` is offered by the same publisher under CC BY
> 4.0 and covers 23 languages rather than 4 — repointing the harness would
> resolve the licence question and the non-English gap together.

The pipeline:

1. **Loads** the dataset from the HuggingFace Hub.
2. **Normalizes** its native `privacy_mask` spans into VecShield's four
   categories (`PII` / `PHI` / `PCI` / `SECRET`).
3. **Runs** VecShield (`regex` and/or `nlp` mode) with no gold-label leakage.
4. **Scores** the standard detection metrics used in PII benchmarks.

## Layout

```
benchmarks/ai4privacy/
  run_ai4privacy.py            # CLI entry point
  run_ablation.py              # model × mode ablation
  requirements.txt             # pinned deps
  normalize/
    schema.py                  # EvalSample + Annotation
    ai4privacy.py              # dataset adapter (label → category mapping)
  runners/
    vecshield_runner.py        # VecShield → predicted Annotations
    metrics.py                 # exact / partial / type_relaxed / binary_doc
  tests/
    test_metrics.py            # metric correctness
    test_ai4privacy_adapter.py # adapter normalization
  results/                     # written at runtime (git-ignored)
```

## Install

```bash
pip install -e .                      # local vecshield
pip install -r benchmarks/ai4privacy/requirements.txt
```

For `nlp` mode (adds Presidio + spaCy recall for names/addresses):

```bash
pip install 'vecshield[nlp]'
python -m spacy download en_core_web_lg
```

## Run

```bash
# Regex mode, 2,000 samples (fast smoke run)
PYTHONHASHSEED=0 python -m benchmarks.ai4privacy.run_ai4privacy --mode regex --max-samples 2000

# Both modes, 5,000 samples
PYTHONHASHSEED=0 python -m benchmarks.ai4privacy.run_ai4privacy --mode regex nlp --max-samples 5000

# Full split
PYTHONHASHSEED=0 python -m benchmarks.ai4privacy.run_ai4privacy --mode regex --max-samples 0
```

Outputs land in `benchmarks/ai4privacy/results/`:

| File | Contents |
| --- | --- |
| `ai4privacy_<mode>.csv` | One row per `match_mode × entity_type`, all metrics. |
| `ai4privacy_false_positives_<mode>.csv` | FP counts per fired detector. |
| `ai4privacy_summary.md` | Headline table (partial-span + document-level). |

### Ablation (spaCy model × mode)

`run_ablation.py` sweeps the product of models (`sm`/`md`/`lg`) and modes
(`regex`/`cascade`/`nlp`) and records accuracy plus throughput:

```bash
# Full 3×3 ablation over the whole validation split, batched inference.
PYTHONHASHSEED=0 python -m benchmarks.ai4privacy.run_ablation --max-samples 0 --batch-size 128
```

It writes `ablation.csv`, `ablation_detail.csv`, and `ablation_summary.md`. The
committed results and methodology are documented in
[docs/benchmarks/ai4privacy_ablation.md](../../docs/library/benchmarks/ai4privacy_ablation.md).

## Latest results

Full `validation` split (43,501 docs, 95,112 gold spans), `en_core_web_lg`:

| Mode | Partial F1 | Doc P | Doc R | Doc F1 | Doc AUC | Docs/s |
| --- | --- | --- | --- | --- | --- | --- |
| regex   | 0.6159 | 0.9994 | 0.7508 | 0.8575 | 0.8732 | 3793.5 |
| cascade | **0.6609** | 0.9714 | **0.9691** | **0.9703** | 0.8471 | 602.4 |
| nlp     | 0.4894 | 0.9685 | 0.8726 | 0.9180 | 0.6898 | 169.4 |

**`cascade` is the best operating point**: doc F1 **0.9703** at ~600 docs/sec on
a single CPU core, by running the (much slower) spaCy pass only on the 27.7% of
documents where regex found nothing. `regex` alone is 6x faster (~3,800 docs/s)
with near-perfect precision (0.9994) but lower recall (0.75) — hence the cascade
fallback. Full model-size sweep (`sm`/`md`/`lg`) and per-category breakdowns in
[docs/benchmarks/ai4privacy_ablation.md](../../docs/library/benchmarks/ai4privacy_ablation.md).

## Metrics

| Match mode | Definition |
| --- | --- |
| `exact` | Predicted span matches gold iff **both boundaries** and **category** match. |
| `partial` | Predicted span matches gold iff their character intervals **overlap** and **category** matches. |
| `type_relaxed` | Same as `partial` but category is ignored (boundary detection only). |
| `binary_doc` | Per-document "any sensitive data?" classification; also reports **ROC-AUC** over the document confidence score. |

For every match mode, metrics are reported for `ALL` entities and per category
(`PII`, `PHI`, `PCI`, `SECRET`). Each row includes precision, recall, **F1**,
**F0.5** (precision-weighted), and **F2** (recall-weighted), plus raw
`tp` / `fp` / `fn` / span counts.

Matching is greedy one-to-one (each gold and predicted span is consumed at most
once) and predicted spans are de-duplicated by keeping the highest-scoring span
among overlaps, so nothing is double-counted.

## Label mapping & scope

ai4privacy annotates many *quasi-identifiers* that are not personal data on
their own (job title, company name, currency, amount, eye colour…). Scoring
those as gold would unfairly penalize a precision-first engine that
deliberately does not flag them, so the adapter scores **direct identifiers**
only and routes quasi-identifiers to an explicit `IGNORE` set. All mapping
decisions live in [`normalize/ai4privacy.py`](normalize/ai4privacy.py) and
unmapped labels are surfaced via `unmapped_labels()` for auditability.

| Category | Example source labels |
| --- | --- |
| `PII` | names, email, phone, SSN, passport, IP, MAC, address, DOB, age |
| `PCI` | credit card, CVV, IBAN, BIC, account number, crypto address |
| `SECRET` | password, PIN |
| `PHI` | (none in this dataset) |

## Tests

```bash
pytest benchmarks/ai4privacy/tests/ -v
```

## Reproducibility notes

- Set `PYTHONHASHSEED=0` (see commands above).
- Sampling uses a fixed shuffle seed (`--seed`, default `42`).
- Predictions are computed before any gold comparison — no leakage.
