# Detection Benchmark — ASQ-PHI ablation

This page records the **methodology** and **results** of VecShield's detection
ablation against the public **ASQ-PHI** (Adversarial Synthetic Queries for PHI
de-identification) dataset. The harness lives in
[benchmarks/asq_phi/](../../../benchmarks/asq_phi/); this document is the committed
record of the numbers, since `results/` is generated at runtime and git-ignored.

ASQ-PHI targets the **safe-handoff boundary** — the point where a
HIPAA-compliant clinical LLM forwards a query to a non-BAA external tool — so the
two questions that matter are: *does the gate catch every PHI-bearing query
(leakage)?* and *does it avoid redacting the clinically-worded but
identifier-free negatives (over-redaction)?*

## Methodology

### Dataset

- Source: [ASQ-PHI](https://github.com/JamesWeatherhead/asq-phi)
  (`synthetic_clinical_queries.txt`), MIT-licensed, fully synthetic — no real
  patient or EHR data.
- Rows evaluated: **1,051** single-line clinician-style queries — **832
  PHI-positive** (79.2%) and **219 hard negatives** (20.8%) engineered to look
  PHI-like (ages, diagnoses, meds, symptoms) while carrying no HIPAA identifier.
- Gold spans (after normalization): **2,973** across **13** HIPAA Safe Harbor
  identifier types.
- Deterministic: fixed `--seed 42` and `PYTHONHASHSEED=0` (sampling only matters
  when `--max-samples` caps below the full set; the default runs all rows).
- Predictions are computed **before** any gold comparison — no label leakage.

### Label normalization

Gold PHI is annotated **by value string, not character offset**. The adapter
([normalize/asq_phi.py](../../../benchmarks/asq_phi/normalize/asq_phi.py)) resolves
each `value` to a `[start, end)` span by locating it in the query, consuming
matched ranges left-to-right (so a repeated value maps to distinct spans) with
case- and Unicode-punctuation-insensitive fallbacks (curly vs. ASCII apostrophe).
All **13** identifier types are Protected Health Information, so every one maps
to VecShield's `PHI` category; the native type is kept as the annotation
`subtype` for the per-type breakdown.

| Category | Source identifier types |
| --- | --- |
| `PHI` | NAME, GEOGRAPHIC_LOCATION, DATE, MEDICAL_RECORD_NUMBER, HEALTH_PLAN_BENEFICIARY_NUMBER, PHONE_NUMBER, SOCIAL_SECURITY_NUMBER, EMAIL_ADDRESS, UNIQUE_IDENTIFIER, ACCOUNT_NUMBER, FAX_NUMBER, CERTIFICATE_LICENSE_NUMBER, IP_ADDRESS |
| `PII` / `PCI` / `SECRET` | (none — ASQ-PHI is a PHI-only benchmark) |

### Axes

The ablation is the **product** of two axes:

- **Model** (spaCy NER backbone): `sm` = `en_core_web_sm`, `md` =
  `en_core_web_md`, `lg` = `en_core_web_lg`. Larger = better NER, slower on CPU.
- **Mode** (detection strategy):
  - `regex` — `RegexClassifier` only (model-independent baseline).
  - `cascade` — regex first; the spaCy pass runs **only** on documents where
    regex found nothing (regex-miss fallback).
  - `nlp` — `PresidioClassifier` alone (pure NLP, no regex).
  - `ensemble` — regex **∪** NLP on every document, merged exactly as the shipped
    `vecshield.default_classifier(use_nlp=True)`. The highest-recall mode.

Because `regex` is model-independent it is computed once and reused across model
rows. Only **93** of 1,051 documents (8.8%) are regex-misses — almost every query
carries a name or a structured ID that regex or spaCy catches — which is why
`cascade` (regex-*or*-NLP per doc) barely improves on `regex` here, while
`ensemble` (regex-*and*-NLP) is far ahead.

### Metrics

| Match mode | Definition |
| --- | --- |
| `exact` | Predicted span matches gold iff **both boundaries** and **category** match. |
| `partial` | Character intervals **overlap** and **category** (`PHI`) matches. |
| `type_relaxed` | Same as `partial` but category is ignored — **raw span detection**. |
| `binary_doc` | Per-query "any PHI?" classification; also reports **ROC-AUC** over the query confidence score. |

Because every gold span is `PHI`, `partial` additionally demands that VecShield
*label* the span `PHI` — so it measures both detection and correct
categorization, while `type_relaxed` (reported below as **relaxed**) is the raw
"did we find the span at all" recall.

We also report **over-redaction** on the 219 hard negatives — the fraction
flagged with any span (`any`) and with a `PHI`-labelled span (`PHI`). The `PHI`
rate is the meaningful one for a PHI-only benchmark (a PII-only hit such as an
age is not a PHI false positive).

### Reproduce

```bash
pip install -e .
pip install 'vecshield[nlp]'
python -m spacy download en_core_web_sm en_core_web_md en_core_web_lg

# Full model × mode ablation over all 1,051 rows.
PYTHONHASHSEED=0 python -m benchmarks.community.asq_phi.run_ablation --batch-size 32
```

Outputs land in `benchmarks/asq_phi/results/`: `ablation.csv`,
`ablation_detail.csv`, `ablation_by_subtype.csv`, and `ablation_summary.md`. The
dataset is bundled in `benchmarks/asq_phi/data/` (auto-downloaded from GitHub if
absent), so no access request is needed.

## Results

Full dataset (1,051 queries, 219 hard negatives, 2,973 gold spans), `en_core_web_sm`/`md`/`lg`.

### Relaxed-span recall (raw detection, category ignored)

| Model | regex | cascade | nlp | ensemble |
| --- | --- | --- | --- | --- |
| sm | 0.1786 | 0.2190 | 0.7467 | 0.8722 |
| md | 0.1786 | 0.2196 | 0.7898 | **0.9112** |
| lg | 0.1786 | 0.2196 | 0.7753 | 0.9018 |

### Partial-span F1 (with PHI-category agreement)

| Model | regex | cascade | nlp | ensemble |
| --- | --- | --- | --- | --- |
| sm | 0.1364 | 0.1744 | 0.6255 | 0.6342 |
| md | 0.1364 | 0.1748 | 0.6487 | 0.6530 |
| lg | 0.1364 | 0.1752 | 0.6414 | **0.6533** |

### Doc recall / Doc F1 / Doc AUC (per-query gate)

| | regex | cascade | nlp | ensemble |
| --- | --- | --- | --- | --- |
| Doc recall (all models) | 0.94 | **1.00** | **1.00** | **1.00** |
| Doc F1 (lg) | 0.8749 | 0.8908 | 0.9275 | 0.8908 |
| Doc AUC (lg) | 0.7660 | 0.7951 | **0.9380** | 0.9252 |

**Every NLP-backed mode leaks nothing: doc recall 1.00 — all 832 PHI queries are
flagged before handoff.**

### Over-redaction on hard negatives (PHI-labelled)

| Model | regex | cascade | nlp | ensemble |
| --- | --- | --- | --- | --- |
| sm | 0.00 | 0.1279 | 0.5251 | 0.5251 |
| md | 0.00 | 0.1187 | 0.4840 | 0.4840 |
| lg | 0.00 | 0.1324 | 0.4658 | **0.4658** |

### Relaxed recall by HIPAA identifier type (`lg`/`ensemble`)

| Identifier type | Gold | Recall |
| --- | --- | --- |
| NAME | 814 | 1.00 |
| PHONE_NUMBER | 45 | 1.00 |
| ACCOUNT_NUMBER | 4 | 1.00 |
| FAX_NUMBER | 2 | 1.00 |
| CERTIFICATE_LICENSE_NUMBER | 1 | 1.00 |
| IP_ADDRESS | 1 | 1.00 |
| MEDICAL_RECORD_NUMBER | 305 | 0.99 |
| SOCIAL_SECURITY_NUMBER | 33 | 0.97 |
| EMAIL_ADDRESS | 31 | 0.97 |
| UNIQUE_IDENTIFIER | 14 | 0.93 |
| GEOGRAPHIC_LOCATION | 826 | 0.91 |
| DATE | 806 | 0.78 |
| HEALTH_PLAN_BENEFICIARY_NUMBER | 91 | 0.77 |
| **TOTAL** | **2,973** | **0.90** |

### Full results

| Model | Mode | Partial F1 | Relaxed R | Relaxed F1 | Doc R | Doc F1 | Doc AUC | OverRed any | OverRed PHI | Docs/s |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| sm | regex    | 0.1364 | 0.1786 | 0.2430 | 0.9411 | 0.8749 | 0.7660 | 0.7991 | 0.0000 | 4136.0 |
| sm | cascade  | 0.1744 | 0.2190 | 0.2852 | 1.0000 | 0.8908 | 0.7919 | 0.9315 | 0.1279 | 1091.4 |
| sm | nlp      | 0.6255 | 0.7467 | 0.7386 | 1.0000 | 0.9188 | 0.9230 | 0.6712 | 0.5251 | 174.1 |
| sm | ensemble | 0.6342 | 0.8722 | 0.7398 | 1.0000 | 0.8908 | 0.9111 | 0.9315 | 0.5251 | 170.9 |
| md | regex    | 0.1364 | 0.1786 | 0.2430 | 0.9411 | 0.8749 | 0.7660 | 0.7991 | 0.0000 | 4136.0 |
| md | cascade  | 0.1748 | 0.2196 | 0.2862 | 1.0000 | 0.8917 | 0.7946 | 0.9224 | 0.1187 | 1409.2 |
| md | nlp      | 0.6487 | 0.7898 | 0.7669 | 1.0000 | 0.9250 | 0.9348 | 0.6164 | 0.4840 | 165.8 |
| md | ensemble | 0.6530 | 0.9112 | 0.7628 | 1.0000 | 0.8917 | 0.9223 | 0.9224 | 0.4840 | 163.6 |
| lg | regex    | 0.1364 | 0.1786 | 0.2430 | 0.9411 | 0.8749 | 0.7660 | 0.7991 | 0.0000 | 4136.0 |
| lg | cascade  | 0.1752 | 0.2196 | 0.2860 | 1.0000 | 0.8908 | 0.7951 | 0.9315 | 0.1324 | 1418.3 |
| lg | nlp      | 0.6414 | 0.7753 | 0.7590 | 1.0000 | 0.9275 | 0.9380 | 0.5936 | 0.4658 | 165.9 |
| lg | ensemble | 0.6533 | 0.9018 | 0.7632 | 1.0000 | 0.8908 | 0.9252 | 0.9315 | 0.4658 | 163.2 |

*Relaxed = character-overlap span match, category ignored (raw detection).
Partial additionally requires PHI-category agreement. Doc = per-query "any PHI?"
classification. OverRed = fraction of the 219 hard negatives flagged.*

## Takeaways

- **Ensemble is the recall operating point.** `ensemble` (regex ∪ NLP) reaches
  **relaxed recall 0.90** and **doc recall 1.00** — it never lets a PHI-bearing
  query through — by unioning regex's structured-ID coverage (MRN, SSN, phone,
  plan IDs) with NLP's names/locations/dates, instead of choosing one per
  document like `cascade`.
- **Cascade is not enough here.** Only 8.8% of queries are regex-misses, so the
  regex-gated NLP fallback almost never fires; `cascade` relaxed recall (0.22)
  barely beats `regex` (0.18). This dataset is where the union genuinely matters.
- **PHI labeling is high, not just detection.** Because a name/SSN/date in
  clinical context is genuinely PHI, identifiers are upgraded to `PHI` in
  context, lifting `partial` F1 to **0.65** — not only overlap recall.
- **Over-redaction is the residual weakness, and it is bounded.** `ensemble`
  flags **0.47** of the hard negatives with a PHI span. This is *after* three
  precision fixes: dates are PHI only when *specific* (month+day, not a bare
  year/age/duration), age below 90 is never upgraded to PHI (Safe Harbor), and
  those two together lifted doc AUC from ~0.75 to **0.93**. The remainder is
  spaCy hallucinating `PERSON`/`ORGANIZATION` on clinically-worded negatives — an
  NER-precision limit, not a rule gap. Because doc AUC is now high,
  `--min-score 0.65` drives PHI over-redaction to **0** at a document level (doc
  F1 0.91), trading ~16% doc recall.
- **Model size barely matters.** `md` and `lg` are within noise (`md` even edges
  `lg` on relaxed recall, 0.9112 vs 0.9018); `sm` trails on the name/location NER
  that drives recall. `lg` is the default, `md` is a fine cheaper substitute.
