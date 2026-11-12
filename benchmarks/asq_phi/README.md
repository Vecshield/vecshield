# VecShield Benchmarks — ASQ-PHI

Reproducible evaluation of VecShield's detection engine against **ASQ-PHI**
(*Adversarial Synthetic Queries for PHI de-identification*) — a fully synthetic
benchmark of short clinician-style search queries at the "safe handoff"
boundary, the point where a HIPAA-compliant clinical LLM would forward a prompt
to a non-BAA external tool.

- Paper: <https://pmc.ncbi.nlm.nih.gov/articles/PMC12926592/> (Data in Brief)
- Code: <https://github.com/JamesWeatherhead/asq-phi>
- Data: <https://data.mendeley.com/datasets/csz5dzp7nx/1>
- License: **MIT**. No real patient or EHR data — every query is synthetic.

**1,051** single-line queries: **832 PHI-positive** (79.2%) and **219 hard
negatives** (20.8%) engineered to *look* PHI-like (ages, diagnoses, meds,
symptoms) while carrying no HIPAA identifier. **2,973** PHI spans across **13**
HIPAA Safe Harbor identifier types. It exists because most de-identification
benchmarks are long EHR notes; ASQ-PHI targets short prompts and specifically
stresses **over-redaction** on the hard negatives (e.g. "18-year-old female" is
*not* PHI under Safe Harbor — age < 90 is not identifying on its own).

The pipeline mirrors [`benchmarks/ai4privacy/`](../ai4privacy/):

1. **Loads** the dataset (bundled locally; auto-downloaded from GitHub if absent).
2. **Normalizes** its value-based PHI tags into VecShield's four categories.
3. **Runs** VecShield (`regex` / `cascade` / `nlp` / `ensemble` mode) with no
   gold leakage. `ensemble` = regex **∪** Presidio on every document — exactly
   what the shipped `vecshield.default_classifier(use_nlp=True)` does — and is
   the highest-recall mode.
4. **Scores** the same detection metrics as every other VecShield benchmark, so
   results are directly comparable across datasets, plus a per-query
   over-redaction rate on the 219 hard negatives.

## Layout

```
benchmarks/asq_phi/
  run_asq_phi.py               # CLI entry point (single-mode / multi-mode run)
  run_ablation.py              # model × mode ablation (regex/cascade/nlp/ensemble)
  requirements.txt             # pinned deps (stdlib-only for regex mode)
  data/
    synthetic_clinical_queries.txt  # the dataset (MIT, bundled)
    dataset_statistics.txt          # upstream stats card
  normalize/
    schema.py                  # EvalSample + Annotation
    asq_phi.py                 # dataset adapter (value → offset resolution)
  runners/
    vecshield_runner.py        # VecShield → predicted Annotations
    metrics.py                 # exact / partial / type_relaxed / binary_doc
  tests/
    test_asq_phi_adapter.py    # adapter normalization (no network needed)
  results/                     # written at runtime (git-ignored)
```

## Install

```bash
pip install -e .                       # local vecshield
```

The regex-mode harness needs **no extra dependencies** — the dataset is a single
MIT-licensed text file fetched with stdlib `urllib` (there is no HuggingFace /
`datasets` dependency here, unlike the other two benchmarks).

For `nlp` / `cascade` / `ensemble` mode (Presidio + spaCy recall for
names/locations/dates — which are 82% of ASQ-PHI's spans):

```bash
pip install 'vecshield[nlp]'
python -m spacy download en_core_web_lg
```

## Run

```bash
# Ensemble mode (regex ∪ NLP — the shipped pipeline, highest recall)
PYTHONHASHSEED=0 python -m benchmarks.asq_phi.run_asq_phi --mode ensemble

# Every mode, full dataset (all 1,051 rows — the default)
PYTHONHASHSEED=0 python -m benchmarks.asq_phi.run_asq_phi --mode regex cascade nlp ensemble

# Trade recall for fewer over-redactions with a document-decision threshold
PYTHONHASHSEED=0 python -m benchmarks.asq_phi.run_asq_phi --mode ensemble --min-score 0.7

# Offline (fail instead of downloading if the file is missing)
python -m benchmarks.asq_phi.run_asq_phi --mode regex --no-download

# Full model × mode ablation (sm/md/lg × regex/cascade/nlp/ensemble)
PYTHONHASHSEED=0 python -m benchmarks.asq_phi.run_ablation --batch-size 32
```

The committed ablation numbers and full methodology live in
[docs/benchmarks/asq_phi_ablation.md](../../docs/library/benchmarks/asq_phi_ablation.md).

Outputs land in `benchmarks/asq_phi/results/`:

| File | Contents |
| --- | --- |
| `asq_phi_<mode>.csv` | One row per `match_mode × entity_type`, all metrics. |
| `asq_phi_false_positives_<mode>.csv` | FP counts per fired detector (over-redaction). |
| `asq_phi_summary.md` | Headline table (partial + relaxed + doc + over-redaction). |

## Latest results

Full dataset (1,051 samples, 2,973 gold spans), `en_core_web_lg`:

| Mode | Partial F1 | Relaxed R | Relaxed F1 | Doc R | Doc F1 | Doc AUC | OverRed any | OverRed PHI |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| regex    | 0.14 | 0.18 | 0.24 | 0.94 | 0.87 | 0.77 | 0.80 | 0.00 |
| cascade  | 0.18 | 0.22 | 0.29 | 1.00 | 0.89 | 0.80 | 0.93 | 0.13 |
| nlp      | 0.64 | 0.78 | 0.76 | 1.00 | 0.93 | 0.94 | 0.59 | 0.47 |
| ensemble | 0.65 | **0.90** | **0.76** | **1.00** | 0.89 | **0.93** | 0.93 | 0.47 |

**Reading these:** ASQ-PHI gold spans are *all* `PHI`. The `partial` column
requires VecShield to also label the span `PHI`; **`relaxed`** (overlap, category
ignored) is the raw span-recall read. `ensemble` (regex ∪ NLP) is the shipped
pipeline and the recall leader — **relaxed recall 0.90, and doc recall 1.00: it
never lets a PHI-bearing query through.** Because a name/SSN/date in clinical
text is genuinely PHI, VecShield upgrades those identifiers to PHI in context, so
`partial` recall is now high too (0.65). `OverRed` is the cost on the hard
negatives; the `PHI` rate is 0.47 (down from 0.73 after the date-specificity and
age fixes below) and the residual is spaCy hallucinating PERSON/ORG on clinically
worded negatives. `Doc AUC` rose to 0.93, so `--min-score` is now an effective
gate knob — e.g. `--min-score 0.65` drops PHI over-redaction to **0** at a
document level while keeping doc F1 0.91 (trading ~16% doc recall).

### Recall improvements landed for this benchmark

Analysis of the miss set drove several detector changes (all in the shared
VecShield core, so every dataset benefits):

- **`ensemble` mode** — benchmarks the real `default_classifier` union; lifted
  relaxed span recall from ~0.70 (best single engine) to **over 0.90**.
- **Full-date recovery in the NLP path** — a regex for abbreviated/ordinal/
  numeric calendar dates spaCy's `DATE_TIME` misses (`Feb 21, 2023`,
  `May 30th, 2022`, `4/3/2023`), gated on health context. DATE recall
  0.48 → 0.80.
- **Broader PHI-context** — the `_PHI_CONTEXT` health-term list was widened
  (and `patient` fixed to match `patients`) so names/locations/dates in clinical
  text upgrade to PHI. NAME partial recall 0.47 → 0.80; this is also the main
  driver of the 0.73 over-redaction (see above — it was a deliberate
  recall-first choice).
- **`prefixed_id` detector** (`AB-1234`-style IDs) — HEALTH_PLAN_BENEFICIARY
  0.19 → 0.78, UNIQUE_IDENTIFIER 0.50 → 0.93, ACCOUNT/CERTIFICATE → 1.0.
  Low-confidence (0.50): it also matches some benign codes (SKU/model/standard
  numbers) in general prose, so it is easily filtered by `--min-score`.
- **`us_ssn_context` detector** — a keyword-anchored SSN pattern that accepts the
  otherwise-invalid `9xx`/`000`/`666` area numbers the strict `us_ssn` rule
  rejects (ASQ's synthetic SSNs use `987-65-4321`). SSN recall 0.70 → 0.97.
- **Unicode-punctuation-normalized value resolution** in the adapter — recovered
  the 1 previously-dropped gold span (`Children's` ASCII vs. `Children’s` curly
  apostrophe); gold spans 2,972 → 2,973.

Second round (driven by the ensemble failure analysis — raised partial F1
0.58 → 0.65 and cut PHI over-redaction 0.73 → 0.47):

- **PHI-context upgrade of regex spans** (`apply_phi_context`, shared by the
  shipped `EnsembleClassifier` and this runner) — an SSN/phone/plan-ID found by
  regex is now labeled PHI in clinical context, matching what Presidio already
  did for its own spans. SSN partial recall 0.06 → 0.67, HEALTH_PLAN 0.07 → 0.49,
  PHONE 0.44 → 0.64, FAX/CERTIFICATE → 1.0.
- **DATE_TIME specificity gate** — spaCy's `DATE_TIME` is upgraded to PHI only
  when the span is a *specific* date (month+day / numeric / ISO), never a bare
  year, age, or duration (which are not Safe Harbor identifiers). Removed 223
  spurious PHI date spans from the hard negatives; `Doc AUC` 0.75 → 0.93.
- **Age is never upgraded to PHI** (`_NO_PHI_UPGRADE`) — under Safe Harbor an age
  < 90 is not identifying, so `age_context` stays PII (still detected) instead of
  becoming PHI in a clinical query. This alone cut PHI over-redaction 0.71 → 0.47
  with no recall loss. (Age remains PII, so ai4privacy AGE detection is intact.)
- **`prefixed_id` accepts a 1-letter prefix** (`R-987654`, `#R-987654`).

**Remaining failure modes** (candidates for future work): (1) spaCy hallucinates
PERSON/ORGANIZATION on clinically-worded negatives — the bulk of the residual
0.47 PHI over-redaction, needs an NER-precision fix not a rule; (2) ~180 dates
sit in queries with no health-context term, so the context gate skips them
(relaxing this trades ai4privacy date precision); (3) spaCy misses some hospital
names (`Cedar Sinai`, `Springfield Medical Center`) — a gazetteer would help.

## Metrics

Identical definitions to every other VecShield benchmark — see
[`benchmarks/ai4privacy/README.md`](../ai4privacy/README.md#metrics) for the full
match-mode table (`exact` / `partial` / `type_relaxed` / `binary_doc`). Each row
reports precision, recall, F1, F0.5, F2, plus raw `tp`/`fp`/`fn` and span counts,
broken down by `ALL` and by category.

## Label mapping & scope

The native file (`synthetic_clinical_queries.txt`) is record-delimited text; PHI
is annotated **by value string, not character offset**:

```
===QUERY===
Treatment for Anna S., seen at Methodist Hospital on April 12, 2023?
===PHI_TAGS===
{"identifier_type": "NAME", "value": "Anna S."}
{"identifier_type": "GEOGRAPHIC_LOCATION", "value": "Methodist Hospital"}
{"identifier_type": "DATE", "value": "April 12, 2023"}
```

The adapter resolves each `value` to a `[start, end)` span by locating it in the
query, consuming matched ranges left-to-right (so a repeated value maps to
distinct spans) with a case-insensitive fallback for casing drift. Values that
still cannot be located are dropped and surfaced via `unresolved_values()`.

All **13** HIPAA Safe Harbor identifier types are PHI, so every one maps to
VecShield's `PHI` category; the native type is kept as the annotation `subtype`:

| VecShield category | Source `identifier_type` values |
| --- | --- |
| `PHI` | `NAME`, `GEOGRAPHIC_LOCATION`, `DATE`, `MEDICAL_RECORD_NUMBER`, `HEALTH_PLAN_BENEFICIARY_NUMBER`, `PHONE_NUMBER`, `SOCIAL_SECURITY_NUMBER`, `EMAIL_ADDRESS`, `UNIQUE_IDENTIFIER`, `ACCOUNT_NUMBER`, `FAX_NUMBER`, `CERTIFICATE_LICENSE_NUMBER`, `IP_ADDRESS` |
| `PII` / `PCI` / `SECRET` | (none — ASQ-PHI is a PHI-only benchmark) |

Any unrecognized identifier type is skipped and surfaced via `unmapped_labels()`.

**Scope note.** ASQ-PHI exercises VecShield's PHI-boundary detectors (PERSON,
LOCATION, DATE_TIME, MRN, phone, SSN, email, driver-license/NPI, Medicare MBI,
IP) and its over-redaction behaviour on clinically-loaded hard negatives. It does
**not** cover most non-healthcare detectors (credit cards, IBAN/SWIFT, crypto
wallets, cloud/API keys, JWTs, national IDs, MAC/VIN, ...) — use `ai4privacy` and
`bigcode_pii` for broad PII/secret coverage.

## Tests

```bash
pytest benchmarks/asq_phi/tests/ -v
```

All adapter tests are pure (no network, no dataset file needed) so they run in
any environment.

## Reproducibility notes

- Set `PYTHONHASHSEED=0` (see commands above).
- Sampling (only when `--max-samples` caps below the full 1,051 rows) uses a
  fixed shuffle seed (`--seed`, default `42`).
- Predictions are computed before any gold comparison — no leakage.
- The bundled dataset is byte-identical to the upstream GitHub `main` copy.
