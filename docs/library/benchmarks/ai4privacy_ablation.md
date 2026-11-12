# Detection Benchmark — ai4privacy ablation

This page records the **methodology** and **results** of VecShield's detection
ablation against the public
[`ai4privacy/pii-masking-200k`](https://huggingface.co/datasets/ai4privacy/pii-masking-200k)
dataset. The harness lives in
[benchmarks/ai4privacy/](../../../benchmarks/ai4privacy/); this document is the
committed record of the numbers, since `results/` is generated at runtime and
git-ignored.

## Methodology

### Dataset

- Source: `ai4privacy/pii-masking-200k` (no registration). **Correction:** an
  earlier version of this page described the dataset as "Apache-2.0 / MIT".
  Its own [LICENSE](https://huggingface.co/datasets/ai4privacy/pii-masking-200k/raw/main/LICENSE)
  restricts free use to individuals, entities of up to 3 staff, and non-profits,
  and prohibits redistributing derivatives. The results below are unaffected —
  the licence governs the data, not the measurements — but the earlier
  statement should not be relied on.
- Split: `validation`.
- Rows evaluated: **43,501** English documents (`english_only=True`).
- Gold spans (after normalization): **95,112**.
- Sampling is deterministic: fixed shuffle `--seed 42` and `PYTHONHASHSEED=0`.
- Predictions are computed **before** any gold comparison — no label leakage.

### Label normalization

The adapter ([normalize/ai4privacy.py](../../../benchmarks/ai4privacy/normalize/ai4privacy.py))
maps the dataset's native `privacy_mask` labels into VecShield's four
categories and **scores direct identifiers only**. Quasi-identifiers that are
not personal data on their own (job title, company name, currency, amount, eye
colour, …) are routed to an explicit `IGNORE` set so a precision-first engine is
not penalized for deliberately not flagging them. Unmapped labels are surfaced
via `unmapped_labels()` for auditability.

| Category | Example source labels |
| --- | --- |
| `PII` | names, email, phone, SSN, passport, IP, MAC, address, DOB, age |
| `PCI` | credit card, CVV, IBAN, BIC, account number, crypto address |
| `SECRET` | password, PIN |
| `PHI` | (none present in this dataset) |

### Axes

The ablation is the **product** of two axes:

- **Model** (spaCy NER backbone): `sm` = `en_core_web_sm`, `md` =
  `en_core_web_md`, `lg` = `en_core_web_lg`. Larger = better NER, slower on CPU.
- **Mode** (detection strategy):
  - `regex` — `RegexClassifier` only (model-independent baseline).
  - `cascade` — regex first; the spaCy pass runs **only** on documents where
    regex found nothing (regex-miss fallback).
  - `nlp` — `PresidioClassifier` alone (pure NLP, no regex).

Because `regex` is model-independent it is computed once and reused across model
rows. **12,057** documents (27.7%) are regex-misses and reach the spaCy pass in
`cascade` mode.

### Metrics

| Match mode | Definition |
| --- | --- |
| `exact` | Predicted span matches gold iff **both boundaries** and **category** match. |
| `partial` | Predicted span matches gold iff their character intervals **overlap** and **category** matches. |
| `type_relaxed` | Same as `partial` but category is ignored (boundary detection only). |
| `binary_doc` | Per-document "any sensitive data?" classification; also reports **ROC-AUC** over the document confidence score. |

Metrics are reported for `ALL` entities and per category (`PII`, `PHI`, `PCI`,
`SECRET`), each with precision, recall, **F1**, **F0.5** (precision-weighted),
and **F2** (recall-weighted). Matching is greedy one-to-one and predicted spans
are de-duplicated by highest score, so nothing is double-counted.

### Reproduce

```bash
pip install -e .
pip install -r benchmarks/ai4privacy/requirements.txt
pip install 'vecshield[nlp]'
python -m spacy download en_core_web_sm en_core_web_md en_core_web_lg

# Full 3×3 ablation over the whole validation split.
PYTHONHASHSEED=0 python -m benchmarks.community.ai4privacy.run_ablation --max-samples 0 --batch-size 128
```

`--batch-size 128` enables batched spaCy inference (`nlp.pipe`) for the NLP leg.
It is a throughput optimization only — results are identical to per-document
inference. On a single-core host, batching (not multiprocessing) is what
saturates the CPU. Outputs are written to `benchmarks/ai4privacy/results/`:
`ablation.csv`, `ablation_detail.csv`, and `ablation_summary.md`.

## Results

Full `validation` split (43,501 docs, 95,112 gold spans), `en_core_web_lg`/`md`/`sm`.

### Doc AUC (per-document ranking quality)

| Model | regex | cascade | nlp |
| --- | --- | --- | --- |
| sm | 0.8732 | 0.8346 | 0.6679 |
| md | 0.8732 | 0.8415 | 0.6760 |
| lg | 0.8732 | 0.8471 | 0.6898 |

### Doc F1 (per-document detection)

| Model | regex | cascade | nlp |
| --- | --- | --- | --- |
| sm | 0.8575 | 0.9688 | 0.9213 |
| md | 0.8575 | 0.9690 | 0.9118 |
| lg | 0.8575 | 0.9703 | 0.9180 |

### Doc recall

| Model | regex | cascade | nlp |
| --- | --- | --- | --- |
| sm | 0.7508 | 0.9682 | 0.8801 |
| md | 0.7508 | 0.9673 | 0.8623 |
| lg | 0.7508 | 0.9691 | 0.8726 |

### Partial-span F1

| Model | regex | cascade | nlp |
| --- | --- | --- | --- |
| sm | 0.6159 | 0.6497 | 0.4670 |
| md | 0.6159 | 0.6569 | 0.4732 |
| lg | 0.6159 | 0.6609 | 0.4894 |

### Throughput (docs/sec, CPU, single core)

| Model | regex | cascade | nlp |
| --- | --- | --- | --- |
| sm | 3793.5 | 617.9 | 174.0 |
| md | 3793.5 | 602.7 | 169.3 |
| lg | 3793.5 | 602.4 | 169.4 |

### Full results

| Model | Mode | Partial P | Partial R | Partial F1 | Doc P | Doc R | Doc F1 | Doc AUC | NLP calls | Wall s | Docs/s |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| sm | regex | 0.9427 | 0.4573 | 0.6159 | 0.9994 | 0.7508 | 0.8575 | 0.8732 | 0 | 11.47 | 3793.5 |
| sm | cascade | 0.8001 | 0.5469 | 0.6497 | 0.9694 | 0.9682 | 0.9688 | 0.8346 | 12057 | 70.40 | 617.9 |
| sm | nlp | 0.5008 | 0.4374 | 0.4670 | 0.9665 | 0.8801 | 0.9213 | 0.6679 | 43501 | 250.04 | 174.0 |
| md | regex | 0.9427 | 0.4573 | 0.6159 | 0.9994 | 0.7508 | 0.8575 | 0.8732 | 0 | 11.47 | 3793.5 |
| md | cascade | 0.8137 | 0.5508 | 0.6569 | 0.9707 | 0.9673 | 0.9690 | 0.8415 | 12057 | 72.18 | 602.7 |
| md | nlp | 0.5197 | 0.4343 | 0.4732 | 0.9673 | 0.8623 | 0.9118 | 0.6760 | 43501 | 256.92 | 169.3 |
| lg | regex | 0.9427 | 0.4573 | 0.6159 | 0.9994 | 0.7508 | 0.8575 | 0.8732 | 0 | 11.47 | 3793.5 |
| lg | cascade | 0.8186 | 0.5541 | 0.6609 | 0.9714 | 0.9691 | 0.9703 | 0.8471 | 12057 | 72.21 | 602.4 |
| lg | nlp | 0.5374 | 0.4492 | 0.4894 | 0.9685 | 0.8726 | 0.9180 | 0.6898 | 43501 | 256.76 | 169.4 |

*Partial = character-overlap span match with category agreement. Doc = per-document "any sensitive data?" classification. `regex` rows are identical across models (regex does not use spaCy).*

## Takeaways

- **Cascade is the best operating point.** `lg/cascade` leads on document
  detection (F1 **0.9703**, recall **0.9691**) while only sending the 27.7%
  regex-miss documents to spaCy, so it keeps ~600 docs/s on CPU.
- **Regex alone is the fastest and highest-ranking baseline.** It reaches doc
  AUC **0.8732** at ~3,800 docs/s with near-perfect precision (0.9994), but its
  recall (0.7508) is why the cascade fallback matters.
- **NLP-only trails on ranking.** Contextual recognizers (`PERSON`, `LOCATION`)
  fire on some truly-negative documents, which lowers ranking quality (AUC) even
  as raw recall stays high — hence cascade (regex-gated NLP) beats pure NLP.
- **Model size helps modestly.** `sm → lg` improves cascade doc F1 by ~0.15pt
  and partial F1 by ~1.1pt, at roughly equal throughput; `lg` is the default.
