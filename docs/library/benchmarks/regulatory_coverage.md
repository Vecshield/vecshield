# Regulatory coverage — measured results

Four classifiers over the same 48-case corpus, scored per category and per
framework. Run on 2026-09-23.

Reproduce with:

```sh
python -m benchmarks.community.regulatory_coverage.run
```

## What was run

| Runner | What it is |
|---|---|
| `vecshield-regex` | The shipped engine, regex layer only |
| `vecshield+nlp[en_core_web_lg]` | The shipped engine with NER, on the same spaCy model Presidio uses |
| `presidio` | `presidio-analyzer` 2.2.364 standalone, `en_core_web_lg` |
| `gliner` | `urchade/gliner_multi_pii-v1`, zero-shot, threshold 0.5 |

Both VecShield rows and Presidio use **the same NER model**, so the difference
between them is orchestration rather than model choice.

## Recall by category

Recall is over the spans a classifier can express. `n/a` counts gold spans in
a category the classifier has **no label for**; those are excluded from recall
rather than scored as misses, because a vocabulary limit is not an accuracy
result.

| Category | gold | vecshield-regex | vecshield+nlp | presidio | gliner |
|---|---|---|---|---|---|
| PII | 14 | 0.86 | **0.93** | **0.93** | 0.64 |
| PHI | 10 | 0.90 | **1.00** | 0.00 | 0.30 |
| PCI | 5 | **1.00** | **1.00** | 0.60 | 0.20 |
| SECRET | 5 | 0.80 | 0.80 | n/a (5) | 0.80 |
| SPECIAL_CATEGORY | 9 | **1.00** | **1.00** | n/a (9) | 0.89 |
| CRIMINAL_OFFENCE | 1 | **1.00** | **1.00** | n/a (1) | **1.00** |
| hard negatives clean | 12 | 10 | 10 | **11** | 9 |

## What the numbers say

**Presidio is not behind us on PII — it ties.** 0.93 against our 0.93 with NER,
and it beats the regex-only layer. It also has the cleanest hard negatives of
anything tested. Any story that treats general PII detection as a
differentiator is not supported by this corpus.

**Presidio cannot express 15 of 44 gold spans.** Not "scored badly" — it has no
label for credentials, special-category or criminal-offence data at all, and
scored 0.00 on PHI. This is the gap the criterion pack sits in, and it is
consistent with the externally reported figure of ~0.07 recall for Presidio on
the GDPR Art. 9/Art. 10 tier.

**The NER layer earns its place.** Adding it lifted PHI from 0.90 to 1.00 and
PII from 0.86 to 0.93 **with no cost in precision** — the hard negatives were
unchanged at 10 of 12. That is not the usual recall/precision trade.

**GLiNER is the only non-VecShield system that can reach Art. 9, and it gets
0.89 there.** That is the most important number in this table. Its labels are
an inference input, so it can simply be *asked* for "trade union membership"
without retraining — the one mechanism that reaches categories no fixed-label
model covers.

**But it is weak exactly where checksums are strong**: PCI 0.20, PII 0.64,
PHI 0.30. It misses structured identifiers a regex with a check digit does not.

**And it over-flags in the way that matters.** Three of twelve negatives fired,
including two that are the classic over-redaction failures:

- it read *"The European Union published guidance"* as a **political
  affiliation**;
- it reported a **person name and a date of birth** inside a letter template
  whose only contents are `[PATIENT NAME]` and `[DATE]` placeholders.

The second is a model inventing an identifier that is not in the text. For a
product whose Actions page refuses irreversible remediation on unmeasured
detectors, that is disqualifying as a sole basis for action — and useful as a
recall-oriented second opinion.

## The read

These are complementary, not competing. Regex plus checksums win on structured
identifiers and cannot reach semantic categories; a zero-shot model reaches the
semantic categories and cannot validate a check digit. An ensemble that used
GLiNER **only** for the categories no pattern can express, at a threshold tuned
against these hard negatives, is the shape the evidence supports.

## Caveats

- **36 positive cases.** This is a coverage instrument, not a precision
  estimate. For precision on realistic text see `ai4privacy/`; for
  over-redaction see `asq_phi/`.
- The corpus is ours, so it cannot be read as an independent evaluation of
  anyone else's tool. It can be read as evidence about what each tool is
  capable of expressing, which is the question it was built for.
- GLiNER ran at its default threshold of 0.5 with no tuning. A threshold sweep
  would move both its recall and its over-flagging.
- Jev could not be evaluated. It is proprietary with no open weights, and the
  only open-source implementation (`kyegomez/open-jev`, Apache 2.0) ships
  random weights by its own account. A runner exists for the hosted API and
  reports "no credential" until one is supplied.
