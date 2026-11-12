# Regulatory coverage benchmark

Every category the detector engine claims, measured on one corpus, against any
classifier you can plug in.

## Why this exists beside the other two

`ai4privacy/` measures PII. `asq_phi/` measures clinical PHI and
over-redaction. Between them they cover two of the six frameworks in the
criterion pack, and both rely on public datasets — which is a strength for
comparability and a limit for coverage. There is no public dataset for trade
union membership under GDPR Art. 9, for magnetic-stripe track data under PCI
DSS Requirement 3.3.1, or for a Polish PESEL. Those categories have never been
measured.

This benchmark carries its own corpus so they can be.

## What it will and will not tell you

It answers: **does a classifier see this category at all, and does it stay
quiet on the hard negative beside it?**

It does not answer: how accurate a detector is on real data at volume. The
corpus has 36 positive cases; that is a coverage instrument, not a precision
estimate. For precision on realistic text use `ai4privacy/`, and for
over-redaction use `asq_phi/`.

## Running it

```sh
python -m benchmarks.regulatory_coverage.run
python -m benchmarks.regulatory_coverage.run --regulation GDPR
python -m benchmarks.regulatory_coverage.run --json
```

Runners whose dependencies are absent print the reason. "Not installed" and
"scored zero" are different facts and the report never conflates them.

## The corpus

48 cases: 36 positive, 12 hard negative, 44 gold spans across all six
frameworks and all six categories.

Synthetic and wholly owned by this repository — invented people,
vendor-published example credentials, the networks' test card numbers, and
check-digit-valid national identifiers computed for the purpose. It carries no
data use agreement and can be redistributed, which the i2b2/n2c2
de-identification corpora cannot.

### Why the corpus is ours rather than borrowed

Not preference — the clinical corpora everyone reaches for first cannot be
vendored into an open repository.

The following is **research reported by another workstream and not verified
here**; check it before relying on it, and treat the quoted clauses as
paraphrase until someone has opened the live pages:

- **i2b2 / n2c2** de-identification corpora are reported to forbid
  redistribution in terms that name this exact scenario — each user must obtain
  the data themselves, and copies may not be "posted to other websites,
  including GitHub". The portal was also reported to be temporarily unavailable
  as of 2026-09-23, with no stated end date.
- **CEGS N-GRID (2016)** is reported to be unavailable outside the original
  challenge altogether, under IRB limitations. No agreement obtains it.
- **PhysioNet / MIMIC** is reported to extend its agreement to *derived*
  datasets and to fine-tuned model weights, not only the source notes. If that
  holds, a model trained on it cannot ship here either. Code is the stated
  exception.
- **MTSamples** is reported to have no licence at all; the widely repeated CC0
  claim appears to originate from a third-party upload rather than from the
  source.

So a benchmark that vendors clinical text is either unshippable or quietly in
breach, and one that requires every user to obtain a DUA is a benchmark most
people will never run. A synthetic corpus we own outright avoids both.

**Redistributable alternatives worth adding as fetched corpora** (again,
unverified here): MedDeID's synthetic English and Dutch sets, which carry PHI
span annotations under CC BY 4.0 and would exercise the non-English path;
PARHAF for French; and NHS England's MIT-licensed synthetic notes as a
substrate for injecting identifiers. ASQ-PHI is MIT and is already vendored in
`../asq_phi/`.

None of these belong *in* this corpus. They belong beside it, fetched on
demand, which is what `runners.py` and the schema already support.

Cases are indexed by **obligation**, not by detector. A benchmark organised by
detector measures whether a tool reproduces our taxonomy; organised by
obligation it measures whether a tool would answer the regulator's question,
which is the thing a competitor can do better or worse than we do.

Hard negatives name the categories they must not provoke rather than demanding
silence. "An IMEI is not payment card data" is a claim about the PCI label —
reporting the IMEI as a device identifier is the *right* answer, and a negative
that failed a run for it would be measuring the wrong thing.

## Comparing other classifiers

`runners.py` defines a `Runner` protocol and ships adapters for Presidio
standalone, GLiNER (zero-shot), and any HuggingFace token-classification model.
Each declares which of our categories it can express.

That declaration is the honest part. A fixed-label model trained on an
email/phone/SSN taxonomy **cannot** report trade union membership at any
threshold. It scores nothing on GDPR Art. 9 because the category is not in its
vocabulary, not because it is inaccurate — so those spans are counted under
`cannot_express` and excluded from recall, and named. Folding them into
"missed" would report a vocabulary limit as an accuracy failure and flatter the
tool on every other row.

To add a model, implement `availability()`, `expressible()` and `predict()`.
For a token classifier you must supply the `label_map` explicitly: every model
names its labels differently, and guessing the mapping is how a benchmark
quietly scores the wrong thing.

## The system test

`tests/system/test_regulatory_coverage_benchmark.py` runs this end to end on
every default test run. It pins floors, not figures: a recall floor of 0.5 per
category catches a detector collapsing without failing the suite each time one
improves, and the two known over-flags are pinned **by name** so a new one
fails loudly instead of hiding inside a tolerance.

It is here because `pyproject.toml` sets `testpaths = ["tests"]`, so nothing
under `benchmarks/` runs by default — which is how both other benchmarks came
to be broken by a package move without anyone noticing.
