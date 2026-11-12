# The VecShield detection library

PII safety gate for AI ingestion and training pipelines.

[![CI](https://github.com/vecshield/vecshield/actions/workflows/ci.yml/badge.svg)](https://github.com/vecshield/vecshield/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/vecshield.svg)](https://pypi.org/project/vecshield/)
[![Python](https://img.shields.io/pypi/pyversions/vecshield.svg)](https://pypi.org/project/vecshield/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](../../LICENSE)
[![Typed](https://img.shields.io/badge/typing-typed-green.svg)](vecshield/py.typed)

VecShield detects and redacts personal data (PII), health data (PHI), payment
data (PCI), and secrets before text is embedded into a RAG/vector pipeline or
baked into a fine-tuning dataset. Once sensitive data is embedded into a vector
store, or trained into model weights, it is expensive or impossible to remove.
VecShield stops it before that boundary.

## Contents

- [Why VecShield](#why-vecshield)
- [Features](#features)
- [Installation](#installation)
- [Quickstart](#quickstart)
- [CLI](#cli)
- [Python SDK](#python-sdk)
- [Pipeline integration](#pipeline-integration)
- [Detection model](#detection-model)
- [Benchmarked performance](#benchmarked-performance)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

## Why VecShield

AI systems often turn raw documents into chunks, embeddings, vector records,
and training examples. That pipeline can accidentally preserve sensitive data in
places where ordinary deletion workflows no longer work.

The `vecshield` library answers one focused question:

> Can I prevent sensitive data from being embedded into my RAG pipeline or
> training dataset?

## Features

| Capability | CLI | Python SDK |
| --- | --- | --- |
| Classify a string or file | `vecshield detect` | `check_text()` |
| Gate chunks before embedding | `vecshield ingest-check` | `check_chunks()` |
| Scan a fine-tuning dataset | `vecshield training-check` | `check_dataset()` |
| Preview redaction | `vecshield redact-preview` | `redact_text()` |

Core properties:

- Runs locally in your process or CI job.
- Does not require an account, service, API key, or network call.
- Sends no telemetry.
- Keeps input text, findings, and reports in your environment.
- Integrates with LangChain, LlamaIndex, Airflow, plain Python, and CI.
- Ships under the Apache-2.0 license.

## Installation

```bash
pip install vecshield
```

Optional extras:

| Extra | Install command | Purpose |
| --- | --- | --- |
| NLP | `pip install "vecshield[nlp]"` | Higher-recall detection using Presidio and spaCy. |
| Datasources | `pip install "vecshield[datasources]"` | Additional local dataset formats such as Parquet and PDF. |
| Development | `pip install -e ".[nlp,datasources,dev]"` | Tests, linting, type checking, packaging tools. |

For the NLP extra, install a spaCy model after installing dependencies:

```bash
python -m spacy download en_core_web_lg
```

## Quickstart

Check a string from the CLI:

```bash
vecshield detect "email jane@example.com or call 415-555-0132"
```

Gate chunks before embedding:

```bash
vecshield ingest-check ./chunks.jsonl --text-field content --fail-on high
```

Use the Python SDK:

```python
import vecshield

result = vecshield.check_text("contact jane@example.com")
print(result.has_pii)  # True

report = vecshield.check_chunks([
    "The quick brown fox.",
    "Patient SSN is 123-45-6789.",
])
print(report.blocked)  # True

print(vecshield.redact_text("SSN 123-45-6789"))
```

## CLI

Every command supports `--json` for automation. Policy-gate commands exit with
status code `2` when sensitive data violates the selected threshold.

### `detect`

Detect PII/PHI/PCI/secrets in a file or literal string.

```bash
vecshield detect "email jane@example.com" --json
vecshield detect ./notes.txt --fail-on-pii
```

### `ingest-check`

Gate chunks before they reach an embedding model or vector database.

```bash
vecshield ingest-check ./corpus/ --text-field content --json
vecshield ingest-check ./chunks.jsonl --fail-on high
```

### `training-check`

Scan local training or fine-tuning data.

```bash
vecshield training-check ./datasets/sft/ --fail-on high
```

### `redact-preview`

Preview masked output without changing the source file.

```bash
vecshield redact-preview "SSN 123-45-6789, card 4111 1111 1111 1111"
```

## Python SDK

```python
from vecshield import check_chunks, check_dataset, check_text, redact_text

single = check_text("contact jane@example.com")
single.has_pii
single.spans

report = check_chunks([
    {"id": "a", "text": "clean product documentation"},
    {"id": "b", "text": "password = syntheticPassword12345"},
])
report.allowed_chunks
report.blocked_chunks

dataset = check_dataset("./datasets/sft", max_records=1000)
dataset.sensitive_records

redact_text("SSN 123-45-6789")
```

`check_chunks()` accepts strings, dictionaries with a `text` field, or
`vecshield.Chunk` objects. Use `mode="hard"` to raise `PiiDetectedError` on a
blocked batch instead of returning a soft report.

## Pipeline integration

Place VecShield after parsing and chunking, before embedding or training:

```text
source data -> loader/parser -> splitter/chunker -> VecShield gate
            -> block/redact/approve -> embedding model -> vector database
```

Examples are available in [examples](../../examples/library/):

- [examples/quickstart.py](../../examples/library/quickstart.py)
- [examples/langchain_ingest_gate.py](../../examples/library/langchain_ingest_gate.py)
- [examples/llamaindex_ingest_gate.py](../../examples/library/llamaindex_ingest_gate.py)
- [examples/airflow_ingest_check.py](../../examples/library/airflow_ingest_check.py)
- [examples/dagster_ingest_gate.py](../../examples/library/dagster_ingest_gate.py)
- [examples/prefect_ingest_gate.py](../../examples/library/prefect_ingest_gate.py)
- [examples/redaction_pipeline.py](../../examples/library/redaction_pipeline.py)
- [examples/custom_detector.py](../../examples/library/custom_detector.py)
- [examples/training_check_jsonl.py](../../examples/library/training_check_jsonl.py)

More integration guidance is in [docs/ingestion_integration.md](ingestion_integration.md).

## Detection model

VecShield combines a high-precision regex layer with an optional NLP layer:

- Regex detectors cover emails, phone numbers, SSNs, dates of birth, street
  addresses, ZIP/postal codes, passports, driver's licenses, tax IDs, UK
  National Insurance numbers, Canadian SINs, bank routing/account numbers,
  payment cards, IBANs, IPv4/IPv6 addresses, MAC addresses, medical record
  numbers, Medicare identifiers, NPIs, metadata identifiers, API keys, tokens,
  credentials, private-key blocks, and JWTs.
- Optional Presidio and spaCy detection improves recall for names, locations,
  addresses, and contextual PHI.
- Findings are labeled as `pii`, `phi`, `pci`, `secret`, `source_code`, or
  `none` and mapped to severities used by the ingest gate.

VecShield is a safety gate, not a legal determination. Production deployments
should validate detector behavior against their own data, policies, and risk
tolerance.

## Benchmarked performance

VecShield is evaluated end-to-end against independent public datasets with
reproducible harnesses in [benchmarks/](benchmarks/) — full methodology and
per-entity breakdowns in [docs/benchmarks/](benchmarks/).

| Benchmark | Tests | Headline result |
| --- | --- | --- |
| [ai4privacy/pii-masking-200k](benchmarks/ai4privacy_ablation.md) — 43,501 docs, general PII | Broad entity coverage across 50+ PII/PCI/secret types | **Doc F1 0.97**, precision 0.97, recall 0.97 (regex→NLP cascade, ~600 docs/s on CPU) |
| [ASQ-PHI](benchmarks/asq_phi_ablation.md) — 1,051 clinical queries | Zero-leakage PHI gating at the LLM "safe handoff" boundary, plus over-redaction on adversarial hard negatives | **0 of 832 PHI-bearing queries leaked** (doc recall 1.00), doc AUC 0.93 (regex ∪ NLP ensemble) |

- **ai4privacy** — a **regex-only** pass reaches doc AUC 0.87 at ~3,800 docs/s
  with 99.9% precision; the cascade fallback (regex, then NLP only on
  regex-misses) lifts recall from 0.75 to **0.97** while still processing
  ~600 docs/s on a single CPU core.
- **ASQ-PHI** — the shipped `default_classifier` (regex ∪ NLP) catches every
  PHI-bearing query (832/832, zero leakage) while a document confidence
  threshold tunes the false-positive rate on the 219 adversarial queries that
  are worded like PHI but contain no HIPAA identifier.

## Documentation

- [Community overview](overview.md)
- [Architecture](architecture.md)
- [CLI reference](cli_reference.md)
- [SDK reference](sdk_reference.md)
- [Configuration](configuration.md)
- [Ingestion integration](ingestion_integration.md)
- [Training-data checking](training_data_check.md)
- Detection benchmarks (methodology + results):
  [ai4privacy ablation](benchmarks/ai4privacy_ablation.md) ·
  [ASQ-PHI ablation](benchmarks/asq_phi_ablation.md)
- [FAQ](faq.md)

## Contributing

Contributions are welcome. Start with [CONTRIBUTING.md](../../CONTRIBUTING.md), read
the [Code of Conduct](../../CODE_OF_CONDUCT.md), and use synthetic data only in
issues, tests, examples, and fixtures.

Useful local commands:

```bash
make install-dev
make lint
make typecheck
make test
```

## Security

Report vulnerabilities privately. See [SECURITY.md](../../SECURITY.md) for the
security policy and reporting process.

## License

Apache-2.0. See [LICENSE](../../LICENSE) and [NOTICE](../../NOTICE).
