# VecShield documentation

VecShield ships two Python packages from one distribution:

| Package | What it is | CLI |
|---|---|---|
| `vecshield` | The detection library: classifiers, ingest gate, dataset scanning. Runs in your process, no server. | `vecshield` |
| `vecshield_platform` | The server: web console, REST API, vector-store connectors, assessment engines. | `vecshield-platform` |

`vecshield_platform` imports `vecshield`. `vecshield` never imports
`vecshield_platform`, so the library stays usable on its own.

## Getting started

| Doc | What it covers |
|---|---|
| [Demo walkthrough](../demo/README.md) | A seeded estate and the console, in one command. Start here. |
| [Library overview](library/overview.md) | What the detection library does and does not do. |
| [Deployment](deployment.md) | Running the server: Docker, Kubernetes, bare metal, air-gapped. |

## Using the library

| Doc | What it covers |
|---|---|
| [SDK reference](library/sdk_reference.md) | The stable Python API. |
| [CLI reference](library/cli_reference.md) | `vecshield detect`, `ingest-check`, `training-check`, `redact-preview`. |
| [Configuration](library/configuration.md) | What is configurable and what is deliberately not. |
| [Ingestion integration](library/ingestion_integration.md) | Gating LangChain, LlamaIndex, Airflow, Dagster and Prefect pipelines. |
| [Training-data check](library/training_data_check.md) | Scanning datasets before fine-tuning. |
| [Library architecture](library/architecture.md) | How the classifier ensemble fits together. |
| [FAQ](library/faq.md) | Including what this does not do. |

## Running the platform

| Doc | What it covers |
|---|---|
| [Architecture](architecture.md) | Packages, layers, and the assessment flow. |
| [Features](features.md) | Capability reference for the server. |
| [Deployment](deployment.md) | Install, auth, state, single-writer lock, air-gapped builds. |
| [Auditing pgvector](pgvector.md) | What is checked on PostgreSQL + pgvector, and with which role. |
| [Crypto posture](crypto_posture.md) | What can be verified about encryption through a connector — and what cannot. |
| [NLP models](nlp_models.md) | Choosing, pinning and installing the NER models. |

## Detection quality

| Doc | What it covers |
|---|---|
| [Detection limitations](detection_limitations.md) | What the detectors cannot see, by regulation. Read before trusting a clean result. |
| [Detector changelog](library/detection-changelog.md) | History of the detection engine. |
| [Regulatory coverage benchmark](library/benchmarks/regulatory_coverage.md) | Coverage measured against the criterion pack. |
| [ai4privacy ablation](library/benchmarks/ai4privacy_ablation.md) | Results on the public ai4privacy dataset. |
| [ASQ-PHI ablation](library/benchmarks/asq_phi_ablation.md) | Results on clinical-query PHI. |

The labelled corpus the detectors are scored against is in
[`benchmark/corpus/`](../benchmark/corpus/), and its
[manifest](../benchmark/corpus/manifest.yaml) states the corpus's own
limitations. The harnesses for public research datasets are in
[`benchmarks/`](../benchmarks/).

## Compliance

Detection is separate from regulatory judgement, and VecShield keeps them
separate on purpose: a technical result, its applicability, the sufficiency of
its evidence, and a reviewer's conclusion are four different fields. **A scan
result is not a compliance determination.**

| Doc | What it covers |
|---|---|
| [Criterion pack migration](compliance/pack-draft-4-migration.md) | What happens to reviewer decisions when a pack version changes. Machine-generated. |

## Decisions and reference

| Doc | What it covers |
|---|---|
| [ADR 0001](adr/0001-exhaustive-tenant-isolation.md) | Exhaustive tenant-isolation probing. |
| [ADR 0002](adr/0002-local-accounts-and-sessions.md) | Local accounts and sessions. |
| [ADR 0003](adr/0003-secret-reference-allowlist.md) | Secret-reference allowlist. |
| [Brand](brand/README.md) | The mark, the palette, and the rules the console's tests enforce. |

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the development setup and the
gates a change has to pass, and [SECURITY.md](../SECURITY.md) for reporting a
vulnerability.
