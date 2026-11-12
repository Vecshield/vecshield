# Examples

This directory contains small, synthetic examples for using VecShield Community
in ingestion, training-data, and redaction workflows. Do not use real sensitive
data in examples or fixtures.

## Quickstart

- [quickstart.py](quickstart.py) — minimal SDK usage for detection, chunk
  gating, and redaction.
- [training_check_jsonl.py](training_check_jsonl.py) — scan a local training or
  fine-tuning dataset.

## Ingestion frameworks

- [langchain_ingest_gate.py](langchain_ingest_gate.py) — filter LangChain
  documents after splitting and before vector-store insertion.
- [llamaindex_ingest_gate.py](llamaindex_ingest_gate.py) — gate LlamaIndex
  nodes before building an index.
- [airflow_ingest_check.py](airflow_ingest_check.py) — fail an Airflow DAG
  before embedding.
- [dagster_ingest_gate.py](dagster_ingest_gate.py) — use VecShield inside a
  Dagster asset check.
- [prefect_ingest_gate.py](prefect_ingest_gate.py) — use VecShield inside a
  Prefect flow task.

## Customization

- [custom_detector.py](custom_detector.py) — compose VecShield with a
  project-specific classifier.
- [redaction_pipeline.py](redaction_pipeline.py) — redact spans while
  preserving surrounding context.
