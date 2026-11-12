# Ingestion integration

VecShield is a **gate** in your ingestion pipeline. A typical RAG ingestion
flow, with VecShield inserted before the embedder:

```
source systems (DBs, apps, docs)
        │
        ▼
data lake / object store (S3, GCS, Azure Blob)
        │
        ▼
loader / parser (PDF, HTML, JSON, ...)
        │
        ▼
splitter / chunker
        │
        ▼
┌─────────────────────────────┐
│   VecShield PII gate         │  ← detect PII/PHI/PCI/secrets
└─────────────────────────────┘
        │
        ├── block   → drop the chunk, fail the batch
        ├── redact  → mask spans, keep the context
        └── approve → pass clean chunks through
        │
        ▼
embedding model
        │
        ▼
vector DB (upsert)
```

The rule of thumb: **gate after chunking and before embedding.** Once a chunk is
embedded, the sensitive data is persisted in the vector store; once it is in a
training set, it is baked into weights.

## Integration points

### Custom Python

```python
from vecshield import check_chunks

report = check_chunks(chunks, mode="soft")
clean = report.allowed_chunks           # embed only these
```

### LangChain

Use the callback handler to filter documents after the splitter. See
[`examples/langchain_ingest_gate.py`](../../examples/library/langchain_ingest_gate.py).

### LlamaIndex

Gate `nodes` after the node parser, before `VectorStoreIndex`. See
[`examples/llamaindex_ingest_gate.py`](../../examples/library/llamaindex_ingest_gate.py).

### Airflow / Dagster / Prefect

Add a gate task between the chunk task and the embed task; raise to fail the DAG
on PII. See [`examples/airflow_ingest_check.py`](../../examples/library/airflow_ingest_check.py),
[`examples/dagster_ingest_gate.py`](../../examples/library/dagster_ingest_gate.py), and
[`examples/prefect_ingest_gate.py`](../../examples/library/prefect_ingest_gate.py).

### S3 / GCS / Azure Blob batch jobs

Run `vecshield ingest-check` (or `check_dataset`) over the staged batch before
the embedding job kicks off.

### CI checks for training datasets

```yaml
- run: pip install vecshield
- run: vecshield training-check ./datasets/ --fail-on high
```

### Kafka / Flink (streaming)

For streaming ingestion, call `check_text` / `check_chunks` inside your stream
processor. This is a later-stage integration; batch gating covers most
pipelines first.

## Modes

- **soft** (default) — report blocked vs allowed; you decide.
- **hard** — raise `PiiDetectedError` when anything is blocked (fail-closed).
- **redact** — mask spans with `IngestGate.redact()` / `redact_text()` and embed
  the cleaned text.
