# Training-data checking

Sensitive data in a training or fine-tuning dataset is **worse** than in a
vector store: it gets baked into model weights on the next run and cannot be
erased by deleting rows. VecShield escalates the severity of PII found in
training data by one rung (PII → CRITICAL) to reflect this.

## CLI

```bash
vecshield training-check ./datasets/sft/ --json
vecshield training-check ./datasets/sft/ --fail-on high   # exit 2 to fail CI
```

Supported local formats: `.jsonl` / `.ndjson` / `.json`, `.csv` / `.tsv`,
`.txt` / `.md`, plus `.parquet` and `.pdf` with the `datasources` extra.

## SDK

```python
from vecshield import check_dataset

report = check_dataset("./datasets/sft/")
print(report.records_scanned, report.sensitive_records, report.density)
for f in report.findings:
    print(f["severity"], f["title"])
```

`DatasetReport` fields:

| Field | Meaning |
|---|---|
| `records_scanned` | total records read |
| `sensitive_records` | records containing PII/PHI/PCI/secrets |
| `density` | sensitive / scanned |
| `max_severity` | highest finding severity (`critical` for training PII) |
| `findings` | per-dataset finding dicts with evidence |

## Recommended workflow

1. Run `training-check` in CI on every dataset change.
2. Fail the build on `--fail-on high` (or `critical`).
3. For flagged records: remove or redact them, regenerate the dataset, and
   re-train from the cleaned data.
4. Add an ingest gate upstream so PII never reaches the dataset again.

## Text-field selection

For structured records, point the reader at the text column:

```bash
vecshield training-check ./data/ --text-field content
```

Otherwise every field is concatenated and scanned, which maximizes recall at
the cost of some noise in the evidence.
