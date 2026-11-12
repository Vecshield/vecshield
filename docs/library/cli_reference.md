# CLI reference

VecShield provides four commands. Each command runs locally. Commands that act
as gates exit with status code `2` when the selected policy fails.

## Common options

| Option | Meaning |
| --- | --- |
| `--json` | Emit machine-readable JSON. |
| `--no-nlp` | Use regex detection only. |
| `--help` | Show command help. |

## `vecshield detect`

Detect sensitive data in a literal string or text file.

```bash
vecshield detect "email jane@example.com"
vecshield detect ./notes.txt --json --fail-on-pii
```

Options:

| Option | Meaning |
| --- | --- |
| `--fail-on-pii` | Exit `2` when any sensitive data is found. |

## `vecshield ingest-check`

Gate chunks before embedding.

```bash
vecshield ingest-check ./chunks.jsonl --text-field content --fail-on high
vecshield ingest-check ./corpus/ --json
```

Options:

| Option | Meaning |
| --- | --- |
| `--text-field FIELD` | Field containing text in JSONL/CSV records. |
| `--format FORMAT` | Force a reader format such as `jsonl`, `csv`, or `text`. |
| `--fail-on LEVEL` | Exit `2` for findings at or above `info`, `low`, `medium`, `high`, or `critical`. |

## `vecshield training-check`

Scan a local training/fine-tuning dataset directory.

```bash
vecshield training-check ./datasets/sft --max-records 1000 --fail-on high
```

Options:

| Option | Meaning |
| --- | --- |
| `--max-records N` | Cap records scanned per dataset. |
| `--fail-on LEVEL` | Exit `2` for findings at or above the selected level. |

## `vecshield redact-preview`

Preview redacted output for a literal string or file.

```bash
vecshield redact-preview "SSN 123-45-6789"
vecshield redact-preview ./notes.txt --json
```
