# SDK reference

The stable SDK lives in `vecshield.sdk` and is re-exported from `vecshield`.

## `check_text()`

```python
from vecshield import check_text

result = check_text("contact jane@example.com", use_nlp=False)
```

Returns `CheckResult`:

| Field | Meaning |
| --- | --- |
| `has_pii` | Whether the text was classified as sensitive. |
| `label` | Dominant label: `pii`, `phi`, `pci`, `secret`, `source_code`, or `none`. |
| `confidence` | Classifier confidence from `0.0` to `1.0`. |
| `detectors` | Detector names that fired. |
| `spans` | Masked span metadata with offsets and previews. |

## `check_chunks()`

```python
from vecshield import check_chunks

report = check_chunks(["clean", "SSN 123-45-6789"], mode="soft")
```

Inputs may be raw strings, dictionaries with a `text` key, or `Chunk` objects.
Returns `IngestGateReport` with `allowed_chunks`, `blocked_chunks`, `findings`,
`pii_density`, and `blocked`.

Use `mode="hard"` when you want a blocked batch to raise `PiiDetectedError`.

## `check_dataset()`

```python
from vecshield import check_dataset

report = check_dataset("./datasets/sft", max_records=1000)
```

Returns `DatasetReport` with `records_scanned`, `sensitive_records`, `density`,
`max_severity`, and `findings`.

## `redact_text()`

```python
from vecshield import redact_text

redact_text("SSN 123-45-6789")
```

Returns a string with detected spans replaced by `[REDACTED:LABEL]` tokens.
