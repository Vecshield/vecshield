# Configuration

The `vecshield` library is configuration-light by design. Most behavior is selected
through CLI flags or SDK parameters.

## NLP detection

By default, VecShield uses regex detection and attempts to add Presidio/spaCy
when the NLP extra is installed. Disable the NLP layer when you need a faster,
dependency-light check:

```bash
vecshield detect ./notes.txt --no-nlp
```

```python
from vecshield import check_text

check_text("contact jane@example.com", use_nlp=False)
```

## Severity thresholds

Gate commands accept `--fail-on` with one of these levels:

| Level | Typical use |
| --- | --- |
| `info` | Fail on any finding. Useful for strict tests. |
| `low` | Fail on low confidence findings and above. |
| `medium` | Fail on source-code or medium-risk findings and above. |
| `high` | Default gate for PII/PHI/PCI. |
| `critical` | Fail only on critical findings such as secrets. |

In the SDK, pass a `Severity` to `check_chunks()`:

```python
from vecshield import check_chunks
from vecshield.models import Severity

report = check_chunks(chunks, block_severity=Severity.HIGH)
```

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Command completed and policy passed. |
| `1` | Usage or input error. |
| `2` | Policy failure: sensitive data met the selected threshold. |

## Redaction policy

Redaction replaces detected spans with `[REDACTED:LABEL]`. The surrounding text
is preserved so embedding can keep non-sensitive context while removing the raw
substring.
