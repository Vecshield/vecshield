"""Check a JSONL fine-tuning dataset for PII before you train.

Sensitive data in training data is worse than in a vector store: it is baked
into model weights and cannot be erased without re-training. Run this in CI on
every dataset change.

    python training_check_jsonl.py ./datasets/sft/
    # or, equivalently, from the CLI:
    #   vecshield training-check ./datasets/sft/ --fail-on high
"""

from __future__ import annotations

import sys

from vecshield import check_dataset


def main(path: str) -> int:
    report = check_dataset(path)
    print(
        f"{report.records_scanned} records scanned, "
        f"{report.sensitive_records} sensitive ({report.density:.1%}), "
        f"top severity {report.max_severity.upper()}"
    )
    for f in report.findings:
        print(f"  [{f['severity'].upper()}] {f['title']}")
    # Non-zero exit fails the CI job.
    return 2 if report.has_pii else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "."))
