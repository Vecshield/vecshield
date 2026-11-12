"""Minimal VecShield SDK quickstart.

Run:
    python examples/quickstart.py
"""

from __future__ import annotations

from vecshield import check_chunks, check_text, redact_text


def main() -> None:
    result = check_text("Contact jane@example.com for access.", use_nlp=False)
    print("single text has pii:", result.has_pii)
    print("detectors:", ", ".join(result.detectors))

    chunks = [
        "Public product documentation.",
        "Customer tax form uses SSN 123-45-6789.",
    ]
    report = check_chunks(chunks, use_nlp=False)
    print("blocked chunk ids:", report.to_dict()["blocked_chunk_ids"])

    print("redacted:", redact_text("SSN 123-45-6789", use_nlp=False))


if __name__ == "__main__":
    main()
