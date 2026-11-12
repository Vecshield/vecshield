"""Redact sensitive spans while preserving non-sensitive context.

Use this pattern when dropping an entire chunk would remove too much useful
context, but embedding the raw sensitive substring is unacceptable.
"""

from __future__ import annotations

from vecshield.ingest import IngestGate
from vecshield.models import Chunk


def redact_chunks(chunks: list[Chunk]) -> list[Chunk]:
    gate = IngestGate()
    clean_chunks, spans_redacted = gate.redact(chunks)
    print(f"redacted {spans_redacted} span(s)")
    return clean_chunks


if __name__ == "__main__":
    original = [
        Chunk(
            id="doc-1#0",
            collection="knowledge-base",
            text="Support contact: jane@example.com. Product tier: internal.",
            metadata={"source_owner": "jane@example.com"},
        )
    ]
    redacted = redact_chunks(original)
    print(redacted[0].text)
    print(redacted[0].metadata)
