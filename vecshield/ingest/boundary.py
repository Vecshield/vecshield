"""ChunkBoundaryAnalyzer — catch PII split across a chunk cut.

Per-chunk scanning misses PII that a chunker split in half: an SSN
`123-45-6789` cut into `...123-45` | `6789...` matches no regex in either chunk.
This analyzer concatenates each adjacent pair's tail+head overlap zone and runs
the classifier over the join, flagging any span that straddles the cut point.

Input chunks must be in document order and from the same document (the caller
groups them; metadata key `document_id`/`source` is used when present).
"""

from __future__ import annotations

import uuid

from vecshield.classify import Classifier, default_classifier
from vecshield.models import Chunk, Finding, Severity

_DEFAULT_ZONE = 64  # chars of tail/head to join around each cut


class ChunkBoundaryAnalyzer:
    def __init__(
        self,
        *,
        classifier: Classifier | None = None,
        zone_chars: int = _DEFAULT_ZONE,
        store: str = "ingest",
    ):
        self.classifier = classifier or default_classifier()
        self.zone_chars = zone_chars
        self.store = store

    def analyze(self, chunks: list[Chunk]) -> list[Finding]:
        """Return boundary_pii findings for spans straddling adjacent-chunk cuts."""
        findings: list[Finding] = []
        ordered = [c for c in chunks if c.text]
        for i in range(len(ordered) - 1):
            a, b = ordered[i], ordered[i + 1]
            left_text = a.text or ""
            right_text = b.text or ""
            tail = left_text[-self.zone_chars :]
            head = right_text[: self.zone_chars]
            joined = tail + head
            cut = len(tail)

            result = self.classifier.classify(joined)
            if not result.is_sensitive:
                continue

            for span in result.spans:
                start, end = span.get("start", 0), span.get("end", 0)
                # straddles the cut iff it starts before and ends after it
                if start < cut < end:
                    findings.append(
                        Finding(
                            id=f"find-{uuid.uuid4().hex[:10]}",
                            title=(
                                f"{span.get('label', 'pii').upper()} split "
                                "across chunk boundary"
                            ),
                            severity=Severity.HIGH,
                            category="boundary_pii",
                            store=self.store,
                            collection=a.collection,
                            description=(
                                f"A {span.get('label', 'sensitive')} value "
                                f"({span.get('detector', 'detector')}) is split "
                                f"across the boundary between chunks '{a.id}' "
                                f"and '{b.id}'. Per-chunk scanning misses it; "
                                "the join zone reveals it."
                            ),
                            evidence={
                                "left_chunk": a.id,
                                "right_chunk": b.id,
                                "detector": span.get("detector"),
                                "label": span.get("label"),
                                "preview": span.get("preview"),
                            },
                            remediation=(
                                "Use an overlap window when chunking so "
                                "sensitive spans aren't cut, and run the "
                                "ingest gate over the overlap zone."
                            ),
                        )
                    )
        return findings
