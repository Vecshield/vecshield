"""Document provenance analysis.

To investigate a poisoning incident you need to know where each chunk came from
and when. This analyzes provenance metadata across a collection, measuring
coverage (what fraction of chunks are traceable) and surfacing rare sources —
a source contributing a tiny slice of a collection is exactly what an injected
document looks like.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

# Metadata keys that carry provenance, in order of preference.
_SOURCE_KEYS = ("source", "source_url", "url", "uri", "file", "filename",
                "document_id", "doc_id", "path")


@dataclass
class ProvenanceReport:
    total: int
    with_source: int
    sources: dict[str, int] = field(default_factory=dict)
    rare_sources: list[str] = field(default_factory=list)

    @property
    def coverage(self) -> float:
        return self.with_source / self.total if self.total else 0.0


def _source_of(metadata: dict) -> str | None:
    for k in _SOURCE_KEYS:
        v = metadata.get(k)
        if v:
            return str(v)
    return None


def analyze_provenance(
    metadatas: list[dict],
    *,
    rare_fraction: float = 0.01,
) -> ProvenanceReport:
    """`rare_fraction`: sources contributing <= this share of chunks are 'rare'."""
    total = len(metadatas)
    counts: Counter[str] = Counter()
    with_source = 0
    for m in metadatas:
        src = _source_of(m or {})
        if src is not None:
            with_source += 1
            counts[src] += 1

    threshold = max(1, int(total * rare_fraction))
    # ...and never above half the median source size. In a corpus made of many
    # small documents (tickets, emails, 20-chunk PDFs) every source is below 1%
    # of the whole; calling them all "rare" says nothing and buries the one
    # that is.
    if counts:
        sizes = sorted(counts.values())
        mid = len(sizes) // 2
        med = sizes[mid] if len(sizes) % 2 else (sizes[mid - 1] + sizes[mid]) / 2
        threshold = min(threshold, max(1, int(med / 2)))
    # A source is 'rare' if it's below the fraction threshold AND there are
    # several sources (a 2-source collection isn't meaningfully "rare").
    rare = []
    if len(counts) > 2:
        rare = sorted(s for s, c in counts.items() if c <= threshold)

    return ProvenanceReport(
        total=total,
        with_source=with_source,
        sources=dict(counts),
        rare_sources=rare,
    )
