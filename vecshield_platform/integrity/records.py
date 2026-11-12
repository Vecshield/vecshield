"""Compact per-chunk records and the report shape shared by integrity detectors.

The integrity engine reads each chunk once. The metadata-driven detectors
(duplication, ingestion bursts, versions) need only a few fields per chunk, so
the engine distils each chunk into a :class:`ChunkRecord` rather than keeping
its text: memory is O(records), never O(corpus text).

Text is reduced to a keyed digest that lives only in memory for the run. It is
never written into findings, stats or outcomes.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Mapping

from vecshield.models import Finding, Severity
from vecshield_platform.integrity.provenance import _SOURCE_KEYS
from vecshield_platform.scan.retention import looks_like_record_time, parse_timestamp

#: Keys that name a chunk's position within its source document.
POSITION_KEYS = ("chunk_index", "chunk_idx", "chunk_number", "chunk_no", "chunk_seq",
                 "position", "seq", "sequence", "start_index", "offset", "part")
#: Keys that further qualify a position (a per-page chunk index, say).
POSITION_QUALIFIERS = ("page", "page_number", "page_no", "section")

#: Document-generation keys, in priority order: explicit versions first, then
#: opaque content identifiers, then modification timestamps.
VERSION_KEYS = ("version", "doc_version", "document_version", "revision", "rev",
                "etag", "source_hash", "doc_hash", "document_hash", "file_hash",
                "content_hash", "sha256", "checksum", "md5",
                "last_modified", "modified", "modified_at", "updated_at", "updated")
#: Version keys whose values are timestamps; coalesced by a time gap.
TIMESTAMP_VERSION_KEYS = frozenset({"last_modified", "modified", "modified_at",
                                    "updated_at", "updated"})
#: Version keys whose values are opaque (no order can be read from them).
OPAQUE_VERSION_KEYS = frozenset({"etag", "source_hash", "doc_hash", "document_hash",
                                 "file_hash", "content_hash", "sha256", "checksum", "md5"})

#: Record-time keys preferred as the *ingestion* time, best first. Any other
#: field retention analysis accepts as a record time is a fallback.
INGEST_TIME_PREFERENCE = ("ingested_at", "ingested", "indexed_at", "indexed",
                          "inserted_at", "inserted", "imported_at", "imported",
                          "loaded_at", "synced_at", "created_at", "created",
                          "crawled_at", "timestamp", "ts", "datetime", "date")

#: The provenance contract (OWASP ASI06: provenance on every memory write).
CONTRACT_FIELDS: dict[str, tuple[str, ...]] = {
    "source_id": _SOURCE_KEYS,
    "ingestion_timestamp": (),  # any record-time field; see _has_ingest_time
    "content_hash": ("content_hash", "hash", "sha256", "sha1", "md5", "checksum",
                     "digest", "etag", "doc_hash", "source_hash", "file_hash"),
    "embedding_model": ("embedding_model", "embedding_model_version", "embedder",
                        "embedding_version", "model", "model_name", "model_version",
                        "encoder"),
    "ingesting_principal": ("ingested_by", "uploaded_by", "created_by", "added_by",
                            "indexed_by", "submitted_by", "principal", "actor",
                            "ingest_user", "uploader"),
}
_CONTRACT_BITS = {name: 1 << i for i, name in enumerate(CONTRACT_FIELDS)}

_WS = re.compile(r"\s+")


def normalize_text(text: str, max_chars: int) -> str:
    return _WS.sub(" ", text[:max_chars]).strip().lower()


def text_digest(normalized: str, key: bytes) -> str:
    return hashlib.blake2b(normalized.encode("utf-8", "replace"), digest_size=10,
                           key=key).hexdigest()


def source_of(metadata: Mapping[str, Any]) -> str | None:
    for k in _SOURCE_KEYS:
        v = metadata.get(k)
        if v:
            return str(v)
    return None


def _present(value: Any) -> bool:
    return value is not None and not (isinstance(value, str) and not value.strip())


def position_of(metadata: Mapping[str, Any]) -> str | None:
    base = next((str(metadata[k]) for k in POSITION_KEYS if _present(metadata.get(k))), None)
    if base is None:
        return None
    qual = next((str(metadata[k]) for k in POSITION_QUALIFIERS
                 if _present(metadata.get(k))), None)
    return f"{qual}:{base}" if qual is not None else base


@dataclass(slots=True)
class ChunkRecord:
    id: str
    source: str | None = None
    position: str | None = None
    text_hash: str | None = None
    text_len: int = 0
    has_embedding: bool = False
    #: record-time field -> epoch seconds
    times: dict[str, float] | None = None
    #: version field -> raw value as text
    versions: dict[str, str] | None = None
    contract: int = 0


def build_record(chunk_id: str, normalized: str | None, metadata: Mapping[str, Any] | None,
                 *, has_embedding: bool, key: bytes) -> ChunkRecord:
    """``normalized`` is the chunk text after :func:`normalize_text`."""
    meta = metadata or {}
    rec = ChunkRecord(id=str(chunk_id), source=source_of(meta), position=position_of(meta),
                      has_embedding=has_embedding)
    if normalized:
        rec.text_len = len(normalized)
        rec.text_hash = text_digest(normalized, key)
    times: dict[str, float] = {}
    versions: dict[str, str] = {}
    lowered = {str(k).lower(): v for k, v in meta.items()}
    for k, v in lowered.items():
        if k in VERSION_KEYS and _present(v) and not isinstance(v, (dict, list)):
            versions[k] = str(v)
        if looks_like_record_time(k):
            when = parse_timestamp(v)
            if when is not None:
                times[k] = when.timestamp()
    rec.times = times or None
    rec.versions = versions or None
    bits = 0
    for name, keys in CONTRACT_FIELDS.items():
        if name == "ingestion_timestamp":
            if times:
                bits |= _CONTRACT_BITS[name]
        elif any(_present(lowered.get(k)) for k in keys):
            bits |= _CONTRACT_BITS[name]
    rec.contract = bits
    return rec


def contract_shares(records: list[ChunkRecord], *,
                    collection_embedding_model: str | None = None) -> dict[str, Any]:
    total = len(records)
    counts = {name: sum(1 for r in records if r.contract & bit)
              for name, bit in _CONTRACT_BITS.items()}
    out: dict[str, Any] = {
        "records": total,
        "fields": {name: {"chunks": counts[name],
                          "share": round(counts[name] / total, 4) if total else 0.0}
                   for name in CONTRACT_FIELDS},
        "complete_records": sum(1 for r in records
                                if r.contract == (1 << len(CONTRACT_FIELDS)) - 1),
    }
    if collection_embedding_model:
        # A collection-level model declaration covers every chunk in it.
        out["embedding_model_declared_by_collection"] = True
    return out


def choose_time_field(records: list[ChunkRecord]) -> tuple[str | None, dict[str, int]]:
    """The field read as ingestion time: an ingestion-named field that most
    records carry, else the most-carried record-time field (ties by name)."""
    counts: dict[str, int] = {}
    for r in records:
        for k in r.times or ():
            counts[k] = counts.get(k, 0) + 1
    if not counts:
        return None, counts
    best = max(counts.values())
    preferred = [k for k in INGEST_TIME_PREFERENCE if counts.get(k, 0) >= 0.5 * best]
    if preferred:
        return preferred[0], counts
    return min(counts, key=lambda k: (-counts[k], k)), counts


def ingest_time(rec: ChunkRecord, field_name: str | None) -> float | None:
    if field_name is None or not rec.times:
        return None
    return rec.times.get(field_name)


def rare_threshold(total: int, fraction: float, floor: int,
                   source_counts: Mapping[str, int] | None = None) -> int:
    """Chunk count at or below which a source is "rare".

    At most ``fraction`` of the collection (never below ``floor``), and never
    more than half the median source size: in a corpus of ten-chunk documents
    a ten-chunk document is typical, whatever share of the whole it is.
    """
    bar = max(floor, int(total * fraction))
    if source_counts:
        sizes = sorted(source_counts.values())
        mid = len(sizes) // 2
        med = sizes[mid] if len(sizes) % 2 else (sizes[mid - 1] + sizes[mid]) / 2
        bar = min(bar, max(1, int(med / 2)))
    return bar


def rarity_informative(records: list[ChunkRecord], rare_thr: int,
                       source_counts: Mapping[str, int]) -> bool:
    """Whether "comes from a rare source" distinguishes anything here.

    When most chunks come from small or unnamed sources (tickets, emails),
    every chunk is "rare" and the signal is switched off.
    """
    total = len(records)
    if not total:
        return False
    rare = sum(c for c in source_counts.values() if c <= rare_thr)
    unattributed = sum(1 for r in records if r.source is None)
    return (rare + unattributed) / total <= 0.2


@dataclass
class DetectorReport:
    """What one detector observed, before it becomes a check outcome."""

    check: str
    findings: list[Finding] = field(default_factory=list)
    #: True when something was observed that the outcome should record as failed.
    detected: bool = False
    #: A coverage shortfall (sample, cap). Makes the outcome partial.
    limitation: str = ""
    #: The data cannot answer the question (no version keys, say). The outcome
    #: is inconclusive, but every record *was* read: not a coverage gap.
    data_gap: str = ""
    note: str = ""
    error: str | None = None
    coverage: dict[str, Any] = field(default_factory=dict)
    stats: dict[str, Any] = field(default_factory=dict)
    #: Chunk ids this detector flagged, for cross-detector corroboration.
    flagged_ids: set[str] = field(default_factory=set)


def make_finding(*, title: str, severity: Severity, category: str, store: str,
                 collection: str, description: str, evidence: dict[str, Any],
                 remediation: str) -> Finding:
    return Finding(id=f"find-{uuid.uuid4().hex[:10]}", title=title, severity=severity,
                   category=category, store=store, collection=collection,
                   description=description, evidence=evidence, remediation=remediation)


def new_run_key() -> bytes:
    """A per-run key for text digests, so digests cannot be compared off-box."""
    return uuid.uuid4().bytes
