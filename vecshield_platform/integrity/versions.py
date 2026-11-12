"""Outdated, superseded and conflicting chunks (check ``chunk_versions``).

A RAG store that re-ingests an edited document without deleting the old
chunks keeps serving the old text. The EDPB's April 2025 report on LLM privacy
risks names retrieval of outdated information as a harm, and for personal data
it is an accuracy failure (GDPR Art. 5(1)(d)) that survives a rectification
(Art. 16) whenever the old chunk is still retrievable.

Chunks are grouped by their source document key (the same keys provenance
analysis reads). Three observations, each report-only:

(a) **Superseded generations.** A document-version field (explicit version or
    revision, an opaque content/etag hash, or a modification timestamp) with
    more than one generation under one source means older chunks coexist with
    newer ones. Timestamp versions within ``generation_gap_seconds`` of each
    other are one generation (per-chunk write times are not generations), and
    a hash-like field whose value is unique to nearly every chunk of multi-chunk
    documents is a per-chunk hash, not a document version, and is ignored. The
    newest generation is identified by version order, then by timestamp, then
    by ingestion time; when none can order them the generations are reported as
    coexisting with the order unknown.

(b) **Conflicting chunks.** The same source and chunk position holding
    different text. When a source also shows re-ingestion (an identical text
    at the same position, or several generations) the conflict is a stale copy
    and MEDIUM; otherwise LOW. If most positioned sources collide, the position
    key is evidently not unique per document (a per-page index, say) and only
    re-ingested sources are reported.

(c) **Source manifest** (optional, customer-supplied list of
    ``{source, version|hash|updated_at, deleted}``): chunks of deleted sources,
    chunks older than the manifest's current version, and chunks whose source
    the manifest does not know.

Severity: MEDIUM for superseded, stale-vs-manifest or deleted-source chunks;
HIGH only when such a chunk is also in ``sensitive_ids`` (the classifier found
personal or regulated data in it): stale personal data that is still served
after it was corrected or deleted is a direct accuracy/erasure failure, not a
quality concern. Unknown-to-manifest sources are LOW.

Outcome: ``failed`` when any of the above is observed; ``inconclusive`` (a
data gap, not a coverage gap) when no chunk carries a version field and no
manifest was supplied; ``passed`` otherwise.
"""

from __future__ import annotations

import re
from collections import defaultdict
from statistics import median
from typing import Any, Iterable, Mapping, Sequence

from vecshield.models import Severity
from vecshield_platform.integrity.limits import IntegrityLimits
from vecshield_platform.integrity.provenance import _SOURCE_KEYS
from vecshield_platform.integrity.records import (
    OPAQUE_VERSION_KEYS,
    TIMESTAMP_VERSION_KEYS,
    VERSION_KEYS,
    ChunkRecord,
    DetectorReport,
    ingest_time,
    make_finding,
)
from vecshield_platform.scan.retention import parse_timestamp

CHECK = "chunk_versions"
_NUM = re.compile(r"\d+")
_MANIFEST_VERSION_KEYS = ("version", "revision", "hash", "content_hash", "etag", "sha256",
                          "checksum", "updated_at", "last_modified", "modified")


def _per_chunk_fields(by_source: Mapping[str, list[ChunkRecord]]) -> set[str]:
    """Opaque fields whose value is unique to (nearly) every chunk of a document."""
    out: set[str] = set()
    for key in OPAQUE_VERSION_KEYS:
        judged = unique = 0
        for recs in by_source.values():
            vals = [r.versions[key] for r in recs if r.versions and key in r.versions]
            if len(vals) >= 3:
                judged += 1
                unique += len(set(vals)) == len(vals)
        if judged and unique / judged >= 0.8:
            out.add(key)
    return out


def _order_key(field: str, value: str) -> tuple | None:
    if field in TIMESTAMP_VERSION_KEYS:
        when = parse_timestamp(value)
        return (when.timestamp(),) if when else None
    if field in OPAQUE_VERSION_KEYS:
        return None
    # Version semantics, not decimals: 1.10 is newer than 1.2.
    nums = _NUM.findall(value)
    return tuple(int(n) for n in nums) if nums else None


def _generations(field: str, recs: list[ChunkRecord], limits: IntegrityLimits,
                 time_field: str | None) -> tuple[list[list[ChunkRecord]], bool]:
    """Generations oldest->newest, and whether that order is known."""
    carrying = [r for r in recs if r.versions and field in r.versions]
    if field in TIMESTAMP_VERSION_KEYS:
        stamped = []
        for r in carrying:
            when = parse_timestamp(r.versions[field])
            if when is not None:
                stamped.append((when.timestamp(), r))
        stamped.sort(key=lambda p: (p[0], p[1].id))
        gens: list[list[ChunkRecord]] = []
        last = None
        for ts, r in stamped:
            if last is None or ts - last > limits.generation_gap_seconds:
                gens.append([])
            gens[-1].append(r)
            last = ts
        return gens, True
    by_value: dict[str, list[ChunkRecord]] = defaultdict(list)
    for r in carrying:
        by_value[r.versions[field]].append(r)
    values = list(by_value)
    keys = {v: _order_key(field, v) for v in values}
    if all(keys[v] is not None for v in values):
        values.sort(key=lambda v: (keys[v], v))
        return [by_value[v] for v in values], True
    # Fall back to when each generation was ingested.
    med = {}
    for v in values:
        ts = [t for r in by_value[v] if (t := ingest_time(r, time_field)) is not None]
        med[v] = median(ts) if ts else None
    if all(med[v] is not None for v in values):
        values.sort(key=lambda v: (med[v], v))
        return [by_value[v] for v in values], True
    values.sort()
    return [by_value[v] for v in values], False


def _manifest_entries(manifest: Sequence[Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
    out: dict[str, Mapping[str, Any]] = {}
    for entry in manifest or ():
        if not isinstance(entry, Mapping):
            continue
        src = next((str(entry[k]) for k in _SOURCE_KEYS if entry.get(k)), None)
        if src is not None:
            out[src] = entry
    return out


def _stale_against(entry: Mapping[str, Any], recs: list[ChunkRecord],
                   limits: IntegrityLimits, time_field: str | None) -> list[ChunkRecord]:
    """Chunks of one source that predate the manifest's current version."""
    stale: list[ChunkRecord] = []
    m_key = next((k for k in _MANIFEST_VERSION_KEYS if entry.get(k) not in (None, "")), None)
    if m_key is None:
        return stale
    m_val = str(entry[m_key])
    m_time = parse_timestamp(entry[m_key]) if m_key in (
        "updated_at", "last_modified", "modified") else None
    for r in recs:
        vers = r.versions or {}
        if m_time is not None:
            chunk_ts = next((parse_timestamp(vers[k]) for k in TIMESTAMP_VERSION_KEYS
                             if k in vers), None)
            ref = chunk_ts.timestamp() if chunk_ts else ingest_time(r, time_field)
            if ref is not None and ref < m_time.timestamp() - limits.generation_gap_seconds:
                stale.append(r)
            continue
        if m_key in ("version", "revision"):
            cand = next((vers[k] for k in ("version", "doc_version", "document_version",
                                           "revision", "rev") if k in vers), None)
        else:
            cand = vers.get(m_key) or next((vers[k] for k in sorted(OPAQUE_VERSION_KEYS)
                                            if k in vers), None)
        if cand is not None and cand != m_val:
            stale.append(r)
    return stale


def analyze_versions(
    *,
    store: str,
    collection: str,
    records: list[ChunkRecord],
    limits: IntegrityLimits,
    time_field: str | None,
    sensitive_ids: Iterable[str] | None = None,
    source_manifest: Sequence[Mapping[str, Any]] | None = None,
) -> DetectorReport:
    report = DetectorReport(check=CHECK)
    sensitive = set(sensitive_ids or ())
    by_source: dict[str, list[ChunkRecord]] = defaultdict(list)
    for r in records:
        if r.source:
            by_source[r.source].append(r)
    versioned = sum(1 for r in records if r.versions)
    positioned = sum(1 for r in records if r.position is not None)
    total = len(records)
    per_chunk = _per_chunk_fields(by_source)
    report.stats = {"sources": len(by_source), "versioned_share":
                    round(versioned / total, 4) if total else 0.0,
                    "positioned_share": round(positioned / total, 4) if total else 0.0,
                    "per_chunk_fields_ignored": sorted(per_chunk)}

    # --- (a) superseded generations -------------------------------------
    superseded: list[dict[str, Any]] = []
    superseded_sensitive = 0
    gen_of: dict[str, int] = {}
    multi_gen_sources: set[str] = set()
    fields_used: set[str] = set()
    for src in sorted(by_source):
        recs = by_source[src]
        field = next((k for k in VERSION_KEYS if k not in per_chunk and any(
            r.versions and k in r.versions for r in recs)), None)
        if field is None:
            continue
        fields_used.add(field)
        gens, ordered = _generations(field, recs, limits, time_field)
        for gi, g in enumerate(gens):
            for r in g:
                gen_of[r.id] = gi
        if len(gens) < 2:
            continue
        multi_gen_sources.add(src)
        old = [r for g in gens[:-1] for r in g] if ordered else []
        sens = sum(1 for r in (old if ordered else [r for g in gens for r in g])
                   if r.id in sensitive)
        if ordered:
            superseded_sensitive += sum(1 for r in old if r.id in sensitive)
        superseded.append({
            "chunk_id": (old or gens[0])[0].id,
            "source": src, "field": field, "generations": len(gens),
            "order_known": ordered,
            "generation_sizes": [len(g) for g in gens],
            "superseded_chunks": len(old),
            "superseded_ids": [r.id for r in old[:limits.max_examples]],
            "sensitive_chunks": sens,
        })
        report.flagged_ids.update(r.id for r in old)
    if superseded:
        n_old = sum(e["superseded_chunks"] for e in superseded)
        report.findings.append(make_finding(
            title=f"Superseded document versions still stored in '{collection}'",
            severity=Severity.HIGH if superseded_sensitive else Severity.MEDIUM,
            category=CHECK, store=store, collection=collection,
            description=(
                f"{len(superseded)} source document(s) have more than one version "
                f"generation stored side by side ({n_old} chunk(s) belong to an older "
                "generation). Retrieval can return the outdated text alongside, or "
                "instead of, the current one."
                + (f" {superseded_sensitive} superseded chunk(s) contain data the "
                   "classifier marked sensitive: corrected personal data that is "
                   "still retrievable." if superseded_sensitive else "")),
            evidence={"count": len(superseded), "superseded_chunks": n_old,
                      "sensitive_superseded_chunks": superseded_sensitive,
                      "version_fields": sorted(fields_used),
                      "generation_gap_seconds": limits.generation_gap_seconds,
                      "references": ["GDPR Art. 5(1)(d), Art. 16",
                                     "EDPB LLM privacy risks report (April 2025)"],
                      "examples": superseded[:limits.max_examples]},
            remediation=(
                "Delete the older generation's chunks (delete-then-insert or upsert "
                "by source and position on every re-ingestion) and re-run the scan.")))
        report.detected = True

    # --- (b) conflicting chunks at one position -------------------------
    positions: dict[tuple[str, str], list[ChunkRecord]] = defaultdict(list)
    for src, recs in by_source.items():
        for r in recs:
            if r.position is not None:
                positions[(src, r.position)].append(r)
    positioned_sources = {s for s, _ in positions}
    colliding_sources: set[str] = set()
    reingested: set[str] = set(multi_gen_sources)
    conflicts_by_source: dict[str, list[list[ChunkRecord]]] = defaultdict(list)
    duplicate_positions = 0
    for (src, _pos), recs in positions.items():
        if len(recs) < 2:
            continue
        colliding_sources.add(src)
        hashes = [r.text_hash for r in recs]
        if len(set(hashes)) < len(hashes):
            duplicate_positions += 1
            reingested.add(src)
        # Different text within one generation (or with no generation at all).
        by_gen: dict[int | None, list[ChunkRecord]] = defaultdict(list)
        for r in recs:
            by_gen[gen_of.get(r.id)].append(r)
        for grp in by_gen.values():
            if len({r.text_hash for r in grp}) >= 2:
                conflicts_by_source[src].append(grp)
    collision_share = (len(colliding_sources) / len(positioned_sources)
                       if positioned_sources else 0.0)
    key_not_unique = collision_share > limits.position_collision_share
    report.stats.update({"position_collision_share": round(collision_share, 4),
                         "duplicate_positions": duplicate_positions,
                         "position_key_not_unique": key_not_unique})
    conflict_examples: list[dict[str, Any]] = []
    stale_conflict = False
    for src in sorted(conflicts_by_source):
        if key_not_unique and src not in reingested:
            continue
        for grp in conflicts_by_source[src]:
            conflict_examples.append({
                "chunk_id": grp[0].id, "source": src, "position": grp[0].position,
                "chunk_ids": [r.id for r in grp[:limits.max_examples]],
                "distinct_texts": len({r.text_hash for r in grp}),
                "source_reingested": src in reingested,
            })
            stale_conflict = stale_conflict or src in reingested
            report.flagged_ids.update(r.id for r in grp)
    if conflict_examples:
        report.findings.append(make_finding(
            title=f"Conflicting chunks at the same document position in '{collection}'",
            severity=Severity.MEDIUM if stale_conflict else Severity.LOW,
            category=CHECK, store=store, collection=collection,
            description=(
                f"{len(conflict_examples)} document position(s) hold two or more "
                "different texts. A retriever can return contradictory passages for "
                "the same part of one document."
                + (" Some of these sources were evidently ingested more than once, so "
                   "one of the texts is likely a stale copy." if stale_conflict else "")),
            evidence={"count": len(conflict_examples),
                      "position_key_not_unique": key_not_unique,
                      "examples": conflict_examples[:limits.max_examples]},
            remediation=(
                "Key chunks by source and position and replace, rather than append, "
                "on re-ingestion; delete the stale copy.")))
        report.detected = True

    # --- (c) source manifest --------------------------------------------
    if source_manifest is not None:
        entries = _manifest_entries(source_manifest)
        deleted, stale, unknown = [], [], []
        for src in sorted(by_source):
            recs = by_source[src]
            entry = entries.get(src)
            if entry is None:
                unknown.append((src, recs))
            elif entry.get("deleted") is True:
                deleted.append((src, recs))
            else:
                old = _stale_against(entry, recs, limits, time_field)
                if old:
                    stale.append((src, old))
        report.stats.update({"manifest_sources": len(entries),
                             "deleted_sources_present": len(deleted),
                             "stale_sources": len(stale),
                             "sources_unknown_to_manifest": len(unknown)})
        for items, title, base_sev, desc, fix in (
            (deleted, f"Chunks from deleted sources still stored in '{collection}'",
             Severity.MEDIUM,
             "source(s) the manifest marks deleted still have chunks in the store.",
             "Delete every chunk of a deleted source and verify with a re-scan."),
            (stale, f"Chunks older than the current source version in '{collection}'",
             Severity.MEDIUM,
             "source(s) have chunks that predate the version the manifest lists as "
             "current.",
             "Re-ingest the current version and delete the older chunks."),
            (unknown, f"Chunks from sources missing from the manifest in '{collection}'",
             Severity.LOW,
             "source(s) in the store do not appear in the source manifest. They may be "
             "legacy content, or content that did not arrive through the governed "
             "pipeline.",
             "Confirm each source's origin; add it to the manifest or remove it."),
        ):
            if not items:
                continue
            chunks = [r for _, rs in items for r in rs]
            sens = sum(1 for r in chunks if r.id in sensitive)
            severity = (Severity.HIGH if sens and base_sev == Severity.MEDIUM else base_sev)
            report.findings.append(make_finding(
                title=title, severity=severity, category=CHECK, store=store,
                collection=collection,
                description=(f"{len(items)} {desc} ({len(chunks)} chunk(s)"
                             + (f", {sens} marked sensitive" if sens else "") + ")."),
                evidence={"count": len(items), "chunks": len(chunks),
                          "sensitive_chunks": sens,
                          "examples": [{"chunk_id": rs[0].id, "source": s,
                                        "chunks": len(rs),
                                        "chunk_ids": [r.id for r in rs[:limits.max_examples]]}
                                       for s, rs in items[:limits.max_examples]]},
                remediation=fix))
            report.detected = True
            if base_sev == Severity.MEDIUM:
                report.flagged_ids.update(r.id for r in chunks)

    report.stats.update({"superseded_sources": len(superseded),
                         "conflicting_positions": len(conflict_examples),
                         "version_fields": sorted(fields_used)})
    report.coverage = {"records": total, "versioned_share": report.stats["versioned_share"],
                       "manifest_supplied": source_manifest is not None}
    if not by_source:
        report.data_gap = ("No chunk names its source document, so versions cannot be "
                           "grouped.")
    elif not fields_used and source_manifest is None and not report.detected:
        lacking = 1 - (versioned / total if total else 0.0)
        report.data_gap = (
            f"No chunk carries a document version, hash or modification time "
            f"({lacking:.0%} lack one) and no source manifest was supplied, so "
            "superseded content cannot be identified.")
    elif fields_used and versioned < total:
        report.note = (f"{total - versioned} chunk(s) carry no version field and were "
                       "not assessed for supersession.")
    return report
