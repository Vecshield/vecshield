"""Ingestion bursts and the provenance contract (check ``ingestion_burst``).

**Bursts.** The ingestion time of each chunk is read from its metadata with
the same record-time inference retention analysis uses (subject dates such as
a date of birth are never read as ingestion times), preferring fields named
for ingestion (``ingested_at``, ``indexed_at``, ``created_at`` ...). Chunks are
bucketed by hour (or by day when the history spans more than three days) and
a bucket is a spike when its count is a robust-z outlier over the non-empty
buckets (>= ``burst_z``), at least ``burst_ratio`` x the median bucket and at
least ``burst_min_chunks`` chunks.

A spike alone is ordinary (a scheduled import, a re-index), so a spike is
reported only when it is *correlated with provenance*: at least half its
chunks come from sources first seen in that bucket, or from rare or
unattributed sources. It is LOW then, and MEDIUM when the burst also contains
chunks another integrity detector flagged (prompt injection, a suspicious
cluster, a hub, an embedding outlier). Other spikes are listed in the stats.

**Provenance contract.** OWASP's Agentic Top 10 (ASI06, memory poisoning)
recommends provenance on every memory write, and OWASP LLM08:2025 (vector and
embedding weaknesses) asks for traceable ingestion. The contract report gives
the share of chunks carrying a source id, an ingestion timestamp, a content
hash, the embedding model/version and the ingesting principal, read from
common key names (see ``records.CONTRACT_FIELDS``). It is evidence for a
reviewer; the existing ``provenance`` check already raises the source-coverage
finding, so the contract adds no second finding for the same gap.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Iterable

import numpy as np

from vecshield.models import Severity
from vecshield_platform.integrity.limits import IntegrityLimits
from vecshield_platform.integrity.records import (
    ChunkRecord,
    DetectorReport,
    choose_time_field,
    contract_shares,
    ingest_time,
    make_finding,
    rare_threshold,
)

CHECK = "ingestion_burst"
_MAD_SCALE = 1.4826


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def analyze_ingestion(
    *,
    store: str,
    collection: str,
    records: list[ChunkRecord],
    limits: IntegrityLimits,
    collection_embedding_model: str | None = None,
    corroborating_ids: Iterable[str] = (),
) -> DetectorReport:
    report = DetectorReport(check=CHECK)
    contract = contract_shares(records, collection_embedding_model=collection_embedding_model)
    field_name, candidates = choose_time_field(records)
    report.stats = {"provenance_contract": contract, "time_field": field_name,
                    "time_field_candidates": candidates}
    report.coverage = {"records": len(records), "time_field": field_name}
    if field_name is None:
        report.data_gap = ("No chunk records when it was ingested, so ingestion bursts "
                           "cannot be observed.")
        return report

    dated = [(t, r) for r in records if (t := ingest_time(r, field_name)) is not None]
    dated_share = len(dated) / len(records) if records else 0.0
    report.coverage["dated_share"] = round(dated_share, 4)
    stamps = np.asarray([t for t, _ in dated], dtype=np.float64)
    lo, hi = float(stamps.min()), float(stamps.max())
    bucket = 3600.0 if hi - lo <= 3 * 86400 else 86400.0
    if (hi - lo) / bucket + 1 > limits.burst_max_buckets:
        bucket = (hi - lo) / (limits.burst_max_buckets - 1)
    by_bucket: dict[int, list[ChunkRecord]] = defaultdict(list)
    for t, r in dated:
        by_bucket[int((t - lo) // bucket)].append(r)
    report.stats.update({"bucket_seconds": bucket, "non_empty_buckets": len(by_bucket),
                         "dated_share": round(dated_share, 4),
                         "first": _iso(lo), "last": _iso(hi)})
    if len(by_bucket) < limits.burst_min_buckets:
        report.data_gap = (f"Chunks were ingested in {len(by_bucket)} "
                           f"{'hour' if bucket == 3600.0 else 'time'} window(s); at least "
                           f"{limits.burst_min_buckets} are needed for a baseline.")
        return report

    keys = sorted(by_bucket)
    counts = np.asarray([len(by_bucket[k]) for k in keys], dtype=np.float64)
    median = float(np.median(counts))
    mad = float(np.median(np.abs(counts - median)))
    scale = mad * _MAD_SCALE if mad > 0 else max(float(counts.std()), 1.0)
    z = (counts - median) / scale

    first_seen: dict[str, float] = {}
    for t, r in dated:
        if r.source and (r.source not in first_seen or t < first_seen[r.source]):
            first_seen[r.source] = t
    source_counts = Counter(r.source for r in records if r.source)
    rare_thr = rare_threshold(len(records), limits.rare_source_fraction,
                              limits.cluster_min_size, source_counts)
    corroborating = set(corroborating_ids)

    spikes: list[dict[str, Any]] = []
    reported: list[dict[str, Any]] = []
    for i, k in enumerate(keys):
        c = counts[i]
        if not (z[i] >= limits.burst_z and c >= limits.burst_min_chunks
                and c >= limits.burst_ratio * median):
            continue
        members = by_bucket[k]
        start = lo + k * bucket
        new = {r.source for r in members
               if r.source and start <= first_seen[r.source] < start + bucket}
        new_chunks = sum(1 for r in members if r.source in new)
        rare_chunks = sum(1 for r in members
                          if r.source is None or source_counts[r.source] <= rare_thr)
        overlap = sorted({r.id for r in members} & corroborating)
        entry = {
            "window_start": _iso(start), "window_seconds": bucket, "chunks": int(c),
            "median_per_window": median, "z": round(float(z[i]), 2),
            "new_source_share": round(new_chunks / c, 3),
            "rare_or_unattributed_share": round(rare_chunks / c, 3),
            "new_sources": sorted(new)[:5],
            "flagged_chunks": overlap[:limits.max_examples],
            "chunk_ids": [r.id for r in members[:limits.max_examples]],
        }
        spikes.append(entry)
        if new_chunks / c >= 0.5 or rare_chunks / c >= 0.5:
            reported.append(entry)
            report.flagged_ids.update(r.id for r in members)

    corroborated = [e for e in reported if e["flagged_chunks"]]
    plain = [e for e in reported if not e["flagged_chunks"]]
    common = {"time_field": field_name, "bucket_seconds": bucket, "burst_z": limits.burst_z,
              "provenance_contract": contract,
              "references": ["OWASP Agentic Top 10 ASI06", "OWASP LLM08:2025"]}
    for group, severity, title, extra in (
        (corroborated, Severity.MEDIUM,
         f"Ingestion burst containing flagged chunks in '{collection}'",
         " Chunks in the burst were also flagged by another integrity check."),
        (plain, Severity.LOW, f"Ingestion burst from new or rare sources in '{collection}'",
         " A legitimate new batch looks the same; confirm it was expected."),
    ):
        if not group:
            continue
        report.findings.append(make_finding(
            title=title, severity=severity, category=CHECK, store=store,
            collection=collection,
            description=(
                f"{len(group)} ingestion window(s) received far more chunks than usual "
                f"(robust z >= {limits.burst_z}), mostly from sources first seen in that "
                "window or from rare or unattributed sources. Poisoning campaigns "
                "often arrive as one burst from an unfamiliar source." + extra),
            evidence={**common, "count": len(group),
                      "examples": [{**e, "chunk_id": e["chunk_ids"][0]}
                                   for e in group[:limits.max_examples]]},
            remediation=(
                "Identify who or what ingested the burst (record the ingesting "
                "principal on every write) and confirm the sources are authorised; "
                "quarantine the chunks if not.")))
    report.detected = bool(reported)
    report.stats.update({"spikes": len(spikes), "reported_spikes": len(reported),
                         "unreported_spikes": [s for s in spikes if s not in reported][:5]})
    if dated_share < 0.95:
        msg = (f"Only {dated_share:.0%} of chunks carry '{field_name}', so bursts among "
               "undated chunks cannot be seen.")
        if report.detected:
            report.note = msg
        else:
            report.data_gap = msg
    return report
