"""Integrity scan: one pass over a collection, several detectors, unified findings.

Combines prompt-injection (text), embedding anomaly (vectors, two-sided and
norm-aware), provenance (metadata), corpus duplication and poison clusters,
retrieval hubness, ingestion bursts with the provenance contract, and
superseded/conflicting chunk versions into a single ScanJob so results
render/serialize like every other VecShield scan.

Every detector is report-only. The chunk stream is read once; each detector
keeps a bounded buffer (the embedding reservoir, compact per-chunk records,
MinHash signatures) and is finalised after the pass. Each records its own
check outcome, so a failure in one leaves the others intact.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

import numpy as np

from vecshield_platform.compliance.fingerprint import apply_fingerprints
from vecshield_platform.connectors.base import Connector, fill_declared_embedding_model
from vecshield_platform.coverage import (
    COUNT_UNKNOWN_REASON,
    check_outcome,
    count_known,
    read_errors_for,
    set_job_coverage,
)
from vecshield_platform.progress import chunks_bound_for, tick as progress_tick
from vecshield_platform.integrity.anomaly import StreamingAnomalyDetector
from vecshield_platform.integrity.duplication import (
    SensitiveFingerprintRegistry,
    TextDuplicationCollector,
    analyze_duplication,
)
from vecshield_platform.integrity.hubness import analyze_hubness
from vecshield_platform.integrity.ingestion import analyze_ingestion
from vecshield_platform.integrity.injection import scan_text
from vecshield_platform.integrity.limits import IntegrityLimits
from vecshield_platform.integrity.provenance import analyze_provenance
from vecshield_platform.integrity.records import (
    ChunkRecord,
    DetectorReport,
    build_record,
    choose_time_field,
    new_run_key,
    normalize_text,
)
from vecshield_platform.integrity.versions import analyze_versions
from vecshield.models import Collection, Finding, ScanJob, Severity

#: Every check outcome an integrity job records, in emission order.
CHECKS = ("prompt_injection", "embedding_anomaly", "provenance", "corpus_duplication",
          "retrieval_hubness", "ingestion_burst", "chunk_versions")
_KNOWN_METRICS = ("cosine", "dot", "euclidean", "manhattan")


def scan_integrity(
    connector: Connector,
    collection: str,
    *,
    z_threshold: float = 3.5,
    max_chunks: int = 50000,
    anomaly_sample_size: int = 50000,
    anomaly_batch_size: int = 2048,
    collection_meta: Collection | None = None,
    source_manifest: Sequence[Mapping[str, Any]] | None = None,
    sensitive_ids: Iterable[str] | None = None,
    limits: IntegrityLimits | None = None,
    boilerplate_patterns: Sequence[str] = (),
    sensitive_registry: SensitiveFingerprintRegistry | None = None,
) -> ScanJob:
    """Scan one collection.

    ``collection_meta`` supplies the index's distance metric; when omitted it
    is read from the connector's inventory. ``source_manifest`` is an optional
    customer list of ``{source, version|hash|updated_at, deleted}`` for the
    versions check. ``sensitive_ids`` are chunk ids another pass classified as
    sensitive (duplication and supersession severity). ``sensitive_registry``
    is shared across collection scans to find sensitive copies in other
    collections. ``limits`` defaults to :meth:`IntegrityLimits.from_env`.
    """
    if max_chunks < 1 or anomaly_batch_size < 1:
        raise ValueError("max_chunks and anomaly_batch_size must be positive")
    limits = limits or IntegrityLimits.from_env()
    store = connector.describe()
    fill_declared_embedding_model(connector, store.collections)
    job = ScanJob(id=f"intg-{uuid.uuid4().hex[:12]}", store=store.name)
    checks = CHECKS
    meta = collection_meta or next(
        (c for c in store.collections if c.name == collection), None)
    raw_metric = getattr(meta, "distance_metric", None)
    metric = raw_metric if raw_metric in _KNOWN_METRICS else None
    sensitive = set(sensitive_ids or ())
    if not getattr(connector, "content_enumerable", True):
        job.stats = {"collection": collection, "chunks_scanned": 0,
                     "vectors_checked": 0, "injections": 0, "provenance_coverage": 0}
        set_job_coverage(job, [check_outcome(
            check, store.name, collection, outcome="unsupported",
            reason="Content enumeration is unsupported.") for check in checks])
        job.finished_at = datetime.now(timezone.utc)
        return job

    metadatas: list[dict] = []
    injections: list[dict] = []

    # Stream embeddings through a bounded-memory anomaly detector in batches
    # rather than accumulating every vector — a large collection would otherwise
    # be an O(N x dim) blow-up. Collections up to anomaly_sample_size are scored
    # exactly; larger ones are fit on a uniform reservoir sample.
    # Direction is scored in cosine geometry for every metric (as before);
    # inner-product stores additionally have raw norms scored, because inner
    # product rewards magnitude.
    anomaly = StreamingAnomalyDetector(
        z_threshold=z_threshold, metric="cosine",
        sample_size=anomaly_sample_size, seed=limits.seed, two_sided=True,
        near_z=limits.near_z, near_ratio=limits.near_ratio,
        score_norms=metric == "dot", norm_z=limits.norm_z, norm_ratio=limits.norm_ratio)
    run_key = new_run_key()
    records: list[ChunkRecord] = []
    records_capped = 0
    text_dups = TextDuplicationCollector(limits, allow_patterns=boilerplate_patterns)
    cross_copies: dict[str, list[tuple[str, str]]] = {}
    _emb_batch_ids: list[str] = []
    _emb_batch: list[list[float]] = []
    anomaly_error = None

    def _flush_embeddings() -> None:
        nonlocal anomaly_error
        if _emb_batch:
            try:
                anomaly.add_batch(_emb_batch_ids, _emb_batch)
            except Exception as exc:
                anomaly_error = type(exc).__name__
            _emb_batch_ids.clear()
            _emb_batch.clear()

    scanned = 0
    capped = False
    read_error = None
    text_missing = 0
    text_truncated = 0
    # Read errors from the classification pass, or another collection's
    # pass, are not this read's.
    reset_read_errors = getattr(connector, "reset_read_errors", None)
    if callable(reset_read_errors):
        reset_read_errors()
    inventoried = next((c for c in store.collections if c.name == collection), None)
    integrity_bound = chunks_bound_for(
        [inventoried] if inventoried is not None else [], max_chunks)
    progress_tick(collection=collection, chunks_read=0, chunks_bound=integrity_bound)
    try:
        for chunk in connector.iter_chunks(collection):
            if scanned >= max_chunks:
                capped = True
                break
            scanned += 1
            progress_tick(collection=collection, chunks_read=scanned,
                          chunks_bound=integrity_bound)
            metadatas.append(chunk.metadata or {})
            normalized = (normalize_text(chunk.text, limits.max_text_chars)
                          if chunk.text else None)
            if len(records) < limits.record_cap:
                records.append(build_record(
                    chunk.id, normalized, chunk.metadata,
                    has_embedding=bool(chunk.embedding), key=run_key))
                text_dups.add(len(records) - 1, normalized)
            else:
                records_capped += 1
            if (sensitive_registry is not None and normalized
                    and str(chunk.id) in sensitive):
                prior = sensitive_registry.register(
                    sensitive_registry.digest(normalized), collection, str(chunk.id))
                if prior:
                    cross_copies[str(chunk.id)] = prior

            if chunk.embedding:
                _emb_batch_ids.append(chunk.id)
                _emb_batch.append(chunk.embedding)
                if len(_emb_batch) >= anomaly_batch_size:
                    _flush_embeddings()

            surfaces = [chunk.text] if chunk.text else []
            for value in (chunk.metadata or {}).values():
                surfaces.extend(_metadata_strings(value))
            text_missing += not bool(surfaces)
            text_truncated += any(len(value) > 5000 for value in surfaces)
            inj = _scan_injection_surfaces(chunk.text, chunk.metadata or {})
            if inj:
                injections.append({
                    "chunk_id": chunk.id,
                    "score": inj["score"],
                    "confidence": inj["confidence"],
                    "categories": inj["categories"],
                    "surfaces": inj["surfaces"],
                    "spans": inj["spans"][:5],
                })
    except Exception as exc:
        read_error = type(exc).__name__
    _flush_embeddings()

    # --- prompt injection ---
    if injections:
        top_cats = sorted({c for inj in injections for c in inj["categories"]})
        # The title stays fixed: fingerprints, suppressions and the action map
        # key on it. Severity follows the strongest chunk, so a collection whose
        # only hit is one borderline phrase is not reported like a live payload.
        confident = [inj for inj in injections if inj["confidence"] == "high"]
        injections.sort(key=lambda inj: (inj["confidence"] != "high", -inj["score"]))
        job.add(Finding(
            id=f"find-{uuid.uuid4().hex[:10]}",
            title=f"Prompt-injection content in '{collection}'",
            severity=Severity.HIGH if confident else Severity.MEDIUM,
            category="rag_integrity",
            store=store.name,
            collection=collection,
            description=(
                f"{len(injections)}/{scanned} chunks contain suspected prompt-"
                f"injection payloads (categories: {', '.join(top_cats)}); "
                f"{len(confident)} at high confidence. Retrieved into an LLM "
                "context, these can hijack model behavior."
            ),
            evidence={"count": len(injections), "scanned": scanned,
                      "high_confidence": len(confident),
                      "max_score": max(inj["score"] for inj in injections),
                      "examples": injections[:10]},
            remediation=(
                "Quarantine and review the flagged chunks; add an injection filter "
                "to the ingestion pipeline; treat retrieved context as untrusted "
                "data, not instructions."
            ),
        ))

    # --- embedding anomalies ---
    total_vectors = anomaly.total_seen
    result = None
    anomalies = []
    if total_vectors >= 10 and not anomaly_error:
        try:
            result = anomaly.finalize()
        except Exception as exc:
            anomaly_error = type(exc).__name__
    near: list = []
    norm_outliers: list = []
    if result is not None:
        anomalies = [s for s in result.scores if s.direction == "far"]
        near = sorted((s for s in result.scores if s.direction == "near"),
                      key=lambda s: s.score)
        norm_outliers = sorted((s for s in result.scores if s.norm_outlier),
                               key=lambda s: -(s.norm_z or 0.0))
        basis = (f" (fit on a random sample of {result.sample_size:,} of "
                 f"{total_vectors:,} vectors)" if result.sampled else "")
        if anomalies:
            anomalies.sort(key=lambda s: -s.score)
            evidence = {
                "count": len(anomalies),
                "total_vectors": total_vectors,
                "z_threshold": z_threshold,
                "examples": [{"chunk_id": a.id, "z": a.score,
                              "distance": a.distance} for a in anomalies[:10]],
            }
            if result.sampled:
                evidence["sampled"] = True
                evidence["sample_size"] = result.sample_size
            job.add(Finding(
                id=f"find-{uuid.uuid4().hex[:10]}",
                title=f"Anomalous embeddings in '{collection}'",
                severity=Severity.MEDIUM,
                category="rag_integrity",
                store=store.name,
                collection=collection,
                description=(
                    f"{len(anomalies)}/{len(result.scores)} vectors are statistical "
                    f"outliers (robust z >= {z_threshold}){basis}. Outliers can "
                    "indicate poisoned or off-distribution content worth reviewing."
                ),
                evidence=evidence,
                remediation=(
                    "Review the outlier chunks against their provenance. Cluster "
                    "drift may be benign (diverse data); concentrated outliers from "
                    "a single source suggest poisoning."
                ),
            ))
        if near:
            evidence = {
                "count": len(near), "total_vectors": total_vectors,
                "near_z": limits.near_z, "near_ratio": limits.near_ratio,
                "references": ["Black-hole vectors (Li et al., arXiv 2604.05480)"],
                "examples": [{"chunk_id": a.id, "z": a.score, "distance": a.distance}
                             for a in near[:10]],
            }
            if result.sampled:
                evidence.update(sampled=True, sample_size=result.sample_size)
            job.add(Finding(
                id=f"find-{uuid.uuid4().hex[:10]}",
                title=f"Anomalous embeddings close to the centroid in '{collection}'",
                severity=Severity.MEDIUM,
                category="rag_integrity",
                store=store.name,
                collection=collection,
                description=(
                    f"{len(near)}/{len(result.scores)} vectors sit abnormally close to "
                    f"the centre of the collection (robust z <= -{limits.near_z} and "
                    f"under {limits.near_ratio:.0%} of the median distance){basis}. A "
                    "vector at the centre is near every query at once, which is how "
                    "a planted 'black-hole' chunk gets retrieved for unrelated "
                    "questions."),
                evidence=evidence,
                remediation=(
                    "Review these chunks and their sources. Empty or generic text also "
                    "embeds near the centre; remove it if it carries no content, and "
                    "quarantine it if the source is unexpected."),
            ))
        if norm_outliers:
            job.add(Finding(
                id=f"find-{uuid.uuid4().hex[:10]}",
                title=f"Anomalous vector norms in '{collection}'",
                severity=Severity.MEDIUM,
                category="rag_integrity",
                store=store.name,
                collection=collection,
                description=(
                    f"{len(norm_outliers)}/{len(result.scores)} vectors have an "
                    f"abnormally large norm (robust z >= {limits.norm_z} and at least "
                    f"{limits.norm_ratio}x the median){basis}. This collection ranks by "
                    "inner product, which rewards magnitude: an inflated vector wins "
                    "retrieval regardless of relevance."),
                evidence={"count": len(norm_outliers), "total_vectors": total_vectors,
                          "distance_metric": metric, "norm_z": limits.norm_z,
                          "examples": [{"chunk_id": a.id, "norm": a.norm,
                                        "norm_z": a.norm_z}
                                       for a in norm_outliers[:10]]},
                remediation=(
                    "Normalise embeddings at ingestion (or switch the index to cosine) "
                    "and review the flagged chunks' sources."),
            ))

    # --- provenance ---
    prov = analyze_provenance(metadatas)
    if prov.total and prov.coverage < 0.95:
        job.add(Finding(
            id=f"find-{uuid.uuid4().hex[:10]}",
            title=f"Incomplete provenance in '{collection}'",
            severity=Severity.MEDIUM,
            category="rag_integrity",
            store=store.name,
            collection=collection,
            description=(
                f"Only {prov.coverage:.0%} of chunks carry a traceable source. "
                "Untraceable chunks cannot be audited or attributed during a "
                "poisoning investigation."
            ),
            evidence={"total": prov.total, "with_source": prov.with_source,
                      "coverage": round(prov.coverage, 4)},
            remediation=(
                "Record a source/document id and ingest timestamp on every chunk "
                "at ingestion time."
            ),
        ))
    if prov.rare_sources:
        job.add(Finding(
            id=f"find-{uuid.uuid4().hex[:10]}",
            title=f"Rare provenance sources in '{collection}'",
            severity=Severity.LOW,
            category="rag_integrity",
            store=store.name,
            collection=collection,
            description=(
                f"{len(prov.rare_sources)} source(s) each contribute a tiny share "
                "of the collection. Injected documents often arrive as a handful of "
                "chunks from an unfamiliar source."
            ),
            evidence={"rare_sources": prov.rare_sources[:20]},
            remediation="Confirm these sources are expected and authorized.",
        ))

    # --- corpus duplication, hubness, ingestion, versions ---
    injection_ids = {str(i["chunk_id"]) for i in injections}
    anomaly_ids = {a.id for a in (*anomalies, *near, *norm_outliers)}
    if result is not None:
        vector_ids = anomaly.sample_ids()
        vectors = anomaly.sample_matrix()
        vectors_sampled = bool(result.sampled)
    else:
        vector_ids, vectors = [], np.zeros((0, 0), dtype=np.float32)
        vectors_sampled = False
    time_field, _ = choose_time_field(records)
    timings: dict[str, float] = {}
    reports: list[DetectorReport] = []

    def _run(check: str, fn) -> DetectorReport:
        started = time.perf_counter()
        try:
            rep = fn()
        except Exception as exc:
            rep = DetectorReport(check=check, error=type(exc).__name__)
        timings[check] = round((time.perf_counter() - started) * 1000, 1)
        reports.append(rep)
        return rep

    dup = _run("corpus_duplication", lambda: analyze_duplication(
        store=store.name, collection=collection, records=records, collector=text_dups,
        vector_ids=vector_ids, vectors=vectors, vectors_sampled=vectors_sampled,
        limits=limits, time_field=time_field, sensitive_ids=sensitive,
        injection_ids=injection_ids, cross_collection=cross_copies))
    hub = _run("retrieval_hubness", lambda: analyze_hubness(
        store=store.name, collection=collection, vector_ids=vector_ids, vectors=vectors,
        vectors_sampled=vectors_sampled, metric=raw_metric, records=records,
        limits=limits, injection_ids=injection_ids, anomaly_ids=anomaly_ids))
    ingest = _run("ingestion_burst", lambda: analyze_ingestion(
        store=store.name, collection=collection, records=records, limits=limits,
        collection_embedding_model=getattr(meta, "embedding_model", None),
        corroborating_ids=(injection_ids | anomaly_ids | dup.flagged_ids
                           | hub.flagged_ids)))
    _run("chunk_versions", lambda: analyze_versions(
        store=store.name, collection=collection, records=records, limits=limits,
        time_field=time_field, sensitive_ids=sensitive, source_manifest=source_manifest))
    for rep in reports:
        for finding in rep.findings:
            job.add(finding)

    job.stats = {
        "collection": collection,
        "chunks_scanned": scanned,
        "vectors_checked": total_vectors,
        "injections": len(injections),
        "provenance_coverage": round(prov.coverage, 4),
        "distance_metric": raw_metric,
        "near_centroid_vectors": len(near),
        "norm_outliers": len(norm_outliers),
        "records_kept": len(records),
        "records_capped": records_capped,
        "provenance_contract": ingest.stats.get("provenance_contract"),
        "duplication": dup.stats,
        "hubness": hub.stats,
        "ingestion": {k: v for k, v in ingest.stats.items() if k != "provenance_contract"},
        "chunk_versions": next(r.stats for r in reports if r.check == "chunk_versions"),
        "integrity_timings_ms": timings,
        "integrity_limits": {"record_cap": limits.record_cap,
                             "text_signature_cap": limits.text_signature_cap,
                             "hub_pool_size": limits.hub_pool_size,
                             "hub_probe_count": limits.hub_probe_count,
                             "seed": limits.seed},
    }
    inventoried = next((c for c in store.collections if c.name == collection), None)
    expected = inventoried.count if inventoried is not None else None
    # A count the store could not produce is not a count to compare against.
    count_gap = inventoried is not None and not count_known(inventoried)
    try:
        content_errors = len(read_errors_for(connector.read_errors(), collection))
    except Exception as exc:
        content_errors = 1
        read_error = type(exc).__name__
    enumeration_complete = not (capped or read_error or content_errors or count_gap or
                                (expected is not None and expected > scanned))
    enumeration_reason = (f"Collection inspection failed ({read_error})." if read_error else
                          "The configured chunk limit was reached." if capped else
                          "The connector reported content-read failures." if content_errors else
                          "Enumeration returned fewer chunks than the inventory count."
                          if expected is not None and expected > scanned else
                          COUNT_UNKNOWN_REASON if count_gap else "")
    metric_note = ("The store did not report its distance metric; cosine geometry was "
                   "assumed and vector norms were not scored." if metric is None else
                   "Inner-product index: vector norms were also scored."
                   if metric == "dot" else "")
    outcomes = []
    for check, detected, limitation in (
        ("prompt_injection", bool(injections),
         "Some text surfaces were absent or exceeded the 5000-character inspection limit."
         if text_missing or text_truncated else ""),
        ("embedding_anomaly", bool(anomalies or near or norm_outliers),
         f"Embedding analysis failed ({anomaly_error})." if anomaly_error else
         "At least 10 vectors are required for anomaly analysis." if total_vectors < 10 else
         "Only a reservoir sample of embeddings was scored." if result and result.sampled else
         "Some chunks had no embedding to inspect." if total_vectors < scanned else ""),
        ("provenance", bool(prov.total and prov.coverage < 0.95 or prov.rare_sources), ""),
    ):
        complete = enumeration_complete and not limitation
        outcomes.append(check_outcome(
            check, store.name, collection,
            outcome=("error" if read_error or (check == "embedding_anomaly" and anomaly_error)
                     else "failed" if detected else "passed" if complete else "inconclusive"),
            reason=" ".join(filter(None, [enumeration_reason, limitation,
                                          metric_note if check == "embedding_anomaly"
                                          else ""])),
            complete=complete, chunks_scanned=scanned, chunks_expected=expected,
            limit=max_chunks, limit_reached=capped,
            **({"sampled": bool(result and result.sampled),
                "vectors_scored": len(result.scores) if result else 0,
                "vectors_seen": total_vectors} if check == "embedding_anomaly" else {}),
        ))
    capped_note = (f"{records_capped:,} chunks exceeded the record cap "
                   f"({limits.record_cap:,}) and were not analysed."
                   if records_capped else "")
    vector_error = (f"Embedding analysis failed ({anomaly_error})."
                    if anomaly_error else "")
    for rep in reports:
        limitation = " ".join(filter(None, [
            capped_note,
            vector_error if rep.check in ("corpus_duplication", "retrieval_hubness") else "",
            rep.limitation]))
        complete = enumeration_complete and not limitation
        outcomes.append(check_outcome(
            rep.check, store.name, collection,
            outcome=("error" if read_error or rep.error else
                     "failed" if rep.detected else
                     "inconclusive" if rep.data_gap or not complete else "passed"),
            reason=" ".join(filter(None, [
                enumeration_reason, limitation, rep.data_gap, rep.note,
                f"The detector failed ({rep.error})." if rep.error else ""])),
            complete=complete, chunks_scanned=scanned, chunks_expected=expected,
            limit=max_chunks, limit_reached=capped,
            **({"data_gap": True} if rep.data_gap else {}), **rep.coverage,
        ))
    set_job_coverage(job, outcomes, chunks_scanned=scanned, chunks_expected=expected,
                     limit=max_chunks, limit_reached=capped,
                     content_read_errors=content_errors)
    apply_fingerprints(job.findings)
    job.finished_at = datetime.now(timezone.utc)
    return job


def _scan_injection_surfaces(text: str | None, metadata: dict[str, Any]) -> dict | None:
    surfaces: list[tuple[str, str]] = []
    if text:
        surfaces.append(("text", text))
    for key, value in metadata.items():
        for item in _metadata_strings(value):
            surfaces.append((f"metadata.{key}", item))

    hits: list[dict] = []
    categories: set[str] = set()
    max_score = 0.0
    high_confidence = False
    for surface, value in surfaces:
        result = scan_text(value[:5000])
        if not result.is_injection:
            continue
        max_score = max(max_score, result.score)
        high_confidence = high_confidence or result.high_confidence
        categories.update(result.categories)
        for span in result.spans[:3]:
            enriched = dict(span)
            enriched["surface"] = surface
            hits.append(enriched)

    if not categories:
        return None
    return {
        "score": round(max_score, 3),
        "confidence": "high" if high_confidence else "medium",
        "categories": sorted(categories),
        "surfaces": sorted({h["surface"] for h in hits}),
        "spans": hits,
    }


def _metadata_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []
