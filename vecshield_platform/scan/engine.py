"""Scan engine: walk a store, classify chunks, score collections, emit findings.

Beyond label-only findings, the sensitivity scorer means severity reflects data sensitivity, density, AND exposure (raw text stored
vs. embedding-inversion risk), so a collection of bare vectors from an
invertible model still rates as exposed.
"""

from __future__ import annotations

import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Callable

from vecshield.classify import Classifier
from vecshield.classify.surfaces import chunk_text_surfaces, labels_from_spans
from vecshield_platform.scan.batching import ClassifiedStream, NlpBudget
from vecshield_platform.compliance.fingerprint import apply_fingerprints
from vecshield_platform.connectors.base import (
    Connector,
    UnsupportedCapability,
    fill_declared_embedding_model,
)
from vecshield_platform.detection import build_classifier, nlp_coverage_gap
from vecshield.classify.language import ner_coverage_gap
from vecshield.classify.language import detect as detect_language
from vecshield.classify.language import summarise_codes as summarise_languages
from vecshield_platform.coverage import (
    COUNT_UNKNOWN_REASON,
    check_outcome,
    count_known,
    read_errors_for,
    set_job_coverage,
)
from vecshield_platform.progress import chunks_bound_for, tick as progress_tick
from vecshield_platform.explain import explain_example
from vecshield_platform.scan.embedding_consistency import (
    check_embedding_consistency)
from vecshield_platform.scan.biometric import (
    biometric_findings,
    biometric_templates_outcome,
    detect_biometric_collection,
)
from vecshield_platform.scan.retention import observe_retention
from vecshield_platform.scan.retention_schedule import (
    CHECK as RETENTION_SCHEDULE_CHECK,
    evaluate_retention_schedule,
    retention_schedule_findings,
    retention_schedule_outcome,
    validate_schedule,
)
from vecshield.models import (
    Chunk,
    Classification,
    Finding,
    ScanJob,
    SensitivityLabel,
    Severity,
)
from vecshield.score import score_collection

#: Sensitive chunk ids kept across all collections for the integrity pass
#: (duplication and supersession severity). Ids only, never content; beyond
#: this the list is truncated and ``sensitive_chunk_ids_truncated`` says so.
MAX_SENSITIVE_IDS = 200_000

# Secrets are always critical regardless of score; everything else is driven by
# the sensitivity score's rating.
_RATING_SEVERITY = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

_REMEDIATION = {
    SensitivityLabel.SECRET: (
        "Credentials must never be embedded. Purge affected chunks, rotate the "
        "exposed secrets, and add a pre-ingest secret scanner to the pipeline."
    ),
    SensitivityLabel.PCI: (
        "Cardholder data in a vector store is almost certainly out of PCI-DSS "
        "scope controls. Remove, tokenize upstream, and restrict the collection."
    ),
    SensitivityLabel.PHI: (
        "PHI in embeddings creates HIPAA exposure. Restrict access, log all "
        "queries, and confirm a BAA covers the vector store provider."
    ),
    SensitivityLabel.PII: (
        "Tag the collection as PII-bearing, enforce least-privilege API keys, "
        "and ensure a GDPR/CCPA erasure path exists (re-embed on deletion)."
    ),
    SensitivityLabel.SPECIAL_CATEGORY: (
        "Special-category data (GDPR Art. 9) needs an Art. 9(2) condition before "
        "it may be processed at all. Confirm the lawful basis, restrict the "
        "collection, and remove the data if no condition applies."
    ),
    SensitivityLabel.CRIMINAL_OFFENCE: (
        "Criminal-offence data (GDPR Art. 10) may only be processed under "
        "official authority or a specific legal authorisation. Confirm one "
        "applies, restrict access, and remove the data if not."
    ),
    SensitivityLabel.SOURCE_CODE: (
        "Proprietary source in embeddings can be reconstructed. Restrict access "
        "and review whether this collection should exist."
    ),
}


def scan_store(
    connector: Connector,
    *,
    classifier: Classifier | None = None,
    max_chunks_per_collection: int | None = None,
    observer: Callable[[Chunk, Classification], None] | None = None,
    retention_schedule: Any = None,
    nlp_time_budget_s: float | None = None,
) -> ScanJob:
    """Classify a store's contents and report what was found, and what was not.

    Chunks are classified in batches (``classify_batch``, so the NER model
    runs ``nlp.pipe``). ``nlp_time_budget_s`` bounds the model time this scan
    may spend (default ``VECSHIELD_NLP_TIME_BUDGET_S``; unset or 0 means no
    budget). Once it is spent, the remaining chunks are classified by the
    pattern detectors only and each affected collection records partial
    coverage saying how many -- they are never skipped silently.

    ``retention_schedule`` is the customer's declared schedule for this store
    (a :class:`~vecshield_platform.scan.retention_schedule.RetentionSchedule`
    or its mapping form). Each chunk's age is compared with it on this same
    pass; without one, ``retention_schedule`` is recorded as an opt-in check
    that was not run.

    ``observer`` is called with every classified chunk while its content is
    still in hand. It exists so the subject index can be built during the pass
    that already reads every chunk, rather than by reading them all again. It
    is deliberately given the classification rather than findings: findings are
    aggregated per collection and keep at most five examples, which is not
    enough to index from. An observer that raises is recorded and does not
    fail the scan — indexing is a convenience, and losing it must not cost the
    assessment.
    """
    if max_chunks_per_collection is not None and max_chunks_per_collection < 1:
        raise ValueError("max_chunks_per_collection must be positive")
    classifier = classifier or build_classifier()
    nlp_budget = NlpBudget.resolve(nlp_time_budget_s)
    # Validated before any content is read: a malformed schedule is a
    # configuration error, not something to discover half-way through a scan.
    schedule = validate_schedule(retention_schedule)
    # Read errors from an earlier pass over this connector belong to that pass.
    reset_read_errors = getattr(connector, "reset_read_errors", None)
    if callable(reset_read_errors):
        reset_read_errors()
    store = connector.describe()
    fill_declared_embedding_model(connector, store.collections)
    job = ScanJob(id=f"scan-{uuid.uuid4().hex[:12]}", store=store.name)
    observer_errors: list[str] = []
    # Per-collection inputs other passes (integrity, inventory) consume, so
    # they do not read the store again for facts this pass already saw.
    sensitive_ids: dict[str, list[str]] = {}
    sensitive_ids_kept = 0
    sensitive_ids_truncated = False
    inventory_inputs: dict[str, dict[str, Any]] = {
        "classification": {}, "retention": {}, "biometric": {}}

    # Managed, inventory-only stores (Bedrock KB, Vertex AI) have no per-chunk
    # enumeration API, so iter_chunks() yields nothing. Emit an explicit coverage
    # finding so a zero-result scan is never mistaken for "no sensitive data".
    enumerable = getattr(connector, "content_enumerable", True)
    if not enumerable:
        job.add(_coverage_finding(store))

    total_chunks = 0
    total_sensitive = 0
    outcomes: list[dict] = []
    # NLP that is degraded or turned off leaves names, places and
    # organisations unexamined in every collection, so no collection can be
    # complete. Recorded on each outcome, not only as a store-level note, so
    # criteria reading per-collection outcomes cannot read a full pass.
    nlp_status, nlp_gap = nlp_coverage_gap(classifier)
    nlp_details = {"nlp_status": nlp_status} if nlp_status else {}
    # The languages the NER layer really covers, so a German collection read
    # with a German model loaded is not reported as unexamined.
    ner_languages = ["en"]
    if hasattr(classifier, "detection_metadata") and not nlp_status:
        ner_languages = list(classifier.detection_metadata().get("ner_languages")
                             or ["en"])

    classify_bound = chunks_bound_for(store.collections, max_chunks_per_collection)

    for col in store.collections:
        label_counts: Counter[SensitivityLabel] = Counter()
        detector_counts: Counter[str] = Counter()
        examples: list[dict] = []
        scanned = 0
        raw_text_stored = False
        surfaces_scanned = 0
        metadata_surfaces_scanned = 0
        sensitive_chunks = 0
        capped = False
        error = None
        unsupported = not enumerable
        unreadable = 0
        # Language is a coverage input, not a finding. The NER layer runs an
        # English model, so a collection that is largely not in English has
        # had its names, locations and organisations left unexamined -- and
        # must not report the same coverage as one that was fully read.
        # Codes only: keeping every chunk's text until the collection ends
        # would hold the whole collection in memory.
        chunk_languages: list[str | None] = []
        # Collected on the pass the scan already makes. Retention is read from
        # the same metadata the classifier is looking at, so it costs one list
        # rather than a second walk of the collection.
        chunk_metadata: list[dict] = []
        # One compact record per chunk for the declared retention schedule:
        # its id, what was found in it, and the metadata dict already kept
        # above (shared, not copied). Built only when a schedule is declared.
        schedule_records: list[dict[str, Any]] = []
        collection_sensitive_ids: list[str] = []
        stream = ClassifiedStream(
            classifier,
            (lambda name=col.name: connector.iter_chunks(name)) if enumerable else (),
            limit=max_chunks_per_collection, budget=nlp_budget)
        try:
            # total_chunks is added once after this collection; ticks use a
            # running classified_so_far so the card never reports more chunks
            # read than the bound.
            classified_so_far = total_chunks
            progress_tick(collection=col.name, chunks_read=classified_so_far,
                          chunks_bound=classify_bound)
            for chunk, surfaces, result in stream:
                if observer is not None:
                    try:
                        observer(chunk, result)
                    except Exception as exc:  # noqa: BLE001
                        if not observer_errors:
                            observer_errors.append(
                                f"{type(exc).__name__} while recording scan "
                                "observations; the assessment continued.")
                scanned += 1
                classified_so_far += 1
                progress_tick(collection=col.name, chunks_read=classified_so_far,
                              chunks_bound=classify_bound)
                chunk_languages.append(detect_language(chunk.text))
                metadata = dict(chunk.metadata or {})
                chunk_metadata.append(metadata)
                if schedule is not None:
                    schedule_records.append({
                        "chunk_id": chunk.id,
                        "labels": ((labels_from_spans(result) or {result.label})
                                   if result.is_sensitive else ()),
                        "detectors": tuple(result.detectors),
                        "qualifiers": tuple(result.qualifiers),
                        "metadata": metadata})
                surfaces_scanned += len(surfaces)
                metadata_surfaces_scanned += sum(
                    1 for surface in surfaces if surface.name.startswith("metadata")
                )
                if surfaces:
                    raw_text_stored = True
                else:
                    unreadable += 1
                if result.is_sensitive:
                    sensitive_chunks += 1
                    if sensitive_ids_kept < MAX_SENSITIVE_IDS:
                        collection_sensitive_ids.append(str(chunk.id))
                        sensitive_ids_kept += 1
                    else:
                        sensitive_ids_truncated = True
                    labels = labels_from_spans(result) or {result.label}
                    for label in labels:
                        label_counts[label] += 1
                    for d in result.detectors:
                        detector_counts[d] += 1
                    if len(examples) < 5:
                        # The span already says which detector fired and where.
                        # An explanation adds what a reader needs to judge it:
                        # a masked preview, and the reasons it might be wrong.
                        # Span offsets are per surface, so keep the surfaces
                        # keyed by name rather than flattening them.
                        surfaces = {s.name: s.text for s in chunk_text_surfaces(chunk)}
                        examples.append(
                            {"chunk_id": chunk.id, "label": result.label.value,
                             "detectors": result.detectors, "spans": result.spans,
                             "explanations": explain_example(
                                 {"spans": result.spans}, collection=col.name,
                                 surfaces=surfaces, metadata=chunk.metadata)}
                        )
        except Exception as exc:
            # Keep evidence already collected and continue with other collections.
            error = type(exc).__name__
            unsupported = isinstance(exc, UnsupportedCapability)
        capped = stream.capped
        # Chunks read without NLP after the budget ran out, and surfaces cut at
        # the classification window: both leave content unexamined.
        stream_gaps, stream_details = stream.coverage_gaps(scanned)

        language_summary = summarise_languages(chunk_languages)
        language_gap = ner_coverage_gap(language_summary, covered=ner_languages)
        # A count of zero the store could not actually produce is not a count:
        # compared with what was read it would pass any read, empty or not.
        count_gap = not count_known(col)

        complete = enumerable and not (
            capped or error or unreadable or col.count > scanned or count_gap
            or language_gap or nlp_gap or stream_gaps)
        reason = ("Content enumeration is unsupported." if not enumerable else
                  f"Collection inspection failed ({error})." if error else
                  "The configured chunk limit was reached." if capped else
                  "Some chunks have no classifiable text surfaces." if unreadable else
                  "Enumeration returned fewer chunks than the inventory count."
                  if col.count > scanned else
                  COUNT_UNKNOWN_REASON if count_gap else language_gap or "")
        if nlp_gap and enumerable and not error:
            reason = f"{reason} {nlp_gap}".strip()
        if stream_gaps:
            reason = " ".join([reason, *stream_gaps]).strip()
        outcomes.append(check_outcome(
            "data_classification", store.name, col.name,
            outcome=("unsupported" if unsupported else "error" if error else
                     "failed" if sensitive_chunks else "passed" if complete else "inconclusive"),
            reason=reason, complete=complete, chunks_scanned=scanned,
            chunks_expected=col.count, limit=max_chunks_per_collection,
            limit_reached=capped, chunks_without_text=unreadable,
            languages=language_summary["languages"],
            non_english_share=round(
                float(language_summary["non_english_share"]), 3),
            **({"count_known": False} if count_gap else {}),
            **nlp_details,
            **stream_details,
        ))
        if collection_sensitive_ids:
            sensitive_ids[col.name] = collection_sensitive_ids
        inventory_inputs["classification"][col.name] = {
            "label_counts": _labels_as_str(label_counts),
            "detector_counts": dict(detector_counts),
            "chunks_scanned": scanned,
            "complete": bool(complete),
        }
        total_chunks += scanned
        total_sensitive += sensitive_chunks

        # Everything below works from what the read above collected. Each step
        # runs in its own error handling: a fault in one (a malformed date, an
        # unexpected metadata shape) is recorded against that check, and the
        # classification already recorded for this collection, and every
        # other collection, still stands.
        def post_error(check: str, exc: Exception, col_name: str = col.name) -> None:
            outcomes.append(check_outcome(
                check, store.name, col_name, outcome="error", complete=False,
                reason=f"The check failed while processing this collection "
                       f"({type(exc).__name__}).",
                chunks_scanned=scanned))

        # Whether the whole collection was read. The schedule and biometric
        # verdicts rest on the read, not on NLP or language coverage.
        read_complete = bool(enumerable and not (capped or error or count_gap)
                             and col.count <= scanned)

        # Retention is reported as its own check rather than folded into
        # classification coverage. It never fails: an old record is a fact a
        # reviewer weighs against a schedule VecShield does not hold, and
        # `failed` would assert a judgement the product cannot make. What it
        # can say is whether the age is knowable at all.
        # Not emitted at all when the collection could not be read. The
        # data_classification outcome above already records that failure, and
        # a second row for the same root cause double-counts it in the
        # coverage tally — one unreadable collection would read as two errors.
        # Criteria see the absence as "not run", which is correct.
        try:
            retention = observe_retention(chunk_metadata)
        except Exception as exc:  # noqa: BLE001
            retention = None
            post_error("retention_horizon", exc)
        if retention is not None and not (unsupported or error):
            try:
                outcomes.append(check_outcome(
                    "retention_horizon", store.name, col.name,
                    # `passed` means the question was answered, not that the
                    # answer was welcome. "These records carry no date" *is* an
                    # answer, and establishing it completely is not a coverage
                    # gap — the gap is in the data, and it is reported as a
                    # finding below. Marking it inconclusive would flip almost
                    # every real store to partial coverage and drain the meaning
                    # out of the one signal this product rests on.
                    outcome=("inconclusive" if retention.status == "partly_dated"
                             else "passed"),
                    reason=retention.summary(),
                    complete=bool(read_complete and retention.status in
                                  ("observed", "no_record_timestamp")),
                    chunks_scanned=scanned, chunks_expected=col.count,
                    **{k: v for k, v in retention.to_dict().items()
                       if k not in ("summary", "records_scanned")},
                ))
                inventory_inputs["retention"][col.name] = {
                    k: v for k, v in retention.to_dict().items()
                    if k not in ("summary", "note", "candidates", "excluded")}
            except Exception as exc:  # noqa: BLE001
                post_error("retention_horizon", exc)

        if schedule is None:
            pass  # recorded once for the store below, as an opt-in not run
        elif not (unsupported or error):
            # Not emitted for an unreadable collection, for the same reason
            # retention_horizon is not: data_classification already records
            # that failure once.
            try:
                evaluated = evaluate_retention_schedule(schedule_records, schedule,
                                                        collection=col.name)
                outcomes.append(retention_schedule_outcome(
                    store.name, col.name, evaluated, complete=read_complete,
                    chunks_expected=col.count))
                for finding in retention_schedule_findings(store.name, col.name, evaluated):
                    job.add(finding)
            except Exception as exc:  # noqa: BLE001
                post_error(RETENTION_SCHEDULE_CHECK, exc)
        schedule_records = []

        # Biometric templates: a verdict about what the vectors are, from the
        # declared model and the metadata this pass already holds. It can be
        # given for an unreadable collection from its declared model alone,
        # and completeness follows the read. With nothing to judge from on an
        # unreadable collection it is not recorded: data_classification
        # already records that failure once.
        try:
            text_share = ((scanned - unreadable) / scanned) if scanned else None
            biometric = detect_biometric_collection(col, chunk_metadata,
                                                    text_share=text_share)
            if biometric.assessed or not (unsupported or error):
                outcomes.append(biometric_templates_outcome(
                    store.name, col.name, biometric, complete=read_complete))
            for finding in biometric_findings(store.name, col.name, biometric):
                job.add(finding)
            inventory_inputs["biometric"][col.name] = {
                k: biometric.to_dict().get(k)
                for k in ("status", "modality", "estimated_distinct_identities",
                          "confidence", "assessed")}
        except Exception as exc:  # noqa: BLE001
            post_error("biometric_templates", exc)

        if sensitive_chunks == 0:
            continue

        try:
            _add_classification_findings(
                job, store, col, label_counts=label_counts,
                detector_counts=detector_counts, examples=examples, scanned=scanned,
                sensitive=sensitive_chunks, raw_text_stored=raw_text_stored,
                surfaces_scanned=surfaces_scanned,
                metadata_surfaces_scanned=metadata_surfaces_scanned,
                retention=retention)
        except Exception as exc:  # noqa: BLE001
            # The data_classification outcome above already says `failed` with
            # the counts; what was lost is the scored finding. Recorded so the
            # loss is visible rather than a quieter report.
            post_error("sensitivity_scoring", exc)

    # Before the read errors are applied: an empty inventory is a pass only
    # if nothing that should have been listed failed to be.
    if not store.collections:
        outcomes.append(check_outcome(
            "data_classification", store.name,
            outcome="passed" if enumerable else "unsupported", complete=enumerable,
            reason="No collections were returned by inventory."))

    try:
        read_errs = connector.read_errors()
    except Exception as exc:
        read_errs = [{"error_type": type(exc).__name__, "operation": "read_errors"}]
    if read_errs:
        job.add(_read_error_finding(store, read_errs))
        # Scoped: a failure reading one collection's items says nothing about
        # another collection's. An entry naming no collection is store-wide.
        for outcome in outcomes:
            affecting = read_errors_for(read_errs, outcome.get("collection"))
            if outcome.get("collection") is not None and not affecting:
                continue
            outcome["coverage"].update(complete=False, status="partial",
                                       content_read_errors=len(affecting or read_errs))
            outcome["reason"] = "The connector reported content-read failures. " + outcome["reason"]
            if outcome["outcome"] == "passed":
                outcome["outcome"] = "inconclusive"
        # The inventory reads `complete` to decide whether a collection with no
        # sensitive labels is clean. A collection with unreadable items is not.
        for name, inputs in inventory_inputs["classification"].items():
            if read_errors_for(read_errs, name):
                inputs["complete"] = False

    if schedule is None:
        # Opt-in: without a declared schedule there is nothing to compare
        # with, and that is not a shortfall of this run.
        outcomes.append(check_outcome(
            RETENTION_SCHEDULE_CHECK, store.name, outcome="skipped",
            reason="No retention schedule declared", complete=False, opt_in=True,
            schedule_status="no_schedule"))

    # Embedding consistency. Store-level, and it reads only what inventory
    # already returned — no content, so it runs even where enumeration is
    # capped, unsupported or refused. `passed` means the declarations do not
    # contradict themselves; it cannot mean the declared model is the one that
    # produced the vectors, and the evidence says so.
    # With no model declared anywhere there is nothing to compare, and "the
    # declarations do not contradict themselves" would be vacuously true:
    # inconclusive, not passed. Like an undated record for retention, the gap
    # is in the store's declarations rather than in what this run read, so it
    # is marked as a declaration gap and does not make the run partial.
    # Declaring `embedding_model` in the store's configuration closes it.
    embeddings = check_embedding_consistency(store.collections)
    if store.collections:
        undeclared = not embeddings.models and not embeddings.issues
        gap: dict[str, Any] = {"declaration_gap": True} if undeclared else {}
        outcomes.append(check_outcome(
            "embedding_consistency", store.name,
            outcome=("failed" if embeddings.issues else
                     "inconclusive" if undeclared else "passed"),
            reason=embeddings.summary(),
            complete=True,
            **gap,
            **{k: v for k, v in embeddings.to_dict().items()
               if k not in ("summary", "collections")},
        ))
        for issue in embeddings.issues:
            job.add(Finding(
                id=f"find-{uuid.uuid4().hex[:10]}",
                title="Declared embedding model contradicts the vector width",
                severity=Severity.MEDIUM,
                category="embedding_consistency",
                store=store.name,
                description=issue,
                evidence=embeddings.to_dict(),
                remediation=(
                    "Correct whichever is wrong. Until they agree, inversion "
                    "risk is scored against the wrong model, and an erasure "
                    "that re-embeds may leave the original vector behind."),
            ))

    job.stats = {
        "collections": len(store.collections),
        "embedding_models": list(embeddings.models),
        "chunks_scanned": total_chunks,
        "sensitive_chunks": total_sensitive,
        "classifier": getattr(classifier, "name", "unknown"),
        "content_enumerable": enumerable,
        "content_read_errors": len(read_errs),
        # Consumed by the orchestrator (integrity, inventory). Ids only.
        "sensitive_chunk_ids": sensitive_ids,
        "sensitive_chunk_ids_truncated": sensitive_ids_truncated,
        "inventory_inputs": inventory_inputs,
        "retention_schedule_declared": schedule is not None,
    }
    if observer_errors:
        # Surfaced rather than swallowed: a scan whose observer failed produced
        # a complete assessment and an incomplete index, and only one of those
        # is visible from the findings.
        job.stats["observer_errors"] = observer_errors
    if hasattr(classifier, "detection_metadata"):
        detection = classifier.detection_metadata()
        job.stats["detection"] = detection
        if detection["status"] == "disabled":
            # Turned off by configuration: the same coverage fact as a missing
            # model, recorded as skipped rather than unsupported because the
            # capability exists and was not used.
            outcomes.append(check_outcome(
                "nlp_classification", store.name, outcome="skipped",
                reason=nlp_gap or "NLP detection is turned off.", status="disabled"))
        elif nlp_status:
            outcomes.append(check_outcome(
                "nlp_classification", store.name, outcome="unsupported",
                reason=detection.get("reason") or nlp_gap or "", status="unavailable"))
        elif nlp_budget is not None and nlp_budget.chunks_without_nlp:
            # The model ran, but not over everything: the budget stopped it.
            # Inconclusive, with the count, never a clean pass.
            outcomes.append(check_outcome(
                "nlp_classification", store.name, outcome="inconclusive",
                reason=(f"The NLP time budget ({nlp_budget.seconds:g}s) ran out; "
                        f"{nlp_budget.chunks_without_nlp} chunk(s) were classified by "
                        "pattern detectors only. Raise VECSHIELD_NLP_TIME_BUDGET_S or "
                        "scan in smaller runs to cover them."),
                status="budget_exhausted",
                chunks_without_nlp=nlp_budget.chunks_without_nlp))
    if nlp_budget is not None:
        job.stats["nlp_budget"] = nlp_budget.to_dict()
    set_job_coverage(job, outcomes, collections_expected=len(store.collections),
                     # One per collection: several checks per collection
                     # record chunks_scanned, so count classification rows.
                     collections_inspected=sum(
                         o["check"] == "data_classification"
                         and o["coverage"].get("chunks_scanned", 0) > 0
                         for o in outcomes),
                     chunks_scanned=total_chunks)
    apply_fingerprints(job.findings)
    job.finished_at = datetime.now(timezone.utc)
    return job


def _add_classification_findings(job: ScanJob, store, col, *, label_counts: Counter,
                                 detector_counts: Counter, examples: list[dict],
                                 scanned: int, sensitive: int, raw_text_stored: bool,
                                 surfaces_scanned: int, metadata_surfaces_scanned: int,
                                 retention: Any) -> None:
    """Score a collection where sensitive data was found and add its findings."""
    sens = score_collection(
        labels_present=dict(label_counts),
        scanned=scanned,
        raw_text_stored=raw_text_stored,
        embedding_model=col.embedding_model,
        dimension=col.dimension,
        sensitive=sensitive,
    )

    top_label = max(label_counts, key=lambda lbl: (_label_rank(lbl), label_counts[lbl]))
    if top_label == SensitivityLabel.SECRET:
        severity = Severity.CRITICAL
    else:
        severity = _RATING_SEVERITY[sens.rating]

    job.add(
        Finding(
            id=f"find-{uuid.uuid4().hex[:10]}",
            title=f"{top_label.value.upper()} detected in collection '{col.name}'",
            severity=severity,
            category="data_classification",
            store=store.name,
            collection=col.name,
            description=(
                f"{sensitive}/{scanned} scanned chunks ({sens.density:.1%}) "
                f"contain sensitive data. Sensitivity {sens.rating} "
                f"(score {sens.score}). {sens.rationale}"
            ),
            evidence={
                "scanned": scanned,
                "sensitive": sensitive,
                "explanations": [e for ex in examples
                                 for e in (ex.get("explanations") or [])],
                "label_counts": _labels_as_str(label_counts),
                "detector_counts": dict(detector_counts),
                "surfaces_scanned": surfaces_scanned,
                "metadata_surfaces_scanned": metadata_surfaces_scanned,
                "sensitivity": sens.to_dict(),
                "examples": examples,
            },
            remediation=_REMEDIATION[top_label],
        )
    )

    # Only where something was found that a retention obligation would
    # attach to. GDPR Art. 5(1)(e) governs personal data; a collection of
    # public documentation with no timestamp is not a gap, and raising one
    # there would bury the collections where it matters. The check outcome
    # is still emitted either way, so coverage stays honest.
    if retention is not None and retention.status == "no_record_timestamp":
        job.add(Finding(
            id=f"find-{uuid.uuid4().hex[:10]}",
            title=f"No retention horizon for collection '{col.name}'",
            severity=Severity.LOW,
            category="retention",
            store=store.name,
            collection=col.name,
            description=(
                retention.summary()
                + " A retention period cannot be evidenced, applied or "
                  "audited for records whose age is not recorded."),
            evidence=retention.to_dict(),
            remediation=(
                "Record an ingestion timestamp on each chunk's metadata at "
                "write time. Any consistent field name works; the scan "
                "reads it back and reports the horizon. Existing records "
                "cannot be dated retrospectively, so the horizon starts "
                "from the change."),
        ))


def _coverage_finding(store) -> Finding:
    """Finding emitted for inventory-only stores whose contents can't be read.

    Names the backing store when the connector advertises one (Bedrock KB), so
    the operator knows exactly where to point a content-capable connector.
    """
    backing = sorted({
        str(c.metadata.get("backing_store"))
        for c in store.collections
        if c.metadata.get("backing_store")
    })
    detail = f" Backing store(s): {', '.join(backing)}." if backing else ""
    return Finding(
        id=f"find-{uuid.uuid4().hex[:10]}",
        title=f"Content not enumerable in '{store.name}' — scan the backing store",
        severity=Severity.MEDIUM,
        category="coverage",
        store=store.name,
        description=(
            f"This store ({store.kind}) exposes inventory only and has no "
            f"per-chunk enumeration API, so chunk contents cannot be read here. "
            f"A result of zero data-classification findings does NOT mean the "
            f"store is free of sensitive data.{detail}"
        ),
        remediation=(
            "Point a content-capable connector (e.g. pgvector or opensearch) at "
            "the backing store to classify contents, run DSAR, and erase."
        ),
        evidence={"kind": store.kind, "backing_stores": backing,
                  "content_enumerable": False},
    )


def _read_error_finding(store, errors: list[dict]) -> Finding:
    """Finding emitted when some items were inventoried but their content could
    not be read (e.g. an OpenAI file whose content endpoint errored).

    Without this, an unreadable item would be scanned as empty text and look
    clean, silently under-reporting sensitive data.
    """
    return Finding(
        id=f"find-{uuid.uuid4().hex[:10]}",
        title=f"{len(errors)} item(s) could not be read in '{store.name}'",
        severity=Severity.MEDIUM,
        category="coverage",
        store=store.name,
        description=(
            f"{len(errors)} item(s) were listed but their content could not be "
            f"retrieved, so they were NOT classified. Absence of findings for "
            f"these items does NOT mean they are free of sensitive data."
        ),
        remediation=(
            "Re-run the scan after resolving access/transient errors, or inspect "
            "the affected items directly. See evidence for the affected ids."
        ),
        evidence={"count": len(errors), "examples": errors[:10]},
    )


def _label_rank(label: SensitivityLabel) -> int:
    from vecshield.classify.base import LABEL_PRIORITY

    return LABEL_PRIORITY[label]


def _labels_as_str(counts: Counter) -> dict[str, int]:
    return {k.value: v for k, v in counts.items()}
