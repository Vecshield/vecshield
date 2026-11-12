"""scan_datasource: walk a DataSource, classify records, emit findings.

Mirrors `scan_store` but over raw training/fine-tuning data. Key difference:
sensitive data here is worse than in a vector store — it gets baked into model
weights — so severity is escalated one rung (PII -> CRITICAL) and the remediation
calls for cleaning the dataset and re-training, not just purging chunks.

Findings use category `training_data_classification` so they're distinguishable
from store findings in history and reports.
"""

from __future__ import annotations

import uuid
from collections import Counter
from datetime import datetime, timezone

from vecshield.classify import Classifier, default_classifier
from vecshield.classify.surfaces import (
    chunk_text_surfaces,
    classify_chunk,
    labels_from_spans,
)
from vecshield.datasources.base import DataSource
from vecshield.models import Finding, ScanJob, SensitivityLabel, Severity
from vecshield.score import score_collection

CATEGORY = "training_data_classification"

# Training data escalates one rung over the store-side rating: sensitive records
# embedded into weights cannot be erased without re-training.
_RATING_SEVERITY = {
    "HIGH": Severity.CRITICAL,
    "MEDIUM": Severity.HIGH,
    "LOW": Severity.MEDIUM,
}

_REMEDIATION = (
    "Sensitive data in a training/fine-tuning dataset is baked into model weights "
    "on the next run and cannot be erased by deleting chunks. Remove the affected "
    "records, re-generate the dataset, and re-train/re-tune from the cleaned data. "
    "Add a pre-ingest gate so this never reaches the embedder again."
)


def scan_datasource(
    source: DataSource,
    *,
    classifier: Classifier | None = None,
    max_records_per_dataset: int | None = None,
) -> ScanJob:
    classifier = classifier or default_classifier()
    store = source.describe()
    job = ScanJob(id=f"dscan-{uuid.uuid4().hex[:12]}", store=store.name)

    total_records = 0
    total_sensitive = 0
    # Text past the per-surface classification window is not read; counted
    # so the run says so instead of presenting the tail as scanned.
    surfaces_truncated = 0
    chars_not_classified = 0

    for ds in store.datasets:
        label_counts: Counter[SensitivityLabel] = Counter()
        detector_counts: Counter[str] = Counter()
        examples: list[dict] = []
        scanned = 0
        sensitive_records = 0
        raw_text_stored = False

        for chunk in source.iter_records(ds.name):
            if max_records_per_dataset and scanned >= max_records_per_dataset:
                break
            scanned += 1
            surfaces = chunk_text_surfaces(chunk)
            if surfaces:
                raw_text_stored = True
            for surface in surfaces:
                if surface.truncated_chars:
                    surfaces_truncated += 1
                    chars_not_classified += surface.truncated_chars
            result = classify_chunk(classifier, chunk)
            if result.is_sensitive:
                sensitive_records += 1
                labels = labels_from_spans(result) or {result.label}
                for label in labels:
                    label_counts[label] += 1
                for d in result.detectors:
                    detector_counts[d] += 1
                if len(examples) < 5:
                    examples.append(
                        {
                            "record_id": chunk.id,
                            "label": result.label.value,
                            "detectors": result.detectors,
                            "spans": result.spans,
                        }
                    )

        total_records += scanned
        total_sensitive += sensitive_records

        if sensitive_records == 0:
            continue

        sens = score_collection(
            labels_present=dict(label_counts),
            scanned=scanned,
            raw_text_stored=raw_text_stored,
            embedding_model=None,
            dimension=None,
            sensitive=sensitive_records,
        )

        top_label = max(
            label_counts, key=lambda lbl: (_label_rank(lbl), label_counts[lbl])
        )
        if top_label == SensitivityLabel.SECRET:
            severity = Severity.CRITICAL
        else:
            severity = _RATING_SEVERITY[sens.rating]

        job.add(
            Finding(
                id=f"find-{uuid.uuid4().hex[:10]}",
                title=f"{top_label.value.upper()} in training dataset '{ds.name}'",
                severity=severity,
                category=CATEGORY,
                store=store.name,
                collection=ds.name,
                description=(
                    f"{sensitive_records}/{scanned} scanned records "
                    f"({sens.density:.1%}) "
                    f"contain sensitive data in training source '{ds.name}' "
                    f"({ds.format}). Sensitivity {sens.rating} (score {sens.score}). "
                    f"{sens.rationale}"
                ),
                evidence={
                    "scanned": scanned,
                    "sensitive": sensitive_records,
                    "format": ds.format,
                    "size_bytes": ds.size_bytes,
                    "label_counts": {k.value: v for k, v in label_counts.items()},
                    "detector_counts": dict(detector_counts),
                    "sensitivity": sens.to_dict(),
                    "examples": examples,
                },
                remediation=_REMEDIATION,
            )
        )

    job.stats = {
        "datasets": len(store.datasets),
        "records_scanned": total_records,
        "sensitive_records": total_sensitive,
        "classifier": getattr(classifier, "name", "unknown"),
        "source_kind": store.kind,
        "surfaces_truncated": surfaces_truncated,
        "chars_not_classified": chars_not_classified,
    }
    job.finished_at = datetime.now(timezone.utc)
    return job


def _label_rank(label: SensitivityLabel) -> int:
    from vecshield.classify.base import LABEL_PRIORITY

    return LABEL_PRIORITY[label]
