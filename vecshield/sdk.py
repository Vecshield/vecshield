"""Stable Python SDK for the `vecshield` library.

Four functions cover the whole surface:

    check_text(text)      -> CheckResult      # is there PII in this string?
    check_chunks(chunks)  -> IngestGateReport # gate a batch before embedding
    check_dataset(path)   -> DatasetReport    # scan a local training dataset
    redact_text(text)     -> str              # mask PII spans in a string

Everything runs locally. No network calls, no telemetry.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from vecshield.classify import Classifier, RegexClassifier, default_classifier
from vecshield.ingest import IngestGate
from vecshield.models import (
    Chunk,
    Classification,
    IngestGateReport,
    ScanJob,
    Severity,
)

# A chunk can be given as raw text, a {"text": ..., "metadata": ...} dict, or a
# fully-formed Chunk. All three normalize to Chunk before gating.
ChunkLike = str | dict | Chunk


def _classifier(use_nlp: bool, classifier: Classifier | None) -> Classifier:
    if classifier is not None:
        return classifier
    return default_classifier(use_nlp=use_nlp) if use_nlp else RegexClassifier()


@dataclass
class CheckResult:
    """Result of :func:`check_text` — a single classified string."""

    text_preview: str
    label: str
    confidence: float
    has_pii: bool
    detectors: list[str] = field(default_factory=list)
    spans: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_classification(cls, text: str, c: Classification) -> CheckResult:
        return cls(
            text_preview=text[:80],
            label=c.label.value,
            confidence=round(c.confidence, 4),
            has_pii=c.is_sensitive,
            detectors=list(c.detectors),
            spans=list(c.spans),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "has_pii": self.has_pii,
            "label": self.label,
            "confidence": self.confidence,
            "detectors": self.detectors,
            "spans": self.spans,
        }


@dataclass
class DatasetReport:
    """Result of :func:`check_dataset` — a local training/fine-tuning scan."""

    path: str
    records_scanned: int
    sensitive_records: int
    findings: list[dict[str, Any]] = field(default_factory=list)
    max_severity: str = "info"

    @property
    def density(self) -> float:
        return (
            self.sensitive_records / self.records_scanned
            if self.records_scanned
            else 0.0
        )

    @property
    def has_pii(self) -> bool:
        return self.sensitive_records > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "records_scanned": self.records_scanned,
            "sensitive_records": self.sensitive_records,
            "density": round(self.density, 4),
            "max_severity": self.max_severity,
            "findings": self.findings,
        }


def _to_chunk(item: ChunkLike, index: int) -> Chunk:
    if isinstance(item, Chunk):
        return item
    if isinstance(item, str):
        return Chunk(id=str(index), collection="sdk", text=item)
    if isinstance(item, dict):
        return Chunk(
            id=str(item.get("id", index)),
            collection=str(item.get("collection", "sdk")),
            text=item.get("text"),
            metadata=dict(item.get("metadata", {})),
        )
    raise TypeError(f"unsupported chunk type: {type(item).__name__}")


def check_text(
    text: str,
    *,
    use_nlp: bool = True,
    classifier: Classifier | None = None,
) -> CheckResult:
    """Classify a single string for PII/PHI/PCI/secrets.

    >>> check_text("email me at jane@acme.com").has_pii
    True
    """
    clf = _classifier(use_nlp, classifier)
    result = clf.classify(text)
    return CheckResult.from_classification(text, result)


def check_chunks(
    chunks: Iterable[ChunkLike],
    *,
    use_nlp: bool = True,
    classifier: Classifier | None = None,
    mode: str = "soft",
    block_severity: Severity = Severity.HIGH,
) -> IngestGateReport:
    """Gate a batch of pre-embedding chunks. Returns an IngestGateReport.

    In ``mode="hard"`` a :class:`~vecshield.ingest.PiiDetectedError` is raised
    when any chunk is blocked; in ``mode="soft"`` (default) the report simply
    lists blocked vs allowed chunks so the caller decides.
    """
    clf = _classifier(use_nlp, classifier)
    gate = IngestGate(classifier=clf, mode=mode, block_severity=block_severity)
    materialized = [_to_chunk(c, i) for i, c in enumerate(chunks)]
    return gate.check(materialized)


def check_dataset(
    path: str,
    *,
    use_nlp: bool = True,
    classifier: Classifier | None = None,
    max_records: int | None = None,
) -> DatasetReport:
    """Scan a local directory of training/fine-tuning data for sensitive content.

    Supports .jsonl/.ndjson/.json, .csv/.tsv, .txt/.md, .parquet, and .pdf
    (parquet/pdf need the ``datasources`` extra).
    """
    from vecshield.datascan import scan_datasource
    from vecshield.datasources import build_datasource

    clf = _classifier(use_nlp, classifier)
    source = build_datasource("local", path=path)
    with source:
        job: ScanJob = scan_datasource(
            source, classifier=clf, max_records_per_dataset=max_records
        )
    return DatasetReport(
        path=path,
        records_scanned=job.stats.get("records_scanned", 0),
        sensitive_records=job.stats.get("sensitive_records", 0),
        findings=[f.to_dict() for f in job.findings],
        max_severity=job.max_severity.value,
    )


def redact_text(
    text: str,
    *,
    use_nlp: bool = True,
    classifier: Classifier | None = None,
) -> str:
    """Return ``text`` with every detected PII span replaced by ``[REDACTED:LABEL]``."""
    clf = _classifier(use_nlp, classifier)
    gate = IngestGate(classifier=clf)
    clean, _ = gate.redact([Chunk(id="0", collection="sdk", text=text)])
    return clean[0].text or ""


__all__ = [
    "CheckResult",
    "DatasetReport",
    "check_text",
    "check_chunks",
    "check_dataset",
    "redact_text",
]
