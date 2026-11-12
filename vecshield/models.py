"""Core data model for VecShield.

The object graph:

    VectorStore  -> Collection -> Chunk -> Classification
    ScanJob produces Findings against any of the above.

Kept dependency-free (stdlib dataclasses) so the model can be imported
anywhere without pulling in connector or ML deps.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class SensitivityLabel(str, Enum):
    """What kind of sensitive data a chunk holds."""

    PII = "pii"  # names, emails, phones, addresses
    PHI = "phi"  # health data
    PCI = "pci"  # payment card data
    SECRET = "secret"  # API keys, tokens, credentials
    SOURCE_CODE = "source_code"
    # GDPR Art. 9(1): racial or ethnic origin, political opinions, religious or
    # philosophical beliefs, trade union membership, genetic data, biometric
    # data for unique identification, health, sex life or sexual orientation.
    # Separate from PII because processing is prohibited outright unless an
    # Art. 9(2) condition applies -- a different lawful-basis analysis, not a
    # more severe grade of Art. 6. Also carries the CPRA right to limit use and
    # disclosure (Cal. Civ. Code s 1798.121) that ordinary personal
    # information does not.
    SPECIAL_CATEGORY = "special_category"
    # GDPR Art. 10: personal data relating to criminal convictions and
    # offences. Its own regime again -- it needs official authority or specific
    # Member State law, and it is deliberately *not* an Art. 9 category.
    CRIMINAL_OFFENCE = "criminal_offence"
    NONE = "none"


@dataclass
class Classification:
    """Result of classifying a single chunk."""

    label: SensitivityLabel
    confidence: float  # 0.0 - 1.0
    detectors: list[str] = field(default_factory=list)  # which rules fired
    spans: list[dict[str, Any]] = field(default_factory=list)  # matched text spans

    @property
    def is_sensitive(self) -> bool:
        return self.label != SensitivityLabel.NONE

    @property
    def qualifiers(self) -> set[str]:
        """Cross-cutting facts about the spans, as opposed to their kind.

        A qualifier is not a label. A child's email address is still an email
        address; what changes is the regime that reaches it -- opt-*in* for
        sale or sharing under CPRA s 1798.120(c), a consent age of 13-16 under
        GDPR Art. 8, under-13 under COPPA. Modelling that as a label would
        force a choice between "this is contact data" and "this is a child's
        data" when the answer is both, so it rides alongside instead.
        """
        return {q for sp in self.spans if (q := sp.get("qualifier"))}


@dataclass
class Chunk:
    """A single vector + its (optional) source text and metadata."""

    id: str
    collection: str
    text: str | None = None  # raw chunk text, if stored alongside vector
    embedding: list[float] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    classification: Classification | None = None


@dataclass
class Collection:
    """A namespace / index / table within a vector store."""

    name: str
    count: int = 0
    dimension: int | None = None
    embedding_model: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    #: The similarity the store's index uses, normalised to "cosine", "dot",
    #: "euclidean" or "manhattan"; None when the store does not report it.
    distance_metric: str | None = None


@dataclass
class VectorStore:
    """A discovered vector database instance."""

    kind: str  # "chroma", "pinecone", "pgvector", ...
    name: str
    endpoint: str
    collections: list[Collection] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class DatasetInfo:
    """A single dataset within an object-storage data source.

    Equivalent of `Collection` for raw training/fine-tuning data — one file,
    table, or HuggingFace split that will be (or was) embedded.
    """

    name: str
    format: str = "unknown"  # jsonl, csv, parquet, text, pdf
    count: int = 0  # records, when cheaply known
    size_bytes: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class DataSourceStore:
    """A discovered object-storage / dataset source.

    Equivalent of `VectorStore` for the raw-data layer that feeds an embedder.
    """

    kind: str  # "local", "s3", "gcs", "azure_blob", "huggingface"
    name: str
    endpoint: str
    datasets: list[DatasetInfo] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class IngestEvent:
    """A single ingestion batch observed at the pipeline gate."""

    principal: str
    dataset: str
    timestamp: float  # epoch seconds (event time)
    batch_size: int = 0
    pii_count: int = 0
    blocked: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "principal": self.principal,
            "dataset": self.dataset,
            "timestamp": self.timestamp,
            "batch_size": self.batch_size,
            "pii_count": self.pii_count,
            "blocked": self.blocked,
            "metadata": self.metadata,
        }


@dataclass
class IngestGateReport:
    """Result of gating a chunk batch before embedding."""

    findings: list[Finding] = field(default_factory=list)
    blocked_chunks: list[Chunk] = field(default_factory=list)
    allowed_chunks: list[Chunk] = field(default_factory=list)
    pii_density: float = 0.0
    #: Sensitive chunks let through because they rated below the block bar,
    #: with the basis of the rating (for example ``nlp_only``), so a chunk
    #: allowed on uncorroborated model output is visible rather than silent.
    below_threshold: list[dict[str, Any]] = field(default_factory=list)
    #: Chunks with a text surface longer than the classification window; the
    #: characters past it were not classified.
    truncated_surfaces: list[dict[str, Any]] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.blocked_chunks) + len(self.allowed_chunks)

    @property
    def blocked(self) -> bool:
        return bool(self.blocked_chunks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "blocked": len(self.blocked_chunks),
            "allowed": len(self.allowed_chunks),
            "pii_density": round(self.pii_density, 4),
            "blocked_chunk_ids": [c.id for c in self.blocked_chunks],
            "findings": [f.to_dict() for f in self.findings],
            "below_threshold": list(self.below_threshold),
            "truncated_surfaces": list(self.truncated_surfaces),
        }


@dataclass
class QueryHit:
    """A single result from a similarity query."""

    id: str
    score: float  # proximity, higher = closer
    text: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class Action(str, Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"


# Actions that mutate or escalate, in increasing order of blast radius.
MUTATING_ACTIONS = {Action.WRITE, Action.DELETE, Action.ADMIN}


@dataclass
class ApiKey:
    """An access credential for a vector store."""

    id: str
    name: str = ""
    actions: list[str] = field(default_factory=list)  # Action values
    namespaces: list[str] = field(default_factory=list)  # ["*"] == all
    last_used: datetime | None = None
    created_at: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def has_wildcard(self) -> bool:
        return "*" in self.namespaces or not self.namespaces

    def can(self, action: Action) -> bool:
        return action.value in self.actions or Action.ADMIN.value in self.actions


@dataclass(frozen=True)
class AccessGrant:
    """A (principal can do action on namespace) tuple — for RBAC diffs."""

    principal: str
    namespace: str
    action: str  # Action value

    def as_tuple(self) -> tuple[str, str, str]:
        return (self.principal, self.namespace, self.action)


@dataclass
class Finding:
    """A single security finding produced by a scan."""

    id: str
    title: str
    severity: Severity
    category: str  # "data_classification", "access_control", ...
    store: str
    collection: str | None = None
    description: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    created_at: datetime = field(default_factory=_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "store": self.store,
            "collection": self.collection,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class ScanJob:
    """A scan run and its accumulated findings."""

    id: str
    store: str
    started_at: datetime = field(default_factory=_now)
    finished_at: datetime | None = None
    findings: list[Finding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "store": self.store,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "stats": self.stats,
            "max_severity": self.max_severity.value,
            "findings": [f.to_dict() for f in self.findings],
        }
