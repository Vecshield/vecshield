"""Framework-neutral safe-ingest helper.

guarded_ingest runs gate -> boundary check -> connector ingest in sequence and
returns a structured result. Only allowed chunks reach the connector; blocked
chunks are returned for the caller to log/redact. If no connector is given, it's
a dry run (gate + boundary only).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from vecshield.ingest.boundary import ChunkBoundaryAnalyzer
from vecshield.ingest.gate import IngestGate
from vecshield.models import Chunk, Finding, IngestGateReport


@dataclass
class GuardedIngestResult:
    report: IngestGateReport
    boundary_findings: list[Finding] = field(default_factory=list)
    ingested: int = 0

    @property
    def blocked(self) -> int:
        return len(self.report.blocked_chunks)

    def to_dict(self) -> dict:
        return {
            "ingested": self.ingested,
            "blocked": self.blocked,
            "boundary_findings": [f.to_dict() for f in self.boundary_findings],
            "report": self.report.to_dict(),
        }


def guarded_ingest(
    chunks: list[Chunk],
    *,
    gate: IngestGate,
    connector=None,
    collection: str | None = None,
    check_boundaries: bool = True,
    boundary_analyzer: ChunkBoundaryAnalyzer | None = None,
) -> GuardedIngestResult:
    report = gate.inspect(chunks)

    boundary_findings: list[Finding] = []
    if check_boundaries:
        analyzer = boundary_analyzer or ChunkBoundaryAnalyzer(
            classifier=gate.classifier
        )
        boundary_findings = analyzer.analyze(chunks)

    ingested = 0
    if connector is not None and report.allowed_chunks:
        target = collection or report.allowed_chunks[0].collection
        ingested = _ingest(connector, target, report.allowed_chunks)

    return GuardedIngestResult(
        report=report, boundary_findings=boundary_findings, ingested=ingested
    )


def _ingest(connector, collection: str, chunks: list[Chunk]) -> int:
    """Best-effort write of clean chunks via a connector's add/upsert hook."""
    if hasattr(connector, "add_chunks"):
        return connector.add_chunks(collection, chunks)
    raise NotImplementedError(
        f"{getattr(connector, 'kind', type(connector).__name__)} has no add_chunks(); "
        "pass connector=None for a dry run or wire an ingest method."
    )
