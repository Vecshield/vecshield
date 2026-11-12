"""RAG ingestion-pipeline PII gate.

Two surfaces:
  * IngestGate            — block/warn/redact on PII before embedding
  * ChunkBoundaryAnalyzer — catch PII split across a chunk cut

Plus framework adapters (generic/langchain/llamaindex) under .adapters.
"""

from __future__ import annotations

from vecshield.ingest.boundary import ChunkBoundaryAnalyzer
from vecshield.ingest.gate import IngestGate, PiiDetectedError

__all__ = [
    "IngestGate",
    "PiiDetectedError",
    "ChunkBoundaryAnalyzer",
]
