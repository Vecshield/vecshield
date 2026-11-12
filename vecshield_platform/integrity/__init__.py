"""RAG pipeline integrity: injection, anomaly, provenance, duplication,
hubness, ingestion bursts and chunk versions."""

from __future__ import annotations

from vecshield_platform.integrity.anomaly import (
    AnomalyScore,
    StreamingAnomalyDetector,
    StreamingAnomalyResult,
    detect_anomalies,
)
from vecshield_platform.integrity.duplication import (
    MinHasher,
    SensitiveFingerprintRegistry,
    TextDuplicationCollector,
    analyze_duplication,
    find_embedding_clusters,
)
from vecshield_platform.integrity.engine import CHECKS, scan_integrity
from vecshield_platform.integrity.hubness import analyze_hubness, k_occurrence
from vecshield_platform.integrity.ingestion import analyze_ingestion
from vecshield_platform.integrity.injection import InjectionResult, scan_text
from vecshield_platform.integrity.limits import IntegrityLimits
from vecshield_platform.integrity.provenance import ProvenanceReport, analyze_provenance
from vecshield_platform.integrity.records import ChunkRecord, DetectorReport, build_record
from vecshield_platform.integrity.versions import analyze_versions

__all__ = [
    "scan_integrity",
    "CHECKS",
    "IntegrityLimits",
    "scan_text",
    "InjectionResult",
    "detect_anomalies",
    "AnomalyScore",
    "StreamingAnomalyDetector",
    "StreamingAnomalyResult",
    "analyze_provenance",
    "ProvenanceReport",
    "analyze_duplication",
    "find_embedding_clusters",
    "MinHasher",
    "TextDuplicationCollector",
    "SensitiveFingerprintRegistry",
    "analyze_hubness",
    "k_occurrence",
    "analyze_ingestion",
    "analyze_versions",
    "ChunkRecord",
    "DetectorReport",
    "build_record",
]
