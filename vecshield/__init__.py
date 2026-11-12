"""VecShield — PII safety gate for AI ingestion and training pipelines.

Detect and redact PII/PHI/PCI/secrets *before* text is embedded into a
RAG/vector pipeline or baked into a fine-tuning dataset. Runs entirely locally.

Quick start::

    import vecshield

    vecshield.check_text("contact jane@acme.com").has_pii        # True
    vecshield.redact_text("SSN 123-45-6789")                     # "SSN [REDACTED:PII]"
    report = vecshield.check_chunks(["hello", "card 4111111111111111"])
    report.blocked                                               # True
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version as _dist_version

try:
    #: Read from the installed distribution so pyproject.toml stays the single
    #: source of truth. An uninstalled checkout has no metadata to read.
    __version__ = _dist_version("vecshield")
except PackageNotFoundError:  # pragma: no cover - source checkout only
    __version__ = "0.0.0+unknown"

from vecshield.models import (
    Chunk,
    Classification,
    Finding,
    IngestGateReport,
    ScanJob,
    SensitivityLabel,
    Severity,
)
from vecshield.sdk import (
    CheckResult,
    DatasetReport,
    check_chunks,
    check_dataset,
    check_text,
    redact_text,
)

__all__ = [
    "__version__",
    # SDK
    "check_text",
    "check_chunks",
    "check_dataset",
    "redact_text",
    "CheckResult",
    "DatasetReport",
    # Core types
    "Chunk",
    "Classification",
    "Finding",
    "IngestGateReport",
    "ScanJob",
    "SensitivityLabel",
    "Severity",
]
