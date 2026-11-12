"""Framework adapters for the ingest gate."""

from __future__ import annotations

from vecshield.ingest.adapters.generic import GuardedIngestResult, guarded_ingest

__all__ = ["guarded_ingest", "GuardedIngestResult"]
