"""Runtime event and alert types.

Every QueryEvent carries its own `timestamp` (epoch seconds). The detection
engine is driven entirely by these event timestamps, never by wall-clock time
inside the logic. That single rule makes the system:
  * deterministically testable ("alert within 60s" is exact, not flaky)
  * replayable for forensics (re-feed an event log, get identical alerts)
  * correct under clock skew between the collector and the analyzer
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from vecshield.models import Severity


@dataclass
class QueryEvent:
    """A single similarity query observed at runtime."""

    principal: str                 # API key id / user / service identity
    collection: str
    timestamp: float               # epoch seconds (event time)
    query_vector: Optional[list[float]] = None
    result_ids: list[str] = field(default_factory=list)
    result_count: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.result_count and self.result_ids:
            self.result_count = len(self.result_ids)


@dataclass
class Alert:
    """A runtime detection. `dedup_key` groups alerts for cooldown suppression."""

    rule: str
    severity: Severity
    principal: str
    timestamp: float               # event time that triggered the alert
    message: str
    dedup_key: str
    collection: Optional[str] = None
    evidence: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: f"alert-{uuid.uuid4().hex[:10]}")
    suppressed_since: int = 0       # count of duplicates folded in during cooldown

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule": self.rule,
            "severity": self.severity.value,
            "principal": self.principal,
            "collection": self.collection,
            "timestamp": self.timestamp,
            "message": self.message,
            "dedup_key": self.dedup_key,
            "evidence": self.evidence,
            "suppressed_since": self.suppressed_since,
        }
