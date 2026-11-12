"""DSAR (Data Subject Access Request) workflow.

A DSAR bundles together:
  1. An impact scan across every registered store
  2. Optional execution of deletions (with per-store evidence)
  3. An evidence bundle (JSON + summary) suitable for reviewer filing

Lifecycle:
    pending → scanned → executed (only with complete verification)
                        awaiting_verification | partial_error

The record is persisted in the ScanHistory SQLite DB so it survives restarts
and can be reviewed / re-executed if some stores failed.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from vecshield_platform.compliance.erasure import (
    ErasureExecution,
    ErasureReport,
    erasure_impact,
    execute_erasure,
    plan_erasure,
    verify_erasure,
)
from vecshield_platform.connectors.base import UnsupportedCapability


# ------------------------------------------------------------------ #
# Data model                                                           #
# ------------------------------------------------------------------ #

@dataclass
class DSARStoreResult:
    store_id: str
    kind: str
    impact: Optional[ErasureReport] = None
    execution: Optional[ErasureExecution] = None
    error: Optional[str] = None

    @property
    def chunks_found(self) -> int:
        return self.impact.chunks_to_delete if self.impact else 0

    @property
    def chunks_deleted(self) -> int:
        return self.execution.total_deleted if self.execution else 0

    @property
    def coverage_complete(self) -> bool:
        return bool(self.impact and self.impact.coverage_complete)

    @property
    def verified(self) -> bool:
        if self.error or not self.coverage_complete:
            return False
        if self.execution is not None:
            return self.execution.verified
        return self.chunks_found == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "store_id": self.store_id,
            "kind": self.kind,
            "chunks_found": self.chunks_found,
            "chunks_deleted": self.chunks_deleted,
            "error": self.error,
            "coverage_complete": self.coverage_complete,
            "verified": self.verified,
            "impact": self.impact.to_dict() if self.impact else None,
            "execution": self.execution.to_dict() if self.execution else None,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "DSARStoreResult":
        impact = d.get("impact")
        execution = d.get("execution")
        return cls(
            store_id=d["store_id"],
            kind=d.get("kind", ""),
            impact=ErasureReport.from_dict(impact) if impact else None,
            execution=ErasureExecution.from_dict(execution) if execution else None,
            error=d.get("error"),
        )


@dataclass
class DSARRecord:
    id: str
    subject: str
    requested_at: str
    status: str = "pending"  # pending | scanned | executed | awaiting_verification | partial_error
    stores: list[DSARStoreResult] = field(default_factory=list)
    executed_at: Optional[str] = None
    notes: str = ""

    @property
    def total_chunks_found(self) -> int:
        return sum(r.chunks_found for r in self.stores)

    @property
    def total_chunks_deleted(self) -> int:
        return sum(r.chunks_deleted for r in self.stores)

    @property
    def stores_with_matches(self) -> list[DSARStoreResult]:
        return [r for r in self.stores if r.chunks_found > 0]

    @property
    def stores_with_errors(self) -> list[DSARStoreResult]:
        return [r for r in self.stores if r.error or not r.coverage_complete
                or (r.execution is not None and not r.execution.ok)]

    @property
    def coverage_complete(self) -> bool:
        return bool(self.stores) and all(r.coverage_complete for r in self.stores)

    @property
    def verified(self) -> bool:
        return bool(self.stores) and all(r.verified for r in self.stores)

    @property
    def ok(self) -> bool:
        if self.status == "scanned":
            return self.coverage_complete and not self.stores_with_errors
        return self.status == "executed" and self.verified

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "subject": self.subject,
            "requested_at": self.requested_at,
            "status": self.status,
            "ok": self.ok,
            "coverage_complete": self.coverage_complete,
            "verified": self.verified,
            "total_chunks_found": self.total_chunks_found,
            "total_chunks_deleted": self.total_chunks_deleted,
            "stores_with_matches": len(self.stores_with_matches),
            "stores_with_errors": len(self.stores_with_errors),
            "executed_at": self.executed_at,
            "notes": self.notes,
            "stores": [r.to_dict() for r in self.stores],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "DSARRecord":
        """Re-hydrate a DSARRecord from its to_dict() representation.

        Derived summary fields (totals, counts) are recomputed from the nested
        store results, so they are ignored here.
        """
        record = cls(
            id=d["id"],
            subject=d["subject"],
            requested_at=d["requested_at"],
            status=d.get("status", "scanned"),
            stores=[DSARStoreResult.from_dict(s) for s in d.get("stores", [])],
            executed_at=d.get("executed_at"),
            notes=d.get("notes", ""),
        )
        if record.status in ("executed", "verified", "closed") and not record.verified:
            record.status = "partial_error"
        return record

    def evidence_bundle(self) -> dict[str, Any]:
        """Structured evidence suitable for DPO filing / audit attachment."""
        return {
            "dsar_id": self.id,
            "data_subject": self.subject,
            "requested_at": self.requested_at,
            "executed_at": self.executed_at,
            "status": self.status,
            "coverage_complete": self.coverage_complete,
            "verified": self.verified,
            "summary": {
                "stores_scanned": len(self.stores),
                "stores_with_matches": len(self.stores_with_matches),
                "total_chunks_found": self.total_chunks_found,
                "total_chunks_deleted": self.total_chunks_deleted,
                "errors": [{"store": r.store_id,
                            "error": r.error or "Incomplete discovery or execution evidence."}
                           for r in self.stores_with_errors],
                "stores_with_incomplete_coverage": sum(not r.coverage_complete for r in self.stores),
                "stores_verified": sum(r.verified for r in self.stores),
            },
            "per_store_detail": [r.to_dict() for r in self.stores],
            "compliance_note": (
                "This bundle records identifier matches in inspected text and metadata, "
                "deletion acknowledgements, verification coverage, and remaining limitations "
                "for the selected stores. A zero-match result supports absence only within "
                "completely inspected scope. It does not establish deletion from backups, "
                "upstream systems, or embeddings, or a legal compliance conclusion."
            ),
        }


# ------------------------------------------------------------------ #
# Core functions                                                       #
# ------------------------------------------------------------------ #

def create_dsar(subject: str) -> DSARRecord:
    return DSARRecord(
        id=f"dsar-{uuid.uuid4().hex[:12]}",
        subject=subject,
        requested_at=datetime.now(timezone.utc).isoformat(),
        status="pending",
    )


def scan_all_stores(
    dsar: DSARRecord,
    registry,           # StoreRegistry — avoids circular import
    *,
    store_ids: Optional[list[str]] = None,
    index_hits: Optional[dict[str, list[str]]] = None,
) -> DSARRecord:
    """Scan every registered store for the subject. Read-only.

    Updates dsar.stores in-place and sets status to 'scanned'.
    Errors on individual stores are captured; scanning continues.

    ``index_hits`` narrows the search to the collections a subject index
    already recorded this subject in, as ``{store_id: [collection, ...]}``.
    It is a **speed trade with a stated cost**: a store or collection the
    index never covered is not searched, so the result cannot be read as
    exhaustive. Every store narrowed this way carries the narrowing in its
    limitations, and a store with no index rows is still scanned in full
    rather than being reported clean — an index miss means "not recorded",
    never "not present".
    """
    targets = registry.list()
    missing = set()
    if store_ids is not None:
        missing = set(store_ids) - {s.store_id for s in targets}
        targets = [s for s in targets if s.store_id in set(store_ids)]

    dsar.stores = [DSARStoreResult(store_id=s, kind="", error="Requested store is not registered.")
                   for s in sorted(missing)]
    dsar.executed_at = None
    for cfg in targets:
        result = DSARStoreResult(store_id=cfg.store_id, kind=cfg.kind)
        try:
            conn = registry.open(cfg.store_id)
            with conn:
                if not getattr(conn, "content_enumerable", True):
                    # Managed, inventory-only store: no per-chunk enumeration API,
                    # so we cannot assess subject data here. Flag it explicitly
                    # instead of silently reporting "no matches" (a false clean).
                    result.error = (
                        "inventory-only store: no per-chunk enumeration API; "
                        "scan the backing store directly (e.g. OpenSearch/pgvector) "
                        "to assess and erase this subject's data"
                    )
                else:
                    narrowed = (index_hits or {}).get(cfg.store_id)
                    result.impact = erasure_impact(conn, dsar.subject,
                                                   collections=narrowed or None)
                    if narrowed:
                        # Narrowing is why this ran fast, and why it is not a
                        # full search. Recording it on the report keeps the two
                        # facts together.
                        result.impact.limitations.append(
                            "Only the collection(s) a subject index had already "
                            f"recorded were searched ({', '.join(sorted(narrowed))}). "
                            "Collections never indexed were not searched.")
                        if result.impact.coverage_status == "complete":
                            result.impact.coverage_status = "partial"
                    if not result.impact.coverage_complete:
                        result.error = "Discovery coverage is incomplete; inspect impact errors and limitations."
        except Exception as e:
            result.error = str(e)
        dsar.stores.append(result)

    dsar.status = "scanned"
    return dsar


def execute_dsar(
    dsar: DSARRecord,
    registry,
    *,
    store_ids: Optional[list[str]] = None,
    verify: bool = True,
    skip_stores_without_matches: bool = True,
) -> DSARRecord:
    """Execute deletions across all stores that have matching chunks.

    Refused with ``execution.SafeModeRefused`` while safe mode is on, before
    any store is opened. Requires dsar.status == 'scanned'.  Stores that don't support
    delete_chunks() are skipped with an error note — their backing
    stores should be targeted directly (e.g. Bedrock → OpenSearch).
    """
    # Safe mode binds every caller, administrators included: it is a
    # deployment switch, and a DSAR execution deletes customer data.
    from vecshield_platform.execution import refuse_in_safe_mode

    refuse_in_safe_mode("no chunk is deleted for this request")
    if dsar.status not in ("scanned", "partial_error", "awaiting_verification"):
        raise ValueError(
            f"DSAR must be in 'scanned' state before executing; current: {dsar.status}"
        )

    targets = {r.store_id: r for r in dsar.stores}
    if store_ids is not None:
        targets = {k: v for k, v in targets.items() if k in set(store_ids)}

    for store_id, result in targets.items():
        if result.impact is None:
            result.error = result.error or "no impact scan — re-scan before executing"
            continue
        if not result.impact.coverage_complete:
            result.error = "Discovery coverage is incomplete or unknown; re-scan before executing."
            continue
        if skip_stores_without_matches and result.chunks_found == 0:
            continue
        if result.verified:
            continue
        try:
            conn = registry.open(store_id)
            with conn:
                if result.execution and result.execution.ok and not result.execution.verification:
                    # Acknowledged deletions awaiting verification must not be repeated.
                    if verify:
                        result.execution.verification = verify_erasure(
                            conn, dsar.subject, expected_deleted=result.execution.total_deleted,
                            collections=result.impact.requested_collections,
                            required_collections=list(result.impact.collection_sizes),
                        )
                else:
                    plan = plan_erasure(result.impact)
                    result.execution = execute_erasure(conn, plan, verify=verify)
                if not result.execution.ok:
                    result.error = "Deletion or verification failed; inspect execution evidence."
                else:
                    result.error = None
        except UnsupportedCapability as e:
            result.error = f"store does not support deletion: {e}"
        except Exception as e:
            result.error = str(e)

    dsar.executed_at = datetime.now(timezone.utc).isoformat()
    if dsar.verified:
        dsar.status = "executed"
    elif (dsar.coverage_complete and not dsar.stores_with_errors
          and all(r.execution is not None or r.chunks_found == 0 for r in dsar.stores)):
        dsar.status = "awaiting_verification"
    else:
        dsar.status = "partial_error"
    return dsar
