"""GDPR / CCPA right-to-erasure impact analysis.

Given a data subject (an email, name, account id, or any identifying string),
find every chunk across the store that contains or references it, so a deletion
request can be executed and evidenced.

Why this is the product's sharpest wedge: you cannot honor "delete my data" if
you don't know which embeddings encode it. Standard DLP can't see inside a vector
store; this enumerates the blast radius and the re-index cost of compliance.

Verification is deliberately not a single question. A vector store commonly
*marks* a record deleted rather than removing it, and an index built over the
old vectors can keep answering for them. Re-enumerating the collection — the
one thing a soft delete is guaranteed to fool — therefore cannot be the only
check. Erasure is verified three ways where the connector allows it:

  enumeration       the subject no longer appears in any inspected chunk
  id re-read        the deleted ids are not returned when addressed directly
  retrieval replay  each deleted chunk's *own stored vector*, captured before
                    the delete, no longer retrieves it

The replay needs no embedding model: the probe is the vector the store itself
held. A disagreement between enumeration and retrieval is a failure, not a
pass — that disagreement is precisely the ghost-vector condition.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from vecshield_platform.connectors.base import Connector, UnsupportedCapability
from vecshield_platform.coverage import check_outcome, count_known


def _compile_subject(subject: str) -> "re.Pattern[str]":
    """Compile a boundary-aware, case-insensitive matcher for the subject.

    Matches the subject as a standalone token rather than a bare substring, so
    e.g. subject "Jon" does not match "Jones". Word boundaries are enforced only
    on edges that are word characters, so identifiers containing punctuation
    (emails like "john.doe@example.com", account ids) still match when they
    appear surrounded by whitespace/punctuation.
    """
    token = subject.strip()
    esc = re.escape(token)
    left = r"(?<!\w)" if token[:1].isalnum() or token[:1] == "_" else ""
    right = r"(?!\w)" if token[-1:].isalnum() or token[-1:] == "_" else ""
    return re.compile(left + esc + right, re.IGNORECASE)


SUBJECT_MARK = "‹SUBJECT›"


def _redact(s: str, pattern: "re.Pattern[str]", pad: int = 20,
            classifier: Any = None) -> str:
    """Show a small window around the match, with the subject itself masked.

    The context is masked the way the chunk view masks it: every value the
    classifier finds in the whole value is masked before the window is cut, so
    a window that starts or ends inside a secret does not show its middle. An
    impact assessment is open to any reader, and the reveal path is the only
    one that returns raw values. With no classifier, or one that fails, the
    context is dropped and only the subject marker is returned.
    """
    m = pattern.search(s)
    if not m:
        return ""
    start = max(0, m.start() - pad)
    end = min(len(s), m.end() + pad)
    lead = "…" if start > 0 else ""
    tail = "…" if end < len(s) else ""
    if classifier is None:
        return lead + SUBJECT_MARK + tail
    try:
        from vecshield_platform.reveal import mask_detected

        masked = mask_detected(s, classifier)
    except Exception:  # noqa: BLE001 — no classification, no context
        return lead + SUBJECT_MARK + tail
    if len(masked) != len(s):
        return lead + SUBJECT_MARK + tail
    window = masked[start:end]
    return (lead + window[: m.start() - start] + SUBJECT_MARK
            + window[m.end() - start:] + tail)


def _preview_classifier() -> Any:
    """The deployment's classifier for masking previews, or None if it cannot load."""
    try:
        from vecshield_platform.detection import build_classifier

        return build_classifier()
    except Exception:  # noqa: BLE001 — previews then carry no context
        return None


#: How many deleted chunks per collection are kept as retrieval probes. The
#: probes hold real embeddings, so this is a memory bound, and the number used
#: is recorded on the verification rather than assumed by the reader.
MAX_PROBES_PER_COLLECTION = 25


@dataclass
class ErasureProbe:
    """A deleted chunk's own vector, captured before the delete.

    Replaying it after the delete asks the store the question enumeration
    cannot: not "is this record listed?" but "does this vector still retrieve?"
    """
    chunk_id: str
    collection: str
    embedding: Optional[list[float]] = None

    def to_dict(self) -> dict:
        # The embedding is deliberately not serialized: it is a probe held for
        # the length of one verification, not evidence to persist.
        return {"chunk_id": self.chunk_id, "collection": self.collection,
                "has_embedding": self.embedding is not None}


@dataclass
class ErasureMatch:
    chunk_id: str
    collection: str
    matched_on: str          # "text" | "metadata:<field>"
    preview: str

    def to_dict(self) -> dict:
        return {"chunk_id": self.chunk_id, "collection": self.collection,
                "matched_on": self.matched_on, "preview": self.preview}

    @classmethod
    def from_dict(cls, d: dict) -> "ErasureMatch":
        return cls(
            chunk_id=d["chunk_id"],
            collection=d["collection"],
            matched_on=d["matched_on"],
            preview=d["preview"],
        )


@dataclass
class ErasureReport:
    subject: str
    generated_at: str
    matches: list[ErasureMatch] = field(default_factory=list)
    collections_affected: dict[str, int] = field(default_factory=dict)
    collection_sizes: dict[str, int] = field(default_factory=dict)
    #: False for managed, inventory-only stores (Bedrock KB, Vertex AI) whose
    #: chunk contents can't be enumerated. When False, chunks_to_delete == 0 does
    #: NOT prove the subject is absent — the backing store must be assessed.
    content_enumerable: bool = True
    # Unknown is deliberate: historical reports did not record coverage.
    coverage_status: str = "unknown"
    requested_collections: Optional[list[str]] = None
    scanned_chunks: dict[str, int] = field(default_factory=dict)
    errors: list[dict[str, Any]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    max_chunks_per_collection: Optional[int] = None

    @property
    def coverage_complete(self) -> bool:
        return (self.content_enumerable and self.coverage_status == "complete"
                and not self.errors and not self.limitations)

    @property
    def chunks_to_delete(self) -> int:
        return len(self.matches)

    @property
    def collections_to_reindex(self) -> list[str]:
        # Deleting points from an ANN index typically warrants a reindex of the
        # affected collections; this is the practical re-embedding/rebuild cost.
        return sorted(self.collections_affected)

    @property
    def reindex_chunk_cost(self) -> int:
        return sum(self.collection_sizes.get(c, 0) for c in self.collections_affected)

    def to_dict(self) -> dict:
        return {
            "subject": self.subject,
            "generated_at": self.generated_at,
            "content_enumerable": self.content_enumerable,
            "coverage_status": self.coverage_status,
            "coverage_complete": self.coverage_complete,
            "requested_collections": self.requested_collections,
            "collection_sizes": dict(self.collection_sizes),
            "scanned_chunks": dict(self.scanned_chunks),
            "errors": list(self.errors),
            "limitations": list(self.limitations),
            "max_chunks_per_collection": self.max_chunks_per_collection,
            "chunks_to_delete": self.chunks_to_delete,
            "collections_affected": self.collections_affected,
            "collections_to_reindex": self.collections_to_reindex,
            "reindex_chunk_cost": self.reindex_chunk_cost,
            "matches": [m.to_dict() for m in self.matches],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ErasureReport":
        """Rehydrate evidence; missing historical coverage stays unknown."""
        return cls(
            subject=d["subject"],
            generated_at=d["generated_at"],
            matches=[ErasureMatch.from_dict(m) for m in d.get("matches", [])],
            collections_affected=dict(d.get("collections_affected", {})),
            collection_sizes=dict(d.get("collection_sizes", {})),
            content_enumerable=d.get("content_enumerable", True),
            coverage_status=d.get("coverage_status", "unknown"),
            requested_collections=(list(d["requested_collections"])
                                   if d.get("requested_collections") is not None else None),
            scanned_chunks=dict(d.get("scanned_chunks", {})),
            errors=list(d.get("errors", [])),
            limitations=list(d.get("limitations", [])),
            max_chunks_per_collection=d.get("max_chunks_per_collection"),
        )


@dataclass
class ErasureVerification:
    subject: str
    generated_at: str
    ok: bool
    remaining: ErasureReport
    expected_deleted: int = 0
    #: Which checks actually ran. A reader must be able to tell a pass that
    #: re-enumerated from a pass that also re-read ids and replayed vectors.
    methods: list[str] = field(default_factory=list)
    #: Chunks the store still returned after deletion, by the method that
    #: caught them. Any entry here is a failure.
    ghost_hits: list[dict] = field(default_factory=list)
    #: Why a method could not run. Never a reason to call the result clean.
    method_limitations: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Do not trust an old serialized ok=true without coverage evidence.
        self.ok = bool(self.ok and self.remaining.coverage_complete
                       and self.remaining.chunks_to_delete == 0
                       and not self.ghost_hits)

    @property
    def outcome(self) -> str:
        # A ghost hit outranks everything: enumeration saying "gone" while the
        # store still serves the record is the failure this check exists for.
        if self.ghost_hits or self.remaining.chunks_to_delete:
            return "failed"
        if self.ok:
            return "passed"
        if self.remaining.coverage_status in ("error", "unsupported"):
            return self.remaining.coverage_status
        return "inconclusive"

    def to_dict(self) -> dict:
        return {
            "subject": self.subject,
            "generated_at": self.generated_at,
            "ok": self.ok,
            "outcome": self.outcome,
            "expected_deleted": self.expected_deleted,
            "remaining_matches": self.remaining.chunks_to_delete,
            "methods": list(self.methods),
            "ghost_hits": [dict(h) for h in self.ghost_hits],
            "method_limitations": list(self.method_limitations),
            "remaining": self.remaining.to_dict(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ErasureVerification":
        remaining = d.get("remaining")
        report = (ErasureReport.from_dict(remaining) if remaining
                  else ErasureReport(subject=d["subject"],
                                     generated_at=d["generated_at"]))
        return cls(
            subject=d["subject"],
            generated_at=d["generated_at"],
            ok=d.get("ok", False),
            remaining=report,
            expected_deleted=d.get("expected_deleted", 0),
            methods=list(d.get("methods", [])),
            ghost_hits=[dict(h) for h in d.get("ghost_hits", [])],
            method_limitations=list(d.get("method_limitations", [])),
        )


@dataclass
class ErasurePlan:
    """Collection of ids to delete, derived from an ErasureReport.

    Built by plan_erasure(); passed to execute_erasure(). Keeps the
    impact report alongside so callers have a single object to audit.
    """
    report: ErasureReport
    by_collection: dict[str, list[str]] = field(default_factory=dict)

    @property
    def total_chunks(self) -> int:
        return sum(len(v) for v in self.by_collection.values())

    def to_dict(self) -> dict:
        return {
            "report": self.report.to_dict(),
            "by_collection": {k: len(v) for k, v in self.by_collection.items()},
            "total_chunks": self.total_chunks,
        }


@dataclass
class ErasureExecution:
    """Result of executing an ErasurePlan via delete_chunks()."""
    subject: str
    executed_at: str
    deleted: dict[str, int] = field(default_factory=dict)   # collection -> count
    errors: dict[str, str] = field(default_factory=dict)    # collection -> error
    verification: Optional["ErasureVerification"] = None

    @property
    def total_deleted(self) -> int:
        return sum(self.deleted.values())

    @property
    def ok(self) -> bool:
        return not self.errors and (
            self.verification is None or self.verification.ok
        )

    @property
    def verified(self) -> bool:
        return bool(not self.errors and self.verification and self.verification.ok)

    def to_dict(self) -> dict:
        return {
            "subject": self.subject,
            "executed_at": self.executed_at,
            "total_deleted": self.total_deleted,
            "deleted": self.deleted,
            "errors": self.errors,
            "ok": self.ok,
            "verified": self.verified,
            "verification": self.verification.to_dict() if self.verification else None,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ErasureExecution":
        verification = d.get("verification")
        return cls(
            subject=d["subject"],
            executed_at=d["executed_at"],
            deleted=dict(d.get("deleted", {})),
            errors=dict(d.get("errors", {})),
            verification=(ErasureVerification.from_dict(verification)
                          if verification else None),
        )


def plan_erasure(report: ErasureReport) -> ErasurePlan:
    """Build a deletion plan from an impact report (dry-run step)."""
    by_collection: dict[str, list[str]] = {}
    for match in report.matches:
        by_collection.setdefault(match.collection, []).append(match.chunk_id)
    return ErasurePlan(report=report, by_collection=by_collection)


def _addresses_by_id(connector: Connector) -> bool:
    """Whether this connector can fetch chunks by id without a full scan.

    The base get_chunks() walks the whole collection and filters, which is the
    same enumeration the first check already did — so re-reading ids through it
    would cost a full pass and establish nothing new. Connectors that override
    it can address a record directly, and only there does the id re-read carry
    information.
    """
    method = getattr(type(connector), "get_chunks", None)
    base = getattr(Connector, "get_chunks", None)
    return method is not None and base is not None and method is not base


def _capture_probes(connector: Connector, collection: str, ids: list[str], *,
                    limit: int = MAX_PROBES_PER_COLLECTION) -> tuple[list[ErasureProbe], str]:
    """Read the vectors of chunks about to be deleted.

    Returns the probes and, when something stopped it, a limitation string.
    Capture failure never blocks a deletion: the subject's erasure is their
    right, and losing the ability to verify it thoroughly is a weaker outcome
    than not erasing at all. It is recorded, not swallowed.
    """
    if not ids:
        return [], ""
    if not _addresses_by_id(connector):
        return [], (f"{connector.kind} cannot address chunks by id, so no retrieval "
                    f"probes were captured for '{collection}'.")
    try:
        chunks = connector.get_chunks(collection, list(ids)[:limit])
    except Exception as exc:
        return [], (f"Probe capture failed for '{collection}' "
                    f"({type(exc).__name__}), so retrieval replay is unavailable there.")
    probes = [ErasureProbe(chunk_id=c.id, collection=collection, embedding=c.embedding)
              for c in chunks]
    without = [p for p in probes if p.embedding is None]
    note = ""
    if without:
        note = (f"{len(without)} chunk(s) in '{collection}' had no stored vector, so "
                "they could not be replayed after deletion.")
    if len(ids) > limit:
        note = (note + " " if note else "") + (
            f"Only the first {limit} of {len(ids)} deleted chunk(s) in '{collection}' "
            "were kept as probes.")
    return [p for p in probes if p.embedding is not None], note


def execute_erasure(
    connector: Connector,
    plan: ErasurePlan,
    *,
    verify: bool = True,
) -> ErasureExecution:
    """Execute a deletion plan, optionally verify erasure afterwards.

    Refused with ``execution.SafeModeRefused`` while safe mode is on.
    Requires the connector to support the "delete" capability.
    Returns an ErasureExecution with per-collection counts and errors.
    If verify=True, re-runs erasure_impact() to produce audit evidence
    that no subject references remain.
    """
    # Before anything else, the store included: safe mode is a deployment
    # switch and binds every caller, administrators too.
    from vecshield_platform.execution import refuse_in_safe_mode

    refuse_in_safe_mode("no chunk is deleted for this erasure")
    if "delete" not in connector.capabilities():
        raise UnsupportedCapability(
            f"{connector.kind} does not support delete_chunks(). "
            "Back up the store, remove chunks manually, and re-index."
        )

    execution = ErasureExecution(
        subject=plan.report.subject,
        executed_at=datetime.now(timezone.utc).isoformat(),
    )

    if not plan.report.coverage_complete:
        execution.errors["coverage"] = (
            "Discovery coverage is incomplete or unknown; re-scan before deletion."
        )
        return execution

    probes: list[ErasureProbe] = []
    probe_notes: list[str] = []
    deleted_ids: dict[str, list[str]] = {}

    for collection, ids in plan.by_collection.items():
        # Capture first: once the chunk is gone its vector is gone with it, and
        # the vector is the only probe that needs no embedding model.
        if verify:
            captured, note = _capture_probes(connector, collection, ids)
            probes.extend(captured)
            if note:
                probe_notes.append(note)
        try:
            n = connector.delete_chunks(collection, ids)
            execution.deleted[collection] = n
            deleted_ids[collection] = list(ids)
            if n != len(ids):
                execution.errors[collection] = (
                    f"Deletion acknowledged {n} of {len(ids)} planned chunks."
                )
        except Exception as exc:
            execution.errors[collection] = str(exc)

    if verify:
        execution.verification = verify_erasure(
            connector,
            plan.report.subject,
            expected_deleted=plan.total_chunks,
            collections=plan.report.requested_collections,
            required_collections=list(plan.report.collection_sizes),
            deleted_ids=deleted_ids,
            probes=probes,
            probe_notes=probe_notes,
        )

    return execution


def erasure_impact(
    connector: Connector,
    subject: str,
    *,
    collections: Optional[list[str]] = None,
    max_chunks_per_collection: Optional[int] = None,
    classifier: Any = None,
) -> ErasureReport:
    """Every chunk that contains or references ``subject``. Read-only.

    ``classifier`` masks the context shown around each match; without one the
    deployment's classifier is built on the first match, and if that fails the
    previews carry the subject marker alone.
    """
    if not subject or not subject.strip():
        raise ValueError("subject must be a non-empty identifier")
    if max_chunks_per_collection is not None and max_chunks_per_collection <= 0:
        raise ValueError("max_chunks_per_collection must be positive")
    pattern = _compile_subject(subject)
    report = ErasureReport(
        subject=subject,
        generated_at=datetime.now(timezone.utc).isoformat(),
        content_enumerable=bool(getattr(connector, "content_enumerable", True)),
        coverage_status="complete",
        requested_collections=list(collections) if collections is not None else None,
        max_chunks_per_collection=max_chunks_per_collection,
    )
    try:
        store = connector.describe()
    except Exception as exc:
        report.errors.append({"stage": "inventory", "error": str(exc)})
        report.coverage_status = "error"
        return report

    targets = store.collections
    if collections is not None:
        requested = set(collections)
        missing = requested - {c.name for c in targets}
        for name in sorted(missing):
            report.errors.append({"stage": "inventory", "collection": name,
                                  "error": "Requested collection was not enumerated."})
        targets = [c for c in targets if c.name in requested]
        if not requested:
            report.limitations.append("No collections were selected for inspection.")

    report.collection_sizes = {c.name: c.count for c in targets}
    if not report.content_enumerable:
        report.coverage_status = "unsupported"
        report.limitations.append(
            "Inventory-only store: chunk content cannot be inspected; assess the backing store."
        )
        return report

    preview_classifier = classifier
    loaded = classifier is not None
    # Read errors left from an earlier pass over this connector are not this
    # search's, and would otherwise be reported against it.
    reset_read_errors = getattr(connector, "reset_read_errors", None)
    if callable(reset_read_errors):
        reset_read_errors()
    for col in targets:
        scanned = 0
        seen: set[str] = set()
        surfaceless = 0
        try:
            for chunk in connector.iter_chunks(col.name):
                if max_chunks_per_collection is not None and scanned >= max_chunks_per_collection:
                    report.limitations.append(f"{col.name}: chunk limit reached before exhaustion.")
                    break
                scanned += 1
                if chunk.id in seen:
                    report.limitations.append(f"{col.name}: duplicate chunk id during enumeration.")
                    continue
                seen.add(chunk.id)
                if (chunk.metadata or {}).get("content_unreadable"):
                    report.errors.append({"stage": "content", "collection": col.name,
                                          "chunk_id": chunk.id, "error": "Content is unreadable."})

                surfaces = [("text", chunk.text)] if chunk.text else []
                surfaces.extend(_metadata_values(chunk.metadata or {}))
                if not any(str(value).strip() for _, value in surfaces):
                    # The scan engine's rule: a chunk with nothing to read was
                    # not inspected, so it cannot support "the subject is absent".
                    surfaceless += 1
                for name, value in surfaces:
                    if not pattern.search(value):
                        continue
                    if not loaded:
                        preview_classifier, loaded = _preview_classifier(), True
                    report.matches.append(ErasureMatch(
                        chunk.id, col.name, name,
                        _redact(value, pattern, classifier=preview_classifier)))
                    report.collections_affected[col.name] = \
                        report.collections_affected.get(col.name, 0) + 1
                    break
        except Exception as exc:
            report.errors.append({"stage": "enumeration", "collection": col.name,
                                  "error": str(exc)})
        report.scanned_chunks[col.name] = len(seen)
        if surfaceless:
            report.limitations.append(
                f"{col.name}: {surfaceless} chunk(s) have no text or metadata to "
                "search (vector only), so the subject's absence from them is not "
                "established.")
        if not count_known(col):
            report.limitations.append(
                f"{col.name}: inspected {len(seen)} unique chunks; the inventory "
                "count could not be read, so whether every chunk was inspected "
                "is not established.")
        elif len(seen) != col.count:
            report.limitations.append(
                f"{col.name}: inspected {len(seen)} unique chunks; inventory reported {col.count}."
            )

    try:
        report.errors.extend({"stage": "content", **error} for error in connector.read_errors())
    except Exception as exc:
        report.errors.append({"stage": "content", "error": str(exc)})

    if report.errors:
        report.coverage_status = "partial" if any(report.scanned_chunks.values()) else "error"
    elif report.limitations:
        report.coverage_status = "partial"

    return report


def _metadata_values(value: Any, path: str = ""):
    """Inspect complete nested metadata, including numeric identifiers."""
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _metadata_values(child, f"{path}.{key}" if path else str(key))
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            yield from _metadata_values(child, f"{path}[{index}]")
    elif isinstance(value, (str, int, float)):
        yield f"metadata:{path}", str(value)


def verify_erasure(
    connector: Connector,
    subject: str,
    *,
    expected_deleted: int = 0,
    collections: Optional[list[str]] = None,
    max_chunks_per_collection: Optional[int] = None,
    required_collections: Optional[list[str]] = None,
    deleted_ids: Optional[dict[str, list[str]]] = None,
    probes: Optional[list[ErasureProbe]] = None,
    probe_notes: Optional[list[str]] = None,
    probe_top_k: int = 10,
) -> ErasureVerification:
    """Verify that a subject no longer appears, and no longer retrieves.

    A post-delete, read-only pass. It does not mutate the vector store;
    callers run their own delete workflow first, then use this to produce
    evidence. Up to three checks run:

    1. **enumeration** — always. The subject appears in no inspected chunk.
    2. **id re-read** — when ``deleted_ids`` is given and the connector can
       address chunks by id. A deleted id the store still returns is a failure.
    3. **retrieval replay** — when ``probes`` are given and the connector
       supports query(). Each probe is a deleted chunk's own stored vector; if
       replaying it retrieves the deleted id, the record is still being served
       even though enumeration says it is gone.

    A check that cannot run is recorded as a limitation. It never becomes a
    pass by omission.
    """
    remaining = erasure_impact(
        connector,
        subject,
        collections=collections,
        max_chunks_per_collection=max_chunks_per_collection,
    )
    missing = set(required_collections or []) - set(remaining.collection_sizes)
    if missing:
        remaining.errors.extend({"stage": "verification", "collection": name,
                                 "error": "Previously inspected collection is no longer visible."}
                                for name in sorted(missing))
        if remaining.coverage_status == "complete":
            remaining.coverage_status = "partial"

    methods = ["enumeration"]
    ghost_hits: list[dict] = []
    limitations: list[str] = list(probe_notes or [])

    # ---- 2. id re-read -----------------------------------------------------
    if deleted_ids:
        if not _addresses_by_id(connector):
            limitations.append(
                f"{connector.kind} cannot address chunks by id, so deleted ids were "
                "not re-read; only enumeration covered them.")
        else:
            methods.append("id_reread")
            for collection, ids in deleted_ids.items():
                if not ids:
                    continue
                try:
                    back = connector.get_chunks(collection, list(ids))
                except Exception as exc:
                    limitations.append(
                        f"Re-reading deleted ids in '{collection}' failed "
                        f"({type(exc).__name__}), so that collection was covered by "
                        "enumeration alone.")
                    continue
                for chunk in back:
                    ghost_hits.append({
                        "method": "id_reread",
                        "collection": collection,
                        "chunk_id": chunk.id,
                        "detail": "The store returned this chunk when its deleted id "
                                  "was read back directly.",
                    })

    # ---- 3. retrieval replay ----------------------------------------------
    if probes:
        if "query" not in connector.capabilities():
            limitations.append(
                f"{connector.kind} does not support query(), so deleted vectors could "
                "not be replayed; a soft delete that leaves the index intact would "
                "not be detected.")
        else:
            methods.append("retrieval_replay")
            expected_gone = {c: set(ids) for c, ids in (deleted_ids or {}).items()}
            for probe in probes:
                if probe.embedding is None:
                    continue
                try:
                    hits = connector.query(probe.collection, probe.embedding,
                                           top_k=probe_top_k)
                except Exception as exc:
                    limitations.append(
                        f"Replaying a deleted vector in '{probe.collection}' failed "
                        f"({type(exc).__name__}).")
                    continue
                gone = expected_gone.get(probe.collection, {probe.chunk_id})
                for hit in hits:
                    # Identity by id only. A different chunk with an identical
                    # vector is a duplicate, not a ghost, and calling it one
                    # would turn a data-modelling choice into a failed erasure.
                    if str(hit.id) in gone:
                        ghost_hits.append({
                            "method": "retrieval_replay",
                            "collection": probe.collection,
                            "chunk_id": str(hit.id),
                            "probe_chunk_id": probe.chunk_id,
                            "detail": "Enumeration reported this chunk deleted, but "
                                      "replaying its own stored vector still "
                                      "retrieved it. The record is soft-deleted; the "
                                      "index was not rebuilt.",
                        })

    return ErasureVerification(
        subject=subject,
        generated_at=datetime.now(timezone.utc).isoformat(),
        ok=(remaining.coverage_complete and remaining.chunks_to_delete == 0
            and not ghost_hits),
        remaining=remaining,
        expected_deleted=expected_deleted,
        methods=methods,
        ghost_hits=ghost_hits,
        method_limitations=limitations,
    )


def erasure_check_outcome(verification: "ErasureVerification", *, store: str) -> dict:
    """Express an erasure verification as a structured check outcome.

    This is how an erasure result reaches criterion evaluation: as an outcome
    with its own coverage, on the same footing as any other check. Zero
    remaining matches over an incompletely inspected scope stays inconclusive
    here exactly as it does in the verification itself.
    """
    remaining = verification.remaining
    if verification.outcome == "passed":
        reason = ("No matches remain in the fully inspected scope, verified by "
                  + ", ".join(verification.methods) + ".")
    elif verification.ghost_hits:
        reason = (f"{len(verification.ghost_hits)} chunk(s) reported deleted are "
                  "still served by the store.")
    elif verification.outcome == "failed":
        reason = f"{remaining.chunks_to_delete} matching chunk(s) still present."
    else:
        reason = ("Discovery could not inspect the whole scope, so the absence of "
                  "matches does not verify deletion.")
    return check_outcome(
        "erasure_verification", store, outcome=verification.outcome, reason=reason,
        complete=remaining.coverage_complete and not verification.method_limitations,
        status=remaining.coverage_status,
        subject_scoped=True, remaining_matches=remaining.chunks_to_delete,
        expected_deleted=verification.expected_deleted,
        methods=list(verification.methods),
        ghost_hits=len(verification.ghost_hits))


def build_erasure_receipt(
    execution: ErasureExecution,
    *,
    store: str,
    actor: str,
    store_kind: str = "",
    scope: Optional[list[str]] = None,
    index_rows_removed: Optional[int] = None,
) -> dict:
    """Build a durable record of what was erased and how it was verified.

    A receipt states **what was checked and what came back**. It is not a
    certificate of compliance, it does not assert that an obligation is met,
    and it carries its own limitations rather than leaving them in a log
    somewhere else. Where a store only soft-deletes, the receipt says so.

    Pure: returns JSON scalars only, so a caller can hand it straight to the
    hash-chained audit log, whose digest sorts keys and must stay stable.
    """
    verification = execution.verification
    limitations: list[str] = []
    if verification is not None:
        limitations.extend(verification.method_limitations)
        limitations.extend(verification.remaining.limitations)

    if verification is None:
        outcome, method_note = "unverified", "No verification was run after deletion."
    elif verification.ghost_hits:
        outcome = "failed"
        method_note = ("The store still serves chunks it reported deleted: "
                       "soft-deleted, index not rebuilt.")
    else:
        outcome = verification.outcome
        method_note = ("Verified by " + ", ".join(verification.methods) + "."
                       if verification.methods else "")

    body: dict[str, Any] = {
        "receipt_version": 1,
        "subject": execution.subject,
        "store": store,
        "store_kind": store_kind,
        "actor": actor,
        "executed_at": execution.executed_at,
        "scope": sorted(scope) if scope else None,
        "deleted_by_collection": dict(sorted(execution.deleted.items())),
        "total_deleted": execution.total_deleted,
        "errors": dict(sorted(execution.errors.items())),
        "verification_outcome": outcome,
        "verification_methods": list(verification.methods) if verification else [],
        "ghost_hits": [dict(h) for h in verification.ghost_hits] if verification else [],
        "coverage_complete": bool(verification.remaining.coverage_complete)
                             if verification else False,
        "limitations": limitations,
        "method_note": method_note,
        # Rows removed from the subject index, when one is in use. None means
        # no index was consulted; 0 means one was and held nothing.
        "index_rows_removed": index_rows_removed,
        "establishes": ("What this store returned when asked three ways. It does not "
                        "establish that a regulatory obligation is satisfied, and it "
                        "does not cover backups, snapshots, or copies outside this "
                        "store."),
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    body["receipt_hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return body
