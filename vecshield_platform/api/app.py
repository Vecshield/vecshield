"""VecShield REST API + admin control plane.

Two surfaces over one app:
  * scan/audit/erasure/report — operational endpoints, store referenced by id
  * /admin/* — the control plane the security team uses to register stores and
    manage scoped policies (backed by a persistent ConfigStore)
  * /            — the single-page admin dashboard (static)

Clients never supply DB credentials to the operational endpoints; admins
configure stores once via the admin API/UI. Optional bearer auth guards every
endpoint except /healthz and the UI shell. Auth is role-split: a read-only
token can run scans/audits/reports and read config, while state-changing routes
(store/policy writes, erasure execute, DSAR execute) require the admin token.
With only one token configured it grants both roles (backward compatible).
"""

from __future__ import annotations

import csv
import io
import mimetypes
import os
import time
import json
from datetime import datetime, timezone
from collections import Counter
from typing import TYPE_CHECKING, Any, Callable, Literal, Optional

from pydantic import BaseModel, Field
try:
    from pydantic import ConfigDict
except ImportError:  # pragma: no cover - pydantic v1 fallback
    ConfigDict = None  # type: ignore[assignment]

# Module level on purpose: with postponed annotations FastAPI resolves a
# dependency's ``request: Request`` against module globals, and a name
# imported inside create_app() would be taken for a query parameter.
try:
    from fastapi import Request, Response
except ImportError:  # pragma: no cover - the API extra is not installed
    Request = Response = Any  # type: ignore[assignment,misc]

if TYPE_CHECKING:
    from vecshield.models import Severity
    from vecshield_platform.api.users import UserStore

from vecshield_platform.api.config_store import ConfigStore, _truthy_env
from vecshield_platform.api.jobs import JobQueue
from vecshield_platform.api.registry import StoreRegistry
from vecshield_platform.api.templates import POLICY_TEMPLATES
from vecshield_platform.assessment_settings import (
    apply_settings_scope,
    resolve_audit_settings,
    supported_audit_kwargs,
)
from vecshield_platform.access import (
    api_keys_from_dicts,
    audit_api_keys,
    diff_access,
    grants_from_dicts,
    probe_isolation,
)
from vecshield_platform.compliance import (
    AuditLog,
    build_erasure_receipt,
    erasure_impact,
    execute_erasure,
    plan_erasure,
)
from vecshield_platform.compliance.allowlist import (
    SuppressionError,
    evaluate_suppressions,
)
from vecshield_platform.compliance.report import build_audit_report
from vecshield_platform.compliance.dsar import (
    create_dsar,
    execute_dsar,
    scan_all_stores,
)
from vecshield_platform.cases import CaseTransitionError
from vecshield_platform.evidence import (
    EvidenceArtifact,
    EvidenceError,
    EvidenceReview,
    RiskException,
    accepted_requirements,
    transition_artifact,
    transition_review,
)
from vecshield_platform.history import ScanHistory
from vecshield_platform.detection import (
    DetectionRuntimeError,
    build_classifier,
    detection_status,
)
from vecshield_platform.integrity import scan_integrity
from vecshield_platform.orchestrator import run_full_audit
from vecshield_platform.progress import (
    CONFIGURATION,
    FINISHING_PASS,
    INTEGRITY,
    SAVING_AUDIT,
    WRITING_DPIA,
    audit_phases,
    finish_phase,
    integrity_phases,
    posture_phases,
    publish_plan,
    start_phase,
    tick as progress_tick,
)
from vecshield_platform.scan import scan_store
from vecshield_platform.validation import validate_connector

#: Local-account session cookie and the header that proves a cookie-carrying
#: request came from the console's own script (ADR 0002).
SESSION_COOKIE = "vecshield_session"
CSRF_HEADER = "x-vecshield-csrf"
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

_STATIC_DIR = os.path.join(os.path.dirname(__file__), "dashboard", "dist")
_DASHBOARD_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'"
)

#: The answer a caller without ``operator`` gets when reading a report would
#: mean running a fresh audit. The console keys on this exact text.
NO_SAVED_AUDIT_DETAIL = "no saved audit for this store; an operator must run one"

#: The most rows one findings export carries; beyond it the export says it is partial.
FINDINGS_EXPORT_CAP = 50_000
#: Findings export columns. No evidence: captured examples leave only through reveal.
#: ``store_id`` is the registered id people see; ``store`` is the name the connector
#: reported, which is what findings are recorded under.
FINDINGS_EXPORT_COLUMNS = ("id", "fingerprint", "severity", "category", "title",
                           "description", "store_id", "store", "collection",
                           "case_state", "case_owner", "suppressed", "created_at")

#: Refusals the console shows as-is on the erasure and DSAR execute routes.
ERASURE_NEEDS_DSAR_DETAIL = (
    "Erasing a subject directly has no request a second person can review, so only "
    "an admin may run it. Open a DSAR for the subject instead; another compliance "
    "officer (or an admin) executes it.")
DSAR_SELF_EXECUTE_DETAIL = (
    "You opened this request, so a second person has to execute it: another "
    "compliance officer, or an admin, under this deployment's separation of duties.")
DSAR_UNKNOWN_CREATOR_DETAIL = (
    "This request does not record who opened it, so a second person cannot be "
    "established; an admin has to execute it.")

# Caps for ingest request payloads (improvement plan 1.9). Overridable via env
# for large-batch deployments; enforced by Pydantic so oversized requests are
# rejected with 422 before any classifier runs.
MAX_INGEST_CHUNKS = int(os.environ.get("VECSHIELD_MAX_INGEST_CHUNKS", "1000"))
MAX_CHUNK_TEXT_CHARS = int(os.environ.get("VECSHIELD_MAX_CHUNK_TEXT_CHARS", "200000"))
MAX_SCHEMA_SAMPLE_CHUNKS = max(
    0,
    int(os.environ.get("VECSHIELD_MAX_SCHEMA_SAMPLE_CHUNKS", "5000")),
)
DEFAULT_SCHEMA_SAMPLE_CHUNKS = min(
    max(0, int(os.environ.get("VECSHIELD_SCHEMA_SAMPLE_CHUNKS", "200"))),
    MAX_SCHEMA_SAMPLE_CHUNKS,
)
DEFAULT_SCHEMA_TOP_VALUES = min(
    max(0, int(os.environ.get("VECSHIELD_SCHEMA_TOP_VALUES", "10"))),
    50,
)


class LoginRequest(BaseModel):
    username: str = Field(default="", max_length=256)
    password: str = Field(default="", max_length=1024)


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(default="", max_length=1024)
    new_password: str = Field(default="", max_length=1024)


class CreateUserRequest(BaseModel):
    username: str = Field(max_length=256)
    password: str = Field(max_length=1024)
    roles: list[str] = Field(default_factory=list, max_length=16)


class UpdateUserRequest(BaseModel):
    roles: Optional[list[str]] = Field(default=None, max_length=16)
    disabled: Optional[bool] = None


class ResetPasswordRequest(BaseModel):
    new_password: str = Field(max_length=1024)


class SuggestRequest(BaseModel):
    finding_ids: list[str] = []
    limit: int = 200
    #: A reviewer's explicit choice to propose actions on chunks whose every
    #: match is disputed as not a live value. Off by default, on purpose.
    include_disputed: bool = False
    #: Findings a later check no longer observes (a targeted re-scan, or a
    #: verified case) are set aside unless asked for; proposing a fix for
    #: something already fixed is noise, and the count of those set aside is
    #: always returned.
    include_resolved: bool = False


class SuggestionInput(BaseModel):
    """A suggestion as it comes back from /suggest, sent on to be staged.

    Echoed rather than looked up by id: a suggestion is not persisted, because
    persisting a proposal invites treating it as a decision.
    """

    id: str
    action: str
    finding_id: str
    collection: Optional[str] = None
    chunk_ids: list[str] = []
    rests_on: list[str] = []
    calibrated: bool = False
    rationale: str = ""
    observed_chunks: int = 0
    named_chunks: int = 0
    excluded: list[dict] = []
    #: The classified labels the proposal answers. label_sensitivity writes
    #: these back, so dropping them here would stage a write with nothing to
    #: write and report it as skipped.
    labels: list[str] = []
    #: A condition resolved against the store at staging, for findings that
    #: name one rather than chunks. Validated by actions.validate_selector.
    selector: Optional[dict] = None
    #: Action parameters (a review reason, the tenant to assign). Every value
    #: that reaches the store is recomputed or checked server-side at staging.
    params: dict = {}
    kind: str = ""
    basis: str = ""


class RemediationAttestRequest(BaseModel):
    """A person saying they carried out a guided step. A claim, not a result."""

    guided_id: str = Field(min_length=1, max_length=300)
    note: str = Field(default="", max_length=2000)


class RemediationVerifyRequest(BaseModel):
    guided_id: str = Field(default="", max_length=300)


class StagePlanRequest(BaseModel):
    suggestions: list[SuggestionInput]
    note: str = ""


class ApprovePlanRequest(BaseModel):
    reason: str = ""
    typed_store_id: str = ""


class ExecutePlanRequest(BaseModel):
    approval_id: str
    verify: bool = True


class ErasureRequest(BaseModel):
    subject: str = Field(min_length=1)


class ErasureExecuteRequest(BaseModel):
    subject: str = Field(min_length=1)
    verify: bool = True


class DSARCreateRequest(BaseModel):
    subject: str = Field(min_length=1)
    store_ids: Optional[list[str]] = None
    notes: str = ""


class DSARExecuteRequest(BaseModel):
    store_ids: Optional[list[str]] = None
    verify: bool = True


class AuditRequest(BaseModel):
    tenant_field: Optional[str] = None
    include_integrity: bool = True
    max_chunks_per_collection: Optional[int] = Field(default=None, gt=0)
    no_nlp: bool = False
    nlp_model: Optional[str] = Field(default=None, min_length=1, max_length=200)
    #: Active cryptographic-posture checks. Off unless asked for: the TLS probe
    #: attempts a credential-free plaintext connection, and the retrieval probe
    #: replays stored vectors as queries.
    tls_probe: bool = False
    retrieval_probe: bool = False
    #: Skip the OSV.dev query for client-library CVEs, for estates with no
    #: outbound network. The CVE check is then recorded as inconclusive.
    cve_offline: bool = False


class ReportRequest(BaseModel):
    audit_id: Optional[str] = None
    if ConfigDict is not None:
        model_config = ConfigDict(extra="forbid")


class CaseChangeRequest(BaseModel):
    """A case change always records who, what, and — where it matters — why."""

    to_state: Optional[str] = None
    owner: Optional[str] = Field(default=None, max_length=200)
    reason: str = Field(default="", max_length=2000)
    verified_by_job_id: Optional[str] = None
    if ConfigDict is not None:
        model_config = ConfigDict(extra="forbid")


class BulkCaseRequest(BaseModel):
    """The same change applied to several findings, reported per finding."""

    finding_ids: list[str] = Field(min_length=1, max_length=200)
    to_state: Optional[str] = None
    owner: Optional[str] = Field(default=None, max_length=200)
    reason: str = Field(default="", max_length=2000)
    verified_by_job_id: Optional[str] = None
    if ConfigDict is not None:
        model_config = ConfigDict(extra="forbid")


class ArtifactRequest(BaseModel):
    """Register something collected. Content stays in customer storage."""

    id: Optional[str] = None
    title: str = Field(min_length=1, max_length=300)
    media_type: str = Field(default="application/octet-stream", max_length=200)
    content_hash: Optional[str] = Field(default=None, max_length=200)
    size_bytes: Optional[int] = Field(default=None, ge=0)
    scope: str = Field(default="", max_length=300)
    period_start: Optional[str] = None
    period_end: Optional[str] = None
    supersedes: Optional[str] = None
    note: str = Field(default="", max_length=2000)
    if ConfigDict is not None:
        model_config = ConfigDict(extra="forbid")


class ArtifactStateRequest(BaseModel):
    to_state: str
    reason: str = Field(default="", max_length=2000)
    if ConfigDict is not None:
        model_config = ConfigDict(extra="forbid")


class ReviewRequest(BaseModel):
    """A review is per artifact, criterion, scope, and period — never a flag."""

    id: Optional[str] = None
    artifact_id: str
    criterion_id: str
    requirement: str = Field(default="", max_length=200)
    scope: str = Field(default="", max_length=300)
    period: str = Field(default="", max_length=100)
    if ConfigDict is not None:
        model_config = ConfigDict(extra="forbid")


class ReviewDecisionRequest(BaseModel):
    to_state: str
    reason: str = Field(default="", max_length=2000)
    if ConfigDict is not None:
        model_config = ConfigDict(extra="forbid")


class ExceptionRequest(BaseModel):
    """Tolerating a gap needs a scope, a rationale, an owner, and an expiry."""

    id: Optional[str] = None
    criterion_id: str
    scope: str = Field(min_length=1, max_length=300)
    rationale: str = Field(min_length=1, max_length=4000)
    expires_at: str
    if ConfigDict is not None:
        model_config = ConfigDict(extra="forbid")


class ExceptionApproveRequest(BaseModel):
    """Approving an exception states why the gap may be tolerated (C-8)."""

    # Not min_length: an empty reason gets the explanatory 422 from the route.
    reason: str = Field(default="", max_length=2000)


class CriteriaRequest(BaseModel):
    """Inputs a criterion evaluation cannot invent on the caller's behalf."""

    audit_id: Optional[str] = None
    framework: Optional[str] = None
    applicability: dict[str, str] = Field(default_factory=dict)
    evidence: dict[str, str] = Field(default_factory=dict)
    reviewer_decisions: dict[str, dict[str, Any]] = Field(default_factory=dict)
    if ConfigDict is not None:
        model_config = ConfigDict(extra="forbid")


class ReviewerDecisionRequest(BaseModel):
    """A reviewer's conclusion. The reviewer is the caller; there is no field for it."""

    conclusion: Literal["satisfied", "gap", "not_applicable"]
    rationale: str = Field(min_length=1, max_length=4000)
    #: The saved audit the reviewer was looking at; defaults to the latest.
    audit_id: Optional[str] = Field(default=None, max_length=200)
    period: str = Field(default="", max_length=100)
    if ConfigDict is not None:
        model_config = ConfigDict(extra="forbid")


class ApplicabilityRequest(BaseModel):
    """Answers to a store's applicability questions. Unanswered stays unknown."""

    answers: dict[str, Literal["yes", "no", "requires_confirmation"]] = Field(
        min_length=1, max_length=200)
    if ConfigDict is not None:
        model_config = ConfigDict(extra="forbid")


class IngestChunk(BaseModel):
    id: str
    text: str = Field(default="", max_length=MAX_CHUNK_TEXT_CHARS)
    collection: str = "ingest"
    metadata: dict[str, Any] = Field(default_factory=dict)


class IngestGateRequest(BaseModel):
    chunks: list[IngestChunk] = Field(max_length=MAX_INGEST_CHUNKS)
    mode: str = "soft"                     # "soft" | "hard"
    block_severity: str = "high"
    show_preview: bool = True
    no_nlp: bool = False
    nlp_model: Optional[str] = Field(default=None, min_length=1, max_length=200)


class BoundaryRequest(BaseModel):
    chunks: list[IngestChunk] = Field(max_length=MAX_INGEST_CHUNKS)  # ordered, same document
    zone_chars: int = Field(default=64, ge=1, le=MAX_CHUNK_TEXT_CHARS)
    no_nlp: bool = False
    nlp_model: Optional[str] = Field(default=None, min_length=1, max_length=200)


class AddStoreRequest(BaseModel):
    store_id: str = Field(min_length=1, pattern=r"^[A-Za-z0-9._-]+$")
    kind: str
    conn: dict[str, Any] = Field(default_factory=dict)
    tenant_field: Optional[str] = None
    description: str = ""


class UpdateStoreRequest(BaseModel):
    kind: str
    conn: dict[str, Any] = Field(default_factory=dict)
    tenant_field: Optional[str] = None
    description: str = ""


class TestConnectionRequest(BaseModel):
    """A connection to try before saving it; nothing here is persisted."""

    kind: str
    conn: dict[str, Any] = Field(default_factory=dict)
    #: When editing, masked values ("***") resolve to this store's saved ones.
    store_id: Optional[str] = None
    if ConfigDict is not None:
        model_config = ConfigDict(extra="forbid")


class AddPolicyRequest(BaseModel):
    template_id: Optional[str] = None
    name: Optional[str] = None
    description: str = ""
    when: Optional[dict[str, Any]] = None
    action: Optional[str] = None
    severity: str = "high"
    enabled: bool = True
    scope_store: Optional[str] = None
    scope_collection: Optional[str] = None


class UpdatePolicyRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    when: Optional[dict[str, Any]] = None
    action: Optional[str] = None
    enabled: Optional[bool] = None
    severity: Optional[str] = None
    scope_store: Optional[str] = None
    scope_collection: Optional[str] = None


class AddAllowlistRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=500)
    category: Optional[str] = None
    store: Optional[str] = None
    collection: Optional[str] = None
    rule: Optional[str] = None
    fingerprints: Optional[list[str]] = None
    value_patterns: Optional[list[str]] = None
    owner: str = ""


class AddSuppressionRequest(BaseModel):
    fingerprint: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=500)
    owner: str = Field(min_length=1, max_length=200)
    expires_at: str = Field(min_length=1)
    ticket: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[str] = None


class AlertingConfigRequest(BaseModel):
    enabled: Optional[bool] = None
    webhooks: Optional[list[dict[str, Any]]] = None
    min_severity: Optional[str] = None
    console: Optional[bool] = None


class DetectorSettingsRequest(BaseModel):
    if ConfigDict is not None:
        model_config = ConfigDict(extra="forbid")

    cooldown_s: Optional[float] = None
    bulk_volume: Optional[dict[str, Any]] = None
    collection_sweep: Optional[dict[str, Any]] = None
    enumeration: Optional[dict[str, Any]] = None
    rate_baseline: Optional[dict[str, Any]] = None


class RuntimeEventRequest(BaseModel):
    """A single similarity query observed by a client, forwarded to the live
    runtime monitor. ``timestamp`` defaults to now; ``result_count`` is derived
    from ``result_ids`` when omitted."""

    principal: str
    collection: str
    timestamp: Optional[float] = None
    query_vector: Optional[list[float]] = None
    result_ids: list[str] = Field(default_factory=list)
    result_count: Optional[int] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class KeyAuditRequest(BaseModel):
    keys: list[dict[str, Any]] = Field(default_factory=list)
    stale_days: int = 90
    sensitive_namespaces: Optional[list[str]] = None
    store_name: Optional[str] = None


class RBACDiffRequest(BaseModel):
    intended: list[dict[str, Any]] = Field(default_factory=list)
    actual: list[dict[str, Any]] = Field(default_factory=list)
    store_name: str = "unknown"


class ValidateRequest(BaseModel):
    store_id: Optional[str] = None
    max_collections: int = 5
    sample_chunks: int = 5
    run_scan: bool = True
    run_query: bool = True
    run_key_audit: bool = True


class DatasourceScanRequest(BaseModel):
    kind: str = "local"
    path: Optional[str] = None
    bucket: Optional[str] = None
    container: Optional[str] = None
    prefix: Optional[str] = None
    region: Optional[str] = None
    dataset: Optional[str] = None
    split: Optional[str] = None
    config: Optional[str] = None
    text_field: Optional[str] = None
    format: Optional[str] = None
    no_nlp: bool = False
    nlp_model: Optional[str] = Field(default=None, min_length=1, max_length=200)
    max_records: Optional[int] = None


def _bearer(authorization: Optional[str]) -> Optional[str]:
    """Extract the token from an ``Authorization: Bearer <token>`` header.

    Retained for backward compatibility with external callers; the API's own
    auth now flows through :mod:`vecshield_platform.api.auth`.
    """
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme != "Bearer" or not token:
        return None
    return token


def _mask_alerting(alerting) -> dict:
    """Public view of the alerting config with webhook secrets masked.

    Slack/PagerDuty webhook URLs carry credentials in their path, so only the
    scheme+host is exposed; routing keys are shown as present/absent.
    """
    from vecshield_platform.api.config_store import mask_webhook_url as _mask_url

    return {
        "enabled": alerting.enabled,
        "min_severity": alerting.min_severity,
        "console": alerting.console,
        "webhooks": [
            {
                "url": _mask_url(w.get("url", "")),
                "style": w.get("style", "slack"),
                **({"routing_key": "***"} if w.get("routing_key") else {}),
            }
            for w in alerting.webhooks
        ],
    }


def _metadata_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def _metadata_text(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float, str)):
        return str(value)
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except TypeError:
        return str(value)


def _metadata_preview(value: Any, *, max_chars: int = 140) -> str:
    text = _metadata_text(value)
    return text if len(text) <= max_chars else f"{text[:max_chars - 3]}..."


def _metadata_masker(classifier: Any) -> Callable[[str, Any], str]:
    """``mask(path, raw)``: the preview of ``raw`` as the masked chunk view shows it.

    The value is judged by its own key (the last segment of ``path``, as the
    chunk view judges it), and an array or object is masked element by
    element under its own keys before it is serialised, so ``people[0].ssn``
    is masked even though ``people`` is not an identifying key. The whole
    value is masked before the preview is cut, so a detected span that
    straddles the cut is never left half readable.
    """
    from vecshield_platform.reveal import _mask_metadata

    cache: dict[str, str] = {}

    def mask(path: str, raw: Any) -> str:
        key = path.rsplit(".", 1)[-1].replace("[]", "")
        masked = _mask_metadata({key: raw}, classifier=classifier, matched=(),
                                cache=cache)[key]
        return _metadata_preview(masked)

    return mask


def _walk_metadata(value: Any, prefix: str = ""):
    """Yield flattened metadata paths with their observed values."""
    if isinstance(value, dict):
        if not value and prefix:
            yield prefix, value
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            yield from _walk_metadata(item, path)
        return
    if isinstance(value, list):
        if prefix:
            yield prefix, value
        for item in value:
            if isinstance(item, dict):
                yield from _walk_metadata(item, f"{prefix}[]")
        return
    if prefix:
        yield prefix, value


def _metadata_field_rows(stats: dict[str, dict[str, Any]], sampled: int,
                         max_values: int,
                         mask: Callable[[str, Any], str]) -> list[dict[str, Any]]:
    """One row per field. Only the values returned are masked, so the
    classifier runs on at most ``max_values`` + 3 values per field."""
    rows: list[dict[str, Any]] = []
    for path, data in stats.items():
        type_counts: Counter = data["types"]
        value_counts: Counter = data["values"]
        raw: dict[str, Any] = data["raw"]
        count = int(data["count"])
        # Distinct values can mask to the same text; count them as one.
        top: Counter = Counter()
        for preview, value_count in value_counts.most_common(max_values):
            top[mask(path, raw[preview])] += value_count
        examples = [mask(path, raw[preview]) for preview in data["examples"][:3]]
        rows.append({
            "path": path,
            "count": count,
            "coverage": round(count / sampled, 4) if sampled else 0.0,
            "types": [t for t, _ in type_counts.most_common()],
            "top_values": [
                {"value": value, "count": value_count}
                for value, value_count in top.most_common()
            ],
            "examples": list(dict.fromkeys(examples)),
        })
    return sorted(rows, key=lambda row: (-row["count"], row["path"]))


def _sample_metadata_fields(conn: Any, collection: str, *,
                            sample_chunks: int,
                            max_values: int,
                            mask: Callable[[str, Any], str],
                            ) -> tuple[list[dict[str, Any]], int, bool]:
    stats: dict[str, dict[str, Any]] = {}
    sampled = 0
    truncated = False
    for chunk in conn.iter_chunks(collection):
        if sampled >= sample_chunks:
            truncated = True
            break
        sampled += 1
        seen: set[str] = set()
        for path, value in _walk_metadata(getattr(chunk, "metadata", {}) or {}):
            if path in seen:
                continue
            seen.add(path)
            entry = stats.setdefault(path, {
                "count": 0,
                "types": Counter(),
                "values": Counter(),
                "examples": [],
                # The first full value behind each preview, masked on output.
                "raw": {},
            })
            entry["count"] += 1
            entry["types"][_metadata_type(value)] += 1
            preview = _metadata_preview(value)
            if preview != "":
                entry["values"][preview] += 1
                entry["raw"].setdefault(preview, value)
                if len(entry["examples"]) < 3 and preview not in entry["examples"]:
                    entry["examples"].append(preview)
    return (_metadata_field_rows(stats, sampled, max_values, mask),
            sampled, not truncated)


def _aggregate_metadata_fields(collections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    aggregate: dict[str, dict[str, Any]] = {}
    for col in collections:
        for field in col.get("metadata_fields", []):
            entry = aggregate.setdefault(field["path"], {
                "path": field["path"],
                "count": 0,
                "collections": set(),
                "types": set(),
            })
            entry["count"] += int(field.get("count") or 0)
            entry["collections"].add(col["name"])
            entry["types"].update(field.get("types") or [])
    rows = []
    for entry in aggregate.values():
        rows.append({
            "path": entry["path"],
            "count": entry["count"],
            "collection_count": len(entry["collections"]),
            "collections": sorted(entry["collections"]),
            "types": sorted(entry["types"]),
        })
    return sorted(rows, key=lambda row: (-row["count"], row["path"]))


def _store_schema_payload(store_id: str, conn: Any, *,
                          sample_chunks: int,
                          max_values: int,
                          classifier: Any) -> dict[str, Any]:
    """The schema explorer's view of a store.

    Metadata values (each field's top values and examples, and collection
    metadata) are masked as the masked chunk view masks them: any role can
    read this, and raw values go through the audited reveal path instead.
    """
    from vecshield_platform.reveal import _mask_metadata

    store = conn.describe()
    try:
        capabilities = sorted(conn.capabilities())
    except Exception:  # noqa: BLE001
        capabilities = []
    content_enumerable = bool(getattr(conn, "content_enumerable", True))
    mask = _metadata_masker(classifier)
    collections = []
    errors = []
    for col in store.collections:
        collection = {
            "name": col.name,
            "count": col.count or 0,
            "dimension": col.dimension,
            "embedding_model": col.embedding_model,
            "metadata": _mask_metadata(col.metadata or {}, classifier=classifier,
                                       matched=set()),
            "sample_size": 0,
            "metadata_complete": False,
            "metadata_key_count": 0,
            "metadata_fields": [],
        }
        if content_enumerable and sample_chunks > 0:
            try:
                fields, sampled, complete = _sample_metadata_fields(
                    conn,
                    col.name,
                    sample_chunks=sample_chunks,
                    max_values=max_values,
                    mask=mask,
                )
                collection["sample_size"] = sampled
                collection["metadata_complete"] = complete
                collection["metadata_key_count"] = len(fields)
                collection["metadata_fields"] = fields
            except Exception as e:  # noqa: BLE001
                errors.append({"collection": col.name, "detail": str(e)})
        collections.append(collection)
    total_vectors = sum(int(c["count"] or 0) for c in collections)
    return {
        "ok": True,
        "store_id": store_id,
        "kind": store.kind,
        "name": store.name,
        "endpoint": store.endpoint,
        "metadata": store.metadata or {},
        "content_enumerable": content_enumerable,
        "capabilities": capabilities,
        "collection_count": len(collections),
        "total_vectors": total_vectors,
        "sample_chunks": sample_chunks,
        "collections": collections,
        "metadata_fields": _aggregate_metadata_fields(collections),
        "values_masked": True,
        "errors": errors,
    }


def create_app(
    registry: Optional[StoreRegistry] = None,
    *,
    config_store: Optional[ConfigStore] = None,
    audit_log: Optional[AuditLog] = None,
    scan_history: Optional[ScanHistory] = None,
    job_queue: Optional[JobQueue] = None,
    alert_store: Optional[object] = None,
    runtime_engine: Optional[object] = None,
    auth_token: Optional[str] = None,
    admin_token: Optional[str] = None,
    authenticator: Optional[object] = None,
    jwt_secret: Optional[str] = None,
    jwt_audience: Optional[str] = None,
    jwt_issuer: Optional[str] = None,
    jwt_roles_claim: str = "roles",
    serve_ui: bool = True,
    cors_origins: Optional[list[str]] = None,
    max_body_bytes: Optional[int] = None,
    rate_limit: Optional[int] = None,
    rate_window_s: float = 60.0,
    separation_of_duties: Optional[str] = None,
    user_store: Optional["UserStore"] = None,
    state_dir: Optional[str] = None,
    vulnfeed_scheduler: bool = False,
):
    from fastapi import Depends, FastAPI, HTTPException, Query
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import (
        FileResponse,
        HTMLResponse,
        JSONResponse,
        PlainTextResponse,
    )
    from fastapi.staticfiles import StaticFiles

    from vecshield_platform import metrics
    from vecshield_platform.api.middleware import (
        MaxBodySizeMiddleware,
        RateLimitMiddleware,
        SecurityHeadersMiddleware,
    )

    # Hardening knobs (improvement plan 1.9). Explicit args win, else env, else
    # off — so the default surface is unchanged.
    if cors_origins is None:
        _env = os.environ.get("VECSHIELD_CORS_ORIGINS")
        cors_origins = [o.strip() for o in _env.split(",") if o.strip()] if _env else None
    if max_body_bytes is None:
        _env = os.environ.get("VECSHIELD_MAX_BODY_BYTES")
        max_body_bytes = int(_env) if _env else None
    if rate_limit is None:
        _env = os.environ.get("VECSHIELD_RATE_LIMIT")
        rate_limit = int(_env) if _env else None

    app = FastAPI(title="VecShield", version="0.0.1")

    @app.exception_handler(DetectionRuntimeError)
    async def detection_failed(_request, error: DetectionRuntimeError):
        return JSONResponse(status_code=503, content={"detail": str(error)})

    log = audit_log if audit_log is not None else AuditLog()

    def _log_intent(actor: str, action: str, target: str, details: dict, *,
                      refused: str) -> None:
        """Record intent before an irreversible or sensitive action.

        The audit log writes to disk and raises when it cannot. If the intent
        cannot be recorded the action does not happen: ``refused`` says what
        was not done.
        """
        try:
            log.append(actor, action, target, details)
        except Exception as e:  # noqa: BLE001
            raise HTTPException(
                status_code=503,
                detail=(f"the audit log could not be written ({type(e).__name__}), "
                        f"so {refused}.")) from e

    def _log_done(actor: str, action: str, target: str, details: dict, *,
                     completed: str) -> None:
        """Record an action that has already happened.

        A failure here must not read as a plain server error: the caller is
        told the action completed and only its audit entry is missing.
        """
        try:
            log.append(actor, action, target, details)
        except Exception as e:  # noqa: BLE001
            raise HTTPException(
                status_code=500,
                detail=(f"{completed}, but its audit entry could not be written "
                        f"({type(e).__name__}). Record it manually and check the "
                        "audit log's storage.")) from e
    hist = scan_history  # may be None; writes are skipped when absent

    # F3: the hash-chained audit log is kept for years and cannot be edited,
    # so it must not become a standing list of who asked to be forgotten. A
    # DSAR or erasure subject is logged as a keyed hash: someone holding the
    # deployment key (the subject index key, beside history.db) can check
    # whether an entry concerns a given person; a reader of the log cannot
    # recover who it was. Without history the key lives only for this process.
    import secrets as _secrets_mod
    _ephemeral_subject_salt = _secrets_mod.token_bytes(32)

    def _audit_subject(subject: str) -> str:
        import hashlib as _hashlib
        import hmac as _hmac
        from vecshield_platform.subject_index import normalize_identifier
        salt = hist.subject_salt() if hist is not None else _ephemeral_subject_salt
        digest = _hmac.new(salt, b"vecshield-audit-subject\x00"
                           + normalize_identifier(subject).encode("utf-8"),
                           _hashlib.sha256).hexdigest()
        return f"subject-key:{digest}"
    # A plan still "executing" at startup was claimed by a process that died
    # mid-run (the audit log's single-writer lock means no live server holds
    # it). Some of its writes may have landed, so it is halted, not re-staged.
    if hist is not None:
        for orphan in hist.list_plans(state="executing"):
            hist.set_plan_state(orphan["id"], "halted")
            try:
                log.append("system", "action_plan_halted", orphan["id"],
                           {"reason": "found executing at startup; the process "
                                      "running it stopped before it finished"})
            except Exception:  # noqa: BLE001 - startup must not fail on this
                pass
    # Async job runner: long endpoints can enqueue work with ?background=true
    # and return 202 {job_id}. Threads are spawned lazily on first submit, so
    # apps that never enqueue pay nothing. Persists to history when available.
    jobs = job_queue if job_queue is not None else JobQueue(history=hist)

    if config_store is not None:
        app.state.config = config_store
        app.state.registry = config_store.build_registry()
    else:
        app.state.config = None
        app.state.registry = registry or StoreRegistry()

    def reg() -> StoreRegistry:
        return app.state.registry

    def rebuild_registry() -> None:
        if app.state.config is not None:
            app.state.registry = app.state.config.build_registry()

    # Pluggable auth + RBAC (improvement plan 1.1). Backward compatible: a
    # single auth_token still grants full (admin) access; add admin_token to
    # split read vs. write; add a JWT secret (arg or env) to accept OIDC HS256
    # bearer tokens carrying a real subject + roles. If nothing is configured,
    # auth is disabled (dev/loopback use) and the principal is a synthetic admin.
    from vecshield_platform.api.auth import (
        ADMIN,
        COMPLIANCE,
        OPERATOR,
        AuthError,
        CompositeAuthenticator,
        JWTAuthenticator,
        Principal,
        StaticTokenAuthenticator,
        expand_roles,
    )

    _admin_token = admin_token if admin_token is not None else auth_token
    _read_token = auth_token
    if jwt_secret is None:
        jwt_secret = os.environ.get("VECSHIELD_JWT_SECRET") or None
    if jwt_audience is None:
        jwt_audience = os.environ.get("VECSHIELD_JWT_AUDIENCE") or None
    if jwt_issuer is None:
        jwt_issuer = os.environ.get("VECSHIELD_JWT_ISSUER") or None
    jwt_roles_claim = os.environ.get("VECSHIELD_JWT_ROLES_CLAIM") or jwt_roles_claim

    if authenticator is not None:
        _authn = authenticator
    else:
        _backends = []
        if _admin_token is not None:
            _backends.append(StaticTokenAuthenticator(_admin_token, _read_token))
        if jwt_secret:
            _max_life = os.environ.get("VECSHIELD_JWT_MAX_LIFETIME") or None
            _backends.append(JWTAuthenticator(
                jwt_secret, audience=jwt_audience, issuer=jwt_issuer,
                roles_claim=jwt_roles_claim,
                max_lifetime_s=float(_max_life) if _max_life else None))
        _authn = CompositeAuthenticator(_backends) if _backends else None

    #: Synthetic principal used when auth is disabled entirely.
    _OPEN_PRINCIPAL = Principal("admin", expand_roles({ADMIN}), source="open",
                                granted_roles=frozenset({ADMIN}))

    # Local accounts (ADR 0002). With a user store the console signs people in
    # and hands the browser an HttpOnly session cookie; the synthetic open
    # admin is never used. Bearer tokens (static/JWT) keep working alongside
    # for automation.
    from vecshield_platform.api.auth import SessionAuthenticator

    _login_enabled = user_store is not None
    _sessions = SessionAuthenticator(user_store) if user_store is not None else None
    _auth_enabled = _authn is not None or _login_enabled
    app.state.user_store = user_store

    def _authenticate(request: Request) -> "tuple[Optional[Principal], str]":
        """Identify the caller without enforcing anything.

        Returns ``(principal, via)`` where ``via`` is ``bearer``, ``cookie``,
        ``open``, or ``none``. A bearer credential wins when valid; a rejected
        bearer falls back to a valid session cookie, since both prove identity
        and the cookie path carries its own CSRF check.
        """
        if not _auth_enabled:
            return _OPEN_PRINCIPAL, "open"
        authorization = request.headers.get("authorization")
        if _authn is not None and authorization:
            try:
                principal = _authn.authenticate(authorization)
            except AuthError:
                principal = None
            if principal is not None:
                return principal, "bearer"
        if _sessions is not None:
            principal = _sessions.authenticate_session(
                request.cookies.get(SESSION_COOKIE))
            if principal is not None:
                return principal, "cookie"
        return None, "none"

    def _principal(request: Request, *, allow_password_change: bool = False) -> "Principal":
        """Authenticate and apply the cookie rules (CSRF, forced password change)."""
        principal, via = _authenticate(request)
        if principal is None:
            raise HTTPException(status_code=401, detail="invalid or missing token")
        if via == "cookie":
            if (request.method not in _SAFE_METHODS
                    and request.headers.get(CSRF_HEADER) != "1"):
                raise HTTPException(status_code=403, detail="missing CSRF header")
            if principal.must_change_password and not allow_password_change:
                raise HTTPException(status_code=403, detail="password change required")
        return principal

    def _require(*roles: str):
        """Build a dependency requiring any of ``roles`` (admin implies all).

        Returns the authenticated subject so it flows to AuditLog.append(actor=).
        With no roles, only authentication is required.
        """
        def dependency(request: Request) -> str:
            principal = _principal(request)
            if roles and not any(principal.has_role(r) for r in roles):
                raise HTTPException(
                    status_code=403,
                    detail=f"requires role: {' or '.join(roles)}")
            return principal.subject
        return dependency

    def _require_principal(*roles: str):
        """Like ``_require`` but returns the whole principal, for the few
        endpoints whose decision depends on the caller's roles and not only
        on who they are (self-approval)."""
        def dependency(request: Request) -> "Principal":
            principal = _principal(request)
            if roles and not any(principal.has_role(r) for r in roles):
                raise HTTPException(
                    status_code=403,
                    detail=f"requires role: {' or '.join(roles)}")
            return principal
        return dependency

    require_auth = _require()             # any authenticated principal
    require_admin = _require(ADMIN)       # store/policy/alerting management
    require_compliance = _require(COMPLIANCE)  # DSAR/erasure execution
    require_compliance_principal = _require_principal(COMPLIANCE)

    # Whether a person may approve what they proposed. Strict by default with
    # real identities; workable by default without them, because then every
    # caller is the same synthetic admin and nothing could ever be approved.
    from vecshield_platform.approvals import SeparationOfDuties

    _separation = SeparationOfDuties.resolve(separation_of_duties,
                                             auth_enabled=_auth_enabled)
    app.state.separation_of_duties = _separation
    # Assessments that run against a store and write results (scan, audit,
    # posture, isolation probe, DPIA) and runtime event ingestion. A viewer
    # reads what an operator ran; it does not start runs of its own.
    require_operator = _require(OPERATOR)


    def _connector_failure(e: BaseException) -> str:
        """Category and exception type of a connector failure, never its text.

        Connector errors can echo a DSN or URL with the credential in it.
        """
        from vecshield_platform.validation import classify_connector_error
        return f"{classify_connector_error(e)}: {type(e).__name__}"

    def _logged_failure(e: BaseException, what: str) -> str:
        """``_connector_failure`` for the client; the full exception for the log.

        The server log is where the original message is still needed to
        diagnose a failure, and it never reaches an API caller.
        """
        import logging
        summary = _connector_failure(e)
        logging.getLogger(__name__).warning("%s (%s)", what, summary, exc_info=e)
        return summary

    def _store(store_id: str):
        try:
            return reg().open(store_id)
        except KeyError:
            raise HTTPException(status_code=404, detail=f"unknown store: {store_id}") from None
        except ImportError as e:
            raise HTTPException(
                status_code=503,
                detail=f"store connector unavailable for '{store_id}': {e}",
            ) from e
        except Exception as e:  # noqa: BLE001
            raise HTTPException(
                status_code=400,
                detail=(f"store connection failed for '{store_id}' "
                        f"({_connector_failure(e)})"),
            ) from e

    def _policies_for(store_id: str):
        if app.state.config is not None:
            return app.state.config.effective_policies(store_id)
        return None  # orchestrator falls back to default policies

    def _tag_suppressions(findings: list) -> list:
        """Tag allow-listed / suppressed findings in place; return the active ones.

        False-positive management (improvement plan 1.12). Applied post-detection
        so suppressed findings are still detected, recorded, and counted — merely
        tagged so callers can exclude them from alerts and gate decisions. When
        no config is present, nothing is suppressed.
        """
        cfg = app.state.config
        if cfg is None:
            return list(findings)
        result = evaluate_suppressions(
            findings,
            allowlist=cfg.effective_allowlist(),
            suppressions=cfg.active_suppressions(),
        )
        return result.active

    def _alert_sinks() -> list:
        """Production alert sinks from the current config (empty if disabled)."""
        if app.state.config is None:
            return []
        alerting = app.state.config.get_alerting()
        if not alerting.enabled:
            return []
        from vecshield_platform.runtime import build_sinks
        return build_sinks(alerting)

    def _alert_min_severity() -> "Severity":
        from vecshield.models import Severity
        if app.state.config is None:
            return Severity.HIGH
        return Severity(app.state.config.get_alerting().min_severity)

    # ---------------- live runtime monitor (improvement plan 1.5) ----------
    # The monitor is on by default: a long-lived MonitorEngine runs inside the
    # app, persists every emitted alert to an AlertStore, and also fans out to
    # any configured delivery sinks (webhook/console). Clients forward observed
    # queries to POST /runtime/events; operators read them from /runtime/alerts.
    from vecshield_platform.runtime import (
        AlertStore,
        MonitorEngine,
        PersistentAlertSink,
        detectors_from_settings,
    )

    _alert_store = alert_store if alert_store is not None else AlertStore()

    def _detector_settings() -> dict:
        if app.state.config is None:
            from vecshield_platform.api.config_store import DetectorSettings
            return DetectorSettings().to_dict()
        return app.state.config.get_detector_settings().to_dict()

    def _build_runtime_engine() -> MonitorEngine:
        settings = _detector_settings()
        return MonitorEngine(
            detectors=detectors_from_settings(settings),
            sinks=[PersistentAlertSink(_alert_store), *_alert_sinks()],
            cooldown_s=float(settings["cooldown_s"]),
        )

    if runtime_engine is not None:
        _runtime_engine = runtime_engine
    else:
        _runtime_engine = _build_runtime_engine()
    app.state.alert_store = _alert_store
    app.state.runtime_engine = _runtime_engine

    def _assert_store(store_id: str) -> None:
        """Cheap existence check (no connection) so background submissions can
        still return an immediate 404 for an unknown store."""
        try:
            reg().get(store_id)
        except KeyError:
            raise HTTPException(status_code=404, detail=f"unknown store: {store_id}")

    def _maybe_background(kind: str, work, *, background: bool, actor: str,
                          resource: Optional[str] = None):
        """Run ``work`` inline (returning its dict) or, when background is set,
        enqueue it and return 202 {job_id}. ``work`` must be a self-contained
        thunk that returns a JSON-safe dict."""
        if background:
            job_id = jobs.submit(kind, work, actor=actor, resource=resource)
            return JSONResponse(
                status_code=202,
                content={"job_id": job_id, "status": "queued", "kind": kind},
            )
        return work()

    def _check_nlp_model(nlp_model: str) -> None:
        """Refuse a caller-chosen NLP model that this deployment did not offer.

        The model name reaches spaCy's loader, which also accepts a directory,
        so a free-form value let any caller point detection at a path on the
        server. Only the configured model or a name from the published
        catalogue is accepted.
        """
        from vecshield_platform.detection import DEFAULT_NLP_MODEL
        from vecshield_platform.nlp_models import CATALOG

        name = nlp_model.strip()
        configured = (os.environ.get("VECSHIELD_NLP_MODEL") or DEFAULT_NLP_MODEL).strip()
        if name == configured:
            return
        if "/" in name or "\\" in name or name.startswith(".") or ":" in name:
            raise HTTPException(
                status_code=400,
                detail="nlp_model must be the name of an installed model package, not a path.")
        if name not in CATALOG:
            raise HTTPException(
                status_code=400,
                detail=(f"nlp_model '{name}' is not offered by this deployment; use the "
                        f"configured model ({configured}) or one of: "
                        + ", ".join(sorted(CATALOG)) + "."))

    def _classifier(no_nlp: bool = False, nlp_model: Optional[str] = None):
        if nlp_model is not None:
            _check_nlp_model(nlp_model)
        try:
            return build_classifier(use_nlp=False if no_nlp else None, model=nlp_model)
        except (ValueError, RuntimeError) as e:
            raise HTTPException(status_code=503, detail=f"detection unavailable: {e}") from e

    @app.get("/admin/detection")
    def detection_runtime_status(actor: str = Depends(require_auth)) -> dict:
        """Inspect local detection configuration without loading or downloading models."""
        try:
            return detection_status()
        except ValueError as e:
            raise HTTPException(status_code=503, detail=f"invalid detection configuration: {e}") from e

    # ---------------- local accounts + sessions (ADR 0002) ----------------

    from vecshield_platform.api.users import (
        AccountGuardError,
        AccountLockedError,
        InvalidCredentialsError,
        InvalidUserError,
        PasswordPolicyError,
        UserExistsError,
        UserNotFoundError,
        session_id_for_token,
    )

    def _users():
        if user_store is None:
            raise HTTPException(status_code=404, detail="local sign-in is not enabled")
        return user_store

    def _user_payload(principal: "Principal") -> dict:
        return {
            "username": principal.subject,
            "roles": sorted(principal.granted),
            "effective_roles": sorted(principal.roles),
            "must_change_password": bool(principal.must_change_password),
            "source": principal.source,
        }

    def _session_principal(user) -> "Principal":
        granted = frozenset(user.roles)
        return Principal(user.username, expand_roles(granted), source="session",
                         must_change_password=user.must_change_password,
                         granted_roles=granted)

    def _cookie_secure(request: Request) -> bool:
        flag = os.environ.get("VECSHIELD_COOKIE_SECURE", "").strip().lower()
        return request.url.scheme == "https" or flag in {"1", "true", "yes", "on"}

    def _set_session_cookie(response: Response, request: Request, token: str) -> None:
        response.set_cookie(
            SESSION_COOKIE, token,
            max_age=int(user_store.max_s) if user_store is not None else None,
            path="/", httponly=True, samesite="strict",
            secure=_cookie_secure(request))

    def _clear_session_cookie(response: Response, request: Request) -> None:
        response.delete_cookie(SESSION_COOKIE, path="/", httponly=True,
                               samesite="strict", secure=_cookie_secure(request))

    def _password_policy() -> dict:
        from vecshield_platform.api.users import MIN_PASSWORD_LENGTH
        return {"min_length": MIN_PASSWORD_LENGTH}

    _NO_STORE = {"Cache-Control": "no-store"}

    @app.get("/auth/session")
    def auth_session(request: Request) -> Any:
        """Who the browser is signed in as. Public; never 401s."""
        principal, _via = _authenticate(request)
        return JSONResponse({
            "login_enabled": _login_enabled,
            "authenticated": principal is not None,
            "user": _user_payload(principal) if principal is not None else None,
            "password_policy": _password_policy(),
        }, headers=_NO_STORE)

    @app.post("/auth/login")
    def auth_login(req: LoginRequest, request: Request) -> Any:
        store = _users()
        try:
            user = store.authenticate(req.username, req.password)
        except AccountLockedError as e:
            existing = store.get_user(req.username)
            log.append(existing.username if existing else "unknown", "auth.login_failed",
                       existing.username if existing else "unknown",
                       {"reason": "locked"})
            raise HTTPException(status_code=429, detail=str(e),
                                headers={"Retry-After": str(int(e.retry_after_s) + 1)})
        except InvalidCredentialsError:
            existing = store.get_user(req.username)
            details: dict = {"reason": "invalid_credentials"}
            if existing is not None:
                if existing.disabled:
                    details["reason"] = "disabled"
                if store.is_locked(existing.username):
                    details["locked"] = True
            name = existing.username if existing else "unknown"
            log.append(name, "auth.login_failed", name, details)
            raise HTTPException(status_code=401, detail="invalid username or password")
        session = store.create_session(user.username,
                                       user_agent=request.headers.get("user-agent"))
        log.append(user.username, "auth.login", user.username,
                   {"must_change_password": user.must_change_password})
        response = JSONResponse({"user": _user_payload(_session_principal(user))},
                                headers=_NO_STORE)
        _set_session_cookie(response, request, session.token)
        return response

    @app.post("/auth/logout")
    def auth_logout(request: Request) -> Any:
        principal, via = _authenticate(request)
        token = request.cookies.get(SESSION_COOKIE)
        if token and user_store is not None:
            if via == "cookie" and request.headers.get(CSRF_HEADER) != "1":
                raise HTTPException(status_code=403, detail="missing CSRF header")
            user_store.revoke_session(token)
            if via == "cookie" and principal is not None:
                log.append(principal.subject, "auth.logout", principal.subject, {})
        response = JSONResponse({"ok": True}, headers=_NO_STORE)
        _clear_session_cookie(response, request)
        return response

    @app.post("/auth/password")
    def auth_change_password(req: PasswordChangeRequest, request: Request) -> Any:
        store = _users()
        principal = _principal(request, allow_password_change=True)
        if principal.source != "session":
            raise HTTPException(
                status_code=400,
                detail="password change applies to local accounts signed in to the console")
        token = request.cookies.get(SESSION_COOKIE)
        try:
            user = store.change_password(principal.subject, req.current_password,
                                         req.new_password, keep_token=token)
        except AccountLockedError as e:
            raise HTTPException(status_code=429, detail=str(e),
                                headers={"Retry-After": str(int(e.retry_after_s) + 1)})
        except InvalidCredentialsError:
            log.append(principal.subject, "auth.login_failed", principal.subject,
                       {"reason": "wrong_current_password"})
            raise HTTPException(status_code=401, detail="current password is incorrect")
        except PasswordPolicyError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except UserNotFoundError:
            raise HTTPException(status_code=401, detail="invalid or missing token")
        log.append(principal.subject, "auth.password_changed", principal.subject, {})
        return JSONResponse({"user": _user_payload(_session_principal(user))},
                            headers=_NO_STORE)

    # Self-service session review. Every route acts only on the caller's own
    # sessions; ids are opaque handles, never the stored token hash.

    def _session_caller(request: Request) -> "Principal":
        principal = _principal(request)
        if principal.source != "session":
            raise HTTPException(
                status_code=400,
                detail="sessions apply to local accounts signed in to the console")
        return principal

    @app.get("/auth/sessions")
    def auth_list_sessions(request: Request) -> Any:
        store = _users()
        principal = _session_caller(request)
        return JSONResponse({
            "sessions": store.list_user_sessions(principal.subject),
            "current": session_id_for_token(request.cookies.get(SESSION_COOKIE)),
        }, headers=_NO_STORE)

    @app.post("/auth/sessions/revoke-others")
    def auth_revoke_other_sessions(request: Request) -> Any:
        store = _users()
        principal = _session_caller(request)
        count = store.revoke_user_sessions(
            principal.subject, except_token=request.cookies.get(SESSION_COOKIE))
        log.append(principal.subject, "auth.sessions_revoked_others", principal.subject,
                   {"count": count})
        return JSONResponse({"revoked": count}, headers=_NO_STORE)

    @app.delete("/auth/sessions/{sid}")
    def auth_revoke_session(sid: str, request: Request) -> Any:
        store = _users()
        principal = _session_caller(request)
        if not store.revoke_session_by_id(principal.subject, sid):
            raise HTTPException(status_code=404, detail="no such session")
        log.append(principal.subject, "auth.session_revoked", principal.subject,
                   {"session": sid})
        current = sid == session_id_for_token(request.cookies.get(SESSION_COOKIE))
        response = JSONResponse({"ok": True, "current": current}, headers=_NO_STORE)
        if current:
            _clear_session_cookie(response, request)
        return response

    _require_admin_principal = _require_principal(ADMIN)

    @app.get("/auth/users")
    def auth_list_users(principal: "Principal" = Depends(_require_admin_principal)) -> dict:
        store = _users()
        return {"users": [u.public_dict() for u in store.list_users()]}

    @app.post("/auth/users", status_code=201)
    def auth_create_user(req: CreateUserRequest,
                         principal: "Principal" = Depends(_require_admin_principal)) -> dict:
        store = _users()
        try:
            user = store.create_user(req.username, req.password, req.roles,
                                     created_by=principal.subject)
        except UserExistsError as e:
            raise HTTPException(status_code=409, detail=str(e))
        except (InvalidUserError, PasswordPolicyError) as e:
            raise HTTPException(status_code=400, detail=str(e))
        _log_done(principal.subject, "user.created", user.username,
                  {"roles": list(user.roles), "actor_source": principal.source},
                  completed=f"user {user.username!r} was created")
        return {"user": user.public_dict()}

    @app.patch("/auth/users/{username}")
    def auth_update_user(username: str, req: UpdateUserRequest,
                         principal: "Principal" = Depends(_require_admin_principal)) -> dict:
        store = _users()
        before = store.get_user(username)
        if before is None:
            raise HTTPException(status_code=404, detail=f"unknown user {username.lower()!r}")
        actor_account = principal.subject if principal.source == "session" else None
        try:
            user = store.update_user(before.username, roles=req.roles,
                                     disabled=req.disabled, actor=actor_account)
        except UserNotFoundError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except InvalidUserError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except AccountGuardError as e:
            raise HTTPException(status_code=409, detail=str(e))
        _log_done(principal.subject, "user.updated", user.username, {
            "before": {"roles": list(before.roles), "disabled": before.disabled},
            "after": {"roles": list(user.roles), "disabled": user.disabled},
            "actor_source": principal.source,
        }, completed=f"user {user.username!r} was updated")
        return {"user": user.public_dict()}

    @app.post("/auth/users/{username}/password")
    def auth_reset_password(username: str, req: ResetPasswordRequest,
                            principal: "Principal" = Depends(_require_admin_principal)) -> dict:
        store = _users()
        try:
            user = store.reset_password(username, req.new_password)
        except UserNotFoundError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except PasswordPolicyError as e:
            raise HTTPException(status_code=400, detail=str(e))
        _log_done(principal.subject, "user.password_reset", user.username,
                  {"sessions_revoked": True, "actor_source": principal.source},
                  completed=f"the password of {user.username!r} was reset")
        return {"user": user.public_dict()}

    # ---------------- health + UI ----------------

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok", "stores": len(reg().list())}

    @app.get("/version")
    def version(actor: str = Depends(require_auth)) -> dict:
        """Version/status payload for the dashboard and support bundles."""
        from vecshield_platform import __version__, detection_version

        return {
            "version": __version__,
            "detection_version": detection_version,
            "auth_enabled": _auth_enabled,
            "login_enabled": _login_enabled,
            "admin_enabled": app.state.config is not None,
            "detectors": [d.name for d in getattr(app.state.runtime_engine, "detectors", [])],
            # Saving configuration rebuilds only the default engine. An engine
            # supplied by the host keeps its own settings and accumulated state.
            "runtime_engine_source": "external" if runtime_engine is not None else "default",
            "approvals": _separation.to_dict(),
        }

    @app.get("/livez")
    def livez() -> dict:
        """Liveness: the process is up and serving. Never touches the DB."""
        return {"status": "alive"}

    @app.get("/readyz")
    def readyz() -> Any:
        """Readiness: config/registry loaded and (if configured) the history DB
        is reachable. Returns 503 with per-check detail when not ready so an
        orchestrator can pull the instance out of rotation."""
        checks: dict[str, str] = {}
        ready = True
        try:
            reg()
            checks["registry"] = "ok"
        except Exception:  # noqa: BLE001 — a broken registry means not ready
            checks["registry"] = "error"
            ready = False
        if hist is not None:
            try:
                hist.ping()
                checks["history"] = "ok"
            except Exception:  # noqa: BLE001
                checks["history"] = "error"
                ready = False
        else:
            checks["history"] = "disabled"
        try:
            app.state.alert_store.ping()
            checks["alert_store"] = "ok"
        except Exception:  # noqa: BLE001
            checks["alert_store"] = "error"
            ready = False
        if ready:
            return {"status": "ready", "checks": checks}
        return JSONResponse(status_code=503, content={"status": "not_ready", "checks": checks})

    _metrics_public = _truthy_env("VECSHIELD_METRICS_PUBLIC")

    @app.get("/metrics")
    def metrics_endpoint(request: Request) -> Any:
        """Prometheus text exposition.

        Requires any authenticated caller whenever authentication is on (F8):
        give the scraper a read-only bearer token. ``VECSHIELD_METRICS_PUBLIC=1``
        restores unauthenticated scraping for a deployment that isolates the
        port on a trusted network instead.
        """
        if not _metrics_public:
            _principal(request)
        return PlainTextResponse(
            metrics.render(),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    if serve_ui and os.path.isdir(_STATIC_DIR):
        class _RevalidatingStaticFiles(StaticFiles):
            """Console assets are versioned by content, not by URL.

            Without an explicit policy a browser applies heuristic caching to
            dashboard.js and dashboard.css and can keep serving a stale copy
            for days after an upgrade. `no-cache` still allows the cache, but
            makes every load revalidate against the ETag, so a fixed console
            is the one people see on their next reload.
            """

            async def get_response(self, path: str, scope: Any) -> Any:
                response = await super().get_response(path, scope)
                response.headers["Cache-Control"] = "no-cache"
                return response

        # The console's fonts are WOFF2. Python's MIME table lacks the type on
        # some platforms (Windows, 3.10), and with `nosniff` on every response
        # a font served as an unknown type would be refused by the browser.
        mimetypes.add_type("font/woff2", ".woff2")
        app.mount("/static", _RevalidatingStaticFiles(directory=_STATIC_DIR), name="static")

        @app.get("/", response_class=HTMLResponse)
        def index() -> Any:
            return FileResponse(
                os.path.join(_STATIC_DIR, "index.html"),
                headers={
                    "Content-Security-Policy": _DASHBOARD_CSP,
                    "X-Content-Type-Options": "nosniff",
                    "Referrer-Policy": "no-referrer",
                    "Cache-Control": "no-cache",
                },
            )

    # ---------------- operational ----------------

    @app.get("/stores")
    def list_stores(actor: str = Depends(require_auth)) -> dict:
        return {"stores": [s.public_dict() for s in reg().list()]}

    # ---------------- one chunk, as it is now ----------------
    # A finding stores offsets and a masked preview; the text itself is fetched
    # here on request, classified again, and never written to history.

    require_principal = _require_principal()

    @app.get("/stores/{store_id}/collections/{collection}/chunks/{chunk_id}")
    def reveal_store_chunk(
        store_id: str, collection: str, chunk_id: str,
        reveal: str = Query("masked", description="masked | raw"),
        reason: str = Query("", description="Required when reveal=raw."),
        finding_id: str = Query("", description="Compare against this finding's recorded spans."),
        principal: "Principal" = Depends(require_principal),
    ) -> Any:
        from vecshield_platform.connectors.base import ConnectorError, UnsupportedCapability
        from vecshield_platform.reveal import LEVELS, RAW, RevealError, fetch_chunk, reveal_chunk

        actor = principal.subject
        if reveal not in LEVELS:
            raise HTTPException(status_code=422,
                                detail=f"reveal must be one of {', '.join(LEVELS)}")
        if reveal == RAW:
            if not principal.has_role(COMPLIANCE):
                raise HTTPException(status_code=403,
                                    detail="revealing values requires the compliance role")
            if not reason.strip():
                raise HTTPException(status_code=422,
                                    detail="revealing values records why; give a reason")

        recorded = None
        if finding_id and hist is not None:
            finding = hist.get_finding(finding_id)
            if finding:
                for example in ((finding.get("evidence") or {}).get("examples")) or []:
                    if isinstance(example, dict) and str(example.get("chunk_id")) == chunk_id:
                        recorded = example.get("spans") or []
                        break

        conn = _store(store_id)
        try:
            chunk = fetch_chunk(conn, collection, chunk_id)
        except UnsupportedCapability as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except RevealError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ConnectorError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        if chunk is None:
            raise HTTPException(
                status_code=404,
                detail=f"chunk '{chunk_id}' is not in '{collection}' now. It may have "
                       "been deleted since the assessment that recorded it.")

        revealed = reveal_chunk(chunk, classifier=_classifier(), store=store_id,
                                collection=collection, level=reveal,
                                recorded_spans=recorded)
        if reveal == RAW:
            _log_intent(actor, "chunk_revealed", store_id,
                        {"collection": collection, "chunk_id": chunk_id,
                         "finding_id": finding_id or None, "level": reveal,
                         "reason": reason.strip(), "labels": list(revealed.labels)},
                        refused="the raw value is not shown")
        body = revealed.to_dict()
        body["related_findings"] = (
            [{"id": f["id"], "title": f.get("title"), "severity": f.get("severity"),
              "category": f.get("category")}
             for f in hist.findings_for_chunk(chunk_id, store=None, collection=collection)]
            if hist is not None else [])
        return JSONResponse(body, headers={"Cache-Control": "no-store"})

    @app.get("/stores/{store_id}/collections/{collection}/sample")
    def sample_store_collection(
        store_id: str, collection: str,
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0),
        actor: str = Depends(require_auth),
    ) -> Any:
        """A masked, classified window over a collection, live. Not an assessment."""
        from vecshield_platform.connectors.base import ConnectorError, UnsupportedCapability
        from vecshield_platform.reveal import sample_collection

        conn = _store(store_id)
        try:
            body = sample_collection(conn, collection, classifier=_classifier(),
                                     limit=limit, offset=offset)
        except UnsupportedCapability as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ConnectorError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        return JSONResponse(body, headers={"Cache-Control": "no-store"})

    @app.get("/stores/{store_id}/schema")
    @app.get("/admin/stores/{store_id}/schema")
    def store_schema(
        store_id: str,
        sample_chunks: int = Query(
            DEFAULT_SCHEMA_SAMPLE_CHUNKS,
            ge=0,
            le=MAX_SCHEMA_SAMPLE_CHUNKS,
            description="Maximum chunks sampled per collection for metadata fields.",
        ),
        max_values: int = Query(
            DEFAULT_SCHEMA_TOP_VALUES,
            ge=0,
            le=50,
            description="Maximum distinct metadata values returned per field.",
        ),
        actor: str = Depends(require_auth),
    ) -> dict:
        conn = _store(store_id)
        try:
            payload = _store_schema_payload(
                store_id,
                conn,
                sample_chunks=sample_chunks,
                max_values=max_values,
                classifier=_classifier(),
            )
        except HTTPException:
            raise  # an unavailable required model is a 503, not a store failure
        except Exception as e:  # noqa: BLE001
            raise HTTPException(
                status_code=400,
                detail=(f"schema discovery failed for '{store_id}' "
                        f"({_logged_failure(e, f'schema discovery failed for {store_id}')})"),
            ) from e
        finally:
            conn.close()
        log.append(actor, "schema_discovered", store_id, {
            "collections": payload["collection_count"],
            "sample_chunks": sample_chunks,
            "metadata_fields": len(payload["metadata_fields"]),
        })
        return payload

    def _subject_observer(store_id: str):
        """Build the scan observer that fills the subject index, or None.

        Returns None when there is nowhere to put the rows, so a deployment
        without history simply does not build an index rather than failing a
        scan over it.
        """
        if hist is None:
            return None
        from vecshield_platform.subject_index import make_sink
        return make_sink(store_id, hist.subject_salt(),
                         lambda locs: hist.record_subject_locations(locs))

    @app.post("/stores/{store_id}/scan")
    def scan(store_id: str, no_nlp: bool = False,
             nlp_model: Optional[str] = Query(default=None, min_length=1, max_length=200),
             actor: str = Depends(require_operator)) -> dict:
        conn = _store(store_id)
        started = time.perf_counter()
        try:
            job = scan_store(conn, classifier=_classifier(no_nlp, nlp_model),
                             observer=_subject_observer(store_id))
            if hist is not None:
                # The rows went in while the scan was still running; only now
                # is it known whether it saw everything.
                hist.finalize_subject_scan(
                    store_id, job.id,
                    bool(job.stats.get("coverage", {}).get("complete")))
        finally:
            conn.close()
        _tag_suppressions(job.findings)
        metrics.observe_operation("scan", time.perf_counter() - started)
        metrics.record_findings(job.findings)
        if hist:
            hist.save_job(job, kind=conn.kind if hasattr(conn, "kind") else None)
        log.append(actor, "scan", store_id, {"findings": len(job.findings)})
        return job.to_dict()

    @app.post("/stores/{store_id}/scan/integrity")
    def integrity(store_id: str, collection: str, background: bool = False,
                  actor: str = Depends(require_operator)):
        _assert_store(store_id)

        def _work() -> dict:
            conn = _store(store_id)
            started = time.perf_counter()
            try:
                publish_plan(integrity_phases())
                start_phase(INTEGRITY)
                progress_tick(collection=collection)
                job = scan_integrity(conn, collection)
                kind = conn.kind if hasattr(conn, "kind") else None
            finally:
                conn.close()
            _tag_suppressions(job.findings)
            metrics.observe_operation("scan_integrity", time.perf_counter() - started)
            metrics.record_findings(job.findings)
            if hist:
                hist.save_job(job, kind=kind)
            log.append(actor, "scan_integrity", f"{store_id}/{collection}",
                       {"findings": len(job.findings)})
            finish_phase(INTEGRITY)
            return job.to_dict()

        return _maybe_background("scan_integrity", _work, background=background,
                                 actor=actor, resource=f"{store_id}/{collection}")

    def _refuse_in_safe_mode(actor: str, action: str, target: str) -> None:
        """Deletion routes obey the deployment's safe mode, for every role.

        Checked before a connection is opened, and the refusal is audited.
        """
        from vecshield_platform.execution import SAFE_MODE_ENV, safe_mode
        if safe_mode():
            log.append(actor, f"{action}_refused", target, {"reason": "safe_mode"})
            raise HTTPException(
                status_code=409,
                detail=(f"safe mode is on, so nothing is deleted from the store. Set "
                        f"{SAFE_MODE_ENV}=0 in the deployment to permit erasure."))

    def _single_person_execution(principal: "Principal") -> Optional[str]:
        """How one person may run an irreversible deletion alone, if at all.

        ``admin`` when the caller holds admin, ``policy_permitted`` when the
        deployment's separation of duties is off, else None (a second person
        is needed).
        """
        if principal.has_role(ADMIN):
            return "admin"
        if _separation.allows_self_approval(principal.roles, irreversible=True):
            return "policy_permitted"
        return None

    @app.post("/stores/{store_id}/erasure")
    def erasure(store_id: str, req: ErasureRequest,
                actor: str = Depends(require_compliance)) -> dict:
        conn = _store(store_id)
        try:
            report = erasure_impact(conn, req.subject)
        finally:
            conn.close()
        log.append(actor, "erasure_assessment", store_id,
                   {"subject_key": _audit_subject(req.subject),
                    "chunks": report.chunks_to_delete})
        # Erasure matches the subject string; no classifier runs. The detection
        # block states the configured engine so the report is self-describing,
        # without loading NLP to say so.
        return {**report.to_dict(), "detection": detection_status()}

    def _connector_erasure_notes(conn: Any) -> Optional[dict]:
        notes = getattr(conn, "erasure_notes", None)
        if not callable(notes):
            return None
        try:
            value = notes()
        except Exception:  # noqa: BLE001 - a note must never fail an erasure
            return None
        return value if isinstance(value, dict) and value else None

    def _reseal_receipt(receipt: dict, connector_notes: dict) -> dict:
        """Add connector notes to a receipt and recompute its hash.

        Uses the same canonical form as ``build_erasure_receipt`` (sorted keys,
        compact separators, ``default=str``), so the hash still covers every
        field. A note's ``limitation`` is also appended to ``limitations`` so
        a reader of the receipt alone sees it.
        """
        import hashlib as _hashlib
        body = {k: v for k, v in receipt.items() if k != "receipt_hash"}
        body["connector_notes"] = connector_notes
        limitation = connector_notes.get("limitation")
        if limitation:
            body["limitations"] = [*body.get("limitations", []), limitation]
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
        body["receipt_hash"] = _hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return body

    @app.post("/stores/{store_id}/erasure/execute")
    def erasure_execute(store_id: str, req: ErasureExecuteRequest,
                        background: bool = False,
                        principal: "Principal" = Depends(require_compliance_principal)):
        from vecshield_platform.connectors.base import UnsupportedCapability
        from vecshield_platform.execution import ExecutionError
        actor = principal.subject
        _assert_store(store_id)
        _refuse_in_safe_mode(actor, "erasure_execution", store_id)
        # A direct erasure has no request record a second person could review
        # and run, so it is an admin's (or a deployment without separation of
        # duties). Everyone else goes through a DSAR.
        execution_mode = _single_person_execution(principal)
        if execution_mode is None:
            log.append(actor, "erasure_execution_refused", store_id,
                       {"reason": "second_person_required",
                        "separation_of_duties": _separation.mode})
            raise HTTPException(status_code=403, detail=ERASURE_NEEDS_DSAR_DETAIL)
        store_kind = reg().get(store_id).kind

        def _work() -> dict:
            conn = _store(store_id)
            try:
                report = erasure_impact(conn, req.subject)
                if report.chunks_to_delete == 0:
                    complete = report.coverage_complete
                    log.append(actor, "erasure_assessed", store_id,
                               {"coverage": report.coverage_status, "deleted": 0})
                    return {"ok": complete, "outcome": "passed" if complete else "inconclusive",
                            "message": ("no matches observed in the fully inspected scope"
                                        if complete else "discovery incomplete; verification inconclusive"),
                            "total_deleted": 0, "report": report.to_dict()}
                p = plan_erasure(report)
                _log_intent(actor, "erasure_execution_started", store_id,
                            {"subject_key": _audit_subject(req.subject),
                             "chunks": report.chunks_to_delete,
                             "execution_mode": execution_mode,
                             "actor_source": principal.source},
                            refused="nothing was deleted")
                try:
                    execution = execute_erasure(conn, p, verify=req.verify)
                except UnsupportedCapability as e:
                    raise HTTPException(status_code=400, detail=str(e))
                except ExecutionError as e:
                    log.append(actor, "erasure_execution_refused", store_id,
                               {"reason": str(e)})
                    raise HTTPException(status_code=409, detail=str(e)) from e
                # What the connector did beyond deleting chunks (e.g. whether
                # OpenAI File objects were deleted too, F6).
                connector_notes = _connector_erasure_notes(conn)
            finally:
                conn.close()
            _log_done(actor, "erasure_executed", store_id,
                      {"subject_key": _audit_subject(req.subject),
                       "deleted": execution.total_deleted,
                       "ok": execution.ok, "execution_mode": execution_mode,
                       "separation_of_duties": _separation.mode,
                       "actor_source": principal.source,
                       **({"connector_notes": connector_notes} if connector_notes else {})},
                      completed=f"{execution.total_deleted} chunk(s) were deleted")
            # The receipt is the durable record of what was verified. It goes
            # into the hash-chained log so it cannot be edited after the fact,
            # and it carries its own limitations rather than implying none.
            # The subject's index rows go with their data. An index that
            # outlived the chunks it pointed at would be a standing record
            # that this particular person asked to be forgotten. Done before
            # the receipt is built so the count is inside its hash rather
            # than added to a document already sealed.
            forgotten = None
            if hist is not None and execution.verified:
                from vecshield_platform.subject_index import candidate_keys
                forgotten = hist.forget_subject(
                    candidate_keys(req.subject, hist.subject_salt()))
            # The receipt names the subject by its audit key (F3), so the
            # sealed copy in the chain never holds the raw identifier.
            import dataclasses as _dc
            receipt = build_erasure_receipt(
                _dc.replace(execution, subject=_audit_subject(req.subject)),
                store=store_id, actor=actor, store_kind=store_kind,
                scope=list(execution.deleted), index_rows_removed=forgotten)
            if connector_notes:
                receipt = _reseal_receipt(receipt, connector_notes)
            _log_done(actor, "erasure_receipt", store_id, receipt,
                      completed=(f"{execution.total_deleted} chunk(s) were deleted "
                                 "and the execution was logged"))
            return {**execution.to_dict(), "receipt": receipt}

        return _maybe_background("erasure_execute", _work, background=background,
                                 actor=actor, resource=store_id)

    @app.get("/stores/{store_id}/erasure/receipts")
    def erasure_receipts(store_id: str, limit: int = 50,
                         actor: str = Depends(require_auth)) -> dict:
        """Erasure receipts recorded for this store, newest first.

        Read back from the hash-chained audit log rather than a separate table,
        so a receipt cannot be present here and absent from the chain.
        """
        _assert_store(store_id)
        entries = [e for e in log.entries
                   if e.action == "erasure_receipt" and e.target == store_id]
        entries.reverse()
        chain = log.verify()
        return {
            "store_id": store_id,
            "count": len(entries),
            "chain_verified": chain.ok,
            "chain_reason": None if chain.ok else chain.reason,
            "receipts": [{"seq": e.seq, "timestamp": e.timestamp, "actor": e.actor,
                          **e.details} for e in entries[:max(0, limit)]],
        }

    def _execute_audit(store_id: str, req: AuditRequest, actor: str):
        """Run one audit, persist its snapshot, and return the result object.

        Both the audit endpoint and the report fallback go through here so a
        downloaded report always names an audit that exists in history.
        """
        store = reg().get(store_id)
        settings = resolve_audit_settings(
            app.state.config, store, tenant_field=req.tenant_field,
            include_integrity=req.include_integrity,
            max_chunks_per_collection=req.max_chunks_per_collection,
            tls_probe=req.tls_probe, retrieval_probe=req.retrieval_probe,
            state_dir=state_dir)
        publish_plan(audit_phases(
            include_integrity=req.include_integrity,
            tenant_field=settings.tenant_field,
            retrieval_probe=req.retrieval_probe, closing=SAVING_AUDIT))
        conn = _store(store_id)  # maps connector faults to 404/503/400, never 500
        started = time.perf_counter()
        try:
            result = run_full_audit(
                conn, policies=settings.policies, tenant_field=settings.tenant_field,
                classifier=_classifier(req.no_nlp, req.nlp_model),
                include_integrity=req.include_integrity,
                max_chunks_per_collection=req.max_chunks_per_collection,
                tls_probe=req.tls_probe, retrieval_probe=req.retrieval_probe,
                cve_offline=req.cve_offline,
                sinks=_alert_sinks(), alert_min_severity=_alert_min_severity(),
                suppressor=settings.suppress,
                **supported_audit_kwargs(run_full_audit, settings.audit_kwargs,
                                         settings.scope))
            apply_settings_scope(result.scope, settings.scope)
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001
            raise HTTPException(
                status_code=400,
                detail=(f"audit failed for '{store_id}' "
                        f"({_logged_failure(e, f'audit failed for {store_id}')})"),
            ) from e
        finally:
            conn.close()
        metrics.observe_operation("audit", time.perf_counter() - started)
        for j in result.jobs:
            metrics.record_findings(j.findings)
        if result.alerts_dispatched:
            metrics.ALERTS_DISPATCHED_TOTAL.inc(result.alerts_dispatched)
        if hist:
            hist.save_audit(result, store_id=store_id)
        finish_phase(SAVING_AUDIT)
        log.append(actor, "full_audit", store_id,
                   {"violations": len(result.violations),
                    "max_severity": result.max_severity.value,
                    "alerts_dispatched": result.alerts_dispatched,
                    "tls_probe": req.tls_probe,
                    "retrieval_probe": req.retrieval_probe})
        return result

    @app.post("/stores/{store_id}/audit")
    def audit(store_id: str, req: AuditRequest = AuditRequest(),
              background: bool = False,
              actor: str = Depends(require_operator)):
        _assert_store(store_id)

        def _work() -> dict:
            return _execute_audit(store_id, req, actor).to_dict()

        return _maybe_background("audit", _work, background=background,
                                 actor=actor, resource=store_id)

    @app.post("/stores/{store_id}/report", response_class=HTMLResponse)
    def report(store_id: str, req: ReportRequest = ReportRequest(),
               principal: "Principal" = Depends(require_principal)) -> str:
        return _build_store_report(store_id, req.audit_id, principal.subject,
                                   may_run=principal.has_role(OPERATOR))

    @app.get("/stores/{store_id}/report", response_class=HTMLResponse)
    def report_get(store_id: str, audit_id: Optional[str] = None,
                   principal: "Principal" = Depends(require_principal)) -> str:
        return _build_store_report(store_id, audit_id, principal.subject,
                                   may_run=principal.has_role(OPERATOR))

    def _build_store_report(store_id: str, audit_id: Optional[str], actor: str, *,
                            may_run: bool) -> str:
        """Serve the saved report for an audit the reviewer can point at.

        A named audit is served from history only, so an exported report is
        never a different run wearing an old id. With no id, the latest saved
        snapshot wins; when a store has no audit yet, an operator's request
        runs and persists one so the returned report still names a
        retrievable audit. Anyone else gets a 404: reading a report must not
        start a run against the store.
        """
        _assert_store(store_id)
        if audit_id is not None:
            if hist is None:
                raise HTTPException(status_code=409,
                                    detail="saved reports require scan history")
            report_html = hist.get_audit_report(store_id=store_id, audit_id=audit_id)
            if report_html is None:
                raise HTTPException(status_code=404,
                                    detail=f"no saved audit '{audit_id}' for store '{store_id}'")
            log.append(actor, "report_downloaded", store_id, {"audit_id": audit_id})
            return report_html
        if hist is not None:
            report_html = hist.get_audit_report(store_id=store_id)
            if report_html is not None:
                log.append(actor, "report_downloaded", store_id, {"audit_id": None})
                return report_html
        if not may_run:
            raise HTTPException(status_code=404, detail=NO_SAVED_AUDIT_DETAIL)
        result = _execute_audit(store_id, AuditRequest(), actor)
        log.append(actor, "report_downloaded", store_id, {"audit_id": result.id})
        if hist is not None:
            report_html = hist.get_audit_report(store_id=store_id, audit_id=result.id)
            if report_html is not None:
                return report_html
        return build_audit_report(result, title=f"VecShield — {store_id}")

    @app.get("/audit-log")
    def audit_log_endpoint(
            principal: "Principal" = Depends(require_principal)) -> dict:
        """The hash-chained audit log.

        Entry details carry reveal reasons, DSAR bookkeeping and approval
        rationales, so the full log is a compliance read (F3). Other roles see
        who did what, to what and when, with details withheld, and the chain's
        verification result, which covers every entry either way.
        """
        v = log.verify()
        full = principal.has_role(COMPLIANCE)
        entries = [e.to_dict() for e in log.entries]
        if not full:
            entries = [{**e, "details": None, "details_withheld": True}
                       for e in entries]
        return {"entries": entries, "verified": v.ok, "reason": v.reason,
                "details_withheld": not full,
                **({} if full else {"note": "Entry details need the compliance role."})}

    # ---------------- ingest gate ----------------
    # Stateless: callers POST chunk text directly — no store credentials involved.

    @app.post("/ingest/gate")
    def ingest_gate(req: IngestGateRequest, actor: str = Depends(require_auth)) -> dict:
        from vecshield.ingest import IngestGate
        from vecshield.models import Chunk, Severity
        chunks = [Chunk(id=c.id, collection=c.collection, text=c.text,
                        metadata=c.metadata) for c in req.chunks]
        try:
            sev = Severity(req.block_severity)
        except ValueError:
            raise HTTPException(status_code=400,
                                detail=f"bad block_severity: {req.block_severity}")
        mode = req.mode if req.mode in ("soft", "hard") else "soft"
        gate = IngestGate(classifier=_classifier(req.no_nlp, req.nlp_model),
                          mode=mode, block_severity=sev)
        report = gate.inspect(chunks)        # inspect never raises
        log.append(actor, "ingest_gate", "ingest",
                   {"total": report.total, "blocked": len(report.blocked_chunks)})
        return {**report.to_dict(), "detection": gate.classifier.detection_metadata()}

    @app.post("/ingest/analyze-boundaries")
    def ingest_boundaries(req: BoundaryRequest,
                          actor: str = Depends(require_auth)) -> dict:
        from vecshield.ingest import ChunkBoundaryAnalyzer
        from vecshield.models import Chunk
        chunks = [Chunk(id=c.id, collection=c.collection, text=c.text,
                        metadata=c.metadata) for c in req.chunks]
        analyzer = ChunkBoundaryAnalyzer(classifier=_classifier(req.no_nlp, req.nlp_model),
                                         zone_chars=req.zone_chars)
        findings = analyzer.analyze(chunks)
        log.append(actor, "ingest_boundaries", "ingest",
                   {"chunks": len(chunks), "findings": len(findings)})
        return {"chunks": len(chunks), "findings": [f.to_dict() for f in findings],
                "detection": analyzer.classifier.detection_metadata()}

    # ---------------- posture & DPIA ----------------

    @app.post("/stores/{store_id}/posture")
    def posture(store_id: str, background: bool = False,
                actor: str = Depends(require_operator)):
        from vecshield_platform.posture import run_posture_audit
        _assert_store(store_id)

        def _work() -> dict:
            conn = _store(store_id)
            try:
                publish_plan(posture_phases())
                start_phase(CONFIGURATION)
                job = run_posture_audit(conn)
            finally:
                conn.close()
            if hist:
                hist.save_job(job)
            log.append(actor, "posture_audit", store_id,
                       {"max_severity": job.max_severity.value,
                        "findings": len(job.findings)})
            finish_phase(CONFIGURATION)
            return job.to_dict()

        return _maybe_background("posture", _work, background=background,
                                 actor=actor, resource=store_id)

    @app.post("/stores/{store_id}/probe-isolation")
    def probe_isolation_endpoint(store_id: str, collection: str, tenant_field: str,
                                 # Deprecated and ignored: the check sizes every
                                 # query to cover the whole collection.
                                 top_k: int = Query(default=10, deprecated=True),
                                 actor: str = Depends(require_operator)) -> dict:
        # Standalone tenant-isolation probe for one collection (reuses the same
        # engine the full audit calls). Reports a coverage-gap finding rather
        # than raising when the connector can't be probed.
        conn = _store(store_id)
        try:
            job = probe_isolation(conn, collection, tenant_field, top_k=top_k)
        except Exception as e:  # noqa: BLE001
            # The probe could not record an outcome. Say so, in the log and to
            # the caller, rather than answer with a bare 500.
            log.append(actor, "probe_isolation_failed", f"{store_id}/{collection}",
                       {"tenant_field": tenant_field,
                        "error": _connector_failure(e)})
            raise HTTPException(
                status_code=502,
                detail=(f"the isolation probe of '{store_id}/{collection}' could not "
                        f"complete ({_connector_failure(e)}); no outcome was recorded."),
            ) from e
        finally:
            conn.close()
        if hist:
            hist.save_job(job)
        log.append(actor, "probe_isolation", f"{store_id}/{collection}",
                   {"tenant_field": tenant_field, "findings": len(job.findings),
                    "max_severity": job.max_severity.value})
        return job.to_dict()

    @app.post("/stores/{store_id}/audit-keys")
    def audit_keys_endpoint(store_id: str, req: KeyAuditRequest,
                            actor: str = Depends(require_auth)) -> dict:
        # Stateless: audits a caller-supplied key inventory (no generic "list
        # keys" connector API exists). The store id only scopes the report name.
        try:
            reg().get(store_id)
        except KeyError:
            raise HTTPException(status_code=404, detail=f"unknown store: {store_id}")
        keys = api_keys_from_dicts(req.keys)
        findings = audit_api_keys(
            keys, store_name=req.store_name or store_id, stale_days=req.stale_days,
            sensitive_namespaces=set(req.sensitive_namespaces or []))
        log.append(actor, "key_audit", store_id,
                   {"keys": len(keys), "findings": len(findings)})
        return {"findings": [f.to_dict() for f in findings]}

    @app.get("/security/cves")
    def security_cves(offline: bool = False,
                      actor: str = Depends(require_auth)) -> dict:
        # Stateless: scans the server's installed connector libraries, no store.
        from vecshield_platform.posture import scan_cves
        findings = scan_cves(offline=offline)
        log.append(actor, "cve_scan", "dependencies", {"findings": len(findings)})
        return {"findings": [f.to_dict() for f in findings]}

    @app.get("/stores/{store_id}/cves")
    def store_cves(store_id: str, offline: bool = False,
                   actor: str = Depends(require_auth)) -> dict:
        # Scans only the client library for this store's connector kind. Reads
        # the kind from the registry, so no live connection is required.
        from vecshield_platform.posture import scan_cves
        try:
            kind = reg().get(store_id).kind
        except KeyError:
            raise HTTPException(status_code=404, detail=f"unknown store: {store_id}")
        findings = scan_cves(kinds=[kind], offline=offline, store_label=store_id)
        log.append(actor, "cve_scan", store_id,
                   {"kind": kind, "findings": len(findings)})
        return {"findings": [f.to_dict() for f in findings]}

    @app.post("/stores/{store_id}/pia")
    def pia(store_id: str, req: AuditRequest = AuditRequest(),
            background: bool = False,
            actor: str = Depends(require_operator)):
        _assert_store(store_id)

        def _work() -> dict:
            report = _build_pia(store_id, req, actor)
            return report.to_dict()

        return _maybe_background("pia", _work, background=background,
                                 actor=actor, resource=store_id)

    @app.post("/stores/{store_id}/pia/html", response_class=HTMLResponse)
    def pia_html(store_id: str, req: AuditRequest = AuditRequest(),
                 actor: str = Depends(require_operator)) -> str:
        from datetime import datetime, timezone
        from vecshield_platform.compliance.pia import build_pia_html
        report = _build_pia(store_id, req, actor)
        return build_pia_html(
            report, generated_at=datetime.now(timezone.utc).isoformat())

    @app.get("/stores/{store_id}/pia/html", response_class=HTMLResponse)
    def pia_html_get(store_id: str, job_id: Optional[str] = None,
                     principal: "Principal" = Depends(require_principal)) -> str:
        if job_id:
            return _pia_html_from_run(store_id, job_id)
        # Without a finished run to render, this would run a fresh audit pass.
        if not principal.has_role(OPERATOR):
            _assert_store(store_id)
            raise HTTPException(status_code=404, detail=NO_SAVED_AUDIT_DETAIL)
        return pia_html(store_id, AuditRequest(), principal.subject)

    def _pia_html_from_run(store_id: str, job_id: str) -> str:
        """Render the document for a DPIA run that already finished.

        Without this, the only printable DPIA was a fresh run, which can differ
        from the draft a reviewer has just read. The report comes from the
        server's own run record, never from the caller, and must be a finished
        DPIA of this store.
        """
        from datetime import datetime, timezone
        from vecshield_platform.compliance.pia import PIAReport, build_pia_html
        _assert_store(store_id)
        job = jobs.get(job_id)
        if (job is None or job.get("kind") != "pia" or job.get("resource") != store_id
                or job.get("status") != "succeeded" or not isinstance(job.get("result"), dict)):
            raise HTTPException(status_code=404,
                                detail="no finished DPIA run with that id for this store")
        data = job["result"]
        fields = set(PIAReport.__dataclass_fields__)
        report = PIAReport(**{k: v for k, v in data.items() if k in fields})
        return build_pia_html(report, generated_at=str(
            job.get("finished_at") or datetime.now(timezone.utc).isoformat()))

    def _build_pia(store_id: str, req: AuditRequest, actor: str):
        # The DPIA is read off an audit pass, so it resolves the same settings a
        # full audit of this store would: its policies, tenant field, allow-list
        # and suppressions, and the chunk cap the caller asked for. It used to
        # drop the cap and resolve policies on its own, so a DPIA and an audit
        # of the same store could disagree about what was inspected.
        from vecshield_platform.compliance import generate_pia
        _assert_store(store_id)
        store = reg().get(store_id)
        settings = resolve_audit_settings(
            app.state.config, store, tenant_field=req.tenant_field,
            include_integrity=req.include_integrity,
            max_chunks_per_collection=req.max_chunks_per_collection,
            tls_probe=req.tls_probe, retrieval_probe=req.retrieval_probe,
            state_dir=state_dir)
        publish_plan(audit_phases(
            include_integrity=req.include_integrity,
            tenant_field=settings.tenant_field,
            retrieval_probe=req.retrieval_probe, closing="dpia"))
        conn = _store(store_id)
        try:
            result = run_full_audit(conn, policies=settings.policies,
                                    classifier=_classifier(req.no_nlp, req.nlp_model),
                                    tenant_field=settings.tenant_field,
                                    include_integrity=req.include_integrity,
                                    max_chunks_per_collection=req.max_chunks_per_collection,
                                    tls_probe=req.tls_probe,
                                    retrieval_probe=req.retrieval_probe,
                                    cve_offline=req.cve_offline,
                                    suppressor=settings.suppress,
                                    **supported_audit_kwargs(run_full_audit,
                                                             settings.audit_kwargs,
                                                             settings.scope))
            apply_settings_scope(result.scope, settings.scope)
        finally:
            conn.close()
        finish_phase(FINISHING_PASS)
        start_phase(WRITING_DPIA)
        # Named by its registry id, not the connector's URI or local path.
        report = generate_pia(result, store=store_id)
        finish_phase(WRITING_DPIA)
        log.append(actor, "pia_generated", store_id,
                   {"high_risk": report.high_risk,
                    "residual_risk": report.residual_risk})
        return report

    @app.post("/ingest/redact")
    def ingest_redact(req: IngestGateRequest,
                      actor: str = Depends(require_auth)) -> dict:
        # Stateless anonymization: returns chunk text with PII spans masked.
        from vecshield.ingest import IngestGate
        from vecshield.models import Chunk
        gate = IngestGate(classifier=_classifier(req.no_nlp, req.nlp_model))
        chunks = [Chunk(id=c.id, collection=c.collection, text=c.text,
                        metadata=c.metadata) for c in req.chunks]
        clean, n = gate.redact(chunks)
        log.append(actor, "ingest_redact", "ingest",
                   {"chunks": len(chunks), "spans_redacted": n})
        payload = {
            "spans_redacted": n,
            "detection": gate.classifier.detection_metadata(),
        }
        if req.show_preview:
            payload["chunks"] = [{"id": c.id, "collection": c.collection,
                                  "text": c.text, "metadata": c.metadata} for c in clean]
        return payload

    # ---------------- datasource scan ----------------

    @app.post("/datasources/scan")
    def datasource_scan(req: DatasourceScanRequest, background: bool = False,
                        actor: str = Depends(require_admin)):
        # Stateless: builds a datasource from the request spec and scans it for
        # sensitive content. No registered store or DB credentials involved.
        def _work() -> dict:
            from vecshield.datascan import scan_datasource
            from vecshield_platform.datasources import build_datasource

            classifier = _classifier(req.no_nlp, req.nlp_model)

            opts = req.model_dump(exclude_none=True)
            for k in ("kind", "no_nlp", "nlp_model", "max_records"):
                opts.pop(k, None)
            try:
                source = build_datasource(req.kind, **opts)
                with source:
                    job = scan_datasource(source, classifier=classifier,
                                          max_records_per_dataset=req.max_records)
                    job.stats["detection"] = classifier.detection_metadata()
            except Exception as e:  # noqa: BLE001
                raise HTTPException(status_code=400,
                                    detail=f"datasource scan failed: {e}")
            log.append(actor, "datasource_scan", req.kind,
                       {"findings": len(job.findings),
                        "max_severity": job.max_severity.value})
            return job.to_dict()

        return _maybe_background("datasource_scan", _work, background=background,
                                 actor=actor, resource=req.kind)

    # ---------------- admin control plane ----------------

    def _require_config() -> ConfigStore:
        if app.state.config is None:
            raise HTTPException(status_code=409,
                                detail="admin disabled: server started without a config store")
        return app.state.config

    @app.get("/admin/policy-templates")
    def policy_templates(actor: str = Depends(require_auth)) -> dict:
        from vecshield_platform.api.templates import enriched_policy_templates
        return {"templates": enriched_policy_templates(POLICY_TEMPLATES)}

    # ----------------------------------------------------------------- #
    # Staged actions: suggest, stage, review, approve, execute, verify.     #
    # ----------------------------------------------------------------- #

    @app.post("/stores/{store_id}/actions/suggest")
    def suggest_actions(store_id: str, req: SuggestRequest,
                        actor: str = Depends(require_auth)) -> dict:
        """Propose actions for findings, and report the ones refused.

        Read-only. The 'withheld' list is part of the answer, not a diagnostic:
        a reader is entitled to know that a delete was available in principle
        and refused on the evidence.
        """
        from vecshield_platform.remediation import catalogue_all, proposal_dict

        # An unknown store must not come back as an empty proposal list: "there
        # is nothing to propose" and "there is no such store" are different
        # answers, and only one of them is reassuring.
        try:
            store_cfg = reg().get(store_id)
        except KeyError:
            raise HTTPException(status_code=404,
                                detail=f"unknown store: {store_id}") from None
        if hist is None:
            raise HTTPException(
                status_code=503,
                detail="suggestions are derived from stored findings, and this "
                       "deployment has no scan history configured.")
        # Findings record the store as the connector describes itself (a path or
        # endpoint); the registry keys by store_id. Querying by store_id alone
        # returns nothing and reads as "no findings", which is the wrong answer.
        observed = hist.observed_store_names(store_id) or [store_id]
        result = hist.query_findings(stores=observed, limit=req.limit)
        records = result.get("findings", []) if isinstance(result, dict) else result
        wanted = set(req.finding_ids)
        findings = [{**dict(f), "store": store_id}
                    for f in records if not wanted or f.get("id") in wanted]
        for finding in findings:
            if isinstance(finding.get("evidence"), str):
                try:
                    finding["evidence"] = json.loads(finding["evidence"])
                except ValueError:
                    finding["evidence"] = {}
        # The same observation recorded by several runs is one thing to fix.
        # Keep the most recent record of each fingerprint unless the caller
        # named findings, and say how many older records were set aside.
        #
        # "Most recent" is the record the work is attached to, when there is
        # one: a re-scan that still observes a finding records it again under a
        # new id, and following that id would drop the case and the plan that
        # belong to the observation. A record whose case someone has moved
        # (the latest such) is kept; otherwise the newest record is.
        superseded = 0
        if not wanted:
            def worked(f: dict) -> str:
                case = f.get("case") or {}
                return str(case.get("updated_at") or "") \
                    if isinstance(case, dict) and case.get("state") not in (None, "new") else ""

            groups: dict[str, list[dict]] = {}
            latest = []
            for finding in findings:
                fp = finding.get("fingerprint") or (finding.get("evidence") or {}).get(
                    "fingerprint")
                if fp:
                    groups.setdefault(str(fp), []).append(finding)
                else:
                    latest.append(finding)
            for group in groups.values():
                group.sort(key=lambda f: (worked(f), str(f.get("created_at") or "")),
                           reverse=True)
                latest.append(group[0])
                superseded += len(group) - 1
            findings = sorted(latest, key=lambda f: str(f.get("created_at") or ""),
                              reverse=True)
        resolutions = _resolutions(findings, records)
        shown = [f for f in findings
                 if req.include_resolved or str(f.get("id")) not in resolutions]
        catalogues = catalogue_all(shown, store_id=store_id, store_kind=store_cfg.kind,
                                   tenant_field=store_cfg.tenant_field,
                                   include_disputed=req.include_disputed)
        by_id = {str(f.get("id")): f for f in findings}
        shown_ids = {str(f.get("id")) for f in shown}
        set_aside = [f for f in findings if str(f.get("id")) not in shown_ids]
        return {
            "store": store_id,
            "findings_considered": len(findings),
            "findings_superseded": superseded,
            "findings_resolved": len(resolutions),
            "include_disputed": req.include_disputed,
            "include_resolved": req.include_resolved,
            "suggestions": [proposal_dict(s) for c in catalogues for s in c.suggestions],
            "withheld": [w.to_dict() for c in catalogues for w in c.withheld],
            "guided": [g.to_dict() for c in catalogues for g in c.guided],
            "findings": {c.finding_id: {
                "title": by_id.get(c.finding_id, {}).get("title"),
                "severity": by_id.get(c.finding_id, {}).get("severity"),
                "collection": by_id.get(c.finding_id, {}).get("collection"),
                "category": by_id.get(c.finding_id, {}).get("category"),
                "case": (by_id.get(c.finding_id, {}).get("case") or {}).get("state"),
                "kind": c.kind, "kind_label": c.to_dict()["kind_label"],
                "resolution": resolutions.get(c.finding_id),
                "note": c.note} for c in catalogues},
            # What was set aside as resolved, so "nothing to do" is never the
            # silent result of a filter.
            "resolved": {str(f.get("id")): {
                "title": f.get("title"), "severity": f.get("severity"),
                "collection": f.get("collection"),
                "resolution": resolutions[str(f.get("id"))]} for f in set_aside},
            "note": ("A suggestion is a proposal. Nothing is staged or executed by "
                     "this call. Guided steps are carried out by a person and "
                     "verified by a re-scan."),
        }

    @app.post("/stores/{store_id}/actions/plans")
    def stage_plan(store_id: str, req: StagePlanRequest,
                   actor: str = Depends(require_compliance)) -> dict:
        """Freeze suggestions into a plan resolved against the store as it is now."""
        from vecshield_platform.actions import (ActionError, Suggestion, stage)

        if not req.suggestions:
            raise HTTPException(status_code=400, detail="a plan needs at least one suggestion")
        try:
            suggestions = [Suggestion(
                id=item.id, action=item.action, finding_id=item.finding_id,
                store=store_id, collection=item.collection,
                chunk_ids=tuple(item.chunk_ids), rests_on=tuple(item.rests_on),
                calibrated=item.calibrated, rationale=item.rationale,
                observed_chunks=item.observed_chunks, named_chunks=item.named_chunks,
                excluded=tuple((str(e.get("chunk_id")), str(e.get("reason")))
                               for e in item.excluded if isinstance(e, dict)),
                labels=tuple(str(x) for x in item.labels),
                selector=item.selector or None, params=dict(item.params or {}),
                kind=item.kind, basis=item.basis,
            ) for item in req.suggestions]
        except KeyError as exc:
            raise HTTPException(status_code=400, detail=f"unknown action: {exc}") from exc

        if hist is None:
            raise HTTPException(
                status_code=503,
                detail="a plan must be persisted before it can be reviewed or "
                       "approved, and this deployment has no scan history configured.")
        # Every suggestion is checked against the stored finding it claims to
        # answer, as the suggestion endpoint read it: an API caller cannot stage
        # an action the server would not have proposed. A finding id that is
        # unknown, or recorded for another store, is left out and refused.
        observed = set(hist.observed_store_names(store_id) or [store_id])
        findings: dict[str, dict] = {}
        for fid in sorted({str(item.finding_id) for item in req.suggestions
                           if item.finding_id}):
            f = hist.get_finding(fid)
            if not f or f.get("store") not in observed:
                continue
            f = dict(f)
            if isinstance(f.get("evidence"), str):
                try:
                    f["evidence"] = json.loads(f["evidence"])
                except ValueError:
                    f["evidence"] = {}
            findings[fid] = {**f, "store": store_id}
        conn = _store(store_id)
        try:
            plan = stage(suggestions, connector=conn, store=store_id,
                         staged_by=actor, note=req.note or "",
                         tenant_field=reg().get(store_id).tenant_field,
                         findings=findings)
        except ActionError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            conn.close()
        hist.save_plan(plan)
        log.append(actor, "action_plan_staged", store_id,
                   {"plan_id": plan.id, "plan_hash": plan.plan_hash,
                    "operations": len(plan.operations),
                    "executable": len(plan.executable)})
        # Staging a fix is starting work on the finding; its case says so.
        for finding_id in sorted({op.finding_id for op in plan.operations if op.finding_id}):
            _advance_case(finding_id, "in_progress", actor,
                          f"Fix staged as plan {plan.id}.")
        return plan.to_dict()

    @app.get("/stores/{store_id}/actions/plans")
    def list_plans(store_id: str, state: Optional[str] = None,
                   actor: str = Depends(require_auth)) -> dict:
        from vecshield_platform.actions import PLAN_STATES

        try:
            reg().get(store_id)
        except KeyError:
            raise HTTPException(status_code=404,
                                detail=f"unknown store: {store_id}") from None
        if state is not None and state not in PLAN_STATES:
            # An unknown filter would match nothing and read as "no plans".
            raise HTTPException(status_code=400,
                                detail=f"unknown plan state: {state}; one of "
                                       f"{', '.join(PLAN_STATES)}")
        if hist is None:
            # An empty list would read as "no plans staged", which is a different
            # claim from "this deployment cannot store plans".
            raise HTTPException(status_code=503,
                                detail="no scan history is configured, so no plans "
                                       "are stored to list.")
        # Each plan carries a summary of what it fixes and how far it has got,
        # so the list reads per finding rather than as a column of hashes.
        return {"store": store_id,
                "plans": [{**row, "summary": _plan_summary(row["id"])}
                          for row in hist.list_plans(store=store_id, state=state)]}

    def _plan_summary(plan_id: str) -> dict:
        """What a stored plan fixes, and where it is on stage → approve → execute → verify."""
        record = hist.get_plan(plan_id) if hist is not None else None
        if not record:
            return {"stage": "unknown"}
        body = record.get("body") or {}
        state = record.get("state") or body.get("state") or "staged"
        approvals = hist.list_approvals(plan_id=plan_id)
        executions = []
        for row in hist.list_executions(plan_id=plan_id):
            full = hist.get_execution(row["id"]) or {}
            verification = full.get("verification") or None
            executions.append({
                "id": row["id"], "started_at": row.get("started_at"),
                "executed_by": row.get("executed_by"), "halted": bool(row.get("halted")),
                "complete": bool((full.get("body") or {}).get("complete")),
                "chunks_changed": (full.get("body") or {}).get("chunks_changed"),
                "verification": ({k: verification.get(k) for k in
                                  ("outcome", "expected", "observed", "unreadable",
                                   "reason", "caveats")} if verification else None)})
        latest = executions[0] if executions else None
        if not record.get("body_intact"):
            stage = "tampered"
        elif state == "halted":
            stage = "halted"
        elif state == "executed":
            outcome = ((latest or {}).get("verification") or {}).get("outcome")
            stage = "verified" if outcome == "confirmed" else "executed"
        elif state == "staged":
            stage = "approved" if approvals else "staged"
        else:
            stage = state
        operations = body.get("operations") or []
        return {
            "stage": stage,
            "intact": bool(record.get("body_intact")),
            "findings": sorted({str(op.get("finding_id")) for op in operations
                                if op.get("finding_id")}),
            "operations": [{"action": op.get("action"), "title": op.get("title"),
                            "finding_id": op.get("finding_id"),
                            "collection": op.get("collection"),
                            "resolved": op.get("resolved"), "runnable": op.get("runnable"),
                            "reversible": op.get("reversible"), "risk": op.get("risk"),
                            "support_reason": None if op.get("runnable")
                            else op.get("support_reason"),
                            "selector_text": op.get("selector_text"),
                            "params": {k: v for k, v in (op.get("params") or {}).items()
                                       if k in ("tenant_value", "tenant_field", "reason",
                                                "status")}}
                           for op in operations],
            "approvals": [{"id": a.get("id"), "approver": a.get("approver"),
                           "approved_at": a.get("approved_at"),
                           "self_approved": bool(a.get("self_approved"))}
                          for a in approvals],
            "executions": executions,
            "verification": (latest or {}).get("verification"),
        }

    @app.get("/actions/plans/{plan_id}/diff")
    def plan_diff(plan_id: str, actor: str = Depends(require_auth)) -> dict:
        """The dry-run diff a reviewer reads before approving anything.

        A plan whose stored body no longer matches its hash is reported as
        tampered rather than rendered, because a diff nobody can trust is worse
        than no diff.
        """
        if hist is None:
            raise HTTPException(status_code=503,
                                detail="no scan history is configured, so no plans "
                                       "are stored to review.")
        record = hist.get_plan(plan_id)
        if not record:
            raise HTTPException(status_code=404, detail=f"unknown plan: {plan_id}")
        if not record.get("body_intact"):
            raise HTTPException(
                status_code=409,
                detail=("This plan's stored body does not match its recorded hash. "
                        "It cannot be reviewed or acted on; re-stage it."))
        from vecshield_platform.actions import EXECUTION_NOTE, warnings_for

        body = record["body"]
        return {
            **body,
            "review": {
                "warnings": warnings_for(body),
                "executes": False,
                "execution_note": EXECUTION_NOTE,
            },
        }

    def _plan_for(plan_id: str) -> dict:
        """Read a stored plan, refusing one that no longer matches its hash."""
        if hist is None:
            raise HTTPException(status_code=503,
                                detail="no scan history is configured, so no plans "
                                       "are stored.")
        record = hist.get_plan(plan_id)
        if not record:
            raise HTTPException(status_code=404, detail=f"unknown plan: {plan_id}")
        if not record.get("body_intact"):
            raise HTTPException(
                status_code=409,
                detail=("This plan's stored body does not match its recorded hash. "
                        "It cannot be reviewed or acted on; re-stage it."))
        return record["body"]

    @app.post("/actions/plans/{plan_id}/approve")
    def approve_plan(plan_id: str, req: ApprovePlanRequest,
                     principal: "Principal" = Depends(require_compliance_principal)) -> dict:
        """Authorize this exact plan. Records who, why, and the hash it covers."""
        from vecshield_platform.execution import ApprovalError, approve

        actor = principal.subject
        body = _plan_for(plan_id)
        try:
            approval = approve(body, approver=actor, reason=req.reason,
                               typed_store_id=req.typed_store_id,
                               roles=principal.roles, separation=_separation)
        except ApprovalError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        hist.save_approval(approval)
        log.append(actor, "action_plan_approved", body.get("store"),
                   {"plan_id": plan_id, "plan_hash": approval.plan_hash,
                    "approval_id": approval.id, "reason": approval.reason,
                    "operations": list(approval.operations),
                    "self_approved": approval.self_approved,
                    "separation_of_duties": approval.separation_of_duties,
                    "actor_source": principal.source})
        return approval.to_dict()

    @app.post("/actions/plans/{plan_id}/execute")
    def execute_plan(plan_id: str, req: ExecutePlanRequest,
                     principal: "Principal" = Depends(require_compliance_principal)) -> dict:
        """Carry out an approved plan, then read the store back.

        The only endpoint in the product that writes to a customer store on the
        product's own initiative. It refuses far more often than it acts.
        """
        from vecshield_platform.actions import is_stale, plan_from_body
        from vecshield_platform.execution import (Approval, ExecutionError,
                                                    Verification, execute, verify_plan)

        actor = principal.subject
        body = _plan_for(plan_id)
        record = hist.get_approval(req.approval_id)
        if not record:
            raise HTTPException(status_code=404,
                                detail=f"unknown approval: {req.approval_id}")
        approval = Approval(
            id=record["id"], plan_id=record["plan_id"], plan_hash=record["plan_hash"],
            approver=record["approver"], reason=record["reason"],
            approved_at=record["approved_at"],
            typed_store_id=record.get("typed_store_id") or "",
            operations=tuple(record.get("operations") or ()),
            self_approved=bool(record.get("self_approved")),
            separation_of_duties=record.get("separation_of_duties") or "required")

        conn = _store(body.get("store"))
        plan = plan_from_body(body)
        # Claim the plan before anything reads the store. Two concurrent
        # requests both saw "staged" and both wrote; now exactly one moves the
        # plan to "executing" and the other is refused here.
        if not hist.claim_plan(plan_id):
            conn.close()
            current = (hist.get_plan(plan_id) or {}).get("state") or "unknown"
            log.append(actor, "action_plan_execution_refused", body.get("store"),
                       {"plan_id": plan_id, "approval_id": approval.id,
                        "reason": f"plan is {current}"})
            raise HTTPException(
                status_code=409,
                detail=(f"this plan is already {current} and cannot be run again. "
                        "Stage a fresh plan."))
        try:
            staleness = is_stale(plan, conn)
        except Exception as exc:  # noqa: BLE001
            # Nothing has been written yet; the plan stays runnable.
            hist.release_plan(plan_id)
            conn.close()
            log.append(actor, "action_plan_execution_refused", body.get("store"),
                       {"plan_id": plan_id, "approval_id": approval.id,
                        "reason": "staleness check failed",
                        "error_type": type(exc).__name__})
            raise HTTPException(
                status_code=502,
                detail=(f"the store could not be read to check this plan is still "
                        f"current ({type(exc).__name__}); nothing was changed.")) from exc
        try:
            _log_intent(actor, "action_plan_execution_started", body.get("store"),
                        {"plan_id": plan_id, "plan_hash": body.get("plan_hash"),
                         "approval_id": approval.id,
                         "actor_source": principal.source},
                        refused="the plan was not executed")
        except HTTPException:
            hist.release_plan(plan_id)
            conn.close()
            raise
        try:
            # The separation-of-duties rule is re-checked against who is
            # running the plan now, not only who approved it earlier.
            outcome = execute(body, approval, connector=conn, executed_by=actor,
                              staleness=staleness, separation=_separation,
                              executor_roles=principal.roles)
        except ExecutionError as exc:
            # Refused before any write: the plan goes back to staged.
            hist.release_plan(plan_id)
            conn.close()
            log.append(actor, "action_plan_execution_refused", body.get("store"),
                       {"plan_id": plan_id, "approval_id": approval.id,
                        "reason": str(exc)})
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except Exception as exc:  # noqa: BLE001
            # Failed part-way with no execution record to say how far it got.
            # The plan is not re-runnable as if nothing happened.
            hist.set_plan_state(plan_id, "halted")
            conn.close()
            log.append(actor, "action_plan_execution_failed", body.get("store"),
                       {"plan_id": plan_id, "approval_id": approval.id,
                        "error_type": type(exc).__name__})
            raise HTTPException(
                status_code=502,
                detail=(f"execution failed part-way ({type(exc).__name__}); the plan is "
                        "marked halted. Re-scan the store before staging a new plan.")
            ) from exc

        # Record what was written before reading the store back. A read-back
        # that raised used to lose the execution record, leave the plan staged
        # and skip the audit entry for a change already made.
        hist.save_execution(outcome, None)
        # "halted" means execution stopped on a failure. A plan whose operations
        # all found nothing left to do ran to the end; calling that halted
        # would tell a reader something went wrong when nothing did.
        hist.set_plan_state(plan_id, "halted" if outcome.halted else "executed")
        try:
            _log_done(actor, "action_plan_executed", outcome.store,
                      {"plan_id": plan_id, "plan_hash": outcome.plan_hash,
                       "approval_id": approval.id, "execution_id": outcome.id,
                       "complete": outcome.complete, "halted": outcome.halted,
                       "chunks_changed": outcome.applied,
                       "self_approved": approval.self_approved,
                       "separation_of_duties": _separation.mode,
                       "actor_source": principal.source,
                       "verification": "pending" if req.verify else "not run"},
                      completed=(f"plan {plan_id} was executed (execution "
                                 f"{outcome.id}, {outcome.applied} chunk(s) changed)"))
        except HTTPException:
            conn.close()
            raise
        verification = None
        try:
            if req.verify:
                try:
                    verification = verify_plan(outcome, body, connector=conn)
                except Exception as exc:  # noqa: BLE001
                    verification = Verification(
                        execution_id=outcome.id, plan_id=outcome.plan_id,
                        store=outcome.store,
                        checked_at=datetime.now(timezone.utc).isoformat(),
                        outcome="inconclusive", expected=outcome.applied, observed=0,
                        reason=(f"the read-back could not be completed "
                                f"({type(exc).__name__}); nothing is established "
                                "about whether the changes are in place."))
        finally:
            conn.close()
        if verification is not None:
            hist.set_execution_verification(outcome.id, verification)
        log.append(actor, "action_plan_verified", outcome.store,
                   {"plan_id": plan_id, "execution_id": outcome.id,
                    "verification": verification.outcome if verification else "not run"})
        # A confirmed read-back is a claim that the change is in place, not
        # that the finding is gone: the case waits for a re-scan to verify it.
        cases = {}
        if outcome.complete and verification is not None \
                and verification.outcome == "confirmed":
            for finding_id in sorted({str(op.get("finding_id")) for op in
                                      body.get("operations") or [] if op.get("finding_id")}):
                cases[finding_id] = _advance_case(
                    finding_id, "awaiting_verification", actor,
                    f"Plan {plan_id} executed and its read-back confirmed every change. "
                    "Awaiting a re-scan.")
        return {**outcome.to_dict(),
                "verification": verification.to_dict() if verification else None,
                "cases": {k: v for k, v in cases.items() if v}}

    @app.get("/actions/plans/{plan_id}/executions")
    def plan_executions(plan_id: str, actor: str = Depends(require_auth)) -> dict:
        if hist is None:
            raise HTTPException(status_code=503,
                                detail="no scan history is configured.")
        if not hist.get_plan(plan_id):
            # Empty lists for a plan that does not exist would read as "nobody
            # has approved this yet".
            raise HTTPException(status_code=404, detail=f"unknown plan: {plan_id}")
        executions = []
        for row in hist.list_executions(plan_id=plan_id):
            # What the read-back observed travels with each run, so a list of
            # runs never reads "ran" without saying what was confirmed.
            full = hist.get_execution(row["id"]) or {}
            executions.append({**row, "verification": full.get("verification")})
        return {"plan_id": plan_id,
                "approvals": hist.list_approvals(plan_id=plan_id),
                "executions": executions}

    @app.get("/actions/executions/{execution_id}")
    def execution_detail(execution_id: str, actor: str = Depends(require_auth)) -> dict:
        if hist is None:
            raise HTTPException(status_code=503,
                                detail="no scan history is configured.")
        record = hist.get_execution(execution_id)
        if not record:
            raise HTTPException(status_code=404,
                                detail=f"unknown execution: {execution_id}")
        return record

    @app.get("/actions/safe-mode")
    def action_safe_mode(actor: str = Depends(require_auth)) -> dict:
        """Whether this deployment permits writes, stated rather than inferred."""
        from vecshield_platform.execution import (EXECUTABLE_ACTIONS, SAFE_MODE_ENV,
                                                    safe_mode)
        from vecshield_platform.explain import CALIBRATED, CONFIDENCE_CLASSES

        from vecshield_platform.actions import ACTION_TEMPLATES, held_class

        on = safe_mode()
        # "Executable" is two separate questions, and reporting only the first
        # would call an action available when nothing can propose it. Delete is
        # implemented and gated shut; saying so is more useful than a list that
        # implies it is one command away.
        actions_state = []
        for kind, template in ACTION_TEMPLATES.items():
            required = template.requires_confidence
            best = max((held_class(d) for d in CALIBRATED), default="uncertain",
                       key=lambda c: -CONFIDENCE_CLASSES.index(c))
            meets = (not required) or any(required in claims
                                          for claims in CALIBRATED.values())
            actions_state.append({
                "action": kind,
                "title": template.title,
                "reversible": template.reversible,
                "implemented": kind in EXECUTABLE_ACTIONS,
                "requires_confidence": required or None,
                "best_measured": best,
                "reachable": bool(kind in EXECUTABLE_ACTIONS and meets),
                "blocked_by": (
                    None if kind in EXECUTABLE_ACTIONS and meets
                    else "Not implemented in this build."
                    if kind not in EXECUTABLE_ACTIONS
                    else f"No detector is measured at '{required}'; the strongest "
                         f"measured class is '{best}'. Growing the benchmark corpus "
                         "is what changes this."),
            })
        return {
            "safe_mode": on,
            "variable": SAFE_MODE_ENV,
            "how_to_enable": _safe_mode_block()["how_to_enable"],
            "executable_actions": list(EXECUTABLE_ACTIONS),
            "actions": actions_state,
            "note": ("Writes are blocked. Suggesting, staging, reviewing and approving "
                     f"all work; set {SAFE_MODE_ENV}=0 to permit execution."
                     if on else
                     "Writes are permitted. Every execution records that safe mode "
                     "was off."),
        }

    # ----------------------------------------------------------------- #
    # Remediation per finding: what can be done, and how far it has got. #
    # ----------------------------------------------------------------- #

    def _remediation_finding(finding_id: str) -> dict:
        if hist is None:
            raise HTTPException(status_code=503,
                                detail="remediation is derived from stored findings, and "
                                       "this deployment has no scan history configured.")
        finding = hist.get_finding(finding_id)
        if finding is None:
            raise HTTPException(status_code=404, detail=f"unknown finding: {finding_id}")
        finding = dict(finding)
        if isinstance(finding.get("evidence"), str):
            try:
                finding["evidence"] = json.loads(finding["evidence"])
            except ValueError:
                finding["evidence"] = {}
        return finding

    def _store_id_of(finding: dict) -> Optional[str]:
        """The registered store a finding was recorded against, if still registered."""
        name = str(finding.get("store") or "")
        stores = reg().list()
        for cfg in stores:
            if name == cfg.store_id:
                return cfg.store_id
        if hist is not None:
            for cfg in stores:
                if name in hist.observed_store_names(cfg.store_id):
                    return cfg.store_id
        return None

    def _remediation_events(finding_id: str) -> list[dict]:
        wanted = ("remediation_attested", "remediation_rescanned")
        return [{"seq": e.seq, "at": e.timestamp, "actor": e.actor, "action": e.action,
                 **(e.details or {})}
                for e in log.entries if e.target == finding_id and e.action in wanted]

    def _epoch(value: Any) -> float:
        if isinstance(value, (int, float)):
            return float(value)
        try:
            stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return 0.0
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        return stamp.timestamp()

    #: Case states that end the work, each with how the console words it. Only
    #: "verified" names a run that confirmed it; the rest are people's claims.
    _CLOSED_CASES = {"verified": "verified", "closed": "closed",
                     "false_positive": "closed as a false positive",
                     "duplicate": "closed as a duplicate",
                     "risk_accepted": "risk accepted"}

    def _resolutions(findings: list[dict], records: list[dict]) -> dict[str, dict]:
        """Which of ``findings`` no longer need a fix, and on what evidence.

        Resolved by re-scan: the latest targeted re-scan of this observation
        (any record sharing its fingerprint) completed without observing it,
        and no run has recorded it since. Otherwise a closed case: verified by
        a named run, or closed by a person's stated claim, labelled as such.
        """
        latest_seen: dict[str, float] = {}
        ids_by_fp: dict[str, set[str]] = {}
        for record in records:
            fp = str(record.get("fingerprint") or "")
            if fp:
                ids_by_fp.setdefault(fp, set()).add(str(record.get("id")))
                latest_seen[fp] = max(latest_seen.get(fp, 0.0),
                                      _epoch(record.get("created_at")))
        rescans: dict[str, Any] = {}
        for entry in log.entries:
            if entry.action == "remediation_rescanned":
                rescans[entry.target] = entry  # later entries win
        out: dict[str, dict] = {}
        for finding in findings:
            fid = str(finding.get("id"))
            fp = str(finding.get("fingerprint") or "")
            ids = (ids_by_fp.get(fp, set()) if fp else set()) | {fid}
            seen = max(latest_seen.get(fp, 0.0), _epoch(finding.get("created_at")))
            last = max((rescans[i] for i in ids if i in rescans),
                       key=lambda e: e.seq, default=None)
            if last is not None and (last.details or {}).get("outcome") == "resolved" \
                    and last.timestamp >= seen:
                out[fid] = {"by": "rescan", "state": "resolved",
                            "label": "resolved by re-scan",
                            "job_id": (last.details or {}).get("job_id"),
                            "actor": last.actor,
                            "at": datetime.fromtimestamp(last.timestamp,
                                                         timezone.utc).isoformat(),
                            "reason": (last.details or {}).get("reason") or ""}
                continue
            case = finding.get("case") or {}
            state = case.get("state") if isinstance(case, dict) else None
            if state in _CLOSED_CASES:
                out[fid] = {"by": "case", "state": state, "label": _CLOSED_CASES[state],
                            "job_id": case.get("verified_by_job_id"),
                            "actor": case.get("owner"), "at": case.get("updated_at"),
                            "reason": case.get("reason") or "",
                            "claim": state != "verified"}
        return out

    def _advance_case(finding_id: str, to_state: str, actor: str, reason: str, *,
                      allow_back: bool = False) -> Optional[dict]:
        """Move a finding's case forward along the working path, recording each step.

        Remediation moves a case only forward (new, triaged, assigned or
        reopened → in progress → awaiting verification), never out of a state a
        person chose to end it in. ``allow_back`` permits the one step back the
        state machine defines: a failed verification returns the case to work.
        Returns the new case, or None when it was left as it was.
        """
        from vecshield_platform.cases import CaseState, CaseTransitionError, transition

        if hist is None:
            return None
        current = hist.get_case(finding_id)
        if not current:
            return None
        path = {"in_progress": ("new", "triaged", "assigned", "reopened"),
                "awaiting_verification": ("new", "triaged", "assigned", "reopened",
                                          "in_progress")}
        start = current.get("state") or "new"
        if allow_back and to_state == "in_progress" and start == "awaiting_verification":
            steps = ["in_progress"]
        elif start in path.get(to_state, ()):
            steps = (["in_progress", to_state] if to_state == "awaiting_verification"
                     and start != "in_progress" else [to_state])
        else:
            return None
        state = CaseState(**current)
        for step in steps:
            try:
                state, event = transition(state, to_state=step, actor=actor, reason=reason)
            except CaseTransitionError:
                return None
            hist.save_case(state, event)
            log.append(actor, "finding_case_changed", finding_id,
                       {"from": event.from_state, "to": event.to_state,
                        "reason": event.reason})
        return state.to_dict()

    def _tenant_hints(store_id: Optional[str], collection: Optional[str]) -> list[str]:
        """Tenant values the isolation check recorded for this collection."""
        if hist is None or not store_id or not collection:
            return []
        stores = hist.observed_store_names(store_id) or [store_id]
        result = hist.query_findings(stores=stores, collection=collection,
                                     category="isolation", limit=50)
        seen: list[str] = []
        for record in result.get("findings", []) if isinstance(result, dict) else result:
            evidence = record.get("evidence") or {}
            if isinstance(evidence, str):
                try:
                    evidence = json.loads(evidence)
                except ValueError:
                    evidence = {}
            for value in evidence.get("tenants") or []:
                if isinstance(value, str) and value and value not in seen:
                    seen.append(value)
        return seen[:20]

    def _safe_mode_block() -> dict:
        from vecshield_platform.execution import SAFE_MODE_ENV, safe_mode

        on = safe_mode()
        return {"safe_mode": on, "variable": SAFE_MODE_ENV,
                "how_to_enable": (f"Set {SAFE_MODE_ENV}=0 in the server's environment and "
                                  "restart it, e.g. "
                                  f"{SAFE_MODE_ENV}=0 vecshield-platform serve --config "
                                  "<config> --state-dir <state>. Staging, review and "
                                  "approval work either way; only execution is blocked."),
                "note": ("Writes are blocked on this deployment. You can stage, review "
                         "and approve here; execution waits until safe mode is off."
                         if on else
                         "Writes are permitted. Every execution records that safe mode "
                         "was off.")}

    @app.get("/admin/findings/{finding_id}/remediation")
    def finding_remediation(finding_id: str, include_disputed: bool = False,
                            principal: "Principal" = Depends(require_principal)) -> dict:
        """Everything that can be done about one finding, and how far each has got.

        Executable proposals carry whether this store's connector can perform
        them, read from its declared capabilities now. Guided steps carry who
        said they were done and what the last re-scan observed. Neither is a
        claim that the finding is fixed.
        """
        from vecshield_platform.actions import capability_verdict, unenumerable_reason
        from vecshield_platform.home import plan_queue_entry
        from vecshield_platform.remediation import catalogue, proposal_dict

        finding = _remediation_finding(finding_id)
        store_id = _store_id_of(finding)
        cfg = reg().get(store_id) if store_id else None
        cat = catalogue(finding, store_id=store_id or str(finding.get("store") or ""),
                        store_kind=cfg.kind if cfg else "",
                        tenant_field=cfg.tenant_field if cfg else None,
                        include_disputed=include_disputed)
        support: dict[str, tuple[Optional[bool], str]] = {}
        if cfg is not None and cat.suggestions:
            try:
                conn = _store(store_id)
            except HTTPException as exc:
                support = {s.id: (None, f"The store could not be opened: {exc.detail}")
                           for s in cat.suggestions}
            else:
                try:
                    for s in cat.suggestions:
                        verdict = capability_verdict(conn, s.template)
                        # Staging also refuses chunk-level actions on a store
                        # whose content cannot be listed; say so here too.
                        if verdict[0] and (why := unenumerable_reason(conn, s.template)):
                            verdict = (False, why)
                        support[s.id] = verdict
                finally:
                    try:
                        conn.close()
                    except Exception:  # noqa: BLE001
                        pass
        events = _remediation_events(finding_id)
        guided = []
        for g in cat.guided:
            mine = [e for e in events if e.get("guided_id") == g.id]
            attested = [e for e in mine if e["action"] == "remediation_attested"]
            rescans = [e for e in events if e["action"] == "remediation_rescanned"]
            guided.append({**g.to_dict(),
                           "attested": attested[-1] if attested else None,
                           "last_rescan": rescans[-1] if rescans else None})
        plans = []
        if store_id:
            for row in hist.list_plans(store=store_id)[:100]:
                summary = _plan_summary(row["id"])
                if finding_id in summary.get("findings", []):
                    record = hist.get_plan(row["id"]) or {**row, "body": None,
                                                          "body_intact": False}
                    # Whether this caller may approve it, previewed by the same
                    # rule the approval queue and the approve endpoint use.
                    you = plan_queue_entry(
                        record, actor=principal.subject, roles=principal.roles,
                        has_approving_role=principal.has_role(COMPLIANCE),
                        separation=_separation, approvals=len(summary.get("approvals") or []),
                        store_registered=True)["you"]
                    plans.append({**row, "summary": summary, "you": you})
        fingerprint = str(finding.get("fingerprint") or "")
        records = (hist.findings_by_fingerprint(fingerprint) if fingerprint else []) \
            or [finding]
        resolution = _resolutions([finding], records).get(finding_id)
        newer = next((r for r in records if str(r.get("id")) != finding_id
                      and _epoch(r.get("created_at")) > _epoch(finding.get("created_at"))),
                     None)
        second_person = _separation.mode == "required"
        hints = _tenant_hints(store_id, finding.get("collection")) \
            if any("tenant_value" in s.template.needs_params for s in cat.suggestions) else []
        body = cat.to_dict()
        return {
            "finding": {k: finding.get(k) for k in ("id", "title", "severity", "category",
                                                    "collection", "store", "fingerprint",
                                                    "description", "created_at")},
            "case": hist.get_case(finding_id),
            "resolution": resolution,
            # A later run recorded the same observation under a newer id; that
            # record, not this one, is what the queue and the case track.
            "newer_record": ({"id": newer.get("id"), "created_at": newer.get("created_at")}
                             if newer else None),
            "store_id": store_id,
            "store_registered": store_id is not None,
            "store_kind": cfg.kind if cfg else None,
            "kind": body["kind"], "kind_label": body["kind_label"],
            "check": body["check"], "rescan_supported": body["rescan_supported"],
            "executable": [{**proposal_dict(s),
                            # Values a person may pick rather than type, each
                            # from a recorded observation; never pre-filled.
                            "param_hints": ({"tenant_value": hints}
                                            if hints and "tenant_value" in
                                            s.template.needs_params else {}),
                            "supported": (support.get(s.id) or (None, ""))[0],
                            "support_reason": (support.get(s.id) or (None, ""))[1]
                            or ("The store is not registered, so nothing can be staged "
                                "against it." if cfg is None else "")}
                           for s in cat.suggestions],
            "withheld": body["withheld"],
            "guided": guided,
            "plans": plans,
            "rescans": [e for e in events if e["action"] == "remediation_rescanned"][-5:],
            "safe_mode": _safe_mode_block(),
            "separation_of_duties": _separation.to_dict(),
            "note": body["note"] or (
                "Executable steps run through staging, "
                + ("a second person's approval, " if second_person else "approval, ")
                + "execution and a read-back. Guided steps are yours to carry out; "
                "VecShield verifies them by re-scanning."),
        }

    @app.post("/admin/findings/{finding_id}/remediation/attest")
    def finding_remediation_attest(finding_id: str, req: RemediationAttestRequest,
                                   actor: str = Depends(require_compliance)) -> dict:
        """Record that a person says they carried out a guided step.

        A claim, recorded as one. It does not verify anything and it does not
        close the case; a re-scan that no longer observes the finding does that.
        Where the case is in progress it moves to awaiting verification, which
        is what the claim means.
        """
        from vecshield_platform.remediation import catalogue

        finding = _remediation_finding(finding_id)
        store_id = _store_id_of(finding)
        cfg = reg().get(store_id) if store_id else None
        cat = catalogue(finding, store_id=store_id or str(finding.get("store") or ""),
                        store_kind=cfg.kind if cfg else "",
                        tenant_field=cfg.tenant_field if cfg else None)
        step = next((g for g in cat.guided if g.id == req.guided_id), None)
        if step is None:
            raise HTTPException(status_code=404,
                                detail=f"{req.guided_id} is not a guided step for {finding_id}")
        entry = log.append(actor, "remediation_attested", finding_id,
                           {"guided_id": step.id, "title": step.title,
                            "note": req.note.strip(), "store": store_id,
                            "claim": "carried out by a person; not yet verified"})
        case = hist.get_case(finding_id)
        moved = _advance_case(finding_id, "awaiting_verification", actor,
                              f"Guided remediation marked done: {step.title}. "
                              "Awaiting a re-scan.")
        return {"attestation": {"seq": entry.seq, "at": entry.timestamp, "actor": actor,
                                "guided_id": step.id, "note": req.note.strip()},
                "case": moved or case,
                "note": ("Recorded as a claim. Run the re-scan to verify it."
                         if step.check else
                         "Recorded as a claim. This step is verified by a new assessment.")}

    @app.post("/admin/findings/{finding_id}/remediation/verify")
    def finding_remediation_verify(finding_id: str, req: RemediationVerifyRequest,
                                   actor: str = Depends(require_compliance)) -> dict:
        """Re-run the check behind a finding, read-only, and record what it observed.

        The only way a guided remediation is verified. The new run is saved like
        any targeted scan; if it no longer observes the finding over a complete
        scope and the case is awaiting verification, the case is verified by
        that run.
        """
        from vecshield_platform.cases import CaseState, CaseTransitionError, transition
        from vecshield_platform.remediation import KINDS, finding_kind, rescan

        finding = _remediation_finding(finding_id)
        store_id = _store_id_of(finding)
        if store_id is None:
            raise HTTPException(status_code=409,
                                detail="the store this finding was recorded against is "
                                       "not registered, so it cannot be re-scanned")
        cfg = reg().get(store_id)
        family = KINDS.get(finding_kind(finding), KINDS["other"])[1]
        # Only the content checks classify; building a classifier for a
        # posture or isolation re-run would load models for nothing.
        classifier = (_classifier(False, None) if family in (
            "data_classification", "data_representation", "retrieval_exposure") else None)
        # The store's declared controls (retention schedule, residency policy,
        # processor register, feed, source manifest), so a re-scan of those
        # checks is judged against the same inputs an audit would use.
        controls = resolve_audit_settings(app.state.config, cfg,
                                          state_dir=state_dir).audit_kwargs
        conn = _store(store_id)
        try:
            result = rescan(finding, conn, tenant_field=cfg.tenant_field,
                            classifier=classifier, controls=controls)
            kind = getattr(conn, "kind", None)
        finally:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass
        if result.job is not None:
            _tag_suppressions(result.job.findings)
            hist.save_job(result.job, kind=kind)
        record = result.to_dict()
        log.append(actor, "remediation_rescanned", finding_id,
                   {"guided_id": req.guided_id or None, "store": store_id,
                    "check": result.check, "outcome": result.outcome,
                    "job_id": record["job_id"], "reason": result.reason})
        case = hist.get_case(finding_id)
        if result.outcome == "resolved" and case and \
                case.get("state") == "awaiting_verification":
            try:
                new_state, event = transition(
                    CaseState(**case), to_state="verified", actor=actor,
                    verified_by_job_id=record["job_id"],
                    reason=f"Re-scan {record['job_id']} no longer observes the finding.")
                hist.save_case(new_state, event)
                log.append(actor, "finding_case_changed", finding_id,
                           {"from": event.from_state, "to": event.to_state,
                            "reason": event.reason})
                case = new_state.to_dict()
            except CaseTransitionError:
                pass
        elif result.outcome == "still_present" and case and \
                case.get("state") == "awaiting_verification":
            # Verification failed: the case goes back to work rather than on.
            case = _advance_case(finding_id, "in_progress", actor,
                                 f"Re-scan {record['job_id']} still observes the finding.",
                                 allow_back=True) or case
        return {**record, "case": case}

    @app.get("/detectors/calibration")
    def detector_calibration(actor: str = Depends(require_auth)) -> dict:
        """What each detector has earned the right to claim, and why.

        A detector that has earned nothing reports 'uncertain'. That is the
        honest default on a small corpus, not a fault to be hidden.
        """
        from vecshield_platform.explain import CALIBRATION_PATH

        try:
            document = json.loads(CALIBRATION_PATH.read_text())
        except (OSError, ValueError):
            return {
                "available": False,
                "detectors": {},
                "note": ("No calibration has been recorded. Every detector reports "
                         "'uncertain' until the benchmark measures one."),
            }
        earned = document.get("detectors") or {}
        return {
            "available": True,
            "thresholds": document.get("thresholds", {}),
            "detectors": earned,
            "claimed": sum(1 for e in earned.values() if e.get("class") != "uncertain"),
            "measured": len(earned),
            "note": document.get("note", ""),
        }

    @app.get("/compliance/criteria")
    def compliance_criteria(framework: Optional[str] = None,
                            actor: str = Depends(require_auth)) -> dict:
        """The criterion pack itself: what each obligation needs, and its limits."""
        from vecshield_platform.compliance.packs import criteria_for, pack_manifest
        from vecshield_platform.compliance.vocabulary import vocabulary

        criteria = criteria_for(framework)
        if framework and not criteria:
            raise HTTPException(status_code=404,
                                detail=f"no criteria for framework '{framework}'")
        # The vocabulary explains the identifiers the criteria use (artifact
        # types, applicability questions), so the console never has to.
        return {"pack": pack_manifest(),
                "criteria": [c.to_dict() for c in criteria],
                **vocabulary()}

    @app.get("/compliance/crypto-basis")
    def compliance_crypto_basis(actor: str = Depends(require_auth)) -> dict:
        """What each framework says about encryption, and the ceiling on what
        VecShield may claim for it. Display data; nothing is evaluated here."""
        from vecshield_platform.compliance.crypto_basis import crypto_basis

        return {"basis": crypto_basis()}

    @app.get("/compliance/hipaa")
    def compliance_hipaa(actor: str = Depends(require_auth)) -> dict:
        """What the HIPAA pack covers, what it deliberately does not, and who
        else holds the ePHI.

        Three things that existed only in Python until this route, and the
        second is the one worth arguing about:

        ``not_covered``
            Obligations the pack names and then declines to assess -- workforce
            clearance, contingency planning, the notification clock. Shipping
            that list is a stronger claim than shipping a longer criterion
            count, because it is the part a competitor's coverage matrix never
            has. It was reachable only from a unit test.
        ``safe_harbor``
            Coverage of the eighteen identifier categories at
            §164.514(b)(2)(i), including the ones no detector can observe.
        ``business_associates``
            Vendors the registered connector kinds imply a business associate
            contract is needed for, under §164.308(b)(1) -- and, separately,
            the stores whose operator the connector kind does not establish.

        The vendor names come from the connector kind already recorded on each
        store. Nothing is opened, and nothing here observes whether a contract
        exists, whether the vendor offers one, or whether the store holds ePHI
        at all.
        """
        from vecshield_platform.compliance.hipaa import (
            business_associate_exposure, safe_harbor_manifest)
        from vecshield_platform.compliance.packs import hipaa_pack_manifest

        stores = [{"store_id": s.store_id, "kind": s.kind} for s in reg().list()]
        manifest = hipaa_pack_manifest(stores=stores)
        return {
            "pack": {k: v for k, v in manifest.items()
                     if k not in ("business_associates",)},
            "safe_harbor": safe_harbor_manifest(),
            "business_associates": business_associate_exposure(stores),
        }

    @app.post("/stores/{store_id}/criteria")
    def evaluate_store_criteria(store_id: str,
                                req: CriteriaRequest = CriteriaRequest(),
                                actor: str = Depends(require_auth)) -> dict:
        """Evaluate the criterion pack against a frozen audit snapshot.

        Reads a saved audit rather than running a new one, so a criterion state
        always refers to observations the reviewer can open. Nothing is assumed
        on the caller's behalf, and every input says where it came from:

        * applicability: the store's stored answers, overridden question by
          question by any the caller sends (what-if);
        * evidence: recorded reviews, which win over caller-supplied states;
        * reviewer decisions: the newest stored decision per criterion, which
          wins over a caller-supplied one. A stored decision recorded against a
          different pack version or criterion wording is reported as stale and
          not applied.
        """
        from vecshield_platform.compliance.criteria import (
            ReviewerDecision, evaluate_pack, summarize_pack)
        from vecshield_platform.compliance.decisions import (
            annotate, choose_decisions, latest_per_criterion, merge_answers)
        from vecshield_platform.compliance.packs import (
            criteria_for, get_criterion, pack_manifest, resolve_criterion_id)

        _assert_store(store_id)
        if hist is None:
            raise HTTPException(status_code=409,
                                detail="criterion evaluation requires scan history")
        snapshot = (hist.get_audit(req.audit_id) if req.audit_id
                    else _latest_audit_snapshot(store_id))
        if snapshot is None:
            raise HTTPException(
                status_code=404 if req.audit_id else 409,
                detail=("no such saved audit" if req.audit_id else
                        "no saved audit snapshot; run an audit before evaluating criteria"))
        if req.audit_id and snapshot.get("store_id") not in (None, store_id):
            raise HTTPException(status_code=404,
                                detail=f"audit '{req.audit_id}' is not from store '{store_id}'")
        criteria = criteria_for(req.framework)
        if req.framework and not criteria:
            raise HTTPException(status_code=404,
                                detail=f"no criteria for framework '{req.framework}'")
        # Evidence states come from recorded reviews, not from the caller: a
        # position is defensible only when the evidence behind it is a stored
        # record somebody can open. Caller-supplied states still work for
        # what-if evaluation, but recorded reviews win.
        artifacts = {a["id"]: EvidenceArtifact(**a).to_dict()
                     for a in hist.list_artifacts()}
        # This store's exceptions, plus the estate-wide ones. Both queries are
        # now exact, so nothing is returned twice.
        recorded_exceptions = (hist.list_exceptions(scope=store_id)
                               + hist.list_exceptions(scope=""))

        def _reviews_for(criterion_id: str) -> list[dict]:
            """Reviews filed against a criterion, including under a retired id.

            Reviews and exceptions store the criterion id as a plain string, so
            a criterion that absorbed an older one would otherwise lose the
            evidence already filed against it. The retired id is rewritten to
            the current one here rather than being matched loosely downstream.
            """
            rows = list(hist.list_reviews(criterion_id=criterion_id))
            for row in hist.list_reviews():
                stored = row.get("criterion_id")
                if stored and stored != criterion_id and (
                        resolve_criterion_id(stored) == criterion_id):
                    rows.append({**row, "criterion_id": criterion_id})
            return rows

        # Stored applicability answers are the default; the caller's override
        # them one question at a time, so a what-if never changes the record.
        stored_answers = {q: row["answer"] for q, row in
                          hist.applicability_answers(store_id).items()}
        applicability, applicability_sources = merge_answers(
            stored_answers, dict(req.applicability or {}))
        # Stored decisions, newest per criterion, with retired ids resolved to
        # the criterion that absorbed them and stale ones marked.
        stored_latest = latest_per_criterion(
            annotate(record, resolve=resolve_criterion_id, lookup=get_criterion)
            for record in hist.list_reviewer_decisions(store_id))

        try:
            what_if = {cid: ReviewerDecision(**value)
                       for cid, value in (req.reviewer_decisions or {}).items()}
            decisions, decision_provenance = choose_decisions(
                criteria, stored_latest=stored_latest, what_if=what_if,
                audit_id=snapshot.get("id"),
                audit_finished_at=snapshot.get("finished_at"),
                decision_audits_finished_at=hist.audit_finish_times(
                    r.get("audit_id") for r in stored_latest.values()))
            assessments = []
            for criterion in criteria:
                evidence_states = dict(req.evidence or {})
                evidence_states.update(accepted_requirements(
                    _reviews_for(criterion.id),
                    criterion_id=criterion.id, artifacts=artifacts))
                assessments.extend(evaluate_pack(
                    [criterion], check_outcomes=snapshot.get("check_outcomes", []),
                    applicability_answers=applicability,
                    evidence=evidence_states, reviewer_decisions=decisions))
        except (TypeError, ValueError) as e:
            raise HTTPException(status_code=422, detail=str(e)) from e
        decision_counts = {
            "stored_applied": sum(p["decision_source"] == "stored"
                                  for p in decision_provenance.values()),
            "stale_not_applied": sum(bool(p["stored_decision"]
                                          and p["stored_decision"]["stale"])
                                     for p in decision_provenance.values()),
            "what_if_applied": sum(p["decision_source"] == "what_if"
                                   for p in decision_provenance.values()),
            "what_if_ignored": sum(p["what_if_ignored"]
                                   for p in decision_provenance.values()),
            "later_audit_not_applied": sum(
                bool(p["stored_decision"] and p["stored_decision"]["not_applied_reason"]
                     == "made_against_later_audit")
                for p in decision_provenance.values()),
            "unplaced_not_applied": sum(
                bool(p["stored_decision"] and p["stored_decision"]["not_applied_reason"]
                     == "decision_audit_unknown")
                for p in decision_provenance.values()),
        }
        input_notes = []
        if decision_counts["stale_not_applied"]:
            input_notes.append(
                f"{decision_counts['stale_not_applied']} stored reviewer decision(s) "
                "were recorded against a different version of their criterion and "
                "were not applied. Record them again against the current criterion.")
        if decision_counts["later_audit_not_applied"]:
            input_notes.append(
                f"{decision_counts['later_audit_not_applied']} stored reviewer "
                "decision(s) were made against a later audit than this one, with "
                "information this audit did not have, and were not applied.")
        if decision_counts["unplaced_not_applied"]:
            input_notes.append(
                f"{decision_counts['unplaced_not_applied']} stored reviewer "
                "decision(s) name an audit that cannot be placed in time relative "
                "to this one, and were not applied.")
        if decision_counts["what_if_ignored"]:
            input_notes.append(
                f"{decision_counts['what_if_ignored']} caller-supplied decision(s) "
                "were ignored because a stored decision exists for the criterion.")
        if any(source == "what_if" for source in applicability_sources.values()):
            input_notes.append(
                "Some applicability answers are what-if values from this request and "
                "are not stored.")

        # An exception is attached to a gap; it never removes one.
        exceptions_by_criterion: dict[str, list] = {}
        for raw in recorded_exceptions:
            record = RiskException(**raw).to_dict()
            key = resolve_criterion_id(record["criterion_id"]) or record["criterion_id"]
            exceptions_by_criterion.setdefault(key, []).append(record)

        log.append(actor, "criteria_evaluated", store_id,
                   {"audit_id": snapshot.get("id"), "framework": req.framework,
                    "decisions": decision_counts})
        # Storage encryption is shown beside PCI Requirement 3 but never
        # satisfies it, so no PCI criterion cites the at-rest check. The
        # console still needs the observation to draw that row, whichever
        # framework filter is applied.
        crypto_context = [o for o in snapshot.get("check_outcomes", [])
                          if o.get("check") == "at_rest_encryption"]
        return {"audit_id": snapshot.get("id"), "pack": pack_manifest(),
                "coverage": snapshot.get("coverage", {}),
                "crypto_context": crypto_context,
                "summary": summarize_pack(assessments),
                "inputs": {
                    "applicability": {
                        "applied": applicability,
                        "sources": applicability_sources,
                        "stored": stored_answers,
                    },
                    "decisions": decision_counts,
                    "notes": input_notes,
                },
                "assessments": [{**a.to_dict(),
                                 **decision_provenance.get(a.criterion_id, {}),
                                 "exceptions": exceptions_by_criterion.get(a.criterion_id, []),
                                 "evidence_reviews": [
                                     EvidenceReview(**r).to_dict()
                                     for r in _reviews_for(a.criterion_id)]}
                                for a in assessments]}

    def _latest_audit_snapshot(store_id: str) -> Optional[dict]:
        listed = hist.list_audits(store_id=store_id, limit=1)
        return hist.get_audit(listed[0]["id"]) if listed else None

    def _audit_before(store_id: str, audit_id: str) -> Optional[dict]:
        """The snapshot saved for this store immediately before ``audit_id``,
        in history's own order (newest first), paging so a long history is
        not read in one query."""
        page, offset = 200, 0
        while True:
            listed = hist.list_audits(store_id=store_id, limit=page, offset=offset)
            ids = [row["id"] for row in listed]
            if audit_id in ids:
                index = ids.index(audit_id)
                if index + 1 < len(ids):
                    return hist.get_audit(ids[index + 1])
                following = hist.list_audits(store_id=store_id, limit=1,
                                             offset=offset + len(ids))
                return hist.get_audit(following[0]["id"]) if following else None
            if len(listed) < page:
                return None
            offset += page

    # ---------------- stored reviewer decisions and applicability ----------------

    def _annotated_decision(record: dict) -> dict:
        from vecshield_platform.compliance.decisions import annotate
        from vecshield_platform.compliance.packs import (get_criterion,
                                                           resolve_criterion_id)

        return annotate(record, resolve=resolve_criterion_id, lookup=get_criterion)

    @app.post("/stores/{store_id}/criteria/{criterion_id}/decision")
    def record_reviewer_decision(store_id: str, criterion_id: str,
                                 req: ReviewerDecisionRequest,
                                 actor: str = Depends(require_compliance)) -> dict:
        """Record a reviewer's conclusion for one criterion on one store.

        The reviewer is the authenticated caller. The decision is bound to the
        saved audit it was made against, the pack version, and the criterion's
        wording, and it is appended, never rewritten: the newest decision per
        criterion is the one criterion evaluation applies.
        """
        from vecshield_platform.compliance.decisions import (DECISION_NOTE,
                                                               criterion_digest)
        from vecshield_platform.compliance.packs import (get_criterion,
                                                           resolve_criterion_id)

        _assert_store(store_id)
        if hist is None:
            raise HTTPException(status_code=409,
                                detail="reviewer decisions require scan history")
        current_id = resolve_criterion_id(criterion_id)
        criterion = get_criterion(current_id) if current_id else None
        if criterion is None:
            raise HTTPException(status_code=404,
                                detail=f"unknown criterion: {criterion_id}")
        rationale = req.rationale.strip()
        if not rationale:
            raise HTTPException(status_code=422,
                                detail="a reviewer decision records why it was made")
        snapshot = (hist.get_audit(req.audit_id) if req.audit_id
                    else _latest_audit_snapshot(store_id))
        if snapshot is None:
            raise HTTPException(
                status_code=404 if req.audit_id else 409,
                detail=("no such saved audit" if req.audit_id else
                        "no saved audit snapshot; a decision is made against a saved "
                        "audit, so run one first"))
        if req.audit_id and snapshot.get("store_id") not in (None, store_id):
            raise HTTPException(status_code=404,
                                detail=f"audit '{req.audit_id}' is not from store '{store_id}'")
        record = {
            "id": _new_id("dec"), "store_id": store_id, "criterion_id": criterion.id,
            "conclusion": req.conclusion, "rationale": rationale, "reviewer": actor,
            "decided_at": datetime.now(timezone.utc).isoformat(),
            "audit_id": snapshot.get("id"), "period": req.period.strip(),
            "pack_version": criterion.pack_version,
            "criterion_digest": criterion_digest(criterion),
        }
        hist.save_reviewer_decision(record)
        details = {"decision_id": record["id"], "criterion_id": criterion.id,
                   "conclusion": req.conclusion, "rationale": rationale,
                   "audit_id": record["audit_id"], "period": record["period"],
                   "pack_version": criterion.pack_version}
        if criterion.id != criterion_id:
            details["requested_criterion_id"] = criterion_id
        log.append(actor, "reviewer_decision_recorded", store_id, details)
        return {"decision": _annotated_decision(record), "note": DECISION_NOTE}

    @app.get("/stores/{store_id}/criteria/decisions")
    def list_reviewer_decisions(store_id: str, criterion_id: Optional[str] = None,
                                actor: str = Depends(require_auth)) -> dict:
        """Every stored decision for a store, newest first, each marked current
        (the newest for its criterion) and stale (not applied) where it is."""
        from vecshield_platform.compliance.criteria import PACK_VERSION
        from vecshield_platform.compliance.decisions import (DECISION_NOTE,
                                                               latest_per_criterion)
        from vecshield_platform.compliance.packs import resolve_criterion_id

        _assert_store(store_id)
        if hist is None:
            raise HTTPException(status_code=409,
                                detail="reviewer decisions require scan history")
        annotated = [_annotated_decision(r) for r in hist.list_reviewer_decisions(store_id)]
        current_ids = {r["id"] for r in latest_per_criterion(annotated).values()}
        rows = [{**r, "current": r["id"] in current_ids} for r in annotated]
        if criterion_id:
            wanted = resolve_criterion_id(criterion_id) or criterion_id
            rows = [r for r in rows if r["criterion_id"] == wanted]
        current = [r for r in rows if r["current"]]
        return {
            "store_id": store_id, "pack_version": PACK_VERSION, "decisions": rows,
            "current": len(current),
            "current_stale": sum(1 for r in current if r["stale"]),
            "note": DECISION_NOTE,
        }

    def _applicability_view(store_id: str) -> dict:
        from vecshield_platform.compliance.decisions import known_questions
        from vecshield_platform.compliance.packs import criteria_for

        stored = hist.applicability_answers(store_id)
        questions = known_questions(criteria_for(None))
        return {
            "store_id": store_id,
            "answers": stored,
            "questions": [{"question": q, "criteria": ids,
                           "answer": (stored.get(q) or {}).get("answer",
                                                               "requires_confirmation"),
                           "answered": q in stored}
                          for q, ids in questions.items()],
            "note": ("An unanswered question stays requires_confirmation, which is "
                     "not 'yes'. Criteria evaluation uses these answers unless a "
                     "request supplies its own as a what-if."),
        }

    @app.get("/stores/{store_id}/applicability")
    def store_applicability(store_id: str, actor: str = Depends(require_auth)) -> dict:
        _assert_store(store_id)
        if hist is None:
            raise HTTPException(status_code=409,
                                detail="applicability answers require scan history")
        return _applicability_view(store_id)

    @app.post("/stores/{store_id}/applicability")
    def record_store_applicability(store_id: str, req: ApplicabilityRequest,
                                   actor: str = Depends(require_compliance)) -> dict:
        """Store answers for this store. Questions not sent keep their answer."""
        from vecshield_platform.compliance.decisions import (known_questions,
                                                               validate_answers)
        from vecshield_platform.compliance.packs import criteria_for

        _assert_store(store_id)
        if hist is None:
            raise HTTPException(status_code=409,
                                detail="applicability answers require scan history")
        answers = dict(req.answers)
        problems = validate_answers(answers, known_questions(criteria_for(None)))
        if problems:
            raise HTTPException(status_code=422, detail="; ".join(problems))
        hist.save_applicability_answers(
            store_id, answers, answered_by=actor,
            answered_at=datetime.now(timezone.utc).isoformat())
        log.append(actor, "applicability_answered", store_id, {"answers": answers})
        return _applicability_view(store_id)

    @app.get("/stores/{store_id}/crypto-posture")
    def store_crypto_posture(store_id: str, audit_id: Optional[str] = None,
                             actor: str = Depends(require_auth)) -> dict:
        """Cryptographic posture, by control layer, from a saved audit.

        Never scans or connects: the read model is assembled from the chosen
        snapshot (default: the latest), with drift against the audit saved
        before it for the same store.
        """
        from vecshield_platform.crypto.view import build_crypto_posture

        _assert_store(store_id)
        if hist is None:
            raise HTTPException(status_code=409,
                                detail="crypto posture requires scan history")
        snapshot = (hist.get_audit(audit_id) if audit_id
                    else _latest_audit_snapshot(store_id))
        if snapshot is None:
            raise HTTPException(
                status_code=404 if audit_id else 409,
                detail=("no such saved audit" if audit_id else
                        "no saved audit snapshot; run an audit before viewing "
                        "crypto posture"))
        if audit_id and snapshot.get("store_id") not in (None, store_id):
            raise HTTPException(status_code=404,
                                detail=f"audit '{audit_id}' is not from store '{store_id}'")
        previous = _audit_before(store_id, snapshot["id"])
        return build_crypto_posture(snapshot, store_id=store_id, previous=previous)

    @app.get("/compliance/crypto-gate/rules")
    def crypto_gate_rules(actor: str = Depends(require_auth)) -> dict:
        """The rules the crypto gate applies, so no screen restates them."""
        from vecshield_platform.crypto.gate import DECISIONS, default_gate_rules

        return {"decisions": list(DECISIONS),
                "rules": [rule.to_dict() for rule in default_gate_rules()]}

    @app.get("/stores/{store_id}/crypto-gate")
    def store_crypto_gate(store_id: str, audit_id: Optional[str] = None,
                          requires_at_rest_encryption: bool = False,
                          record: bool = True,
                          actor: str = Depends(require_auth)) -> dict:
        """Block, request evidence, warn, or pass — decided from a saved audit.

        For a pipeline to ask before promoting a store. It reads the snapshot
        and the evidence accepted for this store; it never scans, and it
        enforces nothing itself. Decisions are audit-logged; the console's
        preview passes ``record=false`` so viewing a screen is not recorded as
        a release decision.
        """
        from vecshield_platform.crypto.gate import accepted_pairs, evaluate_gate

        _assert_store(store_id)
        if hist is None:
            raise HTTPException(status_code=409,
                                detail="the crypto gate requires scan history")
        snapshot = (hist.get_audit(audit_id) if audit_id
                    else _latest_audit_snapshot(store_id))
        if snapshot is None:
            raise HTTPException(
                status_code=404 if audit_id else 409,
                detail=("no such saved audit" if audit_id else
                        "no saved audit snapshot; run an audit before asking the gate"))
        if audit_id and snapshot.get("store_id") not in (None, store_id):
            raise HTTPException(status_code=404,
                                detail=f"audit '{audit_id}' is not from store '{store_id}'")
        artifacts = {a["id"]: EvidenceArtifact(**a).to_dict()
                     for a in hist.list_artifacts()}
        accepted = accepted_pairs(hist.list_reviews(), artifacts, scope=store_id)
        result = evaluate_gate(
            snapshot, store_id=store_id, accepted_evidence=accepted,
            settings={"requires_at_rest_encryption": requires_at_rest_encryption})
        if record:
            log.append(actor, "crypto_gate_decided", store_id,
                       {"audit_id": result["audit_id"], "decision": result["decision"],
                        "fired": [r["id"] for r in result["rules"]
                                  if r["status"] == "fired"]})
        return result

    @app.get("/admin/crypto-estate")
    def crypto_estate(actor: str = Depends(require_auth)) -> dict:
        """Crypto coverage for every registered store, from each latest audit.

        One row per store: the per-layer coverage statement and the release
        gate's decision (evaluated as a preview, not recorded). A store never
        assessed, or whose audit cannot be read, says so rather than showing
        empty counts.
        """
        from vecshield_platform.crypto.gate import accepted_pairs, evaluate_gate
        from vecshield_platform.crypto.view import crypto_coverage

        configs = sorted(reg().list(), key=lambda c: c.store_id)
        note = ("Counts are rows from each store's latest saved audit. Nothing "
                "here is a score, and a store never assessed is not a store "
                "with nothing to report.")
        if hist is None:
            return {"history_available": False, "note": note,
                    "stores": [{"store_id": c.store_id, "kind": c.kind,
                                "state": "unavailable",
                                "reason": "no scan history is configured"}
                               for c in configs]}
        snapshots = hist.latest_audit_snapshots()
        reviews = hist.list_reviews()
        artifacts = {a["id"]: EvidenceArtifact(**a).to_dict()
                     for a in hist.list_artifacts()}
        rows = []
        for cfg in configs:
            snap = snapshots.get(cfg.store_id)
            row: dict = {"store_id": cfg.store_id, "kind": cfg.kind}
            if snap is None:
                rows.append({**row, "state": "never_assessed"})
                continue
            if snap.get("unreadable"):
                rows.append({**row, "state": "unavailable",
                             "reason": "the latest saved audit could not be read"})
                continue
            row.update({"state": "assessed", "audit_id": snap.get("id"),
                        "assessed_at": snap.get("finished_at") or snap.get("started_at"),
                        "coverage_status": (snap.get("coverage") or {}).get("status"),
                        "statement": crypto_coverage(snap)})
            try:
                gate = evaluate_gate(
                    snap, store_id=cfg.store_id,
                    accepted_evidence=accepted_pairs(reviews, artifacts,
                                                     scope=cfg.store_id),
                    settings={"requires_at_rest_encryption": False})
                row["gate"] = {"decision": gate["decision"],
                               "fired": [r["id"] for r in gate["rules"]
                                         if r["status"] == "fired"]}
            except Exception as e:  # noqa: BLE001 - one bad snapshot must not fail the list
                row["gate"] = {"decision": None, "reason": str(e)}
            rows.append(row)
        return {"history_available": True, "stores": rows, "note": note}

    @app.get("/admin/stores")
    def admin_stores(actor: str = Depends(require_auth)) -> dict:
        cfg = _require_config()
        stores = []
        for s in cfg.stores.values():
            row = s.public_dict()
            # A store whose secret reference cannot resolve is registered as
            # unavailable; say so here too rather than list it as usable.
            try:
                unavailable = getattr(reg().get(s.store_id), "unavailable", None)
            except KeyError:
                unavailable = None
            if unavailable:
                row["unavailable"] = unavailable
            stores.append(row)
        return {"stores": stores}

    def _refused_reference(actor: str, target: str, operation: str, conn: dict,
                           error: Exception) -> None:
        """Audit a secret reference refused by the allowlist (ADR 0003).

        Records the reference names and the rule, never a value: a refused
        reference is what an attempt to read the server's own secrets looks
        like, so it is worth a line in the chain.
        """
        from vecshield_platform.api.secrets import reference_names
        log.append(actor, "secret_reference_refused", target,
                   {"operation": operation, "secret_refs": reference_names(conn),
                    "reason": str(error)})

    @app.post("/admin/stores")
    def add_store(req: AddStoreRequest, actor: str = Depends(require_admin)) -> dict:
        from vecshield_platform.api.secrets import SecretReferenceDenied, reference_names
        cfg = _require_config()
        try:
            s = cfg.add_store(req.store_id, req.kind, conn=req.conn,
                              tenant_field=req.tenant_field, description=req.description)
        except SecretReferenceDenied as e:
            _refused_reference(actor, req.store_id, "store_add", req.conn, e)
            raise HTTPException(status_code=422, detail=str(e)) from e
        except ValueError as e:
            raise HTTPException(status_code=409, detail=str(e))
        try:
            rebuild_registry()
        except Exception as e:  # noqa: BLE001
            cfg.remove_store(req.store_id)
            raise HTTPException(status_code=400, detail=f"store registration failed: {e}")
        # Which variables/files the store reads its secrets from (names only).
        log.append(actor, "store_added", req.store_id,
                   {"kind": req.kind, "secret_refs": reference_names(s.conn)})
        return s.public_dict()

    @app.get("/admin/stores/{store_id}")
    def get_store_config(store_id: str, actor: str = Depends(require_auth)) -> dict:
        cfg = _require_config()
        try:
            s = cfg.get_store(store_id)
        except KeyError:
            raise HTTPException(status_code=404, detail=f"unknown store: {store_id}")
        return s.public_dict()

    @app.put("/admin/stores/{store_id}")
    def update_store_config(store_id: str, req: UpdateStoreRequest,
                            actor: str = Depends(require_admin)) -> dict:
        cfg = _require_config()
        try:
            s = cfg.get_store(store_id)
        except KeyError:
            raise HTTPException(status_code=404, detail=f"unknown store: {store_id}")
        # Snapshot the known-good config so we can roll back if the new one
        # cannot be registered. Scoped policies are untouched (store_id is fixed).
        prev = {"kind": s.kind, "conn": dict(s.conn),
                "tenant_field": s.tenant_field, "description": s.description}
        from vecshield_platform.api.secrets import SecretReferenceDenied, reference_names
        try:
            s = cfg.update_store(store_id, kind=req.kind, conn=req.conn,
                                 tenant_field=req.tenant_field,
                                 description=req.description)
        except SecretReferenceDenied as e:
            _refused_reference(actor, store_id, "store_update", req.conn, e)
            raise HTTPException(status_code=422, detail=str(e)) from e
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))
        try:
            rebuild_registry()
        except Exception as e:  # noqa: BLE001
            cfg.update_store(store_id, **prev)
            rebuild_registry()
            raise HTTPException(status_code=400, detail=f"store update failed: {e}")
        log.append(actor, "store_updated", store_id,
                   {"kind": req.kind, "secret_refs": reference_names(s.conn)})
        return s.public_dict()

    @app.delete("/admin/stores/{store_id}")
    def delete_store(store_id: str, actor: str = Depends(require_admin)) -> dict:
        cfg = _require_config()
        cfg.remove_store(store_id)
        rebuild_registry()
        # Reviewer decisions and applicability answers were about this
        # registration. A store later added under the same id is a different
        # system until someone says otherwise, so they stop applying here. The
        # rows are kept as history, not deleted.
        retired = (hist.retire_store_records(
            store_id, retired_by=actor,
            retired_at=datetime.now(timezone.utc).isoformat())
            if hist is not None else None)
        log.append(actor, "store_removed", store_id,
                   {"retired": retired} if retired is not None else {})
        return {"removed": store_id, "retired": retired}

    @app.post("/admin/stores/test-connection")
    def test_connection_dry_run(req: TestConnectionRequest,
                                actor: str = Depends(require_admin)) -> dict:
        """Try a connection before saving it — the edit form's pre-save test.

        Nothing is written to the config. Masked values resolve to the stored
        secrets exactly as a save would. A failure reports its category and
        exception type, never the exception text: connector errors can echo a
        DSN or URL with the credential in it.
        """
        from vecshield_platform.api.config_store import _resolve_secrets
        from vecshield_platform.api.secrets import SecretReferenceDenied, reference_names
        from vecshield_platform.connectors import AVAILABLE, build_connector
        from vecshield_platform.validation import classify_connector_error

        cfg = _require_config()
        if req.kind not in AVAILABLE:
            raise HTTPException(status_code=422, detail=f"unknown connector kind: {req.kind}")
        if req.store_id and req.store_id not in cfg.stores:
            raise HTTPException(status_code=404, detail=f"unknown store: {req.store_id}")
        merged: dict = dict(req.conn)
        try:
            merged = cfg.resolve_masked_conn(req.store_id, req.conn, kind=req.kind)
            conn = _resolve_secrets(merged)
        except SecretReferenceDenied as e:
            _refused_reference(actor, req.store_id or "(new)", "store_connection_test",
                               merged, e)
            raise HTTPException(status_code=422, detail=str(e)) from e
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e)) from e
        result: dict[str, Any]
        connector = None
        try:
            connector = build_connector(req.kind, **conn)
            described = connector.describe()
            result = {"ok": True, "endpoint": described.name,
                      "collections": [{"name": c.name, "count": c.count,
                                       "dimension": c.dimension}
                                      for c in described.collections]}
        except Exception as e:  # noqa: BLE001
            result = {"ok": False, "category": classify_connector_error(e),
                      "error_type": type(e).__name__,
                      "reason": "The connection could not be opened with these "
                                "settings. Nothing was saved."}
        finally:
            if connector is not None:
                try:
                    connector.close()
                except Exception:  # noqa: BLE001
                    pass
        log.append(actor, "store_connection_tested", req.store_id or "(new)",
                   {"kind": req.kind, "ok": result["ok"],
                    "category": result.get("category"),
                    # Names of the resolved references, never their values.
                    "secret_refs": reference_names(merged)})
        return result

    @app.post("/admin/stores/{store_id}/test")
    def test_store(store_id: str, actor: str = Depends(require_auth)) -> dict:
        """Open a saved store and list its collections. Read-only.

        A failure reports its category and exception type, like the pre-save
        test, never the connector's message.
        """
        conn = _store(store_id)
        try:
            store = conn.describe()
            cols = [{"name": c.name, "count": c.count, "dimension": c.dimension}
                    for c in store.collections]
        except Exception as e:  # noqa: BLE001
            raise HTTPException(
                status_code=400,
                detail=f"connection failed ({_connector_failure(e)})") from e
        finally:
            conn.close()
        return {"ok": True, "endpoint": store.name, "collections": cols}

    @app.get("/admin/policies")
    def list_policies(store_id: Optional[str] = None,
                      actor: str = Depends(require_auth)) -> dict:
        cfg = _require_config()
        pols = list(cfg.policies.values())
        if store_id:
            pols = [p for p in pols if p.scope_store in (None, store_id)]
        return {"policies": [p.to_dict() for p in pols]}

    @app.post("/admin/policies")
    def create_policy(req: AddPolicyRequest,
                      actor: str = Depends(require_admin)) -> dict:
        cfg = _require_config()
        try:
            if req.template_id:
                p = cfg.add_policy_from_template(
                    req.template_id, scope_store=req.scope_store,
                    scope_collection=req.scope_collection, enabled=req.enabled,
                    name=req.name, description=req.description,
                    when=req.when, action=req.action, severity=req.severity)
            else:
                if not (req.name and req.when and req.action):
                    raise HTTPException(status_code=422,
                                        detail="custom policy needs name, when, action")
                p = cfg.add_policy(
                    name=req.name, description=req.description, when=req.when,
                    action=req.action, severity=req.severity, enabled=req.enabled,
                    scope_store=req.scope_store, scope_collection=req.scope_collection)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))
        log.append(actor, "policy_created", p.id,
                   {"template": p.template_id, "scope_store": p.scope_store,
                    "scope_collection": p.scope_collection})
        return p.to_dict()

    @app.patch("/admin/policies/{policy_id}")
    def update_policy(policy_id: str, req: UpdatePolicyRequest,
                      actor: str = Depends(require_admin)) -> dict:
        cfg = _require_config()
        changes = req.model_dump(exclude_none=True)
        try:
            p = cfg.update_policy(policy_id, **changes)
        except KeyError:
            raise HTTPException(status_code=404, detail="unknown policy")
        log.append(actor, "policy_updated", policy_id,
                   {"fields": sorted(changes.keys())})
        return p.to_dict()

    @app.delete("/admin/policies/{policy_id}")
    def delete_policy(policy_id: str, actor: str = Depends(require_admin)) -> dict:
        cfg = _require_config()
        cfg.remove_policy(policy_id)
        log.append(actor, "policy_removed", policy_id, {})
        return {"removed": policy_id}

    # ---------------- false-positive management ----------------
    # Two distinct mechanisms, both surfaced here:
    #   * allowlist rules — permanent calibration for known-benign patterns
    #     (scope and/or value patterns); include safe built-ins by default.
    #   * suppressions   — time-boxed risk acceptance for a specific finding
    #     fingerprint, always requiring an owner, reason, and expiry.
    # Suppressed findings are still detected, recorded, and counted — only
    # excluded from alerts and gate decisions — so this never hides risk.

    @app.get("/admin/allowlist")
    def list_allowlist(include_builtin: bool = True,
                       actor: str = Depends(require_auth)) -> dict:
        cfg = _require_config()
        rules = cfg.effective_allowlist(include_builtin=include_builtin)
        return {"allowlist": [r.to_dict() for r in rules]}

    @app.post("/admin/allowlist")
    def create_allowlist(req: AddAllowlistRequest,
                         actor: str = Depends(require_admin)) -> dict:
        cfg = _require_config()
        try:
            rule = cfg.add_allowlist_rule(
                reason=req.reason, category=req.category, store=req.store,
                collection=req.collection, rule=req.rule,
                fingerprints=req.fingerprints, value_patterns=req.value_patterns,
                owner=req.owner or actor)
        except (SuppressionError, ValueError) as e:
            raise HTTPException(status_code=422, detail=str(e))
        log.append(actor, "allowlist_rule_created", rule.id,
                   {"category": rule.category, "store": rule.store,
                    "collection": rule.collection})
        return rule.to_dict()

    @app.delete("/admin/allowlist/{rule_id}")
    def delete_allowlist(rule_id: str, actor: str = Depends(require_admin)) -> dict:
        cfg = _require_config()
        cfg.remove_allowlist_rule(rule_id)
        log.append(actor, "allowlist_rule_removed", rule_id, {})
        return {"removed": rule_id}

    @app.get("/admin/suppressions")
    def list_suppressions(actor: str = Depends(require_auth)) -> dict:
        cfg = _require_config()
        return {"suppressions": [s.to_dict() for s in cfg.active_suppressions()]}

    @app.post("/admin/suppressions")
    def create_suppression(req: AddSuppressionRequest,
                           actor: str = Depends(require_admin)) -> dict:
        from vecshield.models import Severity
        from vecshield_platform.compliance.allowlist import is_sensitive

        cfg = _require_config()
        severity = None
        if req.severity:
            try:
                severity = Severity(req.severity)
            except ValueError:
                raise HTTPException(status_code=422,
                                    detail=f"unknown severity: {req.severity}")
        category = req.category
        # The TTL ceiling follows the finding the fingerprint names, not what
        # the caller says about it: leaving severity out used to let a
        # critical finding be muted for the general maximum. The stricter of
        # the two wins; an unrecorded fingerprint keeps the caller's values.
        recorded = hist.findings_by_fingerprint(req.fingerprint) if hist is not None else []
        for row in recorded:
            try:
                seen = Severity(row.get("severity"))
            except ValueError:
                seen = None
            if seen is not None and (severity is None or seen.rank > severity.rank):
                severity = seen
            if (row.get("category") and not is_sensitive(category=category)
                    and is_sensitive(category=row["category"])):
                category = row["category"]
        try:
            supp = cfg.add_suppression(
                fingerprint=req.fingerprint, reason=req.reason,
                owner=req.owner, expires_at=req.expires_at, ticket=req.ticket,
                category=category, severity=severity)
        except (SuppressionError, ValueError) as e:
            raise HTTPException(status_code=422, detail=str(e))
        log.append(actor, "suppression_created", supp.id,
                   {"fingerprint": supp.fingerprint, "expires_at": supp.expires_at,
                    "ticket": supp.ticket,
                    "severity": severity.value if severity is not None else None,
                    "category": category, "recorded_occurrences": len(recorded)})
        return supp.to_dict()

    @app.delete("/admin/suppressions/{supp_id}")
    def delete_suppression(supp_id: str, actor: str = Depends(require_admin)) -> dict:
        cfg = _require_config()
        cfg.remove_suppression(supp_id)
        log.append(actor, "suppression_removed", supp_id, {})
        return {"removed": supp_id}

    # ---------------- alerting ----------------

    @app.get("/admin/alerting")
    def get_alerting(actor: str = Depends(require_admin)) -> dict:
        """Current alert-delivery config (webhook secrets masked)."""
        cfg = _require_config()
        return _mask_alerting(cfg.get_alerting())

    @app.put("/admin/alerting")
    def put_alerting(req: AlertingConfigRequest,
                     actor: str = Depends(require_admin)) -> dict:
        """Update alert delivery: enable/disable, webhooks, min severity, console."""
        cfg = _require_config()
        changes = req.model_dump(exclude_none=True)
        try:
            a = cfg.set_alerting(**changes)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))
        log.append(actor, "alerting_updated", "alerting",
                   {"enabled": a.enabled, "webhooks": len(a.webhooks),
                    "min_severity": a.min_severity, "console": a.console})
        if runtime_engine is None:
            app.state.runtime_engine = _build_runtime_engine()
        return _mask_alerting(a)

    # ---------------- detector tuning ------------------------------------

    @app.get("/admin/detectors")
    def get_detectors(actor: str = Depends(require_auth)) -> dict:
        cfg = _require_config()
        return cfg.get_detector_settings().to_dict()

    @app.put("/admin/detectors")
    def put_detectors(req: DetectorSettingsRequest,
                      actor: str = Depends(require_admin)) -> dict:
        cfg = _require_config()
        try:
            d = cfg.set_detector_settings(**req.model_dump(exclude_none=True))
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))
        if runtime_engine is None:
            app.state.runtime_engine = _build_runtime_engine()
        log.append(actor, "detectors_updated", "runtime",
                   {"detectors": [x.name for x in getattr(app.state.runtime_engine, "detectors", [])]})
        return d.to_dict()

    # ---------------- access control diagnostics ----------------

    @app.post("/admin/rbac-diff")
    def rbac_diff(req: RBACDiffRequest,
                  actor: str = Depends(require_auth)) -> dict:
        # Stateless: pure set diff of intended vs. actual grants. No store touched.
        try:
            intended = grants_from_dicts(req.intended)
            actual = grants_from_dicts(req.actual)
        except (KeyError, TypeError) as e:
            raise HTTPException(status_code=422, detail=f"invalid grant: {e}")
        findings = diff_access(intended, actual, store_name=req.store_name)
        log.append(actor, "rbac_diff", req.store_name,
                   {"intended": len(intended), "actual": len(actual),
                    "findings": len(findings)})
        return {"findings": [f.to_dict() for f in findings]}

    @app.post("/admin/validate")
    def validate_stores_endpoint(req: ValidateRequest = ValidateRequest(),
                                 background: bool = False,
                                 actor: str = Depends(require_auth)):
        # Read-only live-contract validation over registered stores. A single
        # unreachable store yields a per-store error, never a 500 for the batch.
        stores = reg().list()
        if req.store_id:
            stores = [s for s in stores if s.store_id == req.store_id]
            if not stores:
                raise HTTPException(status_code=404,
                                    detail=f"unknown store: {req.store_id}")

        def _work() -> dict:
            results = []
            for s in stores:
                try:
                    conn = reg().open(s.store_id)
                except Exception as e:  # noqa: BLE001
                    results.append({"store_id": s.store_id, "ok": False,
                                    "error": "open failed: " + _logged_failure(
                                        e, f"validate could not open {s.store_id}")})
                    continue
                try:
                    res = validate_connector(
                        conn, max_collections=req.max_collections,
                        sample_chunks=req.sample_chunks, run_scan=req.run_scan,
                        run_query=req.run_query, run_key_audit=req.run_key_audit)
                    results.append({"store_id": s.store_id, **res.to_dict()})
                except Exception as e:  # noqa: BLE001
                    results.append({"store_id": s.store_id, "ok": False,
                                    "error": _logged_failure(
                                        e, f"validate failed for {s.store_id}")})
                finally:
                    conn.close()
            log.append(actor, "validate_stores", req.store_id or "*",
                       {"stores": len(results)})
            return {"results": results}

        return _maybe_background("validate", _work, background=background,
                                 actor=actor, resource=req.store_id or "*")

    # NOTE: Discovery (active network scanning) is intentionally CLI-only. An
    # active scanner exposed over the served API is a security smell (SSRF /
    # internal-recon vector), so it is deliberately not offered as a route. Run
    # `vecshield discover` from a trusted network context instead.

    # ---------------- DSAR workflow ----------------

    @app.post("/admin/dsar")
    def dsar_create(req: DSARCreateRequest, background: bool = False,
                    actor: str = Depends(require_compliance)):
        """Create a DSAR record and scan all stores for the subject (read-only)."""
        def _work() -> dict:
            dsar = create_dsar(req.subject)
            dsar.notes = req.notes
            scan_all_stores(dsar, reg(), store_ids=req.store_ids)
            if hist:
                hist.save_dsar(dsar, created_by=actor)
            log.append(actor, "dsar_created", dsar.id,
                       {"subject_key": _audit_subject(req.subject),
                        "chunks_found": dsar.total_chunks_found,
                        "stores": len(dsar.stores)})
            return dsar.to_dict()

        # The job record is readable more widely than the request itself, so
        # it names the subject only by its key (F3).
        return _maybe_background("dsar_create", _work, background=background,
                                 actor=actor, resource=_audit_subject(req.subject))

    # F3: a DSAR names a person and what was found about them. Reading one
    # is a compliance task, like opening or executing it.
    @app.get("/admin/dsar")
    def dsar_list(status: Optional[str] = None,
                  actor: str = Depends(require_compliance)) -> dict:
        if hist is None:
            return {"dsars": [], "message": "history not configured"}
        return {"dsars": hist.list_dsars(status=status)}

    @app.get("/admin/dsar/{dsar_id}")
    def dsar_get(dsar_id: str, actor: str = Depends(require_compliance)) -> dict:
        if hist is None:
            raise HTTPException(status_code=409, detail="history not configured")
        d = hist.get_dsar(dsar_id)
        if not d:
            raise HTTPException(status_code=404, detail="DSAR not found")
        # The request's detail lives in its persisted record. Returning the raw
        # row put stores, matches and totals under `record` (and the same JSON
        # again as a string), so a reader saw no stores and zero matches on a
        # request that had found some. Rehydrating also re-derives the status.
        return _dsar_detail(d)

    def _dsar_record(row: dict):
        import json as _json
        from vecshield_platform.compliance.dsar import DSARRecord
        raw = row.get("record_json") or row.get("record") or {}
        if isinstance(raw, str):
            raw = _json.loads(raw)
        return DSARRecord.from_dict(raw)

    def _dsar_detail(row: dict) -> dict:
        try:
            detail = _dsar_record(row).to_dict()
        except (KeyError, TypeError, ValueError):
            # A record that cannot be read is shown as the row it is, with the
            # reason, rather than as an empty request.
            detail = {k: v for k, v in row.items() if k not in ("record_json", "record")}
            detail["error"] = "The stored request record could not be read."
        detail["created_at"] = row.get("created_at")
        # Who opened it: executing it needs someone else (or an admin).
        detail["created_by"] = row.get("created_by")
        return detail

    @app.post("/admin/dsar/{dsar_id}/execute")
    def dsar_execute(dsar_id: str, req: DSARExecuteRequest,
                     background: bool = False,
                     principal: "Principal" = Depends(require_compliance_principal)):
        """Execute deletions for a previously scanned DSAR.

        Irreversible, so it needs a second person: whoever opened the request
        cannot also run it, unless they hold admin or the deployment's
        separation of duties is off. The audit entry says which applied.
        """
        from vecshield_platform.execution import ExecutionError
        actor = principal.subject
        if hist is None:
            raise HTTPException(status_code=409, detail="history not configured")
        row = hist.get_dsar(dsar_id)
        if not row:
            raise HTTPException(status_code=404, detail="DSAR not found")
        # Refuse before queueing: executing an erased (or never-scanned) request
        # raised inside the worker and surfaced as a bare 500.
        current = _dsar_record(row).status
        if current not in ("scanned", "partial_error", "awaiting_verification"):
            raise HTTPException(
                status_code=409,
                detail=(f"This request is '{current}'; only a scanned request, or one "
                        "awaiting verification or partly failed, can be executed."))
        _refuse_in_safe_mode(actor, "dsar_execution", dsar_id)
        creator = row.get("created_by")
        if not creator:
            # Requests opened before the creator was recorded: the hash-chained
            # log names who created them.
            creator = next((e.actor for e in log.entries
                            if e.action == "dsar_created" and e.target == dsar_id), None)
        if creator and creator != actor:
            execution_mode: Optional[str] = "second_person"
        else:
            execution_mode = _single_person_execution(principal)
        if execution_mode is None:
            log.append(actor, "dsar_execution_refused", dsar_id,
                       {"reason": "second_person_required", "created_by": creator,
                        "separation_of_duties": _separation.mode})
            raise HTTPException(
                status_code=403,
                detail=(DSAR_SELF_EXECUTE_DETAIL if creator
                        else DSAR_UNKNOWN_CREATOR_DETAIL))

        def _work() -> dict:
            # Reconstruct DSARRecord from persisted JSON
            import json as _json
            from vecshield_platform.compliance.dsar import DSARRecord
            raw = row.get("record_json") or row.get("record") or {}
            if isinstance(raw, str):
                raw = _json.loads(raw)
            dsar = DSARRecord.from_dict(raw)
            _log_intent(actor, "dsar_execution_started", dsar_id,
                        {"created_by": creator, "execution_mode": execution_mode,
                         "store_ids": req.store_ids, "actor_source": principal.source},
                        refused="nothing was deleted")
            opened: dict[str, Any] = {}

            class _RecordingRegistry:
                """The live registry, noting each connector the DSAR opens so
                its erasure notes (F6) can be recorded afterwards."""

                def open(self, store_id: str):
                    conn = reg().open(store_id)
                    opened[store_id] = conn
                    return conn

                def __getattr__(self, name: str):
                    return getattr(reg(), name)

            try:
                execute_dsar(dsar, _RecordingRegistry(), store_ids=req.store_ids,
                             verify=req.verify)
            except ExecutionError as e:
                log.append(actor, "dsar_execution_refused", dsar_id, {"reason": str(e)})
                raise HTTPException(status_code=409, detail=str(e)) from e
            hist.save_dsar(dsar)
            connector_notes = {sid: n for sid, c in sorted(opened.items())
                               if (n := _connector_erasure_notes(c))}
            _log_done(actor, "dsar_executed", dsar_id,
                      {"deleted": dsar.total_chunks_deleted,
                       "status": dsar.status, "created_by": creator,
                       "execution_mode": execution_mode,
                       "separation_of_duties": _separation.mode,
                       "actor_source": principal.source,
                       **({"connector_notes": connector_notes} if connector_notes else {})},
                      completed=(f"the request was executed "
                                 f"({dsar.total_chunks_deleted} chunk(s) deleted)"))
            return dsar.evidence_bundle()

        return _maybe_background("dsar_execute", _work, background=background,
                                 actor=actor, resource=dsar_id)

    @app.get("/admin/dsar/{dsar_id}/evidence")
    def dsar_evidence(dsar_id: str, actor: str = Depends(require_compliance)) -> dict:
        """Return the evidence bundle for a completed DSAR."""
        if hist is None:
            raise HTTPException(status_code=409, detail="history not configured")
        row = hist.get_dsar(dsar_id)
        if not row:
            raise HTTPException(status_code=404, detail="DSAR not found")
        import json as _json
        from vecshield_platform.compliance.dsar import DSARRecord
        raw = row.get("record_json") or row.get("record") or {}
        if isinstance(raw, str):
            raw = _json.loads(raw)
        dsar = DSARRecord.from_dict(raw)
        return dsar.evidence_bundle()

    # ---------------- evidence and exceptions ----------------

    def _new_id(prefix: str) -> str:
        import uuid as _uuid

        return f"{prefix}-{_uuid.uuid4().hex[:12]}"

    @app.get("/compliance/evidence")
    def evidence_list(scope: Optional[str] = None, state: Optional[str] = None,
                      actor: str = Depends(require_auth)) -> dict:
        store = _require_history()
        artifacts = [EvidenceArtifact(**a).to_dict() for a in
                     store.list_artifacts(scope=scope, state=state)]
        from vecshield_platform.evidence import lifecycle_reference

        return {"artifacts": artifacts,
                "lifecycle": lifecycle_reference(),
                "note": ("An artifact's state says whether the file is fit to look at. "
                         "Whether it evidences anything is a separate review.")}

    @app.post("/compliance/evidence")
    def evidence_register(req: ArtifactRequest,
                          actor: str = Depends(require_compliance)) -> dict:
        store = _require_history()
        artifact = EvidenceArtifact(
            id=req.id or _new_id("ev"), title=req.title, media_type=req.media_type,
            content_hash=req.content_hash, size_bytes=req.size_bytes,
            collector=actor, collected_at=datetime.now(timezone.utc).isoformat(),
            scope=req.scope, period_start=req.period_start, period_end=req.period_end,
            supersedes=req.supersedes, note=req.note)
        store.save_artifact(artifact)
        if req.supersedes:
            prior = store.get_artifact(req.supersedes)
            if prior:
                try:
                    store.save_artifact(transition_artifact(
                        EvidenceArtifact(**prior), to_state="superseded", actor=actor,
                        reason=f"superseded by {artifact.id}"))
                except EvidenceError:
                    pass  # a prior in a state that cannot be superseded is left alone
        log.append(actor, "evidence_registered", artifact.id, {"scope": req.scope})
        return artifact.to_dict()

    @app.post("/compliance/evidence/{artifact_id}/state")
    def evidence_state(artifact_id: str, req: ArtifactStateRequest,
                       actor: str = Depends(require_compliance)) -> dict:
        store = _require_history()
        raw = store.get_artifact(artifact_id)
        if raw is None:
            raise HTTPException(status_code=404, detail=f"unknown artifact: {artifact_id}")
        try:
            artifact = transition_artifact(EvidenceArtifact(**raw), to_state=req.to_state,
                                           actor=actor, reason=req.reason)
        except EvidenceError as e:
            raise HTTPException(status_code=409, detail=str(e)) from e
        store.save_artifact(artifact)
        log.append(actor, "evidence_state_changed", artifact_id,
                   {"to": req.to_state, "reason": req.reason})
        return artifact.to_dict()

    @app.get("/compliance/reviews")
    def reviews_list(criterion_id: Optional[str] = None, scope: Optional[str] = None,
                     actor: str = Depends(require_auth)) -> dict:
        """Reviews, reported against criterion ids that are still in the pack.

        A review stores its criterion id as a plain string, so one filed before
        a criterion was renamed keeps the retired id forever. Served raw, that
        puts an id on the Evidence page which cannot be found anywhere in
        Frameworks -- the reviewer's own record pointing at a criterion the
        product no longer admits exists. `/stores/{id}/criteria` already
        rewrites these; this list is the other surface that shows them, and it
        has to agree. `original_criterion_id` is kept on the row so the
        rewrite is visible rather than silent.
        """
        from vecshield_platform.compliance.packs import resolve_criterion_id

        store = _require_history()
        # Filtering has the same problem in the other direction: asking for the
        # current id must also return what was filed under the retired one, or
        # a criterion silently loses its evidence the day it is renamed.
        if criterion_id:
            wanted = resolve_criterion_id(criterion_id) or criterion_id
            source = [r for r in store.list_reviews(scope=scope)
                      if (resolve_criterion_id(r.get("criterion_id"))
                          or r.get("criterion_id")) == wanted]
        else:
            source = list(store.list_reviews(scope=scope))
        rows = []
        for record in source:
            stored = record.get("criterion_id")
            current = resolve_criterion_id(stored) if stored else None
            if current and current != stored:
                record = {**record, "criterion_id": current,
                          "original_criterion_id": stored}
            rows.append(EvidenceReview(**{
                k: v for k, v in record.items() if k != "original_criterion_id"}).to_dict())
            if "original_criterion_id" in record:
                rows[-1]["original_criterion_id"] = record["original_criterion_id"]
        return {"reviews": rows}

    @app.post("/compliance/reviews")
    def review_request(req: ReviewRequest,
                       actor: str = Depends(require_compliance)) -> dict:
        store = _require_history()
        if store.get_artifact(req.artifact_id) is None:
            raise HTTPException(status_code=404,
                                detail=f"unknown artifact: {req.artifact_id}")
        review = EvidenceReview(
            id=req.id or _new_id("rev"), artifact_id=req.artifact_id,
            criterion_id=req.criterion_id, requirement=req.requirement,
            scope=req.scope, period=req.period, state="submitted")
        store.save_review(review)
        log.append(actor, "evidence_review_opened", review.id,
                   {"criterion": req.criterion_id, "artifact": req.artifact_id})
        return review.to_dict()

    @app.post("/compliance/reviews/{review_id}")
    def review_decide(review_id: str, req: ReviewDecisionRequest,
                      actor: str = Depends(require_compliance)) -> dict:
        store = _require_history()
        raw = store.get_review(review_id)
        if raw is None:
            raise HTTPException(status_code=404, detail=f"unknown review: {review_id}")
        try:
            review = transition_review(EvidenceReview(**raw), to_state=req.to_state,
                                       reviewer=actor, reason=req.reason)
        except EvidenceError as e:
            raise HTTPException(status_code=409, detail=str(e)) from e
        store.save_review(review)
        log.append(actor, "evidence_review_decided", review_id,
                   {"to": req.to_state, "reason": req.reason})
        return review.to_dict()

    @app.get("/compliance/exceptions")
    def exceptions_list(criterion_id: Optional[str] = None, scope: Optional[str] = None,
                        actor: str = Depends(require_auth)) -> dict:
        store = _require_history()
        # An absent query parameter and an empty one both mean "no filter"
        # over HTTP; only the internal caller uses "" to mean the estate-wide
        # scope, and it passes it directly rather than through a URL.
        items = [RiskException(**e).to_dict() for e in
                 store.list_exceptions(criterion_id=criterion_id or None,
                                       scope=scope or None)]
        # Approval reasons (C-8) live in the audit log; attach the latest.
        reasons = {e.target: e.details.get("reason") for e in log.entries
                   if e.action == "exception_approved" and e.details.get("reason")}
        for item in items:
            if not item.get("approval_reason") and item["id"] in reasons:
                item["approval_reason"] = reasons[item["id"]]
        return {
            "exceptions": items,
            "pending_approval": sum(1 for e in items if e["status"] == "pending_approval"),
            "active": sum(1 for e in items if e["active"]),
            "expired": sum(1 for e in items if e["status"] == "expired"),
            "note": ("An exception records that a gap is tolerated. It does not close "
                     "the gap, and it stops applying when it expires."),
        }

    @app.post("/compliance/exceptions")
    def exception_request(req: ExceptionRequest,
                          actor: str = Depends(require_compliance)) -> dict:
        store = _require_history()
        now = datetime.now(timezone.utc).isoformat()
        if req.expires_at <= now:
            raise HTTPException(status_code=422,
                                detail="an exception expires in the future or not at all")
        record = RiskException(
            id=req.id or _new_id("exc"), criterion_id=req.criterion_id, scope=req.scope,
            rationale=req.rationale, requested_by=actor, expires_at=req.expires_at,
            created_at=now)
        store.save_exception(record)
        log.append(actor, "exception_requested", record.id,
                   {"criterion": req.criterion_id, "expires_at": req.expires_at})
        return record.to_dict()

    @app.post("/compliance/exceptions/{exception_id}/approve")
    def exception_approve(exception_id: str,
                          req: Optional[ExceptionApproveRequest] = None,
                          principal: "Principal" = Depends(require_compliance_principal)) -> dict:
        actor = principal.subject
        store = _require_history()
        raw = store.get_exception(exception_id)
        if raw is None:
            raise HTTPException(status_code=404, detail=f"unknown exception: {exception_id}")
        record = RiskException(**raw)
        if record.revoked_at:
            raise HTTPException(status_code=409, detail="a revoked exception cannot be approved")
        if record.approved_by:
            # Approving again would rewrite who approved it and when, and a
            # requester could re-approve an exception someone else approved.
            raise HTTPException(
                status_code=409,
                detail=(f"this exception is already approved by {record.approved_by}; "
                        "revoke it and request a new one to change the approval"))
        reason = (req.reason if req is not None else "").strip()
        if not reason:
            # C-8: an approval without a reason cannot be reviewed later.
            raise HTTPException(
                status_code=422,
                detail=("approving an exception needs a reason: send {\"reason\": \"...\"} "
                        "saying why the gap may be tolerated until it expires"))
        self_approved = record.requested_by == actor
        if self_approved and not _separation.allows_self_approval(principal.roles):
            # Separation of duties: tolerating your own gap is not a decision,
            # unless this deployment has said in so many words that it may be.
            raise HTTPException(
                status_code=409,
                detail="an exception is approved by someone other than the person who "
                       "requested it. " + _separation.refusal(proposer=actor,
                                                              what="this exception"))
        from vecshield_platform.evidence import approve_exception
        try:
            approved = approve_exception(
                record, approver=actor, reason=reason, self_approved=self_approved,
                at=datetime.now(timezone.utc).isoformat())
        except EvidenceError as e:
            raise HTTPException(status_code=422, detail=str(e)) from e
        store.save_exception(approved)
        # The reason is recorded in the hash-chained log, which is also where
        # the exception list reads it back from (history has no column yet).
        log.append(actor, "exception_approved", exception_id,
                   {"self_approved": self_approved,
                    "separation_of_duties": _separation.mode,
                    "actor_source": principal.source,
                    "reason": approved.approval_reason})
        return approved.to_dict()

    @app.post("/compliance/exceptions/{exception_id}/revoke")
    def exception_revoke(exception_id: str,
                         actor: str = Depends(require_compliance)) -> dict:
        store = _require_history()
        raw = store.get_exception(exception_id)
        if raw is None:
            raise HTTPException(status_code=404, detail=f"unknown exception: {exception_id}")
        revoked = RiskException(**{**raw,
                                   "revoked_at": datetime.now(timezone.utc).isoformat()})
        store.save_exception(revoked)
        log.append(actor, "exception_revoked", exception_id, {})
        return revoked.to_dict()

    # ---------------- estate ----------------

    def _merged_case_summary(observed: list[str]) -> dict:
        merged: dict[str, int] = {}
        for name in observed:
            for state, count in hist.case_summary(store=name).items():
                merged[state] = merged.get(state, 0) + count
        return merged

    def _store_history_summary(store_id: str) -> dict:
        """What history knows about a store, without touching the store itself."""
        if hist is None:
            return {"last_assessed": None, "coverage": None, "findings": {},
                    "cases": {}, "history_available": False}
        audits = hist.list_audits(store_id=store_id, limit=1)
        latest = audits[0] if audits else None
        # Findings are recorded under the connector's own name, not the registry
        # id, so translate before counting — otherwise every store reports zero.
        # Falling back to the id itself covers stores whose connector reports the
        # same name, and stores scanned without a saved audit to bridge the two.
        observed = hist.observed_store_names(store_id) or [store_id]
        findings = hist.query_findings(stores=observed, limit=1)
        return {
            "last_assessed": (latest or {}).get("finished_at"),
            "last_audit_id": (latest or {}).get("id"),
            "coverage": (latest or {}).get("coverage"),
            "findings": findings.get("facets", {}).get("severity", {}),
            "findings_total": findings.get("total", 0),
            "cases": _merged_case_summary(observed),
            "history_available": True,
        }

    def _probe_store(store_id: str) -> dict:
        """Open a store and report what it can actually do.

        Capabilities are declared by a live connector, so they are only known
        after connecting. Without a probe this reports `probed: false` rather
        than guessing — an unknown capability is not an absent one.
        """
        try:
            conn = reg().open(store_id)
        except KeyError:
            raise HTTPException(status_code=404, detail=f"unknown store: {store_id}") from None
        except Exception as e:  # noqa: BLE001 - one bad store must not fail the page
            return {"probed": True, "reachable": False,
                    "error": _logged_failure(e, f"probe could not open {store_id}"),
                    "capabilities": None, "content_enumerable": None, "collections": None}
        try:
            described = conn.describe()
            return {
                "probed": True, "reachable": True, "error": None,
                "capabilities": sorted(conn.capabilities()),
                "content_enumerable": bool(getattr(conn, "content_enumerable", True)),
                "collections": len(described.collections),
                "chunks": sum(c.count or 0 for c in described.collections),
            }
        except Exception as e:  # noqa: BLE001
            return {"probed": True, "reachable": False,
                    "error": _logged_failure(e, f"probe failed for {store_id}"),
                    "capabilities": None, "content_enumerable": None, "collections": None}
        finally:
            conn.close()

    # Not /admin/stores/summary: that would be captured by /admin/stores/{store_id}.
    @app.get("/admin/subject-index")
    def subject_index_stats(actor: str = Depends(require_compliance)) -> dict:
        """Size and reach of the subject index. Never any subject detail.

        Gated on the compliance role rather than on any authenticated caller:
        the counts alone say how many distinct people are recorded in this
        estate, which is not a number every viewer needs.
        """
        if hist is None:
            raise HTTPException(
                status_code=409,
                detail="the subject index requires scan history to be configured.")
        from vecshield_platform.subject_index import IDENTIFIER_DETECTORS
        stats = hist.subject_index_stats()
        return {
            **stats,
            "indexed_detectors": sorted(IDENTIFIER_DETECTORS),
            "limits": [
                "Rows record where a subject was seen by a scan. Absence from "
                "the index is not evidence the subject is absent from a store.",
                "Identifiers are not stored: each row holds a keyed hash whose "
                "key lives outside this database.",
                "A subject's rows are removed when their data is erased.",
            ],
        }

    @app.get("/admin/estate")
    def estate_summary(probe: bool = False, actor: str = Depends(require_auth)) -> dict:
        """One call for the whole estate: what we have, and how much we can inspect.

        Probing opens every registered connector, so it is opt-in: the overview
        reads this without a probe and says capabilities are unknown rather than
        assuming them.
        """
        stores = []
        for cfg in reg().list():
            entry = {**cfg.public_dict(), **_store_history_summary(cfg.store_id)}
            entry["probe"] = (_probe_store(cfg.store_id) if probe else
                              {"probed": False, "reachable": None, "error": None,
                               "capabilities": None, "content_enumerable": None,
                               "collections": None})
            stores.append(entry)
        return {
            "stores": stores,
            "probed": probe,
            "note": ("Capabilities and reachability are only known after opening a "
                     "connector. Without a probe they are unknown, which is not the "
                     "same as absent."),
        }

    # ---------------- home summary and approval queue ----------------

    def _plan_queue(principal: "Principal") -> list[dict]:
        """Staged plans across every store, oldest first, with the caller's
        standing under the separation-of-duties rule."""
        from vecshield_platform.home import plan_queue_entry

        registered = {cfg.store_id for cfg in reg().list()}
        approvals_by_plan = Counter(a.get("plan_id") for a in hist.list_approvals())
        entries = []
        for row in hist.list_plans(state="staged"):
            record = hist.get_plan(row["id"]) or {**row, "body": None,
                                                  "body_intact": False}
            entries.append(plan_queue_entry(
                record, actor=principal.subject, roles=principal.roles,
                has_approving_role=principal.has_role(COMPLIANCE),
                separation=_separation, approvals=approvals_by_plan.get(row["id"], 0),
                store_registered=row["store"] in registered))
        entries.sort(key=lambda e: (e["staged_at"] or "", e["plan_id"] or ""))
        return entries

    @app.get("/actions/queue")
    def approval_queue(include_approved: bool = False,
                       principal: "Principal" = Depends(require_principal)) -> dict:
        """Plans waiting for a person, across every store.

        A staged plan with no approval is waiting for approval; one with an
        approval is waiting for execution and is listed only when asked for.
        Each entry says whether the caller may approve it, and if not, why —
        including "needs a second person" under separation of duties. The
        approve endpoint still makes the decision; this previews it.
        """
        if hist is None:
            raise HTTPException(status_code=503,
                                detail="no scan history is configured, so no plans "
                                       "are stored to list.")
        entries = _plan_queue(principal)
        waiting = [e for e in entries if e["awaiting"] == "approval"]
        listed = entries if include_approved else waiting
        return {
            "actor": principal.subject,
            "plans": listed,
            "counts": {
                "awaiting_approval": len(waiting),
                "awaiting_execution": len(entries) - len(waiting),
                "you_may_approve": sum(e["you"]["may_approve"] for e in waiting),
                "needs_second_person": sum(e["you"]["needs_second_person"]
                                           for e in waiting),
            },
            "separation_of_duties": _separation.to_dict(),
            "note": ("Whether you may approve is a preview of the rule the approve "
                     "endpoint applies. Approving never executes a plan."),
        }

    @app.get("/admin/home")
    def home_summary(principal: "Principal" = Depends(require_principal)) -> dict:
        """What needs a person, and what is open, across the registered estate.

        Counts only. Snapshots are read once (the latest per store), findings
        are counted by distinct fingerprint from those audits alone, and the
        crypto gate is evaluated without recording a release decision.
        """
        from vecshield_platform.crypto.gate import accepted_pairs, evaluate_gate
        from vecshield_platform.evidence import RiskException
        from vecshield_platform.home import (
            EXPIRY_WINDOW_DAYS, REVIEW_WAITING_STATES, coverage_status,
            exception_buckets, needs_item, store_target, summarize_open_findings)

        store_ids = sorted(cfg.store_id for cfg in reg().list())
        note = ("Counts only: nothing here is a score or a percentage. A store "
                "that was never assessed is not a store with zero findings.")
        if hist is None:
            return {"history_available": False, "needs_you": [], "checked": [],
                    "unavailable": [], "open_findings": None,
                    "stores": {"total": len(store_ids), "assessed": None,
                               "never_assessed": None, "partial_coverage": None,
                               "coverage_status": None},
                    "note": note + " No scan history is configured, so nothing "
                                   "else can be counted."}

        snapshots = {sid: snap for sid, snap in hist.latest_audit_snapshots().items()
                     if sid in set(store_ids)}
        never = [sid for sid in store_ids if sid not in snapshots]
        coverage = {sid: ("unknown" if snap.get("unreadable") else coverage_status(snap))
                    for sid, snap in snapshots.items()}
        incomplete = sorted(sid for sid, status in coverage.items() if status != "complete")
        audit_store = {snap["id"]: sid for sid, snap in snapshots.items() if snap.get("id")}
        open_findings = summarize_open_findings(
            hist.audit_finding_fingerprints(list(audit_store)), audit_store,
            never_assessed=len(never))

        reviews = hist.list_reviews()
        artifacts = {a["id"]: EvidenceArtifact(**a).to_dict()
                     for a in hist.list_artifacts()}
        blocked, unavailable = [], []
        for sid, snap in sorted(snapshots.items()):
            if snap.get("unreadable"):
                unavailable.append({"check": "crypto_gate", "store_id": sid,
                                    "reason": "the latest saved audit could not be read"})
                continue
            try:
                result = evaluate_gate(
                    snap, store_id=sid,
                    accepted_evidence=accepted_pairs(reviews, artifacts, scope=sid),
                    settings={"requires_at_rest_encryption": False})
            except Exception as e:  # noqa: BLE001 - one bad snapshot must not fail home
                unavailable.append({"check": "crypto_gate", "store_id": sid,
                                    "reason": str(e)})
                continue
            if result["decision"] == "block":
                blocked.append(sid)

        queue = _plan_queue(principal)
        waiting_plans = [e for e in queue if e["awaiting"] == "approval"]
        waiting_reviews = [r for r in reviews if r.get("state") in REVIEW_WAITING_STATES]
        buckets = exception_buckets(
            [RiskException(**e).to_dict() for e in hist.list_exceptions()])

        needs: list[dict] = []
        if waiting_plans:
            needs.append(needs_item(
                "plans_awaiting_approval", "Plans awaiting approval", len(waiting_plans),
                view="actions", params={"queue": "approval"},
                stores=list({e["store"] for e in waiting_plans}),
                you_may_approve=sum(e["you"]["may_approve"] for e in waiting_plans),
                needs_second_person=sum(e["you"]["needs_second_person"]
                                        for e in waiting_plans)))
        if waiting_reviews:
            needs.append(needs_item(
                "evidence_reviews_awaiting_decision",
                "Evidence reviews awaiting a decision", len(waiting_reviews),
                view="evidence", params={"review_state": "awaiting"}))
        if buckets["expired"]:
            needs.append(needs_item(
                "exceptions_expired", "Exceptions that have expired",
                len(buckets["expired"]), view="exceptions", params={"status": "expired"}))
        if buckets["expiring"]:
            needs.append(needs_item(
                "exceptions_expiring",
                f"Exceptions expiring within {EXPIRY_WINDOW_DAYS} days",
                len(buckets["expiring"]), view="exceptions", params={"status": "active"},
                window_days=EXPIRY_WINDOW_DAYS))
        if buckets["awaiting_approval"]:
            needs.append(needs_item(
                "exceptions_awaiting_approval", "Exceptions awaiting approval",
                len(buckets["awaiting_approval"]), view="exceptions",
                params={"status": "pending_approval"}))
        if blocked:
            item = needs_item("crypto_gate_blocks", "Stores the crypto gate would block",
                              len(blocked), view="crypto", stores=blocked,
                              settings={"requires_at_rest_encryption": False})
            # Several stores: the Crypto screen's estate matrix, which shows
            # each one's gate decision, rather than the plain store list.
            item["target"] = (store_target(blocked, view="crypto") if len(blocked) == 1
                              else {"view": "crypto", "params": {"scope": "estate"}})
            needs.append(item)
        if never:
            item = needs_item("stores_never_assessed", "Stores never assessed",
                              len(never), view="assess", stores=never)
            item["target"] = store_target(never, view="assess")
            needs.append(item)
        if incomplete:
            item = needs_item(
                "stores_partial_coverage",
                "Stores whose latest audit did not cover its whole scope",
                len(incomplete), view="history", stores=incomplete,
                by_status=dict(Counter(coverage[sid] for sid in incomplete)))
            item["target"] = store_target(incomplete, view="history")
            needs.append(item)

        return {
            "history_available": True,
            "needs_you": needs,
            "checked": ["plans_awaiting_approval", "evidence_reviews_awaiting_decision",
                        "exceptions_expired", "exceptions_expiring",
                        "exceptions_awaiting_approval", "crypto_gate_blocks",
                        "stores_never_assessed", "stores_partial_coverage"],
            "unavailable": unavailable,
            "open_findings": open_findings,
            "stores": {
                "total": len(store_ids),
                "assessed": len(snapshots),
                "never_assessed": len(never),
                "partial_coverage": len(incomplete),
                "coverage_status": dict(Counter(coverage.values())),
            },
            "note": note,
        }

    # ---------------- findings as cases ----------------

    def _require_history():
        if hist is None:
            raise HTTPException(status_code=409,
                                detail="findings require scan history to be configured")
        return hist

    def _apply_case(finding_id: str, req, actor: str) -> dict:
        """Apply one case change, refusing anything the state machine rejects."""
        from vecshield_platform.cases import CaseState, assign, transition

        store = _require_history()
        current = store.get_case(finding_id)
        if current is None:
            raise HTTPException(status_code=404, detail=f"unknown finding: {finding_id}")
        state = CaseState(**current)
        try:
            if req.to_state:
                new_state, event = transition(
                    state, to_state=req.to_state, actor=actor, owner=req.owner,
                    reason=req.reason, verified_by_job_id=req.verified_by_job_id)
            elif req.owner:
                new_state, event = assign(state, owner=req.owner, actor=actor)
            else:
                raise HTTPException(
                    status_code=422,
                    detail="a case change sets a state, an owner, or both")
        except CaseTransitionError as e:
            # A refused transition is a 409: the request was well-formed, the
            # state machine simply does not allow it.
            raise HTTPException(status_code=409, detail=str(e)) from e
        store.save_case(new_state, event)
        log.append(actor, "finding_case_changed", finding_id,
                   {"from": event.from_state, "to": event.to_state,
                    "owner": event.owner, "reason": event.reason})
        return {**new_state.to_dict(), "events": store.case_events(finding_id)}

    @app.get("/admin/findings")
    def findings_query(
        store: Optional[str] = None,
        collection: Optional[str] = None,
        severity: Optional[str] = None,
        min_severity: Optional[str] = None,
        category: Optional[str] = None,
        case_state: Optional[str] = None,
        owner: Optional[str] = None,
        suppressed: Optional[bool] = None,
        search: Optional[str] = None,
        sort: str = "created_at",
        direction: str = "desc",
        limit: int = Query(default=50, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        scope: Literal["all", "latest"] = "all",
        actor: str = Depends(require_auth),
    ) -> dict:
        """Filter findings in the database and report the true total.

        The total is the count of everything matching, not the size of the page,
        so a filtered count is never silently taken over a capped fetch.

        ``scope=all`` (the default) is every finding every run recorded.
        ``scope=latest`` is distinct findings from each registered store's
        latest saved audit, one row per fingerprint: the same set the home
        summary counts, with every other filter applied on top.
        """
        store_ = _require_history()
        selection, extra = _findings_selection(store_, store, scope)
        try:
            return store_.query_findings(
                **selection, collection=collection, severity=severity,
                min_severity=min_severity, category=category, case_state=case_state,
                owner=owner, suppressed=suppressed, search=search, sort=sort,
                direction=direction, limit=limit, offset=offset) | extra
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e)) from e

    def _findings_selection(store_, store: Optional[str],
                            scope: str) -> tuple[dict[str, Any], dict[str, Any]]:
        """The store and audit narrowing shared by the findings list and export.

        Returns ``query_findings`` keyword arguments and the response fields
        that describe the scope.
        """
        from vecshield_platform.home import LATEST_FINDINGS_NOTE

        latest_ids = None
        extra: dict = {"scope": scope}
        if scope == "latest":
            registered = sorted(cfg.store_id for cfg in reg().list())
            latest = {sid: aid for sid, aid in store_.latest_audit_ids().items()
                      if sid in set(registered)}
            latest_ids = sorted(latest.values())
            extra.update({
                "stores_assessed": len(latest),
                "stores_never_assessed": len(registered) - len(latest),
                "note": LATEST_FINDINGS_NOTE,
            })
        # Callers filter by the id they see in the console; findings are stored
        # under the connector's reported name. Translate, and fall back to
        # treating the value as a raw store name when it is not a registered id.
        observed = store_.observed_store_names(store) if store else None
        if store and not observed:
            observed = [store]
        return ({"store": None if observed else store, "stores": observed or None,
                 "latest_audit_ids": latest_ids}, extra)

    @app.get("/admin/findings/export")
    def findings_export(
        format: Literal["csv", "json"] = "csv",
        store: Optional[str] = None,
        collection: Optional[str] = None,
        severity: Optional[str] = None,
        min_severity: Optional[str] = None,
        category: Optional[str] = None,
        case_state: Optional[str] = None,
        owner: Optional[str] = None,
        suppressed: Optional[bool] = None,
        search: Optional[str] = None,
        sort: str = "created_at",
        direction: str = "desc",
        scope: Literal["all", "latest"] = "all",
        actor: str = Depends(require_auth),
    ):
        """The findings the list shows under the same filters, as CSV or JSON.

        Every match up to FINDINGS_EXPORT_CAP rows, without the list's page
        size. Evidence (the captured examples) is never exported; a reveal is
        a separate, audited act. A capped export says so in its headers and,
        for JSON, in its body.
        """
        store_ = _require_history()
        selection, extra = _findings_selection(store_, store, scope)
        filters = {k: v for k, v in {
            "store": store, "collection": collection, "severity": severity,
            "min_severity": min_severity, "category": category,
            "case_state": case_state, "owner": owner, "suppressed": suppressed,
            "search": search, "scope": scope}.items() if v is not None}
        try:
            result = store_.query_findings(
                **selection, collection=collection, severity=severity,
                min_severity=min_severity, category=category, case_state=case_state,
                owner=owner, suppressed=suppressed, search=search, sort=sort,
                direction=direction, limit=FINDINGS_EXPORT_CAP, offset=0)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e)) from e
        # Saved audits link each registered id to the connector names its
        # findings were recorded under; a name no audit linked stays blank.
        store_ids: dict[str, str] = {}
        for cfg_ in sorted(reg().list(), key=lambda c: c.store_id):
            for name in [cfg_.store_id, *store_.observed_store_names(cfg_.store_id)]:
                store_ids.setdefault(name, cfg_.store_id)
        rows = [{"id": f.get("id"), "fingerprint": f.get("fingerprint"),
                 "severity": f.get("severity"), "category": f.get("category"),
                 "title": f.get("title"), "description": f.get("description"),
                 "store_id": store_ids.get(f.get("store") or ""),
                 "store": f.get("store"), "collection": f.get("collection"),
                 "case_state": (f.get("case") or {}).get("state"),
                 "case_owner": (f.get("case") or {}).get("owner"),
                 "suppressed": bool(f.get("suppressed")),
                 "created_at": f.get("created_at")}
                for f in result["findings"]]
        total = int(result["total"])
        truncated = total > len(rows)
        log.append(actor, "findings_exported", "findings",
                   {"format": format, "filters": filters, "rows": len(rows),
                    "total": total, "truncated": truncated})
        now = datetime.now(timezone.utc)
        headers = {"X-VecShield-Total": str(total),
                   "X-VecShield-Truncated": "true" if truncated else "false",
                   "Content-Disposition": (
                       f'attachment; filename="vecshield-findings-{now:%Y%m%d}.{format}"')}
        if format == "csv":
            from vecshield_platform.inventory import csv_cell

            buffer = io.StringIO()
            writer = csv.writer(buffer, lineterminator="\n")
            writer.writerow(FINDINGS_EXPORT_COLUMNS)
            for row in rows:
                writer.writerow([csv_cell(row[name]) for name in FINDINGS_EXPORT_COLUMNS])
            return Response(content=buffer.getvalue(),
                            media_type="text/csv; charset=utf-8", headers=headers)
        document = {"generated_at": now.isoformat(), "filters": filters, "total": total,
                    "exported": len(rows), "truncated": truncated,
                    **{k: v for k, v in extra.items() if k != "scope"},
                    "findings": rows}
        return Response(content=json.dumps(document, indent=2, sort_keys=True),
                        media_type="application/json", headers=headers)

    @app.get("/admin/findings/{finding_id}/case")
    def finding_case(finding_id: str, actor: str = Depends(require_auth)) -> dict:
        store = _require_history()
        current = store.get_case(finding_id)
        if current is None:
            raise HTTPException(status_code=404, detail=f"unknown finding: {finding_id}")
        from vecshield_platform.cases import ALLOWED_TRANSITIONS, CaseState
        state = CaseState(**current)
        return {**state.to_dict(),
                "events": store.case_events(finding_id),
                "allowed_transitions": list(ALLOWED_TRANSITIONS.get(state.state, ()))}

    @app.post("/admin/findings/{finding_id}/case")
    def finding_case_change(finding_id: str, req: CaseChangeRequest,
                            actor: str = Depends(require_compliance)) -> dict:
        return _apply_case(finding_id, req, actor)

    @app.post("/admin/findings/cases")
    def finding_cases_bulk(req: BulkCaseRequest,
                           actor: str = Depends(require_compliance)) -> dict:
        """Apply one change to many findings, reporting each outcome separately.

        Partial success is the norm here: a bulk move legitimately fails for the
        findings whose current state does not allow it, and saying which ones
        beats refusing the whole batch or pretending it all worked.
        """
        _require_history()
        applied, refused = [], []
        for finding_id in req.finding_ids:
            single = CaseChangeRequest(
                to_state=req.to_state, owner=req.owner, reason=req.reason,
                verified_by_job_id=req.verified_by_job_id)
            try:
                applied.append({"finding_id": finding_id,
                                "case": _apply_case(finding_id, single, actor)})
            except HTTPException as e:
                refused.append({"finding_id": finding_id, "reason": e.detail,
                                "status": e.status_code})
        return {"applied": len(applied), "refused": len(refused),
                "cases": applied, "refusals": refused,
                "ok": not refused}

    @app.get("/admin/findings/summary")
    def findings_case_summary(store: Optional[str] = None,
                              actor: str = Depends(require_auth)) -> dict:
        from vecshield_platform.cases import summarize

        store_ = _require_history()
        counts = store_.case_summary(store=store)
        states = [{"state": name} for name, count in counts.items() for _ in range(count)]
        return summarize(states)

    # Registered after /admin/findings/summary: a path parameter here would
    # otherwise swallow that literal segment.
    @app.get("/admin/findings/{finding_id}")
    def admin_finding(finding_id: str, actor: str = Depends(require_auth)) -> dict:
        """One finding with its evidence, case, and the events behind the case."""
        if hist is None:
            raise HTTPException(status_code=409, detail="scan history is not configured")
        finding = hist.get_finding(finding_id)
        if finding is None:
            raise HTTPException(status_code=404, detail=f"unknown finding: {finding_id}")
        events = hist.case_events(finding_id)
        related = []
        fingerprint = finding.get("fingerprint")
        if fingerprint:
            related = [{"id": f["id"], "job_id": f.get("job_id"), "created_at": f.get("created_at"),
                        "severity": f.get("severity"), "case": f.get("case")}
                       for f in hist.findings_by_fingerprint(fingerprint)
                       if f.get("id") != finding_id]
        return {"finding": finding, "case_events": events, "same_fingerprint": related}

    # ---------------- history ----------------

    @app.get("/admin/history")
    def history(
        store: Optional[str] = None,
        limit: int = Query(default=50, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        actor: str = Depends(require_auth),
    ) -> dict:
        if hist is None:
            return {"jobs": [], "stats": {}, "available": False,
                    "message": "history disabled (no scan_history configured)"}
        jobs = hist.list_jobs(store=store, limit=limit + 1, offset=offset)
        return {"jobs": jobs[:limit], "stats": hist.stats(), "available": True,
                "has_more": len(jobs) > limit,
                "next_offset": offset + limit if len(jobs) > limit else None}

    @app.get("/admin/history/audits")
    def history_audits(store_id: Optional[str] = None,
                       limit: int = Query(default=50, ge=1, le=500),
                       offset: int = Query(default=0, ge=0),
                       actor: str = Depends(require_auth)) -> dict:
        if hist is None:
            return {"audits": [], "available": False, "has_more": False,
                    "next_offset": None}
        audits = hist.list_audits(store_id=store_id, limit=limit + 1, offset=offset)
        return {"audits": audits[:limit], "available": True,
                "has_more": len(audits) > limit,
                "next_offset": offset + limit if len(audits) > limit else None}

    @app.get("/admin/history/audits/{audit_id}")
    def history_audit(audit_id: str, actor: str = Depends(require_auth)) -> dict:
        if hist is None:
            raise HTTPException(status_code=409, detail="history not configured")
        snapshot = hist.get_audit(audit_id)
        if snapshot is None:
            raise HTTPException(status_code=404, detail="audit snapshot not found")
        return snapshot

    # NB: /admin/history/trend must be registered before /admin/history/{job_id}
    # or FastAPI matches "trend" as a job_id and the endpoint is unreachable.
    @app.get("/admin/history/trend")
    def history_trend(
        store: Optional[str] = None,
        days: int = Query(default=30, ge=1, le=3650),
        actor: str = Depends(require_auth),
    ) -> dict:
        note = ("Findings recorded per store per day, counted across every run that "
                "day and including suppressed ones: re-running a scan counts its "
                "findings again. These are not distinct open findings; the Overview "
                "and the Findings list's \"Open now\" view report those.")
        if hist is None:
            return {"trend": [], "available": False, "note": note}
        return {"trend": hist.severity_trend(store=store, days=days), "available": True,
                "note": note}

    @app.get("/admin/history/{job_id}")
    def history_job(job_id: str,
                     limit: int = Query(default=200, ge=1, le=1000),
                     offset: int = Query(default=0, ge=0),
                     actor: str = Depends(require_auth)) -> dict:
        if hist is None:
            raise HTTPException(status_code=409, detail="history not configured")
        job = hist.get_job(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="job not found")
        findings = hist.list_findings(job_id=job_id, limit=limit + 1, offset=offset)
        return {**job, "findings": findings[:limit], "has_more": len(findings) > limit,
                "next_offset": offset + limit if len(findings) > limit else None}

    # ---------------- async jobs ----------------

    #: Background jobs whose resource, result or error can name a DSAR or
    #: erasure subject (F3). Callers without the compliance role see that the
    #: job exists and how it went, not what it was about.
    _SUBJECT_JOB_KINDS = frozenset({"dsar_create", "dsar_execute", "erasure_execute"})

    def _visible_job(job: dict, principal: "Principal") -> dict:
        if job.get("kind") not in _SUBJECT_JOB_KINDS or principal.has_role(COMPLIANCE):
            return job
        # A DSAR job's resource was the raw subject before F3; a store id
        # (erasure) is not sensitive and stays visible.
        resource = job.get("resource")
        if job.get("kind") == "dsar_create" and resource:
            resource = "(restricted)"
        return {**job, "resource": resource,
                "result": None,
                "error": "(restricted)" if job.get("error") else None,
                "restricted": True,
                "restricted_reason": "DSAR and erasure job details need the compliance role."}

    @app.get("/admin/jobs")
    def list_jobs_endpoint(
        kind: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
        principal: "Principal" = Depends(require_principal),
    ) -> dict:
        """Background jobs, newest first.

        Each ``result`` is summarized to ``{"id": ...}``, the record the run
        saved; a full result can be a whole audit. ``GET /admin/jobs/{id}``
        returns it in full.
        """
        return {"jobs": [_visible_job(j, principal) for j in
                         jobs.list(kind=kind, status=status, limit=limit, offset=offset,
                                   summary=True)]}

    @app.get("/admin/jobs/{job_id}")
    def get_job_endpoint(job_id: str,
                         principal: "Principal" = Depends(require_principal)) -> dict:
        job = jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="job not found")
        return _visible_job(job, principal)

    # ---------------- live runtime monitor (improvement plan 1.5) ----------

    @app.post("/runtime/events")
    def ingest_runtime_event(req: RuntimeEventRequest,
                             actor: str = Depends(require_operator)) -> dict:
        """Forward a client-observed similarity query to the live monitor.

        Runs the event through the detector engine synchronously; any alerts it
        emits are persisted and dispatched to configured sinks. Returns the
        alerts raised by *this* event (usually none until a threshold trips)."""
        from vecshield_platform.runtime.events import QueryEvent

        event = QueryEvent(
            principal=req.principal,
            collection=req.collection,
            timestamp=req.timestamp if req.timestamp is not None else time.time(),
            query_vector=req.query_vector,
            result_ids=req.result_ids,
            result_count=req.result_count or 0,
            metadata=req.metadata,
        )
        alerts = app.state.runtime_engine.process(event)
        if alerts:
            log.append(actor, "runtime_alert", req.collection,
                       {"principal": req.principal,
                        "rules": [a.rule for a in alerts]})
        return {"processed": 1, "alerts": [a.to_dict() for a in alerts]}

    @app.get("/runtime/alerts")
    def list_runtime_alerts(
        severity: Optional[str] = None,
        rule: Optional[str] = None,
        principal: Optional[str] = None,
        since: Optional[float] = None,
        limit: int = Query(200, ge=1, le=1000),
        offset: int = Query(0, ge=0),
        actor: str = Depends(require_auth),
    ) -> dict:
        """List persisted runtime alerts, most recent first, with filters."""
        alerts = app.state.alert_store.list_alerts(
            severity=severity, rule=rule, principal=principal, since=since,
            limit=limit, offset=offset)
        return {"alerts": alerts}

    @app.get("/runtime/alerts/stats")
    def runtime_alert_stats(actor: str = Depends(require_auth)) -> dict:
        """Summary counts (total, by severity, by rule) for the alerts panel."""
        return app.state.alert_store.stats()

    @app.get("/runtime/alerts/{alert_id}")
    def get_runtime_alert(alert_id: str,
                          actor: str = Depends(require_auth)) -> dict:
        alert = app.state.alert_store.get_alert(alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="alert not found")
        return alert

    app.state.audit_log = log
    app.state.scan_history = hist
    app.state.jobs = jobs

    # ================================================================== #
    # Store controls: vulnerability feed, retention schedules, residency   #
    # policy, processor register, inventory, source manifests, CCPA risk.  #
    # Settings writes are admin-only and audit-logged before they apply;    #
    # per-store declarations and manifests are operator inputs; CCPA        #
    # inputs and approval are compliance artefacts.                         #
    # ================================================================== #
    from fastapi import Body
    from vecshield_platform.api.config_store import SettingsError, canonical_hash
    import threading

    from vecshield_platform.api.feed_scheduler import (
        EGRESS_HOSTS,
        SCHEDULE_LOCK,
        FeedScheduler,
        refresh_preserving_settings,
    )

    app.state.state_dir = state_dir
    #: Manual refreshes are rate-limited; the scheduler shares the lock.
    _FEED_REFRESH_MIN_INTERVAL_S = 600.0
    _feed_refresh: dict[str, Optional[float]] = {"last": None}
    _feed_lock = threading.Lock()

    def _utcnow_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _settings_problems(e: Exception) -> HTTPException:
        problems = getattr(e, "problems", None) or [str(e)]
        return HTTPException(status_code=422, detail={"problems": problems})

    def _known_store_ids() -> set[str]:
        return {c.store_id for c in reg().list()}

    def _feed_credentials() -> dict:
        """GitHub/NVD tokens for a refresh, resolved at call time; never returned."""
        from vecshield_platform.api.secrets import SecretResolutionError, resolve_conn

        refs = (app.state.config.get_vulnfeed_credentials()
                if app.state.config is not None else {})
        try:
            resolved = resolve_conn(refs) if refs else {}
        except SecretResolutionError as e:
            import logging
            logging.getLogger(__name__).warning(
                "vulnfeed credential reference unavailable: %s", type(e).__name__)
            resolved = {}
        return {
            "github_token": (resolved.get("github_token")
                             or os.environ.get("VECSHIELD_GITHUB_TOKEN") or None),
            "nvd_api_key": (resolved.get("nvd_api_key")
                            or os.environ.get("VECSHIELD_NVD_API_KEY") or None),
        }

    def _credential_status() -> dict:
        refs = (app.state.config.get_vulnfeed_credentials()
                if app.state.config is not None else {})
        out = {}
        for name, env in (("github_token", "VECSHIELD_GITHUB_TOKEN"),
                          ("nvd_api_key", "VECSHIELD_NVD_API_KEY")):
            kinds = [k.rsplit("_", 1)[1] for k in refs if k.startswith(name + "_")]
            source = ("reference" if kinds else
                      "environment" if os.environ.get(env) else None)
            out[name] = {"configured": source is not None, "source": source,
                         "reference_kind": kinds[0] if kinds else None}
        return out

    def _require_state_dir() -> str:
        if not state_dir:
            raise HTTPException(
                status_code=409,
                detail=("the server has no state directory, so the advisory feed "
                        "cannot be stored or refreshed; start it with --state-dir"))
        return str(state_dir)

    def _feed_summary(settings, result) -> dict:
        return {"ok": getattr(result, "ok", None) if result is not None else None,
                "feed_hash": getattr(result, "feed_hash", None),
                "updated_at": getattr(result, "updated_at", None),
                "sources_failed": sorted(k for k, v in (getattr(result, "sources", None)
                                                        or {}).items() if not v.get("ok")),
                "last_error": settings.last_error,
                "last_success": settings.last_success}

    def _log_auto_refresh(settings, result) -> None:
        try:
            log.append("system", "vulnfeed_auto_refreshed", "vulnfeed",
                       _feed_summary(settings, result))
        except Exception:  # noqa: BLE001 - the scheduler must keep running
            import logging
            logging.getLogger(__name__).warning("could not audit-log a feed refresh")

    _scheduler_env = os.environ.get("VECSHIELD_VULNFEED_SCHEDULER", "").strip().lower()
    if vulnfeed_scheduler and state_dir and _scheduler_env not in {"0", "off", "false", "no"}:
        _feed_scheduler = FeedScheduler(state_dir, credentials=_feed_credentials,
                                        on_refresh=_log_auto_refresh, lock=_feed_lock)
        _feed_scheduler.start()
        app.router.on_shutdown.append(_feed_scheduler.stop)
        app.state.feed_scheduler = _feed_scheduler
    else:
        app.state.feed_scheduler = None

    @app.get("/admin/vulnfeed")
    def vulnfeed_status(actor: str = Depends(require_auth)) -> dict:
        """Which advisory feed audits use, how old it is, and its auto-update settings."""
        from vecshield_platform.posture import server_vulns, vulnfeed

        now = datetime.now(timezone.utc)
        feed = vulnfeed.load_feed(state_dir)
        schedule = vulnfeed.load_schedule(state_dir) if state_dir else vulnfeed.FeedSchedule()
        last = _feed_refresh["last"]
        next_allowed = (None if last is None else datetime.fromtimestamp(
            last + _FEED_REFRESH_MIN_INTERVAL_S, timezone.utc).isoformat())
        scheduler = app.state.feed_scheduler
        return {
            "feed": feed.status(now),
            "schedule": schedule.to_dict(),
            "due": vulnfeed.due(schedule, now),
            "state_dir_configured": bool(state_dir),
            "scheduler_running": bool(scheduler and scheduler.running),
            "credentials": _credential_status(),
            "egress_hosts": list(EGRESS_HOSTS),
            "limits": {"min_interval_hours": vulnfeed.MIN_INTERVAL_HOURS,
                       "stale_after_days": server_vulns.DEFAULT_STALE_AFTER_DAYS,
                       "max_age_days": server_vulns.DEFAULT_MAX_AGE_DAYS,
                       "manual_refresh_min_interval_s": _FEED_REFRESH_MIN_INTERVAL_S},
            "manual_refresh_next_allowed_at": next_allowed,
        }

    @app.put("/admin/vulnfeed/settings")
    def vulnfeed_settings(payload: dict[str, Any] = Body(...),
                          actor: str = Depends(require_admin)) -> dict:
        """Auto-update on/off and interval; optional token *references*.

        Turning auto-update on is the admin's consent to outbound requests to
        the hosts in ``egress_hosts``; the audit entry records it.
        """
        from vecshield_platform.posture import vulnfeed

        directory = _require_state_dir()
        problems: list[str] = []
        unknown = sorted(set(payload) - {"auto_update", "interval_hours", "credentials"})
        if unknown:
            problems.append(f"unknown fields: {', '.join(unknown)}")
        auto = payload.get("auto_update")
        if auto is not None and not isinstance(auto, bool):
            problems.append("auto_update must be true or false")
        hours = payload.get("interval_hours")
        if hours is not None and (not isinstance(hours, int) or isinstance(hours, bool)
                                  or hours < vulnfeed.MIN_INTERVAL_HOURS or hours > 24 * 31):
            problems.append(f"interval_hours must be a whole number from "
                            f"{vulnfeed.MIN_INTERVAL_HOURS} to {24 * 31}")
        creds = payload.get("credentials")
        if creds is not None:
            if app.state.config is None:
                problems.append("credentials need a config store")
            else:
                from vecshield_platform.api.config_store import validate_vulnfeed_credentials
                _, found = validate_vulnfeed_credentials(creds)
                problems.extend(found)
        if problems:
            raise HTTPException(status_code=422, detail={"problems": problems})
        with SCHEDULE_LOCK:
            current = vulnfeed.load_schedule(directory)
            new = vulnfeed.FeedSchedule.from_dict({
                **current.to_dict(),
                **({"auto_update": auto} if auto is not None else {}),
                **({"interval_hours": hours} if hours is not None else {})})
            details: dict[str, Any] = {"auto_update": new.auto_update,
                                       "interval_hours": new.interval_hours,
                       "previous_auto_update": current.auto_update}
            if new.auto_update and not current.auto_update:
                details["egress_consent"] = {
                    "granted_by": actor, "hosts": list(EGRESS_HOSTS),
                    "statement": "Admin enabled scheduled outbound requests to public "
                                 "advisory sources; no customer data is sent."}
            if creds is not None:
                details["credential_references"] = sorted(
                    k for k, v in creds.items() if v)
            _log_intent(actor, "vulnfeed_settings_updated", "vulnfeed", details,
                        refused="the feed settings were not changed")
            if creds is not None:
                try:
                    app.state.config.set_vulnfeed_credentials(creds)
                except SettingsError as e:
                    raise _settings_problems(e)
            vulnfeed.save_schedule(directory, new)
        return {"schedule": new.to_dict(), "credentials": _credential_status()}

    @app.post("/admin/vulnfeed/refresh", status_code=202)
    def vulnfeed_refresh(actor: str = Depends(require_admin)):
        """Refresh the advisory feed now, as a background job (202 + job id)."""
        directory = _require_state_dir()
        now = time.monotonic()
        last = _feed_refresh["last"]
        if last is not None and now - last < _FEED_REFRESH_MIN_INTERVAL_S:
            retry = int(_FEED_REFRESH_MIN_INTERVAL_S - (now - last)) + 1
            raise HTTPException(
                status_code=429, headers={"Retry-After": str(retry)},
                detail=(f"the advisory feed was refreshed less than "
                        f"{int(_FEED_REFRESH_MIN_INTERVAL_S // 60)} minutes ago; "
                        f"try again in {retry} s"))
        _log_intent(actor, "vulnfeed_refresh_requested", "vulnfeed",
                    {"hosts": list(EGRESS_HOSTS)},
                    refused="the feed was not refreshed")
        _feed_refresh["last"] = now

        def _work() -> dict:
            with _feed_lock:
                settings, result = refresh_preserving_settings(
                    directory, force=True, **_feed_credentials())
            summary = _feed_summary(settings, result)
            try:
                log.append(actor, "vulnfeed_refreshed", "vulnfeed", summary)
            except Exception:  # noqa: BLE001 - the job result still reports it
                summary["audit_entry"] = "not written"
            return summary

        job_id = jobs.submit("vulnfeed_refresh", _work, actor=actor, resource="vulnfeed")
        return JSONResponse(status_code=202, content={"job_id": job_id, "status": "queued",
                                                      "kind": "vulnfeed_refresh"})

    # ---------------- retention schedules ----------------

    @app.get("/admin/retention-schedules")
    def get_retention_schedules(actor: str = Depends(require_auth)) -> dict:
        cfg = app.state.config
        doc = cfg.get_retention_schedules() if cfg is not None else {"global": None,
                                                                      "stores": {}}
        return {**doc, "semantics": "a store entry replaces the global schedule"}

    @app.put("/admin/retention-schedules")
    def put_retention_schedules(payload: dict[str, Any] = Body(...),
                                actor: str = Depends(require_admin)) -> dict:
        from vecshield_platform.api.config_store import validate_retention_document

        cfg = _require_config()
        value, problems = validate_retention_document(
            payload, store_ids=_known_store_ids() | set(cfg.stores))
        if problems:
            raise HTTPException(status_code=422, detail={"problems": problems})
        _log_intent(actor, "retention_schedules_updated", "retention_schedules",
                    {"global_declared": value["global"] is not None,
                     "store_overrides": sorted(value["stores"]),
                     "hash": canonical_hash(value)},
                    refused="the retention schedules were not changed")
        try:
            saved = cfg.set_retention_schedules(value, known_stores=_known_store_ids())
        except SettingsError as e:
            raise _settings_problems(e)
        return {**saved, "semantics": "a store entry replaces the global schedule"}

    @app.get("/admin/retention-schedules/categories")
    def retention_categories(actor: str = Depends(require_auth)) -> dict:
        from vecshield_platform.compliance.data import load_references
        from vecshield_platform.scan.retention_schedule import CLOCKS, category_catalog

        return {"categories": category_catalog(), "clocks": list(CLOCKS),
                "references": load_references("retention")}

    # ---------------- residency policy, processors, providers ----------------

    @app.get("/admin/residency-policy")
    def get_residency_policy(actor: str = Depends(require_auth)) -> dict:
        from vecshield_platform.api.config_store import RESIDENCY_REGIMES

        cfg = app.state.config
        doc = cfg.get_residency_policy() if cfg is not None else {"default": None,
                                                                  "stores": {}}
        return {**doc, "regimes": list(RESIDENCY_REGIMES),
                "adequacy_evaluated_for": ["GDPR", "UK_GDPR"]}

    @app.put("/admin/residency-policy")
    def put_residency_policy(payload: dict[str, Any] = Body(...),
                             actor: str = Depends(require_admin)) -> dict:
        from vecshield_platform.api.config_store import validate_residency_document

        cfg = _require_config()
        value, problems = validate_residency_document(
            payload, store_ids=_known_store_ids() | set(cfg.stores))
        if problems:
            raise HTTPException(status_code=422, detail={"problems": problems})
        _log_intent(actor, "residency_policy_updated", "residency_policy",
                    {"default_declared": value["default"] is not None,
                     "store_overrides": sorted(value["stores"]),
                     "hash": canonical_hash(value)},
                    refused="the residency policy was not changed")
        try:
            return cfg.set_residency_policy(value, known_stores=_known_store_ids())
        except SettingsError as e:
            raise _settings_problems(e)

    @app.get("/admin/processor-register")
    def get_processor_register(actor: str = Depends(require_auth)) -> dict:
        cfg = app.state.config
        return {"processors": cfg.get_processor_register() if cfg is not None else []}

    @app.put("/admin/processor-register")
    def put_processor_register(payload: dict[str, Any] = Body(...),
                               actor: str = Depends(require_admin)) -> dict:
        from vecshield_platform.api.config_store import validate_processor_register

        cfg = _require_config()
        unknown = sorted(set(payload) - {"processors"})
        if unknown:
            raise HTTPException(status_code=422, detail={
                "problems": [f"unknown fields: {', '.join(unknown)}"]})
        value, problems = validate_processor_register(payload.get("processors"))
        if problems:
            raise HTTPException(status_code=422, detail={"problems": problems})
        _log_intent(actor, "processor_register_updated", "processor_register",
                    {"entries": len(value),
                     "providers": sorted(e["provider"] for e in value),
                     "hash": canonical_hash(value)},
                    refused="the processor register was not changed")
        try:
            return {"processors": cfg.set_processor_register(value)}
        except SettingsError as e:
            raise _settings_problems(e)

    @app.get("/admin/model-providers")
    def model_providers(actor: str = Depends(require_auth)) -> dict:
        """The model-provider registry processor entries are checked against."""
        from vecshield_platform.posture.egress import provider_registry

        registry = provider_registry()
        providers = [{"id": pid, **{k: entry.get(k) for k in (
            "display_name", "operator", "class", "training_use", "retention")}}
            for pid, entry in registry["providers"].items() if pid != "unknown"]
        return {"providers": providers, "aliases": registry.get("aliases") or {},
                "as_of": registry.get("_as_of"),
                "other": "use 'other:<name>' for a provider not in the registry"}

    # ---------------- inventory ----------------

    def _require_hist():
        if hist is None:
            raise HTTPException(status_code=409,
                                detail="the inventory requires scan history")
        return hist

    def _declarations_for(store_id: str) -> Optional[dict]:
        if app.state.config is None:
            return None
        return app.state.config.get_inventory_declarations(store_id)

    def _served_inventory(store_id: str, inventory: dict) -> dict:
        from vecshield_platform.api.config_store import merge_declarations

        inv = dict(inventory)
        inv["store"] = {**(inv.get("store") or {})}
        if not inv["store"].get("id"):
            inv["store"]["id"] = store_id
        merged = merge_declarations(inv, _declarations_for(store_id))
        assert merged is not None
        return merged

    def _latest_inventory(store_id: str, audit_id: Optional[str] = None
                          ) -> tuple[Optional[dict], Optional[dict], str]:
        """(snapshot, inventory, reason) — reason explains a missing inventory."""
        from vecshield_platform.drift import inventory_of

        history = _require_hist()
        if audit_id:
            snap = history.get_audit(audit_id)
            if snap is None or snap.get("store_id") not in (None, store_id):
                raise HTTPException(status_code=404,
                                    detail=f"no saved audit '{audit_id}' for store '{store_id}'")
            inv = inventory_of(snap)
            return snap, inv, ("" if inv is not None else
                               "this audit carries no inventory (an earlier version ran "
                               "it, or the store could not be described)")
        listed = history.list_audits(store_id=store_id, limit=20)
        if not listed:
            return None, None, NO_SAVED_AUDIT_DETAIL
        for row in listed:
            snap = history.get_audit(row["id"])
            inv = inventory_of(snap)
            if inv is not None:
                return snap, inv, ""
        return None, None, ("none of this store's recent audits carries an inventory "
                            "(they predate it, or the store could not be described); "
                            "an operator must run a new audit")

    @app.get("/stores/{store_id}/inventory")
    def store_inventory(store_id: str, audit_id: Optional[str] = None,
                        actor: str = Depends(require_auth)) -> dict:
        _assert_store(store_id)
        snap, inv, reason = _latest_inventory(store_id, audit_id)
        if inv is None or snap is None:
            raise HTTPException(status_code=404, detail=reason)
        return {"store_id": store_id, "audit_id": snap.get("id"),
                "audited_at": snap.get("finished_at") or snap.get("started_at"),
                "inventory": _served_inventory(store_id, inv)}

    @app.get("/stores/{store_id}/inventory/changes")
    def store_inventory_changes(store_id: str, actor: str = Depends(require_auth)) -> dict:
        from vecshield_platform.drift import diff_inventories, latest_inventory_pair

        _assert_store(store_id)
        before, after = latest_inventory_pair(_require_hist(), store_id)
        if after is None:
            raise HTTPException(status_code=404, detail=(
                "no saved audit for this store carries an inventory; an operator "
                "must run one"))
        return {"store_id": store_id, **diff_inventories(before, after)}

    @app.get("/stores/{store_id}/changes")
    def store_changes(store_id: str, actor: str = Depends(require_auth)) -> dict:
        """Findings that are new, resolved or not re-tested since the previous audit.

        ``compared`` is false when there are fewer than two saved audits: with
        nothing to compare against, an empty list would read as "no changes".
        """
        from vecshield_platform.drift import NOTE, finding_changes, latest_pair

        _assert_store(store_id)
        before, after = latest_pair(_require_hist(), store_id)

        def when(snap: Optional[dict]) -> Optional[str]:
            return (snap or {}).get("finished_at") or (snap or {}).get("started_at")

        if after is None or before is None:
            return {"store_id": store_id, "compared": False,
                    "reason": ("this store has no saved audit; an operator must run one"
                               if after is None else
                               "this store has one saved audit; the next audit will be "
                               "compared with it"),
                    "after_audit_id": (after or {}).get("id"), "after_at": when(after),
                    "note": NOTE}
        return {"store_id": store_id, "compared": True,
                "before_at": when(before), "after_at": when(after),
                **finding_changes(before, after)}

    @app.get("/admin/inventory/export")
    def inventory_export(format: Literal["csv", "json"] = "json",
                         actor: str = Depends(require_auth)):
        """Every registered store's latest inventory, as CSV or JSON."""
        from vecshield_platform.inventory import inventory_to_csv, inventory_to_json

        _require_hist()
        inventories, missing = [], []
        for cfg in sorted(reg().list(), key=lambda c: c.store_id):
            _, inv, reason = _latest_inventory(cfg.store_id)
            if inv is None:
                missing.append({"store_id": cfg.store_id, "reason": reason})
            else:
                inventories.append(_served_inventory(cfg.store_id, inv))
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
        log.append(actor, "inventory_exported", "estate",
                   {"format": format, "stores": len(inventories),
                    "stores_without_inventory": len(missing)})
        headers = {"X-VecShield-Stores-Without-Inventory": str(len(missing))}
        if format == "csv":
            headers["Content-Disposition"] = (
                f'attachment; filename="vecshield-inventory-{stamp}.csv"')
            return Response(content=inventory_to_csv(inventories),
                            media_type="text/csv; charset=utf-8", headers=headers)
        document = json.loads(inventory_to_json(inventories))
        document["stores_without_inventory"] = missing
        headers["Content-Disposition"] = (
            f'attachment; filename="vecshield-inventory-{stamp}.json"')
        return Response(content=json.dumps(document, indent=2, sort_keys=True),
                        media_type="application/json", headers=headers)

    @app.get("/stores/{store_id}/inventory/declarations")
    def get_inventory_declarations(store_id: str,
                                   actor: str = Depends(require_auth)) -> dict:
        from vecshield_platform.inventory import (COLLECTION_DECLARED_FIELDS,
                                                    STORE_DECLARED_FIELDS)

        _assert_store(store_id)
        found = _declarations_for(store_id) or {"store": {}, "collections": {}}
        return {"store_id": store_id, **found,
                "fields": {"store": list(STORE_DECLARED_FIELDS),
                           "collection": list(COLLECTION_DECLARED_FIELDS)}}

    @app.put("/stores/{store_id}/inventory/declarations")
    def put_inventory_declarations(store_id: str, payload: dict[str, Any] = Body(...),
                                   actor: str = Depends(require_operator)) -> dict:
        """Owner, business purpose, RTO, support contact and expiry (replaces)."""
        from vecshield_platform.api.config_store import validate_declarations

        _assert_store(store_id)
        cfg = _require_config()
        value, problems = validate_declarations(payload)
        if problems:
            raise HTTPException(status_code=422, detail={"problems": problems})
        _log_intent(actor, "inventory_declarations_updated", store_id,
                    {"store_fields": sorted(value["store"]),
                     "collections": len(value["collections"]),
                     "hash": canonical_hash(value)},
                    refused="the declarations were not saved")
        try:
            saved = cfg.set_inventory_declarations(store_id, value, actor=actor,
                                                   now=_utcnow_iso())
        except SettingsError as e:
            raise _settings_problems(e)
        return {"store_id": store_id, **saved}

    # ---------------- source manifest (chunk-versions check) ----------------

    def _manifest_view(store_id: str, stored: Optional[dict]) -> dict:
        if stored is None:
            return {"store_id": store_id, "supplied": False, "entries": [], "count": 0}
        return {"store_id": store_id, "supplied": True, "count": len(stored["entries"]),
                **stored}

    @app.get("/stores/{store_id}/source-manifest")
    def get_source_manifest(store_id: str, actor: str = Depends(require_operator)) -> dict:
        _assert_store(store_id)
        cfg = app.state.config
        return _manifest_view(store_id, cfg.get_source_manifest(store_id)
                              if cfg is not None else None)

    @app.put("/stores/{store_id}/source-manifest")
    def put_source_manifest(store_id: str, payload: Any = Body(...),
                            actor: str = Depends(require_operator)) -> dict:
        """The current version of every source document, for outdated-chunk detection."""
        from vecshield_platform.api.config_store import validate_source_manifest

        _assert_store(store_id)
        cfg = _require_config()
        entries, problems = validate_source_manifest(payload)
        if problems or entries is None:
            raise HTTPException(status_code=422, detail={
                "problems": problems or ["a manifest is required; DELETE clears it"]})
        _log_intent(actor, "source_manifest_updated", store_id,
                    {"entries": len(entries), "hash": canonical_hash(entries)},
                    refused="the manifest was not saved")
        try:
            saved = cfg.set_source_manifest(store_id, entries, actor=actor,
                                            now=_utcnow_iso())
        except SettingsError as e:
            raise _settings_problems(e)
        return _manifest_view(store_id, saved)

    @app.delete("/stores/{store_id}/source-manifest")
    def delete_source_manifest(store_id: str, actor: str = Depends(require_operator)) -> dict:
        _assert_store(store_id)
        cfg = _require_config()
        _log_intent(actor, "source_manifest_cleared", store_id, {},
                    refused="the manifest was not cleared")
        cfg.set_source_manifest(store_id, None, actor=actor, now=_utcnow_iso())
        return _manifest_view(store_id, None)

    # ---------------- CCPA risk assessment (11 CCR §§ 7150-7157) ----------------

    def _ccpa_state(store_id: str) -> dict:
        """Latest inputs version, its approval (if any) and the full history."""
        cfg = app.state.config
        record = cfg.ccpa_record(store_id) if cfg is not None else {"versions": [],
                                                                     "approvals": []}
        versions, approvals = record["versions"], record["approvals"]
        latest = versions[-1] if versions else None
        approval = None
        if latest is not None:
            approval = next((a for a in reversed(approvals)
                             if a["version"] == latest["version"]), None)
        return {"latest": latest, "approval": approval, "versions": versions,
                "approvals": approvals}

    @app.get("/stores/{store_id}/ccpa-risk-assessment")
    def ccpa_risk_assessment(store_id: str, audit_id: Optional[str] = None,
                             format: Literal["json", "html"] = "json",
                             actor: str = Depends(require_auth)):
        """Prefilled § 7152(a) workbook from a saved audit. Never scans; no raw values."""
        from vecshield_platform.compliance.ccpa_risk import (build_ccpa_risk_html,
                                                               prefill_ccpa_risk_assessment)
        from vecshield_platform.drift import inventory_of

        _assert_store(store_id)
        history = _require_hist()
        snapshot = (history.get_audit(audit_id) if audit_id
                    else _latest_audit_snapshot(store_id))
        if snapshot is None:
            raise HTTPException(status_code=404, detail=(
                f"no saved audit '{audit_id}'" if audit_id else NO_SAVED_AUDIT_DETAIL))
        if audit_id and snapshot.get("store_id") not in (None, store_id):
            raise HTTPException(status_code=404,
                                detail=f"audit '{audit_id}' is not from store '{store_id}'")
        inv = inventory_of(snapshot)
        inventory = _served_inventory(store_id, inv) if inv is not None else None
        state = _ccpa_state(store_id)
        inputs = dict((state["latest"] or {}).get("inputs") or {})
        approval = state["approval"]
        if approval is not None:
            approver = {"name": approval["approved_by"]}
            if approval.get("position"):
                approver["position"] = approval["position"]
            inputs["review_and_approval"] = {"date": approval["approved_at"][:10],
                                             "approvers": [approver]}
        assessment = prefill_ccpa_risk_assessment(snapshot, inventory=inventory,
                                                  business_inputs=inputs, store=store_id)
        if format == "html":
            log.append(actor, "ccpa_risk_assessment_downloaded", store_id,
                       {"audit_id": snapshot.get("id"),
                        "inputs_version": (state["latest"] or {}).get("version")})
            return HTMLResponse(build_ccpa_risk_html(assessment))
        return {**assessment.to_dict(),
                "inputs_version": (state["latest"] or {}).get("version"),
                "approval": approval,
                "approval_current": approval is not None}

    @app.get("/stores/{store_id}/ccpa-risk-assessment/inputs")
    def ccpa_risk_inputs(store_id: str, actor: str = Depends(require_auth)) -> dict:
        _assert_store(store_id)
        state = _ccpa_state(store_id)
        return {"store_id": store_id, "latest": state["latest"],
                "approval": state["approval"], "versions": state["versions"],
                "approvals": state["approvals"]}

    @app.put("/stores/{store_id}/ccpa-risk-assessment/inputs")
    def put_ccpa_risk_inputs(store_id: str, payload: dict[str, Any] = Body(...),
                             actor: str = Depends(require_compliance)) -> dict:
        """Save a new version of the business's inputs; earlier versions are kept."""
        from vecshield_platform.compliance.ccpa_risk import validate_business_inputs

        _assert_store(store_id)
        cfg = _require_config()
        if "review_and_approval" in payload:
            raise HTTPException(status_code=422, detail={"problems": [
                "review_and_approval is recorded by POST .../ccpa-risk-assessment/approve, "
                "not by editing the inputs"]})
        clean, problems = validate_business_inputs(payload)
        if problems:
            raise HTTPException(status_code=422, detail={"problems": problems})
        _log_intent(actor, "ccpa_risk_inputs_saved", store_id,
                    {"keys": sorted(clean), "hash": canonical_hash(clean)},
                    refused="the inputs were not saved")
        try:
            entry = cfg.add_ccpa_inputs(store_id, clean, actor=actor, now=_utcnow_iso())
        except SettingsError as e:
            raise _settings_problems(e)
        return {"store_id": store_id, **entry, "approval_current": False}

    @app.post("/stores/{store_id}/ccpa-risk-assessment/approve")
    def approve_ccpa_risk(store_id: str, payload: dict[str, Any] = Body(default={}),
                          principal: "Principal" = Depends(require_compliance_principal)
                          ) -> dict:
        """Record who approved which inputs version, and when (§ 7152(a)(9))."""
        actor = principal.subject
        _assert_store(store_id)
        cfg = _require_config()
        unknown = sorted(set(payload) - {"version", "note", "position"})
        if unknown:
            raise HTTPException(status_code=422, detail={
                "problems": [f"unknown fields: {', '.join(unknown)}"]})
        state = _ccpa_state(store_id)
        if state["latest"] is None:
            raise HTTPException(status_code=409, detail=(
                "no business inputs have been saved for this store; save them before "
                "approving"))
        version = payload.get("version", state["latest"]["version"])
        if not isinstance(version, int) or isinstance(version, bool):
            raise HTTPException(status_code=422, detail={"problems": [
                "version must be a whole number"]})
        if version != state["latest"]["version"]:
            raise HTTPException(status_code=409, detail=(
                f"version {version} is not the latest inputs version "
                f"({state['latest']['version']}); only the current inputs can be approved"))
        if state["approval"] is not None:
            raise HTTPException(status_code=409, detail=(
                f"version {version} is already approved by "
                f"{state['approval']['approved_by']}"))
        note = payload.get("note") or ""
        position = payload.get("position") or ""
        if not isinstance(note, str) or not isinstance(position, str) \
                or len(note) > 2000 or len(position) > 200:
            raise HTTPException(status_code=422, detail={"problems": [
                "note (≤2000) and position (≤200) must be text"]})
        saved_by = state["latest"].get("saved_by")
        self_approved = saved_by == actor
        if self_approved and not _separation.allows_self_approval(principal.roles):
            raise HTTPException(status_code=409, detail=(
                "the inputs are approved by someone other than the person who saved "
                "them. " + _separation.refusal(proposer=actor,
                                               what="these risk-assessment inputs")))
        _log_intent(actor, "ccpa_risk_approved", store_id,
                    {"version": version, "inputs_hash": state["latest"]["hash"],
                     "self_approved": self_approved,
                     "separation_of_duties": _separation.mode},
                    refused="the approval was not recorded")
        try:
            approval = cfg.approve_ccpa(store_id, version=version, actor=actor,
                                        now=_utcnow_iso(), note=note.strip(),
                                        position=position.strip())
        except SettingsError as e:
            raise _settings_problems(e)
        return {"store_id": store_id, **approval, "self_approved": self_approved}

    # ---------------- hardening middleware (opt-in) ----------------
    # Probe/observability endpoints stay exempt from rate limiting. Middleware
    # added last runs outermost, so CORS wraps everything (headers on all
    # responses, preflight handled) and rate limiting rejects before routing.
    _EXEMPT_PATHS = {"/livez", "/readyz", "/healthz", "/metrics"}
    def _credential_is_valid(authorization: str) -> bool:
        # A caller earns a rate-limit bucket of its own only with a bearer
        # credential that validates; junk ones are counted against the IP.
        if _authn is None:
            return False
        try:
            return _authn.authenticate(authorization) is not None
        except AuthError:
            return False

    if rate_limit:
        app.add_middleware(RateLimitMiddleware, limit=rate_limit,
                           window_s=rate_window_s, exempt_paths=_EXEMPT_PATHS,
                           credential_validator=_credential_is_valid)
    if max_body_bytes:
        app.add_middleware(MaxBodySizeMiddleware, max_bytes=max_body_bytes)
    if cors_origins:
        # A wildcard origin never carries credentials. Starlette answers a
        # credentialed request under "*" by reflecting the caller's Origin, so
        # "*" plus credentials would let any site drive a signed-in console
        # session. With "*" (alone or in a list) the API still answers
        # cross-origin bearer-token callers, but browsers will not send the
        # session cookie; name the console's origins explicitly to allow it.
        _wildcard = "*" in cors_origins
        if _wildcard:
            import logging
            logging.getLogger(__name__).warning(
                "VECSHIELD_CORS_ORIGINS contains '*': cross-origin requests are "
                "served without credentials (no session cookies). List explicit "
                "origins to allow credentialed cross-origin access.")
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_credentials=not _wildcard,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    # F8: baseline security headers on every response, outermost so the 413
    # and 429 answers above carry them too. HSTS follows the request scheme,
    # or is always on with VECSHIELD_HSTS=1 (TLS terminated in front of us).
    app.add_middleware(SecurityHeadersMiddleware,
                       hsts=_truthy_env("VECSHIELD_HSTS"),
                       csp_exempt_paths=("/docs", "/redoc"))

    return app
