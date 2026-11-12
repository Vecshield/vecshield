"""Compliance & reporting: audit log, erasure, policy, reports, and the
regulatory content layer (source records, criteria, packs)."""

from __future__ import annotations

from vecshield_platform.compliance.audit import (
    AuditEntry,
    AuditIntegrityError,
    AuditLog,
    VerifyResult,
)
from vecshield_platform.compliance.erasure import (
    MAX_PROBES_PER_COLLECTION,
    ErasureExecution,
    ErasurePlan,
    ErasureProbe,
    ErasureReport,
    ErasureVerification,
    build_erasure_receipt,
    erasure_impact,
    execute_erasure,
    plan_erasure,
    verify_erasure,
)
from vecshield_platform.compliance.policy import (
    Policy,
    PolicyViolation,
    default_policies,
    evaluate_policies,
)
from vecshield_platform.compliance.training_policy import MAX_PII_DENSITY, training_policies
from vecshield_platform.compliance.dsar import (
    DSARRecord,
    DSARStoreResult,
    create_dsar,
    execute_dsar,
    scan_all_stores,
)
from vecshield_platform.compliance.pia import PIAReport, build_pia_html, generate_pia
from vecshield_platform.compliance.fingerprint import (
    apply_fingerprints,
    fingerprint_finding,
)
from vecshield_platform.compliance.allowlist import (
    AllowlistRule,
    Suppression,
    SuppressionError,
    SuppressionResult,
    builtin_allowlist,
    default_ttl_days,
    evaluate_suppressions,
    is_sensitive,
    validate_suppression,
)
from vecshield_platform.compliance.report import build_report, to_pdf, write_report
from vecshield_platform.compliance.sources import (
    RegulatorySource,
    get_source,
    resolve_sources,
)
from vecshield_platform.compliance.content_review import (
    CONTENT_REVIEWS,
    ContentReview,
    criterion_lifecycle,
    pack_lifecycle,
)
from vecshield_platform.compliance.criteria import (
    Criterion,
    CriterionAssessment,
    ReviewerDecision,
    evaluate_criterion,
    evaluate_pack,
    summarize_pack,
)
from vecshield_platform.compliance.hipaa import (
    SAFE_HARBOR_IDENTIFIERS,
    SafeHarborIdentifier,
    SafeHarborObservation,
    business_associate_exposure,
    evaluate_safe_harbor,
    safe_harbor_manifest,
)
from vecshield_platform.compliance.packs import (
    criteria_for,
    get_criterion,
    hipaa_pack_manifest,
    pack_manifest,
    resolve_criterion_id,
)

__all__ = [
    "AuditLog",
    "AuditEntry",
    "AuditIntegrityError",
    "VerifyResult",
    "erasure_impact",
    "plan_erasure",
    "execute_erasure",
    "verify_erasure",
    "build_erasure_receipt",
    "ErasureExecution",
    "ErasurePlan",
    "ErasureProbe",
    "ErasureReport",
    "ErasureVerification",
    "MAX_PROBES_PER_COLLECTION",
    "Policy",
    "PolicyViolation",
    "evaluate_policies",
    "default_policies",
    "fingerprint_finding",
    "apply_fingerprints",
    "AllowlistRule",
    "Suppression",
    "SuppressionError",
    "SuppressionResult",
    "builtin_allowlist",
    "default_ttl_days",
    "evaluate_suppressions",
    "is_sensitive",
    "validate_suppression",
    "training_policies",
    "MAX_PII_DENSITY",
    "build_report",
    "write_report",
    "to_pdf",
    "generate_pia",
    "build_pia_html",
    "PIAReport",
    "DSARRecord",
    "DSARStoreResult",
    "create_dsar",
    "scan_all_stores",
    "execute_dsar",
    "RegulatorySource",
    "get_source",
    "resolve_sources",
    "CONTENT_REVIEWS",
    "ContentReview",
    "criterion_lifecycle",
    "pack_lifecycle",
    "Criterion",
    "CriterionAssessment",
    "ReviewerDecision",
    "evaluate_criterion",
    "evaluate_pack",
    "summarize_pack",
    "criteria_for",
    "get_criterion",
    "resolve_criterion_id",
    "pack_manifest",
    "hipaa_pack_manifest",
    "SAFE_HARBOR_IDENTIFIERS",
    "SafeHarborIdentifier",
    "SafeHarborObservation",
    "evaluate_safe_harbor",
    "safe_harbor_manifest",
    "business_associate_exposure",
]
