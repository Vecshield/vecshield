"""Policy template catalog, grouped by regulation / framework.

Each template maps a finding condition (which MUST match fields the scan engine
emits) to a remediation action, with a regulatory rationale. `when` clauses use:
  category        : data_classification | isolation | rag_integrity |
                    network_exposure | transport_encryption | cve
  requires_label  : secret | pci | phi | pii   (from evidence.label_counts)
  evidence_gte    : dotted path >= value (e.g. sensitivity.inversion_risk)
  min_severity    : info | low | medium | high | critical

A `when` clause matches one finding category, so a condition that spans two
kinds of observation — a store that is both publicly reachable and plaintext,
say — is two templates, not one with a compound rule. Inventing a condition
field the engine does not emit would produce a rule that silently never fires.

Admins instantiate a template and scope it to a store/collection.

A template is a detection rule, not a compliance conclusion. Three fields keep
that distinction visible wherever a template is displayed or instantiated:

``source_ids``
    References into the maintained source catalog
    (:mod:`vecshield_platform.compliance.sources`). Attribution is looked up
    from those records, never parsed out of the template's display name.
``applicability``
    Facts that decide whether the cited obligation reaches this system at all.
    ``requires_confirmation`` means nobody has answered it yet; a rule can match
    while the obligation does not apply.
``evidence``
    What the detector observes, what it does not establish, and the confidence
    class of the observation. A match is an observation that a reviewer turns
    into a decision.
"""

from __future__ import annotations

import copy
from typing import Any

from vecshield_platform.compliance.sources import (
    LIFECYCLE_LABELS,
    REVIEW_GATED,
    least_advanced,
    resolve_sources,
)

#: How a detector reached its observation. Not a probability.
CONFIDENCE_CLASSES = ("pattern_match", "sampled_probe", "statistical_outlier",
                      "configuration_observation")

#: Limitations that apply to every content classifier in this product.
_CLASSIFIER_LIMITS = [
    "Classification reads chunk text; it does not resolve whether matched content "
    "describes a real, identified person.",
    "Only the inspected scope is covered; capped or sampled runs leave the rest "
    "unassessed.",
]

POLICY_TEMPLATES: list[dict[str, Any]] = [
    # ---------------- GDPR ----------------
    {
        "id": "gdpr-pii-collection", "regulation": "GDPR",
        "name": "PII in a collection (Art. 5, 17)",
        "description": "Content matching personal-data patterns. Tag for lawful-basis "
                       "review and confirm an erasure path reaches these embeddings.",
        "category": "data_classification",
        "when": {"category": "data_classification", "requires_label": "pii"},
        "action": "tag_pii_and_enforce_erasure_path",
        "severity": "high", "default_scope": "collection",
        "source_ids": ["gdpr-art-5", "gdpr-art-17"],
        "applicability": {
            "processes_personal_data_of_eu_subjects": "requires_confirmation",
            "controller_or_processor_role": "requires_confirmation"},
        "evidence": {
            "detects": "Chunk text matching personal-data patterns in the inspected scope.",
            "does_not_establish": "Lawful basis, retention period, or whether an "
                                  "erasure path already reaches these embeddings.",
            "confidence": "pattern_match", "requires_reviewer_decision": True},
    },
    {
        "id": "gdpr-pii-invertible", "regulation": "GDPR",
        "name": "PII recoverable from embeddings (Art. 32)",
        "description": "Personal-data matches in a collection scored above the "
                       "inversion-risk threshold. Restrict access and assess re-embedding.",
        "category": "data_classification",
        "when": {"requires_label": "pii",
                 "evidence_gte": {"sensitivity.inversion_risk": 0.7}},
        "action": "restrict_and_reembed",
        "severity": "critical", "default_scope": "collection",
        "source_ids": ["gdpr-art-32"],
        "applicability": {
            "processes_personal_data_of_eu_subjects": "requires_confirmation"},
        "evidence": {
            "detects": "Personal-data matches in a collection whose embedding model "
                       "scores above the configured inversion-risk threshold.",
            "does_not_establish": "That the embeddings are practically invertible by "
                                  "an attacker with this system's access.",
            "confidence": "pattern_match", "requires_reviewer_decision": True},
    },
    {
        "id": "gdpr-cross-tenant", "regulation": "GDPR",
        "name": "Cross-tenant personal-data bleed (Art. 32)",
        "description": "A probe retrieved vectors carrying another tenant's identifier. "
                       "Investigate the retrieval path and enforce isolation.",
        "category": "isolation",
        "when": {"category": "isolation", "min_severity": "high"},
        "action": "enforce_tenant_isolation",
        "severity": "high", "default_scope": "collection",
        "source_ids": ["gdpr-art-32", "gdpr-art-5"],
        "applicability": {
            "processes_personal_data_of_eu_subjects": "requires_confirmation",
            "multi_tenant_system": "requires_confirmation"},
        "evidence": {
            "detects": "A sampled retrieval probe returned vectors carrying another "
                       "tenant's identifier.",
            "does_not_establish": "The full extent of cross-tenant exposure; probes "
                                  "sample, and application-layer filtering is not tested.",
            "confidence": "sampled_probe", "requires_reviewer_decision": True},
    },

    # ---------------- HIPAA ----------------
    {
        "id": "hipaa-phi", "regulation": "HIPAA",
        "name": "PHI in a collection (§164.312)",
        "description": "Content matching health-data patterns. Restrict access, log "
                       "queries, and confirm BAA coverage for this store.",
        "category": "data_classification",
        "when": {"category": "data_classification", "requires_label": "phi"},
        "action": "restrict_and_log_access",
        "severity": "high", "default_scope": "collection",
        "source_ids": ["hipaa-164-312-a-1", "hipaa-164-308-a-1-ii-a",
                       "hipaa-160-103"],
        "applicability": {
            "covered_entity_or_business_associate": "requires_confirmation",
            "system_handles_ephi": "requires_confirmation"},
        "evidence": {
            "detects": "Chunk text matching health-data patterns in the inspected scope.",
            "does_not_establish": "That the content is ePHI, that the organization is "
                                  "a covered entity or business associate, or whether "
                                  "a BAA covers this store.",
            "confidence": "pattern_match", "requires_reviewer_decision": True},
    },
    {
        "id": "hipaa-phi-invertible", "regulation": "HIPAA",
        "name": "PHI recoverable from embeddings (§164.308(a)(1)(ii)(A))",
        "description": "Health-data matches in a collection scored above the "
                       "inversion-risk threshold. Review whether the vectors should "
                       "be treated as disclosing ePHI.",
        "category": "data_classification",
        "when": {"requires_label": "phi",
                 "evidence_gte": {"sensitivity.inversion_risk": 0.7}},
        "action": "restrict_and_reembed",
        "severity": "critical", "default_scope": "collection",
        # An inversion-risk score is an input to the risk analysis. It is not
        # a disposal event, so the disposal specification is not cited.
        "source_ids": ["hipaa-164-308-a-1-ii-a"],
        "applicability": {
            "covered_entity_or_business_associate": "requires_confirmation",
            "system_handles_ephi": "requires_confirmation"},
        "evidence": {
            "detects": "Health-data matches in a collection scored above the "
                       "configured inversion-risk threshold.",
            "does_not_establish": "That vectors disclose ePHI in practice; the score "
                                  "is a model property, not a demonstrated attack.",
            "confidence": "pattern_match", "requires_reviewer_decision": True},
    },
    {
        "id": "hipaa-min-necessary", "regulation": "HIPAA",
        "name": "PHI beyond the corpus's stated purpose (§164.502(b))",
        "description": "Health-data matches in a corpus whose stated purpose does "
                       "not need them. Confirm the purpose, then remove or "
                       "re-scope the ingest that brought them in.",
        "category": "data_classification",
        "when": {"category": "data_classification", "requires_label": "phi"},
        "action": "review_against_corpus_purpose",
        "severity": "high", "default_scope": "collection",
        "source_ids": ["hipaa-164-502-b"],
        "applicability": {
            "covered_entity_or_business_associate": "requires_confirmation",
            "system_handles_ephi": "requires_confirmation",
            "corpus_purpose_is_recorded": "requires_confirmation"},
        "limitations": [
            "What is minimum necessary depends on the corpus's purpose, which is "
            "supplied by the entity and not verified here.",
            "Exceptions at §164.502(b)(2), including disclosures for treatment, "
            "are a legal determination."],
        "evidence": {
            "detects": "Health-data matches in a collection whose recorded purpose "
                       "does not call for patient-identifiable content.",
            "does_not_establish": "That the use or disclosure exceeds the minimum "
                                  "necessary. That turns on the purpose and on "
                                  "exceptions the scan does not evaluate.",
            "confidence": "pattern_match", "requires_reviewer_decision": True},
    },
    {
        "id": "hipaa-deident-identifiers", "regulation": "HIPAA",
        "name": "Safe Harbor identifiers in de-identified content (§164.514(b)(2))",
        "description": "Content asserted to be de-identified still matches "
                       "identifier patterns from the Safe Harbor list. Re-check "
                       "the assertion before the corpus is used as de-identified.",
        "category": "data_classification",
        "when": {"category": "data_classification", "requires_label": "phi"},
        "action": "review_deidentification_assertion",
        "severity": "high", "default_scope": "collection",
        "source_ids": ["hipaa-164-514-b-2", "hipaa-164-514-b-1", "hipaa-164-514-c"],
        "applicability": {
            "covered_entity_or_business_associate": "requires_confirmation",
            "content_asserted_de_identified": "requires_confirmation"},
        "limitations": [
            "Three of the eighteen Safe Harbor categories — biometric "
            "identifiers, full-face images, and any other unique identifying "
            "number, characteristic or code — are not observable by this "
            "product, so a clean result does not mean they are absent.",
            "The three-digit ZIP population rule is not evaluated, and fax and "
            "telephone numbers cannot be told apart.",
            "Names and URLs are detected only where the NLP classifier is "
            "installed."],
        "evidence": {
            "detects": "Detector matches that map to Safe Harbor identifier "
                       "categories in content asserted to be de-identified.",
            "does_not_establish": "That the content is or is not de-identified. "
                                  "Safe Harbor also requires no actual knowledge "
                                  "that the remainder could identify someone, "
                                  "which is not observable from text.",
            "confidence": "pattern_match", "requires_reviewer_decision": True},
    },
    {
        "id": "hipaa-store-publicly-reachable", "regulation": "HIPAA",
        "name": "Store holding ePHI reachable from the internet (§164.312(d))",
        "description": "The store's endpoint resolves to a public address. "
                       "Confirm authentication is enforced and move the store "
                       "behind a private network path.",
        "category": "network_exposure",
        "when": {"category": "network_exposure", "min_severity": "high"},
        "action": "move_to_private_network",
        "severity": "high", "default_scope": "store",
        "source_ids": ["hipaa-164-312-d", "hipaa-164-312-a-1",
                       "hipaa-164-312-a-2-i"],
        "applicability": {
            "covered_entity_or_business_associate": "requires_confirmation",
            "system_handles_ephi": "requires_confirmation"},
        "limitations": [
            "The check classifies the endpoint. It does not attempt an "
            "unauthenticated connection, so public reachability is exposure, "
            "not proof that authentication is absent.",
            "A managed SaaS endpoint is public by design and is reported "
            "separately; that is a different finding."],
        "evidence": {
            "detects": "A store endpoint that resolves to a public address, or "
                       "carries no private-network marker.",
            "does_not_establish": "That the store is unauthenticated, or that "
                                  "anyone reached it.",
            "confidence": "configuration_observation",
            "requires_reviewer_decision": True},
    },
    {
        "id": "hipaa-transmission-plaintext", "regulation": "HIPAA",
        "name": "Plaintext connection to a store holding ePHI (§164.312(e))",
        "description": "The configured connection to this store is not encrypted. "
                       "Move it to TLS before ePHI transits it.",
        "category": "transport_encryption",
        # Plaintext on VecShield's own connection, or plaintext the store
        # accepts from any client (the crypto posture enforcement check).
        "when": {"category": ["transport_encryption", "transport_tls_enforcement"],
                 "min_severity": "high"},
        "action": "enforce_tls",
        "severity": "high", "default_scope": "store",
        "source_ids": ["hipaa-164-312-e-1", "hipaa-164-312-e-2-ii",
                       "hipaa-164-306-d"],
        "applicability": {
            "covered_entity_or_business_associate": "requires_confirmation",
            "system_handles_ephi": "requires_confirmation"},
        "limitations": [
            "Transport is decided from the endpoint scheme and connector flags, "
            "not by negotiating a connection, so the cipher suite in use is "
            "unobserved.",
            "Only the connection VecShield makes is assessed. Other clients of "
            "the same store may connect differently.",
            "Encryption in transmission at §164.312(e)(2)(ii) is an addressable "
            "specification: not implementing it requires a documented "
            "determination and an equivalent alternative where reasonable, per "
            "§164.306(d)(3). Addressable is not optional."],
        "evidence": {
            "detects": "A store endpoint configured for a plaintext scheme, or "
                       "with TLS explicitly disabled.",
            "does_not_establish": "Whether ePHI has actually transited the "
                                  "connection, or whether a documented "
                                  "determination covers the decision.",
            "confidence": "configuration_observation",
            "requires_reviewer_decision": True},
    },
    {
        "id": "hipaa-cross-tenant", "regulation": "HIPAA",
        "name": "Cross-tenant bleed in a store holding ePHI (§164.402)",
        "description": "A probe retrieved vectors carrying another tenant's "
                       "identifier. Treat as a candidate impermissible disclosure "
                       "and run the four-factor risk assessment.",
        "category": "isolation",
        "when": {"category": "isolation", "min_severity": "high"},
        "action": "enforce_tenant_isolation",
        "severity": "critical", "default_scope": "collection",
        "source_ids": ["hipaa-164-402", "hipaa-164-312-a-1",
                       "hipaa-164-308-a-6-ii"],
        "applicability": {
            "covered_entity_or_business_associate": "requires_confirmation",
            "system_handles_ephi": "requires_confirmation",
            "multi_tenant_system": "requires_confirmation"},
        "limitations": [
            "An impermissible disclosure is presumed to be a breach unless a "
            "risk assessment shows a low probability of compromise. The scan "
            "supplies facts for the first two factors — the identifier types "
            "involved and the path by which content was reachable — and cannot "
            "speak to whether the information was acquired or viewed, or to "
            "mitigation.",
            "Probes sample. Application-layer filtering in front of the store is "
            "not exercised."],
        "evidence": {
            "detects": "A sampled retrieval probe returned vectors carrying "
                       "another tenant's identifier.",
            "does_not_establish": "That a breach occurred, that a real query ever "
                                  "returned the data, or the full extent of "
                                  "cross-tenant exposure.",
            "confidence": "sampled_probe", "requires_reviewer_decision": True},
    },
    {
        "id": "hipaa-corpus-integrity", "regulation": "HIPAA",
        "name": "Altered or unattributable content in an ePHI corpus (§164.312(c))",
        "description": "Injected or unprovenanced chunks in a corpus holding "
                       "health data. Quarantine and trace them to a source.",
        "category": "rag_integrity",
        "when": {"category": "rag_integrity", "min_severity": "high"},
        "action": "quarantine_chunks",
        "severity": "high", "default_scope": "collection",
        "source_ids": ["hipaa-164-312-c-1", "hipaa-164-312-c-2"],
        "applicability": {
            "covered_entity_or_business_associate": "requires_confirmation",
            "system_handles_ephi": "requires_confirmation"},
        "limitations": [
            "An injection pattern in a chunk does not establish that the "
            "application would act on it.",
            "Provenance coverage says how many chunks carry a source, not "
            "whether the source is the one it claims to be."],
        "evidence": {
            "detects": "Chunks matching injection patterns, or chunks with no "
                       "traceable source, in the inspected scope.",
            "does_not_establish": "That ePHI was improperly altered, or who "
                                  "altered it.",
            "confidence": "pattern_match", "requires_reviewer_decision": True},
    },

    # ---------------- PCI-DSS ----------------
    {
        "id": "pci-pan", "regulation": "PCI-DSS",
        "name": "Cardholder data / PAN (Req. 3)",
        "description": "Values passing a card-number check. Confirm whether they are "
                       "live PANs, then remove and tokenize upstream.",
        "category": "data_classification",
        "when": {"category": "data_classification", "requires_label": "pci"},
        "action": "remove_and_tokenize",
        "severity": "critical", "default_scope": "collection",
        # Whether a detected PAN is stored *readable* is the separate built-in
        # crypto policy pan-rendered-unreadable (Requirement 3.5.1).
        "source_ids": ["pci-dss-req-3", "pci-dss-req-3-5-1"],
        "applicability": {
            "stores_processes_or_transmits_account_data": "requires_confirmation",
            "system_in_cardholder_data_environment": "requires_confirmation"},
        "evidence": {
            "detects": "Digit sequences passing a card-number check in chunk text.",
            "does_not_establish": "That the value is a live PAN, nor the assessment "
                                  "scope of the cardholder data environment.",
            "confidence": "pattern_match", "requires_reviewer_decision": True},
    },
    {
        "id": "pci-secrets", "regulation": "PCI-DSS",
        "name": "Embedded credentials (Req. 8.6.2, 8.3.2)",
        "description": "Credential-shaped strings in embedded content. Verify, purge, "
                       "rotate, and add a pre-ingest secret scanner.",
        "category": "data_classification",
        "when": {"category": "data_classification", "requires_label": "secret"},
        "action": "purge_and_rotate",
        "severity": "critical", "default_scope": "global",
        # Both locators are unverified against the licensed standard; their
        # source records say so.
        "source_ids": ["pci-dss-req-8-6-2", "pci-dss-req-8-3-2"],
        "applicability": {
            "system_in_cardholder_data_environment": "requires_confirmation"},
        "evidence": {
            "detects": "Credential-shaped strings in chunk text.",
            "does_not_establish": "Whether the credential is valid, current, or "
                                  "grants access to anything in scope.",
            "confidence": "pattern_match", "requires_reviewer_decision": True},
    },

    # ---------------- SOC 2 ----------------
    {
        "id": "soc2-secrets", "regulation": "SOC 2",
        "name": "Secrets in the data layer (CC6.1)",
        "description": "Credential-shaped strings in embedded content. Verify and, if "
                       "live, purge and rotate.",
        "category": "data_classification",
        "when": {"category": "data_classification", "requires_label": "secret"},
        "action": "purge_and_rotate",
        "severity": "critical", "default_scope": "global",
        "source_ids": ["tsc-cc6-1"],
        "applicability": {
            "criterion_in_audit_scope": "requires_confirmation",
            "system_in_service_boundary": "requires_confirmation"},
        "evidence": {
            "detects": "Credential-shaped strings in chunk text.",
            "does_not_establish": "Operating effectiveness of the access-control "
                                  "criterion; that is an auditor's conclusion.",
            "confidence": "pattern_match", "requires_reviewer_decision": True},
    },
    {
        "id": "soc2-injection", "regulation": "SOC 2",
        "name": "RAG prompt-injection (CC7.2)",
        "description": "Stored chunks match known injection patterns. Quarantine and "
                       "review whether the application would act on them.",
        "category": "rag_integrity",
        "when": {"category": "rag_integrity", "min_severity": "high"},
        "action": "quarantine_chunks",
        "severity": "high", "default_scope": "collection",
        "source_ids": ["tsc-cc7-2"],
        "applicability": {
            "criterion_in_audit_scope": "requires_confirmation",
            "system_in_service_boundary": "requires_confirmation"},
        "evidence": {
            "detects": "Stored chunks containing known prompt-injection patterns.",
            "does_not_establish": "That the deployed application would act on the "
                                  "payload, or that detection controls are effective.",
            "confidence": "pattern_match", "requires_reviewer_decision": True},
    },
    {
        "id": "soc2-anomaly", "regulation": "SOC 2",
        "name": "Anomalous embeddings (CC7.2)",
        "description": "Vectors far from their collection centroid. Review against "
                       "provenance; topic diversity also produces outliers.",
        "category": "rag_integrity",
        "when": {"category": "rag_integrity", "min_severity": "medium"},
        "action": "review_outliers",
        "severity": "medium", "default_scope": "collection",
        "source_ids": ["tsc-cc7-2"],
        "applicability": {
            "criterion_in_audit_scope": "requires_confirmation",
            "system_in_service_boundary": "requires_confirmation"},
        "evidence": {
            "detects": "Vectors far from their collection centroid in the scored sample.",
            "does_not_establish": "Poisoning. Legitimate topic diversity produces "
                                  "outliers; provenance review decides.",
            "confidence": "statistical_outlier", "requires_reviewer_decision": True},
    },

    # ---------------- CCPA ----------------
    {
        "id": "ccpa-personal-info", "regulation": "CCPA/CPRA",
        "name": "Personal information (§1798.105)",
        "description": "Content matching personal-information patterns. Confirm "
                       "deletion-request handling reaches these embeddings.",
        "category": "data_classification",
        "when": {"category": "data_classification", "requires_label": "pii"},
        "action": "tag_pii_and_enforce_erasure_path",
        "severity": "medium", "default_scope": "collection",
        "source_ids": ["ccpa-1798-105"],
        "applicability": {
            "business_subject_to_ccpa": "requires_confirmation",
            "data_relates_to_california_residents": "requires_confirmation"},
        "evidence": {
            "detects": "Chunk text matching personal-information patterns.",
            "does_not_establish": "Whether an exemption applies, or whether deletion "
                                  "requests already reach these embeddings.",
            "confidence": "pattern_match", "requires_reviewer_decision": True},
    },

    # ---------------- EU AI Act ----------------
    {
        "id": "aiact-data-governance", "regulation": "EU AI Act",
        "name": "RAG input data integrity (Art. 26(4))",
        "description": "Injection patterns in knowledge-base content. Quarantine and "
                       "record the outcome in the input-data governance record.",
        "category": "rag_integrity",
        "when": {"category": "rag_integrity", "min_severity": "high"},
        "action": "quarantine_chunks",
        "severity": "high", "default_scope": "collection",
        # Art. 10 is a provider's training-data duty; a deployer's retrieval
        # corpus is input data under Art. 26(4).
        "source_ids": ["aiact-art-26-4"],
        "applicability": {
            "system_is_high_risk_ai": "requires_confirmation",
            "role_provider_or_deployer": "requires_confirmation"},
        "evidence": {
            "detects": "Injection patterns in knowledge-base content.",
            "does_not_establish": "That the system is high-risk under Annex III, or "
                                  "that the input data is not relevant to the "
                                  "system's intended purpose.",
            "confidence": "pattern_match", "requires_reviewer_decision": True},
    },
    {
        "id": "aiact-robustness", "regulation": "EU AI Act",
        "name": "Poisoning / robustness (Art. 15(5))",
        "description": "Outlier vectors in the scored sample. Investigate provenance "
                       "before concluding an accuracy or robustness impact.",
        "category": "rag_integrity",
        "when": {"category": "rag_integrity", "min_severity": "medium"},
        "action": "review_outliers",
        "severity": "medium", "default_scope": "collection",
        "source_ids": ["aiact-art-15-5"],
        "applicability": {
            "system_is_high_risk_ai": "requires_confirmation",
            "role_provider_or_deployer": "requires_confirmation"},
        "evidence": {
            "detects": "Outlier vectors in the scored sample.",
            "does_not_establish": "An accuracy or robustness deficiency of the AI system.",
            "confidence": "statistical_outlier", "requires_reviewer_decision": True},
    },

    # ---------------- General security ----------------
    {
        "id": "sec-secrets", "regulation": "General",
        "name": "Secrets never embedded",
        "description": "Any API key, token, or private key in a collection.",
        "category": "data_classification",
        "when": {"category": "data_classification", "requires_label": "secret"},
        "action": "purge_and_rotate",
        "severity": "critical", "default_scope": "global",
        "source_ids": ["vecshield-baseline"],
        "applicability": {},
        "evidence": {
            "detects": "Credential-shaped strings in chunk text.",
            "does_not_establish": "Whether the credential is valid or still in use.",
            "confidence": "pattern_match", "requires_reviewer_decision": False},
    },
    {
        "id": "sec-high-catchall", "regulation": "General",
        "name": "Any high-severity finding",
        "description": "Escalate any HIGH or CRITICAL finding for review, "
                       "regardless of category.",
        "category": "any",
        "when": {"min_severity": "high"},
        "action": "escalate_to_review",
        "severity": "high", "default_scope": "store",
        "source_ids": ["vecshield-baseline"],
        "applicability": {},
        "evidence": {
            "detects": "Any finding this run rated high or critical.",
            "does_not_establish": "Which obligation, if any, the finding bears on.",
            "confidence": "configuration_observation", "requires_reviewer_decision": False},
    },
]

_BY_ID = {t["id"]: t for t in POLICY_TEMPLATES}

# Stable display order for regulation groupings in the UI.
REGULATIONS = ["GDPR", "HIPAA", "PCI-DSS", "SOC 2", "CCPA/CPRA", "EU AI Act", "General"]


def get_template(template_id: str) -> dict[str, Any] | None:
    return _BY_ID.get(template_id)


def enriched_policy_templates(templates: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Return templates with resolved attribution and evidence framing.

    Attribution comes from the maintained source catalog, so a renamed template
    keeps its citation and a broken reference shows up as unresolved instead of
    vanishing. Nothing here upgrades a detection rule into a conclusion: the
    ``attribution.reviewed`` and ``applicability`` fields report exactly how far
    the content has been taken.
    """

    return [_enrich_template(t) for t in (templates or POLICY_TEMPLATES)]


def _enrich_template(template: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(template)
    sources = resolve_sources(list(out.get("source_ids", [])))
    citations = [s["citation"] for s in sources if s.get("citation")]
    out["attribution"] = {
        "framework": out.get("regulation") or "General",
        "citation": "; ".join(citations) or None,
        "source_text": "; ".join(citations) or out.get("regulation") or "General",
        "sources": sources,
        # A template is only as reviewed as its least-reviewed source. No
        # source record in this catalog has been through a content review.
        "lifecycle": least_advanced([s.get("lifecycle") or "draft" for s in sources]),
        "lifecycle_label": LIFECYCLE_LABELS[
            least_advanced([s.get("lifecycle") or "draft" for s in sources])],
        "legal_statuses": sorted({s["legal_status"] for s in sources
                                  if s.get("legal_status")}),
        "reviewed": bool(sources) and all(
            s.get("lifecycle") in REVIEW_GATED for s in sources),
        "verified": bool(sources) and all(s.get("verified") for s in sources),
        "unresolved": [s["id"] for s in sources if s.get("status") == "unresolved"],
    }
    applicability = dict(out.get("applicability") or {})
    out["applicability"] = applicability
    out["requires_applicability_decision"] = any(
        value == "requires_confirmation" for value in applicability.values())
    evidence = dict(out.get("evidence") or {})
    evidence.setdefault("confidence", "pattern_match")
    evidence.setdefault("requires_reviewer_decision", True)
    evidence["limitations"] = list(out.get("limitations") or []) + _CLASSIFIER_LIMITS
    out["evidence"] = evidence
    out["rule"] = copy.deepcopy(out.get("when", {}))
    return out
