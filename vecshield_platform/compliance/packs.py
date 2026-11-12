"""The draft criterion pack shipped with VecShield.

Scope is deliberate: every criterion here is one a vector-store assessment can
say something concrete about, and each names the checks that speak to it plus
the artifacts a person still has to supply. Obligations VecShield cannot
observe are absent rather than present-and-unassessable. Where an obligation is
worth carrying but nothing in the product observes it, the criterion says so
with ``manual_evidence_only`` instead of naming a check that does not exist.

The HIPAA criteria name individual standards and implementation
specifications, and record whether each is a standard, a *required*
specification, or an *addressable* one, citing 45 CFR 164.306(d) as the
provision that draws that line. :func:`hipaa_pack_manifest` lists the HIPAA
obligations this pack deliberately does **not** reach; naming them is more
honest than silence.

This pack has had no regulatory review. Each criterion carries its own
lifecycle, which can reach ``regulatory_reviewed`` only through a matching
content review (:mod:`vecshield_platform.compliance.content_review`), and the
pack's lifecycle is its least-advanced criterion's. Its version is
:data:`PACK_VERSION` so a later pack cannot silently rewrite an assessment made
against this one.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

from vecshield_platform.compliance.content_review import (
    QUALIFIED_REVIEWER,
    pack_lifecycle,
)
from vecshield_platform.compliance.criteria import PACK_VERSION, Criterion
from vecshield_platform.compliance.sources import (
    LIFECYCLE_LABELS,
    resolve_sources,
)
from vecshield_platform.compliance.hipaa import (
    business_associate_exposure,
    safe_harbor_manifest,
)

_SAMPLING_LIMIT = ("The isolation check verifies that the store enforces the "
                   "tenant filter for every tenant; it cannot see whether every "
                   "query an application builds carries that filter.")
_SCOPE_LIMIT = ("Only stores and collections included in the run are covered; "
                "capped runs leave the remainder unassessed.")
_CLASSIFIER_LIMIT = ("Classification matches patterns in chunk text and cannot "
                     "confirm that content concerns a real, identified person.")

#: Cited in the rationale whenever an addressable specification is evaluated.
_306D = "45 CFR 164.306(d)"

_EPHI_APPLICABILITY = ["covered_entity_or_business_associate", "system_handles_ephi"]

_EPHI_LIMIT = ("Whether content is ePHI, and whether the organization is a covered "
               "entity or business associate, are determinations under 45 CFR "
               "160.103. This scan classifies text; it does not make them.")

_POSTURE_LIMIT = ("The posture checks read the store's endpoint, its connector "
                  "metadata, what the connector's own session and data-plane API "
                  "expose, and known CVEs for the connector library. They do not "
                  "authenticate to a cloud provider's management API, so anything "
                  "the provider only exposes there is unobserved.")

#: Posture sub-checks, as run_posture_audit emits them. Criteria cite these,
#: not the orchestrator's umbrella name, which is only recorded when the whole
#: posture audit was skipped or failed to run.
_ACCESS_POSTURE = ["authentication", "network_exposure"]
#: Least privilege of the retrieval role, from the store's own roles and
#: grants (access/grants.py). Cited only by criteria whose sources speak to
#: authorization of access, not by authentication criteria. Stores whose
#: connector reports no grants record it as not observable, so these
#: criteria read inconclusive there rather than passed.
_GRANTS = "access_grants"

_CRYPTO_SCOPE_LIMIT = ("Cryptographic posture is assessed at the vector-database "
                       "data plane. Volume, disk and cloud key-management "
                       "encryption the database does not expose are outside the "
                       "connector's view and are reported as not observable, "
                       "never as absent.")

_AT_REST_LIMIT = ("Encryption at rest is read from what the database itself "
                  "exposes (system catalogs, server status, index configuration). "
                  "Most vector stores expose nothing, and then the state is not "
                  "observable and the fallback statement carries the criterion.")

_TRANSIT_LIMIT = ("Transport is assessed on the connection VecShield makes, from "
                  "the live session where the client exposes it and otherwise "
                  "from the configured scheme. Whether the store refuses "
                  "plaintext clients is a separate check, which is opt-in when "
                  "it needs an active probe.")

CRITERIA: list[Criterion] = [
    # ---------------- HIPAA Security Rule, 45 CFR Part 164 Subpart C --------
    Criterion(
        id="HIPAA-164-308-A1-RISK-01", framework="HIPAA",
        title="Health data in the store is part of the risk analysis",
        specification="required", specification_basis=_306D,
        aliases=["HIPAA-SEC-EPHI-INVENTORY-01"],
        paraphrase="ePHI held in the vector store, and in the embeddings derived "
                   "from it, is identified and carried into the risk analysis.",
        source_ids=["hipaa-164-308-a-1-ii-a", "hipaa-164-308-a-1-ii-b",
                    "hipaa-160-103"],
        technical_checks=["data_classification", "training_data_classification"],
        manual_evidence=["ephi_inventory", "risk_analysis", "risk_management_plan"],
        applicability_questions=_EPHI_APPLICABILITY,
        limitations=[_CLASSIFIER_LIMIT, _EPHI_LIMIT, _SCOPE_LIMIT,
                     "An inventory of one estate's registered stores is not the "
                     "enterprise-wide risk analysis the specification requires."],
        interpretation_notes="Risk analysis is required, not addressable. This "
                             "criterion supplies one input to it — what is actually "
                             "in the corpus — and absorbs the retired "
                             "HIPAA-SEC-EPHI-INVENTORY-01."),
    Criterion(
        id="HIPAA-164-308-A4-ACCESS-MGMT-01", framework="HIPAA",
        title="Access to health data is approved and periodically reviewed",
        specification="addressable", specification_basis=_306D,
        paraphrase="Access to ePHI in the store is authorized on a documented "
                   "basis, established when granted, and reviewed periodically.",
        source_ids=["hipaa-164-308-a-4", "hipaa-164-308-a-4-ii-b",
                    "hipaa-164-308-a-4-ii-c", "hipaa-164-306-d"],
        technical_checks=["tenant_isolation", *_ACCESS_POSTURE, _GRANTS],
        manual_evidence=["authorized_access_policy", "access_review_record"],
        applicability_questions=_EPHI_APPLICABILITY,
        limitations=[_SAMPLING_LIMIT, _POSTURE_LIMIT, _SCOPE_LIMIT,
                     "Who holds which grant is read from the store's own "
                     "configuration where the connector exposes it; the identity "
                     "provider behind those grants is not inspected.",
                     "The standard is about administrative policies and "
                     "procedures for authorizing access. The checks look at "
                     "technical access to the store: they inform that policy, "
                     "and they do not evaluate it."],
        interpretation_notes="Access authorization and access establishment and "
                             "modification are addressable specifications. If they "
                             "are not implemented, §164.306(d)(3) still requires a "
                             "documented determination and an equivalent "
                             "alternative where one is reasonable."),
    Criterion(
        id="HIPAA-164-308-A6-INCIDENT-01", framework="HIPAA",
        title="Suspicious retrieval activity is handled as a possible incident",
        specification="required", specification_basis=_306D,
        paraphrase="Suspected impermissible activity in the retrieval layer is "
                   "identified, responded to, and its outcome recorded.",
        source_ids=["hipaa-164-308-a-6", "hipaa-164-308-a-6-ii", "hipaa-164-304"],
        technical_checks=["tenant_isolation", "prompt_injection", "rag_integrity"],
        manual_evidence=["incident_response_procedure", "incident_records"],
        applicability_questions=_EPHI_APPLICABILITY,
        limitations=[_SAMPLING_LIMIT, _SCOPE_LIMIT,
                     "This is a point-in-time assessment, not monitoring. It can "
                     "surface an incident candidate; it does not establish that "
                     "the entity detects incidents as they happen."],
        interpretation_notes="A failed isolation probe or an injected chunk is a "
                             "candidate security incident under §164.304, which a "
                             "person triages. VecShield does not declare one."),
    Criterion(
        id="HIPAA-164-308-A8-EVALUATION-01", framework="HIPAA",
        title="The store's safeguards are re-evaluated on a schedule",
        specification="standard", specification_basis=_306D,
        paraphrase="The technical safeguards over the store are periodically "
                   "evaluated, and the evaluation leaves a record.",
        source_ids=["hipaa-164-308-a-8", "hipaa-164-316-b-1"],
        technical_checks=["data_classification", "rag_integrity",
                          "tenant_isolation", *_ACCESS_POSTURE,
                          "transport_encryption", "cve"],
        manual_evidence=["evaluation_schedule", "prior_evaluation_record"],
        applicability_questions=_EPHI_APPLICABILITY,
        limitations=[_SCOPE_LIMIT, _POSTURE_LIMIT,
                     "One run is one evaluation of the technical safeguards over "
                     "the stores in scope. The standard also reaches non-technical "
                     "evaluation and the rest of the environment.",
                     "Periodicity is a property of the programme, not of a run. "
                     "Nothing here establishes that evaluations recur."],
        interpretation_notes="The saved audit snapshot and this assessment are "
                             "themselves part of the evidence for this standard, "
                             "which is why the criterion cites the documentation "
                             "requirement alongside it."),
    Criterion(
        id="HIPAA-164-308-B1-BAA-01", framework="HIPAA",
        title="Every vendor holding health data has a business associate agreement",
        specification="standard", specification_basis=_306D,
        paraphrase="Every vendor that holds ePHI in this estate is under a "
                   "business associate contract before ePHI reaches it.",
        source_ids=["hipaa-164-308-b-1", "hipaa-164-314-a", "hipaa-164-502-e",
                    "hipaa-164-504-e", "hipaa-160-103"],
        manual_evidence_only=True,
        manual_evidence=["business_associate_agreements", "vendor_inventory"],
        applicability_questions=_EPHI_APPLICABILITY,
        limitations=[
            "The connector kind is what is observed. For a self-hostable store "
            "(pgvector, Qdrant, OpenSearch, Chroma, Milvus, Redis, Weaviate, "
            "MongoDB) it does not say who operates the deployment, so those are "
            "reported as 'operator not established' rather than as self-hosted.",
            "Nothing here observes whether a contract exists, what it says, or "
            "whether the vendor offers one at all.",
            "A managed service may be backed by another store — a Bedrock "
            "knowledge base by OpenSearch, for example — and the backing store "
            "is a separate holder of the same content.",
            _SCOPE_LIMIT],
        interpretation_notes="VecShield names the vendors the registered connector "
                             "kinds imply a BAA is needed for. See "
                             "vecshield_platform.compliance.hipaa."
                             "business_associate_exposure. It is an inference from "
                             "the connector kind, not a contract check. That "
                             "inference is shown as context, not as a check "
                             "result, so this criterion rests on the artifacts. "
                             "The Privacy Rule's business associate provisions, "
                             "§164.502(e) and §164.504(e), are cited alongside the "
                             "Security Rule's; those two locators are unverified "
                             "and marked so on their source records."),
    Criterion(
        id="HIPAA-164-310-D2-DISPOSAL-01", framework="HIPAA",
        title="Disposal of ePHI on retired media and indexes",
        specification="required", specification_basis=_306D,
        paraphrase="When media or an index holding ePHI is retired, the ePHI on "
                   "it, including in the embeddings derived from it, is disposed "
                   "of so it cannot be recovered.",
        source_ids=["hipaa-164-310-d-2-i"],
        technical_checks=["data_classification", "erasure_verification"],
        manual_evidence=["disposal_procedure", "backup_retention_statement"],
        applicability_questions=_EPHI_APPLICABILITY,
        limitations=["Deletion from the live index is not evidence of deletion from "
                     "backups, snapshots, or downstream copies.",
                     "The embedding of a deleted chunk is removed only if the "
                     "connector deletes the vector with it; a vector left behind "
                     "can still carry recoverable content.",
                     "HIPAA has no general rule requiring ePHI to be deleted once "
                     "it is no longer needed. How long ePHI may be kept is "
                     "outside this criterion; record age is not evaluated here.",
                     _SCOPE_LIMIT],
        interpretation_notes="§164.310(d)(2)(i) covers the final disposition of "
                             "ePHI and the media holding it. Treating a retired "
                             "vector index as such media is direct. Applying the "
                             "specification to deletion of individual records "
                             "from a live index, which is what the erasure check "
                             "verifies, is VecShield's interpretation, offered "
                             "for counsel to confirm; it is not a reading of the "
                             "rule. §164.310 is otherwise a physical safeguard "
                             "outside what this product sees."),
    Criterion(
        id="HIPAA-164-312-A1-ACCESS-CONTROL-01", framework="HIPAA",
        title="Only authorized users and tenants can read health data",
        specification="standard", specification_basis=_306D,
        aliases=["HIPAA-SEC-ACCESS-01"],
        paraphrase="Technical access control limits ePHI in the store to "
                   "authorized users and workloads, including across tenants.",
        source_ids=["hipaa-164-312-a-1", "hipaa-164-312-a-2-i"],
        technical_checks=["tenant_isolation", *_ACCESS_POSTURE, _GRANTS],
        manual_evidence=["authorized_access_policy", "access_review_record"],
        applicability_questions=_EPHI_APPLICABILITY,
        limitations=[_SAMPLING_LIMIT, _POSTURE_LIMIT, _SCOPE_LIMIT,
                     "Unique user identification is a property of the accounts "
                     "used to reach the store. VecShield observes the store's "
                     "exposure, not whether each person has their own account."],
        interpretation_notes="A passing isolation probe evidences one access path. "
                             "The standard covers access control overall, and this "
                             "criterion is where the retired HIPAA-SEC-ACCESS-01 "
                             "now lives."),
    Criterion(
        id="HIPAA-164-312-A2IV-ENCRYPTION-01", framework="HIPAA",
        title="Health data is encrypted at rest, or the decision not to is documented",
        specification="addressable", specification_basis=_306D,
        paraphrase="ePHI held in the store is encrypted at rest, or the decision "
                   "not to encrypt it is documented with an equivalent measure.",
        source_ids=["hipaa-164-312-a-2-iv", "hipaa-164-306-d"],
        technical_checks=["at_rest_encryption"],
        fallback_evidence=["encryption_at_rest_statement"],
        applicability_questions=_EPHI_APPLICABILITY,
        limitations=[
            _AT_REST_LIMIT,
            "Transport encryption is a different property and never stands in "
            "for encryption at rest here.",
            _CRYPTO_SCOPE_LIMIT, _SCOPE_LIMIT],
        interpretation_notes="Addressable. An unencrypted store is not "
                             "automatically a gap, but under §164.306(d)(3) the "
                             "entity must have documented why encryption is not "
                             "reasonable and appropriate and put an equivalent "
                             "alternative in place where one is. Where the store "
                             "exposes its at-rest state, the check carries this "
                             "criterion; where it does not, the documented "
                             "statement does."),
    Criterion(
        id="HIPAA-164-312-B-AUDIT-01", framework="HIPAA",
        title="Activity on the store is logged and the logs are reviewed",
        specification="standard", specification_basis=_306D,
        manual_evidence_only=True,
        paraphrase="Activity in the system holding ePHI is recorded and examined.",
        source_ids=["hipaa-164-312-b"],
        manual_evidence=["store_audit_log_configuration", "log_review_record"],
        applicability_questions=_EPHI_APPLICABILITY,
        limitations=[
            "No check in this product reads the vector store's own access logs, "
            "and no connector exposes them. Nothing here observes whether "
            "queries against the store are recorded or examined.",
            "VecShield's own tamper-evident audit log records actions taken in "
            "VecShield — scans, approvals, reveals, executions. It is evidence "
            "about the assessment tool, not about access to the store.",
            _SCOPE_LIMIT],
        interpretation_notes="Deliberately manual-evidence-only. Naming a check "
                             "here would imply VecShield watches the store's query "
                             "traffic, which it does not."),
    Criterion(
        id="HIPAA-164-312-C1-INTEGRITY-01", framework="HIPAA",
        title="Retrieval content is protected against tampering and injection",
        specification="standard", specification_basis=_306D,
        paraphrase="ePHI in the retrieval corpus is not improperly altered: "
                   "injected, tampered, or unattributable content is detected.",
        source_ids=["hipaa-164-312-c-1", "hipaa-164-312-c-2", "hipaa-164-306-d"],
        technical_checks=["rag_integrity", "prompt_injection", "embedding_anomaly",
                          "provenance"],
        manual_evidence=["ingest_controls_description", "integrity_review_records"],
        applicability_questions=_EPHI_APPLICABILITY,
        limitations=["Outlier scoring samples vectors and flags distance, not "
                     "intent; legitimate topic diversity produces outliers.",
                     "Injection patterns are matched in chunk text. A match does "
                     "not establish that the application would act on it.",
                     "Provenance coverage says how many chunks carry a source, not "
                     "whether the source is the one it claims to be.",
                     _SCOPE_LIMIT],
        interpretation_notes="§164.312(c)(2), a mechanism to authenticate ePHI, is "
                             "addressable and is cited here because provenance "
                             "coverage is the closest observable proxy. The "
                             "criterion itself is evaluated against the integrity "
                             "standard, which is mandatory."),
    Criterion(
        id="HIPAA-164-312-D-AUTHN-01", framework="HIPAA",
        title="The store requires authentication to connect",
        specification="standard", specification_basis=_306D,
        paraphrase="The store authenticates the person or entity connecting to "
                   "it, and is not reachable without authentication.",
        source_ids=["hipaa-164-312-d", "hipaa-164-312-a-2-i"],
        technical_checks=list(_ACCESS_POSTURE),
        manual_evidence=["authentication_configuration"],
        applicability_questions=_EPHI_APPLICABILITY,
        limitations=[
            "The network check decides whether the endpoint is reachable from "
            "the public internet, and reports 'unknown' when it cannot tell "
            "rather than assuming private. It does not attempt an "
            "unauthenticated connection, so a publicly reachable store is "
            "evidence of exposure, not proof that authentication is absent.",
            "A managed SaaS endpoint is public by design and is reported as "
            "such; that is not the same finding as an exposed self-hosted store.",
            _POSTURE_LIMIT, _SCOPE_LIMIT],
        interpretation_notes="A self-hosted store on a public endpoint with no "
                             "authentication configured is a concrete, observable "
                             "failure of this standard. The two halves come from "
                             "different places: exposure from the posture check, "
                             "authentication from the connector's configuration."),
    Criterion(
        id="HIPAA-164-312-E1-TRANSMISSION-01", framework="HIPAA",
        title="Health data is protected on the network path to the store",
        specification="standard", specification_basis=_306D,
        paraphrase="ePHI transmitted to and from the store is guarded against "
                   "unauthorized access on the network path.",
        source_ids=["hipaa-164-312-e-1", "hipaa-164-306-d"],
        technical_checks=["network_exposure"],
        fallback_evidence=["transport_security_statement"],
        applicability_questions=_EPHI_APPLICABILITY,
        limitations=[
            "The network check decides whether the endpoint is reachable from "
            "the public internet; it reports 'unknown' rather than assuming "
            "private.",
            "Only the connection VecShield makes is assessed. Other clients of "
            "the same store may connect differently.",
            _POSTURE_LIMIT, _SCOPE_LIMIT],
        interpretation_notes="The transmission security standard is mandatory. "
                             "Encryption is the addressable specification under "
                             "it and is assessed separately in "
                             "HIPAA-164-312-E2II-ENCRYPTION-01, so a plaintext "
                             "connection on a private network is decided under "
                             "the addressable rule rather than recorded here as "
                             "an unexcusable gap."),
    Criterion(
        id="HIPAA-164-312-E2II-ENCRYPTION-01", framework="HIPAA",
        title="Health data is encrypted in transit, or the decision not to is documented",
        specification="addressable", specification_basis=_306D,
        paraphrase="ePHI is encrypted in transit to and from the store, or the "
                   "decision not to is documented with an equivalent measure.",
        source_ids=["hipaa-164-312-e-2-ii", "hipaa-164-312-e-1",
                    "hipaa-164-306-d"],
        technical_checks=["transport_encryption", "transport_tls_enforcement"],
        fallback_evidence=["transport_security_statement"],
        applicability_questions=_EPHI_APPLICABILITY,
        limitations=[_TRANSIT_LIMIT, _CRYPTO_SCOPE_LIMIT, _SCOPE_LIMIT],
        interpretation_notes="Addressable. A plaintext connection is an observed "
                             "fact; under §164.306(d)(3) it is a gap until the "
                             "entity documents why encryption is not reasonable "
                             "and appropriate and records an equivalent measure, "
                             "such as a private network path. Without the "
                             "enforcement check, VecShield using TLS does not "
                             "show that other clients must, so the statement "
                             "is asked for."),
    Criterion(
        id="HIPAA-164-316-B1-DOCUMENTATION-01", framework="HIPAA",
        title="Assessments, evidence and decisions are documented and kept",
        specification="standard", specification_basis=_306D,
        manual_evidence_only=True,
        paraphrase="The assessment, its evidence, and the decisions taken on it "
                   "are documented and retained.",
        source_ids=["hipaa-164-316-b-1", "hipaa-164-316-b-2-i"],
        manual_evidence=["documentation_retention_policy"],
        applicability_questions=_EPHI_APPLICABILITY,
        limitations=[
            "VecShield retains audit snapshots, evidence artifacts, reviews, "
            "exceptions and its audit log for as long as its history database "
            "is kept. It enforces no retention period and deletes nothing on a "
            "schedule, so the six-year time limit at §164.316(b)(2)(i) is a "
            "policy the operator implements, not a control the product applies.",
            "Documentation of the wider security programme is outside this "
            "estate entirely."],
        interpretation_notes="Manual-evidence-only by design: the product produces "
                             "documentation, which is not the same as enforcing a "
                             "documentation requirement."),

    # ---------------- HIPAA Privacy Rule, 45 CFR Part 164 Subpart E ---------
    Criterion(
        id="HIPAA-164-502-B-MIN-NECESSARY-01", framework="HIPAA",
        title="The corpus holds no more health data than its purpose needs",
        specification="standard",
        paraphrase="The retrieval corpus holds no more PHI than its stated "
                   "purpose needs.",
        source_ids=["hipaa-164-502-b", "hipaa-164-514-d"],
        technical_checks=["data_classification", "training_data_classification"],
        manual_evidence=["corpus_purpose_statement", "minimum_necessary_policy"],
        applicability_questions=_EPHI_APPLICABILITY,
        limitations=[_CLASSIFIER_LIMIT, _EPHI_LIMIT, _SCOPE_LIMIT,
                     "What is minimum necessary depends on the corpus's purpose, "
                     "which the product reads from the supplied statement and "
                     "cannot verify.",
                     "Exceptions at §164.502(b)(2), including disclosures for "
                     "treatment, are a legal determination."],
        interpretation_notes="The observable case is a purpose mismatch: clinical "
                             "letters in a corpus whose stated purpose is clinical "
                             "guidance. The scan shows what is there; the purpose "
                             "statement supplies what should be."),
    Criterion(
        id="HIPAA-164-514-B-DEIDENT-01", framework="HIPAA",
        title="Content labelled de-identified really is de-identified",
        specification="standard",
        paraphrase="Content asserted to be de-identified actually meets Safe "
                   "Harbor or rests on a documented expert determination.",
        source_ids=["hipaa-164-514-a", "hipaa-164-514-b-2", "hipaa-164-514-b-1",
                    "hipaa-164-514-c"],
        technical_checks=["data_classification"],
        manual_evidence=["deidentification_assertion", "expert_determination_report"],
        applicability_questions=_EPHI_APPLICABILITY,
        limitations=[
            "Three of the eighteen Safe Harbor categories — biometric "
            "identifiers (P), full-face images (Q), and any other unique "
            "identifying number, characteristic or code (R) — cannot be "
            "observed by this product at all, so their absence from the "
            "observed list is not evidence that they are absent from the "
            "content.",
            "Several more categories are only partly covered: the three-digit "
            "ZIP population rule is not evaluated, fax and telephone numbers "
            "cannot be told apart, and 'dates related to an individual' is a "
            "judgement about context rather than a pattern.",
            "Names and URLs are detected only when the Presidio/spaCy "
            "classifier is installed. A regex-only deployment does not see them.",
            "Expert determination under §164.514(b)(1) is a qualified person's "
            "analysis. VecShield produces no part of it.",
            _CLASSIFIER_LIMIT, _SCOPE_LIMIT],
        interpretation_notes="Wired to the identifier map in "
                             "vecshield_platform.compliance.hipaa: the "
                             "assessment reports which of the eighteen categories "
                             "were observed, which were looked for and not found, "
                             "and which the product cannot detect. A clean result "
                             "is not a de-identification conclusion, and "
                             "§164.514(b)(2)(ii) actual knowledge is never "
                             "observable from text. The standard is §164.514(a); "
                             "§164.514(b) and (c) are its implementation "
                             "specifications."),
    Criterion(
        id="HIPAA-164-524-ACCESS-01", framework="HIPAA",
        title="A patient's access request reaches data held in the store",
        specification="standard",
        paraphrase="An individual's right-of-access request reaches PHI held in "
                   "the store, including in embeddings.",
        source_ids=["hipaa-164-524"],
        technical_checks=["data_classification", "erasure_verification"],
        manual_evidence=["access_request_procedure", "designated_record_set_definition"],
        applicability_questions=_EPHI_APPLICABILITY,
        limitations=[
            "The subject scan matches the identifier supplied with the request "
            "across registered stores. It finds records that match that "
            "identifier; it does not resolve identity or find records held "
            "under a different identifier.",
            "A store with no per-chunk enumeration API is reported as "
            "inventory-only and is explicitly not searched — that is recorded "
            "as an error, never as 'no matches'.",
            "Incomplete discovery coverage is reported as incomplete. Zero "
            "matches over a partially inspected scope establishes nothing.",
            "Whether the vector store is part of the designated record set, and "
            "what must be produced in response, are determinations under "
            "§164.501 and §164.524 that the entity makes.",
            _SCOPE_LIMIT],
        interpretation_notes="Built on the same discovery path as erasure "
                             "(compliance.dsar). That path was designed to find "
                             "and delete; the right of access is about producing "
                             "a copy, which this product does not assemble."),

    # ---------------- HIPAA Breach Notification, Part 164 Subpart D ---------
    Criterion(
        id="HIPAA-164-402-BREACH-ASSESS-01", framework="HIPAA",
        title="A possible disclosure is risk-assessed before it is dismissed",
        # §164.402 is a definitions section, not a standard.
        specification=None,
        paraphrase="An observed impermissible disclosure is put through the "
                   "four-factor risk assessment before it is dismissed.",
        source_ids=["hipaa-164-402", "hipaa-164-404-b", "hipaa-164-410"],
        technical_checks=["tenant_isolation", "data_classification"],
        manual_evidence=["breach_risk_assessment", "breach_response_procedure"],
        applicability_questions=_EPHI_APPLICABILITY,
        limitations=[
            "The product supplies facts for the first two factors only: the "
            "identifier types observed in the affected content, which bears on "
            "the nature and extent of the PHI and its re-identification risk; "
            "and the retrieval path by which the content was reachable, which "
            "bears on who could have received it.",
            "It cannot speak to the third or fourth factor. Nothing here shows "
            "whether the PHI was actually acquired or viewed, and nothing here "
            "measures the extent to which the risk has been mitigated.",
            "An impermissible disclosure is presumed to be a breach unless the "
            "assessment shows a low probability of compromise. That conclusion "
            "is the entity's, and a scan result is not it.",
            "A cross-tenant probe demonstrates that a retrieval path returned "
            "another tenant's records to this assessment. It does not establish "
            "that a real query ever did.",
            _SAMPLING_LIMIT, _SCOPE_LIMIT],
        interpretation_notes="The demoable case is a cross-tenant bleed in a store "
                             "the classifier found PHI in: an impermissible "
                             "disclosure with an identifier inventory attached. "
                             "The 60-day clock at §164.404(b) and the business "
                             "associate's duty at §164.410 are cited so the "
                             "reviewer sees them; VecShield tracks neither."),

    Criterion(
        id="GDPR-STORAGE-LIMITATION-01", framework="GDPR",
        title="Personal data is not kept for longer than it is needed",
        paraphrase="Personal data in the store is kept in a form permitting "
                   "identification no longer than is necessary, and how long "
                   "it has been held is knowable.",
        source_ids=["gdpr-art-5-1-e"],
        technical_checks=["retention_horizon", "data_classification"],
        manual_evidence=["retention_schedule"],
        applicability_questions=["processes_personal_data_of_eu_subjects",
                                 "controller_or_processor_role"],
        limitations=[
            "VecShield observes the age of records. It does not hold the "
            "retention schedule, the lawful basis, or any legal hold, so it "
            "cannot say whether an age is permitted.",
            "The horizon is read from a timestamp the records carry. Where "
            "none exists the age is unknown, which is reported as such and is "
            "not the same as the data being recent.",
            _SCOPE_LIMIT],
        interpretation_notes=(
            "Art. 5(1)(e) is about necessity, which is a purpose question a "
            "reviewer answers. What this criterion contributes is the fact "
            "the reviewer needs and usually cannot get: how long the data has "
            "actually been in the store, or that nobody can tell."),
    ),
    Criterion(
        id="GDPR-ERASURE-01", framework="GDPR",
        title="Erasure requests reach embeddings, and the result can be verified",
        paraphrase="An erasure request reaches personal data held in embeddings, "
                   "and the outcome is verifiable.",
        source_ids=["gdpr-art-17", "gdpr-art-17-3", "gdpr-art-12-3", "gdpr-art-19",
                    "edpb-cef-2025-erasure"],
        technical_checks=["data_classification", "erasure_verification"],
        manual_evidence=["erasure_procedure", "backup_retention_statement"],
        applicability_questions=["processes_personal_data_of_eu_subjects",
                                 "controller_or_processor_role"],
        limitations=["Deletion from the live index is not evidence of deletion from "
                     "backups, snapshots, or downstream copies.",
                     "Whether an embedding, or the text stored with it, is "
                     "personal data is itself a legal question. The erasure "
                     "check finds records it can link to the identifier "
                     "supplied; a reviewer decides whether what remains is "
                     "personal data.",
                     "Whether an exception under Art. 17(3) applies is a legal "
                     "determination this product does not make.",
                     "The one-month response period under Art. 12(3) and "
                     "informing recipients under Art. 19 are process "
                     "obligations the product does not track.",
                     _SCOPE_LIMIT],
        interpretation_notes="The EDPB's coordinated enforcement report on the "
                             "right to erasure (adopted 2026-02-18) found, among "
                             "other things, that erasure often did not reach "
                             "backups. That is why a backup retention statement "
                             "is asked for. The report is guidance, confirmed "
                             "here from secondary sources only."),
    Criterion(
        id="GDPR-SECURITY-32-01", framework="GDPR",
        title="Personal data in the store is protected from unauthorized access",
        paraphrase="Technical measures protect personal data in the store against "
                   "unauthorised access, including across tenants.",
        source_ids=["gdpr-art-32-1-b", "gdpr-art-5-1-f"],
        technical_checks=["tenant_isolation", *_ACCESS_POSTURE, _GRANTS],
        manual_evidence=["security_measures_description"],
        applicability_questions=["processes_personal_data_of_eu_subjects"],
        limitations=[_SAMPLING_LIMIT, _SCOPE_LIMIT]),
    Criterion(
        id="GDPR-32-1A-ENCRYPTION-01", framework="GDPR",
        title="Personal data is encrypted or pseudonymised as the risk requires",
        specification="risk_based", specification_basis="GDPR Art. 32(1)",
        paraphrase="Personal data in the store is encrypted and pseudonymised as "
                   "appropriate to the risk, or the decision not to is documented.",
        source_ids=["gdpr-art-32-1-a", "gdpr-art-32"],
        technical_checks=["transport_encryption", "at_rest_encryption",
                          "data_representation"],
        fallback_evidence=["encryption_risk_assessment"],
        applicability_questions=["processes_personal_data_of_eu_subjects"],
        limitations=[_TRANSIT_LIMIT, _AT_REST_LIMIT, _CRYPTO_SCOPE_LIMIT,
                     "Representation is read from sampled values: an opaque or "
                     "token-shaped value is a protected representation, not proof "
                     "of a particular algorithm.", _SCOPE_LIMIT],
        interpretation_notes="Risk-based. Article 32 names encryption and "
                             "pseudonymisation among the measures appropriate to "
                             "the risk; it does not mandate them for every store. "
                             "Personal data readable in plaintext is recorded as "
                             "an observed exposure for review, not as a breach."),
    Criterion(
        id="PCI-DSS-3-STORAGE-01", framework="PCI-DSS",
        title="Card numbers are kept out of the store, or protected where present",
        paraphrase="Card account data is kept out of the vector store, or any "
                   "PAN held there is protected so it cannot be read.",
        source_ids=["pci-dss-req-3", "pci-dss-req-3-5-1", "pci-dss-req-3-5-1-2"],
        technical_checks=["data_classification", "pan_representation"],
        manual_evidence=["cde_scope_statement", "tokenization_design"],
        applicability_questions=["stores_processes_or_transmits_account_data",
                                 "system_in_cardholder_data_environment"],
        limitations=[_CLASSIFIER_LIMIT, _SCOPE_LIMIT,
                     "Truncated, tokenized and hashed values are recognised by "
                     "shape. A token-shaped value is not proof that the token "
                     "vault is sound."],
        interpretation_notes="A pattern match is not proof of a live PAN; scope for "
                             "an assessment is set by the entity, not by this scan. "
                             "Storage encryption is shown beside this criterion but "
                             "never satisfies it: under Requirement 3.5.1.2, disk- or "
                             "partition-level encryption alone does not render PAN "
                             "unreadable on non-removable media."),
    Criterion(
        id="PCI-DSS-4-2-1-TRANSMISSION-01", framework="PCI-DSS",
        title="Card numbers sent over public networks are strongly encrypted",
        paraphrase="PAN sent to or from the store over open, public networks is "
                   "protected with strong cryptography.",
        source_ids=["pci-dss-req-4-2-1"],
        technical_checks=["transport_encryption", "transport_tls_enforcement"],
        fallback_evidence=["pan_transmission_statement"],
        applicability_questions=["stores_processes_or_transmits_account_data",
                                 "account_data_transmitted_over_open_public_networks"],
        limitations=[_TRANSIT_LIMIT,
                     "Whether the path to the store crosses an open, public "
                     "network is the entity's determination; the network-exposure "
                     "check informs it but does not make it.", _SCOPE_LIMIT],
        interpretation_notes="Direct where PAN travels over open, public networks. "
                             "The check observes the protocol, not the cipher "
                             "suite's strength beyond what the session reports."),
    Criterion(
        id="SOC2-CC6.1-SECRETS-01", framework="SOC 2",
        title="No credentials or secrets sit in the embedded content",
        paraphrase="Credentials are not stored in the embedded data layer.",
        source_ids=["tsc-cc6-1"],
        technical_checks=["data_classification"],
        manual_evidence=["secret_management_procedure"],
        applicability_questions=["criterion_in_audit_scope",
                                 "system_in_service_boundary"],
        limitations=[_SCOPE_LIMIT],
        interpretation_notes="A SOC 2 conclusion is an auditor's opinion over a "
                             "period. This criterion supports it; it does not reach it."),
    Criterion(
        id="SOC2-CC6.1-ENCRYPTION-01", framework="SOC 2",
        title="Data is encrypted at rest where the risk assessment calls for it",
        specification="risk_based", specification_basis="TSC CC6.1 points of focus",
        paraphrase="Data in the store is encrypted at rest where the entity's "
                   "risk assessment calls for it.",
        source_ids=["tsc-cc6-1"],
        technical_checks=["at_rest_encryption"],
        fallback_evidence=["encryption_policy"],
        applicability_questions=["criterion_in_audit_scope",
                                 "system_in_service_boundary"],
        limitations=[_AT_REST_LIMIT, _CRYPTO_SCOPE_LIMIT, _SCOPE_LIMIT],
        interpretation_notes="Control evidence, not a statute. A point of focus "
                             "discusses encryption at rest based on risk; the "
                             "entity's own control design governs, and the SOC 2 "
                             "conclusion is the auditor's opinion."),
    Criterion(
        id="SOC2-CC6.7-TRANSMISSION-01", framework="SOC 2",
        title="Data in transit is secured where the risk assessment calls for it",
        specification="risk_based", specification_basis="TSC CC6.7 points of focus",
        paraphrase="Data moving to and from the store uses encryption or a secure "
                   "channel where the entity's risk assessment calls for it.",
        source_ids=["tsc-cc6-7"],
        technical_checks=["transport_encryption", "transport_tls_enforcement"],
        fallback_evidence=["transmission_security_policy"],
        applicability_questions=["criterion_in_audit_scope",
                                 "system_in_service_boundary"],
        limitations=[_TRANSIT_LIMIT, _SCOPE_LIMIT],
        interpretation_notes="Control evidence, not a statute. The SOC 2 "
                             "conclusion is the auditor's opinion over a period."),
    Criterion(
        id="SOC2-CC7.2-ANOMALY-01", framework="SOC 2",
        title="Injected or anomalous content is detected and reviewed",
        paraphrase="Anomalous or injected content in the knowledge base is detected "
                   "and reviewed.",
        source_ids=["tsc-cc7-2"],
        technical_checks=["prompt_injection", "embedding_anomaly",
                          "provenance", "rag_integrity"],
        manual_evidence=["monitoring_procedure", "triage_records"],
        applicability_questions=["criterion_in_audit_scope",
                                 "system_in_service_boundary"],
        limitations=["Outlier scoring samples vectors and flags distance, not intent.",
                     _SCOPE_LIMIT]),
    Criterion(
        id="AIACT-ART26-4-INPUT-DATA-01", framework="EU AI Act",
        title="The retrieval corpus fits the AI system's intended purpose",
        aliases=["AIACT-ART10-DATA-GOV-01"],
        paraphrase="Where the deployer controls the retrieval corpus the AI "
                   "system draws on, that input data is relevant to, and "
                   "sufficiently representative for, the system's intended "
                   "purpose.",
        source_ids=["aiact-art-26-4"],
        technical_checks=["data_classification", "rag_integrity",
                          "embedding_consistency"],
        manual_evidence=["data_governance_record"],
        applicability_questions=["system_is_high_risk_ai", "role_provider_or_deployer"],
        limitations=["Whether the system is high-risk is a legal determination, not "
                     "an output of this scan.",
                     "Relevance and representativeness are judged against the "
                     "system's intended purpose, which the product does not "
                     "know. The checks show what the corpus contains and "
                     "whether it has been tampered with; the record supplies "
                     "the purpose.",
                     "The obligation reaches input data only to the extent the "
                     "deployer controls it.",
                     _SCOPE_LIMIT],
        interpretation_notes="Replaces AIACT-ART10-DATA-GOV-01. Art. 10 governs a "
                             "provider's training, validation and testing data; a "
                             "deployer's retrieval corpus is closer to input data "
                             "under Art. 26(4). Art. 10 is kept only as a "
                             "provider-side informational note on its source "
                             "record, and no criterion cites it. Attack "
                             "resilience moved to AIACT-ART15-5-RESILIENCE-01. "
                             "Application dates are per provision and come from "
                             "secondary sources; see the source record."),
    Criterion(
        id="AIACT-ART15-5-RESILIENCE-01", framework="EU AI Act",
        title="The retrieval corpus resists poisoning and injected instructions",
        paraphrase="The retrieval layer of a high-risk AI system is protected "
                   "against attempts to alter its outputs by planting poisoned "
                   "or instruction-bearing content, and such content is "
                   "detected.",
        source_ids=["aiact-art-15-5"],
        technical_checks=["prompt_injection", "embedding_anomaly", "rag_integrity"],
        manual_evidence=["resilience_measures_description"],
        applicability_questions=["system_is_high_risk_ai", "role_provider_or_deployer"],
        limitations=["Whether the system is high-risk is a legal determination, not "
                     "an output of this scan.",
                     "Art. 15 is a requirement on the AI system, and meeting it "
                     "is the provider's obligation. A deployer's scan supplies "
                     "evidence about the corpus it controls; it does not show "
                     "the system as a whole is resilient.",
                     "Outlier scoring samples vectors and flags distance, not "
                     "intent; injection patterns in a chunk do not establish "
                     "that the application would act on them.",
                     _SCOPE_LIMIT],
        interpretation_notes="Art. 15(5) names data poisoning and confidentiality "
                             "attacks among the threats a high-risk system's "
                             "technical solutions address. Poisoned or "
                             "instruction-bearing chunks in a retrieval corpus "
                             "are the observable form of that threat here."),
    Criterion(
        id="CCPA-DELETE-01", framework="CCPA/CPRA",
        title="Consumer deletion requests reach embeddings",
        paraphrase="Consumer deletion requests reach personal information held in "
                   "embeddings.",
        source_ids=["ccpa-1798-105", "ccpa-1798-105-d", "ccpa-regs-7022"],
        technical_checks=["data_classification", "erasure_verification"],
        manual_evidence=["deletion_request_procedure"],
        applicability_questions=["business_subject_to_ccpa",
                                 "data_relates_to_california_residents"],
        limitations=["Whether an exception under Civ. Code § 1798.105(d) applies "
                     "is a legal determination.",
                     "Deletion from the live index says nothing about archived "
                     "or backup copies. Under Cal. Code Regs. tit. 11, "
                     "§ 7022(d), deletion there may be delayed until the backup "
                     "is restored or next used, so a backup still holding the "
                     "data is not by itself a failure.",
                     _SCOPE_LIMIT]),
    Criterion(
        id="CCPA-CYBERAUDIT-ENCRYPTION-01", framework="CCPA/CPRA",
        title="Encryption evidence for the CPPA cybersecurity audit",
        # The regulation names encryption as a component the audit assesses;
        # it is not written as a duty to encrypt, so no specification kind.
        specification=None,
        paraphrase="For a business that must complete the CPPA cybersecurity "
                   "audit, evidence of whether personal information in the store "
                   "is encrypted at rest and in transit is available for the "
                   "audit's encryption component.",
        source_ids=["ccpa-cppa-cyberaudit", "ccpa-1798-150"],
        technical_checks=["transport_encryption", "transport_tls_enforcement",
                          "at_rest_encryption"],
        fallback_evidence=["encryption_program_description"],
        applicability_questions=["business_subject_to_ccpa",
                                 "subject_to_cppa_cybersecurity_audit"],
        limitations=[_TRANSIT_LIMIT, _AT_REST_LIMIT, _CRYPTO_SCOPE_LIMIT,
                     "Whether a business meets the cybersecurity-audit thresholds "
                     "is a legal determination, which is why it is an "
                     "applicability question.", _SCOPE_LIMIT],
        interpretation_notes="An audit component, not a mandate. § 7123(c)(2) "
                             "names encryption at rest and in transit as "
                             "something the cybersecurity audit assesses where "
                             "applicable; it does not require the business to "
                             "encrypt. A plaintext finding here is evidence the "
                             "auditor will weigh, not a legal breach. Civil Code "
                             "§1798.150 ties the private right of action to "
                             "nonencrypted and nonredacted personal information; "
                             "that is supporting context, not a separate "
                             "mandate. An independent auditor reaches the "
                             "audit's conclusion."),
    Criterion(
        id="CCPA-CYBERAUDIT-ACCESS-01", framework="CCPA/CPRA",
        title="Access-control evidence for the CPPA cybersecurity audit",
        paraphrase="For a business that must complete the CPPA cybersecurity "
                   "audit, evidence of how access to personal information in the "
                   "store is authenticated and separated between tenants is "
                   "available for the audit's access-control component.",
        source_ids=["ccpa-regs-7123-c-3"],
        technical_checks=["tenant_isolation", "authentication"],
        manual_evidence=["authorized_access_policy"],
        applicability_questions=["business_subject_to_ccpa",
                                 "subject_to_cppa_cybersecurity_audit"],
        limitations=[_SAMPLING_LIMIT, _POSTURE_LIMIT,
                     "Whether a business meets the cybersecurity-audit thresholds "
                     "is a legal determination, which is why it is an "
                     "applicability question.", _SCOPE_LIMIT],
        interpretation_notes="An audit component, not a mandate. § 7123(c)(3) "
                             "names account management and access controls as "
                             "something the audit assesses where applicable. "
                             "The checks read the store's authentication and "
                             "tenant separation; account management across the "
                             "business is outside them."),
]

_BY_ID = {criterion.id: criterion for criterion in CRITERIA}

#: Retired criterion id -> the criterion that absorbed it. Stored evidence
#: reviews, exceptions and reviewer decisions reference criterion ids as plain
#: strings, so a rename would orphan them. Lookups resolve through this map;
#: the pack itself lists only current ids.
CRITERION_ALIASES: dict[str, str] = {
    alias: criterion.id for criterion in CRITERIA for alias in criterion.aliases
}


def get_criterion(criterion_id: str) -> Optional[Criterion]:
    """Resolve a criterion id, following a retired id to its successor."""
    criterion = _BY_ID.get(criterion_id)
    if criterion is not None:
        return criterion
    successor = CRITERION_ALIASES.get(criterion_id)
    return _BY_ID.get(successor) if successor else None


def resolve_criterion_id(criterion_id: str) -> Optional[str]:
    """Return the current id for a possibly-retired one, or None if unknown."""
    if criterion_id in _BY_ID:
        return criterion_id
    return CRITERION_ALIASES.get(criterion_id)


def criteria_for(framework: Optional[str] = None) -> list[Criterion]:
    if framework is None:
        return list(CRITERIA)
    wanted = framework.casefold()
    return [c for c in CRITERIA if c.framework.casefold() == wanted]


#: Provisions the plan's citation audit named as obligations a vector store
#: bears on that no criterion in this pack evaluates yet. Listed so their
#: absence is visible rather than inferred from silence.
COVERAGE_GAPS: list[dict[str, str]] = [
    {"source_id": "pci-dss-req-3-3-1", "framework": "PCI-DSS",
     "reason": "Card verification codes pasted into support chats can end up "
               "embedded. No detector in this product recognises sensitive "
               "authentication data reliably enough to evaluate it yet."},
    {"source_id": "pci-dss-req-3-2-1", "framework": "PCI-DSS",
     "reason": "Retention of stored account data is a policy question; the "
               "record-age check has not been mapped to it."},
]

#: Proposed rules the pack does not evaluate against, shown so a reader knows
#: they are being followed. None of them binds anyone yet.
TRACKED_PROPOSALS = ["hipaa-security-nprm-2025"]


def _lifecycle_fields(criteria: Iterable[Criterion]) -> dict[str, Any]:
    """The lifecycle block shared by every pack manifest.

    ``lifecycle`` is derived from the least-advanced criterion, never written
    by hand. ``regulatory_review`` stays None until a content review applies
    to at least one criterion.
    """
    derived = pack_lifecycle(criteria)
    return {
        "lifecycle": derived["state"],
        "lifecycle_label": derived["label"],
        "lifecycle_by_state": derived["by_state"],
        "lifecycle_labels": dict(LIFECYCLE_LABELS),
        "content_reviews": derived["content_reviews"],
        "regulatory_review": derived["content_reviews"] or None,
        "mapping_hint": derived["hint"],
        "qualified_reviewers": dict(QUALIFIED_REVIEWER),
    }


def pack_manifest() -> dict[str, Any]:
    """Describe the pack itself, including what it does not claim."""
    return {
        "pack_version": PACK_VERSION,
        "criteria": len(CRITERIA),
        "frameworks": sorted({c.framework for c in CRITERIA}),
        **_lifecycle_fields(CRITERIA),
        "retired_criterion_ids": dict(sorted(CRITERION_ALIASES.items())),
        "manual_evidence_only": sorted(c.id for c in CRITERIA
                                       if c.manual_evidence_only),
        "coverage_gaps": [{**gap, "source": resolve_sources([gap["source_id"]])[0]}
                          for gap in COVERAGE_GAPS],
        "tracked_proposals": resolve_sources(TRACKED_PROPOSALS),
        "note": ("Authored alongside the detection rules and not reviewed by a "
                 "lawyer or other qualified reviewer. Criteria cover only "
                 "obligations a vector-store assessment can observe."),
    }


#: HIPAA obligations this pack deliberately does not reach. Naming them is
#: more honest than leaving a reader to infer coverage from silence, and it is
#: the list a reviewer needs in order to know what they still have to do
#: elsewhere. Each entry says what is out of scope and why.
HIPAA_NOT_COVERED: list[dict[str, str]] = [
    {"topic": "Workforce security and clearance",
     "section": "45 CFR 164.308(a)(3)",
     "reason": "Authorization, supervision, clearance and termination "
               "procedures are personnel processes. Nothing about a vector "
               "store observes them."},
    {"topic": "Security awareness and training",
     "section": "45 CFR 164.308(a)(5)",
     "reason": "Training delivery and completion live in an HR or LMS system, "
               "not in the data layer."},
    {"topic": "Sanction policy",
     "section": "45 CFR 164.308(a)(1)(ii)(C)",
     "reason": "A disciplinary policy and its application are outside the "
               "product entirely."},
    {"topic": "Contingency planning, backup and disaster recovery",
     "section": "45 CFR 164.308(a)(7)",
     "reason": "VecShield does not inspect backups, test restores, or observe "
               "an emergency mode operation plan. It can only say that "
               "deletion from a live index says nothing about backups."},
    {"topic": "Physical safeguards other than disposal",
     "section": "45 CFR 164.310",
     "reason": "Facility access, workstation use and workstation security are "
               "physical controls. Only the disposal specification at "
               "§164.310(d)(2)(i) is reached, because whether a retired vector "
               "index still holds recoverable content is observable."},
    {"topic": "Breach notification to individuals and the 60-day clock",
     "section": "45 CFR 164.404(b)",
     "reason": "VecShield does not track discovery dates, start a clock, or "
               "manage notification. The provision is cited on "
               "HIPAA-164-402-BREACH-ASSESS-01 so a reviewer sees it, not "
               "because the product assesses it."},
    {"topic": "Business associate notification to the covered entity",
     "section": "45 CFR 164.410",
     "reason": "The duty runs between organizations. Cited for the same "
               "reason as above; not assessed."},
    {"topic": "Notification to the Secretary and to the media",
     "section": "45 CFR 164.406, 164.408",
     "reason": "Reporting workflows outside the product."},
    {"topic": "Notice of privacy practices",
     "section": "45 CFR 164.520",
     "reason": "A published notice is a document about the entity, not a "
               "property of a store."},
    {"topic": "Accounting of disclosures",
     "section": "45 CFR 164.528",
     "reason": "Deliberately excluded. Nothing in this product records "
               "disclosures of PHI from the store: no connector exposes query "
               "logs, and VecShield's own audit log covers actions taken in "
               "VecShield. A criterion here would have no observing check and "
               "no artifact the product helps produce."},
    {"topic": "Amendment of PHI",
     "section": "45 CFR 164.526",
     "reason": "Amendment workflows run against the source record system."},
    {"topic": "Authorizations and uses beyond minimum necessary",
     "section": "45 CFR 164.508",
     "reason": "Whether a use or disclosure is permitted is a legal "
               "determination about purpose, not about content."},
]


def hipaa_pack_manifest(
        stores: Optional[Iterable[dict[str, Any]]] = None) -> dict[str, Any]:
    """The HIPAA slice of the pack, with its coverage boundary stated.

    ``stores`` are registered-store mappings with a ``kind`` (and optionally a
    ``store_id``). When supplied, the manifest names the vendors that estate
    implies a business associate contract is needed for. Pure: no store is
    opened and no scan is run.
    """
    hipaa = criteria_for("HIPAA")
    manifest: dict[str, Any] = {
        "pack_version": PACK_VERSION,
        "framework": "HIPAA",
        "criteria": len(hipaa),
        "criterion_ids": [c.id for c in hipaa],
        "by_specification": {
            kind: sorted(c.id for c in hipaa if c.specification == kind)
            for kind in ("standard", "required", "addressable")},
        # Criteria anchored on a definitions section (§164.402) rather than a
        # standard or implementation specification.
        "no_specification": sorted(c.id for c in hipaa if c.specification is None),
        "manual_evidence_only": sorted(c.id for c in hipaa
                                       if c.manual_evidence_only),
        "retired_criterion_ids": {alias: target
                                  for alias, target in CRITERION_ALIASES.items()
                                  if target in {c.id for c in hipaa}},
        "safe_harbor": safe_harbor_manifest(),
        "not_covered": list(HIPAA_NOT_COVERED),
        **_lifecycle_fields(hipaa),
        "tracked_proposals": resolve_sources(TRACKED_PROPOSALS),
        "note": ("Criteria reach the Security Rule safeguards, the minimum "
                 "necessary and de-identification provisions of the Privacy "
                 "Rule, the right of access, and the breach risk assessment — "
                 "and only as far as a vector-store assessment observes them. "
                 "Everything in 'not_covered' is out of scope on purpose. "
                 "Addressable specifications are not optional: see "
                 "45 CFR 164.306(d). This pack has had no regulatory review."),
    }
    if stores is not None:
        manifest["business_associates"] = business_associate_exposure(stores)
    return manifest
