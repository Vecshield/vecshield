"""What the pack's identifiers mean, in words a reviewer can act on.

Criteria name the artifacts they need and the questions that decide whether
they apply as identifiers (``business_associate_agreements``,
``system_handles_ephi``). This module is the one place those identifiers are
explained, so every surface that shows them — the Criteria and Evidence
screens, the framework reference, an exported position — says the same thing.

For each artifact type it records:

``label``
    A short name.
``what``
    One sentence saying what the document is.
``examples``
    Concrete documents that would typically be put forward, phrased for a
    vector store. They are illustrations, not a checklist: whether a given
    document suffices is a reviewer's decision about that document.
``reviewer_checks``
    What a reviewer should look for in *this* kind of document before
    accepting it for a criterion, beyond the checks every artifact needs
    (right scope, right period, current version, sound provenance).

Everything here is presentation. None of it changes how a criterion is
evaluated, and none of it is part of the digest a stored reviewer decision is
bound to. The wording is VecShield's own and has had no regulatory review.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class EvidenceType:
    """One kind of artifact a criterion can ask for."""

    label: str
    what: str
    examples: tuple[str, ...]
    reviewer_checks: str

    def to_dict(self) -> dict[str, Any]:
        return {"label": self.label, "what": self.what,
                "examples": list(self.examples),
                "reviewer_checks": self.reviewer_checks}


@dataclass(frozen=True)
class ApplicabilityQuestion:
    """A yes/no question that decides whether a criterion reaches a store."""

    question: str
    help: str

    def to_dict(self) -> dict[str, Any]:
        return {"question": self.question, "help": self.help}


E = EvidenceType

EVIDENCE_TYPES: dict[str, EvidenceType] = {
    # ---- access -------------------------------------------------------------
    "authorized_access_policy": E(
        "Authorized access policy",
        "The policy stating which people, services and tenants may read the store, "
        "and on what basis access is granted.",
        ("An access-control policy that names the retrieval store and the roles "
         "allowed to query it",
         "A role matrix mapping service accounts to the collections they may read"),
        "It names this store or its collections, not only 'production systems'; "
        "it covers service accounts and applications, not just people."),
    "access_review_record": E(
        "Access review record",
        "A dated record that someone compared who actually has access to the "
        "store against the access policy, and what they changed.",
        ("A quarterly access review export listing every principal on the store, "
         "signed off by its owner",
         "A ticket closing out removed grants after a periodic review"),
        "It is dated inside the period under review and lists actual grants on "
        "this store, with the reviewer's sign-off and any removals."),
    "authentication_configuration": E(
        "Authentication configuration",
        "Evidence of how the store authenticates clients: the mechanism, and that "
        "unauthenticated access is off.",
        ("A configuration export showing API-key or mTLS authentication enabled "
         "on the store",
         "A screenshot of the managed service's auth settings with anonymous "
         "access disabled"),
        "It shows the configuration of this deployment, not the vendor's "
        "documentation of what is possible."),

    # ---- risk, inventory and evaluation ------------------------------------
    "ephi_inventory": E(
        "ePHI inventory",
        "A list of where electronic protected health information is held, "
        "including this store, its collections and the embeddings built from them.",
        ("A data inventory entry naming the vector store and each collection that "
         "holds clinical text",
         "A data-flow map showing patient notes flowing into the retrieval index"),
        "The store and its embeddings appear as a location in their own right, "
        "not only the source system the text came from."),
    "risk_analysis": E(
        "Risk analysis",
        "The organization's security risk analysis, showing that risks to health "
        "data in this store were identified and rated.",
        ("A HIPAA risk analysis with a line item for the retrieval corpus and its "
         "embeddings",
         "A risk register entry covering unauthorized retrieval from the vector store"),
        "It is current for the period and addresses this store specifically; an "
        "enterprise analysis that never mentions it does not cover it."),
    "risk_management_plan": E(
        "Risk management plan",
        "The plan for reducing the risks the analysis found to a reasonable level, "
        "with owners and dates.",
        ("A remediation plan with owners for the risks rated for the vector store",
         "Risk treatment decisions recorded against the retrieval corpus"),
        "Risks identified for this store have a treatment, an owner and a status."),
    "evaluation_schedule": E(
        "Evaluation schedule",
        "The schedule on which the store's safeguards are re-evaluated, and what "
        "triggers an unscheduled evaluation.",
        ("A security evaluation calendar listing the vector store with its "
         "review frequency",
         "A change-management rule that triggers re-assessment when the store "
         "is reconfigured"),
        "It names a frequency or trigger that reaches this store."),
    "prior_evaluation_record": E(
        "Previous evaluation record",
        "The record of the last evaluation of the store's safeguards, showing "
        "that evaluations actually recur.",
        ("Last year's saved assessment report for the store, with sign-off",
         "A prior audit snapshot and the decisions taken on it"),
        "It is an earlier evaluation than the one now under review, so together "
        "they show a recurring programme."),

    # ---- incidents and breach ----------------------------------------------
    "incident_response_procedure": E(
        "Incident response procedure",
        "How suspected security incidents, including ones found in the retrieval "
        "layer, are triaged, escalated and closed.",
        ("An incident runbook that covers cross-tenant retrieval and injected "
         "content",
         "An on-call procedure naming who triages a VecShield isolation failure"),
        "It covers incidents in the retrieval layer, not only infrastructure "
        "outages."),
    "incident_records": E(
        "Incident records",
        "Records of suspected incidents in the period and what was decided about "
        "each, including ones dismissed.",
        ("Incident tickets for findings from the last assessment, with outcomes",
         "A log showing a failed isolation probe was triaged and closed"),
        "Each record has an outcome and a date inside the period; an empty log "
        "needs an explanation of how incidents would have been found."),
    "breach_risk_assessment": E(
        "Breach risk assessment",
        "The four-factor assessment of whether an impermissible disclosure is a "
        "reportable breach.",
        ("A completed four-factor assessment for a cross-tenant retrieval finding",
         "A privacy officer's memo concluding low probability of compromise, with "
         "the reasons"),
        "All four factors are addressed, including the two a scan cannot speak "
        "to: whether the data was actually viewed, and how far risk was mitigated."),
    "breach_response_procedure": E(
        "Breach response procedure",
        "How a suspected breach is assessed, decided and, where required, "
        "notified, including who owns each step.",
        ("A breach notification procedure with the 60-day timeline and owners",
         "A business associate's procedure for notifying the covered entity"),
        "It assigns owners and deadlines and covers disclosures found in the "
        "retrieval layer."),

    # ---- vendors -----------------------------------------------------------
    "business_associate_agreements": E(
        "Business associate agreements",
        "Signed contracts with each vendor that holds health data in this estate, "
        "including the vector-database provider.",
        ("A signed BAA with the managed vector-database vendor that names the "
         "retrieval corpus or service",
         "A BAA with the embedding-model provider, if text is sent to it"),
        "It is executed by both parties, in force for the period, and names the "
        "vendor and service that actually holds the data."),
    "vendor_inventory": E(
        "Vendor inventory",
        "The list of vendors that store or process health data for this system, "
        "with the contract that covers each.",
        ("A vendor register listing the vector-database provider and its BAA status",
         "A subprocessor list for the retrieval pipeline"),
        "Every vendor the connector estate implies is listed, including any "
        "service that backs a managed store."),

    # ---- disposal and erasure ----------------------------------------------
    "disposal_procedure": E(
        "Disposal procedure",
        "How health data is removed from the store when no longer needed, "
        "including deleting the vectors built from it.",
        ("A retention and disposal procedure that says vectors are deleted with "
         "their source chunks",
         "A runbook for decommissioning a collection"),
        "It covers the vectors and metadata, not just the source documents."),
    "backup_retention_statement": E(
        "Backup retention statement",
        "How long backups, snapshots and replicas keep data after it is deleted "
        "from the live index.",
        ("The vector database's snapshot retention setting and schedule",
         "A statement that backups expire after 35 days and are not restored "
         "selectively"),
        "It gives a concrete retention period for this store's backups and "
        "snapshots, not a general policy."),
    "erasure_procedure": E(
        "Erasure procedure",
        "The documented steps an erasure request follows, including finding and "
        "deleting the person's data in the vector index.",
        ("A data-subject request procedure with a step for searching and deleting "
         "embeddings",
         "A runbook referencing VecShield's subject search and erasure receipt"),
        "It reaches the vector store explicitly and says how completion is "
        "verified."),
    "deletion_request_procedure": E(
        "Deletion request procedure",
        "How a consumer's deletion request reaches personal information held in "
        "the store, including embeddings.",
        ("A CCPA request-handling procedure that includes the retrieval index",
         "A privacy operations runbook with a vector-store deletion step"),
        "It reaches the vector store and records statutory exemptions applied."),
    "access_request_procedure": E(
        "Access request procedure",
        "How an individual's request for a copy of their information is fulfilled "
        "when some of it is held in the store.",
        ("A right-of-access procedure that includes searching the retrieval corpus",
         "A request-handling runbook with a vector-store lookup step"),
        "It says whether the store is searched and how a copy is produced."),
    "designated_record_set_definition": E(
        "Designated record set definition",
        "The organization's definition of which systems make up the designated "
        "record set, and whether this store is one of them.",
        ("A records policy stating whether the retrieval corpus is part of the "
         "designated record set, and why",),
        "It takes a position on this store specifically."),

    "retention_schedule": E(
        "Retention schedule",
        "How long each kind of personal data may be kept, and what happens to "
        "it at the end of that period, including in the vector store.",
        ("A records-retention schedule with an entry for the retrieval corpus "
         "and its embeddings",
         "A deletion job configuration that expires chunks older than the "
         "retention period"),
        "It sets a period for the data in this store and says how expiry "
        "reaches the vectors, not only the source documents."),

    # ---- documentation -----------------------------------------------------
    "documentation_retention_policy": E(
        "Documentation retention policy",
        "How long assessments, evidence and decisions are kept, and where.",
        ("A records-retention schedule keeping security documentation for six "
         "years",
         "A policy covering retention of VecShield's history database"),
        "The period meets the framework's minimum and covers the assessment "
        "records VecShield produces."),

    # ---- corpus purpose and de-identification ------------------------------
    "corpus_purpose_statement": E(
        "Corpus purpose statement",
        "What the retrieval corpus is for, and therefore what content belongs in it.",
        ("A product brief stating the assistant answers clinical-guideline "
         "questions and needs no patient records",),
        "It is specific enough to judge whether observed content is outside the "
        "purpose."),
    "minimum_necessary_policy": E(
        "Minimum necessary policy",
        "The policy limiting the health data used to what a purpose needs.",
        ("A minimum-necessary policy with a section on data used for AI retrieval",),
        "It applies to data fed into retrieval systems, not only to disclosures."),
    "deidentification_assertion": E(
        "De-identification assertion",
        "A statement that the corpus is de-identified, naming the method used.",
        ("A data-preparation record stating Safe Harbor was applied before "
         "embedding, with the tool and date",),
        "It names the method and date and covers the collections in scope; it "
        "is weighed against what the scan observed."),
    "expert_determination_report": E(
        "Expert determination report",
        "A qualified expert's analysis concluding that re-identification risk is "
        "very small.",
        ("A statistician's expert determination covering the corpus and its "
         "embeddings",),
        "It is signed by the expert, covers this data set, and is still in date."),

    # ---- integrity and monitoring ------------------------------------------
    "ingest_controls_description": E(
        "Ingest controls description",
        "How content is vetted, attributed and approved before it is embedded.",
        ("A pipeline design showing source allow-lists and provenance metadata "
         "on ingest",),
        "It shows controls that would stop or attribute injected content."),
    "integrity_review_records": E(
        "Integrity review records",
        "Records showing flagged content was reviewed and resolved.",
        ("Tickets resolving injection and anomaly findings from the last scan",),
        "Findings from the period have outcomes, not just acknowledgements."),
    "monitoring_procedure": E(
        "Monitoring procedure",
        "How anomalous or injected content is detected and escalated on an "
        "ongoing basis.",
        ("A monitoring runbook with scan frequency and escalation path",),
        "It describes ongoing detection; a single scan is not monitoring."),
    "triage_records": E(
        "Triage records",
        "Records showing detections were reviewed and resolved.",
        ("A findings export with case states and owners for the period",),
        "Detections in the period have owners and outcomes."),
    "store_audit_log_configuration": E(
        "Store audit-log configuration",
        "Evidence that the vector store records who queried and changed it.",
        ("The database's audit-logging settings, with retention",
         "A log-shipping configuration sending store logs to the SIEM"),
        "Logging is on for this deployment and captures reads, not only admin "
        "actions."),
    "log_review_record": E(
        "Log review record",
        "A record that the store's logs were examined, by whom, and what was found.",
        ("A monthly log-review sign-off covering the vector store",),
        "It is dated in the period and covers this store's logs."),
    "data_governance_record": E(
        "Data governance record",
        "The record of how the AI system's input data is sourced, prepared and "
        "checked against the system's intended purpose.",
        ("A data governance sheet for the retrieval corpus: sources, preparation, "
         "known gaps",
         "A data sheet naming the corpus, its provenance and the intended purpose "
         "it serves"),
        "It covers the retrieval corpus, not only training data, and states the "
        "intended purpose the corpus is judged against."),
    "resilience_measures_description": E(
        "Resilience measures description",
        "How the retrieval layer is protected against poisoned or "
        "instruction-bearing content, and how such content is found and removed.",
        ("An ingest design with source allow-lists, content scanning and "
         "quarantine",
         "The provider's documentation of its resilience measures, with the "
         "deployer's own controls on the corpus"),
        "It covers the retrieval corpus and names who is responsible for each "
        "measure, provider or deployer."),

    # ---- security measures and secrets -------------------------------------
    "security_measures_description": E(
        "Security measures description",
        "The technical and organizational measures protecting personal data in "
        "the store.",
        ("An Article 32 measures document with a section on the vector store",
         "A security architecture note covering tenant isolation"),
        "It describes measures for this store, including tenant separation."),
    "secret_management_procedure": E(
        "Secret management procedure",
        "How credentials are issued and stored, and how they are kept out of "
        "embedded content.",
        ("A secrets policy requiring a vault, with a pre-ingest secret scan",),
        "It includes a control that keeps secrets out of documents before they "
        "are embedded."),

    # ---- payments ----------------------------------------------------------
    "cde_scope_statement": E(
        "CDE scope statement",
        "Whether this store is inside the cardholder data environment, and why.",
        ("A PCI scoping document that lists the vector store in or out of scope, "
         "with the reasoning",),
        "It is current and mentions the vector store; a scope that predates the "
        "store does not cover it."),
    "tokenization_design": E(
        "Tokenization design",
        "How account data is tokenized or rendered unreadable before it is "
        "embedded.",
        ("A design document showing card numbers replaced with tokens before "
         "ingest",),
        "It shows where in the pipeline card numbers are replaced, before "
        "embedding."),
    "pan_transmission_statement": E(
        "Card-number transmission statement",
        "How card numbers travelling to and from the store are protected over "
        "open, public networks.",
        ("A network diagram and TLS configuration for traffic to the store",),
        "It shows strong cryptography on every public path, not only "
        "VecShield's connection."),

    # ---- encryption statements (fallback evidence) -------------------------
    "encryption_at_rest_statement": E(
        "Encryption-at-rest statement",
        "How data in the store is encrypted at rest, where the store itself does "
        "not report it.",
        ("The cloud volume encryption settings and key-management configuration "
         "for the store's disks",
         "The managed vendor's attestation that storage is encrypted with a "
         "named key"),
        "It covers this deployment's storage, names the mechanism and key "
        "custody, and is not just a vendor marketing page."),
    "transport_security_statement": E(
        "Transport security statement",
        "How connections to the store are encrypted or otherwise protected, where "
        "the check could not establish it.",
        ("A TLS configuration requiring encryption for every client",
         "A private-network design showing the store is reachable only inside a VPC"),
        "It covers all clients of the store, not only VecShield's connection."),
    "encryption_risk_assessment": E(
        "Encryption risk assessment",
        "The risk assessment deciding which encryption and pseudonymisation "
        "measures apply to this store.",
        ("An Article 32 risk assessment concluding which fields are encrypted or "
         "pseudonymised, and why",),
        "It reaches a decision for this store and gives reasons."),
    "encryption_policy": E(
        "Encryption policy",
        "The organization's encryption-at-rest policy and how this store meets it.",
        ("An encryption standard plus the store's configuration showing it is met",),
        "It connects the policy to this store's actual configuration."),
    "transmission_security_policy": E(
        "Transmission security policy",
        "The policy for encrypting or securing data in transit to this store.",
        ("A transport security standard requiring TLS 1.2+ for data services",),
        "It applies to this store's connections."),
    "encryption_program_description": E(
        "Encryption program description",
        "The encryption program described for the cybersecurity audit, covering "
        "this store.",
        ("The encryption section of the CPPA cybersecurity audit, naming the store",),
        "It names the store and covers both at rest and in transit."),

    # ---- retention against a declared schedule ----------------------------
    "data_retention_policy": E(
        "Data retention policy",
        "The policy that sets how long account data is kept, with the business "
        "reason for each period and how disposal happens at the end of it.",
        ("A retention and disposal policy with a line for card data held in the "
         "retrieval corpus and its embeddings",
         "A data-retention standard naming the vector store as a location covered"),
        "It sets a period and a business reason for the data in this store, and "
        "says how disposal reaches the vectors as well as the source documents."),
    "quarterly_deletion_evidence": E(
        "Quarterly deletion evidence",
        "A record, made at least every three months, that data past its "
        "retention period was found and securely deleted or made unrecoverable.",
        ("Saved VecShield assessments from each quarter showing no records older "
         "than the declared maximum, with the deletion tickets in between",
         "A quarterly disposal job report naming the store and the records removed"),
        "There is one per quarter in the period, each dated, and each covers this "
        "store; a single clean scan is one quarter, not the process."),

    # ---- vulnerability and patch management -------------------------------
    "vulnerability_management_procedure": E(
        "Vulnerability management procedure",
        "How new vulnerabilities in the database server and its libraries are "
        "found, ranked by risk and fixed within set timeframes.",
        ("A procedure that subscribes to the database vendor's advisories and the "
         "CISA known-exploited catalog, with fix deadlines by severity",
         "A patch-management standard naming the vector database as an asset in "
         "scope"),
        "It names sources for new advisories, a way to rank them, and deadlines, "
        "and the vector database is covered by it."),
    "patch_records": E(
        "Patch records",
        "Records of the updates applied to the database server in the period, "
        "with dates, versions and the advisories they closed.",
        ("Change tickets upgrading the vector database, each naming the version "
         "installed and the advisories fixed",
         "A deployment history showing the server moved to a fixed release within "
         "the deadline"),
        "Dates show critical fixes went in within the procedure's deadline, and "
        "the versions match what the store reports now."),
    "provider_patching_statement": E(
        "Provider patching statement",
        "For a managed service, the provider's statement of how and how quickly "
        "it patches the database; for a self-hosted store the scan could not "
        "read, the version actually running.",
        ("The managed vendor's security documentation on patching and its latest "
         "independent audit report",
         "An operator's note of the server version, read from the host, with the "
         "date it was read"),
        "It covers this service or this deployment, and is current for the "
        "period."),
    "software_support_inventory": E(
        "Software support inventory",
        "The yearly review of the software in use, showing each component still "
        "receives security fixes and what the plan is for any that will not.",
        ("An annual technology review listing the vector database, its release "
         "line and that line's end-of-support date",
         "A migration plan for a database release line reaching end of life"),
        "It is no more than a year old, lists this store's database and release "
        "line, and has a dated plan for anything past or near end of support."),

    # ---- processors, model providers and transfers -----------------------
    "sub_processor_register": E(
        "Sub-processor register",
        "The list of processors and model providers that receive personal data "
        "from this system, with what they receive and under which contract.",
        ("A processor register with the embedding and reranking providers the "
         "store's own model modules call",
         "A record of processing activities naming each model provider as a "
         "recipient"),
        "Every provider the store sends text to is listed, including ones "
        "called by the database's own model modules, not only by the "
        "application."),
    "data_processing_agreement": E(
        "Data processing agreement",
        "The signed contract with a processor that sets out what it may do with "
        "the personal data it receives.",
        ("The model provider's data processing addendum, signed and in force",
         "A processor contract naming the embedding service and its "
         "sub-processors"),
        "It is signed, in force for the period, and covers the service the store "
        "actually calls."),
    "business_associate_agreement": E(
        "Business associate agreement",
        "The signed contract with one vendor, such as a model provider, that "
        "receives health data from this store.",
        ("A BAA with the embedding provider the store's vectorizer module calls",),
        "It is executed, in force for the period, and names the service that "
        "receives the data."),
    "model_integration_configuration": E(
        "Model integration configuration",
        "The configuration of the database's own model modules: which provider "
        "each calls, from which collections, and with which credentials.",
        ("An export of the vectorizer and reranker modules enabled on the store",
         "The store's model-integration settings showing no module is enabled"),
        "It is taken from this deployment and names every enabled module, or "
        "shows none is."),
    "transfer_mechanism": E(
        "Transfer mechanism",
        "The legal basis relied on for sending personal data from this store to "
        "a country outside the protected area, such as an adequacy decision or "
        "standard contractual clauses.",
        ("Signed standard contractual clauses with the provider hosting a replica "
         "outside the EEA, with the transfer impact assessment",
         "A note that every location is inside the EEA, so no transfer "
         "mechanism is needed"),
        "It names the destination and the mechanism, and the mechanism covers "
        "the provider that actually receives the data."),
    "data_residency_statement": E(
        "Data residency statement",
        "Where the store's data, its replicas and backups are held, where the "
        "scan could not read the location itself.",
        ("The cloud region and replica settings of a self-hosted cluster",
         "The managed vendor's statement of the region the index is held in"),
        "It names regions or countries for the primary copy, replicas and "
        "backups of this store."),
    "residency_policy": E(
        "Residency policy",
        "The organization's rule for where this store's data may be held and "
        "processed.",
        ("A data-residency standard allowing EU regions only for customer data",),
        "It names permitted regions or countries and applies to this store."),
    "country_of_concern_access_assessment": E(
        "Country-of-concern access assessment",
        "An assessment of whether any person or vendor tied to a country of "
        "concern can reach bulk sensitive data in this store, as the US "
        "Department of Justice data security rule asks.",
        ("A review of vendors, employees and investors with access to the store "
         "against the rule's list of countries of concern",),
        "It covers everyone with access to the store, including vendors, and "
        "says how access is restricted where the rule applies."),

    # ---- accuracy and versions -------------------------------------------
    "rectification_procedure": E(
        "Rectification procedure",
        "How corrected or completed personal data replaces the inaccurate "
        "version everywhere it is held, including in the retrieval index.",
        ("A data-subject request procedure with a step that re-ingests corrected "
         "records and deletes the old chunks",),
        "It reaches the vector store and says how the old version stops being "
        "retrievable."),
    "document_update_procedure": E(
        "Document update procedure",
        "How a changed source document replaces its old chunks in the store, "
        "where the chunks carry no version the scan can read.",
        ("An ingestion design that deletes a document's chunks before loading "
         "the new version",
         "A pipeline setting that upserts chunks by stable document and position "
         "ids"),
        "It shows the old version is removed or superseded, not left alongside "
        "the new one."),

    # ---- biometric templates ---------------------------------------------
    "biometric_consent_records": E(
        "Biometric consent records",
        "Records of notice and consent, or of the other legal condition relied "
        "on, for the people whose face or voice templates the store holds.",
        ("Signed written releases for every enrolled person",
         "The record of the Article 9(2) condition relied on, with its scope"),
        "They cover every enrolled person, predate enrolment, and match the "
        "purpose the templates are used for."),
    "biometric_retention_schedule": E(
        "Biometric retention schedule",
        "The published schedule for destroying face or voice templates when "
        "their purpose is met, and no later than the legal limit.",
        ("A public retention schedule for voiceprints with a destruction deadline",
         "A retention rule for the template collection declared in VecShield"),
        "It is published where the law requires, sets a deadline, and reaches "
        "the template collection."),
    "data_protection_impact_assessment": E(
        "Data protection impact assessment",
        "The assessment of the risks of a processing operation to the people "
        "concerned, and the measures that address them.",
        ("A DPIA covering the face-matching service and its template store",),
        "It covers the processing this store supports and was completed before "
        "the processing began."),
    "face_image_provenance_record": E(
        "Face image provenance record",
        "Where the face images behind the stored templates came from, showing "
        "they were not gathered by untargeted scraping of the internet or CCTV "
        "footage.",
        ("An enrolment log showing each template came from a person who enrolled "
         "directly",
         "A note that the collection holds voice templates only, with no face "
         "images"),
        "It covers every source that fed the collection, including any bulk "
        "import."),

    # ---- CCPA risk assessments and cybersecurity audit -------------------
    "risk_assessment_report": E(
        "Risk assessment report",
        "The CCPA risk assessment report for the processing this store supports: "
        "purpose, categories of personal information, retention, recipients, "
        "negative impacts, safeguards, and who approved it.",
        ("The risk assessment report VecShield drafts for the store, completed "
         "and approved by the business",
         "A data protection assessment prepared for another law, with the items "
         "the CCPA adds"),
        "It covers this processing, was approved before the processing began, "
        "and its safeguards match what the scan observed."),
    "ccpa_7150_determination": E(
        "Risk assessment trigger determination",
        "The business's recorded decision on which significant-risk activities "
        "in the CCPA regulations the store's processing involves.",
        ("A memo recording that the corpus holds sensitive personal information, "
         "so a risk assessment is required",),
        "It takes a position on each trigger that could apply, including "
        "sensitive personal information and biometric identification."),
    "risk_assessment_review_record": E(
        "Risk assessment review record",
        "A record that the risk assessment was reviewed at least every three "
        "years, and updated within 45 days of a material change.",
        ("A dated review of the corpus risk assessment after a new model provider "
         "was added",),
        "It is dated, names what changed, and falls within the time limits."),
    "risk_assessment_submission_record": E(
        "Risk assessment submission record",
        "The record of the risk assessment information the business filed with "
        "the California Privacy Protection Agency, and who attested to it.",
        ("The agency filing confirmation for the period, with the executive who "
         "attested",),
        "It covers the period, and the person who attested is a member of the "
        "executive team."),
    "asset_owner_declarations": E(
        "Asset owner declarations",
        "The facts an inventory needs that no scan can observe: who owns the "
        "store, its recovery objectives and its classification decision.",
        ("The inventory export with owner, recovery time objective and support "
         "end date filled in",),
        "Every declared field is filled for this store and dated in the period."),

    # ---- change and vendor management -------------------------------------
    "change_approval_records": E(
        "Change approval records",
        "Records that loads of new or changed content into the store were "
        "authorized, tested where needed and approved.",
        ("Pipeline run records showing each bulk ingestion was approved",
         "Tickets for corpus refreshes with the approver named"),
        "Ingestion in the period, including large batches, maps to an approved "
        "change."),
    "vendor_risk_assessments": E(
        "Vendor risk assessments",
        "The assessments of the risk each vendor that receives data from this "
        "system poses, and how that risk is managed.",
        ("A vendor review of each model provider the store calls, with its "
         "security report and contract terms",),
        "Every vendor that receives data from the store has a current "
        "assessment."),

    # ---- determinations ----------------------------------------------------
    "addressable_determination": E(
        "Addressable determination",
        "The documented reason an addressable HIPAA safeguard is not reasonable "
        "and appropriate here, and the alternative adopted instead.",
        ("A risk-based memo explaining why encryption is not implemented on a "
         "private-network store, and the compensating control",),
        "It gives a reason tied to this store's risk, and an equivalent "
        "alternative where one is reasonable. Addressable does not mean optional."),
    "risk_determination": E(
        "Risk determination",
        "The documented risk assessment explaining why a risk-based measure is "
        "not appropriate here.",
        ("A risk assessment concluding pseudonymisation is not appropriate for a "
         "collection, with the reasons",),
        "It is specific to this store and the data it holds."),
}

#: What every reviewer checks, whatever the artifact. Shown beside the
#: artifact-specific checks above.
REVIEWER_CHECKLIST: tuple[str, ...] = (
    "Right document: it is the kind of artifact the requirement asks for.",
    "Right scope: it names this store, its collections, or the system they "
    "belong to — not only the organization in general.",
    "Right period: it is in force for the period under review.",
    "Current: it is the latest version, approved or signed, and not superseded.",
    "Says the thing: its content meets the criterion. A content hash only "
    "proves the file has not changed; it does not prove what the file claims.",
)

Q = ApplicabilityQuestion

APPLICABILITY_QUESTIONS: dict[str, ApplicabilityQuestion] = {
    "covered_entity_or_business_associate": Q(
        "Is the organization a HIPAA covered entity or business associate?",
        "Covered entities are health plans, clearinghouses and providers that "
        "bill electronically; business associates handle health data for them. "
        "This is a legal determination."),
    "system_handles_ephi": Q(
        "Does this system handle electronic protected health information?",
        "Health information about an identifiable person, held electronically by "
        "a covered entity or its business associate. A classifier match does not "
        "settle this."),
    "processes_personal_data_of_eu_subjects": Q(
        "Does the store hold personal data of people in the EU?",
        "GDPR applies to controllers and processors handling EU residents' "
        "personal data, wherever the processing happens."),
    "controller_or_processor_role": Q(
        "Is the organization a controller or processor for this data?",
        "Erasure duties fall on the controller; a processor acts on its "
        "instructions."),
    "stores_processes_or_transmits_account_data": Q(
        "Does the system store, process or transmit payment account data?",
        "Account data is the card number and related cardholder or "
        "authentication data."),
    "system_in_cardholder_data_environment": Q(
        "Is the store inside the cardholder data environment?",
        "Scope is set by the entity's PCI assessment, not by this scan."),
    "account_data_transmitted_over_open_public_networks": Q(
        "Does account data travel to or from the store over open, public networks?",
        "The internet is an open, public network; a private link or VPC usually "
        "is not."),
    "criterion_in_audit_scope": Q(
        "Is this criterion in scope for the SOC 2 report?",
        "The service organization and its auditor choose which criteria the "
        "report covers."),
    "system_in_service_boundary": Q(
        "Is the store inside the audited service boundary?",
        "The system description in the SOC 2 report defines the boundary."),
    "system_is_high_risk_ai": Q(
        "Is the AI system classified as high-risk under the EU AI Act?",
        "High-risk classification follows Annex III and Article 6. This is a "
        "legal determination."),
    "role_provider_or_deployer": Q(
        "Is the organization the provider or deployer of the AI system?",
        "Article 26 duties fall on deployers. Article 15 requirements attach to "
        "the system, and meeting them is the provider's obligation."),
    "business_subject_to_ccpa": Q(
        "Does the business meet the CCPA/CPRA thresholds?",
        "Revenue, volume of consumers' data, or share of revenue from selling or "
        "sharing it. This is a legal determination."),
    "data_relates_to_california_residents": Q(
        "Does the data relate to California residents?",
        "The CCPA protects consumers who are California residents."),
    "subject_to_cppa_cybersecurity_audit": Q(
        "Must the business complete a CPPA cybersecurity audit?",
        "The CPPA regulations set thresholds for the annual cybersecurity audit. "
        "This is a legal determination."),
    "processing_triggers_ccpa_risk_assessment": Q(
        "Does the store's processing involve an activity that needs a CCPA risk "
        "assessment?",
        "The regulations list them: selling or sharing personal information, "
        "processing sensitive personal information, and training identity or "
        "profiling technology, among others. Sensitive or biometric data found "
        "by the scan informs this answer but does not settle it."),
    "ai_system_placed_on_market_or_used_in_eu": Q(
        "Is an AI system that builds or searches this store placed on the EU "
        "market, put into service or used in the EU?",
        "The AI Act's prohibited practices apply to providers and deployers "
        "alike. This is a legal determination."),
}

#: How each specification kind reads, for a reader who has not met the
#: distinction. Mirrors criteria.SPECIFICATION_KINDS.
SPECIFICATION_NOTES: dict[str, str] = {
    "standard": "A standard: mandatory wherever the framework applies.",
    "required": "A required specification: must be implemented as written.",
    "addressable": (
        "An addressable specification: it may be replaced by a documented "
        "determination and an equivalent alternative, but it is not optional."),
    "risk_based": (
        "A risk-based measure: required where the risk calls for it. Leaving it "
        "out needs a documented risk determination; it is not optional."),
}

#: Terms the criterion wording uses that a reader may not know.
TERMS: dict[str, str] = {
    "ePHI": "Electronic protected health information: health data about an "
            "identifiable person, held electronically.",
    "PHI": "Protected health information: health data about an identifiable "
           "person held by a covered entity or its business associate.",
    "PAN": "Primary account number: the long number on a payment card.",
    "embeddings": "The vectors a model computes from text. They can carry "
                  "recoverable content. Whether an embedding is personal data "
                  "is a legal question a reviewer answers.",
    "Safe Harbor": "The HIPAA de-identification method that removes eighteen "
                   "kinds of identifier.",
    "business associate": "A vendor that handles health data on behalf of a "
                          "covered entity.",
    "pseudonymised": "Identifiers replaced with a key that needs separately "
                     "held information to reverse.",
    "sub-processor": "A processor another processor engages to handle personal "
                     "data, such as a model provider the database calls.",
    "known exploited": "A vulnerability CISA's catalog lists as exploited in the "
                       "wild. A signal to fix first, whatever its score.",
    "end of life": "A release line its maintainer no longer fixes, so later "
                   "vulnerabilities in it stay open.",
    "biometric template": "A vector computed from a face or a voice that "
                          "identifies the person when it is searched.",
}


def evidence_catalogue() -> dict[str, dict[str, Any]]:
    return {key: spec.to_dict() for key, spec in EVIDENCE_TYPES.items()}


def applicability_catalogue() -> dict[str, dict[str, Any]]:
    return {key: q.to_dict() for key, q in APPLICABILITY_QUESTIONS.items()}


def vocabulary() -> dict[str, Any]:
    """Everything a console needs to explain the pack's identifiers."""
    return {
        "evidence_types": evidence_catalogue(),
        "applicability_questions": applicability_catalogue(),
        "reviewer_checklist": list(REVIEWER_CHECKLIST),
        "specification_notes": dict(SPECIFICATION_NOTES),
        "terms": dict(TERMS),
        "note": ("Examples illustrate the kind of document a requirement asks "
                 "for. Whether a particular document suffices is a reviewer's "
                 "decision, and no example is a compliance determination."),
    }
