"""CCPA risk-assessment workbook (Cal. Code Regs. tit. 11, Article 10, §§ 7150-7157).

The California CCPA regulations in force from 2026-01-01 require a business to
conduct a risk assessment before processing that presents significant risk to
consumers' privacy (§ 7150), to document it with the content § 7152(a) lists,
to keep it current (§ 7155) and to submit certain information about it to the
California Privacy Protection Agency (§ 7157).

This module does two separate things and keeps them separate:

* It models the regulation. :data:`ELEMENTS` mirrors § 7152(a) subsection by
  subsection, :data:`TRIGGERS` mirrors § 7150(b), and :func:`deadlines` states
  the § 7155 and § 7157 timing rules with their citations. Provision text is
  paraphrased in VecShield's own words; nothing here reproduces it at length.
* It prefills that model from what a VecShield audit actually observed, and
  marks everything else as needing the business's input.

Honesty rules this module enforces by construction:

* **It never concludes.** No output says a risk assessment is or is not
  required, that the business "complies", or that the risks are outweighed.
  § 7152(a) makes the weighing of risks against benefits the business's; the
  goal in § 7154 is the business's decision to restrict or prohibit processing.
* **A check that did not run is "not assessed", never satisfied.** Every check
  the workbook reads is optional. When it is absent, skipped, unsupported or
  errored, the elements and safeguards that depend on it say so.
* **Triggers are suggestions.** Scan evidence can be *consistent with* a
  § 7150(b) trigger (sensitive personal information sitting in a RAG store, for
  instance); only the business can determine that the processing activity is
  one the paragraph describes, or that an exemption such as § 7150(b)(2)(A)
  applies.
* **No raw values leave the audit.** Categories are derived from detector and
  label counts. Finding examples and match previews are never copied in.

The primary text was verified against the CPPA's published regulations
(:data:`REGULATION_SOURCE`); the personal-information categories against Cal.
Civ. Code § 1798.140 (:data:`STATUTE_SOURCE`).
"""

from __future__ import annotations

import html
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any, Iterable, Mapping, Optional

# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

#: The regulation text this module was written against. ``content_sha256`` is
#: the hash of the PDF that was read when the element list was checked; a
#: later edition must be re-read before this module claims to follow it.
REGULATION_SOURCE: dict[str, Any] = {
    "id": "ccpa-regs-art-10",
    "issuer": "California Privacy Protection Agency",
    "title": "California Consumer Privacy Act Regulations, Cal. Code Regs. tit. 11, "
             "div. 6, ch. 1, Article 10 (Risk Assessments), §§ 7150-7157",
    "kind": "regulation",
    "effective_date": "2026-01-01",
    "url": "https://privacy.ca.gov/wp-content/uploads/sites/357/2026/03/"
           "ccpa_regulations_eff_20260101-1.pdf",
    "retrieved_at": "2026-09-29",
    "content_sha256": "8d57eba97a7fe13346b7827d0131e1ab84dc110c6ff20daa6fa6ec4a4329d0fe",
    "lifecycle": "draft",
    "notes": "Paraphrased; not reviewed by counsel. The same file is served at "
             "cppa.ca.gov/regulations/pdf/ccpa_statute_eff_20260101.pdf.",
}

STATUTE_SOURCE: dict[str, Any] = {
    "id": "ccpa-1798-140",
    "issuer": "State of California",
    "title": "Cal. Civ. Code § 1798.140 (definitions: personal information, "
             "sensitive personal information)",
    "kind": "statute",
    "url": "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml"
           "?lawCode=CIV&sectionNum=1798.140",
    "retrieved_at": "2026-09-29",
    "lifecycle": "draft",
}

_REGS = "Cal. Code Regs. tit. 11"

#: Printed with every rendering of the workbook.
DISCLAIMER = (
    "This workbook organises technical evidence from a VecShield audit against the "
    "content Cal. Code Regs. tit. 11, § 7152(a) requires in a CCPA risk assessment. "
    "It does not determine whether the business must conduct a risk assessment, "
    "whether the processing may proceed, or whether the business meets its obligations. Those "
    "are the business's determinations, made by the individuals § 7152(a)(9) names."
)

# ---------------------------------------------------------------------------
# § 7152(a): required content
# ---------------------------------------------------------------------------

#: How much of an element scan evidence can speak to.
#:   ``full`` — the element is a factual question a scan can observe;
#:   ``part`` — evidence informs it, but it also asks for the business's plan,
#:              intent or purpose, which no scan can see;
#:   ``none`` — the element is purely the business's to state.
EVIDENCE_REACH = ("full", "part", "none")

#: Element statuses. Only the business moves an element to business_provided.
ELEMENT_STATUSES = ("prefilled", "partially_prefilled", "business_provided",
                    "requires_business_input", "not_assessed", "not_applicable")

STATUS_LABELS = {
    "prefilled": "Prefilled from evidence (confirm)",
    "partially_prefilled": "Partly prefilled (business input needed)",
    "business_provided": "Provided by the business",
    "requires_business_input": "Requires business input",
    "not_assessed": "Not assessed",
    "not_applicable": "Not applicable (business determination)",
}


@dataclass(frozen=True)
class ElementSpec:
    """One piece of content § 7152(a) requires."""

    key: str
    subsection: str
    title: str
    requirement: str
    evidence_reach: str
    prompt: str
    #: § 7001(zz) defines the risk assessment *report* as the content of
    #: § 7152(a)(1)-(3) and (6)-(9). (a)(4) and (a)(5) must still be identified.
    in_report: bool = True
    #: A trigger id the element depends on, e.g. ADMT logic only for (b)(3).
    only_if_trigger: Optional[str] = None
    #: Backing checks whose absence makes an evidence-reached element unassessed.
    checks: tuple[str, ...] = ()

    @property
    def citation(self) -> str:
        return f"{_REGS}, § {self.subsection}"

    def to_dict(self) -> dict[str, Any]:
        return {"key": self.key, "subsection": self.subsection,
                "citation": self.citation, "title": self.title,
                "requirement": self.requirement,
                "evidence_reach": self.evidence_reach, "prompt": self.prompt,
                "in_report": self.in_report, "only_if_trigger": self.only_if_trigger,
                "checks": list(self.checks)}


ELEMENTS: tuple[ElementSpec, ...] = (
    ElementSpec(
        "purpose", "7152(a)(1)", "Purpose of the processing",
        "The business's purpose for processing consumers' personal information, "
        "stated specifically. Generic descriptions such as improving services or "
        "security purposes are not sufficient.",
        "none",
        "State the specific purpose this store serves (for example, which "
        "assistant or workflow retrieves from it and what outcome it produces). "
        "Avoid generic phrases."),
    ElementSpec(
        "pi_categories", "7152(a)(2)",
        "Categories of personal information, including sensitive personal information",
        "The categories of personal information to be processed, including any "
        "categories of sensitive personal information.",
        "full",
        "Confirm the categories observed below, and add categories processed "
        "elsewhere in this activity that the scanned store does not hold.",
        checks=("data_classification", "asset_inventory")),
    ElementSpec(
        "minimum_necessary", "7152(a)(2)",
        "Minimum personal information necessary for the purpose",
        "The minimum personal information necessary to achieve the purpose.",
        "none",
        "State which of the categories present are necessary for the purpose, "
        "and which could be removed, redacted or pseudonymised before embedding."),
    ElementSpec(
        "method_and_sources", "7152(a)(3)(A)",
        "Method of collecting, using, disclosing and retaining; sources",
        "The planned method for collecting, using, disclosing, retaining or "
        "otherwise processing the personal information, and its sources.",
        "part",
        "Describe where the source documents come from, how they reach the "
        "store, and how retrieved content is used and disclosed.",
        checks=("asset_inventory", "data_residency", "model_egress")),
    ElementSpec(
        "retention", "7152(a)(3)(B)", "Retention period for each category",
        "How long each category of personal information will be retained or, if "
        "unknown, the criteria used to determine that period.",
        "part",
        "State the planned retention period (or the criteria for it) for each "
        "category, including the embeddings and any superseded chunk versions.",
        checks=("retention_schedule", "retention_horizon", "chunk_versions")),
    ElementSpec(
        "consumer_interaction", "7152(a)(3)(C)",
        "Method and purpose of interacting with consumers",
        "How the business interacts with the consumers whose information is "
        "processed (website, application, offline) and the purpose of that "
        "interaction.",
        "none",
        "Describe how these consumers interact with the business and why."),
    ElementSpec(
        "approximate_consumers", "7152(a)(3)(D)",
        "Approximate number of consumers",
        "The approximate number of consumers whose personal information will "
        "be processed.",
        "full",
        "Confirm or replace the estimate. The regulation asks for consumers the "
        "activity will process, which can exceed what this store holds today.",
        checks=("asset_inventory",)),
    ElementSpec(
        "consumer_disclosures", "7152(a)(3)(E)", "Disclosures made to consumers",
        "What the business has disclosed or will disclose to consumers about "
        "the processing, and how (for example a just-in-time notice).",
        "none",
        "List the notices that describe this processing and how consumers "
        "receive them."),
    ElementSpec(
        "recipients", "7152(a)(3)(F)",
        "Service providers, contractors and third parties",
        "The names or categories of service providers, contractors or third "
        "parties the personal information is disclosed or made available to "
        "for the processing, and the purpose of each disclosure.",
        "part",
        "Confirm each recipient's role (service provider, contractor or third "
        "party) and the purpose for which the information is made available.",
        checks=("model_egress", "asset_inventory")),
    ElementSpec(
        "admt_logic", "7152(a)(3)(G)(i)", "ADMT logic, assumptions and limitations",
        "For ADMT used for a significant decision (§ 7150(b)(3)): the logic of "
        "the ADMT, including its assumptions and limitations.",
        "none",
        "Only where § 7150(b)(3) applies: describe the ADMT's logic, assumptions "
        "and limitations. Record a determination on § 7150(b)(3) otherwise.",
        only_if_trigger="7150(b)(3)"),
    ElementSpec(
        "admt_output", "7152(a)(3)(G)(ii)", "ADMT output and its use",
        "For ADMT used for a significant decision (§ 7150(b)(3)): the output of "
        "the ADMT and how it is used to make the decision.",
        "none",
        "Only where § 7150(b)(3) applies: describe the output and how it feeds "
        "the significant decision.",
        only_if_trigger="7150(b)(3)"),
    ElementSpec(
        "benefits", "7152(a)(4)", "Benefits of the processing",
        "The benefits to the business, the consumer, other stakeholders and the "
        "public, stated specifically rather than generically.",
        "none",
        "State concrete benefits and to whom they accrue.",
        in_report=False),
    ElementSpec(
        "negative_impacts", "7152(a)(5)",
        "Negative impacts to consumers' privacy, with sources and causes",
        "The negative impacts to consumers' privacy and their sources and "
        "causes. § 7152(a)(5)(A)-(H) gives examples the business may consider.",
        "part",
        "Review the impacts suggested by the evidence, add others, and state "
        "the source and cause of each.",
        in_report=False),
    ElementSpec(
        "safeguards", "7152(a)(6)", "Safeguards for the processing",
        "The safeguards the business plans to implement, including those that "
        "address the negative impacts in (a)(5).",
        "part",
        "Confirm the observed technical safeguards, resolve each row that was "
        "not assessed, and add organisational and planned safeguards.",
        checks=("transport_encryption", "at_rest_encryption", "authentication",
                "tenant_isolation", "network_exposure", "erasure_verification",
                "server_vulnerability", "cve")),
    ElementSpec(
        "will_initiate", "7152(a)(7)", "Whether the business will initiate the processing",
        "Whether the business will initiate the processing that is the subject "
        "of the assessment.",
        "none",
        "Record the decision whether to initiate (or continue) the processing."),
    ElementSpec(
        "contributors", "7152(a)(8)", "Individuals who provided information",
        "The individuals who provided information for the assessment, other "
        "than legal counsel providing legal advice. § 7151(a) requires employees "
        "who take part in the processing to be included.",
        "none",
        "List the people (name and role) who contributed information. VecShield "
        "is a source of evidence, not a contributor."),
    ElementSpec(
        "review_and_approval", "7152(a)(9)",
        "Date of review and approval; reviewers and approvers",
        "The date the assessment was reviewed and approved and the names and "
        "positions of the reviewers or approvers, other than legal counsel. An "
        "approver must have authority to decide whether the processing proceeds.",
        "none",
        "Record the approval date and each reviewer's or approver's name and "
        "position; at least one must be able to decide whether processing "
        "proceeds."),
)

ELEMENT_KEYS = tuple(spec.key for spec in ELEMENTS)

# ---------------------------------------------------------------------------
# § 7150(b): when an assessment is required
# ---------------------------------------------------------------------------

#: Trigger statuses. None of them says a trigger does not apply.
TRIGGER_STATUSES = ("suggested", "review", "no_indication", "not_assessed",
                    "not_determinable")

TRIGGER_STATUS_LABELS = {
    "suggested": "Suggested by evidence (confirm)",
    "review": "Evidence relevant (review)",
    "no_indication": "No indication in the scanned scope",
    "not_assessed": "Not assessed",
    "not_determinable": "Not determinable from a scan",
}


@dataclass(frozen=True)
class TriggerSpec:
    id: str
    title: str
    description: str

    @property
    def citation(self) -> str:
        return f"{_REGS}, § {self.id}"


TRIGGERS: tuple[TriggerSpec, ...] = (
    TriggerSpec("7150(b)(1)", "Selling or sharing personal information",
                "Selling or sharing (as the CCPA defines those terms) presents "
                "significant risk."),
    TriggerSpec("7150(b)(2)", "Processing sensitive personal information",
                "Processing sensitive personal information presents significant "
                "risk. § 7150(b)(2)(A) excludes certain employee and contractor "
                "processing done solely for payroll, work authorisation, "
                "benefits, legally required accommodation or wage reporting."),
    TriggerSpec("7150(b)(3)", "ADMT for a significant decision",
                "Using automated decisionmaking technology for a significant "
                "decision concerning a consumer."),
    TriggerSpec("7150(b)(4)", "Inference from systematic observation",
                "Automated processing to infer or extrapolate attributes of an "
                "applicant, student, employee or contractor from systematic "
                "observation of them in that capacity."),
    TriggerSpec("7150(b)(5)", "Inference from presence at a sensitive location",
                "Automated processing to infer or extrapolate attributes of a "
                "consumer from their presence at a sensitive location (§ 7001(aaa))."),
    TriggerSpec("7150(b)(6)", "Training ADMT or identification technology",
                "Processing personal information the business intends to use to "
                "train ADMT for a significant decision, or facial-recognition, "
                "emotion-recognition or other identity-verification or "
                "physical/biological identification or profiling technology."),
)

TRIGGER_IDS = tuple(t.id for t in TRIGGERS)

# ---------------------------------------------------------------------------
# Personal-information categories (Cal. Civ. Code § 1798.140(v), (ae))
# ---------------------------------------------------------------------------

_CIV = "Cal. Civ. Code § 1798.140"


@dataclass(frozen=True)
class _Category:
    code: str
    citation: str
    title: str
    sensitive: bool


_CATEGORIES: dict[str, _Category] = {c.code: c for c in (
    _Category("v1A", f"{_CIV}(v)(1)(A)", "Identifiers", False),
    _Category("v1B", f"{_CIV}(v)(1)(B)",
              "Customer-record information under Civ. Code § 1798.80(e) "
              "(e.g. financial account, card, insurance numbers)", False),
    _Category("v1C", f"{_CIV}(v)(1)(C)",
              "Characteristics of protected classifications", False),
    _Category("v1E", f"{_CIV}(v)(1)(E)", "Biometric information", False),
    _Category("v1F", f"{_CIV}(v)(1)(F)",
              "Internet or other electronic network activity", False),
    _Category("v1G", f"{_CIV}(v)(1)(G)", "Geolocation data", False),
    _Category("v1", f"{_CIV}(v)(1)",
              "Other personal information (no enumerated category)", False),
    _Category("ae1A", f"{_CIV}(ae)(1)(A)",
              "Social security, driver's licence, state ID or passport number", True),
    _Category("ae1B", f"{_CIV}(ae)(1)(B)",
              "Account log-in, financial account or card number with its access "
              "credential", True),
    _Category("ae1C", f"{_CIV}(ae)(1)(C)", "Precise geolocation", True),
    _Category("ae1D", f"{_CIV}(ae)(1)(D)",
              "Racial or ethnic origin, citizenship or immigration status, "
              "religious or philosophical beliefs, union membership", True),
    _Category("ae1F", f"{_CIV}(ae)(1)(F)", "Genetic data", True),
    _Category("ae2A", f"{_CIV}(ae)(2)(A)",
              "Biometric information processed to uniquely identify a consumer", True),
    _Category("ae2B", f"{_CIV}(ae)(2)(B)",
              "Personal information collected and analysed concerning health", True),
    _Category("ae2C", f"{_CIV}(ae)(2)(C)",
              "Personal information concerning sex life or sexual orientation", True),
    _Category("ae", f"{_CIV}(ae)",
              "Sensitive personal information (the scan did not record which kind)", True),
    _Category("bbb4", f"{_REGS}, § 7001(bbb)(4)",
              "Personal information of consumers known to be under 16", True),
)}

#: Sensitive-PI categories no VecShield detector can observe. Listed so that a
#: clean result is never read as "none of these are present".
UNOBSERVABLE_SPI = (
    (f"{_CIV}(ae)(1)(E)",
     "Contents of mail, email and text messages (depends on who the intended "
     "recipient was)"),
    (f"{_CIV}(ae)(1)(G)", "Neural data"),
    (f"{_CIV}(ae)(1)(D)", "Citizenship or immigration status (no detector)"),
)

_OBSERVED = "observed"
_POSSIBLE = "possible"

_ID = [("v1A", _OBSERVED)]
_GOV_ID = [("v1A", _OBSERVED), ("ae1A", _OBSERVED)]
_HEALTH = [("ae2B", _OBSERVED)]
_GENETIC = [("ae1F", _OBSERVED)]

#: Detector -> categories it evidences. ``possible`` marks categories whose
#: definition turns on context a pattern cannot see (a card number is
#: sensitive only with its access credential; a coordinate only if precise).
_DETECTOR_CATEGORIES: dict[str, list[tuple[str, str]]] = {
    **{d: _ID for d in (
        "email", "us_phone", "intl_phone", "ipv4_address", "ipv6_address",
        "mac_address", "imei_number", "us_street_address", "us_zip_context",
        "zip_plus4", "secondary_address", "username_handle", "prefixed_id",
        "metadata_identifier", "date_of_birth", "tax_id_context", "us_itin",
        "uk_nino_context", "canada_sin_context", "india_pan",
        "india_aadhaar_context", "brazil_cpf_context", "china_resident_id",
        "singapore_nric", "italy_fiscal_code", "mexico_curp",
        "netherlands_bsn_context", "south_africa_id_context",
        "australia_tfn_context", "uk_utr_context", "france_nir_context",
        "poland_pesel_context", "germany_steuer_id_context",
        "spain_dni_nie_context", "sweden_personnummer_context",
        "norway_fodselsnummer_context", "finland_hetu_context",
        "denmark_cpr_context", "belgium_rrn_context", "ireland_ppsn_context",
        "portugal_nif_context", "greece_amka_context",
        "presidio:PERSON", "presidio:EMAIL_ADDRESS", "presidio:PHONE_NUMBER",
        "presidio:IP_ADDRESS")},
    **{d: _GOV_ID for d in (
        "us_ssn", "us_ssn_spaced", "us_ssn_context", "us_driver_license_context",
        "passport_context", "presidio:US_SSN", "presidio:US_PASSPORT",
        "presidio:US_DRIVER_LICENSE")},
    **{d: [("v1B", _OBSERVED), ("ae1B", _POSSIBLE)] for d in (
        "credit_card", "bank_account_context", "bank_routing", "iban",
        "credit_card_expiry_context", "presidio:CREDIT_CARD", "presidio:IBAN_CODE")},
    **{d: [("v1B", _OBSERVED), ("ae1B", _OBSERVED)] for d in (
        "credit_card_cvv_context", "card_pin_context", "card_pin_block_context",
        "card_track1_data", "card_track2_data", "card_track2_equivalent")},
    **{d: [("ae1B", _POSSIBLE)] for d in (
        "database_url_credentials", "basic_auth_header")},
    **{d: _HEALTH for d in (
        "medical_record_context", "us_medicare_mbi_context", "uk_nhs_context",
        "icd_code_context", "ndc_code_context", "cpt_hcpcs_code_context",
        "loinc_code_context", "snomed_code_context", "rxnorm_code_context",
        "drg_code_context", "clinical_trial_nct", "lab_accession_context")},
    **{d: _GENETIC for d in (
        "genetic_variant_hgvs", "genetic_rsid", "genetic_sequence_run",
        "genetic_testing_context")},
    "racial_ethnic_origin": [("v1C", _OBSERVED), ("ae1D", _OBSERVED)],
    "religious_belief": [("v1C", _OBSERVED), ("ae1D", _OBSERVED)],
    "trade_union_membership": [("ae1D", _OBSERVED)],
    "sexual_orientation": [("v1C", _OBSERVED), ("ae2C", _OBSERVED)],
    # Political opinion is GDPR Art. 9 data but not a CCPA sensitive category.
    "political_opinion": [("v1", _OBSERVED)],
    "criminal_offence_context": [("v1", _OBSERVED)],
    "biometric_reference": [("v1E", _OBSERVED), ("ae2A", _POSSIBLE)],
    "gps_coordinate": [("v1G", _OBSERVED), ("ae1C", _POSSIBLE)],
    "user_agent_string": [("v1F", _OBSERVED)],
    "minor_age_context": [("bbb4", _POSSIBLE)],
    "minor_school_context": [("bbb4", _POSSIBLE)],
}

#: Label -> categories, used only where no detector in that collection already
#: explains the label (older audits recorded labels without detectors).
_LABEL_CATEGORIES: dict[str, list[tuple[str, str]]] = {
    "pii": [("v1A", _OBSERVED)],
    "phi": [("ae2B", _OBSERVED)],
    "pci": [("v1B", _OBSERVED), ("ae1B", _POSSIBLE)],
    "secret": [("ae1B", _POSSIBLE)],
    "special_category": [("ae", _POSSIBLE)],
    "criminal_offence": [("v1", _OBSERVED)],
}

#: Which categories count as "already explained" for a label.
_LABEL_FAMILY = {
    "pii": {"v1A", "ae1A"}, "phi": {"ae2B"}, "pci": {"v1B"},
    "secret": {"ae1B"}, "criminal_offence": {"v1"},
    "special_category": {"ae1D", "ae1F", "ae2A", "ae2C", "v1C"},
}

# ---------------------------------------------------------------------------
# Evidence normalisation
# ---------------------------------------------------------------------------

#: Managed services whose vector store is always operated by the vendor.
_MANAGED_PROVIDERS = {
    "pinecone": "Pinecone", "bedrock_kb": "Amazon Web Services (Bedrock Knowledge Bases)",
    "vertex_ai": "Google Cloud (Vertex AI)", "azure_search": "Microsoft Azure (AI Search)",
    "openai": "OpenAI (vector stores)",
}

_RAN = ("passed", "failed", "inconclusive")

#: Safeguard states. Only ``observed`` is evidence the safeguard is present.
SAFEGUARD_STATES = ("observed", "not_observed", "partially_assessed",
                    "not_assessed", "not_applicable")

SAFEGUARD_LABELS = {
    "observed": "Observed",
    "not_observed": "Not observed (gap)",
    "partially_assessed": "Partially assessed",
    "not_assessed": "Not assessed",
    "not_applicable": "Not applicable",
}

#: (key, control, backing checks most specific first, § 7152(a)(6) example).
_SAFEGUARDS: tuple[tuple[str, str, tuple[str, ...], str], ...] = (
    ("transport_encryption", "Encryption in transit",
     ("transport_encryption", "configuration_posture"), "7152(a)(6)(A)(i)"),
    ("at_rest_encryption", "Encryption at rest", ("at_rest_encryption",),
     "7152(a)(6)(A)(i)"),
    ("authentication", "Authentication and access control",
     ("authentication", "configuration_posture"), "7152(a)(6)(A)(i)"),
    ("tenant_isolation", "Tenant isolation (logical segmentation)",
     ("tenant_isolation",), "7152(a)(6)(A)(i)"),
    ("network_exposure", "Network exposure and defences",
     ("network_exposure", "configuration_posture"), "7152(a)(6)(A)(i)"),
    ("erasure_verification", "Verified erasure of consumer data",
     ("erasure_verification",), "7152(a)(6)"),
    ("vulnerability_posture", "Known-vulnerability posture of the store",
     ("server_vulnerability", "cve", "configuration_posture"), "7152(a)(6)(A)(i)"),
)


class _Evidence:
    """A read-only view over an audit, however it arrived.

    Accepts an ``AuditResult`` (anything with ``all_check_outcomes`` and
    ``all_findings``) or its serialised snapshot. Legacy snapshots without
    structured outcomes yield none, so every dependent element is unassessed.
    """

    def __init__(self, audit: Any, inventory: Optional[Mapping[str, Any]],
                 store: Optional[str]) -> None:
        self.present = audit is not None
        self.outcomes: list[dict[str, Any]] = []
        self.findings: list[dict[str, Any]] = []
        self.job_stats: list[dict[str, Any]] = []
        self.audit_id = ""
        self.store = ""
        self.finished_at = ""
        self.scope: dict[str, Any] = {}
        self.coverage: dict[str, Any] = {}
        if audit is None:
            pass
        elif isinstance(audit, Mapping):
            self._from_mapping(audit)
        else:
            self._from_object(audit)
        self.store = store or self.store or "vector store"
        self.inventory = _store_inventory(inventory, self.store)
        self.by_check: dict[str, list[dict[str, Any]]] = {}
        for outcome in self.outcomes:
            self.by_check.setdefault(str(outcome.get("check") or ""), []).append(outcome)

    def _from_mapping(self, data: Mapping[str, Any]) -> None:
        for wrapper in ("audit", "snapshot", "result"):
            inner = data.get(wrapper)
            if isinstance(inner, Mapping) and "check_outcomes" not in data:
                data = inner
                break
        self.audit_id = str(data.get("id") or "")
        self.store = str(data.get("store") or "")
        self.finished_at = str(data.get("finished_at") or "")
        self.scope = dict(data.get("scope") or {})
        self.coverage = dict(data.get("coverage") or {})
        jobs = [j for j in (data.get("jobs") or []) if isinstance(j, Mapping)]
        self.job_stats = [dict(j.get("stats") or {}) for j in jobs]
        for job in jobs:
            self.findings.extend(dict(f) for f in (job.get("findings") or [])
                                 if isinstance(f, Mapping))
        if isinstance(data.get("check_outcomes"), list):
            self.outcomes = [dict(o) for o in data["check_outcomes"]
                             if isinstance(o, Mapping)]
        else:
            for stats in self.job_stats:
                self.outcomes.extend(dict(o) for o in (stats.get("check_outcomes") or [])
                                     if isinstance(o, Mapping))

    def _from_object(self, audit: Any) -> None:
        self.audit_id = str(getattr(audit, "id", "") or "")
        self.store = str(getattr(audit, "store", "") or "")
        self.finished_at = str(getattr(audit, "finished_at", "") or "")
        self.scope = dict(getattr(audit, "scope", {}) or {})
        coverage = getattr(audit, "coverage", {}) or {}
        self.coverage = dict(coverage() if callable(coverage) else coverage)
        getter = getattr(audit, "all_check_outcomes", None)
        self.outcomes = [dict(o) for o in (getter() if callable(getter) else [])]
        finder = getattr(audit, "all_findings", None)
        for finding in (finder() if callable(finder) else []):
            to_dict = getattr(finding, "to_dict", None)
            if callable(to_dict):
                self.findings.append(dict(to_dict()))
        self.job_stats = [dict(getattr(j, "stats", {}) or {})
                          for j in (getattr(audit, "jobs", []) or [])]

    # -- helpers ------------------------------------------------------------

    def pointer(self, check: str, outcome: Mapping[str, Any]) -> dict[str, Any]:
        return {"audit_id": self.audit_id, "check": check,
                "collection": outcome.get("collection"),
                "outcome": outcome.get("outcome")}

    def finding_pointer(self, finding: Mapping[str, Any]) -> dict[str, Any]:
        return {"audit_id": self.audit_id, "finding_id": finding.get("id"),
                "category": finding.get("category"),
                "collection": finding.get("collection")}

    def ran(self, check: str) -> list[dict[str, Any]]:
        return [o for o in self.by_check.get(check, []) if o.get("outcome") in _RAN]

    def store_kind(self) -> str:
        for stats in self.job_stats:
            if stats.get("store_kind"):
                return str(stats["store_kind"])
        inv = self.inventory or {}
        return str(inv.get("kind") or inv.get("store_kind") or "")


def _store_inventory(inventory: Optional[Mapping[str, Any]],
                     store: str) -> Optional[dict[str, Any]]:
    """The inventory entry for this store, from a store- or estate-level dict."""
    if not isinstance(inventory, Mapping):
        return None
    stores = inventory.get("stores")
    if isinstance(stores, list):
        entries = [s for s in stores if isinstance(s, Mapping)]
        for entry in entries:
            if store and store in (entry.get("id"), entry.get("store_id"),
                                   entry.get("name"), entry.get("store")):
                return dict(entry)
        return dict(entries[0]) if len(entries) == 1 else None
    return dict(inventory)


def _inventory_collections(inv: Optional[Mapping[str, Any]]) -> list[dict[str, Any]]:
    if not inv:
        return []
    cols = inv.get("collections") or []
    if isinstance(cols, Mapping):
        return [{"name": name, **(value if isinstance(value, Mapping) else {})}
                for name, value in cols.items()]
    return [dict(c) for c in cols if isinstance(c, Mapping)]


def _col_name(entry: Mapping[str, Any]) -> Optional[str]:
    value = entry.get("name") or entry.get("collection")
    return str(value) if value else None


def _int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float) and value >= 0:
        return int(value)
    return None


def _first(mapping: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if mapping.get(key) not in (None, "", [], {}):
            return mapping[key]
    return None


def _names(value: Any, *keys: str) -> list[str]:
    """Flatten a provider/region value that may be a str, list of str or dicts."""
    out: list[str] = []
    items = value if isinstance(value, (list, tuple, set)) else [value]
    for item in items:
        if isinstance(item, str) and item.strip():
            out.append(item.strip())
        elif isinstance(item, Mapping):
            found = _first(item, *keys)
            if isinstance(found, str) and found.strip():
                out.append(found.strip())
    return out


# ---------------------------------------------------------------------------
# Check reduction
# ---------------------------------------------------------------------------

def _check_state(ev: _Evidence, checks: Iterable[str]) -> tuple[str, str, str, list[dict]]:
    """(state, backing check, reason, pointers) for the first check that ran.

    A failed outcome anywhere is a gap; an inconclusive or incomplete one is
    partial; only complete passes are ``observed``.
    """
    checks = tuple(checks)
    for check in checks:
        outcomes = ev.by_check.get(check, [])
        if not outcomes:
            continue
        pointers = [ev.pointer(check, o) for o in outcomes]
        ran = [o for o in outcomes if o.get("outcome") in _RAN]
        if not ran:
            # Skipped, unsupported or errored: try a less specific check, then
            # report this one's reason.
            fallback = _check_state(ev, checks[checks.index(check) + 1:])
            if fallback[0] != "not_assessed":
                return fallback
            reason = next((str(o.get("reason")) for o in outcomes if o.get("reason")),
                          "The backing check did not run.")
            return "not_assessed", check, reason, pointers
        failed = [o for o in ran if o.get("outcome") == "failed"]
        if failed:
            return ("not_observed", check,
                    next((str(o.get("reason")) for o in failed if o.get("reason")), ""),
                    pointers)
        partial = [o for o in ran if o.get("outcome") == "inconclusive"
                   or (o.get("coverage") or {}).get("complete") is not True]
        if partial:
            return ("partially_assessed", check,
                    next((str(o.get("reason")) for o in partial if o.get("reason")),
                         "The check inspected only part of the scope."), pointers)
        if all((o.get("coverage") or {}).get("applicability") == "not_applicable"
               for o in ran):
            return ("not_applicable", check,
                    next((str(o.get("reason")) for o in ran if o.get("reason")), ""),
                    pointers)
        return ("observed", check,
                next((str(o.get("reason")) for o in ran if o.get("reason")), ""),
                pointers)
    return ("not_assessed", checks[0] if checks else "",
            "This audit recorded no outcome for the backing check.", [])


def _safeguards(ev: _Evidence) -> list[dict[str, Any]]:
    rows = []
    for key, control, checks, example in _SAFEGUARDS:
        state, check, reason, pointers = _check_state(ev, checks)
        rows.append({"key": key, "control": control, "state": state,
                     "label": SAFEGUARD_LABELS[state], "assessed_by": check,
                     "reason": reason, "regulation_example": f"{_REGS}, § {example}",
                     "evidence": pointers})
    return rows


# ---------------------------------------------------------------------------
# Evidence extraction per element
# ---------------------------------------------------------------------------

def _normalise_detector(name: str) -> str:
    return name[len("regex:"):] if name.startswith("regex:") else name


def _pi_categories(ev: _Evidence) -> list[dict[str, Any]]:
    """Categories observed in the scanned scope, with counts and pointers."""
    found: dict[str, dict[str, Any]] = {}

    def add(code: str, confidence: str, collection: Optional[str], count: int,
            basis: str, pointer: Optional[dict]) -> None:
        cat = _CATEGORIES[code]
        row = found.setdefault(code, {
            "code": code, "citation": cat.citation, "title": cat.title,
            "sensitive": cat.sensitive, "confidence": _POSSIBLE,
            "collections": [], "matches": 0, "basis": [], "evidence": []})
        if confidence == _OBSERVED:
            row["confidence"] = _OBSERVED
        if collection and collection not in row["collections"]:
            row["collections"].append(collection)
        row["matches"] += max(0, count)
        if basis not in row["basis"]:
            row["basis"].append(basis)
        if pointer and pointer not in row["evidence"]:
            row["evidence"].append(pointer)

    def apply(collection: Optional[str], detectors: Mapping[str, Any],
              labels: Mapping[str, Any], pointer: Optional[dict], source: str) -> None:
        explained: set[str] = set()
        for raw, count in detectors.items():
            det = _normalise_detector(str(raw))
            for code, confidence in _DETECTOR_CATEGORIES.get(det, []):
                add(code, confidence, collection, _int(count) or 0,
                    f"{source} detector {det}", pointer)
                explained.add(code)
        for raw, count in labels.items():
            label = str(raw).lower()
            if _LABEL_FAMILY.get(label, set()) & explained:
                continue
            for code, confidence in _LABEL_CATEGORIES.get(label, []):
                add(code, confidence, collection, _int(count) or 0,
                    f"{source} label {label}", pointer)

    for finding in ev.findings:
        if finding.get("category") != "data_classification":
            continue
        evidence = finding.get("evidence") or {}
        apply(finding.get("collection"), evidence.get("detector_counts") or {},
              evidence.get("label_counts") or {}, ev.finding_pointer(finding), "scan")

    for col in _inventory_collections(ev.inventory):
        cats = _first(col, "sensitive_categories", "categories", "labels")
        if isinstance(cats, (list, tuple, set)):
            cats = {str(c): 0 for c in cats}
        if not isinstance(cats, Mapping):
            continue
        detectors = {k: v for k, v in cats.items()
                     if _normalise_detector(str(k)) in _DETECTOR_CATEGORIES}
        labels = {k: v for k, v in cats.items() if k not in detectors}
        apply(_col_name(col), detectors, labels,
              {"source": "inventory", "collection": _col_name(col)}, "inventory")

    order = list(_CATEGORIES)
    rows = sorted(found.values(), key=lambda r: (not r["sensitive"], order.index(r["code"])))
    for row in rows:
        row["collections"].sort(key=str)
    return rows


def _approximate_consumers(ev: _Evidence) -> dict[str, Any]:
    """Distinct-subject counts, stated with what they are and are not."""
    limits = [
        "Counts are distinct identifier keys from the subject index (email "
        "addresses, phone numbers, national identifiers and similar), not people: "
        "one person with two identifiers is counted twice, and a person with no "
        "indexed identifier is not counted.",
        "The regulation asks how many consumers the activity will process, which "
        "can exceed what this store holds today.",
    ]
    pointers: list[dict] = []
    total: Optional[int] = None
    inv = ev.inventory or {}
    total = _int(_first(inv, "distinct_subjects", "subjects", "subject_count"))
    if total is not None:
        pointers.append({"source": "inventory", "field": "distinct_subjects"})
    if total is None:
        for outcome in ev.ran("asset_inventory"):
            cov = outcome.get("coverage") or {}
            value = _int(_first(cov, "distinct_subjects", "subjects", "subject_count"))
            if value is not None and outcome.get("collection") in (None, ""):
                total = value
                pointers.append(ev.pointer("asset_inventory", outcome))
                break
    per_collection: dict[str, int] = {}
    for col in _inventory_collections(ev.inventory):
        value = _int(_first(col, "distinct_subjects", "subjects", "subject_count"))
        if value is not None and _col_name(col):
            per_collection[str(_col_name(col))] = value
    if per_collection:
        pointers.append({"source": "inventory", "field": "collections"})
    for outcome in ev.ran("asset_inventory"):
        cov = outcome.get("coverage") or {}
        value = _int(_first(cov, "distinct_subjects", "subjects", "subject_count"))
        name = outcome.get("collection")
        if value is not None and name and str(name) not in per_collection:
            per_collection[str(name)] = value
            pointers.append(ev.pointer("asset_inventory", outcome))

    if total is not None:
        statement = f"About {total:,} distinct subject identifiers in this store."
        low, high = total, total
    elif per_collection:
        low, high = max(per_collection.values()), sum(per_collection.values())
        counted = f"{len(per_collection)} counted collection(s)"
        statement = (f"At least {low:,} distinct subject identifiers in {counted}."
                     if low == high else
                     f"Between {low:,} and {high:,} distinct subject identifiers across "
                     f"{counted}: per-collection counts cannot be summed without "
                     "double-counting a subject present in more than one collection.")
        limits.append("Collections without a subject count are not included.")
    else:
        return {"established": False, "value": None, "range": None,
                "statement": "Not established: this audit and inventory carry no "
                             "distinct-subject count for the store.",
                "per_collection": {}, "limits": limits, "evidence": []}
    incomplete = any(not (o.get("coverage") or {}).get("complete")
                     for o in ev.ran("data_classification"))
    if incomplete:
        limits.append("Classification did not cover the whole scope, so subjects in "
                      "unscanned content are not counted.")
    return {"established": True, "value": total, "range": [low, high],
            "statement": statement, "per_collection": dict(sorted(per_collection.items())),
            "limits": limits, "evidence": pointers}


def _retention(ev: _Evidence) -> dict[str, Any]:
    horizons = []
    for outcome in ev.by_check.get("retention_horizon", []):
        cov = outcome.get("coverage") or {}
        horizons.append({
            "collection": outcome.get("collection"), "outcome": outcome.get("outcome"),
            "timestamp_field": cov.get("field"),
            "oldest_age_days": _int(cov.get("oldest_age_days")),
            "newest_age_days": _int(cov.get("newest_age_days")),
            "statement": str(outcome.get("reason") or ""),
            "evidence": ev.pointer("retention_horizon", outcome)})
    schedules = []
    for outcome in ev.by_check.get("retention_schedule", []):
        cov = outcome.get("coverage") or {}
        schedules.append({
            "collection": outcome.get("collection"), "outcome": outcome.get("outcome"),
            "declared": _first(cov, "declared", "schedule", "retention_days",
                               "declared_retention_days", "period"),
            "statement": str(outcome.get("reason") or ""),
            "evidence": ev.pointer("retention_schedule", outcome)})
    versions = [{"collection": o.get("collection"), "outcome": o.get("outcome"),
                 "statement": str(o.get("reason") or ""),
                 "evidence": ev.pointer("chunk_versions", o)}
                for o in ev.by_check.get("chunk_versions", [])]
    no_timestamp = [f for f in ev.findings if f.get("category") == "retention"]
    return {"horizons": horizons, "schedules": schedules, "chunk_versions": versions,
            "undated_collections": sorted({str(f.get("collection")) for f in no_timestamp
                                           if f.get("collection")})}


def _egress_providers(ev: _Evidence) -> list[dict[str, Any]]:
    """External model providers content flows to, per collection."""
    out: dict[tuple[str, Optional[str]], dict[str, Any]] = {}

    def add(provider: str, collection: Optional[str], purpose: Optional[str],
            pointer: dict) -> None:
        row = out.setdefault((provider, collection), {
            "name": provider, "collection": collection, "kind": "model provider",
            "observed_purpose": purpose, "evidence": []})
        if pointer not in row["evidence"]:
            row["evidence"].append(pointer)

    for outcome in ev.ran("model_egress"):
        cov = outcome.get("coverage") or {}
        pointer = ev.pointer("model_egress", outcome)
        for flow in cov.get("flows") or []:
            if isinstance(flow, Mapping):
                for name in _names(flow, "provider", "destination", "vendor"):
                    add(name, flow.get("collection") or outcome.get("collection"),
                        flow.get("purpose") or flow.get("model"), pointer)
        for name in _names(_first(cov, "providers", "provider") or [],
                           "name", "provider"):
            add(name, outcome.get("collection"), None, pointer)
    for col in _inventory_collections(ev.inventory):
        for name in _names(_first(col, "model_providers", "egress", "providers") or [],
                           "name", "provider", "destination"):
            add(name, _col_name(col), None,
                {"source": "inventory", "collection": _col_name(col)})
    return sorted(out.values(), key=lambda r: (r["name"], str(r["collection"])))


def _store_provider(ev: _Evidence) -> Optional[dict[str, Any]]:
    kind = ev.store_kind()
    inv = ev.inventory or {}
    hosting = str(inv.get("hosting") or "")
    if kind in _MANAGED_PROVIDERS:
        return {"name": _MANAGED_PROVIDERS[kind], "collection": None,
                "kind": "managed vector-store service",
                "observed_purpose": "hosting the vector store",
                "evidence": [{"audit_id": ev.audit_id, "source": "connector kind",
                              "value": kind}]}
    provider = inv.get("provider")
    if isinstance(provider, str) and provider and hosting != "self_hosted":
        return {"name": provider, "collection": None,
                "kind": "vector-store hosting provider",
                "observed_purpose": "hosting the vector store",
                "evidence": [{"source": "inventory", "field": "provider"}]}
    return None


def _residency(ev: _Evidence) -> list[dict[str, Any]]:
    rows = []
    for outcome in ev.ran("data_residency"):
        cov = outcome.get("coverage") or {}
        regions = _names(_first(cov, "regions", "region", "locations", "location") or [],
                         "region", "name", "location")
        rows.append({"collection": outcome.get("collection"), "regions": regions,
                     "outcome": outcome.get("outcome"),
                     "statement": str(outcome.get("reason") or ""),
                     "evidence": ev.pointer("data_residency", outcome)})
    inv = ev.inventory or {}
    regions = _names(_first(inv, "regions", "region", "location") or [], "region", "name")
    if regions and not rows:
        rows.append({"collection": None, "regions": regions, "outcome": None,
                     "statement": "Region recorded in the asset inventory.",
                     "evidence": {"source": "inventory", "field": "region"}})
    return rows


def _biometric_templates(ev: _Evidence) -> tuple[str, list[dict]]:
    """('detected' | 'none_found' | 'not_assessed', pointers).

    The check's contract: ``failed`` or a truthy ``detected`` /
    ``template_collections`` in coverage means templates were found.
    """
    outcomes = ev.ran("biometric_templates")
    if not outcomes:
        return "not_assessed", [ev.pointer("biometric_templates", o)
                                for o in ev.by_check.get("biometric_templates", [])]
    pointers = [ev.pointer("biometric_templates", o) for o in outcomes]
    for o in outcomes:
        cov = o.get("coverage") or {}
        if (o.get("outcome") == "failed" or cov.get("detected")
                or cov.get("template_collections")):
            return "detected", pointers
    return "none_found", pointers


# ---------------------------------------------------------------------------
# Triggers
# ---------------------------------------------------------------------------

_TRIGGER_CAVEAT = ("The business determines whether this paragraph applies. Scan "
                   "evidence can be consistent with a trigger; it cannot establish "
                   "the purpose, intent or legal character of the processing.")


def triggers(audit: Any, inventory: Optional[Mapping[str, Any]] = None, *,
             business_inputs: Optional[Mapping[str, Any]] = None,
             store: Optional[str] = None) -> list[dict[str, Any]]:
    """Which § 7150(b) triggers the scan evidence suggests, with pointers.

    Never returns a finding that a trigger does not apply: the weakest
    statement is "no indication in the scanned scope".
    """
    return _triggers(_Evidence(audit, inventory, store),
                     _clean_inputs(business_inputs)[0])


def _triggers(ev: _Evidence, business: Mapping[str, Any]) -> list[dict[str, Any]]:
    cats = _pi_categories(ev)
    spi_observed = [c for c in cats if c["sensitive"] and c["confidence"] == _OBSERVED]
    spi_possible = [c for c in cats if c["sensitive"] and c["confidence"] == _POSSIBLE]
    classification = ev.by_check.get("data_classification", [])
    classification_ran = ev.ran("data_classification")
    classification_complete = bool(classification_ran) and all(
        (o.get("coverage") or {}).get("complete") is True for o in classification_ran)
    egress = _egress_providers(ev)
    store_provider = _store_provider(ev)
    biometric, biometric_pointers = _biometric_templates(ev)
    geolocation = [c for c in cats if c["code"] in ("ae1C", "v1G")]
    determinations = business.get("triggers") or {}

    def cat_pointers(rows: list[dict]) -> list[dict]:
        return [p for row in rows for p in row["evidence"]]

    out: list[dict[str, Any]] = []
    for spec in TRIGGERS:
        status, note, evidence = "not_determinable", "", []
        if spec.id == "7150(b)(1)":
            if egress or store_provider:
                names = sorted({r["name"] for r in egress}
                               | ({store_provider["name"]} if store_provider else set()))
                status = "review"
                note = ("Personal information is made available to "
                        + ", ".join(names) + ". Whether any of these disclosures is a "
                        "sale or sharing, rather than a disclosure to a service "
                        "provider or contractor under contract, is a legal "
                        "characterisation the business makes.")
                evidence = [p for r in egress for p in r["evidence"]] + (
                    store_provider["evidence"] if store_provider else [])
            else:
                note = ("Selling or sharing depends on commercial arrangements a scan "
                        "cannot see.")
        elif spec.id == "7150(b)(2)":
            if spi_observed:
                status = "suggested"
                note = ("Content consistent with sensitive personal information was "
                        "observed: " + "; ".join(
                            f"{c['title']} ({c['citation']})" for c in spi_observed)
                        + ". Confirm whether § 7150(b)(2)(A)'s employee-administration "
                          "exclusion covers this processing; it applies only where "
                          "the processing is solely for those purposes.")
                evidence = cat_pointers(spi_observed)
            elif spi_possible:
                status = "review"
                note = ("Content that may be sensitive personal information depending on "
                        "context was observed: " + "; ".join(
                            f"{c['title']} ({c['citation']})" for c in spi_possible) + ".")
                evidence = cat_pointers(spi_possible)
            elif classification_ran:
                status = "no_indication"
                note = ("No content consistent with sensitive personal information was "
                        "observed" + ("" if classification_complete else
                                      " in the part of the store that was scanned; "
                                      "classification was partial") + ". Categories "
                        "no detector can observe (mail and message contents, neural "
                        "data, immigration status) are not covered.")
                evidence = [ev.pointer("data_classification", o) for o in classification_ran]
            else:
                status = "not_assessed"
                note = "Data classification did not run in this audit."
                evidence = [ev.pointer("data_classification", o) for o in classification]
        elif spec.id == "7150(b)(3)":
            note = ("Whether retrieval output feeds a significant decision (financial "
                    "or lending services, housing, education, employment, healthcare) "
                    "without human involvement depends on the application, not the "
                    "store.")
        elif spec.id == "7150(b)(4)":
            note = ("Depends on whether the application infers attributes of "
                    "applicants, students, employees or contractors from systematic "
                    "observation.")
        elif spec.id == "7150(b)(5)":
            if geolocation:
                status = "review"
                note = ("Geolocation content was observed. If it is used to infer "
                        "attributes from presence at a sensitive location "
                        "(§ 7001(aaa)), this paragraph applies.")
                evidence = cat_pointers(geolocation)
            else:
                note = "Depends on how the application uses location data."
        elif spec.id == "7150(b)(6)":
            bio_cats = [c for c in cats if c["code"] in ("ae2A", "v1E")]
            if biometric == "detected" or bio_cats:
                status = "suggested"
                note = ("Biometric templates or references were observed. Confirm "
                        "whether the business uses, plans to use or permits others to "
                        "use this information to train facial-recognition, "
                        "emotion-recognition, identity-verification or other "
                        "identification or profiling technology, or ADMT for a "
                        "significant decision.")
                evidence = (biometric_pointers if biometric == "detected" else []) \
                    + cat_pointers(bio_cats)
            elif biometric == "none_found":
                status = "no_indication"
                note = ("No biometric templates were observed. Training ADMT on other "
                        "personal information is not visible to a scan.")
                evidence = biometric_pointers
            else:
                note = ("Intent to train ADMT or identification technology is not "
                        "visible to a scan; the biometric-template check did not run.")
                evidence = biometric_pointers
        determination = determinations.get(spec.id) or {}
        out.append({
            "id": spec.id, "citation": spec.citation, "title": spec.title,
            "description": spec.description, "status": status,
            "label": TRIGGER_STATUS_LABELS[status], "note": note,
            "evidence": evidence,
            "business_determination": {
                "applies": determination.get("applies"),
                "note": determination.get("note", ""),
            } if determination else None,
            "caveat": _TRIGGER_CAVEAT,
        })
    return out


# ---------------------------------------------------------------------------
# Deadlines (§ 7155, § 7157)
# ---------------------------------------------------------------------------

def _add_years(day: date, years: int) -> date:
    try:
        return day.replace(year=day.year + years)
    except ValueError:  # 29 February
        return day.replace(year=day.year + years, day=28)


def _parse_date(value: Any) -> Optional[date]:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str) and value.strip():
        try:
            return date.fromisoformat(value.strip()[:10])
        except ValueError:
            return None
    return None


def deadlines(business_inputs: Optional[Mapping[str, Any]] = None, *,
              now: Optional[datetime] = None) -> list[dict[str, Any]]:
    """The § 7155 and § 7157 timing rules, dated where the inputs allow.

    ``business_inputs`` may carry ``processing_started``,
    ``assessment_completed``, ``last_reviewed`` and ``material_change_on`` as
    ISO dates. Without them a rule is stated but left undated.
    """
    business = _clean_inputs(business_inputs)[0]
    today = (now or datetime.now(timezone.utc)).date()
    started = _parse_date(business.get("processing_started"))
    approval = business.get("review_and_approval")
    approval_date = _parse_date(approval.get("date")) if isinstance(approval, Mapping) else None
    completed = _parse_date(business.get("assessment_completed")) or approval_date
    reviewed = _parse_date(business.get("last_reviewed")) or completed
    material = _parse_date(business.get("material_change_on"))

    def row(key: str, section: str, title: str, rule: str, due: Optional[date],
            basis: str, applies: Optional[bool] = None) -> dict[str, Any]:
        return {"key": key, "section": section, "citation": f"{_REGS}, § {section}",
                "title": title, "rule": rule,
                "due": due.isoformat() if due else None,
                "days_remaining": (due - today).days if due else None,
                "date_passed": (due < today) if due else None,
                "applies": applies, "basis": basis}

    existing_applies = None if started is None else started < date(2026, 1, 1)
    if started is None:
        existing_basis = ("Applies if the processing began before 2026-01-01; record "
                          "processing_started to settle it.")
    elif existing_applies:
        existing_basis = f"Applies because the processing began on {started.isoformat()}."
    else:
        existing_basis = ("Does not apply to processing begun on or after 2026-01-01; "
                          "that processing is assessed before it starts.")
    out = [
        row("before_initiating", "7155(a)(1)", "Before initiating the processing",
            "Conduct and document the assessment before starting any processing "
            "activity listed in § 7150(b).", None,
            "Dated by the planned start of the processing."),
        row("existing_processing", "7155(b)", "Processing already under way on 2026-01-01",
            "Processing begun before 2026-01-01 and continuing after it must be "
            "assessed and documented by 2027-12-31.", date(2027, 12, 31),
            existing_basis, applies=existing_applies),
        row("periodic_review", "7155(a)(2)", "Periodic review",
            "Review, and update as necessary, at least once every three years.",
            _add_years(reviewed, 3) if reviewed else None,
            (f"Three years after the last review on {reviewed.isoformat()}."
             if reviewed else "Record assessment_completed or last_reviewed to date it.")),
        row("material_change", "7155(a)(3)", "Material change",
            "Update as soon as feasibly possible and no later than 45 calendar days "
            "after a material change: one that creates new negative impacts, "
            "increases existing ones, or weakens safeguards.",
            material + timedelta(days=45) if material else None,
            (f"45 days after the change recorded on {material.isoformat()}."
             if material else "No material change recorded.")),
        row("retention", "7155(c)", "Retention of the assessment",
            "Keep original and updated versions for as long as the processing "
            "continues or five years after completion, whichever is later.",
            _add_years(completed, 5) if completed else None,
            (f"Not before {_add_years(completed, 5).isoformat()}, and not while the "
             "processing continues." if completed else
             "Record assessment_completed to date the earliest disposal.")),
    ]
    if completed and completed.year >= 2028:
        due = date(completed.year + 1, 4, 1)
        out.append(row("agency_submission", "7157(a)(2)", "Submission to the Agency",
                       "Submit the § 7157(b) information by April 1 of the year after "
                       "the assessment was conducted.", due,
                       f"Assessment conducted in {completed.year}."))
    else:
        out.append(row("agency_submission", "7157(a)(1)", "Submission to the Agency",
                       "For assessments conducted in 2026 or 2027, submit the "
                       "§ 7157(b) information by 2028-04-01; later assessments by "
                       "April 1 of the following year (§ 7157(a)(2)).",
                       date(2028, 4, 1),
                       (f"Assessment conducted in {completed.year}." if completed
                        else "Assumes the assessment is conducted in 2026 or 2027.")))
    out.append(row("on_request", "7157(e)", "On request of the Agency or Attorney General",
                   "Produce the risk assessment reports within 30 calendar days of a "
                   "request.", None, "Dated by the request."))
    return out


#: § 7157(b): what the annual submission carries, and what evidence can inform.
SUBMISSION_FIELDS: tuple[tuple[str, str, str], ...] = (
    ("7157(b)(1)", "Business name and point of contact", "business"),
    ("7157(b)(2)", "Period covered, by month and year", "business"),
    ("7157(b)(3)", "Number of assessments conducted or updated, in total and per "
                   "§ 7150(b) activity", "business"),
    ("7157(b)(4)", "Whether the assessments involved each category in Civ. Code "
                   "§ 1798.140(v)(1)(A)-(L), (ae)(1)(A)-(G) and (ae)(2)(A)-(C)",
     "evidence informs"),
    ("7157(b)(5)", "Attestation under penalty of perjury", "business"),
    ("7157(b)(6)", "Name and title of the submitter and date of certification; "
                   "an executive meeting § 7157(c)", "business"),
)

REGULATORY_NOTES: tuple[tuple[str, str], ...] = (
    ("7151(b)", "External parties (service providers, bias experts, consumer "
                "representatives) may be involved in conducting the assessment."),
    ("7154", "The goal of the assessment is to restrict or prohibit processing whose "
             "privacy risks outweigh its benefits."),
    ("7156(a)", "One assessment may cover a comparable set of processing activities "
                "that present similar risks."),
    ("7156(b)", "An assessment prepared for another law may be used if it contains, "
                "or is paired with, everything § 7152 requires."),
    ("7001(zz)", "The risk assessment report is the documentation of § 7152(a)(1)-(3) "
                 "and (6)-(9)."),
)

# ---------------------------------------------------------------------------
# Business inputs
# ---------------------------------------------------------------------------

_MAX_TEXT = 10_000
_MAX_ITEMS = 200

#: Phrases § 7152(a)(1) and (a)(4) give as too generic.
_GENERIC_PHRASES = ("improve our service", "improving our service",
                    "improve our services", "improving our services",
                    "security purposes", "for security")


def _clean_text(value: Any) -> Optional[str]:
    if isinstance(value, str):
        text = value.strip()
        return text[:_MAX_TEXT] if text else None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return None


def _clean_people(value: Any) -> Optional[list[dict[str, str]]]:
    if isinstance(value, str):
        text = _clean_text(value)
        return [{"name": text}] if text else None
    if not isinstance(value, (list, tuple)):
        return None
    people = []
    for item in list(value)[:_MAX_ITEMS]:
        if isinstance(item, str) and item.strip():
            people.append({"name": item.strip()[:_MAX_TEXT]})
        elif isinstance(item, Mapping):
            entry: dict[str, str] = {}
            for k in ("name", "position", "role", "purpose", "category"):
                text = _clean_text(item.get(k))
                if text:
                    entry[k] = text
            if entry:
                people.append(entry)
    return people or None


def _clean_inputs(raw: Optional[Mapping[str, Any]]) -> tuple[dict[str, Any], list[str]]:
    """Validate business inputs. Unrecognised or malformed keys are reported."""
    if not isinstance(raw, Mapping):
        return {}, []
    clean: dict[str, Any] = {}
    problems: list[str] = []
    for key, value in raw.items():
        if value is None:
            continue
        if key in ("contributors", "recipients"):
            people = _clean_people(value)
            if people:
                clean[key] = people
            else:
                problems.append(f"{key}: expected a list of names or records")
        elif key == "review_and_approval":
            if isinstance(value, Mapping):
                approval: dict[str, Any] = {}
                approved_on = _parse_date(value.get("date"))
                if value.get("date") and not approved_on:
                    problems.append("review_and_approval.date: expected an ISO date")
                if approved_on:
                    approval["date"] = approved_on.isoformat()
                approvers = _clean_people(value.get("approvers"))
                if approvers:
                    approval["approvers"] = approvers
                if approval:
                    clean[key] = approval
            else:
                problems.append("review_and_approval: expected {date, approvers}")
        elif key == "will_initiate":
            if isinstance(value, bool):
                clean[key] = "Yes" if value else "No"
            elif _clean_text(value):
                clean[key] = _clean_text(value)
        elif key == "approximate_consumers":
            number = _int(value)
            text = _clean_text(value)
            if number is not None:
                clean[key] = f"{number:,}"
            elif text:
                clean[key] = text
        elif key == "triggers":
            if isinstance(value, Mapping):
                determinations = {}
                for tid, det in value.items():
                    if tid not in TRIGGER_IDS:
                        problems.append(f"triggers.{tid}: unknown § 7150(b) paragraph")
                        continue
                    if isinstance(det, bool):
                        det = {"applies": det}
                    if isinstance(det, Mapping) and isinstance(det.get("applies"), bool):
                        determinations[tid] = {"applies": det["applies"],
                                               "note": _clean_text(det.get("note")) or ""}
                    else:
                        problems.append(f"triggers.{tid}: expected {{applies: bool}}")
                if determinations:
                    clean[key] = determinations
            else:
                problems.append("triggers: expected a mapping of § 7150(b) ids")
        elif key in ("processing_started", "assessment_completed", "last_reviewed",
                     "material_change_on"):
            parsed = _parse_date(value)
            if parsed:
                clean[key] = parsed.isoformat()
            else:
                problems.append(f"{key}: expected an ISO date")
        elif key in ELEMENT_KEYS or key == "processing_activity":
            text = _clean_text(value)
            if text:
                clean[key] = text
            else:
                problems.append(f"{key}: expected text")
        else:
            problems.append(f"{key}: not a recognised input")
    return clean, problems


def validate_business_inputs(raw: Optional[Mapping[str, Any]]
                             ) -> tuple[dict[str, Any], list[str]]:
    """Normalise business inputs and list every key that was not applied.

    For an API ``PUT``: store the normalised dict, and return the problems to
    the caller rather than dropping them silently.
    """
    return _clean_inputs(raw)


# ---------------------------------------------------------------------------
# The assessment
# ---------------------------------------------------------------------------

@dataclass
class CCPARiskAssessment:
    store: str
    audit_id: str
    generated_at: str
    processing_activity: str
    elements: list[dict[str, Any]] = field(default_factory=list)
    triggers: list[dict[str, Any]] = field(default_factory=list)
    safeguards: list[dict[str, Any]] = field(default_factory=list)
    categories: list[dict[str, Any]] = field(default_factory=list)
    deadlines: list[dict[str, Any]] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)
    input_problems: list[str] = field(default_factory=list)
    review_notes: list[str] = field(default_factory=list)
    cyberaudit_support: list[dict[str, Any]] = field(default_factory=list)

    @property
    def completeness(self) -> dict[str, Any]:
        counts = {status: 0 for status in ELEMENT_STATUSES}
        for element in self.elements:
            counts[element["status"]] += 1
        total = len(self.elements)
        parts = [f"{counts['prefilled']} of {total} elements prefilled from evidence"]
        for status, text in (("partially_prefilled", "partly prefilled"),
                             ("business_provided", "provided by the business"),
                             ("requires_business_input", "need business input"),
                             ("not_assessed", "not assessed"),
                             ("not_applicable", "not applicable")):
            if counts[status]:
                parts.append(f"{counts[status]} {text}")
        safeguard_counts = {state: 0 for state in SAFEGUARD_STATES}
        for row in self.safeguards:
            safeguard_counts[row["state"]] += 1
        return {"total": total, "counts": counts, "summary": " · ".join(parts),
                "safeguards": safeguard_counts,
                "approved": any(e["key"] == "review_and_approval"
                                and e["status"] == "business_provided"
                                for e in self.elements)}

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "ccpa_risk_assessment",
            "regulation": f"{_REGS}, Article 10 (§§ 7150-7157)",
            "store": self.store, "audit_id": self.audit_id,
            "generated_at": self.generated_at,
            "processing_activity": self.processing_activity,
            "disclaimer": DISCLAIMER,
            "completeness": self.completeness,
            "coverage": self.coverage,
            "triggers": self.triggers,
            "elements": self.elements,
            "categories": self.categories,
            "unobservable_sensitive_categories": [
                {"citation": c, "title": t} for c, t in UNOBSERVABLE_SPI],
            "safeguards": self.safeguards,
            "deadlines": self.deadlines,
            "agency_submission": [{"section": s, "citation": f"{_REGS}, § {s}",
                                   "field": t, "source": src}
                                  for s, t, src in SUBMISSION_FIELDS],
            "regulatory_notes": [{"section": s, "citation": f"{_REGS}, § {s}",
                                  "note": n} for s, n in REGULATORY_NOTES],
            "cyberaudit_7123_support": self.cyberaudit_support,
            "input_problems": self.input_problems,
            "review_notes": self.review_notes,
            "sources": [REGULATION_SOURCE, STATUTE_SOURCE],
        }


def _element_evidence(key: str, ev: _Evidence, cats: list[dict], safeguards: list[dict],
                      consumers: dict, retention: dict, recipients: list[dict],
                      residency: list[dict], impacts: list[dict]) -> tuple[list[dict], bool]:
    """(evidence statements, whether the evidence covers the element fully)."""
    if key == "pi_categories":
        classification_ran = ev.ran("data_classification")
        if not classification_ran and not cats:
            return [], False
        complete = bool(classification_ran) and all(
            (o.get("coverage") or {}).get("complete") is True for o in classification_ran)
        items = [{"statement": f"{c['title']} ({c['citation']})"
                               + (" — possible; depends on context" if
                                  c["confidence"] == _POSSIBLE else "")
                               + f": {c['matches']:,} match(es) in "
                               + (", ".join(c["collections"]) or "the store"),
                  "sensitive": c["sensitive"], "evidence": c["evidence"]}
                 for c in cats]
        if not cats:
            items.append({"statement": "No personal information was detected"
                          + ("" if complete else " in the part of the store that was "
                             "scanned (classification was partial)") + ".",
                          "evidence": [ev.pointer("data_classification", o)
                                       for o in classification_ran]})
        elif not complete:
            items.append({"statement": "Classification did not cover the whole scope; "
                                       "other categories may be present.",
                          "evidence": [ev.pointer("data_classification", o)
                                       for o in classification_ran]})
        return items, complete
    if key == "minimum_necessary":
        if cats:
            return [{"statement": "Categories present in the store, for the necessity "
                                  "review: " + ", ".join(c["title"] for c in cats) + ".",
                     "evidence": []}], False
        return [], False
    if key == "method_and_sources":
        items = []
        if ev.present:
            collections = ev.scope.get("collections") or []
            kind = ev.store_kind()
            items.append({"statement": f"Content is embedded and held in vector store "
                                       f"'{ev.store}'" + (f" ({kind})" if kind else "")
                                       + (f", {len(collections)} collection(s) in scope"
                                          if collections else "") + ".",
                          "evidence": [{"audit_id": ev.audit_id, "source": "audit scope"}]})
        for row in residency:
            where = ", ".join(row["regions"]) or "not reported"
            items.append({"statement": "Data location"
                                       + (f" for '{row['collection']}'" if row["collection"]
                                          else "") + f": {where}. {row['statement']}".strip(),
                          "evidence": [row["evidence"]]})
        for row in recipients:
            if row["kind"] == "model provider":
                items.append({"statement": f"Content flows to external model provider "
                                           f"{row['name']}"
                                           + (f" from '{row['collection']}'"
                                              if row["collection"] else "") + ".",
                              "evidence": row["evidence"]})
        return items, False
    if key == "retention":
        items = []
        for s in retention["schedules"]:
            declared = s["declared"]
            items.append({"statement": ("Declared schedule"
                                        + (f" for '{s['collection']}'" if s["collection"]
                                           else "")
                                        + (f": {declared}" if isinstance(declared, (str, int))
                                           else "") + ". " + s["statement"]).strip(),
                          "evidence": [s["evidence"]]})
        for h in retention["horizons"]:
            items.append({"statement": f"Observed age in '{h['collection']}': "
                                       + (h["statement"] or "no statement recorded."),
                          "evidence": [h["evidence"]]})
        for v in retention["chunk_versions"]:
            if v["statement"]:
                items.append({"statement": f"Chunk versions in '{v['collection']}': "
                                           + v["statement"], "evidence": [v["evidence"]]})
        full = any(s["outcome"] == "passed" for s in retention["schedules"])
        return items, full
    if key == "approximate_consumers":
        if not consumers["established"]:
            return [], False
        return [{"statement": consumers["statement"], "evidence": consumers["evidence"],
                 "limits": consumers["limits"]}], True
    if key == "recipients":
        return [{"statement": f"{r['name']} ({r['kind']})"
                              + (f", collection '{r['collection']}'" if r["collection"]
                                 else "")
                              + (f"; observed use: {r['observed_purpose']}"
                                 if r["observed_purpose"] else "") + ".",
                 "evidence": r["evidence"]} for r in recipients], False
    if key == "negative_impacts":
        return [{"statement": f"{i['example']}: {i['impact']} Cause: {i['cause']}",
                 "evidence": i["evidence"]} for i in impacts], False
    if key == "safeguards":
        assessed = [s for s in safeguards if s["state"] != "not_assessed"]
        return ([{"statement": f"{s['control']}: {s['label'].lower()}"
                               + (f" — {s['reason']}" if s["reason"] else ""),
                  "state": s["state"], "evidence": s["evidence"]} for s in safeguards]
                if assessed else []), False
    return [], False


def _suggested_impacts(ev: _Evidence, cats: list[dict], safeguards: list[dict],
                       retention: dict, recipients: list[dict]) -> list[dict[str, Any]]:
    impacts: list[dict[str, Any]] = []
    ex = f"{_REGS}, § 7152(a)(5)"
    if cats:
        impacts.append({
            "example": f"{ex}(A)",
            "impact": "Unauthorised disclosure through retrieval.",
            "cause": "Personal information is embedded in a retrieval corpus, so a "
                     "query can surface it in generated output to users who were "
                     "not meant to see it.",
            "evidence": [p for c in cats for p in c["evidence"]][:20]})
    for s in safeguards:
        if s["state"] == "not_observed":
            impacts.append({
                "example": f"{ex}(A)",
                "impact": "Unauthorised access, use or disclosure.",
                "cause": f"{s['control']} was checked and not observed. {s['reason']}".strip(),
                "evidence": s["evidence"]})
    for check, cause in (("erasure_verification",
                          "Deleted consumer data was still found after erasure."),
                         ("chunk_versions",
                          "Superseded versions of chunks remain retrievable.")):
        failed = [o for o in ev.ran(check) if o.get("outcome") == "failed"]
        if failed and not (check == "erasure_verification" and any(
                s["key"] == "erasure_verification" and s["state"] == "not_observed"
                for s in safeguards)):
            impacts.append({"example": f"{ex}(C)",
                            "impact": "Impairing consumers' control over their "
                                      "personal information.",
                            "cause": cause,
                            "evidence": [ev.pointer(check, o) for o in failed]})
    if retention["undated_collections"] and cats:
        impacts.append({
            "example": f"{ex}(A)",
            "impact": "Longer exposure than the retention period intends.",
            "cause": "Records in " + ", ".join(retention["undated_collections"])
                     + " carry no ingestion date, so no retention period can be "
                       "applied to them.",
            "evidence": [ev.finding_pointer(f) for f in ev.findings
                         if f.get("category") == "retention"]})
    stigmatising = [c for c in cats if c["code"] in ("ae2B", "ae2C", "ae1D", "ae1F")]
    if stigmatising:
        impacts.append({
            "example": f"{ex}(G)-(H)",
            "impact": "Reputational or psychological harm if disclosed.",
            "cause": "Health, sexual-orientation, genetic or belief-related content is "
                     "present.",
            "evidence": [p for c in stigmatising for p in c["evidence"]][:20]})
    external = [r for r in recipients if r["kind"] == "model provider"]
    if external and cats:
        impacts.append({
            "example": f"{ex}(A)",
            "impact": "Disclosure beyond the business's systems.",
            "cause": "Content containing personal information flows to "
                     + ", ".join(sorted({r["name"] for r in external})) + ".",
            "evidence": [p for r in external for p in r["evidence"]]})
    return impacts


def _element_status(spec: ElementSpec, ev: _Evidence, evidence: list[dict], full: bool,
                    business: Mapping[str, Any]) -> str:
    if business.get(spec.key):
        return "business_provided"
    if spec.only_if_trigger:
        det = (business.get("triggers") or {}).get(spec.only_if_trigger)
        if det and det.get("applies") is False:
            return "not_applicable"
    if spec.evidence_reach == "none":
        return "requires_business_input"
    if evidence:
        # ``full`` is decided per element by the evidence: complete
        # classification for categories, a subject count, a declared schedule.
        return "prefilled" if full else "partially_prefilled"
    ran_any = any(ev.ran(check) for check in spec.checks)
    if spec.checks and not ran_any:
        return "not_assessed"
    return "requires_business_input"


def prefill_ccpa_risk_assessment(
    audit_result_or_snapshot: Any,
    *,
    inventory: Optional[Mapping[str, Any]] = None,
    business_inputs: Optional[Mapping[str, Any]] = None,
    now: Optional[datetime] = None,
    store: Optional[str] = None,
    include_cyberaudit: bool = True,
) -> CCPARiskAssessment:
    """Prefill a § 7152(a) risk assessment from one audit.

    ``store`` names the store in the output; the API should pass the registry
    id rather than the connector's name, which can be a URI or a local path.
    """
    now = now or datetime.now(timezone.utc)
    ev = _Evidence(audit_result_or_snapshot, inventory, store)
    business, problems = _clean_inputs(business_inputs)

    cats = _pi_categories(ev)
    safeguards = _safeguards(ev)
    consumers = _approximate_consumers(ev)
    retention = _retention(ev)
    recipients = _egress_providers(ev)
    provider = _store_provider(ev)
    if provider:
        recipients = [provider, *recipients]
    residency = _residency(ev)
    impacts = _suggested_impacts(ev, cats, safeguards, retention, recipients)

    elements = []
    for spec in ELEMENTS:
        evidence, full = _element_evidence(spec.key, ev, cats, safeguards, consumers,
                                           retention, recipients, residency, impacts)
        status = _element_status(spec, ev, evidence, full, business)
        value = business.get(spec.key)
        element = {**spec.to_dict(), "status": status, "status_label": STATUS_LABELS[status],
                   "evidence": evidence, "business_input": value}
        if spec.key == "approximate_consumers" and not consumers["established"]:
            element["evidence_value"] = "not established"
        elements.append(element)

    notes = []
    for key, where in (("purpose", "7152(a)(1)"), ("benefits", "7152(a)(4)")):
        text = str(business.get(key) or "").lower()
        if text and any(p in text for p in _GENERIC_PHRASES) and len(text) < 200:
            notes.append(f"The {key} reads as generic; § {where} asks for a specific "
                         "statement.")
    approval = business.get("review_and_approval") or {}
    if approval and not approval.get("approvers"):
        notes.append("An approval date is recorded without an approver; § 7152(a)(9) "
                     "requires names and positions.")
    if not ev.present:
        notes.append("No audit was supplied, so no element could be prefilled.")

    coverage = dict(ev.coverage)
    return CCPARiskAssessment(
        store=ev.store, audit_id=ev.audit_id, generated_at=now.isoformat(),
        processing_activity=str(business.get("processing_activity")
                                or f"Retrieval over vector store '{ev.store}'"),
        elements=elements, triggers=_triggers(ev, business), safeguards=safeguards,
        categories=cats, deadlines=deadlines(business, now=now), coverage=coverage,
        input_problems=problems, review_notes=notes,
        cyberaudit_support=_cyberaudit(ev) if include_cyberaudit else [])


# ---------------------------------------------------------------------------
# § 7123 cybersecurity audit: which components this evidence informs
# ---------------------------------------------------------------------------

CYBERAUDIT_COMPONENTS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("7123(c)(1)", "Authentication", ("authentication",)),
    ("7123(c)(2)", "Encryption of personal information at rest and in transit",
     ("at_rest_encryption", "transport_encryption")),
    ("7123(c)(3)", "Account management and access controls",
     ("tenant_isolation", "authentication")),
    ("7123(c)(4)(A)", "Personal-information inventories, classification and tagging",
     ("asset_inventory", "data_classification")),
    ("7123(c)(4)(B)", "Hardware and software inventories", ("asset_inventory",)),
    ("7123(c)(5)(A)", "Software updates and upgrades", ("server_vulnerability", "cve")),
    ("7123(c)(5)(B)", "Securing on-premises and cloud environments",
     ("network_exposure", "transport_encryption")),
    ("7123(c)(5)(D)", "Security patch management", ("server_vulnerability", "cve")),
    ("7123(c)(6)", "Vulnerability scanning", ("server_vulnerability", "cve")),
    ("7123(c)(10)", "Segmentation of the information system",
     ("tenant_isolation", "network_exposure")),
    ("7123(c)(11)", "Limitation and control of ports, services and protocols",
     ("network_exposure",)),
    ("7123(c)(15)", "Oversight of service providers, contractors and third parties",
     ("model_egress",)),
    ("7123(c)(16)", "Retention schedules and disposal",
     ("retention_schedule", "retention_horizon", "erasure_verification",
      "chunk_versions")),
)


def cyberaudit_7123_support(audit: Any, inventory: Optional[Mapping[str, Any]] = None,
                            *, store: Optional[str] = None) -> list[dict[str, Any]]:
    """Which § 7123(c) components this audit's checks inform.

    The audit itself is performed by a qualified, objective, independent
    auditor (§ 7122(a)); this lists evidence the auditor can use, never a
    component's result.
    """
    return _cyberaudit(_Evidence(audit, inventory, store))


def _cyberaudit(ev: _Evidence) -> list[dict[str, Any]]:
    out = []
    for section, title, checks in CYBERAUDIT_COMPONENTS:
        states = []
        for check in checks:
            state, _, reason, pointers = _check_state(ev, (check,))
            states.append({"check": check, "state": state, "reason": reason,
                           "evidence": pointers})
        assessed = [s for s in states if s["state"] != "not_assessed"]
        availability = ("evidence_available" if len(assessed) == len(states)
                        else "partial_evidence" if assessed else "not_assessed")
        out.append({"section": section, "citation": f"{_REGS}, § {section}",
                    "component": title, "evidence_availability": availability,
                    "checks": states,
                    "note": "Informs the independent auditor's assessment of this "
                            "component (§ 7122(a)); it is not that assessment."})
    return out


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _coverage_banner(a: CCPARiskAssessment) -> str:
    status = a.coverage.get("status")
    not_assessed = [s["control"] for s in a.safeguards if s["state"] == "not_assessed"]
    if a.coverage.get("complete") is True and not not_assessed:
        return ("<p class='muted'>Every check this workbook reads that ran in the audit "
                "covered its full scope. Checks that did not run are marked below.</p>")
    unmeasured = ", ".join(not_assessed) or "one or more checks"
    return ("<p class='banner'><b>Incomplete evidence (audit coverage: "
            f"{_esc(status or 'unknown')}).</b> This workbook does not establish "
            f"{_esc(unmeasured)}. A check that did not run is not evidence that a "
            "safeguard is in place or that a category is absent; each "
            "not-assessed row needs a reviewer's resolution.</p>")


def _evidence_list(items: list[dict]) -> str:
    if not items:
        return "<span class='muted'>—</span>"
    lis = []
    for item in items:
        limits = "".join(f"<br><span class='muted'>{_esc(x)}</span>"
                         for x in item.get("limits", []))
        lis.append(f"<li>{_esc(item.get('statement'))}{limits}</li>")
    return "<ul>" + "".join(lis) + "</ul>"


def _business_value(value: Any) -> str:
    if value in (None, "", [], {}):
        return ""
    if isinstance(value, list):
        return "<ul>" + "".join(
            "<li>" + _esc(", ".join(f"{v}" for v in item.values())
                          if isinstance(item, Mapping) else item) + "</li>"
            for item in value) + "</ul>"
    if isinstance(value, Mapping):
        parts = []
        if value.get("date"):
            parts.append(f"Approved {_esc(value['date'])}")
        for person in value.get("approvers", []):
            parts.append(_esc(", ".join(str(v) for v in person.values())))
        return "<br>".join(parts)
    return _esc(value)


def build_ccpa_risk_html(assessment: CCPARiskAssessment) -> str:
    a = assessment
    comp = a.completeness
    p = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        f"<title>CCPA risk assessment — {_esc(a.store)}</title>",
        "<style>body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;"
        "margin:2rem;color:#1a1a1a}h1{margin-bottom:0}h2{margin-top:1.8rem;"
        "border-bottom:2px solid #eee;padding-bottom:.3rem}.muted{color:#777;"
        "font-size:.85em}table{border-collapse:collapse;width:100%;font-size:.9em;"
        "margin-top:.5rem}th,td{border:1px solid #e3e3e3;padding:.45rem .6rem;"
        "text-align:left;vertical-align:top}th{background:#f7f7f7}ul{margin:0;"
        "padding-left:1.1rem}.banner{background:#fff4e5;border-left:4px solid #e8a33d;"
        "padding:.6rem .8rem}</style></head><body>",
        "<h1>CCPA risk assessment workbook</h1>",
        f"<p class='muted'>{_esc(REGULATION_SOURCE['title'])} · store "
        f"<code>{_esc(a.store)}</code>"
        + (f" · audit <code>{_esc(a.audit_id)}</code>" if a.audit_id else "")
        + f" · generated {_esc(a.generated_at)}</p>",
        f"<p><b>Processing activity:</b> {_esc(a.processing_activity)}</p>",
        f"<p>{_esc(DISCLAIMER)}</p>",
        _coverage_banner(a),
        f"<p><b>Completeness:</b> {_esc(comp['summary'])}.</p>",
    ]
    if not comp["approved"]:
        p.append("<p class='muted'>Draft: no review and approval has been recorded "
                 "(§ 7152(a)(9)).</p>")
    for note in a.review_notes:
        p.append(f"<p class='banner'>{_esc(note)}</p>")
    if a.input_problems:
        p.append("<p class='banner'>Inputs not applied: "
                 + _esc("; ".join(a.input_problems)) + "</p>")

    p.append("<h2>When an assessment is required (§ 7150(b))</h2>")
    p.append("<table><tr><th>Paragraph</th><th>Activity</th><th>Scan evidence</th>"
             "<th>Note</th><th>Business determination</th></tr>")
    for t in a.triggers:
        det = t.get("business_determination")
        det_text = ("—" if not det else
                    ("Applies" if det.get("applies") else "Does not apply")
                    + (f": {det.get('note')}" if det.get("note") else ""))
        p.append(f"<tr><td>{_esc(t['id'])}</td><td>{_esc(t['title'])}</td>"
                 f"<td>{_esc(t['label'])}</td><td>{_esc(t['note'])}</td>"
                 f"<td>{_esc(det_text)}</td></tr>")
    p.append("</table>")
    p.append(f"<p class='muted'>{_esc(_TRIGGER_CAVEAT)}</p>")

    p.append("<h2>Required content (§ 7152(a))</h2>")
    p.append("<table><tr><th>Subsection</th><th>Element</th><th>Status</th>"
             "<th>Evidence</th><th>Business input</th></tr>")
    for e in a.elements:
        business = _business_value(e.get("business_input"))
        prompt = ("" if business else
                  f"<span class='muted'>{_esc(e['prompt'])}</span>")
        in_report = "" if e["in_report"] else \
            "<br><span class='muted'>Identified; outside the report per § 7001(zz)</span>"
        p.append(f"<tr><td>{_esc(e['subsection'])}</td><td><b>{_esc(e['title'])}</b>"
                 f"{in_report}</td><td>{_esc(e['status_label'])}</td>"
                 f"<td>{_evidence_list(e['evidence'])}</td>"
                 f"<td>{business or prompt}</td></tr>")
    p.append("</table>")
    p.append("<p class='muted'>Not observable by any detector, so never shown as "
             "absent: " + _esc("; ".join(f"{t} ({c})" for c, t in UNOBSERVABLE_SPI))
             + ".</p>")

    p.append("<h2>Safeguards observed (§ 7152(a)(6))</h2>")
    p.append("<table><tr><th>Control</th><th>State</th><th>Assessed by</th>"
             "<th>Basis</th></tr>")
    for s in a.safeguards:
        p.append(f"<tr><td>{_esc(s['control'])}</td><td>{_esc(s['label'])}</td>"
                 f"<td>{_esc(s['assessed_by'] or '—')}</td>"
                 f"<td>{_esc(s['reason'])}</td></tr>")
    p.append("</table>")

    p.append("<h2>Timing (§§ 7155, 7157)</h2>")
    p.append("<table><tr><th>Section</th><th>Rule</th><th>Date</th><th>Basis</th></tr>")
    for d in a.deadlines:
        p.append(f"<tr><td>{_esc(d['section'])}</td><td><b>{_esc(d['title'])}.</b> "
                 f"{_esc(d['rule'])}</td><td>{_esc(d['due'] or '—')}</td>"
                 f"<td>{_esc(d['basis'])}</td></tr>")
    p.append("</table>")

    p.append("<h2>Agency submission (§ 7157(b))</h2><ul>")
    for section, title, source in SUBMISSION_FIELDS:
        p.append(f"<li>{_esc(section)}: {_esc(title)} "
                 f"<span class='muted'>({_esc(source)})</span></li>")
    p.append("</ul>")

    if a.cyberaudit_support:
        p.append("<h2>Cybersecurity audit components this evidence informs (§ 7123(c))</h2>")
        p.append("<table><tr><th>Component</th><th>Evidence</th><th>Checks</th></tr>")
        for c in a.cyberaudit_support:
            checks = ", ".join(f"{s['check']}: {SAFEGUARD_LABELS[s['state']].lower()}"
                               for s in c["checks"])
            p.append(f"<tr><td>{_esc(c['section'])} {_esc(c['component'])}</td>"
                     f"<td>{_esc(c['evidence_availability'].replace('_', ' '))}</td>"
                     f"<td>{_esc(checks)}</td></tr>")
        p.append("</table><p class='muted'>These rows inform an independent "
                 "auditor's work (§ 7122(a)); they are not audit results.</p>")

    p.append("<h2>Sources</h2><ul>")
    for src in (REGULATION_SOURCE, STATUTE_SOURCE):
        p.append(f"<li>{_esc(src['title'])} — <a href='{_esc(src['url'])}'>"
                 f"{_esc(src['url'])}</a> (retrieved {_esc(src['retrieved_at'])})</li>")
    p.append("</ul></body></html>")
    return "\n".join(p)


__all__ = [
    "CCPARiskAssessment", "ELEMENTS", "ElementSpec", "TRIGGERS", "TriggerSpec",
    "REGULATION_SOURCE", "STATUTE_SOURCE", "DISCLAIMER", "SUBMISSION_FIELDS",
    "CYBERAUDIT_COMPONENTS", "build_ccpa_risk_html", "cyberaudit_7123_support",
    "deadlines", "prefill_ccpa_risk_assessment", "triggers", "validate_business_inputs",
]
