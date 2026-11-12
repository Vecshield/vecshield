"""What each framework says about the store controls, and what VecShield may claim.

The store controls are the checks that look past the corpus text to how the
store is run: retention against a declared schedule, the database server's
vulnerabilities and support status, the model providers the store sends data
to, where its data sits, biometric templates, corpus integrity patterns,
superseded versions, and the asset inventory.

This is their regulatory basis, in the same shape as :mod:`crypto_basis`: a
ceiling, not an evaluation. Each row names the framework, how it relates to
the control, and the pack criteria that evaluate it. Criteria in
``packs.py`` do the evaluating; tests hold them to this table.

**Regimes outside the pack.** Several regimes bear on these controls but are
deliberately not frameworks in the pack — NYDFS 23 NYCRR 500.13, Minnesota
325M.16, COPPA, BIPA and other state biometric laws, GLBA, the US Department of
Justice data security rule (28 CFR Part 202), and CISA's Binding Operational
Directive 22-01. Broad framework-catalog expansion is deliberately not
pursued: it would strain the source-record discipline that makes the pack
trustworthy. They appear here as
*references* a reviewer should know about, each with its citation and where
it was checked. A reference never produces a criterion status.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

#: How a framework relates to a control. Display labels only; none is a score.
RELATIONSHIPS = {
    "direct": "Direct",
    "direct_if_in_scope": "Direct where the data is in scope",
    "required": "Required specification",
    "risk_based": "Risk-based",
    "control_evidence": "Control evidence",
    "supporting": "Supporting evidence only",
    "context": "Context only; no criterion",
}


@dataclass(frozen=True)
class FrameworkBasis:
    """How one pack framework relates to one control."""

    framework: str
    relationship: str
    interpretation: str
    #: Pack criteria that evaluate this control for this framework.
    criteria: tuple[str, ...] = ()
    source_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.relationship not in RELATIONSHIPS:
            raise ValueError(f"unknown relationship: {self.relationship}")
        if self.relationship == "context" and self.criteria:
            raise ValueError(f"{self.framework}: a context-only row names no criterion")

    def to_dict(self) -> dict[str, Any]:
        return {"framework": self.framework, "relationship": self.relationship,
                "relationship_label": RELATIONSHIPS[self.relationship],
                "interpretation": self.interpretation,
                "criteria": list(self.criteria), "source_ids": list(self.source_ids)}


@dataclass(frozen=True)
class Reference:
    """A regime outside the pack that bears on a control. Never a status.

    ``reference_set`` names a verified set in :mod:`compliance.data` whose
    entry ``id`` carries the citation, source URL and verification date. A
    reference with no set carries those itself.
    """

    id: str
    regime: str
    why: str
    reference_set: Optional[str] = None
    citation: str = ""
    url: str = ""
    checked_on: str = ""
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"id": self.id, "regime": self.regime, "why": self.why,
                               "reference_set": self.reference_set,
                               "citation": self.citation, "url": self.url,
                               "checked_on": self.checked_on, "note": self.note}
        if self.reference_set:
            from vecshield_platform.compliance.data import load_references

            data = load_references(self.reference_set)
            entry = next((r for r in data["references"] if r["id"] == self.id), None)
            if entry is not None:
                out["citation"] = entry.get("citation", "")
                out["url"] = entry.get("source_url", "")
                out["checked_on"] = data.get("verified_on", "")
        return out


@dataclass(frozen=True)
class ControlBasis:
    """One store control: the checks, the frameworks, and what else bears on it."""

    control: str
    label: str
    checks: tuple[str, ...]
    frameworks: tuple[FrameworkBasis, ...]
    #: Artifacts a reviewer typically needs for this control; every name is in
    #: the evidence vocabulary.
    evidence: tuple[str, ...] = ()
    references: tuple[Reference, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {"control": self.control, "label": self.label,
                "checks": list(self.checks),
                "frameworks": [f.to_dict() for f in self.frameworks],
                "evidence": list(self.evidence),
                "references": [r.to_dict() for r in self.references]}


F = FrameworkBasis
R = Reference

#: CISA BOD 22-01, read 2026-09-29 at the URL below (SHA-256 of the page
#: 89521a4c7e9b413b1f6c77e5199c4c9353e24291999fae1affce992e56792654).
_BOD_22_01 = R(
    id="cisa_bod_22_01", regime="CISA Binding Operational Directive 22-01",
    citation="BOD 22-01, Reducing the Significant Risk of Known Exploited "
             "Vulnerabilities",
    url="https://www.cisa.gov/news-events/directives/"
        "bod-22-01-reducing-significant-risk-known-exploited-vulnerabilities",
    checked_on="2026-09-29",
    why="A server vulnerability in CISA's Known Exploited Vulnerabilities "
        "catalog is exploited in the wild; the finding carries the catalog "
        "entry and its required action.",
    note="Binds US federal civilian agencies only. For everyone else the "
         "catalog is a prioritisation signal, which is how the posture policy "
         "uses it.")

#: The DOJ rule, as read into posture/data/us_doj_dsp.json (its _as_of date).
_DOJ_202 = R(
    id="doj_28_cfr_202", regime="US DOJ Data Security Program",
    citation="28 CFR Part 202",
    url="https://www.ecfr.gov/current/title-28/chapter-I/part-202",
    checked_on="2026-09-29",
    why="Bulk US sensitive personal data reachable from a country of concern "
        "can be a prohibited or restricted transaction. The residency check "
        "reports countries of concern and, where subject counts are available, "
        "the bulk thresholds.",
    note="Thresholds and the country list are in posture/data/us_doj_dsp.json. "
         "Whether the rule reaches a transaction is a legal determination.")

STORE_CONTROLS_BASIS: tuple[ControlBasis, ...] = (
    ControlBasis(
        control="retention_schedule",
        label="Retention against a declared schedule",
        checks=("retention_schedule", "retention_horizon"),
        frameworks=(
            F("PCI-DSS", "direct_if_in_scope",
              "Account data is kept no longer than the entity's retention "
              "period, verified at least quarterly.",
              criteria=("PCI-DSS-3-2-1-RETENTION-01",),
              source_ids=("pci-dss-req-3-2-1",)),
            F("GDPR", "direct",
              "Storage limitation: necessity is the controller's judgement; the "
              "check supplies ages against the controller's own schedule.",
              criteria=("GDPR-STORAGE-LIMITATION-01",),
              source_ids=("gdpr-art-5-1-e",)),
            F("HIPAA", "context",
              "HIPAA sets no general retention limit for PHI; the six-year "
              "period at 164.316(b)(2)(i) is for documentation.",
              source_ids=("hipaa-164-316-b-2-i",)),
            F("CCPA/CPRA", "context",
              "Retention periods per category are disclosed and documented in "
              "the risk assessment; no criterion evaluates the notice.",
              source_ids=("ccpa-regs-7152",)),
        ),
        evidence=("retention_schedule", "data_retention_policy",
                  "quarterly_deletion_evidence"),
        references=(
            R("coppa_16_cfr_312_10", "COPPA Rule",
              "Children's personal information is kept only as long as "
              "reasonably necessary under a written retention policy; declare "
              "a rule for the 'minor' qualifier.", reference_set="retention"),
            R("bipa_740_ilcs_14_15_a", "Illinois BIPA",
              "Biometric identifiers carry a published destruction deadline.",
              reference_set="retention"),
            R("glba_16_cfr_314_4_c_6", "GLBA Safeguards Rule",
              "Customer information is disposed of within two years of last "
              "use, with exceptions.", reference_set="retention"),
            R("ccpa_1798_100_a_3", "CCPA",
              "Retention per category of personal information is disclosed and "
              "limited to what is reasonably necessary.",
              reference_set="retention"),
        )),
    ControlBasis(
        control="server_vulnerabilities",
        label="Database server vulnerabilities and support status",
        checks=("server_vulnerability", "server_support_status", "cve"),
        frameworks=(
            F("PCI-DSS", "direct_if_in_scope",
              "Vulnerabilities are identified and ranked, patches installed, and "
              "technologies reviewed yearly for continued security fixes.",
              criteria=("PCI-DSS-6-3-VULNERABILITIES-01",
                        "PCI-DSS-12-3-4-SUPPORTED-SOFTWARE-01"),
              source_ids=("pci-dss-req-6-3-1", "pci-dss-req-6-3-3",
                          "pci-dss-req-12-3-4")),
            F("HIPAA", "required",
              "Risk management reduces known vulnerabilities to a reasonable "
              "and appropriate level.",
              criteria=("HIPAA-164-308-A1IIB-RISK-MGMT-01",),
              source_ids=("hipaa-164-308-a-1-ii-b",)),
            F("SOC 2", "control_evidence",
              "Detection of newly discovered vulnerabilities.",
              criteria=("SOC2-CC7.1-VULNERABILITIES-01",),
              source_ids=("tsc-cc7-1",)),
            F("CCPA/CPRA", "direct",
              "For businesses subject to the cybersecurity audit, which assesses "
              "software updates, patch management and vulnerability scans.",
              criteria=("CCPA-7123-PATCHING-01",),
              source_ids=("ccpa-regs-7123-c-5",)),
        ),
        evidence=("vulnerability_management_procedure", "patch_records",
                  "software_support_inventory", "provider_patching_statement"),
        references=(_BOD_22_01,)),
    ControlBasis(
        control="model_egress",
        label="Model providers the store sends data to",
        checks=("model_egress",),
        frameworks=(
            F("GDPR", "direct",
              "Processors under contract, sub-processors authorised, recipients "
              "in the record of processing.",
              criteria=("GDPR-28-30-PROCESSORS-01",),
              source_ids=("gdpr-art-28", "gdpr-art-30")),
            F("HIPAA", "direct",
              "A vendor receiving ePHI is a business associate under contract.",
              criteria=("HIPAA-164-308-B1-BAA-01",),
              source_ids=("hipaa-164-308-b-1", "hipaa-164-502-e")),
            F("SOC 2", "control_evidence",
              "Vendor and business partner risk is assessed and managed.",
              criteria=("SOC2-CC9.2-VENDORS-01",), source_ids=("tsc-cc9-2",)),
            F("CCPA/CPRA", "direct",
              "Recipients of personal information are documented in the risk "
              "assessment, which sensitive processing requires.",
              criteria=("CCPA-7150-RISK-ASSESSMENT-01",),
              source_ids=("ccpa-regs-7150", "ccpa-regs-7152")),
        ),
        evidence=("sub_processor_register", "data_processing_agreement",
                  "business_associate_agreements", "model_integration_configuration",
                  "vendor_risk_assessments")),
    ControlBasis(
        control="data_residency",
        label="Where the store's data sits and goes",
        checks=("data_residency",),
        frameworks=(
            F("GDPR", "direct",
              "Transfers outside the EEA rest on adequacy or appropriate "
              "safeguards.",
              criteria=("GDPR-44-46-TRANSFERS-01",),
              source_ids=("gdpr-art-44", "gdpr-art-45", "gdpr-art-46")),
        ),
        evidence=("transfer_mechanism", "data_residency_statement",
                  "residency_policy", "country_of_concern_access_assessment"),
        references=(_DOJ_202,)),
    ControlBasis(
        control="biometric_templates",
        label="Face and voice template collections",
        checks=("biometric_templates",),
        frameworks=(
            F("GDPR", "direct",
              "Biometric data used to identify a person is a special category, "
              "processed only under an Art. 9(2) condition.",
              criteria=("GDPR-9-BIOMETRIC-01",), source_ids=("gdpr-art-9",)),
            F("CCPA/CPRA", "direct",
              "Biometric identification is sensitive personal information, "
              "which needs a risk assessment.",
              criteria=("CCPA-7150-RISK-ASSESSMENT-01",),
              source_ids=("ccpa-1798-140-ae", "ccpa-regs-7150")),
            F("EU AI Act", "supporting",
              "Face databases built by untargeted scraping are prohibited; the "
              "scan shows a face-template store exists, not how it was built.",
              criteria=("AIACT-ART5-1E-FACE-SCRAPING-01",),
              source_ids=("aiact-art-5-1-e",)),
        ),
        evidence=("biometric_consent_records", "biometric_retention_schedule",
                  "data_protection_impact_assessment", "face_image_provenance_record"),
        references=(
            R("bipa_740_ilcs_14_15", "Illinois BIPA",
              "Written release before collection, and a published retention "
              "schedule.", reference_set="biometric"),
            R("texas_cubi_bus_com_503_001", "Texas CUBI",
              "Notice and consent before capture, and destruction deadlines.",
              reference_set="biometric"),
            R("washington_rcw_19_375_020", "Washington RCW 19.375",
              "Notice and consent before enrolment in a database.",
              reference_set="biometric"),
            R("colorado_crs_6_1_1314", "Colorado Privacy Act",
              "A written biometric policy with a retention schedule.",
              reference_set="biometric"),
        )),
    ControlBasis(
        control="corpus_integrity",
        label="Corpus integrity and poisoning patterns",
        checks=("corpus_duplication", "retrieval_hubness", "ingestion_burst",
                "embedding_anomaly"),
        frameworks=(
            F("HIPAA", "direct",
              "ePHI is protected from improper alteration; planted or "
              "unexplained content is a candidate alteration.",
              criteria=("HIPAA-164-312-C1-INTEGRITY-01",),
              source_ids=("hipaa-164-312-c-1",)),
            F("SOC 2", "control_evidence",
              "Anomalies are detected and reviewed; changes to data are "
              "controlled.",
              criteria=("SOC2-CC7.2-ANOMALY-01", "SOC2-CC8.1-CHANGE-01"),
              source_ids=("tsc-cc7-2", "tsc-cc8-1")),
            F("EU AI Act", "supporting",
              "Art. 15(5) names data poisoning among the attacks a high-risk "
              "system's technical solutions address where appropriate.",
              criteria=("AIACT-ART15-5-POISONING-01",),
              source_ids=("aiact-art-15-5",)),
        ),
        evidence=("ingest_controls_description", "integrity_review_records",
                  "change_approval_records")),
    ControlBasis(
        control="chunk_versions",
        label="Superseded document versions",
        checks=("chunk_versions",),
        frameworks=(
            F("GDPR", "direct",
              "Inaccurate personal data is erased or rectified; corrected data "
              "whose old chunks remain is still retrievable.",
              criteria=("GDPR-ACCURACY-01",),
              source_ids=("gdpr-art-5-1-d", "gdpr-art-16")),
            F("HIPAA", "direct",
              "A stale version beside the current one is an integrity question "
              "for a reviewer.",
              criteria=("HIPAA-164-312-C1-INTEGRITY-01",),
              source_ids=("hipaa-164-312-c-1",)),
            F("SOC 2", "control_evidence",
              "Replacing a document is a change to data.",
              criteria=("SOC2-CC8.1-CHANGE-01",), source_ids=("tsc-cc8-1",)),
        ),
        evidence=("rectification_procedure", "document_update_procedure")),
    ControlBasis(
        control="access_grants",
        label="Least privilege of the retrieval role",
        checks=("access_grants",),
        frameworks=(
            F("HIPAA", "required",
              "Technical access control limits ePHI to authorized users; a "
              "retrieval role that bypasses row security, or that every role "
              "can read through, defeats it.",
              criteria=("HIPAA-164-312-A1-ACCESS-CONTROL-01",
                        "HIPAA-164-308-A4-ACCESS-MGMT-01"),
              source_ids=("hipaa-164-312-a-1", "hipaa-164-308-a-4")),
            F("GDPR", "risk_based",
              "Appropriate measures against unauthorised access to personal "
              "data include limiting what the reading role can do.",
              criteria=("GDPR-SECURITY-32-01",),
              source_ids=("gdpr-art-32-1-b",)),
            F("SOC 2", "supporting",
              "Logical access over protected information assets; the check "
              "supplies one store's grants, not the entity's access program. "
              "No criterion cites it yet.",
              source_ids=("tsc-cc6-1",)),
        ),
        evidence=("authorized_access_policy", "access_review_record")),
    ControlBasis(
        control="server_hardening",
        label="Database server hardening (PostgreSQL)",
        checks=("server_hardening",),
        # A bundle of independent settings (trust and md5 authentication, TLS,
        # statement logging, pgaudit). No criterion cites it: a criterion
        # would fail on whichever rule fired, whatever it was about. The rows
        # below say which settings bear on which obligation, as context.
        frameworks=(
            F("HIPAA", "supporting",
              "ssl and the TLS floor bear on transmission security; pgaudit on "
              "audit controls. No regulatory mapping beyond that.",
              source_ids=("hipaa-164-312-e-1", "hipaa-164-312-b")),
            F("PCI-DSS", "supporting",
              "md5 password hashing and clear-text password authentication bear "
              "on rendering authentication factors unreadable. No regulatory "
              "mapping beyond that.",
              source_ids=("pci-dss-req-8-3-2",)),
        ),
        evidence=("store_audit_log_configuration", "transport_security_statement")),
    ControlBasis(
        control="asset_inventory",
        label="Asset inventory",
        checks=("asset_inventory",),
        frameworks=(
            F("CCPA/CPRA", "direct",
              "For businesses subject to the cybersecurity audit, which assesses "
              "personal-information and software inventories.",
              criteria=("CCPA-7123-INVENTORY-01",),
              source_ids=("ccpa-regs-7123-c-4",)),
        ),
        evidence=("asset_owner_declarations",),
        references=(
            R("nydfs_23_nycrr_500_13_a", "NYDFS Cybersecurity Regulation",
              "A documented asset inventory tracking owner, location, "
              "classification, support expiration and recovery objectives.",
              reference_set="inventory"),
            R("minnesota_325m_16_subd_2_c", "Minnesota Consumer Data Privacy Act",
              "Reasonable security includes an inventory of the data managed.",
              reference_set="inventory"),
        )),
)


def store_controls_basis() -> list[dict[str, Any]]:
    return [row.to_dict() for row in STORE_CONTROLS_BASIS]


def basis_for_control(control: str) -> Optional[ControlBasis]:
    return next((row for row in STORE_CONTROLS_BASIS if row.control == control), None)


def references() -> list[Reference]:
    """Every reference to a regime outside the pack, once each."""
    seen: dict[str, Reference] = {}
    for row in STORE_CONTROLS_BASIS:
        for ref in row.references:
            seen.setdefault(ref.id, ref)
    return list(seen.values())
