"""What each framework actually says about encryption, and what VecShield may claim.

This is the regulatory basis for cryptographic posture (docs/crypto_posture.md,
"Regulatory basis"). It is the ceiling: no criterion may claim a stronger
relationship than its framework's row supports, and the EU AI Act row has no
criterion at all, because the Act states no encryption requirement.

The rows are data, not evaluation. Criteria in ``packs.py`` do the evaluating;
this module labels the relationship for display and lets tests hold the
criteria to it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

#: How a framework relates to an encryption observation. Display labels only;
#: none of these is a score.
RELATIONSHIPS = {
    "direct": "Direct",
    #: The provision names encryption as something an audit assesses; it does
    #: not itself require the entity to encrypt.
    "audit_component": "Assessed in a required audit",
    "direct_if_pan": "Direct where PAN is present",
    "risk_based": "Risk-based",
    "addressable": "Addressable",
    "control_evidence": "Control evidence",
    "supporting": "Supporting evidence only",
}


@dataclass(frozen=True)
class CryptoBasis:
    framework: str
    at_rest: str
    in_transit: str
    interpretation: str
    relationship: str
    #: Criteria in the pack that evaluate encryption for this framework. Empty
    #: for a framework whose relationship is supporting only.
    criteria: tuple[str, ...] = field(default_factory=tuple)
    source_ids: tuple[str, ...] = field(default_factory=tuple)
    applicability: str = ""

    def __post_init__(self) -> None:
        if self.relationship not in RELATIONSHIPS:
            raise ValueError(f"unknown relationship: {self.relationship}")
        if self.relationship == "supporting" and self.criteria:
            raise ValueError(f"{self.framework}: a supporting-only framework cannot "
                             "carry an encryption criterion")

    def to_dict(self) -> dict[str, Any]:
        return {"framework": self.framework, "at_rest": self.at_rest,
                "in_transit": self.in_transit, "interpretation": self.interpretation,
                "relationship": self.relationship,
                "relationship_label": RELATIONSHIPS[self.relationship],
                "criteria": list(self.criteria), "source_ids": list(self.source_ids),
                "applicability": self.applicability}


CRYPTO_BASIS: tuple[CryptoBasis, ...] = (
    CryptoBasis(
        framework="CCPA/CPRA",
        at_rest="Named as a component the cybersecurity audit assesses, where "
                "applicable (2026 regulations)",
        in_transit="Named as a component the cybersecurity audit assesses, where "
                   "applicable (2026 regulations)",
        interpretation="Evidence for an audit component for businesses subject "
                       "to the cybersecurity audit; the regulation does not "
                       "itself require the business to encrypt",
        relationship="audit_component",
        criteria=("CCPA-CYBERAUDIT-ENCRYPTION-01",),
        source_ids=("ccpa-cppa-cyberaudit", "ccpa-1798-150"),
        applicability="Businesses subject to the CPPA cybersecurity-audit "
                      "requirement"),
    CryptoBasis(
        framework="GDPR",
        at_rest="Explicitly contemplated, risk-based",
        in_transit="Explicitly contemplated, risk-based",
        interpretation="Appropriate according to risk, not universally mandatory",
        relationship="risk_based",
        criteria=("GDPR-32-1A-ENCRYPTION-01",),
        source_ids=("gdpr-art-32-1-a",),
        applicability="Processing personal data of EU data subjects"),
    CryptoBasis(
        framework="HIPAA",
        at_rest="Explicit, but currently “addressable”",
        in_transit="Explicit, but currently “addressable”",
        interpretation="Encrypt if reasonable/appropriate; otherwise document "
                       "alternative",
        relationship="addressable",
        criteria=("HIPAA-164-312-A2IV-ENCRYPTION-01",
                  "HIPAA-164-312-E2II-ENCRYPTION-01"),
        source_ids=("hipaa-164-312-a-2-iv", "hipaa-164-312-e-2-ii",
                    "hipaa-164-306-d"),
        applicability="Covered entities and business associates handling ePHI"),
    CryptoBasis(
        framework="PCI-DSS",
        at_rest="Stored PAN must be unreadable; encryption is one permitted "
                "mechanism",
        in_transit="Strong cryptography explicitly required for PAN over "
                   "open/public networks",
        interpretation="Very strong if PAN is in vector DB",
        relationship="direct_if_pan",
        criteria=("PCI-DSS-3-STORAGE-01", "PCI-DSS-4-2-1-TRANSMISSION-01"),
        source_ids=("pci-dss-req-3-5-1", "pci-dss-req-3-5-1-2",
                    "pci-dss-req-4-2-1"),
        applicability="Account data stored, processed or transmitted"),
    CryptoBasis(
        framework="SOC 2",
        at_rest="AICPA point of focus explicitly discusses encryption of data at "
                "rest based on risk",
        in_transit="AICPA point of focus explicitly discusses encryption/secure "
                   "channels",
        interpretation="Excellent audit-evidence mapping, but SOC 2 is not a "
                       "statute",
        relationship="control_evidence",
        criteria=("SOC2-CC6.1-ENCRYPTION-01", "SOC2-CC6.7-TRANSMISSION-01"),
        source_ids=("tsc-cc6-1", "tsc-cc6-7"),
        applicability="Criteria in audit scope"),
    CryptoBasis(
        framework="EU AI Act",
        at_rest="No explicit at-rest encryption requirement",
        in_transit="No explicit transit-encryption requirement",
        interpretation="Supporting cybersecurity/privacy control only; don't claim "
                       "direct mandate",
        relationship="supporting",
        source_ids=("aiact-art-15", "aiact-omnibus-2026-1744"),
        applicability="High-risk AI systems (Art. 15 cybersecurity), as context"),
)


def crypto_basis() -> list[dict[str, Any]]:
    return [row.to_dict() for row in CRYPTO_BASIS]


def basis_for(framework: str) -> CryptoBasis | None:
    wanted = framework.casefold()
    return next((row for row in CRYPTO_BASIS if row.framework.casefold() == wanted),
                None)
