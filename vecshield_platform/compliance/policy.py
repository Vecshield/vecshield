"""Declarative policy engine.

A Policy is a named condition over a Finding plus an action to take when it
matches. Conditions are data, not code, so policies can live in config and be
reviewed/audited. Example:

    Policy(
        id="phi-high-inversion",
        description="PHI in a highly-invertible collection",
        when={"requires_label": "phi",
              "evidence_gte": {"sensitivity.inversion_risk": 0.7}},
        action="block_public_api_keys",
        severity=Severity.CRITICAL,
    )

The engine evaluates every policy against every finding and returns the
violations — the actions a downstream control plane should enforce.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from vecshield.models import Finding, Severity


def _dotted(d: dict, path: str) -> Any:
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


@dataclass
class Policy:
    id: str
    description: str
    when: dict[str, Any]
    action: str
    severity: Severity = Severity.HIGH

    def matches(self, finding: Finding) -> bool:
        w = self.when

        if "category" in w:
            # One category, or several: a rule about plaintext transmission
            # holds whether the plaintext was seen on VecShield's connection
            # or accepted from any client.
            wanted = w["category"]
            if isinstance(wanted, (list, tuple)):
                if finding.category not in wanted:
                    return False
            elif finding.category != wanted:
                return False
        if "store" in w and finding.store != w["store"]:
            return False
        if "collection" in w and finding.collection != w["collection"]:
            return False
        if "min_severity" in w:
            need = Severity(w["min_severity"]).rank
            if finding.severity.rank < need:
                return False
        if "requires_label" in w:
            labels = finding.evidence.get("label_counts", {}) or {}
            if w["requires_label"] not in labels:
                return False
        for path, threshold in (w.get("evidence_gte") or {}).items():
            val = _dotted(finding.evidence, path)
            if not isinstance(val, (int, float)) or val < threshold:
                return False
        return True


@dataclass
class PolicyViolation:
    policy_id: str
    action: str
    severity: Severity
    description: str
    finding_id: str
    store: str
    collection: Optional[str]
    id: str = field(default_factory=lambda: f"viol-{uuid.uuid4().hex[:10]}")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "policy_id": self.policy_id,
            "action": self.action,
            "severity": self.severity.value,
            "description": self.description,
            "finding_id": self.finding_id,
            "store": self.store,
            "collection": self.collection,
        }


def evaluate_policies(
    policies: list[Policy], findings: list[Finding]
) -> list[PolicyViolation]:
    violations: list[PolicyViolation] = []
    for policy in policies:
        for f in findings:
            if policy.matches(f):
                violations.append(PolicyViolation(
                    policy_id=policy.id,
                    action=policy.action,
                    severity=policy.severity,
                    description=policy.description,
                    finding_id=f.id,
                    store=f.store,
                    collection=f.collection,
                ))
    return violations


# A small starter pack of sensible defaults.
def default_policies() -> list[Policy]:
    return [
        Policy(
            id="secrets-never-embedded",
            description="Secrets/credentials present in a vector collection",
            when={"category": "data_classification", "requires_label": "secret"},
            action="purge_and_rotate",
            severity=Severity.CRITICAL,
        ),
        Policy(
            id="phi-high-inversion",
            description="PHI in a highly-invertible collection",
            when={"requires_label": "phi",
                  "evidence_gte": {"sensitivity.inversion_risk": 0.7}},
            action="restrict_and_log",
            severity=Severity.CRITICAL,
        ),
        Policy(
            id="cross-tenant-bleed",
            description="Cross-tenant data bleed detected",
            when={"category": "isolation", "min_severity": "high"},
            action="enforce_tenant_isolation",
            severity=Severity.HIGH,
        ),
        Policy(
            id="rag-injection",
            description="Prompt-injection content in the knowledge base",
            when={"category": "rag_integrity", "min_severity": "high"},
            action="quarantine_chunks",
            severity=Severity.HIGH,
        ),
        Policy(
            # The scan grades an over-retention finding by the category the
            # exceeded rule governs: HIGH for card data, health data, special-
            # category and criminal-offence data, secrets and children's data
            # (scan/retention_schedule.py). The schedule is the customer's own,
            # so this fires on "older than your declared maximum", never on a
            # judgement that holding the records is unlawful.
            id="retention-sensitive-over-max",
            description="Card, health or other high-sensitivity records are older "
                        "than the declared retention maximum",
            when={"category": "retention_schedule", "min_severity": "high"},
            action="purge_expired_records",
            severity=Severity.HIGH,
        ),
        Policy(
            # HIGH means face or voice templates are confirmed, not possible.
            # Holding them is not a violation in itself; the obligations that
            # attach (consent, retention schedule, impact assessment) need a
            # person to review them.
            id="biometric-templates-reviewed",
            description="A collection holds face or voice templates, so biometric "
                        "obligations must be reviewed",
            when={"category": "biometric_templates", "min_severity": "high"},
            action="review_biometric_obligations",
            severity=Severity.HIGH,
        ),
        Policy(
            # HIGH is a superseded document version that still holds data the
            # classifier marked sensitive: corrected personal data that is
            # still retrievable (integrity/versions.py).
            id="superseded-sensitive-chunks",
            description="Superseded versions of documents with sensitive data are "
                        "still retrievable",
            when={"category": "chunk_versions", "min_severity": "high"},
            action="purge_superseded_chunks",
            severity=Severity.HIGH,
        ),
        Policy(
            # MEDIUM is the corroborated tier only: a dense cluster or a hub
            # that also comes from rare or unattributed sources, carries an
            # injection hit, or is an embedding outlier. Uncorroborated
            # patterns are LOW and do not trip this. Quarantine is reversible
            # and still goes through review and approval before it runs.
            id="poisoning-signals-review",
            description="Chunks show corroborated corpus-poisoning signals; review "
                        "them and quarantine what is not expected",
            when={"category": ["corpus_duplication", "retrieval_hubness"],
                  "min_severity": "medium"},
            action="quarantine_chunks",
            severity=Severity.MEDIUM,
        ),
    ]
