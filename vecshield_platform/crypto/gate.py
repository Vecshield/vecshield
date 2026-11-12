"""The crypto gate: detect, then decide — block, request evidence, warn, or pass.

Policies (``compliance/policy.py``) match one finding at a time. The questions
a release gate asks combine facts instead: *this store holds PHI* **and** *its
encryption at rest is not verified*. The second fact is often no finding at
all — a database that cannot report encryption at rest produces an outcome,
not a finding — so the gate reads the saved audit's check outcomes and
findings together.

It decides; it enforces nothing by itself. A pipeline asks it before
promoting a store (``GET /stores/{id}/crypto-gate``, or the ``crypto-gate``
CLI's exit code) and refuses to proceed on ``block``.

Evidence can clear a rule, because not observable is not a failure. A store
whose database cannot report encryption at rest is not blocked forever: once
the fallback statement the matching criterion asks for is accepted, the rule
reads as cleared, and says by what. An observed failure — a readable full PAN,
encryption at rest reported off, a plaintext connection — is never cleared by
a document; it has to be fixed.

Sensitivity has to be established before its absence can pass. When the
audit did not classify every collection completely -- a chunk cap, an
inventory-only store, a read error, or NLP that was degraded or turned off --
the labels the gate reads are only a lower bound. A rule conditioned on labels
then holds as "sensitivity not established" and asks for evidence (a complete
audit) instead of passing; labels that *were* observed still decide as usual,
so PHI read in full still blocks.

Pure: no I/O. Callers pass the snapshot and the accepted evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from vecshield_platform.crypto.states import (
    AT_REST_ENCRYPTION,
    DATA_REPRESENTATION,
    PAN_REPRESENTATION,
    RETRIEVAL_EXPOSURE,
    TLS_ENFORCEMENT,
    TRANSPORT_ENCRYPTION,
)

#: Strongest first. The gate's decision is the strongest uncleared rule.
DECISIONS = ("block", "request_evidence", "warn", "pass")

#: Labels that make transport and storage protection matter to a regulator.
SENSITIVE_LABELS = ("pii", "phi", "pci", "special_category", "criminal_offence",
                    "secret")

#: What a check reads as when the audit never recorded it.
NOT_RUN = "not_run"

#: The check whose coverage decides whether labels are established.
CLASSIFICATION_CHECK = "data_classification"

#: Detection states under which names, places and other NER entities were
#: never examined, so a classification cannot be complete.
_NLP_NOT_READY = ("degraded", "disabled", "unavailable")


@dataclass(frozen=True)
class GateRule:
    """One condition over an audit, and what it decides when it holds.

    ``when`` keys, all of which must hold:

    * ``labels_any`` — the store holds at least one of these labels.
    * ``check`` — the check the remaining keys read.
    * ``outcomes`` — that check has an outcome in this list, anywhere.
    * ``states`` — that check has a crypto state in this list, anywhere.
    * ``not_states`` — that check has an outcome whose crypto state is not in
      this list (a missing check counts, as ``not_run``).
    * ``setting`` — a named gate setting is true.
    * ``classification_incomplete`` — the audit did not classify the store's
      content completely, so its sensitivity is not established.
    """

    id: str
    description: str
    decision: str
    when: dict[str, Any]
    #: (criterion id, evidence requirement) pairs; any one accepted clears it.
    cleared_by: tuple[tuple[str, str], ...] = field(default_factory=tuple)
    remediation: str = ""
    basis: str = ""

    def __post_init__(self) -> None:
        if self.decision not in DECISIONS[:-1]:
            raise ValueError(f"{self.id}: unknown gate decision {self.decision}")

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "description": self.description,
                "decision": self.decision, "when": dict(self.when),
                "evidence_that_clears": [{"criterion_id": c, "requirement": r}
                                         for c, r in self.cleared_by],
                "clears_with": "any" if self.cleared_by else None,
                "remediation": self.remediation, "basis": self.basis}


def default_gate_rules() -> list[GateRule]:
    """The release-gate rules (docs/crypto_posture.md)."""
    return [
        GateRule(
            id="pan-must-be-unreadable",
            description="Full PAN is readable in the store",
            decision="block",
            when={"check": PAN_REPRESENTATION, "outcomes": ["failed"]},
            remediation="Truncate or tokenize PAN before it is embedded, then "
                        "re-run the audit. Storage encryption does not substitute.",
            basis="PCI DSS Requirement 3.5.1 (3.5.1.2 for storage encryption)"),
        GateRule(
            id="at-rest-encryption-reported-off",
            description="The database reports encryption at rest as off",
            decision="block",
            when={"check": AT_REST_ENCRYPTION, "outcomes": ["failed"]},
            remediation="Enable the database's encryption at rest and re-run the audit.",
            basis="HIPAA §164.312(a)(2)(iv); GDPR Art. 32(1)(a); SOC 2 CC6.1"),
        GateRule(
            id="sensitive-data-over-plaintext",
            description="Sensitive data is served over a connection without TLS",
            decision="block",
            when={"labels_any": list(SENSITIVE_LABELS), "check": TRANSPORT_ENCRYPTION,
                  "outcomes": ["failed"]},
            remediation="Connect over TLS (https://, rediss://, sslmode=require) "
                        "and re-run the audit.",
            basis="HIPAA §164.312(e)(2)(ii); PCI DSS 4.2.1; SOC 2 CC6.7"),
        GateRule(
            id="sensitive-store-accepts-plaintext",
            description="A store holding sensitive data accepts plaintext connections",
            decision="block",
            when={"labels_any": list(SENSITIVE_LABELS), "check": TLS_ENFORCEMENT,
                  "outcomes": ["failed"]},
            remediation="Refuse unencrypted connections at the store (hostssl-only "
                        "pg_hba rules, TLS-only listeners) and re-run the audit.",
            basis="HIPAA §164.312(e)(2)(ii); PCI DSS 4.2.1; SOC 2 CC6.7"),
        GateRule(
            id="phi-needs-verified-at-rest",
            description="PHI is stored where encryption at rest is not verified",
            decision="block",
            when={"labels_any": ["phi"], "check": AT_REST_ENCRYPTION,
                  "not_states": ["verified"]},
            cleared_by=(("HIPAA-164-312-A2IV-ENCRYPTION-01",
                         "encryption_at_rest_statement"),
                        ("HIPAA-164-312-A2IV-ENCRYPTION-01",
                         "addressable_determination")),
            remediation="Enable encryption the database can report, or register "
                        "the encryption-at-rest statement (or the addressable "
                        "determination) as evidence and have it accepted.",
            basis="HIPAA §164.312(a)(2)(iv), addressable"),
        GateRule(
            id="required-at-rest-needs-evidence",
            description="Policy requires encryption at rest, and it is not verified",
            decision="request_evidence",
            when={"setting": "requires_at_rest_encryption", "check": AT_REST_ENCRYPTION,
                  "not_states": ["verified"]},
            cleared_by=(("SOC2-CC6.1-ENCRYPTION-01", "encryption_policy"),
                        ("GDPR-32-1A-ENCRYPTION-01", "encryption_risk_assessment"),
                        ("HIPAA-164-312-A2IV-ENCRYPTION-01",
                         "encryption_at_rest_statement")),
            remediation="Supply evidence of encryption at rest for this store.",
            basis="The organisation's own policy; SOC 2 CC6.1 control evidence"),
        GateRule(
            id="protection-applied-inconsistently",
            description="A field mixes protected and plaintext sensitive values",
            decision="warn",
            when={"check": DATA_REPRESENTATION, "outcomes": ["failed"]},
            remediation="Find the ingestion path that skips tokenization and fix it.",
            basis="GDPR Art. 32(1)(d) — testing the effectiveness of measures"),
        GateRule(
            id="regulated-data-retrievable-in-plaintext",
            description="PHI or card data comes back in plaintext from retrieval",
            decision="warn",
            when={"labels_any": ["phi", "pci"], "check": RETRIEVAL_EXPOSURE,
                  "states": ["observed_exposure"]},
            remediation="Remove, tokenize or restrict what retrieval returns.",
            basis="Supporting evidence; readable to a retrieval client, not unencrypted on disk"),
        GateRule(
            id="sensitivity-must-be-established",
            description="The audit did not classify the store's content completely",
            decision="request_evidence",
            when={"classification_incomplete": True},
            remediation="Re-run the audit so every collection is classified in full: "
                        "remove the chunk limit, fix read errors, point a "
                        "content-capable connector at an inventory-only store, and "
                        "install the configured NLP model. No document substitutes "
                        "for reading the data.",
            basis="Zero findings over partial coverage is not a pass"),
    ]


# ---- reading the snapshot --------------------------------------------------

def _labels(snapshot: dict[str, Any]) -> set[str]:
    labels: set[str] = set()
    for job in snapshot.get("jobs", []) or []:
        for finding in job.get("findings", []) or []:
            if finding.get("category") != "data_classification":
                continue
            evidence = finding.get("evidence") or {}
            labels.update(k for k, v in (evidence.get("label_counts") or {}).items() if v)
    return labels


def classification_coverage(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Whether the audit classified the store's content completely.

    Complete only when at least one ``data_classification`` outcome was
    recorded, every one of them says complete with an outcome that read the
    data (``passed`` or ``failed``), and the detection pipeline was ready.
    Anything else leaves sensitivity not established.
    """
    reasons: list[str] = []
    outcomes = _outcomes(snapshot, CLASSIFICATION_CHECK)
    if not outcomes:
        reasons.append("data classification was not recorded in this audit")
    for outcome in outcomes:
        cov = outcome.get("coverage") or {}
        if cov.get("complete") is True and outcome.get("outcome") in ("passed", "failed"):
            continue
        where = f" [{outcome['collection']}]" if outcome.get("collection") else ""
        why = outcome.get("reason") or f"outcome {outcome.get('outcome')}"
        reasons.append(f"{CLASSIFICATION_CHECK}{where}: {why}")
    detection_states = []
    for source in [snapshot.get("scope") or {}] + [
            job.get("stats") or {} for job in snapshot.get("jobs", []) or []]:
        status = (source.get("detection") or {}).get("status")
        if status and status not in detection_states:
            detection_states.append(status)
    for status in detection_states:
        if status in _NLP_NOT_READY:
            reasons.append(f"NLP detection was {status}; names, places and "
                           "organisations were not examined")
    complete = not reasons
    return {"classification": "complete" if complete else
            ("not_recorded" if not outcomes else "partial"),
            "complete": complete,
            "sensitivity": "established" if complete else "not_established",
            "reasons": reasons}


def _outcomes(snapshot: dict[str, Any], check: str) -> list[dict[str, Any]]:
    return [o for o in snapshot.get("check_outcomes", []) or []
            if o.get("check") == check]


def _state(outcome: dict[str, Any]) -> str:
    return (outcome.get("coverage") or {}).get("crypto_state") or NOT_RUN


def _matches(rule: GateRule, snapshot: dict[str, Any], labels: set[str],
             settings: dict[str, Any],
             coverage: Optional[dict[str, Any]] = None) -> tuple[bool, list[str], bool]:
    """Whether the rule holds, the facts that made it hold, and whether it
    holds only because sensitivity was not established."""
    when, reasons = rule.when, []
    coverage = coverage or {"complete": True, "reasons": []}
    unestablished = False
    if when.get("classification_incomplete"):
        if coverage["complete"]:
            return False, [], False
        reasons.extend(coverage["reasons"])
    if "setting" in when:
        if not settings.get(when["setting"]):
            return False, [], False
        reasons.append(f"setting {when['setting']} is on")
    if "labels_any" in when:
        found = sorted(labels & set(when["labels_any"]))
        if found:
            reasons.append("store holds " + ", ".join(found))
        elif not coverage["complete"]:
            # Nothing observed, but the classification did not read the whole
            # store: what it missed may hold exactly these labels.
            unestablished = True
            reasons.append("sensitivity not established: classification coverage "
                           "is partial, so the store may hold "
                           + ", ".join(when["labels_any"]))
        else:
            return False, [], False
    check = when.get("check")
    if check is None:
        return True, reasons, unestablished
    outcomes = _outcomes(snapshot, check)
    if "outcomes" in when:
        hits = [o for o in outcomes if o.get("outcome") in when["outcomes"]]
        if not hits:
            return False, [], False
        reasons.extend(_describe(o) for o in hits)
    if "states" in when:
        hits = [o for o in outcomes if _state(o) in when["states"]]
        if not hits:
            return False, [], False
        reasons.extend(_describe(o) for o in hits)
    if "not_states" in when:
        if not outcomes:
            reasons.append(f"{check} was not recorded in this audit")
        else:
            hits = [o for o in outcomes if _state(o) not in when["not_states"]]
            if not hits:
                return False, [], False
            reasons.extend(_describe(o) for o in hits)
    return True, reasons, unestablished


def _describe(outcome: dict[str, Any]) -> str:
    where = f" [{outcome['collection']}]" if outcome.get("collection") else ""
    reason = outcome.get("reason") or ""
    return (f"{outcome.get('check')}{where}: {_state(outcome).replace('_', ' ')}"
            + (f" — {reason}" if reason else ""))


# ---- deciding --------------------------------------------------------------

def evaluate_gate(snapshot: dict[str, Any], *, store_id: str,
                  accepted_evidence: Iterable[tuple[str, str]] = (),
                  settings: Optional[dict[str, Any]] = None,
                  rules: Optional[list[GateRule]] = None) -> dict[str, Any]:
    """Decide the gate for one saved audit.

    ``accepted_evidence`` is the (criterion id, requirement) pairs whose
    review is accepted with a usable artifact. ``settings`` carries the
    organisation's own switches, such as ``requires_at_rest_encryption``.
    """
    settings = settings or {}
    accepted = set(accepted_evidence)
    labels = _labels(snapshot)
    coverage = classification_coverage(snapshot)
    results: list[dict[str, Any]] = []
    for rule in rules if rules is not None else default_gate_rules():
        holds, reasons, unestablished = _matches(rule, snapshot, labels, settings,
                                                 coverage)
        cleared = [pair for pair in rule.cleared_by if pair in accepted]
        status = ("not_triggered" if not holds
                  else "cleared" if cleared else "fired")
        # A rule that holds only because sensitivity is unknown cannot block
        # on a label nobody observed; it asks for evidence instead. It still
        # never passes.
        decision = (DECISIONS[max(DECISIONS.index(rule.decision),
                                  DECISIONS.index("request_evidence"))]
                    if unestablished else rule.decision)
        results.append({
            "id": rule.id, "description": rule.description,
            "decision": decision, "rule_decision": rule.decision,
            "sensitivity": "not_established" if unestablished else None,
            "status": status, "reasons": reasons,
            "cleared_by": [{"criterion_id": c, "requirement": r} for c, r in cleared],
            "evidence_that_clears": [{"criterion_id": c, "requirement": r}
                                     for c, r in rule.cleared_by],
            # Any one accepted item clears a rule; none is needed alongside another.
            "clears_with": "any" if rule.cleared_by else None,
            "remediation": rule.remediation, "basis": rule.basis,
        })
    fired = [r for r in results if r["status"] == "fired"]
    decision = next((d for d in DECISIONS if any(r["decision"] == d for r in fired)),
                    "pass")
    evidence_needed = []
    for result in fired:
        for item in result["evidence_that_clears"]:
            if item not in evidence_needed:
                evidence_needed.append(item)
    return {
        "store_id": store_id,
        "audit_id": snapshot.get("id"),
        "assessed_at": snapshot.get("finished_at") or snapshot.get("started_at"),
        "decision": decision,
        "labels": sorted(labels),
        "coverage": coverage,
        "settings": dict(settings),
        "rules": results,
        "evidence_needed": evidence_needed,
        "note": ("The gate decides from one saved audit and the evidence accepted "
                 "for it. It is not a compliance determination, and a pass only "
                 "means no rule held in what this audit could observe. It never "
                 "passes an audit that did not classify the store completely."),
    }


def accepted_pairs(reviews: Iterable[dict[str, Any]],
                   artifacts: dict[str, dict[str, Any]],
                   *, scope: str) -> set[tuple[str, str]]:
    """(criterion, requirement) pairs accepted for this store or estate-wide.

    Mirrors ``evidence.accepted_requirements``: an accepted review counts only
    while its artifact is still usable.
    """
    pairs: set[tuple[str, str]] = set()
    for review in reviews:
        if review.get("state") != "accepted" or not review.get("requirement"):
            continue
        if review.get("scope") not in ("", None, scope):
            continue
        if not (artifacts.get(review.get("artifact_id", "")) or {}).get("usable"):
            continue
        pairs.add((review.get("criterion_id", ""), review["requirement"]))
    return pairs
