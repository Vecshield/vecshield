"""Inputs for a GDPR Article 35 data protection impact assessment (DPIA).

What the law asks, and who decides:

* Art. 35(1) requires a DPIA where a type of processing, in particular one
  using new technologies, is *likely to result in a high risk* to the rights
  and freedoms of natural persons. That is a judgement about the processing as
  a whole — its nature, scope, context and purposes — not about the presence
  of personal data in a store. Embedding personal data into a vector store
  does not by itself make a DPIA required.
* Art. 35(3) names cases where one is required in particular: systematic and
  extensive evaluation of personal aspects, including profiling, on which
  decisions with legal or similarly significant effects are based;
  large-scale processing of special categories (Art. 9(1)) or criminal
  offence data (Art. 10); and large-scale systematic monitoring of a publicly
  accessible area.
* Art. 35(4) has each supervisory authority publish a list of processing
  operations that require a DPIA. Those national lists must be checked too.
* The **controller** carries out the DPIA and owns its conclusion. Under
  Art. 35(2) the controller seeks the advice of the data protection officer
  where one is designated. The DPO advises and monitors; the DPO does not own
  or sign off the assessment on the controller's behalf.

Art. 35(7) sets the minimum content of a DPIA:

  (a) a systematic description of the processing and its purposes
  (b) an assessment of necessity and proportionality
  (c) an assessment of the risks to the rights and freedoms of data subjects
  (d) the measures envisaged to address those risks (safeguards)

This module derives *inputs* for (a), (c) and (d), and a starting point for
(b), from an existing audit. It does not invent risk: it reorganizes the
findings VecShield already produced into the Art. 35(7) shape for the
controller to complete. ``high_risk`` means indicators of high risk were
observed in the scan (special-category data, or high-severity findings on
personal data); it is an input to the controller's Art. 35(1) screening, not
that screening. It is duck-typed over the audit result (anything exposing
`all_findings()`, `.violations`, `.store`) to avoid an import cycle with the
orchestrator.
"""

from __future__ import annotations

import html
from dataclasses import dataclass, field
from typing import Any

from vecshield.models import Finding, SensitivityLabel, Severity

# Sensitivity label -> Article-35 data-category description.
_LABEL_CATEGORY = {
    SensitivityLabel.PII.value: "Personal data (identities, contact details)",
    SensitivityLabel.PHI.value: "Special-category health data (Art. 9)",
    SensitivityLabel.PCI.value: "Financial / payment-card data",
    SensitivityLabel.SECRET.value: "Authentication secrets / credentials",
    SensitivityLabel.SOURCE_CODE.value: "Proprietary source code",
}

# Posture finding category -> the safeguard it speaks to.
_SAFEGUARD_FOR = {
    "transport_encryption": "Encryption in transit (TLS)",
    "network_exposure": "Network isolation",
    "cve": "Patch management",
    "access_control": "Access control / least privilege",
    "isolation": "Tenant isolation",
}

# Safeguard dimension -> the audit checks that can evidence it, most specific
# first. A successful posture audit records its sub-checks by name; the
# orchestrator's umbrella "configuration_posture" outcome exists only when the
# whole posture audit was skipped or failed to run. A safeguard whose check
# never ran is unassessed; it is not a safeguard that is in place.
_CHECK_FOR_SAFEGUARD = {
    "transport_encryption": ("transport_encryption", "configuration_posture"),
    "network_exposure": ("network_exposure", "configuration_posture"),
    "cve": ("cve", "configuration_posture"),
    "access_control": ("authentication", "configuration_posture"),
    "isolation": ("tenant_isolation",),
}


def _backing_check(category: str,
                   by_check: dict[str, list[dict[str, Any]]]) -> tuple[str, list[dict[str, Any]]]:
    """The first candidate check that recorded outcomes, with those outcomes."""
    candidates = _CHECK_FOR_SAFEGUARD.get(category, ())
    for check in candidates:
        if by_check.get(check):
            return check, by_check[check]
    return (candidates[0] if candidates else ""), []

#: What ``high_risk`` means, stated with every report.
HIGH_RISK_BASIS = (
    "Indicators of high risk observed in the scan: special-category data, or "
    "high-severity findings on personal data. This is an input to the "
    "controller's screening under Art. 35(1) and (3) and the supervisory "
    "authority's list under Art. 35(4), not a determination that a DPIA is "
    "required.")

#: Who owns the assessment, stated with every report.
ROLES_NOTE = (
    "The controller carries out the DPIA and decides whether one is required. "
    "Where a data protection officer is designated, the controller seeks the "
    "DPO's advice (Art. 35(2)); the DPO advises and monitors, and does not "
    "sign off the assessment on the controller's behalf.")

# Article-35 statuses. Only OBSERVED_OK is evidence; the rest require review.
_GAP = "GAP"
_OBSERVED_OK = "in place / no gap detected"
_NOT_ASSESSED = "not assessed — review required"
_PARTIAL = "partially assessed — review required"


@dataclass
class PIAReport:
    store: str
    high_risk: bool
    data_categories: list[str] = field(default_factory=list)
    processing_description: str = ""
    necessity: str = ""
    risks: list[dict[str, Any]] = field(default_factory=list)
    safeguards: list[dict[str, Any]] = field(default_factory=list)
    residual_risk: str = "medium"
    #: The controller has something to decide or complete before relying on
    #: this draft. Kept under its original name for API compatibility; the
    #: controller owns the decision and the DPO advises (Art. 35(2)).
    dpo_action_required: bool = False
    coverage: dict[str, Any] = field(default_factory=dict)
    assessment_complete: bool = False
    unassessed_safeguards: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "store": self.store,
            "high_risk": self.high_risk,
            "data_categories": self.data_categories,
            "processing_description": self.processing_description,
            "necessity": self.necessity,
            "risks": self.risks,
            "safeguards": self.safeguards,
            "residual_risk": self.residual_risk,
            "dpo_action_required": self.dpo_action_required,
            "controller_action_required": self.dpo_action_required,
            "high_risk_basis": HIGH_RISK_BASIS,
            "roles_note": ROLES_NOTE,
            "coverage": self.coverage,
            "assessment_complete": self.assessment_complete,
            "unassessed_safeguards": self.unassessed_safeguards,
            "article": "GDPR Article 35",
        }


def _data_categories(findings: list[Finding]) -> list[str]:
    cats: set[str] = set()
    for f in findings:
        if f.category != "data_classification":
            continue
        for label in (f.evidence.get("label_counts", {}) or {}):
            desc = _LABEL_CATEGORY.get(label)
            if desc:
                cats.add(desc)
    return sorted(cats)


def _outcomes_by_check(audit_result) -> dict[str, list[dict[str, Any]]]:
    """Group the run's structured check outcomes by check name.

    Older audits and duck-typed callers carry no outcomes; every safeguard is
    then unassessed rather than silently satisfied.
    """
    getter = getattr(audit_result, "all_check_outcomes", None)
    outcomes = list(getter()) if callable(getter) else []
    grouped: dict[str, list[dict[str, Any]]] = {}
    for outcome in outcomes:
        grouped.setdefault(outcome.get("check", ""), []).append(outcome)
    return grouped


def _check_status(outcomes: list[dict[str, Any]]) -> tuple[str, str]:
    """Reduce one check's outcomes to an evidential status and a reason."""
    if not outcomes:
        return _NOT_ASSESSED, "This assessment recorded no outcome for the backing check."
    ran = [o for o in outcomes if o.get("outcome") in ("passed", "failed", "inconclusive")]
    if not ran:
        # skipped / unsupported / error: the check produced no observation at all.
        reasons = sorted({o.get("reason", "") for o in outcomes if o.get("reason")})
        summary = sorted({str(o.get("outcome")) for o in outcomes})
        return _NOT_ASSESSED, (reasons[0] if reasons
                               else f"The backing check did not run ({', '.join(summary)}).")
    partial = [o for o in ran if o.get("outcome") == "inconclusive"
               or o.get("coverage", {}).get("complete") is not True]
    if partial:
        reason = next((o.get("reason") for o in partial if o.get("reason")), "")
        return _PARTIAL, reason or (
            "The backing check inspected only part of the scope, so absence of a "
            "finding does not establish the safeguard.")
    # A complete check that found the safeguard does not apply (e.g. a
    # collection holding one tenant's data) says so, rather than reading as a
    # control that was observed in place.
    if all(o.get("coverage", {}).get("applicability") == "not_applicable" for o in ran):
        return _OBSERVED_OK, next((o.get("reason") for o in ran if o.get("reason")), "")
    return _OBSERVED_OK, ""


def generate_pia(audit_result, *, purpose: str = "Retrieval-augmented generation (RAG)",
                 store: str | None = None) -> PIAReport:
    """Build a DPIA from a completed AuditResult (or compatible object).

    Safeguards, data categories, and residual risk are stated only as far as the
    run's coverage supports them: a check that did not run produces a
    review-required state, never a satisfied one (GDPR Art. 35(7)(d)).

    ``store`` names the store in the report. The API passes the registry id: the
    connector's own name is often a URI or a local path, which a DPO cannot map
    to a system and which a shared DPIA should not disclose.
    """
    findings = list(audit_result.all_findings())
    violations = list(getattr(audit_result, "violations", []))
    store = store or getattr(audit_result, "store", "vector store")
    by_check = _outcomes_by_check(audit_result)
    coverage = getattr(audit_result, "coverage", {}) or {}
    if callable(coverage):
        coverage = coverage() or {}
    classification_status, classification_reason = _check_status(
        by_check.get("data_classification", []))
    categories_established = classification_status == _OBSERVED_OK

    categories = _data_categories(findings)
    special = any("health" in c.lower() or "Art. 9" in c for c in categories)
    high_sev = [f for f in findings if f.severity.rank >= Severity.HIGH.rank]
    high_risk = bool(categories) and (special or bool(high_sev))

    # (a) description
    coll_count = len({f.collection for f in findings if f.collection})
    processing = (
        f"Embedding and similarity-retrieval of unstructured content in '{store}' "
        f"across {coll_count or 'one or more'} collection(s) for the purpose of: "
        f"{purpose}. Source text is transformed into vector embeddings and stored; "
        "embeddings of an invertible model can leak the underlying personal data."
    )

    # (b) necessity & proportionality
    if categories:
        necessity = (
            "Personal data is present in the embedding store. The controller "
            "assesses whether it is necessary for each purpose; data "
            "minimisation (Art. 5(1)(c)) points to removing or pseudonymising "
            "personal data the retrieval does not need. An ingest-time "
            "redaction gate is one control the controller may consider."
        )
    elif categories_established:
        necessity = ("No personal data was detected across the fully inspected scope. "
                     "That does not by itself settle whether a DPIA is required: "
                     "that depends on the processing as a whole under Art. 35(1) "
                     "and (3) and on the supervisory authority's list under "
                     "Art. 35(4).")
    else:
        necessity = (
            "No personal data was observed, but classification did not cover the whole "
            f"scope ({classification_status}). {classification_reason} "
            "Whether a DPIA is required cannot be concluded from this run; complete "
            "the classification scope, and the controller records its own "
            "screening under Art. 35(1), (3) and (4)."
        ).strip()

    # (c) risks — derive from high-severity findings, grouped by category
    risks: list[dict[str, Any]] = []
    for f in sorted(high_sev, key=lambda x: -x.severity.rank):
        risks.append({
            "severity": f.severity.value,
            "category": f.category,
            "title": f.title,
            "collection": f.collection,
            "to_rights": _rights_impact(f.category),
        })

    # (d) safeguards — pair posture/access findings with their control + status
    safeguards = _safeguards(findings, violations, by_check)
    unassessed = [s["control"] for s in safeguards
                  if s["status"] in (_NOT_ASSESSED, _PARTIAL)]

    # residual risk — observed severity, bounded by what was actually inspected
    crit = any(f.severity == Severity.CRITICAL for f in findings)
    if crit:
        residual = "high"
    elif high_sev:
        residual = "medium"
    elif unassessed or not categories_established:
        # Nothing severe was seen, but parts of the assessment never ran: an
        # unmeasured safeguard is not a low residual risk.
        residual = "unknown"
    else:
        residual = "low"

    complete = not unassessed and categories_established

    return PIAReport(
        store=store,
        high_risk=high_risk,
        data_categories=categories,
        processing_description=processing,
        necessity=necessity,
        risks=risks,
        safeguards=safeguards,
        residual_risk=residual,
        dpo_action_required=(high_risk and residual in ("high", "medium")) or not complete,
        coverage=dict(coverage),
        assessment_complete=complete,
        unassessed_safeguards=unassessed,
    )


def _rights_impact(category: str) -> str:
    return {
        "data_classification": "Confidentiality of personal data; risk of "
                               "unauthorised disclosure via retrieval or model inversion.",
        "transport_encryption": "Interception in transit; loss of confidentiality.",
        "network_exposure": "Unauthorised external access to personal data.",
        "access_control": "Excessive access; risk of misuse or exfiltration.",
        "isolation": "Cross-tenant disclosure of personal data.",
        "rag_integrity": "Integrity/availability; poisoned context affecting decisions.",
        "cve": "Exploitable vulnerability enabling data breach.",
    }.get(category, "Risk to rights and freedoms of data subjects.")


def _safeguards(findings: list[Finding], violations: list,
                by_check: dict[str, list[dict[str, Any]]] | None = None) -> list[dict[str, Any]]:
    """For each safeguard dimension, report a gap, an observation, or a blank.

    A dimension with no findings is only "no gap detected" when the check that
    would have produced those findings ran over the whole scope. Otherwise the
    absence is unmeasured and the DPO sees that instead of a clean row.
    """
    by_cat: dict[str, list[Finding]] = {}
    for f in findings:
        by_cat.setdefault(f.category, []).append(f)
    by_check = by_check or {}

    out: list[dict[str, Any]] = []
    for cat, control in _SAFEGUARD_FOR.items():
        gaps = [f for f in by_cat.get(cat, []) if f.severity.rank >= Severity.MEDIUM.rank]
        check, outcomes = _backing_check(cat, by_check)
        if gaps:
            status, reason = _GAP, ""
        else:
            status, reason = _check_status(outcomes)
        out.append({
            "control": control,
            "status": status,
            "assessed_by": check,
            "reason": reason,
            "open_findings": len(gaps),
            "remediation": gaps[0].remediation if gaps else "",
        })
    return out


# ---- HTML rendering (shares the report.py house style) ----

def _coverage_banner(pia: PIAReport) -> str:
    """State up front whether this DPIA rests on a complete assessment."""
    if pia.assessment_complete:
        return ("<p class='muted'>Every safeguard in this assessment was measured over "
                "its full scope.</p>")
    status = html.escape(str(pia.coverage.get("status", "unknown")))
    unmeasured = html.escape(", ".join(pia.unassessed_safeguards)) or "one or more controls"
    return ("<p style='background:#fff4e5;border-left:4px solid #e8a33d;padding:.6rem .8rem'>"
            f"<b>Incomplete assessment (coverage: {status}).</b> This DPIA does not "
            f"establish {unmeasured}. Absent findings for an unmeasured control are not "
            "evidence that the control was implemented; a reviewer must resolve each "
            "review-required row below.</p>")


def build_pia_html(pia: PIAReport, *, generated_at: str = "") -> str:
    def esc(s):
        return html.escape(str(s))

    badge = ("High-risk indicators observed" if pia.high_risk
             else "No high-risk indicators observed")
    color = "#b3001b" if pia.high_risk else "#1c7ed6"

    p = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        "<title>DPIA — {}</title>".format(esc(pia.store)),
        "<style>body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;"
        "margin:2rem;color:#1a1a1a}h1{margin-bottom:0}h2{margin-top:1.8rem;"
        "border-bottom:2px solid #eee;padding-bottom:.3rem}.muted{color:#777;"
        "font-size:.85em}table{border-collapse:collapse;width:100%;font-size:.9em;"
        "margin-top:.5rem}th,td{border:1px solid #e3e3e3;padding:.45rem .6rem;"
        "text-align:left;vertical-align:top}th{background:#f7f7f7}"
        ".tag{display:inline-block;padding:.15rem .6rem;border-radius:6px;"
        "color:#fff;font-weight:600}</style></head><body>",
        "<h1>Data Protection Impact Assessment — draft inputs</h1>",
        f"<p class='muted'>GDPR Article 35 · store <code>{esc(pia.store)}</code>"
        + (f" · generated {esc(generated_at)}" if generated_at else "") + "</p>",
        f"<p>{esc(ROLES_NOTE)}</p>",
        f"<p><span class='tag' style='background:{color}'>{esc(badge)}</span> "
        f"&nbsp; Residual risk: <b>{esc(pia.residual_risk.upper())}</b></p>",
        f"<p class='muted'>{esc(HIGH_RISK_BASIS)}</p>",

        _coverage_banner(pia),

        "<h2>(a) Description of processing</h2>",
        f"<p>{esc(pia.processing_description)}</p>",
        "<p><b>Categories of personal data:</b></p><ul>"
        + ("".join(f"<li>{esc(c)}</li>" for c in pia.data_categories)
           or "<li>None detected</li>") + "</ul>",

        "<h2>(b) Necessity & proportionality</h2>",
        f"<p>{esc(pia.necessity)}</p>",

        "<h2>(c) Risks to data subjects</h2>",
    ]
    if pia.risks:
        p.append("<table><tr><th>Severity</th><th>Category</th><th>Risk</th>"
                 "<th>Impact on rights</th></tr>")
        for r in pia.risks:
            p.append(f"<tr><td>{esc(r['severity'].upper())}</td>"
                     f"<td>{esc(r['category'])}</td>"
                     f"<td>{esc(r['title'])}</td>"
                     f"<td>{esc(r['to_rights'])}</td></tr>")
        p.append("</table>")
    else:
        p.append("<p>No high-severity risks identified.</p>")

    p.append("<h2>(d) Safeguards & measures</h2>")
    p.append("<table><tr><th>Control</th><th>Status</th><th>Assessed by</th>"
             "<th>Open findings</th><th>Basis / remediation</th></tr>")
    for s in pia.safeguards:
        note = s.get("remediation") or s.get("reason", "")
        p.append(f"<tr><td>{esc(s['control'])}</td><td>{esc(s['status'])}</td>"
                 f"<td>{esc(s.get('assessed_by', '') or '—')}</td>"
                 f"<td>{s['open_findings']}</td><td>{esc(note)}</td></tr>")
    p.append("</table>")

    if pia.dpo_action_required:
        p.append("<h2>Controller action</h2><p><b>The controller has decisions to "
                 "record before relying on this draft</b>: whether a DPIA is "
                 "required (Art. 35(1), (3) and (4)) and, if so, its completion. "
                 "Where a DPO is designated, seek the DPO's advice "
                 "(Art. 35(2)).</p>")
        if pia.unassessed_safeguards:
            p.append("<p>Unmeasured safeguards needing a documented decision: "
                     + esc(", ".join(pia.unassessed_safeguards)) + ".</p>")

    p.append("</body></html>")
    return "\n".join(p)
