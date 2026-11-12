"""Criterion records and the evaluation contract behind them.

A criterion is an obligation VecShield can say something about. This module
keeps the four things §8.3 of the improvement plan requires to stay separate,
separate:

``applicability``
    Does the obligation reach this system at all? Unanswered is not "yes".
``technical_result``
    What the run observed, taken from structured check outcomes — never from
    the absence of findings.
``evidence_sufficiency``
    Whether the manual artifacts the obligation needs were supplied and
    accepted. A high-confidence detector can still be insufficient evidence for
    a broad obligation.
``reviewer conclusion``
    A person's decision. Only a reviewer moves a criterion to
    ``satisfied_for_scope``; the pipeline can never conclude compliance on its
    own.

Some frameworks write an obligation as an *addressable* implementation
specification, which an entity may lawfully not implement provided it
documented why and put an equivalent alternative in place where reasonable.
:data:`SPECIFICATION_KINDS` records that, and the documented determination is
read from the evidence map under :data:`ADDRESSABLE_DETERMINATION` — it is an
evidence question, not a fifth input. Criteria whose ``specification`` is
``None`` are unaffected.

Paraphrases here are VecShield's own words. Provision text is referenced
through :mod:`vecshield_platform.compliance.sources`, not reproduced.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from vecshield_platform.compliance.sources import resolve_sources

#: Criterion assessment states. Risk acceptance attaches to a gap; it does not
#: replace one, so there is no "accepted" state here.
CRITERION_STATUSES = ("not_assessed", "evidence_needed", "under_review",
                      "satisfied_for_scope", "gap_identified", "not_applicable")

#: What the run's checks showed for this criterion.
TECHNICAL_RESULTS = ("not_run", "passed", "failed", "inconclusive")

#: Whether required manual artifacts are present and accepted.
EVIDENCE_STATES = ("not_required", "missing", "submitted", "accepted", "rejected")

#: Answers to an applicability question. Anything unanswered stays unknown.
APPLICABILITY_ANSWERS = ("yes", "no", "requires_confirmation")

#: How an obligation is written in its framework. ``None`` means the framework
#: does not draw this distinction, and evaluation behaves exactly as before.
#:
#: ``standard``
#:     A standard in its own right; mandatory where the framework applies.
#: ``required``
#:     An implementation specification that must be implemented as stated.
#: ``addressable``
#:     An implementation specification the entity assesses. Where it is not a
#:     reasonable and appropriate safeguard the entity documents that
#:     determination and implements an equivalent alternative measure if
#:     reasonable and appropriate. Addressable is not optional, and a missing
#:     addressable control is not automatically a gap — an undocumented one is.
#: ``risk_based``
#:     A measure the framework makes appropriate to the risk rather than
#:     universal — GDPR Art. 32(1)'s encryption and pseudonymisation, or a SOC 2
#:     point of focus. Evaluated like ``addressable``: an absent control is a gap
#:     until the entity documents a risk determination explaining why the
#:     measure is not appropriate here, read from :data:`RISK_DETERMINATION`.
SPECIFICATION_KINDS = ("standard", "required", "addressable", "risk_based")

#: The evidence key that carries the determination an addressable
#: specification needs when its technical control is absent. It is read from
#: the same evidence map as any other artifact and uses EVIDENCE_STATES, but
#: it is not listed in a criterion's ``manual_evidence``: it is required only
#: when the control is missing, not unconditionally.
ADDRESSABLE_DETERMINATION = "addressable_determination"

#: The evidence key that carries a risk-based measure's documented risk
#: determination. Same mechanics as :data:`ADDRESSABLE_DETERMINATION`, kept
#: separate so a HIPAA determination is never read as a GDPR one.
RISK_DETERMINATION = "risk_determination"

#: Which evidence key each determination-bearing specification kind reads.
DETERMINATION_KEYS = {"addressable": ADDRESSABLE_DETERMINATION,
                      "risk_based": RISK_DETERMINATION}

#: This pack is authored alongside the detection rules and has had no
#: regulatory review. It is versioned so a later pack cannot silently rewrite
#: assessments made against this one. Bumped to -2 when the HIPAA criteria
#: were rewritten from two broad entries to a cited requirement set, to -3
#: when posture criteria began citing the checks the posture audit actually
#: emits and the cryptographic-posture criteria were added, and to -4 when a
#: citation audit of this pack's sources was applied. Which
#: criteria changed between -3 and -4 is listed in
#: docs/compliance/pack-draft-4-migration.md, generated by
#: :mod:`vecshield_platform.compliance.pack_history`.
PACK_VERSION = "vecshield-vector-store-draft-4"

#: Pack versions this build still recognises, newest first. A stored
#: assessment naming an older version was made against different criteria and
#: must not be read as if it were made against this pack. A reviewer decision
#: recorded under an older version is carried forward only when the
#: criterion's definition is unchanged (see ``decisions.staleness``).
KNOWN_PACK_VERSIONS = ("vecshield-vector-store-draft-4",
                       "vecshield-vector-store-draft-3",
                       "vecshield-vector-store-draft-2",
                       "vecshield-vector-store-draft-1")


#: Criterion fields that change how an obligation is presented, not what it
#: asks. A stored reviewer decision is bound to a digest of the criterion
#: that leaves these out, so a clearer title cannot orphan a conclusion.
#: ``aliases`` is here because absorbing a retired id does not change the
#: obligation either.
DISPLAY_ONLY_FIELDS = ("aliases", "title")

#: Everything left out of the digest a reviewer decision is bound to: the
#: display-only fields, plus the criterion's declared content lifecycle, which
#: records how far the *mapping* has been taken and not what it asks.
NON_MATERIAL_FIELDS = DISPLAY_ONLY_FIELDS + ("lifecycle",)

#: Lifecycle states a criterion may declare for itself. The states from
#: ``regulatory_reviewed`` on are never declared: they are derived from a
#: recorded content review whose digests match (``compliance.content_review``).
DECLARABLE_LIFECYCLE = ("draft", "technically_validated", "superseded")


@dataclass(frozen=True)
class Criterion:
    """One obligation, with the checks and artifacts that can speak to it."""

    id: str
    framework: str
    paraphrase: str
    source_ids: list[str] = field(default_factory=list)
    #: Check names as emitted in structured check outcomes.
    technical_checks: list[str] = field(default_factory=list)
    #: Artifacts a person must supply; a check cannot substitute for these.
    manual_evidence: list[str] = field(default_factory=list)
    applicability_questions: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    interpretation_notes: str = ""
    pack_version: str = PACK_VERSION
    #: How the framework writes this obligation. See SPECIFICATION_KINDS.
    #: None for frameworks that do not draw the distinction.
    specification: Optional[str] = None
    #: The provision that draws the required/addressable line, quoted back in
    #: an evaluation rationale so the reader can check the reasoning.
    specification_basis: Optional[str] = None
    #: Retired criterion ids this one absorbed. Kept resolvable so stored
    #: evidence reviews, exceptions and reviewer decisions are not orphaned.
    aliases: list[str] = field(default_factory=list)
    #: True when no check in this product speaks to the obligation and the
    #: criterion rests on manual artifacts alone. Stated rather than inferred
    #: from an empty check list, so an accidentally empty list stays a bug.
    manual_evidence_only: bool = False
    #: Artifacts required only when the technical checks could not establish
    #: the assertion (result ``not_run`` or ``inconclusive``) — the store does
    #: not expose the property, or the check saw part of the scope. When a
    #: check does observe it, the artifact is no longer demanded. Unlike
    #: ``manual_evidence``, which a check can never substitute for.
    fallback_evidence: list[str] = field(default_factory=list)
    #: A plain-language name for the obligation, for a reader who does not
    #: know the id or the provision. Display only: it is excluded from the
    #: digest a stored reviewer decision is bound to (see
    #: :data:`DISPLAY_ONLY_FIELDS`), so retitling never makes a decision stale.
    #: ``paraphrase`` remains the wording the decision was made against.
    title: str = ""
    #: The content lifecycle this criterion declares for itself: draft,
    #: technically_validated or superseded. Its effective state, which can
    #: reach regulatory_reviewed only through a matching content review, is
    #: :func:`compliance.content_review.criterion_lifecycle`. Not part of the
    #: decision digest (see :data:`NON_MATERIAL_FIELDS`).
    lifecycle: str = "draft"

    def __post_init__(self) -> None:
        if self.lifecycle not in DECLARABLE_LIFECYCLE:
            raise ValueError(
                f"{self.id}: lifecycle '{self.lifecycle}' cannot be declared; "
                "states from regulatory_reviewed on are reached only through a "
                "recorded content review")
        if self.specification is not None and self.specification not in SPECIFICATION_KINDS:
            raise ValueError(f"unknown specification kind: {self.specification}")
        if self.manual_evidence_only and self.technical_checks:
            raise ValueError(
                f"{self.id} is manual-evidence-only but names technical checks")
        if self.manual_evidence_only and not self.manual_evidence:
            raise ValueError(
                f"{self.id} is manual-evidence-only but names no artifact")
        if self.manual_evidence_only and self.fallback_evidence:
            raise ValueError(
                f"{self.id} is manual-evidence-only, so it has no technical result "
                "to fall back from; list the artifacts in manual_evidence")
        if not self.manual_evidence_only and not self.technical_checks:
            raise ValueError(
                f"{self.id} names no technical check; mark it "
                "manual_evidence_only if nothing in this product observes it")

    def to_dict(self) -> dict[str, Any]:
        # Imported here: content_review depends on this module for the digest.
        from vecshield_platform.compliance.content_review import criterion_lifecycle

        lifecycle = criterion_lifecycle(self)
        return {
            "criterion_id": self.id, "framework": self.framework,
            "pack_version": self.pack_version, "title": self.title,
            "paraphrase": self.paraphrase,
            "sources": resolve_sources(self.source_ids),
            "technical_checks": list(self.technical_checks),
            "manual_evidence": list(self.manual_evidence),
            "fallback_evidence": list(self.fallback_evidence),
            "manual_evidence_only": self.manual_evidence_only,
            "applicability_questions": list(self.applicability_questions),
            "limitations": list(self.limitations),
            "interpretation_notes": self.interpretation_notes,
            "specification": self.specification,
            "specification_basis": self.specification_basis,
            "aliases": list(self.aliases),
            "lifecycle": lifecycle["state"],
            "lifecycle_label": lifecycle["label"],
            "content_review": lifecycle["review"],
        }


@dataclass(frozen=True)
class ReviewerDecision:
    """A named person's conclusion for one criterion, scope, and period."""

    reviewer: str
    conclusion: str  # satisfied | gap | not_applicable
    rationale: str
    decided_at: str
    scope: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"reviewer": self.reviewer, "conclusion": self.conclusion,
                "rationale": self.rationale, "decided_at": self.decided_at,
                "scope": self.scope}


@dataclass
class CriterionAssessment:
    """The evaluated state of one criterion, with its four inputs intact."""

    criterion_id: str
    framework: str
    pack_version: str
    status: str
    applicability: dict[str, str]
    applicability_status: str
    technical_result: str
    technical_coverage: str
    evidence_sufficiency: str
    observations: list[dict[str, Any]] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    reviewer: Optional[dict[str, Any]] = None
    rationale: str = ""
    #: How the framework writes this obligation; None where it draws no
    #: standard/required/addressable distinction.
    specification: Optional[str] = None
    #: For an addressable specification: the state of the documented
    #: determination, or None where the concept does not apply. "missing" only
    #: signifies anything when the technical control is also absent — a
    #: specification that is implemented needs no determination.
    addressable_determination: Optional[str] = None
    #: For a risk-based measure: the state of the documented risk
    #: determination, or None where the concept does not apply.
    risk_determination: Optional[str] = None
    #: Fallback artifacts this evaluation required because the checks did not
    #: establish the assertion. Empty when the checks observed it.
    fallback_required: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "criterion_id": self.criterion_id, "framework": self.framework,
            "pack_version": self.pack_version, "status": self.status,
            "applicability": dict(self.applicability),
            "applicability_status": self.applicability_status,
            "technical_result": self.technical_result,
            "technical_coverage": self.technical_coverage,
            "evidence_sufficiency": self.evidence_sufficiency,
            "observations": list(self.observations),
            "missing_evidence": list(self.missing_evidence),
            "gaps": list(self.gaps), "limitations": list(self.limitations),
            "reviewer": self.reviewer, "rationale": self.rationale,
            "specification": self.specification,
            "addressable_determination": self.addressable_determination,
            "risk_determination": self.risk_determination,
            "fallback_required": list(self.fallback_required),
        }


def _applicability(criterion: Criterion,
                   answers: dict[str, str]) -> tuple[dict[str, str], str]:
    """Resolve each question; anything unanswered stays requires_confirmation."""
    resolved: dict[str, str] = {}
    for question in criterion.applicability_questions:
        answer = answers.get(question, "requires_confirmation")
        if answer not in APPLICABILITY_ANSWERS:
            raise ValueError(f"unknown applicability answer: {answer}")
        resolved[question] = answer
    if any(value == "no" for value in resolved.values()):
        return resolved, "excluded"
    if any(value == "requires_confirmation" for value in resolved.values()):
        return resolved, "requires_confirmation"
    return resolved, "confirmed"


def _technical(criterion: Criterion,
               outcomes: Iterable[dict[str, Any]]) -> tuple[str, str, list[dict[str, Any]]]:
    """Reduce the run's check outcomes for this criterion's checks.

    A manual-evidence-only criterion has no checks to reduce. It reports
    ``not_run`` with coverage ``not_applicable`` — distinct from ``unknown``,
    which means checks exist and did not report.
    """
    if criterion.manual_evidence_only:
        return "not_run", "not_applicable", []
    relevant = [o for o in outcomes if o.get("check") in criterion.technical_checks]
    if not relevant:
        return "not_run", "unknown", []
    # Crypto and access checks carry their evidence state; both read alike.
    states = {o.get("coverage", {}).get("crypto_state")
              or o.get("coverage", {}).get("access_state") for o in relevant}
    if states == {"not_applicable"}:
        # Every check says the property does not arise here — a filesystem
        # store has no transport to encrypt. That is not evidence the
        # obligation is met, so it must not read as a pass. Kept distinct from
        # "not_applicable", which marks a criterion no check speaks to.
        return "not_run", "does_not_arise", relevant
    if states == {"not_observable"}:
        # The checks ran; the store does not expose the property. Distinct
        # from "unknown", which means no check reported at all.
        return "not_run", "not_observable", relevant
    results = {o.get("outcome") for o in relevant}
    complete = all(o.get("coverage", {}).get("complete") is True for o in relevant)
    coverage = "complete" if complete else "partial"
    if "failed" in results:
        return "failed", coverage, relevant
    if results <= {"passed"} and complete:
        return "passed", "complete", relevant
    if results & {"error", "unsupported", "skipped"} and not (results & {"passed", "inconclusive"}):
        return "not_run", "unknown", relevant
    return "inconclusive", coverage, relevant


def _required_evidence(criterion: Criterion, technical_result: str) -> list[str]:
    """Manual artifacts always; fallback artifacts only when checks fell short."""
    required = list(criterion.manual_evidence)
    if technical_result in ("not_run", "inconclusive"):
        required += [r for r in criterion.fallback_evidence if r not in required]
    return required


def _evidence(criterion: Criterion, evidence: dict[str, str],
              technical_result: str = "not_run") -> tuple[str, list[str]]:
    """Summarize manual artifacts without letting silence become sufficiency."""
    required = _required_evidence(criterion, technical_result)
    if not required:
        return "not_required", []
    states = {}
    for requirement in required:
        state = evidence.get(requirement, "missing")
        if state not in EVIDENCE_STATES:
            raise ValueError(f"unknown evidence state: {state}")
        states[requirement] = state
    missing = [name for name, state in states.items()
               if state in ("missing", "rejected")]
    if missing:
        return ("rejected" if any(states[name] == "rejected" for name in missing)
                else "missing"), missing
    if all(state == "accepted" for state in states.values()):
        return "accepted", []
    return "submitted", []


def _determination(criterion: Criterion,
                   evidence: dict[str, str]) -> Optional[str]:
    """Read the documented determination, if the criterion has one to read.

    Returns None for every criterion that is neither an addressable
    specification nor a risk-based measure, so nothing about a standard or a
    required specification changes.
    """
    key = DETERMINATION_KEYS.get(criterion.specification or "")
    if key is None:
        return None
    state = evidence.get(key, "missing")
    if state not in EVIDENCE_STATES:
        raise ValueError(f"unknown evidence state: {state}")
    return state


def evaluate_criterion(criterion: Criterion, *,
                       check_outcomes: Iterable[dict[str, Any]] = (),
                       applicability_answers: Optional[dict[str, str]] = None,
                       evidence: Optional[dict[str, str]] = None,
                       reviewer_decision: Optional[ReviewerDecision] = None,
                       ) -> CriterionAssessment:
    """Evaluate one criterion. Pure: no I/O, no hidden defaults.

    The ordering encodes the plan's rules. Applicability is settled first,
    because an unconfirmed obligation cannot be satisfied or breached. An
    observed failure is a gap regardless of who has reviewed it. Everything
    else needs a reviewer before it can read as satisfied, and missing evidence
    never becomes a pass because no finding was produced.

    One obligation kind bends the "observed failure is a gap" rule, and only
    that kind. An *addressable* implementation specification (``specification
    == "addressable"``) is one the entity may lawfully not implement, provided
    it documented why the safeguard was not reasonable and appropriate and
    implemented an equivalent alternative where reasonable. So an addressable
    criterion with the control absent reads as a gap when there is no
    determination, and as an ordinary assessed criterion — still needing a
    reviewer — when an ``addressable_determination`` artifact is accepted.
    Accepting a determination never concludes compliance on its own; it moves
    the criterion from "unexplained absence" to "explained, now review it".
    Criteria whose ``specification`` is None are evaluated exactly as before.
    """
    evidence = evidence or {}
    resolved, applicability_status = _applicability(
        criterion, applicability_answers or {})
    technical_result, coverage, observations = _technical(
        criterion, check_outcomes)
    evidence_state, missing = _evidence(criterion, evidence, technical_result)
    fallback_required = [r for r in _required_evidence(criterion, technical_result)
                         if r not in criterion.manual_evidence]
    determination = _determination(criterion, evidence)
    risk_based = criterion.specification == "risk_based"
    basis = criterion.specification_basis or (
        "the framework's risk-based rule" if risk_based
        else "the framework's addressable rule")
    kind_label = "risk-based measure" if risk_based else "addressable specification"
    excused = determination == "accepted"

    gaps: list[str] = []
    if technical_result == "failed" and not excused:
        gaps.append("A technical check for this criterion observed a failure.")
    elif technical_result == "failed" and excused:
        gaps.append(
            "A technical check observed a failure. It is not recorded as an "
            f"unexplained gap because this is an {kind_label} and "
            f"an accepted determination under {basis} explains the absence. A "
            "reviewer still has to agree that the alternative measure is "
            "equivalent.")
    if missing:
        gaps.append("Required evidence is missing or rejected: " + ", ".join(missing))

    if applicability_status == "excluded":
        if reviewer_decision is None:
            status = "not_assessed"
            rationale = ("Scoped out by an applicability answer, but a reviewer must "
                         "record the exclusion before it counts as not applicable.")
        else:
            status = "not_applicable"
            rationale = reviewer_decision.rationale
    elif technical_result == "failed" and not excused:
        status = "gap_identified"
        rationale = "A check for this criterion failed within the observed scope."
        if criterion.specification == "addressable":
            rationale += (
                f" This is an addressable specification: under {basis} its "
                "absence is a gap until the entity documents why the safeguard "
                "is not reasonable and appropriate and records an equivalent "
                "alternative measure where one is reasonable. Addressable does "
                "not mean optional.")
        elif risk_based:
            rationale += (
                f" This is a risk-based measure: under {basis} it is required "
                "where appropriate to the risk, not universally. Its absence is a "
                "gap until the entity documents a risk determination explaining "
                "why the measure is not appropriate here. Risk-based does not "
                "mean optional.")
    elif applicability_status == "requires_confirmation":
        status = "not_assessed"
        rationale = ("Applicability is unconfirmed; this criterion has neither been "
                     "satisfied nor breached by this run.")
    elif evidence_state in ("missing", "rejected"):
        status = "evidence_needed"
        rationale = "Applicable, but the required manual evidence is not accepted."
    elif criterion.manual_evidence_only:
        # Nothing in this product observes the obligation, so "the checks did
        # not establish it" is not a finding about this run. The accepted
        # artifacts carry it to a reviewer, who still has to conclude.
        if reviewer_decision is None:
            status = "under_review"
            rationale = ("No check in this product observes this obligation; it "
                         "rests on the accepted artifacts alone, and a reviewer "
                         "must conclude.")
        elif reviewer_decision.conclusion == "satisfied":
            status = "satisfied_for_scope"
            rationale = reviewer_decision.rationale
        elif reviewer_decision.conclusion == "not_applicable":
            status = "not_applicable"
            rationale = reviewer_decision.rationale
        else:
            status = "gap_identified"
            rationale = reviewer_decision.rationale
            gaps.append("A reviewer recorded a gap for this criterion.")
    elif (technical_result in ("not_run", "inconclusive") and fallback_required
          and evidence_state == "accepted"):
        # The store could not show the property, and the accepted fallback
        # artifact is what the criterion rests on instead. It carries the
        # criterion to a reviewer; it never concludes it.
        if reviewer_decision is None:
            status = "under_review"
            rationale = (f"Technical coverage is {coverage}; the checks could not "
                         "establish the assertion, so it rests on the accepted "
                         "fallback evidence (" + ", ".join(fallback_required) +
                         "), and a reviewer must conclude.")
        elif reviewer_decision.conclusion == "satisfied":
            status = "satisfied_for_scope"
            rationale = reviewer_decision.rationale
        elif reviewer_decision.conclusion == "not_applicable":
            status = "not_applicable"
            rationale = reviewer_decision.rationale
        else:
            status = "gap_identified"
            rationale = reviewer_decision.rationale
            gaps.append("A reviewer recorded a gap for this criterion.")
    elif technical_result in ("not_run", "inconclusive") and not excused:
        status = "evidence_needed"
        rationale = (f"Technical coverage is {coverage}; the checks did not establish "
                     "the assertion for the whole scope.")
        if criterion.specification == "addressable":
            rationale += (
                f" For an addressable specification, {basis} accepts a documented "
                "determination that the safeguard is not reasonable and "
                "appropriate, with an equivalent alternative measure where one "
                "is reasonable, in place of the control. Neither the control "
                "nor that determination is established here.")
        elif risk_based:
            rationale += (
                f" For a risk-based measure, {basis} accepts a documented risk "
                "determination in place of the control. Neither the control nor "
                "that determination is established here.")
        if fallback_required:
            rationale += (" Because the checks could not establish it, this "
                          "criterion asks for: " + ", ".join(fallback_required) + ".")
    elif technical_result in ("not_run", "inconclusive") and excused:
        status = "under_review"
        rationale = (
            f"Technical coverage is {coverage}, but an accepted determination "
            f"under {basis} explains why this {kind_label} is not "
            "implemented as written. A reviewer must decide whether the "
            "alternative measure is equivalent.")
    elif reviewer_decision is None:
        status = "under_review"
        rationale = ("Checks passed over the full scope and evidence is accepted; a "
                     "reviewer must conclude.")
        if excused:
            rationale = (
                f"An accepted determination explains why this {kind_label} "
                f"is not implemented as written, per {basis}; a "
                "reviewer must decide whether the alternative measure is "
                "equivalent.")
    elif reviewer_decision.conclusion == "satisfied":
        status = "satisfied_for_scope"
        rationale = reviewer_decision.rationale
    elif reviewer_decision.conclusion == "not_applicable":
        status = "not_applicable"
        rationale = reviewer_decision.rationale
    else:
        status = "gap_identified"
        rationale = reviewer_decision.rationale
        gaps.append("A reviewer recorded a gap for this criterion.")

    assert status in CRITERION_STATUSES
    return CriterionAssessment(
        criterion_id=criterion.id, framework=criterion.framework,
        pack_version=criterion.pack_version, status=status,
        applicability=resolved, applicability_status=applicability_status,
        technical_result=technical_result, technical_coverage=coverage,
        evidence_sufficiency=evidence_state,
        observations=[dict(o) for o in observations], missing_evidence=missing,
        gaps=gaps, limitations=list(criterion.limitations),
        reviewer=reviewer_decision.to_dict() if reviewer_decision else None,
        rationale=rationale, specification=criterion.specification,
        addressable_determination=(determination if not risk_based else None),
        risk_determination=(determination if risk_based else None),
        fallback_required=fallback_required)


def evaluate_pack(criteria: Iterable[Criterion], *,
                  check_outcomes: Iterable[dict[str, Any]] = (),
                  applicability_answers: Optional[dict[str, str]] = None,
                  evidence: Optional[dict[str, str]] = None,
                  reviewer_decisions: Optional[dict[str, ReviewerDecision]] = None,
                  ) -> list[CriterionAssessment]:
    outcomes = list(check_outcomes)
    decisions = reviewer_decisions or {}
    return [evaluate_criterion(
        criterion, check_outcomes=outcomes,
        applicability_answers=applicability_answers, evidence=evidence,
        reviewer_decision=decisions.get(criterion.id)) for criterion in criteria]


def summarize_pack(assessments: Iterable[CriterionAssessment]) -> dict[str, Any]:
    """Counts for a criterion list. Nothing here rolls up to a compliance score."""
    assessments = list(assessments)
    counts = {status: 0 for status in CRITERION_STATUSES}
    for assessment in assessments:
        counts[assessment.status] += 1
    return {
        "criteria": len(assessments),
        "by_status": counts,
        "assessed": sum(counts[s] for s in
                        ("satisfied_for_scope", "gap_identified", "not_applicable")),
        "awaiting_input": sum(counts[s] for s in
                              ("not_assessed", "evidence_needed", "under_review")),
        "note": ("Status counts describe this run and its evidence. They are not a "
                 "compliance score and do not roll up across frameworks."),
    }
