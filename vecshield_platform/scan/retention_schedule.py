"""Retention measured against the schedule the customer declared.

``retention.py`` reports how old records are and deliberately never judges
it: VecShield does not know the schedule. This module is the other half. When
a customer *declares* a schedule — "card data 365 days, children's data 180
days, everything else 3 years" — the scan can compare each chunk's age with
the customer's own maximum and say which records are older than it.

Three rules keep the answer honest:

* **The judgement is the customer's, not ours.** A record older than the
  declared maximum is ``failed`` because the customer's own schedule says so.
  The wording is "older than your declared maximum", never "unlawful": a legal
  hold, a statutory clock that is not record time (BIPA runs from last
  interaction, GLBA from last use) or a wrong schedule can each explain it.
* **No schedule is not a failure.** Without one the check is ``skipped`` with
  that reason. Suggested periods from ``compliance/data/retention_references
  .json`` are for people to pick from; none is applied automatically.
* **Undated is not over-retained.** A chunk with no record-time field has an
  unknown age. It is counted as such, and a rule whose in-scope chunks are all
  undated is ``inconclusive`` rather than passed or failed.

Record time is inferred exactly as ``retention.observe_retention`` infers it
(same field choice across the collection, subject dates such as a date of
birth excluded), so the horizon check and this check never disagree about how
old a record is.

Pure: no I/O, no connector, no clock except the one passed in.
"""

from __future__ import annotations

import bisect
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from functools import lru_cache
from typing import Any, Optional, cast

from vecshield.models import Finding, SensitivityLabel, Severity
from vecshield_platform.coverage import check_outcome
from vecshield_platform.scan.retention import observe_retention, parse_timestamp

CHECK = "retention_schedule"
CATEGORY = "retention_schedule"

#: How the age of a record is measured. Only record time exists today: it is
#: the only clock the store itself can evidence. Kept as a declared field so a
#: schedule written now stays valid when another clock is added.
CLOCKS = ("record_time",)

#: Chunk ids kept per rule as examples. Ids only — never content.
MAX_EXAMPLES = 5

_BASIS_MAX = 500

#: Severity of an exceedance by the category the rule governs. The customer's
#: schedule decides *whether* a record is over; this decides how loudly.
_LABEL_SEVERITY: dict[str, Severity] = {
    SensitivityLabel.PCI.value: Severity.HIGH,
    SensitivityLabel.PHI.value: Severity.HIGH,
    SensitivityLabel.SPECIAL_CATEGORY.value: Severity.HIGH,
    SensitivityLabel.SECRET.value: Severity.HIGH,
    SensitivityLabel.CRIMINAL_OFFENCE.value: Severity.HIGH,
    SensitivityLabel.PII.value: Severity.MEDIUM,
    SensitivityLabel.SOURCE_CODE.value: Severity.LOW,
}
#: Qualifiers reach a stricter regime than their label (a child's email is
#: still an email, but COPPA / GDPR Art. 8 reach it).
_QUALIFIER_SEVERITY: dict[str, Severity] = {"minor": Severity.HIGH}
_DEFAULT_RULE_SEVERITY = Severity.LOW


class ScheduleError(ValueError):
    """A declared schedule that cannot be evaluated. Lists every problem."""

    def __init__(self, problems: list[str]):
        self.problems = list(problems)
        super().__init__("; ".join(self.problems))


# --------------------------------------------------------------- categories
@lru_cache(maxsize=1)
def _catalog() -> tuple[tuple[str, str, str], ...]:
    """(id, kind, label) for every category a rule may name."""
    from vecshield.classify.regex_classifier import DETECTORS

    rows: dict[str, tuple[str, str, str]] = {}
    for label in SensitivityLabel:
        if label is not SensitivityLabel.NONE:
            rows[label.value] = (label.value, "label", label.value)
    for det in DETECTORS:
        rows.setdefault(det.name, (det.name, "detector", det.label.value))
        if det.qualifier:
            # A qualifier inherits no single label; "minor" rides on PII spans.
            rows.setdefault(det.qualifier, (det.qualifier, "qualifier", ""))
    try:
        from vecshield.classify.presidio_classifier import _ENTITY_LABEL
    except Exception:  # noqa: BLE001 - optional NLP layer
        _ENTITY_LABEL = {}
    for entity, label in _ENTITY_LABEL.items():
        if label is not SensitivityLabel.NONE:
            name = f"presidio:{entity}"
            rows.setdefault(name, (name, "detector", label.value))
    return tuple(sorted(rows.values()))


def valid_categories() -> frozenset[str]:
    """Every category a rule may name: labels, detector ids and qualifiers."""
    return frozenset(row[0] for row in _catalog())


def category_catalog() -> list[dict[str, str]]:
    """The same list with its kind and parent label, for a rules editor."""
    return [{"id": cid, "kind": kind, "label": label} for cid, kind, label in _catalog()]


def category_severity(category: str) -> Severity:
    """How severe an exceedance of a rule for ``category`` is."""
    if category in _LABEL_SEVERITY:
        return _LABEL_SEVERITY[category]
    if category in _QUALIFIER_SEVERITY:
        return _QUALIFIER_SEVERITY[category]
    for cid, kind, label in _catalog():
        if cid == category and kind == "detector":
            return _LABEL_SEVERITY.get(label, Severity.MEDIUM)
    return Severity.MEDIUM


# ------------------------------------------------------------------ schema
@dataclass(frozen=True)
class RetentionRule:
    category: str
    max_age_days: int
    basis: str
    clock: str = "record_time"
    #: Id of a suggestion in retention_references.json the customer chose.
    reference: Optional[str] = None
    #: Collection-name patterns (fnmatch) the rule is limited to; empty = all.
    collections: tuple[str, ...] = ()

    def applies_to(self, collection: Optional[str]) -> bool:
        if not self.collections or collection is None:
            return True
        return any(fnmatchcase(collection, pattern) for pattern in self.collections)

    def to_dict(self) -> dict[str, Any]:
        return {"category": self.category, "max_age_days": self.max_age_days,
                "basis": self.basis, "clock": self.clock,
                "reference": self.reference, "collections": list(self.collections)}


@dataclass(frozen=True)
class RetentionSchedule:
    rules: tuple[RetentionRule, ...] = ()
    #: Maximum for any chunk no explicit rule reaches, sensitive or not.
    default_max_age_days: Optional[int] = None
    default_basis: str = ""

    @property
    def declared(self) -> bool:
        return bool(self.rules) or self.default_max_age_days is not None

    def to_dict(self) -> dict[str, Any]:
        return {"rules": [rule.to_dict() for rule in self.rules],
                "default_max_age_days": self.default_max_age_days,
                "default_basis": self.default_basis}


def _positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def validate_schedule(raw: RetentionSchedule | Mapping[str, Any] | None,
                      ) -> Optional[RetentionSchedule]:
    """Parse a declared schedule. ``None`` when nothing is declared.

    Raises :class:`ScheduleError` listing every problem, so an editor can show
    them all at once rather than one per save.
    """
    if raw is None:
        return None
    if isinstance(raw, RetentionSchedule):
        return raw if raw.declared else None
    if not isinstance(raw, Mapping):
        raise ScheduleError(["A retention schedule must be an object."])
    from vecshield_platform.compliance.data import reference_ids

    problems: list[str] = []
    unknown_keys = set(raw) - {"rules", "default_max_age_days", "default_basis"}
    if unknown_keys:
        problems.append(f"Unknown schedule fields: {', '.join(sorted(unknown_keys))}.")
    categories = valid_categories()
    references = reference_ids("retention")
    rules: list[RetentionRule] = []
    raw_rules = raw.get("rules") or []
    if not isinstance(raw_rules, list):
        problems.append("'rules' must be a list.")
        raw_rules = []
    seen: set[tuple[str, tuple[str, ...]]] = set()
    for index, item in enumerate(raw_rules):
        where = f"Rule {index + 1}"
        found: list[str] = []
        if not isinstance(item, Mapping):
            problems.append(f"{where} must be an object.")
            continue
        extra = set(item) - {"category", "max_age_days", "basis", "clock",
                             "reference", "collections"}
        if extra:
            found.append(f"{where} has unknown fields: {', '.join(sorted(extra))}.")
        category = item.get("category")
        if not isinstance(category, str) or category not in categories:
            found.append(f"{where}: unknown category {category!r}.")
        max_age = item.get("max_age_days")
        if not _positive_int(max_age):
            found.append(f"{where}: max_age_days must be a positive whole number of days.")
        basis = item.get("basis")
        if not isinstance(basis, str) or not basis.strip():
            found.append(f"{where}: basis is required (cite the policy or law "
                         "the period comes from).")
        elif len(basis) > _BASIS_MAX:
            found.append(f"{where}: basis is longer than {_BASIS_MAX} characters.")
        clock = item.get("clock", "record_time")
        if clock not in CLOCKS:
            found.append(f"{where}: clock must be one of {', '.join(CLOCKS)}.")
        reference = item.get("reference")
        if reference is not None and reference not in references:
            found.append(f"{where}: unknown reference {reference!r}.")
        patterns = item.get("collections") or []
        if not isinstance(patterns, list) or not all(
                isinstance(p, str) and p for p in patterns):
            found.append(f"{where}: collections must be a list of names or patterns.")
            patterns = []
        key = (str(category), tuple(sorted(patterns)))
        if key in seen:
            found.append(f"{where}: duplicates an earlier rule for {category!r}.")
        seen.add(key)
        problems.extend(found)
        if not found:
            rules.append(RetentionRule(
                category=str(category), max_age_days=cast(int, max_age),
                basis=str(basis).strip(),
                clock=clock, reference=reference,
                collections=tuple(sorted(patterns))))
    default = raw.get("default_max_age_days")
    if default is not None and not _positive_int(default):
        problems.append("default_max_age_days must be a positive whole number of days or null.")
    default_basis = raw.get("default_basis") or ""
    if not isinstance(default_basis, str) or len(default_basis) > _BASIS_MAX:
        problems.append(f"default_basis must be text of at most {_BASIS_MAX} characters.")
        default_basis = ""
    if problems:
        raise ScheduleError(problems)
    schedule = RetentionSchedule(rules=tuple(rules), default_max_age_days=default,
                                 default_basis=default_basis.strip())
    return schedule if schedule.declared else None


def resolve_schedule(config: Optional[Mapping[str, Any]],
                     store_id: Optional[str] = None) -> Optional[RetentionSchedule]:
    """The schedule that governs ``store_id``.

    ``config`` is ``{"global": <schedule>, "stores": {<store_id>: <schedule>}}``.
    A store entry *replaces* the global schedule rather than merging with it,
    so what a reviewer reads for a store is exactly what is evaluated. A bare
    schedule (a mapping with ``rules``) is read as the global one.
    """
    if not config:
        return None
    if "rules" in config or "default_max_age_days" in config:
        return validate_schedule(config)
    stores = config.get("stores") or {}
    if store_id is not None and store_id in stores:
        return validate_schedule(stores[store_id])
    return validate_schedule(config.get("global"))


# --------------------------------------------------------------- evaluation
@dataclass(frozen=True)
class RuleEvaluation:
    category: str
    max_age_days: int
    basis: str
    reference: Optional[str] = None
    is_default: bool = False
    in_scope: int = 0
    dated: int = 0
    age_unknown: int = 0
    over_max: int = 0
    oldest_age_days: Optional[int] = None
    examples: tuple[str, ...] = ()

    @property
    def severity(self) -> Severity:
        return _DEFAULT_RULE_SEVERITY if self.is_default else category_severity(self.category)

    def describe(self) -> str:
        subject = ("chunks no other rule covers" if self.is_default
                   else f"chunks with '{self.category}'")
        return (f"{self.over_max} of {self.in_scope} {subject} are older than "
                f"your declared maximum of {self.max_age_days} days"
                f" (oldest {self.oldest_age_days} days; basis: {self.basis or 'not stated'})")

    def to_dict(self) -> dict[str, Any]:
        return {"category": self.category, "is_default": self.is_default,
                "max_age_days": self.max_age_days, "basis": self.basis,
                "reference": self.reference, "in_scope": self.in_scope,
                "dated": self.dated, "age_unknown": self.age_unknown,
                "over_max": self.over_max, "oldest_age_days": self.oldest_age_days,
                "examples": list(self.examples), "severity": self.severity.value}


@dataclass(frozen=True)
class RetentionScheduleResult:
    declared: bool
    records_scanned: int = 0
    timestamp_field: Optional[str] = None
    excluded_fields: dict[str, int] = field(default_factory=dict)
    rules: tuple[RuleEvaluation, ...] = ()
    schedule: Optional[dict[str, Any]] = None

    @property
    def in_scope(self) -> int:
        return sum(rule.in_scope for rule in self.rules)

    @property
    def exceeded(self) -> tuple[RuleEvaluation, ...]:
        return tuple(rule for rule in self.rules if rule.over_max)

    @property
    def status(self) -> str:
        if not self.declared:
            return "no_schedule"
        if not self.records_scanned:
            return "nothing_scanned"
        if self.exceeded:
            return "exceeded"
        if not self.in_scope:
            return "nothing_in_scope"
        if not any(rule.dated for rule in self.rules):
            return "undated"
        if any(rule.age_unknown for rule in self.rules):
            return "partly_dated"
        return "within"

    @property
    def outcome(self) -> str:
        return {"no_schedule": "skipped", "exceeded": "failed",
                "undated": "inconclusive"}.get(self.status, "passed")

    @property
    def severity(self) -> Optional[Severity]:
        exceeded = self.exceeded
        if not exceeded:
            return None
        return max((rule.severity for rule in exceeded), key=lambda s: s.rank)

    def summary(self) -> str:
        status = self.status
        if status == "no_schedule":
            return "No retention schedule declared"
        if status == "nothing_scanned":
            return "No records were read, so there was nothing to compare with the declared schedule."
        if status == "exceeded":
            return "; ".join(rule.describe() for rule in self.exceeded) + "."
        if status == "nothing_in_scope":
            return "No scanned record falls under a declared retention rule."
        unknown = sum(rule.age_unknown for rule in self.rules)
        if status == "undated":
            return (f"{unknown} records fall under a declared retention rule but "
                    "none records when it was written, so their age against the "
                    "schedule is unknown.")
        if status == "partly_dated":
            return (f"No dated record is older than the declared maximum; "
                    f"{unknown} in-scope records have no record time and their "
                    "age is unknown.")
        return "Every in-scope record is within the declared maximum."

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status, "declared": self.declared,
                "records_scanned": self.records_scanned,
                "timestamp_field": self.timestamp_field,
                "excluded_fields": dict(self.excluded_fields),
                "in_scope": self.in_scope,
                "over_max": sum(rule.over_max for rule in self.rules),
                "age_unknown": sum(rule.age_unknown for rule in self.rules),
                "rules": [rule.to_dict() for rule in self.rules],
                "schedule": self.schedule,
                "summary": self.summary(),
                "note": ("Compared with the retention schedule you declared. "
                         "Older than your declared maximum is not a finding "
                         "that retention is unlawful: a legal hold, a legal "
                         "clock other than record time, or a wrong schedule "
                         "can explain it.")}


class _Tally:
    __slots__ = ("rule", "is_default", "in_scope", "dated", "unknown", "over",
                 "oldest", "examples")

    def __init__(self, rule: RetentionRule, is_default: bool = False):
        self.rule = rule
        self.is_default = is_default
        self.in_scope = self.dated = self.unknown = self.over = 0
        self.oldest: Optional[int] = None
        #: The MAX_EXAMPLES oldest over-max chunks as (-age, id): oldest
        #: first, ties broken by id so two runs over the same data agree.
        self.examples: list[tuple[int, str]] = []

    def add(self, chunk_id: str, age: Optional[int]) -> None:
        self.in_scope += 1
        if age is None:
            self.unknown += 1
            return
        self.dated += 1
        self.oldest = age if self.oldest is None else max(self.oldest, age)
        if age > self.rule.max_age_days:
            self.over += 1
            entry = (-age, chunk_id)
            if len(self.examples) < MAX_EXAMPLES or entry < self.examples[-1]:
                bisect.insort(self.examples, entry)
                del self.examples[MAX_EXAMPLES:]

    def result(self) -> RuleEvaluation:
        return RuleEvaluation(
            category="default" if self.is_default else self.rule.category,
            max_age_days=self.rule.max_age_days, basis=self.rule.basis,
            reference=self.rule.reference, is_default=self.is_default,
            in_scope=self.in_scope, dated=self.dated, age_unknown=self.unknown,
            over_max=self.over, oldest_age_days=self.oldest,
            examples=tuple(chunk_id for _, chunk_id in self.examples))


def _names(values: Any) -> set[str]:
    out: set[str] = set()
    for value in values or ():
        name = getattr(value, "value", value)
        if isinstance(name, str) and name:
            out.add(name)
    return out


def evaluate_retention_schedule(
        records: Iterable[Mapping[str, Any]],
        schedule: RetentionSchedule | Mapping[str, Any] | None, *,
        collection: Optional[str] = None,
        now: Optional[datetime] = None) -> RetentionScheduleResult:
    """Compare each chunk's record-time age with the declared schedule.

    ``records`` holds one mapping per scanned chunk: ``chunk_id``, ``labels``
    (sensitivity label values or enums), ``detectors`` (detector ids),
    ``qualifiers`` (e.g. ``"minor"``) and ``metadata`` (the chunk's metadata).
    A chunk is in scope of a rule when the rule's category is among its
    labels, detectors or qualifiers. It may be in scope of several rules, and
    each is evaluated on its own. The default maximum covers chunks no
    explicit rule reaches, sensitive or not.
    """
    parsed = validate_schedule(schedule)
    if parsed is None:
        return RetentionScheduleResult(declared=False)
    now = now or datetime.now(timezone.utc)
    items = list(records)
    horizon = observe_retention((dict(item.get("metadata") or {}) for item in items),
                                now=now)
    ts_field = horizon.timestamp_field

    rules = [rule for rule in parsed.rules if rule.applies_to(collection)]
    tallies = [_Tally(rule) for rule in rules]
    default = None
    if parsed.default_max_age_days is not None:
        default = _Tally(RetentionRule(category="default",
                                       max_age_days=parsed.default_max_age_days,
                                       basis=parsed.default_basis), is_default=True)

    for index, item in enumerate(items):
        chunk_id = str(item.get("chunk_id") or item.get("id") or f"#{index}")
        tags = (_names(item.get("labels")) | _names(item.get("detectors"))
                | _names(item.get("qualifiers")))
        age: Optional[int] = None
        if ts_field is not None:
            when = parse_timestamp((item.get("metadata") or {}).get(ts_field))
            if when is not None:
                age = max(0, (now - when).days)
        matched = False
        for tally in tallies:
            if tally.rule.category in tags:
                tally.add(chunk_id, age)
                matched = True
        if not matched and default is not None:
            default.add(chunk_id, age)

    evaluations = [tally.result() for tally in tallies]
    if default is not None:
        evaluations.append(default.result())
    return RetentionScheduleResult(
        declared=True, records_scanned=len(items), timestamp_field=ts_field,
        excluded_fields=dict(horizon.excluded), rules=tuple(evaluations),
        schedule=parsed.to_dict())


# ------------------------------------------------------------------ outputs
def retention_schedule_outcome(store: str, collection: Optional[str],
                               result: RetentionScheduleResult, *,
                               complete: bool = True, **coverage: Any) -> dict:
    """The ``retention_schedule`` check outcome for one collection.

    ``complete`` is whether the scan read the whole collection (not capped,
    no read errors); an evaluation is never more complete than the read it
    rests on. ``coverage`` passes through extra counters (chunks_expected...).
    """
    status = result.status
    # "status" is renamed: inside coverage it is the complete/partial flag
    # that summarize_coverage reads, and must not be overwritten.
    details = {("schedule_status" if k == "status" else k): v
               for k, v in result.to_dict().items()
               if k not in ("summary", "note", "schedule")}
    if status == "no_schedule":
        # Opt-in: a customer who declared no schedule did not ask for this
        # evaluation, so its absence must not make the run partial. Criteria
        # that rely on it still see `skipped` and ask for the schedule.
        return check_outcome(CHECK, store, collection, outcome="skipped",
                             reason=result.summary(), complete=False,
                             opt_in=True, schedule_status=status, **coverage)
    is_complete = bool(complete) and status not in ("undated", "partly_dated")
    return check_outcome(CHECK, store, collection, outcome=result.outcome,
                         reason=result.summary(), complete=is_complete,
                         chunks_scanned=result.records_scanned,
                         **{**details, **coverage})


def retention_schedule_findings(store: str, collection: Optional[str],
                                result: RetentionScheduleResult) -> list[Finding]:
    """One finding per collection whose records exceed the declared schedule."""
    exceeded = result.exceeded
    severity = result.severity
    if not exceeded or severity is None:
        return []
    remediation = (
        "Delete or anonymise the listed records (the evidence carries their "
        "ids), or correct the schedule if the period is wrong or the records "
        "are under a legal hold. Re-scan afterwards: the next assessment is the "
        "evidence that the deletion happened.")
    if any(rule.category == SensitivityLabel.PCI.value for rule in exceeded):
        remediation += (" PCI DSS 3.2.1 expects this verification at least once "
                        "every three months for stored account data.")
    where = f" in collection '{collection}'" if collection else ""
    return [Finding(
        id=f"find-{uuid.uuid4().hex[:10]}",
        title=f"Records older than your declared retention maximum{where}",
        severity=severity,
        category=CATEGORY,
        store=store,
        collection=collection,
        description=(result.summary() + " Ages are measured from record time ('"
                     f"{result.timestamp_field}'). This compares the records "
                     "with the schedule you declared; it does not determine "
                     "that holding them is unlawful."),
        evidence={k: v for k, v in result.to_dict().items() if k != "summary"},
        remediation=remediation,
    )]
