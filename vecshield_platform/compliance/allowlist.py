"""False-positive management: calibration allow-lists and finding suppressions.

Two *distinct* mechanisms — deliberately not conflated:

1. :class:`AllowlistRule` (**calibration**) — a standing decision that a class of
   findings is a known false positive (a synthetic test PAN, an
   injection-research corpus, an intentionally public demo endpoint). Matched by
   *scope* (store / collection / category / detector rule) and/or *value*
   patterns. Reduces noise at the class level.
2. :class:`Suppression` (**risk acceptance**) — accepting one specific,
   already-surfaced finding by its stable :mod:`fingerprint`. Every suppression
   carries an owner, a justification, and a **mandatory expiry** (VEX-style), so
   nothing is muted permanently or anonymously.

Guiding principle (see the design notes in the improvement plan): *suppress ≠
delete ≠ hide*. Suppressed findings are still detected, recorded, and counted —
they are merely tagged so they can be excluded from alerts / gate failures /
the SIEM feed, while remaining fully visible in the record and in compliance
evidence. Evaluation therefore never drops a finding; it partitions and tags.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from vecshield.models import Finding, Severity

from vecshield_platform.compliance.fingerprint import _rule_token, fingerprint_finding


class SuppressionError(ValueError):
    """Raised when a suppression / allow-list rule is invalid or unsafe."""


# --------------------------------------------------------------------------- #
# Safety knobs                                                                #
# --------------------------------------------------------------------------- #

#: Hard ceiling on any suppression's lifetime — nothing is muted "forever".
MAX_TTL_DAYS = 365
#: Tighter ceiling for the most sensitive findings (see :func:`is_sensitive`).
SENSITIVE_MAX_TTL_DAYS = 30

#: Categories always treated as sensitive regardless of severity.
_SENSITIVE_CATEGORIES = {"data_classification"}

#: Default suppression lifetime by severity — the more severe, the shorter the
#: leash, forcing re-review sooner.
_DEFAULT_TTL_DAYS = {
    Severity.CRITICAL: 7,
    Severity.HIGH: 30,
    Severity.MEDIUM: 90,
    Severity.LOW: 180,
    Severity.INFO: 365,
}


def is_sensitive(*, category: Optional[str] = None,
                 severity: Optional[Severity] = None) -> bool:
    """Whether a finding is sensitive enough to forbid a long / permanent mute.

    CRITICAL findings (which include SECRET / PCI / high-inversion PHI under the
    default policy set) and the data-classification category always qualify.
    """
    if severity is not None and severity.rank >= Severity.CRITICAL.rank:
        return True
    return category in _SENSITIVE_CATEGORIES


def default_ttl_days(severity: Severity) -> int:
    """Suggested suppression lifetime for a finding of the given severity."""
    return _DEFAULT_TTL_DAYS.get(severity, 90)


def _parse_dt(value: str) -> datetime:
    """Parse an ISO-8601 timestamp (tolerating a trailing ``Z``) as UTC-aware."""
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iter_strings(value: Any) -> Iterable[str]:
    """Yield every string reachable inside an arbitrarily nested evidence value."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _iter_strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _iter_strings(v)


# --------------------------------------------------------------------------- #
# Calibration allow-list                                                       #
# --------------------------------------------------------------------------- #

@dataclass
class AllowlistRule:
    """A scope/value matcher that marks a class of findings as a known FP."""

    id: str
    reason: str
    # scope (None = "any")
    category: Optional[str] = None
    store: Optional[str] = None
    collection: Optional[str] = None
    rule: Optional[str] = None            # substring of the detector rule token
    # matchers (empty = "not constrained on this dimension")
    fingerprints: tuple[str, ...] = ()
    value_patterns: tuple[str, ...] = ()
    source: str = "custom"                # "custom" | "builtin"
    owner: str = ""
    created_at: str = field(default_factory=lambda: _now().isoformat())

    def __post_init__(self) -> None:
        # A rule with neither a scope nor a matcher would silence *everything*.
        has_scope = any([self.category, self.store, self.collection, self.rule])
        has_matcher = bool(self.fingerprints or self.value_patterns)
        if not has_scope and not has_matcher:
            raise SuppressionError(
                f"allow-list rule '{self.id}' is unscoped: it would match every "
                "finding. Add a scope (category/store/collection/rule) or a "
                "matcher (fingerprints/value_patterns).")
        self._value_re = [re.compile(p, re.IGNORECASE) for p in self.value_patterns]

    def matches(self, finding: Finding, fingerprint: str) -> bool:
        if self.category is not None and finding.category != self.category:
            return False
        if self.store is not None and finding.store != self.store:
            return False
        if self.collection is not None and finding.collection != self.collection:
            return False
        if self.rule is not None and self.rule.lower() not in _rule_token(finding.title):
            return False
        if self.fingerprints and fingerprint not in self.fingerprints:
            return False
        if self._value_re:
            strings = list(_iter_strings(finding.evidence or {}))
            if not any(rx.search(s) for rx in self._value_re for s in strings):
                return False
        return True

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "reason": self.reason,
            "category": self.category,
            "store": self.store,
            "collection": self.collection,
            "rule": self.rule,
            "fingerprints": list(self.fingerprints),
            "value_patterns": list(self.value_patterns),
            "source": self.source,
            "owner": self.owner,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "AllowlistRule":
        return cls(
            id=d["id"],
            reason=d.get("reason", ""),
            category=d.get("category"),
            store=d.get("store"),
            collection=d.get("collection"),
            rule=d.get("rule"),
            fingerprints=tuple(d.get("fingerprints") or ()),
            value_patterns=tuple(d.get("value_patterns") or ()),
            source=d.get("source", "custom"),
            owner=d.get("owner", ""),
            created_at=d.get("created_at") or _now().isoformat(),
        )


# --------------------------------------------------------------------------- #
# Finding suppression (risk acceptance)                                        #
# --------------------------------------------------------------------------- #

@dataclass
class Suppression:
    """Time-boxed acceptance of one specific finding, by fingerprint."""

    fingerprint: str
    reason: str
    owner: str
    expires_at: str                       # ISO-8601, mandatory
    ticket: Optional[str] = None
    id: str = field(default_factory=lambda: f"supp-{uuid.uuid4().hex[:10]}")
    created_at: str = field(default_factory=lambda: _now().isoformat())

    def is_active(self, now: Optional[datetime] = None) -> bool:
        return (now or _now()) < _parse_dt(self.expires_at)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "fingerprint": self.fingerprint,
            "reason": self.reason,
            "owner": self.owner,
            "expires_at": self.expires_at,
            "ticket": self.ticket,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Suppression":
        return cls(
            fingerprint=d["fingerprint"],
            reason=d.get("reason", ""),
            owner=d.get("owner", ""),
            expires_at=d["expires_at"],
            ticket=d.get("ticket"),
            id=d.get("id") or f"supp-{uuid.uuid4().hex[:10]}",
            created_at=d.get("created_at") or _now().isoformat(),
        )


def validate_suppression(
    supp: Suppression,
    *,
    category: Optional[str] = None,
    severity: Optional[Severity] = None,
    now: Optional[datetime] = None,
) -> None:
    """Enforce the anti-"suppress-and-forget" rules; raise on violation.

    Every suppression must expire, must not already be expired, and must not
    outlive the global ceiling. Sensitive findings (see :func:`is_sensitive`)
    get a much tighter ceiling so they cannot be quietly muted for long.
    """
    now = now or _now()
    if not supp.fingerprint:
        raise SuppressionError("suppression requires a finding fingerprint.")
    if not supp.reason.strip():
        raise SuppressionError("suppression requires a justification (reason).")
    if not supp.owner.strip():
        raise SuppressionError("suppression requires an owner.")
    if not supp.expires_at:
        raise SuppressionError("suppression requires an expiry (mandatory TTL).")

    expires = _parse_dt(supp.expires_at)
    if expires <= now:
        raise SuppressionError("suppression expiry is already in the past.")

    ttl_days = (expires - now).days
    if ttl_days > MAX_TTL_DAYS:
        raise SuppressionError(
            f"suppression TTL {ttl_days}d exceeds the maximum {MAX_TTL_DAYS}d.")
    if is_sensitive(category=category, severity=severity) and ttl_days > SENSITIVE_MAX_TTL_DAYS:
        raise SuppressionError(
            f"sensitive findings cannot be muted for {ttl_days}d; the maximum is "
            f"{SENSITIVE_MAX_TTL_DAYS}d and re-approval is required after that.")


# --------------------------------------------------------------------------- #
# Evaluation                                                                   #
# --------------------------------------------------------------------------- #

@dataclass
class SuppressionResult:
    active: list[Finding]
    suppressed: list[Finding]
    coverage: dict[str, float]            # category -> fraction suppressed
    over_suppressed: list[str]            # categories over the coverage threshold

    @property
    def suppressed_count(self) -> int:
        return len(self.suppressed)


def _tag(finding: Finding, info: Optional[dict]) -> None:
    if finding.evidence is None:
        finding.evidence = {}
    if info is None:
        finding.evidence["suppressed"] = False
        finding.evidence.pop("suppression", None)
    else:
        finding.evidence["suppressed"] = True
        finding.evidence["suppression"] = info


def evaluate_suppressions(
    findings: Iterable[Finding],
    *,
    allowlist: Iterable[AllowlistRule] = (),
    suppressions: Iterable[Suppression] = (),
    now: Optional[datetime] = None,
    over_threshold: float = 0.5,
    min_scope_size: int = 3,
) -> SuppressionResult:
    """Partition findings into active vs. suppressed, tagging each in place.

    A finding is suppressed if an *active* :class:`Suppression` matches its
    fingerprint, or if any :class:`AllowlistRule` matches it. Suppressed
    findings are tagged (``evidence['suppressed']`` / ``evidence['suppression']``)
    but never removed — callers filter on the tag for alerts/gates while keeping
    the full record for evidence.
    """
    now = now or _now()
    allow = list(allowlist)
    active_supp = {s.fingerprint: s for s in suppressions if s.is_active(now)}

    active: list[Finding] = []
    suppressed: list[Finding] = []
    by_cat_total: dict[str, int] = {}
    by_cat_supp: dict[str, int] = {}

    for f in findings:
        cat = f.category or ""
        by_cat_total[cat] = by_cat_total.get(cat, 0) + 1
        fp = fingerprint_finding(f)

        info: Optional[dict] = None
        supp = active_supp.get(fp)
        if supp is not None:
            info = {"source": "suppression", "rule_id": supp.id,
                    "reason": supp.reason, "owner": supp.owner,
                    "expires_at": supp.expires_at, "ticket": supp.ticket}
        else:
            for rule in allow:
                if rule.matches(f, fp):
                    info = {"source": "allowlist", "rule_id": rule.id,
                            "reason": rule.reason, "owner": rule.owner,
                            "origin": rule.source}
                    break

        _tag(f, info)
        if info is None:
            active.append(f)
        else:
            suppressed.append(f)
            by_cat_supp[cat] = by_cat_supp.get(cat, 0) + 1

    coverage = {
        cat: round(by_cat_supp.get(cat, 0) / total, 4)
        for cat, total in by_cat_total.items()
    }
    over = sorted(
        cat for cat, total in by_cat_total.items()
        if total >= min_scope_size and coverage[cat] > over_threshold
    )
    return SuppressionResult(active=active, suppressed=suppressed,
                             coverage=coverage, over_suppressed=over)


# --------------------------------------------------------------------------- #
# Safe built-in defaults                                                       #
# --------------------------------------------------------------------------- #

def builtin_allowlist() -> list[AllowlistRule]:
    """Curated allow-list of unambiguously-synthetic artifacts.

    These keep the day-one false-positive rate low *without* customers muting
    anything real. They match on value patterns found in finding evidence
    (previews/examples); where a detector does not surface the raw value they
    are simply inert.
    """
    return [
        AllowlistRule(
            id="builtin-test-pan",
            reason="Well-known Luhn-valid synthetic test card numbers (not real PANs).",
            category="data_classification", source="builtin",
            value_patterns=(
                r"4111[\s-]?1111[\s-]?1111[\s-]?1111",   # Visa test
                r"5500[\s-]?0000[\s-]?0000[\s-]?0004",   # MasterCard test
                r"3400[\s-]?0000[\s-]?0000[\s-]?009",    # Amex test
                r"6011[\s-]?0000[\s-]?0000[\s-]?0004",   # Discover test
            ),
        ),
        AllowlistRule(
            id="builtin-example-domains",
            reason="RFC 2606 reserved example domains used in docs/tests.",
            source="builtin",
            value_patterns=(r"@example\.(?:com|net|org)\b",),
        ),
        AllowlistRule(
            id="builtin-doc-ips",
            reason="RFC 5737 documentation IP ranges (TEST-NET-1/2/3).",
            source="builtin",
            value_patterns=(
                r"\b192\.0\.2\.\d{1,3}\b",
                r"\b198\.51\.100\.\d{1,3}\b",
                r"\b203\.0\.113\.\d{1,3}\b",
            ),
        ),
        AllowlistRule(
            id="builtin-aws-example-key",
            reason="AWS documentation placeholder access key id.",
            source="builtin",
            value_patterns=(r"AKIAIOSFODNN7EXAMPLE",),
        ),
    ]
