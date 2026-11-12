"""Known vulnerabilities and support status of the database *server*.

``run_server_vulnerability_checks`` asks the connector which server product
and version it is talking to (``server_info()``), matches that against the
local advisory feed (``vulnfeed``), and produces:

* one ``server_vulnerability`` finding per advisory the running version is
  affected by, carrying the advisory's own description, CVSS, CWE, affected
  range, fixed versions, the nearest fix on the customer's release line, the
  single upgrade that clears every matched advisory, the advisory's own
  workaround (quoted, with its source), whether the customer's configuration
  exposes it, and CISA KEV status;
* a ``server_support_status`` finding when the release line is end-of-life or
  close to it;
* check outcomes named exactly ``server_vulnerability`` and
  ``server_support_status`` (store-level, collection ``None``).

Nothing here guesses. An unknown or unparseable version is inconclusive, a
managed service that hides its version is the provider's to patch, and
remediation text is assembled only from the advisory data and the curated,
cited overlay in ``data/advisory_conditions.json``.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any, Callable, Iterable, Optional

from vecshield.models import Finding, Severity
from vecshield_platform.connectors.base import UnsupportedCapability
from vecshield_platform.coverage import check_outcome
from vecshield_platform.posture.cvss import band_step, score_to_severity
from vecshield_platform.posture.versions import (
    Version,
    parse_server_version,
    parse_version,
    release_line,
)
from vecshield_platform.posture.vulnfeed import (
    PRODUCTS,
    Feed,
    canonical_product,
    load_feed,
    trim,
)

SERVER_VULNERABILITY = "server_vulnerability"
SERVER_SUPPORT_STATUS = "server_support_status"

DESCRIPTION_LIMIT = 600
DEFAULT_STALE_AFTER_DAYS = 7
DEFAULT_MAX_AGE_DAYS = 30
EOL_WARNING_DAYS = 90

#: Connector kinds whose product has no server-version API at all (managed,
#: versionless services). A missing server_info there is a product fact.
NO_VERSION_API_KINDS = frozenset({"pinecone", "openai", "azure_search", "bedrock_kb",
                                  "vertex_ai"})

AFFECTED_AND_EXPOSED = "affected_and_exposed"
AFFECTED_CONDITION_UNKNOWN = "affected_condition_unknown"
AFFECTED_NOT_EXPOSED = "affected_not_exposed"


# --- matching -------------------------------------------------------------------

def _v(text: object) -> Optional[Version]:
    return parse_version(str(text).lstrip("vV")) if text not in (None, "") else None


def in_interval(version: Version, interval: dict) -> Optional[bool]:
    """Whether ``version`` lies in one advisory interval (None if unreadable)."""
    if "version" in interval:
        exact = _v(interval["version"])
        return None if exact is None else version == exact
    lower = interval.get("introduced")
    if lower not in (None, "", "0"):
        lo = _v(lower)
        if lo is None:
            return None
        if interval.get("introduced_exclusive") and not version > lo:
            return False
        if version < lo:
            return False
    for key, inclusive in (("fixed", False), ("before", False), ("last_affected", True)):
        if key in interval:
            hi = _v(interval[key])
            if hi is None:
                return None
            return version <= hi if inclusive else version < hi
    return True


def affected_by(version: Version, advisory: dict, product: str) -> tuple[Optional[bool], dict]:
    """(affected?, basis). None means the advisory's data cannot decide."""
    ranges = advisory.get("ranges") or []
    listed = [v for v in (_v(x) for x in advisory.get("versions") or []) if v is not None]
    if not ranges and not listed:
        return None, {"basis": "no_version_data"}
    for interval in ranges:
        if in_interval(version, interval):
            return True, {"basis": "range", "interval": interval}
    if listed:
        if version in listed:
            return True, {"basis": "listed_version"}
        line = release_line(product, version)
        same_line = [v for v in listed if release_line(product, v) == line and v <= version]
        line_fixes = [f for f in (_v(r.get("fixed")) for r in ranges if r.get("fixed"))
                      if f is not None and release_line(product, f) == line]
        if same_line and not any(f <= version for f in line_fixes):
            return True, {"basis": "inferred_same_line",
                          "note": (f"the advisory lists {', '.join(str(v) for v in same_line[:3])}"
                                   f" on the {line} line and records no fix on that line at or "
                                   f"below {version}")}
    return False, {"basis": "not_in_range"}


def _fix_versions(advisory: dict) -> list[Version]:
    out = {f for f in (_v(r.get("fixed")) for r in advisory.get("ranges") or []
                       if r.get("fixed")) if f is not None}
    return sorted(out)


def _stable(version: Version) -> Version:
    """A pre-release fix ships in its final release (1.38.0-rc.0 -> 1.38.0)."""
    if not version.is_prerelease:
        return version
    return Version(".".join(map(str, version.release)), version.release)


# --- applicability ----------------------------------------------------------------

def _feature(features: dict, path: str) -> Any:
    node: Any = features
    for part in path.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    return node


def _norm(value: Any) -> Any:
    return value.strip().lower() if isinstance(value, str) else value


def _names(value: Any) -> Optional[list[str]]:
    if value is None:
        return None
    if isinstance(value, dict):
        return [str(k).lower() for k in value]
    if isinstance(value, (list, tuple, set)):
        return [str(v).lower() for v in value]
    return [p.strip().lower() for p in str(value).split(",") if p.strip()]


def evaluate_check(check: dict, features: dict) -> tuple[Optional[bool], str]:
    """(exposed?, explanation). None = the feature is not reported."""
    if "any_of" in check:
        notes = []
        for option in check["any_of"]:
            result, note = evaluate_check(option, features)
            if result is not None:
                return result, note
            notes.append(note)
        return None, "; ".join(notes)
    path = check.get("feature", "")
    value = _feature(features, path)
    if value is None:
        return None, f"{path} is not reported by the connector"
    kind = check.get("kind")
    if kind == "equals":
        normalised = _norm(value)
        if normalised in [_norm(v) for v in check.get("exposed") or []]:
            return True, f"{path} = {value!r}"
        if normalised in [_norm(v) for v in check.get("not_exposed") or []]:
            return False, f"{path} = {value!r}"
        return None, f"{path} = {value!r} does not decide exposure"
    if kind in ("any_prefix", "contains"):
        names = _names(value) or []
        target = str(check.get("value", "")).lower()
        hit = [n for n in names if (n.startswith(target) if kind == "any_prefix"
                                    else n == target or target in n)]
        if hit:
            return True, f"{path} includes {', '.join(hit[:5])}"
        return False, f"{path} ({', '.join(names[:8]) or 'empty'}) has no {target!r}"
    if kind == "greater_than":
        try:
            number = float(value)
        except (TypeError, ValueError):
            return None, f"{path} = {value!r} is not numeric"
        threshold = float(check.get("value", 0))
        return (number > threshold), f"{path} = {value!r}"
    if kind == "regex":
        text = str(value)
        if check.get("exposed") and re.search(check["exposed"], text):
            return True, f"{path} matches {check['exposed']!r}"
        if check.get("not_exposed") and re.search(check["not_exposed"], text):
            return False, f"{path} matches {check['not_exposed']!r}"
        return None, f"{path} does not decide exposure"
    return None, f"unknown condition kind {kind!r}"


def applicability(advisory: dict, features: dict, feed: Optional[Feed],
                  product: str) -> dict:
    """Whether the customer's configuration exposes a matched advisory."""
    overlay = advisory.get("overlay") or {}
    condition = overlay.get("condition")
    pg_component = (advisory.get("pg_component") or "").lower()
    if pg_component and pg_component != "core server":
        return _pg_component_applicability(advisory, pg_component, features, feed)
    if not condition and advisory.get("platforms"):
        return _platform_applicability(advisory["platforms"], features)
    if not condition:
        return {"state": AFFECTED_AND_EXPOSED,
                "reason": "The advisory states no configuration prerequisite beyond the "
                          "affected version."}
    results = [evaluate_check(check, features) for check in condition.get("checks") or []]
    notes = "; ".join(note for _r, note in results)
    base = {"condition": condition.get("summary", ""), "source_url": condition.get("source_url"),
            "quote": condition.get("quote", ""), "evaluated": notes}
    if any(r is False for r, _n in results):
        return {"state": AFFECTED_NOT_EXPOSED,
                "reason": f"{condition.get('summary', '')} Observed: {notes}.", **base}
    if results and all(r is True for r, _n in results):
        return {"state": AFFECTED_AND_EXPOSED,
                "reason": f"{condition.get('summary', '')} Observed: {notes}.", **base}
    return {"state": AFFECTED_CONDITION_UNKNOWN,
            "reason": f"{condition.get('summary', '')} Could not confirm from the server: "
                      f"{notes}.", **base}


def _platform_applicability(platforms: list[str], features: dict) -> dict:
    """NVD lists the advisory only on specific operating systems."""
    names = ", ".join(p.replace(":", " ") for p in platforms)
    base = {"condition": f"NVD lists this only when running on: {names}",
            "source_url": "https://nvd.nist.gov/"}
    os_name = _feature(features, "os")
    if not os_name:
        return {"state": AFFECTED_CONDITION_UNKNOWN,
                "reason": f"NVD lists this only on {names}; the server OS was not reported.",
                **base}
    text = str(os_name).lower()
    hit = [p for p in platforms if any(tok in text for tok in p.split(":") if len(tok) > 2)]
    if hit:
        return {"state": AFFECTED_AND_EXPOSED,
                "reason": f"NVD lists this on {names}; the server reports OS {os_name!r}.", **base}
    return {"state": AFFECTED_NOT_EXPOSED,
            "reason": f"NVD lists this only on {names}; the server reports OS {os_name!r}.",
            **base}


def _pg_component_applicability(advisory: dict, component: str, features: dict,
                                feed: Optional[Feed]) -> dict:
    notes = feed.product_notes("postgresql") if feed is not None else {}
    legend = (notes.get("components") or {}).get(component, "")
    source = notes.get("components_source_url") or "https://www.postgresql.org/support/security/"
    base = {"condition": f"PostgreSQL component: {component}", "quote": legend,
            "source_url": source}
    if component in ("client", "client contrib module", "packaging"):
        return {"state": AFFECTED_NOT_EXPOSED,
                "reason": (f"PostgreSQL classifies this as a '{component}' issue: {legend} The "
                           "server process is not the vulnerable component, but client tools "
                           "installed from this release are."), **base}
    if component == "contrib module":
        installed = _names(_feature(features, "extensions"))
        preload = _names(_feature(features, "shared_preload_libraries")) or []
        if installed is None and not preload:
            return {"state": AFFECTED_CONDITION_UNKNOWN,
                    "reason": (f"{legend} The connector did not report installed extensions, "
                               "so whether the named module is in use is unknown."), **base}
        text = f"{advisory.get('summary', '')} {advisory.get('details', '')[:300]}".lower()
        used = [n for n in (installed or []) + preload
                if re.search(rf"\b{re.escape(n)}\b", text)]
        if used:
            return {"state": AFFECTED_AND_EXPOSED,
                    "reason": f"The advisory names {', '.join(used)}, which is installed.", **base}
        return {"state": AFFECTED_NOT_EXPOSED,
                "reason": (f"{legend} None of the installed extensions or preloaded libraries "
                           f"({', '.join((installed or []) + preload) or 'none'}) is named in "
                           "the advisory."), **base}
    return {"state": AFFECTED_CONDITION_UNKNOWN,
            "reason": f"PostgreSQL component '{component}'.", **base}


# --- assessment ---------------------------------------------------------------

@dataclass
class AdvisoryMatch:
    advisory: dict
    component: str
    component_version: Version
    basis: dict
    severity: Severity
    base_severity: Severity
    severity_reason: str
    applicability: dict
    same_line_fix: Optional[str] = None
    next_fix: Optional[str] = None
    fix_note: str = ""

    @property
    def id(self) -> str:
        return self.advisory["id"]


@dataclass
class ComponentAssessment:
    component: str
    raw_version: str
    version: Optional[Version]
    line: Optional[str]
    note: str = ""
    version_source: str = ""
    matches: list[AdvisoryMatch] = field(default_factory=list)
    undetermined: list[dict] = field(default_factory=list)
    not_version_assessed: list[dict] = field(default_factory=list)
    recommended_upgrade: Optional[dict] = None
    advisories_checked: int = 0


@dataclass
class ServerAssessment:
    product: str
    label: str
    status: str                      # assessed | inconclusive | not_applicable | unsupported
    reason: str
    server_info: dict
    components: list[ComponentAssessment] = field(default_factory=list)
    support: Optional[dict] = None
    feed: dict = field(default_factory=dict)

    @property
    def matches(self) -> list[AdvisoryMatch]:
        return [m for c in self.components for m in c.matches]


def _severity_for(advisory: dict, app: dict) -> tuple[Severity, Severity, str]:
    best = advisory.get("cvss_best") or {}
    base = score_to_severity(best.get("score"), advisory.get("severity_label") or "")
    reasons = []
    if base is None:
        base = Severity.MEDIUM
        reasons.append("no CVSS score or severity label in the advisory sources; "
                       "treated as MEDIUM")
    elif best.get("score") is not None:
        reasons.append(f"CVSS {best.get('version')} base score {best.get('score')}")
    else:
        reasons.append(f"advisory severity label {advisory.get('severity_label')}")
        curated = (advisory.get("overlay") or {}).get("advisory") or {}
        if curated.get("severity_basis") and \
                curated.get("severity_label") == advisory.get("severity_label"):
            reasons.append(f"label set by VecShield's advisory overlay: "
                           f"{curated['severity_basis']}")
    severity = base
    if app["state"] == AFFECTED_NOT_EXPOSED:
        severity = band_step(base, -1)
        if severity != base:
            reasons.append("lowered one band: the observed configuration does not expose it")
    kev = advisory.get("kev")
    if kev:
        floor = Severity.HIGH if app["state"] != AFFECTED_NOT_EXPOSED else Severity.MEDIUM
        if severity.rank < floor.rank:
            severity = floor
            reasons.append(f"raised to {floor.value.upper()}: listed in CISA KEV "
                           f"(added {kev.get('date_added', '?')})")
        else:
            reasons.append("listed in CISA KEV")
    return severity, base, "; ".join(reasons)


def _match_fixes(match: AdvisoryMatch, product: str, all_advisories: list[dict]) -> None:
    version = match.component_version
    line = release_line(product, version)
    fixes = [f for f in _fix_versions(match.advisory) if f > version]
    same_line = [f for f in fixes if release_line(product, f) == line]
    if same_line:
        fix = _stable(min(same_line))
        match.same_line_fix = str(fix)
        if fix != min(same_line):
            match.fix_note = (f"the fix first shipped in pre-release {min(same_line).raw}; "
                              f"{fix} is its final release")
        return
    later = [f for f in fixes if affected_by(f, match.advisory, product)[0] is not True]
    if later:
        fix = _stable(min(later))
        match.next_fix = str(fix)
        match.fix_note = (f"no fix is recorded for the {line} line; the nearest fixed release "
                          f"is {fix} on the {release_line(product, fix)} line")
        if fix != min(later):
            match.fix_note += f" (first shipped in pre-release {min(later).raw})"
    else:
        last = [la for la in (_v(r.get("last_affected")) for r in match.advisory.get("ranges") or []
                              if r.get("last_affected")) if la is not None and la >= version]
        match.fix_note = "the advisory sources record no fixed release"
        if last:
            match.fix_note += (f"; the last affected release they record is {max(last)}, so "
                               f"check the release notes of later releases for the fix")


def _recommend_upgrade(product: str, version: Version, matches: list[AdvisoryMatch],
                       advisories: list[dict], support: Optional[dict]) -> Optional[dict]:
    """The lowest release that clears every matched advisory (same line first)."""
    if not matches:
        return None
    # Every fixed release named by any advisory is a real release number; the
    # lowest one that no known advisory affects is the recommendation.
    candidates = {_stable(f) for a in advisories for f in _fix_versions(a) if f > version}
    candidates |= {_stable(f) for m in matches for f in _fix_versions(m.advisory) if f > version}
    latest = _v((support or {}).get("latest_on_line"))
    if latest is not None and latest > version:
        candidates.add(latest)
    if not candidates:
        return {"version": None,
                "reason": "none of the matched advisories records a fixed release"}
    line = release_line(product, version)
    eol_lines = set((support or {}).get("eol_lines") or [])

    def clears(candidate: Version, pool: Iterable[dict]) -> list[str]:
        return [a["id"] for a in pool if affected_by(candidate, a, product)[0] is True]

    ordered = sorted(candidates, key=lambda c: (release_line(product, c) != line,
                                                release_line(product, c) in eol_lines, c))
    matched_advisories = [m.advisory for m in matches]
    for candidate in ordered:
        if not clears(candidate, matched_advisories) and not clears(candidate, advisories):
            cand_line = release_line(product, candidate)
            return {"version": str(candidate), "line": cand_line,
                    "same_line": cand_line == line,
                    "clears": [m.id for m in matches],
                    "reason": ("lowest release on your line with none of the known advisories"
                               if cand_line == line else
                               f"no release on the {line} line clears every matched advisory; "
                               f"lowest clean release is on the {cand_line} line")}
    for candidate in ordered:
        if not clears(candidate, matched_advisories):
            residual = clears(candidate, advisories)
            return {"version": str(candidate), "line": release_line(product, candidate),
                    "same_line": release_line(product, candidate) == line,
                    "clears": [m.id for m in matches], "still_affected_by": residual,
                    "reason": "clears every matched advisory, but other known advisories "
                              "affect this release too"}
    unfixed = [m.id for m in matches if not _fix_versions(m.advisory)]
    return {"version": None, "unfixed": unfixed,
            "reason": "no single recorded release clears every matched advisory"}


def _component_version(product: str, component: str, server_info: dict) -> tuple[str, str]:
    if component == "server":
        return str(server_info.get("version") or ""), ""
    features = server_info.get("features") or {}
    for path in PRODUCTS[product].components.get(component, ()):
        value = _feature(features, path)
        if isinstance(value, dict):
            value = value.get("version")
        if value:
            return str(value), path
    return "", ""


def assess_support(product: str, version: Optional[Version], feed: Feed,
                   now: datetime) -> dict:
    spec = PRODUCTS.get(product)
    if spec is None:
        return {"status": "unknown", "reason": "product is not in the catalogue"}
    if version is None:
        return {"status": "unknown", "reason": "server version unknown"}
    line = release_line(product, version)
    data = feed.eol(product) or {}
    today = now.date()
    if spec.eol.kind == "not_published":
        notes = feed.product_notes(product)
        return {"status": "policy_not_published", "line": line,
                "reason": spec.eol.note or f"{spec.label} publishes no end-of-life schedule.",
                "policy_url": spec.eol.policy_url or None,
                "upgrade_notes": notes.get("upgrade_notes")}
    if spec.eol.kind == "latest_n_minors":
        latest = _v(data.get("latest"))
        if latest is None:
            return {"status": "unknown", "line": line, "policy_url": spec.eol.policy_url,
                    "reason": "the latest release is not in the feed; refresh it"}
        n = int(data.get("n") or spec.eol.n)
        supported = [f"{latest.part(0)}.{latest.part(1) - i}" for i in range(n)
                     if latest.part(1) - i >= 0]
        base = {"line": line, "policy_url": spec.eol.policy_url,
                "policy_quote": data.get("policy_quote") or spec.eol.note,
                "latest_release": str(latest), "latest_source": data.get("latest_source"),
                "supported_lines": supported}
        if line in supported:
            return {"status": "supported", "reason": f"{line} is one of the {n} most recent "
                                                      f"minors ({', '.join(supported)})", **base}
        if version > latest:
            return {"status": "unknown", "reason": f"{version} is newer than the latest "
                                                   f"release in the feed ({latest})", **base}
        return {"status": "eol", "eol_date": None,
                "reason": f"{line} is outside the {n} most recent minors "
                          f"({', '.join(supported)})", **base}
    cycles = data.get("cycles") or []
    if not cycles:
        return {"status": "unknown", "line": line,
                "reason": "no end-of-life data in the feed; refresh it"}
    by_name = {str(c.get("cycle")): c for c in cycles}
    cycle = by_name.get(line) or by_name.get(f"{version.part(0)}.{version.part(1)}") \
        or by_name.get(str(version.part(0)))
    eol_lines = [str(c.get("cycle")) for c in cycles if _cycle_is_eol(c, today)]
    base = {"line": line, "source_url": data.get("source_url"),
            "policy_url": data.get("policy_url") or None, "eol_lines": eol_lines}
    if cycle is None:
        return {"status": "unknown", "reason": f"release line {line} is not in the "
                                               "end-of-life table", **base}
    base.update({"cycle": cycle.get("cycle"), "eol_date": cycle.get("eol"),
                 "latest_on_line": cycle.get("latest")})
    if _cycle_is_eol(cycle, today):
        return {"status": "eol", "reason": f"{spec.label} {cycle.get('cycle')} reached end of "
                                           f"life{' on ' + cycle['eol'] if cycle.get('eol') else ''}",
                **base}
    eol_date = _date(cycle.get("eol"))
    if eol_date is not None and (eol_date - today).days <= EOL_WARNING_DAYS:
        return {"status": "eol_within_90_days", "days_left": (eol_date - today).days,
                "reason": f"{spec.label} {cycle.get('cycle')} reaches end of life on "
                          f"{cycle.get('eol')}", **base}
    return {"status": "supported", "reason": f"{spec.label} {cycle.get('cycle')} is supported"
                                             + (f" until {cycle['eol']}" if cycle.get("eol")
                                                else ""), **base}


def _date(value: object) -> Optional[date]:
    try:
        return date.fromisoformat(str(value)[:10]) if value else None
    except ValueError:
        return None


def _cycle_is_eol(cycle: dict, today: date) -> bool:
    eol_date = _date(cycle.get("eol"))
    if eol_date is not None:
        return eol_date <= today
    return bool(cycle.get("is_eol"))


def assess_server(server_info: dict, feed: Feed, *, now: Optional[datetime] = None
                  ) -> ServerAssessment:
    now = now or datetime.now(timezone.utc)
    info = dict(server_info or {})
    product = canonical_product(info.get("product"))
    spec = PRODUCTS.get(product)
    label = spec.label if spec else (str(info.get("product") or "unknown"))
    feed_state = feed.status(now)
    base: dict[str, Any] = dict(product=product, label=label,
                                server_info=_safe_info(info), feed=feed_state)
    if spec is None:
        return ServerAssessment(status="unsupported", reason=(
            f"No advisory source is catalogued for server product "
            f"{info.get('product') or 'unknown'!r}."), **base)
    if not feed.available:
        return ServerAssessment(status="inconclusive",
                                reason="No advisory feed is available.", **base)
    if info.get("managed") and not info.get("version"):
        return ServerAssessment(status="not_applicable", reason=(
            f"Managed {label} service: the provider patches the server and does not expose its "
            f"version{': ' + info['reason'] if info.get('reason') else ''}."), **base)
    parsed = parse_server_version(product, info.get("version"))
    if parsed.version is None:
        return ServerAssessment(status="inconclusive", reason=(
            f"The {label} server version could not be determined ({parsed.note}); known "
            "vulnerabilities cannot be ruled out."), **base)
    features = info.get("features") or {}
    support = assess_support(product, parsed.version, feed, now)
    components: list[ComponentAssessment] = []
    for component in ["server"] + list(spec.components):
        raw, path = _component_version(product, component, info)
        if component != "server" and not raw:
            continue
        cver: Optional[Version]
        if component == "server":
            cver, note = parsed.version, parsed.note
        else:
            cparsed = parse_server_version(component, raw)
            cver, note = cparsed.version, cparsed.note
        comp = ComponentAssessment(component=component, raw_version=raw, version=cver,
                                   line=release_line(product, cver) if cver else None, note=note,
                                   version_source=path)
        components.append(comp)
        if cver is None:
            continue
        advisories = feed.advisories(product, component)
        comp.advisories_checked = len(advisories)
        for advisory in advisories:
            excluded = (advisory.get("overlay") or {}).get("exclude_from_version_matching")
            if excluded:
                comp.not_version_assessed.append({"id": advisory["id"], **excluded})
                continue
            affected, basis = affected_by(cver, advisory, product)
            if affected is None:
                comp.undetermined.append({
                    "id": advisory["id"], "summary": advisory.get("summary", ""),
                    "reason": advisory.get("unparsed") or "no comparable version data",
                    "kev": bool(advisory.get("kev")), "url": advisory.get("advisory_url")})
                continue
            if not affected:
                continue
            app = applicability(advisory, features, feed, product)
            severity, base_sev, why = _severity_for(advisory, app)
            match = AdvisoryMatch(advisory=advisory, component=component,
                                  component_version=cver, basis=basis, severity=severity,
                                  base_severity=base_sev, severity_reason=why,
                                  applicability=app)
            _match_fixes(match, product, advisories)
            comp.matches.append(match)
        comp.recommended_upgrade = _recommend_upgrade(
            product, cver, comp.matches, advisories,
            support if component == "server" else None)
    return ServerAssessment(status="assessed", reason="", components=components,
                            support=support, **base)


def _safe_info(info: dict) -> dict:
    """server_info without anything that looks like a credential."""
    out = {}
    for key in ("product", "version", "edition", "managed", "source", "reason"):
        if key in info:
            out[key] = info[key]
    features = info.get("features") or {}
    out["features"] = {k: v for k, v in features.items()
                       if not re.search(r"(?i)(pass|secret|token|key|auth.*header)", str(k))}
    return out


# --- findings and outcomes ------------------------------------------------------

def _fid() -> str:
    return f"find-{uuid.uuid4().hex[:10]}"


def _match_finding(assessment: ServerAssessment, comp: ComponentAssessment,
                   match: AdvisoryMatch, store: str) -> Finding:
    adv = match.advisory
    label = assessment.label if comp.component == "server" else comp.component
    ids = [adv["id"]] + [a for a in adv.get("aliases") or [] if a.startswith("GHSA-")][:1]
    title = (f"{label} {comp.version} is affected by {ids[0]}"
             + (f" ({ids[1]})" if len(ids) > 1 else "")
             + (f": {trim(adv.get('summary', ''), 90)}" if adv.get("summary") else ""))
    description = trim(adv.get("details") or adv.get("summary") or "", DESCRIPTION_LIMIT)
    app = match.applicability
    kev = adv.get("kev")
    best = adv.get("cvss_best") or {}
    upgrade = comp.recommended_upgrade or {}
    workaround = adv.get("workaround")
    remediation = _remediation_text(assessment, comp, match, upgrade, workaround)
    evidence = {
        "advisory_id": adv["id"], "aliases": adv.get("aliases") or [],
        "product": assessment.product, "component": comp.component,
        "running_version": str(comp.version), "reported_version": comp.raw_version,
        "version_source": comp.version_source or None,
        "release_line": comp.line, "version_note": comp.note or None,
        "summary": adv.get("summary"), "description": description,
        "cvss": {"vector": best.get("vector"), "score": best.get("score"),
                 "version": best.get("version"), "score_basis": best.get("score_basis"),
                 "all": adv.get("cvss") or []},
        "severity_reason": match.severity_reason, "base_severity": match.base_severity.value,
        "cwe": adv.get("cwe") or [],
        "affected_ranges": adv.get("ranges") or [],
        "affected_versions_listed": (adv.get("versions") or [])[:20],
        "match_basis": match.basis,
        "range_source": adv.get("range_source"),
        "fixed_versions": adv.get("fixed_versions") or [],
        "same_line_fix": match.same_line_fix, "nearest_fix": match.next_fix,
        "fix_note": match.fix_note or None,
        "recommended_upgrade": _compact_upgrade(upgrade),
        "workaround": workaround,
        "applicability": app["state"], "applicability_reason": app.get("reason"),
        "applicability_source": {k: app.get(k) for k in ("condition", "quote", "source_url",
                                                         "evaluated") if app.get(k)} or None,
        "known_exploited": bool(kev), "kev": kev,
        "published": adv.get("published"), "modified": adv.get("modified"),
        "advisory_url": adv.get("advisory_url"), "references": adv.get("references") or [],
        "sources": adv.get("sources") or [],
        "feed": {"origin": assessment.feed.get("origin"),
                 "updated_at": assessment.feed.get("updated_at"),
                 "age_days": assessment.feed.get("age_days")},
    }
    if adv.get("pg_component"):
        evidence["postgresql_component"] = adv["pg_component"]
    return Finding(id=_fid(), title=title, severity=match.severity,
                   category=SERVER_VULNERABILITY, store=store, collection=None,
                   description=description + (f"\n\nApplicability: {app.get('reason')}"
                                              if app.get("reason") else ""),
                   evidence=evidence, remediation=remediation)


def _compact_upgrade(upgrade: Optional[dict]) -> Optional[dict]:
    if not upgrade:
        return None
    out = dict(upgrade)
    for key in ("clears", "still_affected_by", "unfixed"):
        if key in out:
            out[f"{key}_count"] = len(out[key])
            out[key] = out[key][:20]
    return out


def _remediation_text(assessment: ServerAssessment, comp: ComponentAssessment,
                      match: AdvisoryMatch, upgrade: dict, workaround: Optional[dict]) -> str:
    label = assessment.label if comp.component == "server" else comp.component
    parts: list[str] = []
    managed = bool(assessment.server_info.get("managed"))
    verb = "Apply the provider's upgrade to" if managed else "Upgrade"
    if match.same_line_fix:
        parts.append(f"{verb} {label} from {comp.version} to {match.same_line_fix}, the fix for "
                     f"{match.id} on your {comp.line} release line"
                     + (f" ({match.fix_note})" if match.fix_note else "") + ".")
    elif match.next_fix:
        parts.append(f"{verb} {label} to {match.next_fix}: {match.fix_note}.")
    else:
        last = (f" ({match.fix_note.split('; ', 1)[1]})"
                if "; " in match.fix_note else "")
        usable = workaround and not workaround.get("none_known")
        parts.append(f"No fixed {label} release is recorded for {match.id} yet{last}"
                     + ("; apply the workaround below and track the advisory." if usable
                        else "; restrict access to the affected feature and track the "
                             "advisory for a fixed release."))
    if upgrade.get("version") and len(comp.matches) > 1:
        clears = len(upgrade.get("clears") or [])
        parts.append(f"To clear all {clears} advisories matched for {comp.version}, upgrade to "
                     f"{upgrade['version']} ({upgrade.get('reason')}).")
    notes = (assessment.support or {}).get("upgrade_notes")
    if notes and comp.component == "server":
        parts.append(f"Upgrade path ({notes.get('source_url')}): {notes.get('text')}")
    if workaround and workaround.get("none_known"):
        parts.append(f"The advisory states there is no workaround ({workaround.get('source_url')}):"
                     f" \"{trim(workaround.get('text', ''), 200)}\" Upgrading is the only fix.")
    elif workaround:
        heading = workaround.get("heading") or "advisory"
        parts.append(f"Until you can upgrade — {heading} ({workaround.get('source_url')}): "
                     f"\"{trim(workaround.get('text', ''), 500)}\"")
    kev = match.advisory.get("kev")
    if kev:
        parts.append(f"CISA lists this as known exploited (added {kev.get('date_added')}, federal "
                     f"due date {kev.get('due_date')}); required action: "
                     f"{kev.get('required_action')}")
    app = match.applicability
    if app["state"] == AFFECTED_CONDITION_UNKNOWN and app.get("condition"):
        parts.append(f"Check whether this applies: {app.get('condition')}"
                     + (f" (source: {app.get('source_url')})" if app.get("source_url") else ""))
    return " ".join(parts)


def _support_finding(assessment: ServerAssessment, store: str) -> Optional[Finding]:
    support = assessment.support or {}
    status = support.get("status")
    if status not in ("eol", "eol_within_90_days"):
        return None
    comp = assessment.components[0]
    label = assessment.label
    severity = Severity.HIGH if status == "eol" else Severity.LOW
    latest = support.get("latest_release") or support.get("latest_on_line")
    supported = support.get("supported_lines")
    if status == "eol":
        title = f"{label} {comp.line} is end-of-life (running {comp.version})"
        remediation = (f"Move to a supported {label} release line"
                       + (f" ({', '.join(supported)})" if supported else "")
                       + (f"; the latest release is {latest}" if support.get("latest_release")
                          else "")
                       + ". End-of-life lines receive no security fixes, so advisories "
                         "published after the end date will not be fixed on this line.")
    else:
        title = (f"{label} {comp.line} reaches end of life on {support.get('eol_date')} "
                 f"({support.get('days_left')} days)")
        remediation = (f"Plan the upgrade to a newer {label} release line before "
                       f"{support.get('eol_date')}"
                       + (f"; meanwhile stay on the latest {comp.line} release ({latest})"
                          if latest else "") + ".")
    return Finding(id=_fid(), title=title, severity=severity, category=SERVER_SUPPORT_STATUS,
                   store=store, collection=None, description=support.get("reason", ""),
                   evidence={k: v for k, v in {**support, "product": assessment.product,
                                                "running_version": str(comp.version)}.items()
                             if v not in (None, [], "")},
                   remediation=remediation)


def _extension_lag_finding(assessment: ServerAssessment, store: str) -> Optional[Finding]:
    """pgvector's package was upgraded but the database's extension objects were not.

    The advisory match uses the package (the code that runs); this records
    that the SQL objects still describe the older release.
    """
    if assessment.product != "postgresql":
        return None
    features = (assessment.server_info or {}).get("features") or {}
    package, catalog = features.get("pgvector_package"), features.get("pgvector")
    package_v, catalog_v = parse_version(str(package or "")), parse_version(str(catalog or ""))
    if package_v is None or catalog_v is None or not catalog_v < package_v:
        return None
    return Finding(
        id=_fid(), title=(f"pgvector extension objects are at {catalog} while the installed "
                          f"package is {package}"),
        severity=Severity.LOW, category=SERVER_VULNERABILITY, store=store, collection=None,
        description=("The pgvector package on the server was upgraded, but this database's "
                     "extension was not updated. The functions, operators and types it "
                     "defines are the older release's, so SQL-level changes in the newer "
                     "release are missing until the extension is updated."),
        evidence={"product": "postgresql", "component": "pgvector",
                  "installed_package_version": str(package),
                  "extension_catalog_version": str(catalog),
                  "source": "pg_available_extensions.default_version; "
                            "pg_extension.extversion",
                  "source_url": "https://github.com/pgvector/pgvector#upgrading"},
        remediation="Run ALTER EXTENSION vector UPDATE; in each database that uses pgvector.")


def findings_and_outcomes(assessment: ServerAssessment, store: str, *,
                          stale_after_days: float = DEFAULT_STALE_AFTER_DAYS,
                          max_age_days: float = DEFAULT_MAX_AGE_DAYS
                          ) -> tuple[list[Finding], list[dict]]:
    findings: list[Finding] = []
    feed = assessment.feed or {}
    age = feed.get("age_days")
    feed_cov = {"feed_origin": feed.get("origin"), "feed_updated_at": feed.get("updated_at"),
                "feed_age_days": age,
                "feed_stale": bool(age is not None and age > stale_after_days),
                "product": assessment.product,
                "version": (assessment.server_info or {}).get("version")}
    feed_fresh = age is not None and age <= max_age_days
    if assessment.status != "assessed":
        outcome, limit = {"inconclusive": ("inconclusive", False),
                          "not_applicable": ("unsupported", True),
                          "unsupported": ("unsupported", False)}[assessment.status]
        extra = {"applicability": "not_applicable"} if assessment.status == "not_applicable" \
            else {}
        if assessment.status == "not_applicable":
            findings.append(Finding(
                id=_fid(), title=f"{assessment.label} server patching is managed by the provider",
                severity=Severity.INFO, category=SERVER_VULNERABILITY, store=store,
                description=assessment.reason,
                evidence={"product": assessment.product, "managed": True,
                          "server_info": assessment.server_info},
                remediation="Keep the provider's patch-management attestation (for example its "
                            "SOC 2 report) as evidence; the server version is not visible."))
        outcomes = [check_outcome(check, store, None, outcome=outcome, reason=assessment.reason,
                                  complete=False, capability_limit=limit, **extra, **feed_cov)
                    for check in (SERVER_VULNERABILITY, SERVER_SUPPORT_STATUS)]
        return findings, outcomes

    matches: list[AdvisoryMatch] = []
    undetermined: list[dict] = []
    excluded: list[dict] = []
    for comp in assessment.components:
        for match in comp.matches:
            findings.append(_match_finding(assessment, comp, match, store))
            matches.append(match)
        undetermined.extend(comp.undetermined)
        excluded.extend(comp.not_version_assessed)
    lag = _extension_lag_finding(assessment, store)
    if lag:
        findings.append(lag)
    server = assessment.components[0]
    if undetermined:
        findings.append(Finding(
            id=_fid(), title=(f"{len(undetermined)} {assessment.label} advisories could not be "
                              "matched to a version"),
            severity=Severity.INFO, category=SERVER_VULNERABILITY, store=store,
            description=("These advisories do not state affected versions in a form that can be "
                         "compared with the running release; review them manually."),
            evidence={"advisories": undetermined[:25]},
            remediation="Read each advisory and confirm it does not apply to this deployment."))
    kev_undetermined = [u["id"] for u in undetermined if u.get("kev")]
    checked = sum(c.advisories_checked for c in assessment.components)
    upgrade = server.recommended_upgrade
    cov = {**feed_cov, "advisories_checked": checked, "advisories_matched": len(matches),
           "matched": [m.id for m in matches], "undetermined": [u["id"] for u in undetermined],
           "not_version_assessed": [e["id"] for e in excluded],
           "known_exploited_matched": [m.id for m in matches if m.advisory.get("kev")],
           "recommended_upgrade": (upgrade or {}).get("version"),
           "recommended_upgrade_reason": (upgrade or {}).get("reason"),
           "components": {c.component: str(c.version) if c.version else None
                          for c in assessment.components}}
    unparsed_components = [c.component for c in assessment.components if c.version is None]
    if matches:
        outcome = "failed"
        worst = max(matches, key=lambda m: m.severity.rank)
        reason = (f"{assessment.label} {server.version} is affected by {len(matches)} known "
                  f"advisor{'y' if len(matches) == 1 else 'ies'} (most severe: {worst.id}, "
                  f"{worst.severity.value}).")
    elif kev_undetermined:
        outcome = "inconclusive"
        reason = ("Known-exploited advisories could not be matched to a version: "
                  f"{', '.join(kev_undetermined)}.")
    elif unparsed_components:
        outcome = "inconclusive"
        reason = f"Component version unreadable: {', '.join(unparsed_components)}."
    else:
        outcome = "passed"
        reason = (f"No known advisory in the feed affects {assessment.label} {server.version} "
                  f"({checked} checked).")
    outcomes = [check_outcome(SERVER_VULNERABILITY, store, None, outcome=outcome, reason=reason,
                              complete=feed_fresh and not unparsed_components, **cov)]

    support = assessment.support or {}
    status = support.get("status")
    support_finding = _support_finding(assessment, store)
    if support_finding:
        findings.append(support_finding)
    support_cov = {**feed_cov, "support_status": status, "release_line": support.get("line"),
                   "eol_date": support.get("eol_date"),
                   "source_url": support.get("source_url") or support.get("policy_url")}
    if status == "eol":
        s_outcome, limit = "failed", False
    elif status in ("supported", "eol_within_90_days"):
        s_outcome, limit = "passed", False
    elif status == "policy_not_published":
        s_outcome, limit = "unsupported", True
    else:
        s_outcome, limit = "inconclusive", False
    outcomes.append(check_outcome(SERVER_SUPPORT_STATUS, store, None, outcome=s_outcome,
                                  reason=support.get("reason", ""),
                                  complete=feed_fresh and s_outcome in ("passed", "failed"),
                                  capability_limit=limit, **support_cov))
    return findings, outcomes


def run_server_vulnerability_checks(connector: Any, store: Any, *, feed: Optional[Feed] = None,
                                    now: Optional[datetime] = None,
                                    state_dir: Optional[str] = None,
                                    stale_after_days: float = DEFAULT_STALE_AFTER_DAYS,
                                    max_age_days: float = DEFAULT_MAX_AGE_DAYS,
                                    info_reader: Optional[Callable[[], Any]] = None,
                                    ) -> tuple[list[Finding], list[dict]]:
    """Entry point: read ``server_info()`` where it can be read, assess, and report.

    Whether it can be read is decided by ``store_facts`` (the connector's own
    method or its kind's adapter). ``info_reader`` returns ``server_info()``
    (or raises its failure); an assessment passes one that replays what it
    already gathered, so the store is asked once.
    """
    from vecshield_platform import store_facts

    store_name = getattr(store, "name", None) or str(store)
    now = now or datetime.now(timezone.utc)
    feed = feed or load_feed(state_dir)
    kind = str(getattr(connector, "kind", "") or "")
    try:
        capabilities = set(store_facts.supported(connector))
    except Exception:  # noqa: BLE001 - a posture check never crashes the audit
        capabilities = set()
    feed_cov = {"feed_origin": feed.origin, "feed_age_days": feed.age_days(now)}

    def no_version_api() -> tuple[list[Finding], list[dict]]:
        limit = kind in NO_VERSION_API_KINDS
        reason = (f"{kind or 'This store'} exposes no server version; the provider patches the "
                  "service." if limit else
                  f"The {kind or 'store'} connector does not report the server version, so "
                  "known server vulnerabilities cannot be ruled out.")
        return [], [check_outcome(check, store_name, None,
                                  outcome="unsupported" if limit else "inconclusive",
                                  reason=reason, complete=False, capability_limit=limit,
                                  **feed_cov)
                    for check in (SERVER_VULNERABILITY, SERVER_SUPPORT_STATUS)]

    if "server_info" not in capabilities:
        return no_version_api()
    if info_reader is None:
        def info_reader() -> Any:
            return store_facts.server_info(connector)
    try:
        info = info_reader()
    except UnsupportedCapability:
        return no_version_api()
    except Exception as exc:  # noqa: BLE001
        reason = f"server_info() failed ({type(exc).__name__}); server version unknown."
        return [], [check_outcome(check, store_name, None, outcome="error", reason=reason,
                                  complete=False, **feed_cov)
                    for check in (SERVER_VULNERABILITY, SERVER_SUPPORT_STATUS)]
    if not isinstance(info, dict):
        info = {}
    info.setdefault("product", kind)
    assessment = assess_server(info, feed, now=now)
    return findings_and_outcomes(assessment, store_name, stale_after_days=stale_after_days,
                                 max_age_days=max_age_days)
