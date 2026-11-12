"""What changed between two saved audits of the same store.

Answers "what changed since the last scan" (improvement plan §2.3) and, for
cryptographic posture, VCR-14: storage encryption that was verified last time
and is not now. It compares two frozen snapshots — the dicts
``History.save_audit`` stores — and never touches a store.

Two rules keep the comparison honest:

* A check is compared by ``(check, collection)``. One missing from the older
  snapshot is ``new``: it was not run then, so there is nothing to call fixed.
  One missing from the newer snapshot is ``absent``: untested, not passed.
* A finding that disappears is ``resolved`` only when the newer audit ran a
  check that could have reported it again, and ran it to completion (or it
  failed, which is a complete answer). Otherwise it is ``not_retested``: a
  scan that did not look, or looked at only a capped sample, is not evidence
  of a fix.
"""

from __future__ import annotations

import difflib
import re
from typing import Any, Optional

from vecshield.models import Finding, Severity
from vecshield_platform.compliance.fingerprint import fingerprint_finding
from vecshield_platform.crypto.states import CRYPTO_CHECKS

NOTE = "A check absent from one snapshot is untested there, not passed."

#: When one snapshot records several outcomes for the same key, the worst one
#: stands for it, so a regression in one record is never hidden by a sibling.
_OUTCOME_RANK = {"failed": 5, "error": 4, "inconclusive": 3, "unsupported": 2,
                 "skipped": 1, "passed": 0}

#: Checks whose findings share their name, whether or not either snapshot ran
#: them (an excluded posture pass leaves no outcome to recognise them by).
_KNOWN_CHECKS = frozenset({"data_classification", "network_exposure",
                           "transport_encryption", "authentication", "cve",
                           "retention_schedule", "biometric_templates",
                           *CRYPTO_CHECKS})

#: Finding category -> the checks that would report it again. A category that
#: is also a check name maps to itself without an entry here.
_CATEGORY_CHECKS = {
    "isolation": ("tenant_isolation",),
    "rag_integrity": ("prompt_injection", "embedding_anomaly", "provenance"),
    "boundary_pii": ("chunk_boundary",),
    # "No retention horizon" findings come from the retention_horizon check.
    # Without this entry a capped re-scan would read their disappearance as
    # resolved, since an unmapped category is taken at face value.
    "retention": ("retention_horizon",),
}


def check_outcomes(snapshot: Optional[dict]) -> list[dict]:
    """Every check outcome a snapshot recorded, including pre-v1 layouts.

    Schema-1 snapshots list them at the top level (audit and job outcomes
    together). Older ones only have them on each job.
    """
    if not snapshot:
        return []
    if isinstance(snapshot.get("check_outcomes"), list):
        return list(snapshot["check_outcomes"])
    return [outcome for job in snapshot.get("jobs", [])
            for outcome in (job.get("stats") or {}).get("check_outcomes", [])]


def _state(outcome: dict) -> dict:
    coverage = outcome.get("coverage") or {}
    return {"outcome": outcome.get("outcome"),
            "crypto_state": coverage.get("crypto_state")}


def _keyed(snapshot: Optional[dict]) -> dict[tuple[str, Optional[str]], dict]:
    keyed: dict[tuple[str, Optional[str]], dict] = {}
    for outcome in check_outcomes(snapshot):
        check = outcome.get("check")
        if not check:
            continue
        key = (check, outcome.get("collection"))
        state = _state(outcome)
        current = keyed.get(key)
        if current is None or (_OUTCOME_RANK.get(state["outcome"], 3)
                               > _OUTCOME_RANK.get(current["outcome"], 3)):
            keyed[key] = state
    return keyed


def _retest_keys(snapshot: Optional[dict]) -> set[tuple[str, Optional[str]]]:
    """Checks whose outcome is conclusive enough to confirm a finding is gone.

    A complete pass qualifies; so does ``failed``, since a failing check has
    certainly looked. A partial or ``inconclusive`` run — a capped
    classification, say — may simply not have reached the record.
    """
    return {(outcome.get("check"), outcome.get("collection"))
            for outcome in check_outcomes(snapshot)
            if outcome.get("outcome") == "failed"
            or (outcome.get("coverage") or {}).get("complete") is True}


def _findings(snapshot: Optional[dict]) -> dict[str, dict]:
    """Findings by fingerprint. Old snapshots without one get it computed."""
    out: dict[str, dict] = {}
    for job in (snapshot or {}).get("jobs", []):
        for raw in job.get("findings", []):
            evidence = raw.get("evidence") or {}
            fp = evidence.get("fingerprint")
            if not fp:
                try:
                    severity = Severity(raw.get("severity", "info"))
                except ValueError:
                    severity = Severity.INFO
                fp = fingerprint_finding(Finding(
                    id=str(raw.get("id", "")), title=raw.get("title", ""),
                    severity=severity, category=raw.get("category", ""),
                    store=raw.get("store", ""), collection=raw.get("collection"),
                    evidence=evidence))
            out.setdefault(fp, raw)
    return out


def _label(check: str) -> str:
    try:
        from vecshield_platform.crypto.view import CHECK_LABELS
    except ImportError:
        CHECK_LABELS = {}
    return CHECK_LABELS.get(check) or check.replace("_", " ").capitalize()


def _summary(check: str, collection: Optional[str], change: str,
             before: Optional[dict], after: Optional[dict]) -> str:
    subject = _label(check) + (f" for '{collection}'" if collection else "")
    was = (before or {}).get("crypto_state")
    now = (after or {}).get("crypto_state")
    if change == "new":
        return f"{subject} was assessed for the first time: {now}"
    if change == "absent":
        return (f"{subject} was {was} and was not assessed in the newer audit "
                "(untested, not passed)")
    if was is None:
        return f"{subject} now records {now}"
    if now is None:
        return f"{subject} no longer records a crypto state (was {was})"
    return f"{subject} changed from {was} to {now}"


def _retested(finding: dict, retest_keys: set, known_checks: set[str]) -> bool:
    """Whether the newer audit conclusively re-ran a check able to report it.

    A category with no check of its own (``coverage``, ``access_control``...)
    has nothing to consult, so its disappearance is taken at face value. A
    store-level outcome (collection ``None``) covers every collection.
    """
    category = finding.get("category") or ""
    checks = _CATEGORY_CHECKS.get(category, (category,))
    if category not in _CATEGORY_CHECKS and category not in known_checks:
        return True
    collection = finding.get("collection")
    return any(check in checks and (collection is None or col in (collection, None))
               for check, col in retest_keys)


def diff_snapshots(before: Optional[dict], after: Optional[dict]) -> dict[str, Any]:
    """Compare two audit snapshots of one store. Pure; no I/O.

    ``before`` is the older snapshot and may be ``None`` (a first audit), in
    which case every check is ``new``. Raises ``ValueError`` when both
    snapshots name different registered stores.
    """
    b_store = (before or {}).get("store_id")
    a_store = (after or {}).get("store_id")
    if b_store and a_store and b_store != a_store:
        raise ValueError("snapshots belong to different stores")

    old, new = _keyed(before), _keyed(after)
    checks: list[dict[str, Any]] = []
    for key in sorted(old.keys() | new.keys(), key=lambda k: (k[0], k[1] or "")):
        was, now = old.get(key), new.get(key)
        if was is None:
            change = "new"
        elif now is None:
            change = "absent"
        else:
            change = "unchanged" if was == now else "changed"
        checks.append({"check": key[0], "collection": key[1], "change": change,
                       "before": was, "after": now})

    crypto_changes = []
    for entry in checks:
        was = (entry["before"] or {}).get("crypto_state")
        now = (entry["after"] or {}).get("crypto_state")
        if was == now:
            continue
        crypto_changes.append({**entry, "summary": _summary(
            entry["check"], entry["collection"], entry["change"],
            entry["before"], entry["after"])})

    old_findings, new_findings = _findings(before), _findings(after)
    gone = sorted(old_findings.keys() - new_findings.keys())
    known = _KNOWN_CHECKS | {check for check, _ in old.keys() | new.keys()}
    retest_keys = _retest_keys(after)
    resolved = [fp for fp in gone if _retested(old_findings[fp], retest_keys, known)]
    return {
        "before_audit_id": (before or {}).get("id"),
        "after_audit_id": (after or {}).get("id"),
        "checks": checks,
        "crypto_state_changes": crypto_changes,
        "findings": {
            "new": sorted(new_findings.keys() - old_findings.keys()),
            "resolved": resolved,
            "not_retested": sorted(set(gone) - set(resolved)),
            "persistent": len(old_findings.keys() & new_findings.keys()),
        },
        "note": NOTE,
    }


def latest_pair(history, store_id: str) -> tuple[Optional[dict], Optional[dict]]:
    """The previous and latest saved snapshots for ``store_id``, oldest first.

    Read-only. ``(None, latest)`` when the store has one audit; ``(None, None)``
    when it has none.
    """
    rows = history.list_audits(store_id=store_id, limit=2)
    snapshots = [history.get_audit(row["id"]) for row in rows]
    snapshots = [s for s in snapshots if s is not None]
    if not snapshots:
        return None, None
    if len(snapshots) == 1:
        return None, snapshots[0]
    return snapshots[1], snapshots[0]


_FINDING_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _finding_summary(fingerprint: str, raw: dict) -> dict[str, Any]:
    """What a person needs to recognise a finding. Never its evidence."""
    return {"fingerprint": fingerprint, "id": raw.get("id"),
            "title": raw.get("title") or "", "severity": raw.get("severity") or "info",
            "category": raw.get("category") or "", "collection": raw.get("collection")}


def finding_changes(before: Optional[dict], after: Optional[dict], *,
                    limit: int = 100) -> dict[str, Any]:
    """``diff_snapshots``' finding buckets, each fingerprint resolved to a summary.

    New findings are described from the newer snapshot; resolved and
    not-retested ones from the older one, the only place they still exist.
    Each list is ordered worst first and capped at ``limit``; ``*_total``
    keeps the true count. Pure; no I/O.
    """
    diff = diff_snapshots(before, after)
    old_findings, new_findings = _findings(before), _findings(after)

    def bucket(fingerprints: list[str], source: dict[str, dict]) -> list[dict[str, Any]]:
        entries = [_finding_summary(fp, source[fp]) for fp in fingerprints if fp in source]
        entries.sort(key=lambda e: (-_FINDING_SEVERITY_RANK.get(e["severity"], 0),
                                    e["title"], e["fingerprint"]))
        return entries

    findings = diff["findings"]
    buckets = {"new": bucket(findings["new"], new_findings),
               "resolved": bucket(findings["resolved"], old_findings),
               "not_retested": bucket(findings["not_retested"], old_findings)}
    out: dict[str, Any] = {"before_audit_id": diff["before_audit_id"],
                           "after_audit_id": diff["after_audit_id"],
                           "persistent": findings["persistent"], "note": NOTE}
    for name, entries in buckets.items():
        out[name] = entries[:limit]
        out[f"{name}_total"] = len(entries)
    return out


# --------------------------------------------------------------------------- #
# Inventory change tracking                                                   #
#                                                                             #
# ``diff_snapshots`` compares what the checks said. ``diff_inventories``      #
# compares what the store *is*: which collections exist, how large they are, #
# which model and metric built them, where aliases point, which server        #
# version answers and which region holds the data. Several of these changes  #
# are the whole story of an incident: a sensitive collection copied to        #
# "customers_backup", an alias silently repointed at a different corpus, a    #
# store moved to another region.                                              #
#                                                                             #
# The inventory an audit took is carried in the saved snapshot at             #
# ``snapshot["scope"]["inventory"]`` (AuditResult.scope is persisted whole by #
# History.save_audit and stripped from list_audits rows, so it costs listing  #
# nothing). ``latest_inventory_pair`` reads it from there.                    #
# --------------------------------------------------------------------------- #

#: Default count-jump threshold: a change larger than both this share of the
#: previous count and COUNT_JUMP_MIN vectors is reported.
COUNT_JUMP_RATIO = 0.5
COUNT_JUMP_MIN = 1000

#: Name fragments that suggest a collection is a copy of another.
_COPY_MARKERS = re.compile(
    r"(?:^|[_\-. ])(?:copy|tmp|temp|backup|bak|old|test|dev|staging|clone|dup)"
    r"(?:[_\-. ]|\d|$)"
    r"|[_\-.]v\d+$"
    r"|[_\-.]?(?:19|20)\d{2}[_\-.]?\d{2}(?:[_\-.]?\d{2})?$",
    re.IGNORECASE)

_SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1, "info": 0}


def _collections_by_name(inventory: Optional[dict]) -> dict[str, dict]:
    return {str(c.get("name")): c for c in (inventory or {}).get("collections") or []
            if c.get("name") is not None}


def _base_name(name: str) -> str:
    stripped = _COPY_MARKERS.sub("", name)
    return stripped.strip("_-. ") or name


def looks_like_copy(name: str) -> bool:
    """True when a collection name carries a copy/backup/test/date marker."""
    return bool(_COPY_MARKERS.search(name))


def _closest(name: str, others: list[str]) -> Optional[str]:
    base = _base_name(name).lower()
    best, score = None, 0.0
    for other in sorted(others):
        if other == name:
            continue
        ratio = difflib.SequenceMatcher(None, base, other.lower()).ratio()
        if ratio > score:
            best, score = other, ratio
    return best if score >= 0.6 else None


def _event(kind: str, severity: str, summary: str, **details: Any) -> dict[str, Any]:
    return {"kind": kind, "severity": severity, "summary": summary, **details}


def diff_inventories(before: Optional[dict], after: Optional[dict], *,
                     count_jump_ratio: float = COUNT_JUMP_RATIO,
                     count_jump_min: int = COUNT_JUMP_MIN) -> dict[str, Any]:
    """What changed in a store between two inventories. Pure; no I/O.

    ``before`` may be ``None`` (a first inventory): every collection is then
    ``added`` and copy-like names are still reported, since a first scan can
    find a shadow copy too. Raises ``ValueError`` when both inventories name
    different stores. Every change is also listed in ``events`` with a
    severity, for display; the typed lists carry the details.
    """
    b_store = ((before or {}).get("store") or {}).get("id")
    a_store = ((after or {}).get("store") or {}).get("id")
    if b_store and a_store and b_store != a_store:
        raise ValueError("inventories belong to different stores")

    old, new = _collections_by_name(before), _collections_by_name(after)
    added = sorted(new.keys() - old.keys())
    removed = sorted(old.keys() - new.keys())
    events: list[dict[str, Any]] = []
    for name in added:
        events.append(_event("collection_added", "info",
                             f"Collection '{name}' is new.", collection=name))
    for name in removed:
        events.append(_event("collection_removed", "info",
                             f"Collection '{name}' is no longer present.", collection=name))

    shadow: list[dict[str, Any]] = []
    for name in (added if before is not None else sorted(new)):
        if not looks_like_copy(name):
            continue
        categories = sorted((new[name].get("sensitive_categories") or {}).keys())
        original = _closest(name, list(new) + list(old))
        severity = "high" if categories else "low"
        entry: dict[str, Any] = {"collection": name, "possible_copy_of": original,
                 "sensitive_categories": categories, "severity": severity}
        shadow.append(entry)
        target = f" of '{original}'" if original else ""
        held = f", holding {', '.join(categories)}" if categories else ""
        events.append(_event(
            "possible_shadow_copy", severity,
            f"'{name}' looks like a copy{target}{held}. Copies are easy to miss "
            "in erasure, retention and access reviews.",
            **{k: v for k, v in entry.items() if k != "severity"}))

    count_jumps: list[dict[str, Any]] = []
    re_embedding: list[dict[str, Any]] = []
    new_sensitive: list[dict[str, Any]] = []
    for name in sorted(old.keys() & new.keys()):
        was, now = old[name], new[name]
        b_count, a_count = int(was.get("count") or 0), int(now.get("count") or 0)
        delta = a_count - b_count
        if abs(delta) > max(count_jump_ratio * b_count, count_jump_min):
            entry = {"collection": name, "before": b_count, "after": a_count,
                     "delta": delta}
            count_jumps.append(entry)
            direction = "grew" if delta > 0 else "shrank"
            events.append(_event("count_jump", "medium",
                                 f"'{name}' {direction} from {b_count} to {a_count} vectors.",
                                 **entry))
        changed = {key: {"before": was.get(key), "after": now.get(key)}
                   for key in ("dimension", "embedding_model", "distance_metric")
                   if was.get(key) != now.get(key)}
        if changed:
            entry = {"collection": name, "changes": changed}
            re_embedding.append(entry)
            events.append(_event(
                "re_embedding", "medium",
                f"'{name}' changed {', '.join(sorted(changed))}: the collection was "
                "re-embedded or rebuilt. Vectors written before the change may "
                "remain, and erasure evidence from before it may not cover them.",
                **entry))
        b_cats = set((was.get("sensitive_categories") or {}).keys())
        a_cats = set((now.get("sensitive_categories") or {}).keys())
        appeared = sorted(a_cats - b_cats)
        if appeared and was.get("classified", True):
            entry = {"collection": name, "categories": appeared}
            new_sensitive.append(entry)
            events.append(_event("new_sensitive_category", "high",
                                 f"'{name}' now holds {', '.join(appeared)}.", **entry))

    b_info = (before or {}).get("store") or {}
    a_info = (after or {}).get("store") or {}
    alias_changes: dict[str, list[dict[str, Any]]] = {"repointed": [], "added": [],
                                                      "removed": []}
    if before is not None and b_info.get("aliases_observed") and a_info.get("aliases_observed"):
        b_alias, a_alias = b_info.get("aliases") or {}, a_info.get("aliases") or {}
        for alias in sorted(b_alias.keys() & a_alias.keys()):
            if b_alias[alias] != a_alias[alias]:
                entry = {"alias": alias, "before": b_alias[alias], "after": a_alias[alias]}
                alias_changes["repointed"].append(entry)
                events.append(_event(
                    "alias_repointed", "high",
                    f"Alias '{alias}' now points at '{a_alias[alias]}' instead of "
                    f"'{b_alias[alias]}'. Applications querying the alias now "
                    "retrieve from a different corpus.", **entry))
        for alias in sorted(a_alias.keys() - b_alias.keys()):
            alias_changes["added"].append({"alias": alias, "after": a_alias[alias]})
            events.append(_event("alias_added", "low",
                                 f"Alias '{alias}' was added.", alias=alias))
        for alias in sorted(b_alias.keys() - a_alias.keys()):
            alias_changes["removed"].append({"alias": alias, "before": b_alias[alias]})
            events.append(_event("alias_removed", "low",
                                 f"Alias '{alias}' was removed.", alias=alias))

    server = None
    if before is not None and b_info.get("server_observed") and a_info.get("server_observed"):
        fields = ("product", "version", "edition")
        if any(b_info.get(f) != a_info.get(f) for f in fields):
            server = {f: {"before": b_info.get(f), "after": a_info.get(f)} for f in fields}
            events.append(_event(
                "server_version_changed", "low",
                f"Server changed from {b_info.get('product')} {b_info.get('version')} "
                f"to {a_info.get('product')} {a_info.get('version')}.", changes=server))

    location = None
    if before is not None and b_info.get("location_observed") and a_info.get("location_observed"):
        fields = ("provider", "region", "replica_regions")
        if any(b_info.get(f) != a_info.get(f) for f in fields):
            location = {f: {"before": b_info.get(f), "after": a_info.get(f)} for f in fields}
            events.append(_event(
                "location_changed", "high",
                f"Data location changed from {b_info.get('provider')}/"
                f"{b_info.get('region')} to {a_info.get('provider')}/"
                f"{a_info.get('region')}. Check data-residency commitments and "
                "transfer mechanisms.", changes=location))

    events.sort(key=lambda e: (-_SEVERITY_ORDER.get(e["severity"], 0), e["kind"],
                               str(e.get("collection") or e.get("alias") or "")))
    b_hash, a_hash = (before or {}).get("inventory_hash"), (after or {}).get("inventory_hash")
    return {
        "baseline": before is None,
        "before_hash": b_hash,
        "after_hash": a_hash,
        "unchanged": bool(b_hash and b_hash == a_hash),
        "collections": {"added": added, "removed": removed},
        "possible_shadow_copies": shadow,
        "count_jumps": count_jumps,
        "re_embedding": re_embedding,
        "new_sensitive_categories": new_sensitive,
        "aliases": alias_changes,
        "server": server,
        "location": location,
        "integrity_relevant": bool(alias_changes["repointed"] or re_embedding),
        "events": events,
        "thresholds": {"count_jump_ratio": count_jump_ratio,
                       "count_jump_min": count_jump_min},
        "note": ("Aliases, server version and location are compared only when "
                 "both inventories observed them; an unobserved fact is not a change."),
    }


def inventory_of(snapshot: Optional[dict]) -> Optional[dict]:
    """The inventory a saved audit carried, or None."""
    inventory = ((snapshot or {}).get("scope") or {}).get("inventory")
    return inventory if isinstance(inventory, dict) else None


def latest_inventory_pair(history, store_id: str, *,
                          search_limit: int = 20) -> tuple[Optional[dict], Optional[dict]]:
    """The previous and latest *inventories* for ``store_id``, oldest first.

    Mirrors ``latest_pair`` but skips audits that carried no inventory (older
    audits, or ones where describe() failed), looking back at most
    ``search_limit`` audits. ``(None, latest)`` with one; ``(None, None)``
    with none.
    """
    found: list[dict] = []
    for row in history.list_audits(store_id=store_id, limit=search_limit):
        inventory = inventory_of(history.get_audit(row["id"]))
        if inventory is not None:
            found.append(inventory)
            if len(found) == 2:
                break
    if not found:
        return None, None
    if len(found) == 1:
        return None, found[0]
    return found[1], found[0]
