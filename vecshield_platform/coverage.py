"""Serializable coverage and check outcomes, independent of finding severity.

These records live in ScanJob.stats so the `vecshield` ScanJob contract remains
unchanged. Missing coverage from older jobs is unknown, never an implicit pass.
"""

from __future__ import annotations

from collections import Counter
from copy import deepcopy


OUTCOMES = ("passed", "failed", "inconclusive", "error", "unsupported", "skipped")


def check_outcome(check: str, store: str, collection: str | None = None, *,
                  outcome: str, reason: str = "", complete: bool = False,
                  **coverage) -> dict:
    if outcome not in OUTCOMES:
        raise ValueError(f"Unknown check outcome: {outcome}")
    return {
        "check": check,
        "store": store,
        "collection": collection,
        "outcome": outcome,
        "reason": reason,
        "coverage": {"status": "complete" if complete else "partial",
                     "complete": complete, **coverage},
    }


#: Why a read cannot be shown complete when the store gave no count.
COUNT_UNKNOWN_REASON = ("The inventory count could not be read, so whether "
                        "enumeration reached every chunk could not be verified.")


def count_known(col) -> bool:
    """Whether a collection's inventory count was actually read.

    A connector that cannot count reports ``count=0`` with
    ``metadata["count_known"] = False``. Zero is then not a count, and a
    cross-check against it would pass any read, including an empty one.
    """
    metadata = getattr(col, "metadata", None) or {}
    return metadata.get("count_known", True) is not False


def read_errors_for(errors: list[dict], collection: str | None) -> list[dict]:
    """The read errors that affect one collection.

    An entry naming the collection affects it; an entry naming none is
    store-wide and affects every collection.
    """
    return [e for e in errors
            if not isinstance(e, dict) or e.get("collection") in (None, collection)]


def not_requested(item: dict) -> bool:
    """An opt-in active check the run did not ask for.

    It is still recorded, so criteria that rely on it see it as skipped and ask
    for evidence instead. But a run is not partial because an active probe
    nobody requested did not run.
    """
    return item.get("outcome") == "skipped" and item.get("coverage", {}).get("opt_in") is True


def capability_limited(item: dict) -> bool:
    """A property the database itself offers no way to report.

    Qdrant, for one, has no encryption-at-rest setting in its API at all. That
    is a fact about the product, recorded with its reason and the evidence to
    supply instead, and criteria still ask for that evidence. It is not a
    shortfall of this run, so it does not make the run partial.
    """
    return (item.get("outcome") == "unsupported"
            and item.get("coverage", {}).get("capability_limit") is True)


def read_shortfall(item: dict) -> bool:
    """Whether a check failed or left part of what it set out to read unread.

    Narrower than incomplete coverage. A check can read everything and still be
    inconclusive by its nature: too few vectors to score, NLP turned off, no
    tenant field configured, the CVE database not consulted. Those leave the
    run partial, but the store was read. A shortfall is an error, a chunk limit
    reached, fewer chunks read than the store counts, or items the connector
    could not read (rows that row-level security hid among them). A count the
    store could not produce is not by itself a shortfall: there is no count
    the read fell short of.
    """
    if item.get("outcome") == "error":
        return True
    cov = item.get("coverage") or {}
    if (cov.get("limit_reached") or cov.get("enumeration_capped")
            or cov.get("content_read_errors")):
        return True
    if cov.get("short_read") and cov["short_read"] != COUNT_UNKNOWN_REASON:
        return True
    scanned, expected = cov.get("chunks_scanned"), cov.get("chunks_expected")
    return isinstance(scanned, int) and isinstance(expected, int) and expected > scanned


def job_read_shortfalls(job) -> list[dict]:
    """The outcomes of one job that are read shortfalls.

    A job can record read errors once for all its checks (the integrity scan
    does), so each of its outcomes then counts as one.
    """
    job_errors = (job.stats.get("coverage") or {}).get("content_read_errors")
    return [o for o in job_outcomes(job) if job_errors or read_shortfall(o)]


def summarize_coverage(outcomes: list[dict]) -> dict:
    counts = Counter(item["outcome"] for item in outcomes)
    requested = [item for item in outcomes
                 if not not_requested(item) and not capability_limited(item)]
    complete = bool(requested) and all(
        item.get("coverage", {}).get("complete") is True for item in requested)
    observed = any(item.get("coverage", {}).get("complete") or
                   item.get("coverage", {}).get("chunks_scanned", 0)
                   for item in outcomes)
    status = "complete" if complete else ("partial" if observed else "unavailable")
    if not outcomes or any(item.get("coverage", {}).get("status") == "unknown"
                           for item in outcomes):
        status = "unknown" if not observed else "partial"
    return {
        "status": status,
        "complete": complete,
        "checks_expected": len(requested),
        "checks_complete": sum(item.get("coverage", {}).get("complete") is True
                               for item in requested),
        "checks_not_requested": sum(not_requested(item) for item in outcomes),
        "checks_not_supported": sum(capability_limited(item) for item in outcomes),
        "outcomes": {name: counts[name] for name in OUTCOMES},
    }


def set_job_coverage(job, outcomes: list[dict], **details) -> None:
    job.stats["check_outcomes"] = outcomes
    job.stats["coverage"] = {**summarize_coverage(outcomes), **details}


LEGACY_REASON = "This scan did not record structured coverage."

#: Posture sub-checks an earlier engine listed in ``stats["checks"]``, with the
#: finding categories that report on each and a plain label.
_POSTURE_CHECKS = {
    "network_exposure": (("network_exposure",), "network exposure"),
    "transport_encryption": (("transport_encryption",), "transport encryption"),
    "authentication": (("authentication",), "authentication"),
    "cve": (("cve",), "known CVE"),
}

_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def reconstruct_posture_outcomes(stats: dict, findings: list[dict],
                                 store: str) -> list[dict] | None:
    """Per-check outcomes for a posture job saved before outcomes were recorded.

    An earlier posture engine saved the list of checks it ran and their
    findings, but no outcome per check. What those findings establish is
    reconstructed, and nothing more: a high or critical finding is a failure
    that run observed; anything else is inconclusive, because whether the check
    completed was never recorded. Nothing is reconstructed as passed. The
    stored snapshot is not changed.
    """
    if stats.get("check") != "configuration_posture" or not stats.get("checks"):
        return None
    outcomes = []
    for check in stats["checks"]:
        categories, label = _POSTURE_CHECKS.get(check, ((check,), check.replace("_", " ")))
        relevant = [f for f in findings if f.get("category") in categories]
        worst = max((_RANK.get(str(f.get("severity")), 0) for f in relevant), default=-1)
        if worst >= _RANK["high"]:
            outcome = "failed"
            reason = (f"This audit recorded a {label} failure. It predates structured "
                      "coverage, so the outcome is rebuilt from its findings.")
        elif worst >= _RANK["medium"]:
            outcome = "inconclusive"
            reason = (f"This audit recorded that {label} could not be settled. It "
                      "predates structured coverage; re-run it for a full result.")
        else:
            outcome = "inconclusive"
            reason = (f"No {label} failure was recorded, but this audit predates "
                      "structured coverage, so whether the check completed is "
                      "unknown. Re-run it for a full result.")
        outcomes.append(check_outcome(check, store, None, outcome=outcome,
                                      reason=reason, complete=False,
                                      reconstructed=True))
    return outcomes


def job_outcomes(job) -> list[dict]:
    if "check_outcomes" in job.stats:
        return deepcopy(job.stats["check_outcomes"])
    rebuilt = reconstruct_posture_outcomes(
        job.stats, [f.to_dict() for f in job.findings], job.store)
    if rebuilt is not None:
        return rebuilt
    return [check_outcome(
        job.stats.get("check", "legacy_scan"), job.store,
        job.stats.get("collection"), outcome="inconclusive",
        reason=LEGACY_REASON, status="unknown")]


def upgrade_legacy_snapshot(snapshot: dict) -> dict:
    """Read a saved audit with legacy posture outcomes rebuilt per check.

    Returns a new dict; the stored snapshot is immutable and is not touched.
    Each rebuilt outcome carries ``coverage.reconstructed``, the coverage
    summary is recomputed from them, and the summary as recorded is kept
    beside it under ``coverage_as_recorded``.
    """
    outcomes = list(snapshot.get("check_outcomes") or [])
    if not any(o.get("reason") == LEGACY_REASON for o in outcomes):
        return snapshot
    changed = 0
    for job in snapshot.get("jobs") or []:
        stats = job.get("stats") or {}
        if "check_outcomes" in stats:
            continue
        rebuilt = reconstruct_posture_outcomes(stats, job.get("findings") or [],
                                               job.get("store", ""))
        if rebuilt is None:
            continue
        legacy = next((o for o in outcomes if o.get("reason") == LEGACY_REASON
                       and o.get("check") == stats.get("check")
                       and o.get("store") == job.get("store")), None)
        if legacy is None:
            continue
        outcomes.remove(legacy)
        outcomes.extend(rebuilt)
        changed += 1
    if not changed:
        return snapshot
    upgraded = dict(snapshot)
    upgraded["check_outcomes"] = outcomes
    upgraded["coverage_as_recorded"] = snapshot.get("coverage")
    upgraded["coverage"] = summarize_coverage(outcomes)
    upgraded["reconstructed_jobs"] = changed
    return upgraded
