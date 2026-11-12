"""The Crypto Posture read model: one saved audit, laid out by control layer.

Everything here is assembled from a frozen audit snapshot
(``AuditResult.to_dict()``). Nothing connects to a store or scans, so the page a
reviewer opens always describes observations they can trace back to a saved
audit.

Three rules shape the output:

- Layers stay separate. Transport, storage, field/data-level and retrieval rows
  are never collapsed into one encryption verdict, and a layer is never
  dropped: a check the audit did not run is shown as a row saying so.
- Coverage is counts, never a percentage or a score. "38 verified, 4 unknown"
  must not be readable as complete.
- Regulatory rows carry only the criteria engine's *technical* reduction.
  Applicability answers and evidence are not known here, so a criterion status
  would be a claim this view cannot support.
"""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
from typing import Any, Optional

from vecshield_platform.crypto.states import (
    AT_REST_ENCRYPTION,
    CONTROL_IDS,
    CRYPTO_CHECKS,
    DATA_REPRESENTATION,
    DIRECT_IDENTIFIER_EXPOSURE,
    FIELD_ENCRYPTION,
    LAYERS,
    NOT_OBSERVABLE,
    NOT_VERIFIED,
    OBSERVED_EXPOSURE,
    PAN_REPRESENTATION,
    RETRIEVAL_EXPOSURE,
    TLS_ENFORCEMENT,
    TRANSPORT_ENCRYPTION,
    VERIFIED,
)

LAYER_TITLES = {
    "transport": "Transport",
    "storage": "Storage encryption",
    "data": "Field and data-level protection",
    "retrieval": "Retrieval exposure",
}

CHECK_LABELS = {
    TRANSPORT_ENCRYPTION: "TLS on VecShield's connection",
    TLS_ENFORCEMENT: "Plaintext connections refused",
    AT_REST_ENCRYPTION: "Database-native encryption at rest",
    FIELD_ENCRYPTION: "Field-level encryption",
    DATA_REPRESENTATION: "Sensitive data representation",
    PAN_REPRESENTATION: "PAN storage representation",
    DIRECT_IDENTIFIER_EXPOSURE: "Direct identifiers beside pseudonymous ones",
    RETRIEVAL_EXPOSURE: "Retrieval-time plaintext exposure",
}

#: The run-level check whose outcome explains a crypto check's absence. When
#: posture was excluded, or the classification pass errored, the crypto checks
#: it carries were never recorded; saying "predates the check" would be wrong.
_PARENT_CHECK = {
    TRANSPORT_ENCRYPTION: "configuration_posture",
    TLS_ENFORCEMENT: "configuration_posture",
    AT_REST_ENCRYPTION: "configuration_posture",
    FIELD_ENCRYPTION: "configuration_posture",
    DATA_REPRESENTATION: "data_classification",
    PAN_REPRESENTATION: "data_classification",
    DIRECT_IDENTIFIER_EXPOSURE: "data_classification",
}

#: Scope flags that, when False, mean the parent check was switched off.
_PARENT_SCOPE_FLAG = {"configuration_posture": "include_posture"}

PREDATES_REASON = "This audit predates the check."

#: Outcomes recorded before crypto_state existed (e.g. transport_encryption
#: from earlier posture engines) still get a state, read conservatively.
_STATE_FOR_OUTCOME = {
    "passed": VERIFIED,
    "failed": OBSERVED_EXPOSURE,
    "inconclusive": NOT_VERIFIED,
    "unsupported": NOT_OBSERVABLE,
    "skipped": NOT_VERIFIED,
    "error": NOT_VERIFIED,
}

#: Coverage keys that the row already carries at top level, or that restate a
#: completeness flag the crypto state expresses more precisely.
_ROW_KEYS_NOT_DETAILS = {"status", "complete", "crypto_state", "control"}

OUT_OF_SCOPE = (
    {"property": "Infrastructure disk / volume encryption",
     "state": "not_observable",
     "reason": "EBS, LUKS and other volume encryption sit below the database "
               "interface the connector uses; the database does not report them."},
    {"property": "Cloud KMS / Key Vault configuration",
     "state": "outside_connector_scope",
     "reason": "Key management services are cloud control-plane resources. "
               "VecShield reads only what the vector database itself exposes."},
    {"property": "Cloud IAM and snapshot settings",
     "state": "outside_connector_scope",
     "reason": "Identity policies and backup or snapshot encryption are "
               "configured in the cloud account, not visible through the "
               "database connection."},
)

STATEMENTS = (
    "Embeddings are not treated as cryptographic protection.",
    "Readable through the database is not the same as unencrypted on disk.",
    "Not observable is not a failure: supply manual evidence where a criterion "
    "asks for it.",
)

NOTE = "No crypto score. Counts describe what the connector could observe."


# ---- rows -----------------------------------------------------------------

def _row(outcome: dict[str, Any]) -> dict[str, Any]:
    check = outcome.get("check", "")
    coverage = outcome.get("coverage") or {}
    state = coverage.get("crypto_state") or _STATE_FOR_OUTCOME.get(
        outcome.get("outcome", ""), NOT_VERIFIED)
    return {
        "check": check,
        "control": coverage.get("control") or CONTROL_IDS.get(check, ""),
        "label": CHECK_LABELS.get(check, check),
        "collection": outcome.get("collection"),
        "outcome": outcome.get("outcome"),
        "crypto_state": state,
        "reason": outcome.get("reason", ""),
        "details": {k: deepcopy(v) for k, v in coverage.items()
                    if k not in _ROW_KEYS_NOT_DETAILS},
    }


def _absent_row(check: str, outcomes: list[dict[str, Any]],
                scope: dict[str, Any]) -> dict[str, Any]:
    """A row for a check the snapshot holds no outcome for.

    If the run switched off, skipped or errored the pass that carries the
    check, the row says so with that pass's reason. Otherwise the audit was
    saved before the check existed.
    """
    outcome, reason = "not_run", PREDATES_REASON
    parent = _PARENT_CHECK.get(check)
    flag = _PARENT_SCOPE_FLAG.get(parent or "")
    parent_outcome = next(
        (o for o in outcomes if o.get("check") == parent
         and o.get("outcome") in ("skipped", "error", "unsupported")), None)
    if parent_outcome is not None:
        outcome = parent_outcome["outcome"]
        detail = parent_outcome.get("reason") or ""
        reason = ("Not included in this run" + (f": {detail}" if detail else "."))
    elif flag and scope.get(flag) is False:
        outcome = "skipped"
        reason = "Not included in this run: excluded by the run configuration."
    return {"check": check, "control": CONTROL_IDS.get(check, ""),
            "label": CHECK_LABELS.get(check, check), "collection": None,
            "outcome": outcome, "crypto_state": NOT_VERIFIED, "reason": reason,
            "details": {}}


def _layers(outcomes: list[dict[str, Any]],
            scope: dict[str, Any]) -> list[dict[str, Any]]:
    by_check: dict[str, list[dict[str, Any]]] = {}
    for outcome in outcomes:
        if outcome.get("check") in CRYPTO_CHECKS:
            by_check.setdefault(outcome["check"], []).append(outcome)
    layers = []
    for layer, checks in LAYERS.items():
        rows: list[dict[str, Any]] = []
        for check in checks:
            recorded = sorted(by_check.get(check, []),
                              key=lambda o: (o.get("collection") is not None,
                                             o.get("collection") or ""))
            if recorded:
                rows.extend(_row(o) for o in recorded)
            else:
                rows.append(_absent_row(check, outcomes, scope))
        layers.append({"layer": layer, "title": LAYER_TITLES[layer], "rows": rows})
    return layers


# ---- coverage -------------------------------------------------------------

def _collections_total(snapshot: dict[str, Any],
                       outcomes: list[dict[str, Any]]) -> int:
    listed = (snapshot.get("scope") or {}).get("collections")
    if isinstance(listed, list):
        return len(listed)
    return len({o.get("collection") for o in outcomes if o.get("collection")})


def _at_rest_counts(outcomes: list[dict[str, Any]], total: int) -> dict[str, int]:
    """Sum the at-rest rollup; collections nobody reported on stay unknown.

    No outcome, or one without a per-collection rollup (the store's interface
    exposed nothing), means every collection is unknown — not unencrypted and
    not encrypted.
    """
    counts = {"verified_encrypted": 0, "verified_unencrypted": 0, "unknown": 0,
              "not_supported": 0}
    reported = False
    for outcome in outcomes:
        if outcome.get("check") != AT_REST_ENCRYPTION:
            continue
        coverage = outcome.get("coverage") or {}
        if coverage.get("support") == "not_supported" or (
                coverage.get("capability_limit") is True
                and outcome.get("outcome") == "unsupported"):
            # The database has no interface for this at all. Counted apart from
            # "unknown", which means this run could not establish it.
            counts["not_supported"] = total
            reported = True
            continue
        rollup = coverage.get("collections")
        if not isinstance(rollup, dict):
            continue
        reported = True
        for key in counts:
            counts[key] += int(rollup.get(key) or 0)
    if not reported:
        counts["unknown"] = total
    return counts


def _check_counts(layers: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    counts: dict[str, Counter] = {check: Counter() for check in CRYPTO_CHECKS}
    for layer in layers:
        for row in layer["rows"]:
            counts[row["check"]][row["outcome"]] += 1
    return {check: dict(sorted(c.items())) for check, c in counts.items()}


# ---- coverage statement -----------------------------------------------------
#
# What the audit established, per layer, in the reader's words: observed
# (verified, or an exposure seen), only declared (configuration or vendor
# documentation, never observed), unknown or not observable, and not checked.
# Counts are rows (one check, one collection); nothing is a share or a score.

#: Buckets, worst first. A layer's headline is the first bucket it has, so a
#: layer reads "verified" only when every row is verified or not applicable.
COVERAGE_BUCKETS = ("exposure", "unknown", "not_checked", "not_observable",
                    "declared", "verified", "not_applicable")

COVERAGE_PHRASES = {
    "exposure": "exposure observed",
    "unknown": "could not be established",
    "not_checked": "not checked",
    "not_observable": "not observable",
    "declared": "declared, not verified",
    "verified": "verified",
    "not_applicable": "not applicable",
}

#: How each bucket was reached: observed by the connector, stated by
#: configuration or documentation, or neither.
COVERAGE_BASIS = {
    "exposure": "observed", "verified": "observed", "not_applicable": "observed",
    "declared": "declared", "unknown": "unknown", "not_observable": "unknown",
    "not_checked": "not_checked",
}

_STATEMENT_TITLES = {
    "transport": "Transport",
    "storage": "At rest",
    "data": "Field and data",
    "retrieval": "Retrieval",
}


def _declared(details: dict[str, Any]) -> bool:
    """Configuration or vendor documentation says something the run did not see."""
    documented = details.get("documented_default")
    return bool((isinstance(documented, dict) and documented.get("text"))
                or details.get("config_source") or details.get("sslmode"))


def coverage_bucket(row: dict[str, Any]) -> str:
    """The coverage bucket for one read-model row."""
    if row.get("outcome") in ("skipped", "not_run"):
        return "not_checked"
    state = row.get("crypto_state")
    if state in (VERIFIED, "protected_representation"):
        return "verified"
    if state == OBSERVED_EXPOSURE:
        return "exposure"
    if state == "not_applicable":
        return "not_applicable"
    details = row.get("details") or {}
    if _declared(details):
        return "declared"
    return "not_observable" if state == NOT_OBSERVABLE else "unknown"


def _not_checked_why(rows: list[dict[str, Any]]) -> str:
    details = [r.get("details") or {} for r in rows]
    reasons = [str(r.get("reason") or "") for r in rows]
    if details and all(d.get("opt_in") for d in details):
        return "opt-in probe not requested"
    if reasons and all(text == PREDATES_REASON for text in reasons):
        return "the audit predates the check"
    if reasons and all(text.startswith("Not included in this run") for text in reasons):
        return "excluded from this run"
    return ""


def _layer_statement(layer: dict[str, Any]) -> dict[str, Any]:
    rows = layer.get("rows") or []
    buckets = [coverage_bucket(row) for row in rows]
    counts = {name: buckets.count(name) for name in COVERAGE_BUCKETS}
    present = [name for name in COVERAGE_BUCKETS if counts[name]]
    headline = present[0] if present else "not_checked"
    databases = sorted({str((row.get("details") or {}).get("database"))
                        for row, bucket in zip(rows, buckets)
                        if bucket == "not_observable"
                        and (row.get("details") or {}).get("database")})
    title = _STATEMENT_TITLES.get(layer.get("layer", ""), layer.get("title", ""))

    def phrase(name: str) -> str:
        text = COVERAGE_PHRASES[name]
        if name == "not_observable" and databases:
            text += f" for {', '.join(databases)}"
        if name == "not_checked":
            why = _not_checked_why([r for r, b in zip(rows, buckets) if b == name])
            text += f" ({why})" if why else ""
        return text

    if not rows:
        text = f"{title}: nothing recorded"
    elif len(present) == 1:
        text = f"{title}: {phrase(headline)}"
    else:
        text = f"{title}: " + ", ".join(f"{counts[name]} {phrase(name)}" for name in present)
    exposed = sorted({str(row.get("collection")) for row, bucket in zip(rows, buckets)
                      if bucket == "exposure" and row.get("collection")})
    return {"layer": layer.get("layer"), "title": title, "headline": headline,
            "basis": COVERAGE_BASIS[headline] if rows else "not_checked",
            "rows": len(rows), "counts": counts, "text": text,
            "collections_with_exposure": exposed, "databases_not_observable": databases}


def coverage_statement(layers: list[dict[str, Any]],
                       out_of_scope: Optional[list[dict[str, Any]]] = None) -> dict[str, Any]:
    """Per-layer and total counts of what was observed, declared, unknown and unchecked."""
    statements = [_layer_statement(layer) for layer in layers]
    totals = {name: sum(s["counts"][name] for s in statements) for name in COVERAGE_BUCKETS}
    by_basis = {basis: sum(n for name, n in totals.items() if COVERAGE_BASIS[name] == basis)
                for basis in ("observed", "declared", "unknown", "not_checked")}
    outside = list(OUT_OF_SCOPE if out_of_scope is None else out_of_scope)
    return {
        "layers": statements,
        "totals": totals,
        "by_basis": by_basis,
        "rows": sum(s["rows"] for s in statements),
        "outside_connector": [item.get("property") for item in outside],
        "text": " · ".join(s["text"] for s in statements),
        "note": ("Counts are rows: one check on one collection, or on the store. "
                 "Only verified rows were observed to be protected; declared, "
                 "unknown and unchecked rows are not evidence of protection."),
    }


def crypto_coverage(snapshot: dict[str, Any]) -> dict[str, Any]:
    """The coverage statement alone, for estate views that list many stores."""
    outcomes = list(snapshot.get("check_outcomes") or [])
    return coverage_statement(_layers(outcomes, snapshot.get("scope") or {}))


# ---- drift ----------------------------------------------------------------

def _state(value: Any) -> Optional[dict[str, Any]]:
    if not isinstance(value, dict):
        return None
    return {"outcome": value.get("outcome"),
            "crypto_state": value.get("crypto_state")
            or (value.get("coverage") or {}).get("crypto_state")}


def _drift(previous: Optional[dict[str, Any]],
           snapshot: dict[str, Any]) -> dict[str, Any]:
    """Crypto checks whose outcome or state changed since the previous audit.

    ``compared`` distinguishes "nothing changed" from "nothing to compare
    against": an empty change list alone must not read as stability.
    """
    if previous is None:
        return {"previous_audit_id": None, "compared": False, "changes": []}
    try:
        from vecshield_platform.drift import diff_snapshots
    except ImportError:
        return {"previous_audit_id": previous.get("id"), "compared": False,
                "changes": [],
                "reason": "Snapshot comparison is not available in this build."}

    diff = diff_snapshots(previous, snapshot)
    changes = []
    for entry in diff.get("checks", []):
        if entry.get("check") not in CRYPTO_CHECKS:
            continue
        before, after = _state(entry.get("before")), _state(entry.get("after"))
        if before == after:
            continue
        changes.append({"check": entry["check"],
                        "label": CHECK_LABELS.get(entry["check"], entry["check"]),
                        "collection": entry.get("collection"),
                        "change": entry.get("change"),
                        "before": before, "after": after})
    changes.sort(key=lambda c: (CRYPTO_CHECKS.index(c["check"]),
                                c["collection"] or ""))
    return {"previous_audit_id": previous.get("id"), "compared": True,
            "changes": changes}


# ---- regulatory -----------------------------------------------------------

def _regulatory(outcomes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Each framework's relationship, with its criteria's technical reduction.

    Only ``technical_result``, ``technical_coverage`` and ``fallback_required``
    are reported. They depend on the audit alone; a criterion *status* also
    depends on applicability answers and evidence this view does not hold.
    """
    from vecshield_platform.compliance.criteria import evaluate_criterion
    from vecshield_platform.compliance.crypto_basis import CRYPTO_BASIS
    from vecshield_platform.compliance.packs import get_criterion

    rows = []
    for basis in CRYPTO_BASIS:
        row = basis.to_dict()
        criteria = []
        for criterion_id in basis.criteria:
            criterion = get_criterion(criterion_id)
            if criterion is None:
                criteria.append({"criterion_id": criterion_id,
                                 "technical_result": "not_run",
                                 "technical_coverage": "unknown",
                                 "fallback_required": [], "checks": [],
                                 "reason": "Criterion is not in the current pack."})
                continue
            assessment = evaluate_criterion(criterion, check_outcomes=outcomes)
            criteria.append({"criterion_id": criterion.id,
                             "technical_result": assessment.technical_result,
                             "technical_coverage": assessment.technical_coverage,
                             "fallback_required": list(assessment.fallback_required),
                             "checks": list(criterion.technical_checks)})
        row["criteria"] = criteria
        rows.append(row)
    return rows


# ---- entry point ----------------------------------------------------------

def build_crypto_posture(snapshot: dict[str, Any], *, store_id: str,
                         previous: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """Assemble the Crypto Posture read model from a saved audit snapshot.

    Pure: reads ``snapshot`` (and ``previous`` for drift) and nothing else.
    """
    from vecshield_platform.compliance.criteria import PACK_VERSION

    outcomes = list(snapshot.get("check_outcomes") or [])
    scope = snapshot.get("scope") or {}
    layers = _layers(outcomes, scope)
    total = _collections_total(snapshot, outcomes)
    return {
        "store_id": store_id,
        "audit_id": snapshot.get("id"),
        "assessed_at": snapshot.get("finished_at") or snapshot.get("started_at"),
        "pack_version": PACK_VERSION,
        "layers": layers,
        "coverage": {"collections_total": total,
                     "at_rest": _at_rest_counts(outcomes, total),
                     "checks": _check_counts(layers),
                     "statement": coverage_statement(layers)},
        "out_of_scope": [dict(item) for item in OUT_OF_SCOPE],
        "statements": list(STATEMENTS),
        "drift": _drift(previous, snapshot),
        "regulatory": _regulatory(outcomes),
        "note": NOTE,
    }
