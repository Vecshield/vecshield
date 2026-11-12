"""Encryption at rest (VCR-11/13) and field-level encryption (VCR-10) at the data plane.

The connector reports what its store exposes (``at_rest_encryption_state``,
``field_encryption_config``); this module turns those observations into check
outcomes and findings. It never guesses. The asymmetry is deliberate:

* ``disabled`` — the database itself says its native encryption is off — is
  an observed fact and fails the check.
* ``not_observable`` and ``unsupported`` — the interface cannot answer, or the
  connector cannot ask — are ``unsupported`` outcomes that ask for evidence.
  Volume, disk and cloud-KMS encryption live below the data plane, so most
  stores land here, and that is not a finding.

Coverage is reported as counts per collection (verified encrypted, verified
unencrypted, unknown), never as a percentage.

Every outcome also carries the kind's entry from ``at_rest_support.py``: what
the database can show, what to supply when it cannot, and what the vendor
documents. A connector that has no way to ask at all is marked
``capability_limit`` — a fact about the product, not a shortfall of the run.
"""

from __future__ import annotations

import uuid
from collections import Counter
from dataclasses import replace
from functools import partial
from typing import Any, Callable

from vecshield.models import Finding, Severity
from vecshield_platform.connectors.base import AtRestObservation, UnsupportedCapability
from vecshield_platform.posture.at_rest_support import AtRestSupport, support_for
from vecshield_platform.crypto.states import (
    AT_REST_ENCRYPTION,
    FIELD_ENCRYPTION,
    NOT_OBSERVABLE,
    NOT_VERIFIED,
    OBSERVED_EXPOSURE,
    VERIFIED,
    crypto_outcome,
)

_DECISIVE = ("enabled", "disabled")


def _observe(fn: Callable[[], Any], collection: str | None) -> AtRestObservation:
    """Call a connector method; any failure becomes an observation, not an exception."""
    scope = "collection" if collection else "store"
    try:
        obs = fn()
    except UnsupportedCapability as exc:
        return AtRestObservation(state="unsupported", scope=scope, collection=collection,
                                 reason=str(exc))
    except Exception as exc:  # noqa: BLE001 - an audit never crashes on one store call
        return AtRestObservation(state="error", scope=scope, collection=collection,
                                 reason=f"the connector raised {type(exc).__name__}")
    if not isinstance(obs, AtRestObservation):
        return AtRestObservation(state="error", scope=scope, collection=collection,
                                 reason="the connector returned no observation")
    return obs


def observe_at_rest(connector: Any, collections: list[str], *,
                    supported: bool) -> tuple[AtRestObservation, list[AtRestObservation]]:
    """The store-level observation and one per collection.

    A decisive store-level answer (a cluster-wide setting) covers every
    collection. Otherwise, if the connector says the answer is per
    collection, each collection is asked; if not, each inherits the store's
    unknown state.
    """
    if not supported:
        entry = support_for(getattr(connector, "kind", ""))
        store = AtRestObservation(state="unsupported", scope="store",
                                  reason=entry.not_supported_reason or "")
        return store, [replace(store, collection=c) for c in collections]

    store = _observe(lambda: connector.at_rest_encryption_state(None), None)
    if store.state in _DECISIVE or not store.per_collection:
        return store, [replace(store, collection=c) for c in collections]
    per = [_observe(partial(connector.at_rest_encryption_state, c), c)
           for c in collections]
    return store, per


def _distinct(values) -> list:
    return sorted({v for v in values if v})


def _sentence(text: str) -> str:
    text = (text or "").strip()
    return text if not text or text.endswith((".", "!", "?")) else text + "."


def _headline_reason(store_obs: AtRestObservation,
                     observations: list[AtRestObservation]) -> str:
    """The reason that best explains an unknown result: the store's own, unless
    it only says "ask per collection", in which case the commonest collection
    reason."""
    if not store_obs.per_collection and store_obs.reason:
        return store_obs.reason
    reasons = Counter(o.reason for o in observations if o.reason)
    return reasons.most_common(1)[0][0] if reasons else store_obs.reason


def _merge_supply(observations: list[AtRestObservation], entry: AtRestSupport) -> list[str]:
    merged: list[str] = []
    for item in [i for o in observations for i in o.evidence_to_supply] + \
            list(entry.evidence_to_supply):
        if item not in merged:
            merged.append(item)
    return merged


def at_rest_check(store_name: str, store_obs: AtRestObservation,
                  per_collection: list[AtRestObservation], *,
                  support: AtRestSupport | None = None,
                  capability_limit: bool = False) -> tuple[dict, list[Finding]]:
    """One store-level ``at_rest_encryption`` outcome, plus findings for observed facts.

    ``capability_limit`` is set by the caller when the connector cannot ask at
    all; the reason is then the support entry's researched explanation.
    """
    entry = support or support_for("")
    observations = per_collection or [store_obs]
    states = [o.state for o in observations]
    enabled = states.count("enabled")
    disabled = states.count("disabled")
    unknown = len(states) - enabled - disabled
    counts = {"total": len(per_collection), "verified_encrypted": enabled if per_collection else 0,
              "verified_unencrypted": disabled if per_collection else 0,
              "unknown": unknown if per_collection else 0}

    if disabled:
        state, outcome = OBSERVED_EXPOSURE, "failed"
        reason = (f"Database-native encryption at rest is disabled for {disabled} of "
                  f"{len(states)} collection(s)." if per_collection and
                  store_obs.state != "disabled" else
                  "Database-native encryption at rest is disabled for the store.")
    elif enabled == len(states):
        state, outcome = VERIFIED, "passed"
        reason = ("Database-native encryption at rest is enabled for every collection."
                  if per_collection else "Database-native encryption at rest is enabled.")
    elif enabled:
        state, outcome = NOT_VERIFIED, "inconclusive"
        reason = (f"Encryption at rest is verified for {enabled} of {len(states)} "
                  "collection(s); the rest could not be observed.")
    elif states and all(s == "error" for s in states):
        state, outcome = NOT_VERIFIED, "error"
        reason = "Encryption at rest could not be read: " + (store_obs.reason or
                                                             observations[0].reason)
    elif capability_limit:
        state, outcome = NOT_OBSERVABLE, None
        reason = entry.not_supported_reason or _sentence(store_obs.reason)
    else:
        state, outcome = NOT_OBSERVABLE, None
        headline = _headline_reason(store_obs, observations) or "No data-plane source."
        reason = (_sentence(headline[:1].upper() + headline[1:])
                  + " This is not evidence the data is unencrypted.")

    decisive_store = store_obs.state in _DECISIVE
    details: dict[str, Any] = {
        "source": ", ".join(_distinct(o.source for o in observations + [store_obs])) or None,
        "scope": "store" if decisive_store or not per_collection
                 or all(o.scope == "store" for o in per_collection) else "collection",
        "mechanism": ", ".join(_distinct(o.mechanism for o in observations)) or None,
        "key_reference": (lambda keys: keys[0] if len(keys) == 1 else None)(
            _distinct(o.key_reference for o in observations)),
        "collections": counts,
        "per_collection": [{"collection": o.collection, "state": o.state,
                            "reason": o.reason} for o in per_collection],
        "support": entry.support,
        "database": entry.database,
        "evidence_to_supply": ([] if state == VERIFIED
                               else _merge_supply(observations + [store_obs], entry)),
        "documented_default": next((o.documented_default for o in observations + [store_obs]
                                    if o.documented_default), None)
                              or entry.default_record(),
        "sources": list(entry.sources),
    }
    if capability_limit:
        details["capability_limit"] = True
    kwargs = {"outcome": outcome} if outcome else {}
    record = crypto_outcome(AT_REST_ENCRYPTION, store_name, None, state=state,
                            reason=reason, complete=state in (VERIFIED, OBSERVED_EXPOSURE),
                            **kwargs, **details)

    findings: list[Finding] = []
    if disabled:
        if decisive_store or not per_collection:
            targets: list[tuple[str | None, AtRestObservation]] = [(None, store_obs)]
        else:
            targets = [(o.collection, o) for o in per_collection if o.state == "disabled"]
        for collection, obs in targets:
            where = f"collection '{collection}' in " if collection else ""
            findings.append(Finding(
                id=f"find-{uuid.uuid4().hex[:10]}",
                title=f"Database-native encryption at rest is disabled for {where}"
                      f"vector store '{store_name}'",
                severity=Severity.HIGH,
                category=AT_REST_ENCRYPTION,
                store=store_name,
                collection=collection,
                description=(f"{obs.reason}. The store reports its own encryption at "
                             "rest as off. Encryption at the volume, disk or cloud-KMS "
                             "layer is outside what the connector can see; if it is in "
                             "place, record it as evidence rather than treating this "
                             "check as satisfied by it."),
                evidence={"source": obs.source, "scope": obs.scope, **obs.evidence},
                remediation="Enable the database's native encryption at rest (for "
                            "example pg_tde or TDE for PostgreSQL, the encrypted "
                            "storage engine for MongoDB), or document the equivalent "
                            "control and its risk decision.",
            ))
    return record, findings


def field_encryption_checks(connector: Any, store_name: str, collections: list[str], *,
                            supported: bool) -> list[dict]:
    """``field_encryption`` per collection where the store can report it.

    Every outcome names the database and whether it has a field-encryption
    interface, so a reader sees "not supported by <database>" rather than a
    bare unknown. ``capability_limit`` is set only when the database has no
    such interface at all — never when a supported database failed to answer.
    """
    database = support_for(getattr(connector, "kind", "")).database
    support = "supported" if supported else "not_supported"

    def outcome(collection: str | None, state: str, reason: str, **details: Any) -> dict:
        return crypto_outcome(FIELD_ENCRYPTION, store_name, collection, state=state,
                              reason=reason, database=database, support=support,
                              **details)

    if not supported:
        return [outcome(
            None, NOT_OBSERVABLE,
            f"{database} does not report field-level encryption configuration to "
            "this connector. Encryption applied by the application before writing "
            "is not visible here.",
            fields=[], supported=False, capability_limit=True,
            evidence_to_supply=["The application's field-level encryption design "
                                "and key management, if fields are encrypted "
                                "before they are written"])]

    outcomes: list[dict] = []
    for collection in collections:
        try:
            config = connector.field_encryption_config(collection) or []
        except UnsupportedCapability as exc:
            outcomes.append(outcome(collection, NOT_OBSERVABLE, str(exc),
                                    fields=[], supported=True))
            continue
        except Exception as exc:  # noqa: BLE001
            outcomes.append(outcome(
                collection, NOT_VERIFIED,
                f"Field encryption configuration could not be read "
                f"({type(exc).__name__}).", outcome="error", fields=[], supported=True))
            continue
        fields = [{k: v for k, v in item.items() if k in
                   ("path", "mechanism", "algorithm", "queries")}
                  for item in config if isinstance(item, dict) and item.get("path")]
        if fields:
            outcomes.append(outcome(
                collection, VERIFIED,
                f"The store declares field-level encryption on {len(fields)} "
                "field(s). Fields not listed are stored as written.",
                complete=True, fields=fields, supported=True))
        else:
            outcomes.append(outcome(
                collection, NOT_VERIFIED,
                "The store declares no field-level encryption for this collection. "
                "Encryption applied by the application before writing is not "
                "visible here.", fields=[], supported=True))
    if not collections:
        outcomes.append(outcome(
            None, NOT_VERIFIED, "The store has no collections to read field encryption "
            "for.", fields=[], supported=True))
    return outcomes
