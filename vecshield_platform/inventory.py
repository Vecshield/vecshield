"""A vector-store and personal-data inventory, built from what a scan observed.

Several regimes ask for an inventory a vector store is rarely in:

* NYDFS 23 NYCRR 500.13(a): an asset inventory tracking owner, location,
  classification or sensitivity, support expiration date and recovery time
  objective;
* CCPA regulations 11 CCR 7123(c)(4)(A)-(B): personal information inventories
  ("maps and flows identifying where personal information is stored") and
  hardware/software inventories, assessed in the cybersecurity audit;
* Minnesota 325M.16 subd. 2(c): an inventory of the data that must be managed.

This module assembles one inventory per store from facts the product already
collects — the store description, server version, location, aliases,
classification counts, subject counts, retention horizon, biometric verdicts
and model egress — into a stable, serialisable dict. Facts only a person can
supply (owner, business purpose, RTO, support contact, support expiration)
are present as ``{"value": None, "declared": False}`` so the export shows what
remains to be filled rather than omitting it.

``inventory_hash`` is a SHA-256 over the canonical JSON with volatile fields
removed (generation time, product version, record *ages*): two inventories of
an unchanged store hash the same, so change tracking can compare hashes first.

Pure: no I/O, no connector. The caller gathers the inputs.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import Any, Optional

from vecshield.models import VectorStore
from vecshield_platform.connectors.redact import redact_credentials
from vecshield_platform.coverage import check_outcome

SCHEMA_VERSION = 1
CHECK = "asset_inventory"

#: Facts a person declares; the scan cannot observe them.
STORE_DECLARED_FIELDS = ("owner", "business_purpose", "recovery_time_objective",
                         "support_contact", "support_expiration_date")
COLLECTION_DECLARED_FIELDS = ("owner", "business_purpose")

#: Keys excluded from the hash: they change with the clock, not the store.
_VOLATILE_KEYS = frozenset({"generated_at", "vecshield_version", "inventory_hash"})


def _version() -> str:
    try:
        from vecshield_platform import __version__
    except Exception:  # noqa: BLE001
        return "unknown"
    return __version__


def _declared(fields: Iterable[str], supplied: Optional[Mapping[str, Any]]) -> dict[str, Any]:
    supplied = supplied or {}
    out: dict[str, Any] = {}
    for name in fields:
        value = supplied.get(name)
        if isinstance(value, str):
            value = value.strip() or None
        elif not isinstance(value, (int, float)) or isinstance(value, bool):
            value = None
        out[name] = {"value": value, "declared": value is not None}
    return out


def _label_counts(entry: Mapping[str, Any]) -> dict[str, int]:
    raw = entry.get("label_counts") or entry.get("labels") or {}
    out: dict[str, int] = {}
    for label, count in dict(raw).items():
        name = str(getattr(label, "value", label))
        if name != "none" and isinstance(count, int) and count > 0:
            out[name] = out.get(name, 0) + count
    return dict(sorted(out.items()))


def _as_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, Mapping):
        return dict(value)
    to_dict = getattr(value, "to_dict", None)
    return dict(to_dict()) if callable(to_dict) else {}


def _integrations(egress: Any) -> list[dict[str, Any]]:
    if isinstance(egress, Mapping):
        egress = egress.get("integrations")
    return [dict(item) for item in (egress or []) if isinstance(item, Mapping)]


def build_inventory(store: VectorStore, *,
                    store_id: Optional[str] = None,
                    server_info: Optional[Mapping[str, Any]] = None,
                    location: Optional[Mapping[str, Any]] = None,
                    aliases: Optional[Mapping[str, str]] = None,
                    classification_by_collection: Optional[Mapping[str, Mapping[str, Any]]] = None,
                    subject_counts: Optional[Mapping[str, int]] = None,
                    retention_by_collection: Optional[Mapping[str, Any]] = None,
                    biometric_by_collection: Optional[Mapping[str, Any]] = None,
                    egress: Optional[Any] = None,
                    declarations: Optional[Mapping[str, Any]] = None,
                    now: Optional[datetime] = None) -> dict[str, Any]:
    """One store's inventory. Every argument but ``store`` is optional.

    A ``None`` input is recorded as not observed, never as empty: an
    unreported region is ``region: None`` with ``location_observed: False``,
    not a claim that the store has no region.
    """
    now = now or datetime.now(timezone.utc)
    classification_by_collection = classification_by_collection or {}
    retention_by_collection = retention_by_collection or {}
    biometric_by_collection = biometric_by_collection or {}
    declarations = declarations or {}
    server = dict(server_info or {})
    where = dict(location or {})
    integrations = _integrations(egress)
    storewide = sorted({str(i.get("provider")) for i in integrations
                        if i.get("provider") and i.get("collection") is None})
    alias_map = ({str(k): str(v) for k, v in sorted(aliases.items())}
                 if aliases is not None else None)

    collections: list[dict[str, Any]] = []
    for col in sorted(store.collections, key=lambda c: c.name):
        classified = classification_by_collection.get(col.name)
        retention = _as_dict(retention_by_collection.get(col.name))
        biometric = _as_dict(biometric_by_collection.get(col.name))
        providers = sorted(set(storewide) | {
            str(i.get("provider")) for i in integrations
            if i.get("provider") and i.get("collection") == col.name})
        collections.append({
            "name": col.name,
            "count": col.count,
            "dimension": col.dimension,
            "embedding_model": col.embedding_model,
            "distance_metric": col.distance_metric,
            "classified": classified is not None,
            "chunks_scanned": (classified or {}).get("chunks_scanned"),
            "sensitive_categories": _label_counts(classified or {}),
            "detectors": dict(sorted(dict((classified or {}).get("detector_counts")
                                          or (classified or {}).get("detectors") or {}).items())),
            "distinct_subjects": (subject_counts or {}).get(col.name)
            if subject_counts is not None else None,
            "retention": {
                "observed": bool(retention),
                "status": retention.get("status"),
                "timestamp_field": retention.get("field", retention.get("timestamp_field")),
                "oldest": retention.get("oldest"),
                "newest": retention.get("newest"),
                "oldest_age_days": retention.get("oldest_age_days"),
                "newest_age_days": retention.get("newest_age_days"),
            },
            "biometric": {
                "status": biometric.get("status") if biometric else None,
                "modality": biometric.get("modality"),
                "estimated_distinct_identities": biometric.get("estimated_distinct_identities"),
            },
            "egress_providers": providers,
            "aliased_by": sorted(a for a, target in (alias_map or {}).items()
                                 if target == col.name),
            "declared": _declared(COLLECTION_DECLARED_FIELDS,
                                  (declarations.get("collections") or {}).get(col.name)),
        })

    inventory: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": now.isoformat(),
        "vecshield_version": _version(),
        "store": {
            "id": store_id,
            "name": redact_credentials(store.name),
            "kind": store.kind,
            "endpoint": redact_credentials(store.endpoint),
            "server_observed": bool(server),
            "product": server.get("product"),
            "version": server.get("version"),
            "edition": server.get("edition"),
            "managed": server.get("managed"),
            "server_info_source": server.get("source"),
            "location_observed": bool(where.get("observable", bool(where))),
            "provider": where.get("provider"),
            "region": where.get("region"),
            "replica_regions": sorted(where.get("replica_regions") or []),
            "location_source": where.get("source"),
            "aliases_observed": alias_map is not None,
            "aliases": alias_map,
            "egress_observed": egress is not None,
            "egress_providers": storewide,
            "declared": _declared(STORE_DECLARED_FIELDS, declarations.get("store")),
        },
        "collections": collections,
        "totals": {
            "collections": len(collections),
            "vectors": sum(int(c["count"] or 0) for c in collections),
            "sensitive_collections": sum(bool(c["sensitive_categories"]) for c in collections),
            "biometric_collections": sum(
                c["biometric"]["status"] == "biometric_templates" for c in collections),
            "undeclared_fields": sum(
                not entry["declared"]
                for c in collections for entry in c["declared"].values()) + sum(
                not entry["declared"]
                for entry in _declared(STORE_DECLARED_FIELDS,
                                       declarations.get("store")).values()),
        },
        "requirements": _requirements(),
    }
    inventory["inventory_hash"] = inventory_hash(inventory)
    return inventory


def _requirements() -> list[dict[str, str]]:
    from vecshield_platform.compliance.data import load_references

    return [{"id": ref["id"], "citation": ref["citation"], "source_url": ref["source_url"]}
            for ref in load_references("inventory")["references"]]


def _stable(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {k: _stable(v) for k, v in value.items()
                if k not in _VOLATILE_KEYS and not str(k).endswith("_age_days")}
    if isinstance(value, (list, tuple)):
        return [_stable(v) for v in value]
    return value


def inventory_hash(inventory: Mapping[str, Any]) -> str:
    """SHA-256 over the canonical JSON, excluding clock-dependent fields."""
    canonical = json.dumps(_stable(inventory), sort_keys=True, separators=(",", ":"),
                           default=str, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------ exports
CSV_COLUMNS = (
    "store_id", "store_name", "store_kind", "endpoint", "product", "version",
    "managed", "provider", "region", "collection", "count", "dimension",
    "embedding_model", "distance_metric", "sensitive_categories",
    "distinct_subjects", "oldest_record", "newest_record", "oldest_age_days",
    "biometric_status", "egress_providers", "aliased_by", "owner",
    "business_purpose", "store_owner", "recovery_time_objective",
    "support_contact", "support_expiration_date", "inventory_hash",
)

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def csv_cell(value: Any) -> Any:
    """A CSV cell that a spreadsheet will not execute.

    Collection names and metadata come from the store, so a name such as
    ``=HYPERLINK(...)`` is attacker-reachable. Text beginning with a formula
    character is prefixed with an apostrophe (OWASP CSV injection guidance).
    Every CSV export uses this, not only the inventory.
    """
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return value
    text = str(value)
    return "'" + text if text.startswith(_FORMULA_PREFIXES) else text


def _declared_value(block: Optional[Mapping[str, Any]], name: str) -> Any:
    return ((block or {}).get(name) or {}).get("value")


def inventory_to_csv(inventories: Iterable[Mapping[str, Any]]) -> str:
    """One row per collection (one row for a store with none)."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for inv in inventories:
        store = inv.get("store") or {}
        base = {
            "store_id": store.get("id"), "store_name": store.get("name"),
            "store_kind": store.get("kind"), "endpoint": store.get("endpoint"),
            "product": store.get("product"), "version": store.get("version"),
            "managed": store.get("managed"), "provider": store.get("provider"),
            "region": store.get("region"),
            "store_owner": _declared_value(store.get("declared"), "owner"),
            "recovery_time_objective": _declared_value(store.get("declared"),
                                                       "recovery_time_objective"),
            "support_contact": _declared_value(store.get("declared"), "support_contact"),
            "support_expiration_date": _declared_value(store.get("declared"),
                                                       "support_expiration_date"),
            "inventory_hash": inv.get("inventory_hash"),
        }
        rows = inv.get("collections") or [None]
        for col in rows:
            row = dict(base)
            if col is not None:
                retention = col.get("retention") or {}
                row.update({
                    "collection": col.get("name"), "count": col.get("count"),
                    "dimension": col.get("dimension"),
                    "embedding_model": col.get("embedding_model"),
                    "distance_metric": col.get("distance_metric"),
                    "sensitive_categories": ";".join(
                        f"{k}:{v}" for k, v in (col.get("sensitive_categories") or {}).items()),
                    "distinct_subjects": col.get("distinct_subjects"),
                    "oldest_record": retention.get("oldest"),
                    "newest_record": retention.get("newest"),
                    "oldest_age_days": retention.get("oldest_age_days"),
                    "biometric_status": (col.get("biometric") or {}).get("status"),
                    "egress_providers": ";".join(col.get("egress_providers") or []),
                    "aliased_by": ";".join(col.get("aliased_by") or []),
                    "owner": _declared_value(col.get("declared"), "owner"),
                    "business_purpose": _declared_value(col.get("declared"),
                                                        "business_purpose"),
                })
            writer.writerow([csv_cell(row.get(name)) for name in CSV_COLUMNS])
    return buffer.getvalue()


def inventory_to_json(inventories: Iterable[Mapping[str, Any]], *,
                      now: Optional[datetime] = None) -> str:
    """The inventories as one JSON document, with the requirements they serve."""
    items = [dict(inv) for inv in inventories]
    document = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": (now or datetime.now(timezone.utc)).isoformat(),
        "vecshield_version": _version(),
        "inventories": items,
        "requirements": _requirements(),
        "note": ("Observed facts from the scan. Fields marked declared=false "
                 "are for the organisation to supply."),
    }
    return json.dumps(document, indent=2, sort_keys=True, default=str, ensure_ascii=False)


def asset_inventory_outcome(store: str, inventory: Optional[Mapping[str, Any]], *,
                            reason: str = "") -> dict:
    """Store-level ``asset_inventory`` outcome.

    ``passed`` and complete when describe() succeeded and an inventory was
    built; ``error`` when it was not (``reason`` says why). Unobserved
    optional facts (server version, region, aliases) do not make it partial:
    they are recorded as not observed in the inventory itself.
    """
    if inventory is None:
        return check_outcome(CHECK, store, outcome="error",
                             reason=reason or "The store could not be described.",
                             complete=False)
    totals = dict(inventory.get("totals") or {})
    info = inventory.get("store") or {}
    return check_outcome(
        CHECK, store, outcome="passed",
        reason=reason or (f"Inventoried {totals.get('collections', 0)} collections "
                          f"holding {totals.get('vectors', 0)} vectors."),
        complete=True, inventory_hash=inventory.get("inventory_hash"),
        server_observed=info.get("server_observed"),
        location_observed=info.get("location_observed"),
        aliases_observed=info.get("aliases_observed"), **totals)
