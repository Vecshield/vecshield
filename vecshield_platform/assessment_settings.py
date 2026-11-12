"""Resolve and freeze effective settings shared by API and scheduled audits."""

from __future__ import annotations

import inspect
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version

from vecshield_platform.compliance.allowlist import evaluate_suppressions
from vecshield_platform.compliance.policy import default_policies


@dataclass
class AuditSettings:
    policies: list
    tenant_field: str | None
    allowlist: list
    suppressions: list
    resolved_at: datetime
    scope: dict
    #: Store controls resolved for ``run_full_audit`` (retention schedule,
    #: residency policy, processor register, source manifest, feed dir). Pass
    #: them through :func:`supported_audit_kwargs`.
    audit_kwargs: dict = field(default_factory=dict)

    def suppress(self, findings: list) -> list:
        return evaluate_suppressions(findings, allowlist=self.allowlist,
                                     suppressions=self.suppressions,
                                     now=self.resolved_at).active


def resolve_audit_settings(config, store, *, tenant_field: str | None = None,
                           include_integrity: bool = True,
                           max_chunks_per_collection: int | None = None,
                           tls_probe: bool = False,
                           retrieval_probe: bool = False,
                           state_dir=None,
                           overrides: dict | None = None) -> AuditSettings:
    """Snapshot settings before enqueueing, without connector credentials.

    The two probes are active checks and are off unless the caller asks: the
    TLS probe opens an extra plaintext connection attempt, and the retrieval
    probe replays stored vectors as queries. Both are recorded in the scope so
    an audit says which of them ran.

    Store controls (retention schedule, residency policy, processor register,
    source manifest, inventory declarations) are resolved here too, so the
    API, the scheduler and the CLI evaluate the same settings. The scope
    records booleans, counts and hashes, never the contents.
    """
    now = datetime.now(timezone.utc)
    policies = deepcopy(config.effective_policies(store.store_id)
                        if config is not None else default_policies())
    allowlist = deepcopy(config.effective_allowlist() if config is not None else [])
    suppressions = deepcopy(config.active_suppressions(now) if config is not None else [])
    effective_tenant = tenant_field if tenant_field is not None else store.tenant_field
    versions = {}
    for package in ("vecshield",):
        try:
            versions[package] = version(package)
        except PackageNotFoundError:
            versions[package] = "unknown"
    scope = {
        "store_id": store.store_id,
        "connector_kind": store.kind,
        "tenant_field": effective_tenant,
        "include_integrity": include_integrity,
        "include_posture": True,
        "tls_probe": tls_probe,
        "retrieval_probe": retrieval_probe,
        "max_chunks_per_collection": max_chunks_per_collection,
        "resolved_at": now.isoformat(),
        "versions": versions,
        "configured_policies": [
            {"id": p.id, "description": p.description, "when": deepcopy(p.when),
             "action": p.action, "severity": p.severity.value} for p in policies
        ],
        "allowlist": [rule.to_dict() for rule in allowlist],
        "suppressions": [rule.to_dict() for rule in suppressions],
    }
    kwargs, controls = resolve_store_controls(config, store.store_id, state_dir=state_dir,
                                              overrides=overrides)
    scope["store_controls"] = controls
    return AuditSettings(policies, effective_tenant, allowlist, suppressions, now, scope,
                         audit_kwargs=kwargs)


def _hash(value):
    from vecshield_platform.api.config_store import canonical_hash

    return canonical_hash(value)


_MISSING = object()


def resolve_store_controls(config, store_id: str | None, *, state_dir=None,
                           overrides: dict | None = None) -> tuple[dict, dict]:
    """``run_full_audit`` keyword arguments and their scope summary.

    ``config`` is a ConfigStore or None. ``overrides`` (the CLI's files) take
    precedence over the config and are validated the same way; a key present
    with ``None`` means "not declared" rather than "use the config".
    """
    from vecshield_platform.api.config_store import (
        validate_processor_register,
        validate_residency_policy,
        validate_source_manifest,
    )
    from vecshield_platform.scan.retention_schedule import (
        ScheduleError,
        resolve_schedule,
        validate_schedule,
    )

    overrides = overrides or {}
    kwargs: dict = {}
    scope: dict = {}

    # Retention schedule (a store entry replaces the global one).
    retention_scope: dict = {"declared": False, "source": None, "valid": True}
    raw = overrides.get("retention_schedule", _MISSING)
    schedule = None
    try:
        if raw is not _MISSING:
            retention_scope["source"] = "override" if raw is not None else None
            schedule = (resolve_schedule(raw, store_id) if isinstance(raw, dict)
                        and ("global" in raw or "stores" in raw) else validate_schedule(raw))
        elif config is not None and getattr(config, "retention_schedules", None):
            doc = config.retention_schedules
            if store_id in (doc.get("stores") or {}):
                retention_scope["source"] = "store"
            elif doc.get("global") is not None:
                retention_scope["source"] = "global"
            schedule = resolve_schedule(doc, store_id)
    except ScheduleError as e:
        # Recorded, not ignored: the check reports no schedule, and the scope
        # says one was configured but no longer validates.
        retention_scope.update(valid=False, problems=e.problems[:20])
        schedule = None
    if schedule is not None:
        retention_scope.update(declared=True, rules=len(schedule.rules),
                               default_max_age_days=schedule.default_max_age_days,
                               hash=_hash(schedule.to_dict()))
    kwargs["retention_schedule"] = schedule
    scope["retention_schedule"] = retention_scope

    # Residency policy for this store.
    raw = overrides.get("residency_policy", _MISSING)
    policy, source = None, None
    problems: list[str] = []
    if raw is not _MISSING:
        policy, problems = validate_residency_policy(raw)
        source = "override" if raw is not None else None
    elif config is not None and hasattr(config, "residency_policy_for"):
        policy, source = config.residency_policy_for(store_id)
    kwargs["residency_policy"] = policy
    scope["residency_policy"] = {"declared": policy is not None, "source": source,
                                 "valid": not problems, "hash": _hash(policy)}
    if problems:
        scope["residency_policy"]["problems"] = problems[:20]

    # Sub-processor register (deployment-wide).
    raw = overrides.get("processor_register", _MISSING)
    register: list[dict] = []
    problems = []
    if raw is not _MISSING:
        register, problems = validate_processor_register(raw)
    elif config is not None:
        register = deepcopy(getattr(config, "processor_register", None) or [])
    kwargs["processor_register"] = register
    scope["processor_register"] = {"entries": len(register), "valid": not problems,
                                   "hash": _hash(register) if register else None}

    # Source manifest for the chunk-versions check.
    raw = overrides.get("source_manifest", _MISSING)
    manifest: list[dict] | None = None
    problems = []
    if raw is not _MISSING:
        manifest, problems = validate_source_manifest(raw)
    elif config is not None and hasattr(config, "get_source_manifest"):
        stored = config.get_source_manifest(store_id)
        manifest = stored["entries"] if stored else None
    kwargs["source_manifest"] = manifest
    scope["source_manifest"] = {"supplied": manifest is not None,
                                "entries": len(manifest or []), "valid": not problems,
                                "hash": _hash(manifest)}

    # Manually declared inventory facts.
    declarations = None
    if config is not None and hasattr(config, "get_inventory_declarations"):
        found = config.get_inventory_declarations(store_id)
        declarations = {"store": found.get("store") or {},
                        "collections": found.get("collections") or {}}
    kwargs["inventory_declarations"] = declarations
    scope["inventory_declarations"] = {
        "store_fields": len((declarations or {}).get("store") or {}),
        "collections": len((declarations or {}).get("collections") or {}),
        "hash": _hash(declarations) if declarations and (
            declarations["store"] or declarations["collections"]) else None}

    # Server vulnerability feed: read from the server's state directory (the
    # bundled seed when there is none). Auditing never refreshes it.
    kwargs["vuln_feed_dir"] = str(state_dir) if state_dir else None
    kwargs["include_store_facts"] = True
    if store_id is not None:
        kwargs["store_id"] = store_id
    scope["vuln_feed"] = {"state_dir_configured": bool(state_dir)}
    return kwargs, scope


def supported_audit_kwargs(fn, kwargs: dict, scope: dict | None = None) -> dict:
    """The subset of ``kwargs`` that ``fn`` accepts.

    Lets the callers pass store controls to an orchestrator that may not yet
    take all of them. What was dropped is recorded in ``scope`` (when given)
    under ``store_controls.not_applied``, so an audit never implies a control
    was evaluated when it was not.
    """
    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return dict(kwargs)
    if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
        return dict(kwargs)
    accepted = {k: v for k, v in kwargs.items() if k in params}
    dropped = sorted(k for k in kwargs if k not in params)
    if scope is not None and dropped:
        scope.setdefault("store_controls", {})["not_applied"] = dropped
    return accepted



def apply_settings_scope(result_scope: dict, settings_scope: dict) -> dict:
    """Merge the frozen settings into an audit's scope.

    The orchestrator records what it *observed* of each store control under
    ``store_controls`` (supplied, counts, feed age); the settings add where
    each came from and its hash. Both are kept: a plain ``dict.update`` would
    replace the orchestrator's half.
    """
    incoming = dict(settings_scope)
    ours = incoming.pop("store_controls", None)
    result_scope.update(incoming)
    if ours:
        theirs = result_scope.get("store_controls")
        merged = dict(theirs) if isinstance(theirs, dict) else {}
        for key, value in ours.items():
            existing = merged.get(key)
            merged[key] = ({**existing, **value}
                           if isinstance(existing, dict) and isinstance(value, dict) else value)
        result_scope["store_controls"] = merged
    return result_scope
