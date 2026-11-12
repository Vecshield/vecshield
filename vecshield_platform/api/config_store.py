"""Persistent admin configuration: registered stores + scoped policies.

JSON-file backed so an admin's setup survives restarts. Stores hold connector
config; policies carry a scope (global / a store / a specific collection) and
are converted to runtime Policy objects, scoped via the engine's existing
collection matcher.

Security note: connection config is persisted to disk. Secrets (e.g. a pgvector
password) should be supplied via an environment variable referenced in config
(`password_env`) rather than stored in plaintext — resolved at connect time.
"""

from __future__ import annotations

import contextlib
import copy
import json
import logging
import math
import os
import threading
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Iterator, Optional

try:
    import fcntl  # POSIX advisory locks
except ImportError:  # pragma: no cover - non-POSIX (e.g. Windows)
    fcntl = None  # type: ignore[assignment]

from vecshield_platform.connectors import AVAILABLE
from vecshield_platform.connectors.redact import (
    MASK,
    embedded_credentials,
    redact_credentials,
)
from vecshield_platform.api.registry import StoreRegistry
from vecshield_platform.api.secrets import (
    SecretReferenceDenied,
    SecretResolutionError,
    check_references,
    is_reference_key,
    resolve_conn,
)
from vecshield_platform.api.templates import get_template
from vecshield_platform.compliance.allowlist import (
    AllowlistRule,
    Suppression,
    builtin_allowlist,
    validate_suppression,
)
from vecshield_platform.compliance.policy import Policy
from vecshield.models import Severity

logger = logging.getLogger(__name__)

#: ``headers`` carries Chroma's auth header (``Authorization`` or
#: ``X-Chroma-Token``), so the whole mapping is masked like a password.
_SECRET_KEYS = {"password", "api_key", "token", "dsn", "headers"}
_SECRET_KEY_PARTS = ("password", "api_key", "token", "secret")

#: Connection keys that decide where a connector sends its credentials. A
#: masked secret ("***") is only carried over while all of these stay the same.
_ENDPOINT_KEYS = frozenset({
    "host", "hosts", "url", "uri", "dsn", "port", "grpc_port", "endpoint",
    "conninfo", "connection_string", "connection_uri", "index_host", "region",
    "use_ssl", "secure", "ssl",
    # Weaviate sends its API key in gRPC metadata to this host, which can
    # differ from the HTTP host.
    "grpc_host",
})


def _truthy_env(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class StoredStore:
    store_id: str
    kind: str
    conn: dict[str, Any] = field(default_factory=dict)  # connector kwargs
    tenant_field: Optional[str] = None
    description: str = ""

    def public_dict(self) -> dict:
        # Never expose raw secrets in API responses: secret-named keys are
        # masked whole, and a credential embedded in any other value (the
        # password in a ``uri``/``url``, a ``password=`` in a keyword DSN) is
        # masked in place so the rest of the configuration stays readable.
        safe_conn = {}
        for k, v in self.conn.items():
            if _is_secret_key(k):
                safe_conn[k] = "***"
            else:
                safe_conn[k] = _redact_value(v)
        return {"store_id": self.store_id, "kind": self.kind,
                "tenant_field": self.tenant_field, "description": self.description,
                "conn": safe_conn}


@dataclass
class StoredPolicy:
    id: str
    name: str
    description: str
    when: dict[str, Any]
    action: str
    severity: str = "high"
    enabled: bool = True
    scope_store: Optional[str] = None       # None = all stores
    scope_collection: Optional[str] = None  # None = all collections
    template_id: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)

    def to_policy(self) -> Policy:
        when = dict(self.when)
        if self.scope_collection:
            when["collection"] = self.scope_collection
        return Policy(id=self.id, description=self.description, when=when,
                      action=self.action, severity=Severity(self.severity))


def mask_webhook_url(url: str) -> str:
    """The public form of a webhook URL: scheme and host only.

    Slack and PagerDuty URLs carry their credential in the path, so the path is
    never shown. ``set_alerting`` recognises this form coming back and keeps
    the stored URL it stands for.
    """
    from urllib.parse import urlparse

    try:
        parsed = urlparse(url)
        host = parsed.hostname
        if parsed.scheme and host:
            # Host and port only: userinfo (user:password@) is a credential.
            if ":" in host:
                host = f"[{host}]"
            port = parsed.port
            return f"{parsed.scheme}://{host}{f':{port}' if port else ''}/\u2026"
    except Exception:  # noqa: BLE001
        pass
    return "***"


def _is_masked(url: str) -> bool:
    return url == "***" or url.endswith("/\u2026")


def _keep_masked_secrets(incoming: list[dict], existing: list[dict]) -> list[dict]:
    """Resolve masked values sent back from a GET to the secrets they stand for.

    A settings screen loads the masked list and saves it whole, so a change to
    the severity threshold alone must not replace real webhook URLs with their
    masks. Each masked URL is matched, in order, to an unused stored webhook
    with the same masked form and style; a masked routing key keeps the stored
    key. A masked URL that matches nothing cannot be turned back into a real
    one, so it is refused rather than saved as a broken destination.
    """
    unused = list(existing)
    out: list[dict] = []
    for hook in incoming:
        url = hook.get("url", "")
        match = None
        if _is_masked(url):
            match = next((old for old in unused
                          if mask_webhook_url(old.get("url", "")) == url
                          and old.get("style", "slack") == hook.get("style", "slack")),
                         None)
            if match is None:
                raise ValueError(
                    f"webhook {url} is a masked value that matches no stored webhook; "
                    "enter the full URL to add a new one")
            unused.remove(match)
            hook = {**hook, "url": match["url"]}
        if hook.get("routing_key") == "***":
            source = match or next((old for old in existing
                                    if old.get("url") == hook["url"]), None)
            if source and source.get("routing_key"):
                hook = {**hook, "routing_key": source["routing_key"]}
            else:
                raise ValueError("a masked routing key matches no stored webhook; "
                                 "enter the full routing key")
        out.append(hook)
    return out


@dataclass
class AlertingConfig:
    """Where audit/monitor alerts are delivered (persisted with the config).

    Each webhook entry is a dict ``{"url", "style", "routing_key"}`` where style
    is ``slack`` (default), ``pagerduty`` (Events v2 — needs ``routing_key``) or
    ``generic`` (raw alert JSON). A bare URL string is accepted as Slack-style.
    Only alerts at or above ``min_severity`` are delivered.
    """
    enabled: bool = False
    webhooks: list[dict] = field(default_factory=list)
    min_severity: str = "high"
    console: bool = False

    @classmethod
    def from_dict(cls, d: Optional[dict]) -> "AlertingConfig":
        d = dict(d or {})
        webhooks: list[dict] = []
        for w in d.get("webhooks", []):
            if isinstance(w, str) and w:
                webhooks.append({"url": w, "style": "slack"})
            elif isinstance(w, dict) and w.get("url"):
                entry = {"url": w["url"], "style": w.get("style", "slack")}
                if w.get("routing_key"):
                    entry["routing_key"] = w["routing_key"]
                webhooks.append(entry)
        # Validate the severity threshold up front (raises on a bad value).
        Severity(str(d.get("min_severity", "high")))
        return cls(
            enabled=bool(d.get("enabled", False)),
            webhooks=webhooks,
            min_severity=str(d.get("min_severity", "high")),
            console=bool(d.get("console", False)),
        )

    def to_dict(self) -> dict:
        return asdict(self)


_DEFAULT_DETECTOR_SETTINGS: dict[str, Any] = {
    "cooldown_s": 300.0,
    "bulk_volume": {
        "enabled": True,
        "threshold": 500,
        "window_s": 600.0,
        "severity": "high",
    },
    "collection_sweep": {
        "enabled": True,
        "fraction": 0.8,
        "window_s": 600.0,
        "severity": "high",
    },
    "enumeration": {
        "enabled": True,
        "sim_threshold": 0.97,
        "run_length": 10,
        "max_gap_s": 30.0,
        "severity": "medium",
    },
    "rate_baseline": {
        "enabled": True,
        "window_s": 60.0,
        "spike_factor": 5.0,
        "warmup_samples": 3,
        "min_rate": 10.0,
        "alpha": 0.3,
        "severity": "medium",
    },
}


@dataclass
class DetectorSettings:
    """Persisted runtime detector thresholds, independent of policy templates."""

    data: dict[str, Any] = field(default_factory=lambda: copy.deepcopy(_DEFAULT_DETECTOR_SETTINGS))

    @classmethod
    def from_dict(cls, d: Optional[dict[str, Any]]) -> "DetectorSettings":
        data = copy.deepcopy(_DEFAULT_DETECTOR_SETTINGS)
        if d:
            for key, value in d.items():
                if key == "cooldown_s":
                    data[key] = value
                elif key in data and isinstance(value, dict):
                    data[key].update(value)
                else:
                    raise ValueError(f"unknown detector setting: {key}")
        _validate_detector_settings(data)
        return cls(data)

    def to_dict(self) -> dict[str, Any]:
        return copy.deepcopy(self.data)


class ConfigStore:
    def __init__(self, path: Optional[str] = None, *,
                 reject_plaintext_secrets: Optional[bool] = None):
        self.path = path
        # When True, add_store/update_store refuse connector config that carries
        # a plaintext secret (a password/api_key/token/dsn given directly rather
        # than as a ``*_env`` / ``*_file`` reference). Defaults to permissive
        # (warn only) for backward compatibility; enable strict mode explicitly
        # or via env VECSHIELD_REJECT_PLAINTEXT_SECRETS=1.
        if reject_plaintext_secrets is None:
            reject_plaintext_secrets = _truthy_env("VECSHIELD_REJECT_PLAINTEXT_SECRETS")
        self.reject_plaintext_secrets = reject_plaintext_secrets
        # Serializes read-modify-write within this process (FastAPI runs sync
        # routes on a threadpool); combined with a cross-process file lock this
        # makes concurrent writers safe. RLock so nested helpers don't deadlock.
        self._write_lock = threading.RLock()
        self.stores: dict[str, StoredStore] = {}
        self.policies: dict[str, StoredPolicy] = {}
        self.allowlist: dict[str, AllowlistRule] = {}
        self.suppressions: dict[str, Suppression] = {}
        self.alerting = AlertingConfig()
        self.detectors = DetectorSettings()
        self._init_store_controls()
        # Stores added/edited since the last build_registry(): an unresolvable
        # secret reference on one of these is an error for its editor rather
        # than an "unavailable" store (see build_registry).
        self._validate_on_build: set[str] = set()
        if path and os.path.exists(path):
            self.load()

    # ---- persistence ----

    @property
    def _lock_path(self) -> Optional[str]:
        return f"{self.path}.lock" if self.path else None

    @contextlib.contextmanager
    def _file_lock(self) -> Iterator[None]:
        """Cross-process exclusive advisory lock over the config file.

        Best-effort: a no-op when there is no backing file, or on platforms
        without ``fcntl`` (a warning is logged once so the single-writer
        expectation is explicit).
        """
        if not self.path or fcntl is None:
            if self.path and fcntl is None:
                logger.warning(
                    "fcntl unavailable: config file locking disabled; run a "
                    "single writer (one process, --workers 1)."
                )
            yield
            return
        handle = open(self._lock_path, "w")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            finally:
                handle.close()

    @contextlib.contextmanager
    def _locked_write(self) -> Iterator[None]:
        """Run a read-modify-write atomically across threads and processes.

        Acquires the write lock, reloads the freshest on-disk state (so we do
        not clobber a concurrent writer's update), yields for the mutation, then
        persists atomically. If the body raises, nothing is persisted.
        """
        with self._write_lock, self._file_lock():
            if self.path and os.path.exists(self.path):
                self.load()
            yield
            self._save_unlocked()

    def load(self) -> None:
        with open(self.path) as f:
            data = json.load(f)
        self.stores = {s["store_id"]: StoredStore(**s)
                       for s in data.get("stores", [])}
        self.policies = {p["id"]: StoredPolicy(**p)
                         for p in data.get("policies", [])}
        self.allowlist = {r["id"]: AllowlistRule.from_dict(r)
                          for r in data.get("allowlist", [])}
        self.suppressions = {s["id"]: Suppression.from_dict(s)
                             for s in data.get("suppressions", [])}
        self.alerting = AlertingConfig.from_dict(data.get("alerting"))
        self.detectors = DetectorSettings.from_dict(data.get("detectors"))
        _warn_on_refused_webhooks(self.alerting)
        self._load_store_controls(data)

    def save(self) -> None:
        """Persist the current in-memory state under the write/file lock."""
        if not self.path:
            return
        with self._write_lock, self._file_lock():
            self._save_unlocked()

    def _save_unlocked(self) -> None:
        if not self.path:
            return
        data = {
            "stores": [asdict(s) for s in self.stores.values()],
            "policies": [asdict(p) for p in self.policies.values()],
            "allowlist": [r.to_dict() for r in self.allowlist.values()],
            "suppressions": [s.to_dict() for s in self.suppressions.values()],
            "alerting": asdict(self.alerting),
            "detectors": self.detectors.to_dict(),
            **self._store_controls_dict(),
        }
        tmp = f"{self.path}.tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, self.path)  # atomic swap

    # ---- stores ----

    def _check_secrets(self, conn: dict) -> None:
        """Warn on (or, in strict mode, reject) plaintext secrets in ``conn``.

        A value is considered a plaintext secret when its key looks like a
        secret (``password``/``api_key``/``token``/``dsn``/...), it is not the
        masking sentinel ``"***"``, and it is not an indirect ``*_env`` /
        ``*_file`` reference. Empty values are ignored.
        """
        offenders = [
            k for k, v in conn.items()
            if _is_secret_key(k) and (
                (isinstance(v, str) and v and v != "***")
                or (isinstance(v, dict) and v))
        ]
        # A password inside a connection string is the same plaintext secret.
        offenders += [
            k for k, v in conn.items()
            if not _is_secret_key(k) and not is_reference_key(k)
            and any(c and c != MASK for c in _value_credentials(v))
        ]
        if not offenders:
            return
        hint = (", ".join(sorted(offenders)))
        if self.reject_plaintext_secrets:
            raise ValueError(
                f"plaintext secret(s) not allowed: {hint}. Reference a secret "
                f"indirectly with a '<key>_env' or '<key>_file' key instead."
            )
        logger.warning(
            "connector config contains plaintext secret(s): %s — prefer "
            "'<key>_env' / '<key>_file' references so secrets stay off disk.",
            hint,
        )

    def add_store(self, store_id: str, kind: str, *, conn: dict,
                  tenant_field: Optional[str] = None,
                  description: str = "") -> StoredStore:
        if kind not in AVAILABLE:
            raise ValueError(
                f"unknown connector kind: {kind!r}. "
                f"Available: {', '.join(AVAILABLE)}"
            )
        self._check_secrets(conn)
        # ADR 0003: a reference outside the allowlist is refused before it is
        # saved, not only when a connection is opened.
        check_references(conn)
        with self._locked_write():
            if store_id in self.stores:
                raise ValueError(f"store_id already exists: {store_id}")
            s = StoredStore(store_id=store_id, kind=kind, conn=conn,
                            tenant_field=tenant_field, description=description)
            self.stores[store_id] = s
            self._validate_on_build.add(store_id)
        return s

    def remove_store(self, store_id: str) -> None:
        with self._locked_write():
            self.stores.pop(store_id, None)
            self._validate_on_build.discard(store_id)
            # Per-store settings describe this registration; a store later
            # added under the same id starts without them. CCPA risk-assessment
            # versions are records and are kept.
            self.retention_schedules["stores"].pop(store_id, None)
            self.residency_policy["stores"].pop(store_id, None)
            self.inventory_declarations.pop(store_id, None)
            self.source_manifests.pop(store_id, None)
            # drop policies scoped to this store
            for pid in [p.id for p in self.policies.values()
                        if p.scope_store == store_id]:
                self.policies.pop(pid, None)

    def get_store(self, store_id: str) -> StoredStore:
        if store_id not in self.stores:
            raise KeyError(store_id)
        return self.stores[store_id]

    def update_store(self, store_id: str, *, kind: str, conn: dict,
                     tenant_field: Optional[str] = None,
                     description: str = "") -> StoredStore:
        """Replace a store's connector config in place.

        The ``store_id`` is immutable, so any policies scoped to this store are
        preserved untouched. Connection values that arrive as the masking
        sentinel (``"***"``), or as the masked form of a stored connection
        string, are kept from the existing config, so an edit round-trip never
        clobbers a secret that was masked in a prior GET. A masked secret is
        not carried over when the endpoint or connector kind changes: it must
        be re-entered, so an edit cannot send a stored credential to a host of
        the editor's choosing.
        """
        if kind not in AVAILABLE:
            raise ValueError(
                f"unknown connector kind: {kind!r}. "
                f"Available: {', '.join(AVAILABLE)}"
            )
        with self._locked_write():
            if store_id not in self.stores:
                raise KeyError(store_id)
            s = self.stores[store_id]
            merged, _missing = _unmask_conn(s.conn, conn,
                                            kind_changed=kind != s.kind)
            self._check_secrets(merged)
            check_references(merged)
            s.kind = kind
            s.conn = merged
            s.tenant_field = tenant_field
            s.description = description
            self._validate_on_build.add(store_id)
        return s

    def resolve_masked_conn(self, store_id: Optional[str], conn: dict, *,
                            kind: Optional[str] = None) -> dict:
        """The connection an edit would save, without saving it.

        ``"***"`` stands for the stored value, exactly as ``update_store``
        treats it — including refusing to carry it to a changed endpoint or,
        when ``kind`` is given, to a different connector kind. A masked value
        with nothing stored behind it cannot be tested, so it is refused
        rather than sent to the connector literally.
        """
        store = self.stores.get(store_id) if store_id else None
        stored = store.conn if store is not None else {}
        merged, missing = _unmask_conn(
            stored, conn,
            kind_changed=store is not None and kind is not None and kind != store.kind)
        if missing:
            raise ValueError(f"{missing[0]} is masked but no stored value exists; "
                             "enter it to test the connection")
        return merged

    def build_registry(self) -> StoreRegistry:
        """A registry of every stored store.

        A store whose secret reference cannot be resolved (an unset
        environment variable, an unreadable file) is registered as
        unavailable — opening it raises :class:`SecretResolutionError` naming
        the reference — so one broken store does not take every other store
        down with it, at startup or on an unrelated edit. A store just added
        or edited through this ConfigStore is still refused outright, so the
        admin who entered the reference hears about it.
        """
        with self._write_lock:
            just_changed, self._validate_on_build = self._validate_on_build, set()
        reg = StoreRegistry()
        for s in self.stores.values():
            try:
                conn = _resolve_secrets(s.conn)
            except SecretResolutionError as exc:
                if s.store_id in just_changed:
                    raise
                reason = str(exc)
                if isinstance(exc, SecretReferenceDenied):
                    # A reference saved before the allowlist existed (ADR 0003).
                    logger.warning(
                        "store %s is unavailable: %s. Move the secret to a "
                        "VECSHIELD_STORE_* variable or a file under "
                        "/run/secrets/vecshield/, or allow the exact name with "
                        "VECSHIELD_SECRET_ENV_ALLOW (see docs/adr/"
                        "0003-secret-reference-allowlist.md).", s.store_id, reason)
                else:
                    logger.warning("store %s is unavailable: %s", s.store_id, reason)
                reg.register(s.store_id, s.kind, tenant_field=s.tenant_field,
                             description=s.description, unavailable=reason,
                             factory=_unavailable_factory(s.store_id, reason))
                continue
            reg.register(s.store_id, s.kind, tenant_field=s.tenant_field,
                         description=s.description, **conn)
        return reg

    # ---- policies ----

    def add_policy(self, *, name: str, description: str, when: dict, action: str,
                   severity: str = "high", enabled: bool = True,
                   scope_store: Optional[str] = None,
                   scope_collection: Optional[str] = None,
                   template_id: Optional[str] = None) -> StoredPolicy:
        pid = f"pol-{uuid.uuid4().hex[:10]}"
        p = StoredPolicy(id=pid, name=name, description=description, when=when,
                         action=action, severity=severity, enabled=enabled,
                         scope_store=scope_store, scope_collection=scope_collection,
                         template_id=template_id)
        with self._locked_write():
            self.policies[pid] = p
        return p

    def add_policy_from_template(self, template_id: str, *,
                                 scope_store: Optional[str] = None,
                                 scope_collection: Optional[str] = None,
                                 name: Optional[str] = None,
                                 description: Optional[str] = None,
                                 when: Optional[dict[str, Any]] = None,
                                 action: Optional[str] = None,
                                 severity: Optional[str] = None,
                                 enabled: bool = True) -> StoredPolicy:
        t = get_template(template_id)
        if not t:
            raise ValueError(f"unknown template: {template_id}")
        return self.add_policy(
            name=name or t["name"],
            description=t["description"] if description is None else description,
            when=when or t["when"],
            action=action or t["action"],
            severity=severity or t["severity"],
            enabled=enabled,
            scope_store=scope_store, scope_collection=scope_collection,
            template_id=template_id)

    def update_policy(self, pid: str, **changes) -> StoredPolicy:
        with self._locked_write():
            if pid not in self.policies:
                raise KeyError(pid)
            p = self.policies[pid]
            for k, v in changes.items():
                if hasattr(p, k) and v is not None:
                    setattr(p, k, v)
        return p

    def remove_policy(self, pid: str) -> None:
        with self._locked_write():
            self.policies.pop(pid, None)

    def effective_policies(self, store_id: str) -> list[Policy]:
        """Enabled policies that apply to this store (global + store-scoped),
        as runtime Policy objects (collection scope folded into the matcher)."""
        out: list[Policy] = []
        for p in self.policies.values():
            if not p.enabled:
                continue
            if p.scope_store and p.scope_store != store_id:
                continue
            out.append(p.to_policy())
        return out

    # ---- allow-list (calibration) ----

    def add_allowlist_rule(self, *, reason: str,
                           category: Optional[str] = None,
                           store: Optional[str] = None,
                           collection: Optional[str] = None,
                           rule: Optional[str] = None,
                           fingerprints: Optional[list[str]] = None,
                           value_patterns: Optional[list[str]] = None,
                           owner: str = "") -> AllowlistRule:
        # Constructing the rule validates that it is scoped or has a matcher
        # (an unscoped rule would silence everything and raises).
        r = AllowlistRule(
            id=f"al-{uuid.uuid4().hex[:10]}", reason=reason, category=category,
            store=store, collection=collection, rule=rule,
            fingerprints=tuple(fingerprints or ()),
            value_patterns=tuple(value_patterns or ()),
            source="custom", owner=owner)
        with self._locked_write():
            self.allowlist[r.id] = r
        return r

    def remove_allowlist_rule(self, rid: str) -> None:
        with self._locked_write():
            self.allowlist.pop(rid, None)

    def effective_allowlist(self, *, include_builtin: bool = True) -> list[AllowlistRule]:
        """Allow-list rules to evaluate: curated built-ins plus custom rules."""
        rules: list[AllowlistRule] = []
        if include_builtin:
            rules.extend(builtin_allowlist())
        rules.extend(self.allowlist.values())
        return rules

    # ---- suppressions (risk acceptance) ----

    def add_suppression(self, *, fingerprint: str, reason: str, owner: str,
                        expires_at: str, ticket: Optional[str] = None,
                        category: Optional[str] = None,
                        severity: Optional[Severity] = None) -> Suppression:
        s = Suppression(fingerprint=fingerprint, reason=reason, owner=owner,
                        expires_at=expires_at, ticket=ticket)
        # Enforce mandatory expiry / sensitive-TTL guardrails before persisting.
        validate_suppression(s, category=category, severity=severity)
        with self._locked_write():
            self.suppressions[s.id] = s
        return s

    def remove_suppression(self, sid: str) -> None:
        with self._locked_write():
            self.suppressions.pop(sid, None)

    def active_suppressions(self, now=None) -> list[Suppression]:
        return [s for s in self.suppressions.values() if s.is_active(now)]

    # ---- alerting ----

    def get_alerting(self) -> AlertingConfig:
        return self.alerting

    def set_alerting(self, **changes) -> AlertingConfig:
        """Update the alerting config in place (only non-None fields).

        ``webhooks`` is normalized (bare URL strings become Slack entries) and
        ``min_severity`` is validated against the Severity enum.
        """
        with self._locked_write():
            # Built on a copy and swapped in only once every field validated:
            # a refused update must not leave half its changes in memory.
            a = copy.deepcopy(self.alerting)
            if changes.get("enabled") is not None:
                a.enabled = bool(changes["enabled"])
            if changes.get("console") is not None:
                a.console = bool(changes["console"])
            if changes.get("min_severity") is not None:
                Severity(str(changes["min_severity"]))  # validate
                a.min_severity = str(changes["min_severity"])
            if changes.get("webhooks") is not None:
                incoming = AlertingConfig.from_dict(
                    {"webhooks": changes["webhooks"]}).webhooks
                a.webhooks = _keep_masked_secrets(incoming, a.webhooks)
                # F2: https only, no internal or metadata destinations. A URL
                # already stored is checked again, since the rules (or what
                # its host resolves to) may have changed since it was saved.
                from vecshield_platform.runtime.sinks import validate_webhook_url
                for hook in a.webhooks:
                    validate_webhook_url(hook["url"], resolve=True)
            self.alerting = a
        return self.alerting

    # ---- runtime detector settings ----

    def get_detector_settings(self) -> DetectorSettings:
        return self.detectors

    # ---- store controls (retention, residency, processors, inventory) ----

    def _init_store_controls(self) -> None:
        self.retention_schedules: dict[str, Any] = {"global": None, "stores": {}}
        self.residency_policy: dict[str, Any] = {"default": None, "stores": {}}
        self.processor_register: list[dict] = []
        #: store_id -> {"store": {...}, "collections": {name: {...}}, "updated_*"}
        self.inventory_declarations: dict[str, dict] = {}
        #: store_id -> {"entries": [...], "updated_at", "updated_by"}
        self.source_manifests: dict[str, dict] = {}
        #: store_id -> {"versions": [...], "approvals": [...]} (append-only)
        self.ccpa_risk: dict[str, dict] = {}
        #: Secret references only (see VULNFEED_CREDENTIAL_KEYS).
        self.vulnfeed_credentials: dict[str, str] = {}

    def _load_store_controls(self, data: dict) -> None:
        # Loaded as saved: a schedule naming a detector a later release
        # renamed must not stop the server starting. Every value was
        # validated on write, and the audit path re-validates and records a
        # schedule that no longer validates rather than ignoring it.
        self._init_store_controls()
        rs = data.get("retention_schedules") or {}
        self.retention_schedules = {"global": rs.get("global"),
                                    "stores": dict(rs.get("stores") or {})}
        rp = data.get("residency_policy") or {}
        self.residency_policy = {"default": rp.get("default"),
                                 "stores": dict(rp.get("stores") or {})}
        self.processor_register = list(data.get("processor_register") or [])
        self.inventory_declarations = dict(data.get("inventory_declarations") or {})
        self.source_manifests = dict(data.get("source_manifests") or {})
        self.ccpa_risk = dict(data.get("ccpa_risk") or {})
        self.vulnfeed_credentials = dict(data.get("vulnfeed_credentials") or {})

    def _store_controls_dict(self) -> dict:
        return {
            "retention_schedules": self.retention_schedules,
            "residency_policy": self.residency_policy,
            "processor_register": self.processor_register,
            "inventory_declarations": self.inventory_declarations,
            "source_manifests": self.source_manifests,
            "ccpa_risk": self.ccpa_risk,
            "vulnfeed_credentials": self.vulnfeed_credentials,
        }

    def _store_ids(self, extra: Optional[Iterable[str]] = None) -> set[str]:
        return set(self.stores) | set(extra or ())

    def get_retention_schedules(self) -> dict:
        return copy.deepcopy(self.retention_schedules)

    def set_retention_schedules(self, document: Any, *,
                                known_stores: Optional[Iterable[str]] = None) -> dict:
        """Replace the whole ``{global, stores}`` document (store replaces global)."""
        value, problems = validate_retention_document(
            document, store_ids=self._store_ids(known_stores))
        if problems:
            raise SettingsError(problems)
        with self._locked_write():
            self.retention_schedules = value
        return copy.deepcopy(value)

    def get_residency_policy(self) -> dict:
        return copy.deepcopy(self.residency_policy)

    def set_residency_policy(self, document: Any, *,
                             known_stores: Optional[Iterable[str]] = None) -> dict:
        value, problems = validate_residency_document(
            document, store_ids=self._store_ids(known_stores))
        if problems:
            raise SettingsError(problems)
        with self._locked_write():
            self.residency_policy = value
        return copy.deepcopy(value)

    def residency_policy_for(self, store_id: str) -> tuple[Optional[dict], Optional[str]]:
        """The policy for ``store_id`` and where it came from (store/default)."""
        stores = self.residency_policy.get("stores") or {}
        if store_id in stores:
            return copy.deepcopy(stores[store_id]), "store"
        default = self.residency_policy.get("default")
        return (copy.deepcopy(default), "default") if default is not None else (None, None)

    def get_processor_register(self) -> list[dict]:
        return copy.deepcopy(self.processor_register)

    def set_processor_register(self, entries: Any) -> list[dict]:
        value, problems = validate_processor_register(entries)
        if problems:
            raise SettingsError(problems)
        with self._locked_write():
            self.processor_register = value
        return copy.deepcopy(value)

    def get_inventory_declarations(self, store_id: str) -> dict:
        found = self.inventory_declarations.get(store_id)
        return copy.deepcopy(found) if found else {"store": {}, "collections": {}}

    def set_inventory_declarations(self, store_id: str, document: Any, *,
                                   actor: str, now: str) -> dict:
        value, problems = validate_declarations(document)
        if problems:
            raise SettingsError(problems)
        with self._locked_write():
            self.inventory_declarations[store_id] = {**value, "updated_at": now,
                                                     "updated_by": actor}
        return copy.deepcopy(self.inventory_declarations[store_id])

    def get_source_manifest(self, store_id: str) -> Optional[dict]:
        found = self.source_manifests.get(store_id)
        return copy.deepcopy(found) if found else None

    def set_source_manifest(self, store_id: str, manifest: Any, *,
                            actor: str, now: str) -> Optional[dict]:
        """Save (or, with ``None``, clear) a store's source manifest."""
        entries, problems = validate_source_manifest(manifest)
        if problems:
            raise SettingsError(problems)
        with self._locked_write():
            if entries is None:
                self.source_manifests.pop(store_id, None)
                return None
            self.source_manifests[store_id] = {"entries": entries, "updated_at": now,
                                               "updated_by": actor,
                                               "hash": canonical_hash(entries)}
        return copy.deepcopy(self.source_manifests[store_id])

    def get_vulnfeed_credentials(self) -> dict:
        return dict(self.vulnfeed_credentials)

    def set_vulnfeed_credentials(self, refs: Any) -> dict:
        value, problems = validate_vulnfeed_credentials(refs)
        if problems:
            raise SettingsError(problems)
        with self._locked_write():
            self.vulnfeed_credentials = value
        return dict(value)

    # ---- CCPA risk-assessment inputs (append-only versions) ----

    def ccpa_record(self, store_id: str) -> dict:
        found = self.ccpa_risk.get(store_id) or {}
        return {"versions": copy.deepcopy(found.get("versions") or []),
                "approvals": copy.deepcopy(found.get("approvals") or [])}

    def add_ccpa_inputs(self, store_id: str, inputs: dict, *, actor: str, now: str,
                        problems: Optional[list[str]] = None) -> dict:
        """Append a new inputs version; earlier versions are never rewritten."""
        with self._locked_write():
            record = self.ccpa_risk.setdefault(store_id, {"versions": [], "approvals": []})
            versions = record.setdefault("versions", [])
            if len(versions) >= MAX_CCPA_VERSIONS:
                raise SettingsError([f"This store already has {MAX_CCPA_VERSIONS} input "
                                     "versions; archive the record before adding more."])
            entry = {"version": len(versions) + 1, "inputs": copy.deepcopy(inputs),
                     "saved_at": now, "saved_by": actor,
                     "hash": canonical_hash(inputs), "problems": list(problems or [])}
            versions.append(entry)
        return copy.deepcopy(entry)

    def approve_ccpa(self, store_id: str, *, version: int, actor: str, now: str,
                     note: str = "", position: str = "") -> dict:
        with self._locked_write():
            record = self.ccpa_risk.get(store_id) or {}
            versions = record.get("versions") or []
            if not versions:
                raise KeyError(store_id)
            if not 1 <= version <= len(versions):
                raise SettingsError([f"version {version} does not exist"])
            approval = {"version": version, "approved_by": actor, "approved_at": now,
                        "inputs_hash": versions[version - 1]["hash"]}
            if note:
                approval["note"] = note
            if position:
                approval["position"] = position
            record.setdefault("approvals", []).append(approval)
            self.ccpa_risk[store_id] = record
        return copy.deepcopy(approval)

    def set_detector_settings(self, **changes) -> DetectorSettings:
        with self._locked_write():
            merged = self.detectors.to_dict()
            for key, value in changes.items():
                if value is None:
                    continue
                if key == "cooldown_s":
                    merged[key] = value
                elif key in merged and isinstance(value, dict):
                    merged[key].update(value)
                else:
                    raise ValueError(f"unknown detector setting: {key}")
            self.detectors = DetectorSettings.from_dict(merged)
        return self.detectors


_warned_webhooks: set[str] = set()


def _warn_on_refused_webhooks(alerting: AlertingConfig) -> None:
    """Log, once per URL, a stored webhook that deliveries will now refuse.

    Config saved before webhook validation (F2) may hold an ``http://`` or
    internal URL. Loading it must not fail, so it is reported here and every
    delivery to it is refused (and counted as failed) until it is fixed.
    """
    from vecshield_platform.runtime.sinks import WebhookURLError, validate_webhook_url

    for hook in alerting.webhooks:
        url = hook.get("url", "")
        try:
            validate_webhook_url(url, resolve=False)
        except WebhookURLError as exc:
            if url not in _warned_webhooks:
                _warned_webhooks.add(url)
                logger.warning("stored webhook %s will not receive alerts: %s",
                               mask_webhook_url(url), exc)


def _resolve_secrets(conn: dict) -> dict:
    """Resolve indirect secret references (``*_env`` / ``*_file``) to real
    values at connect time. Thin wrapper over the pluggable resolver."""
    return resolve_conn(conn)


def _unavailable_factory(store_id: str, reason: str):
    def factory():
        raise SecretResolutionError(
            f"store '{store_id}' is unavailable: {reason}")
    return factory


def _value_credentials(value: Any) -> list[str]:
    """Credentials embedded in a connection value (a string or list of them)."""
    if isinstance(value, str):
        return embedded_credentials(value)
    if isinstance(value, (list, tuple)):
        return [c for item in value if isinstance(item, str)
                for c in embedded_credentials(item)]
    return []


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_credentials(value)
    if isinstance(value, (list, tuple)):
        return [redact_credentials(v) if isinstance(v, str) else v for v in value]
    return value


def _endpoint_key(key: str) -> bool:
    base = key
    for suffix in ("_env", "_file"):
        if key.endswith(suffix):
            base = key[: -len(suffix)]
            break
    return base.lower() in _ENDPOINT_KEYS


def _endpoint_view(conn: dict) -> dict:
    return {k: v for k, v in conn.items() if _endpoint_key(k)}


def _unmask_conn(stored: dict, incoming: dict, *,
                 kind_changed: bool = False) -> tuple[dict, list[str]]:
    """Resolve masked values in an edited connection to the stored secrets.

    Returns the merged connection and the keys that were ``"***"`` with no
    stored value behind them (left as they are; callers decide). A value is
    masked when it is ``"***"`` or when it is the public (credential-masked)
    form of the stored connection string. Raises ``ValueError`` when:

    * a connection string carries a masked credential but is not the stored
      string's masked form — the credential cannot be reconstructed; or
    * a stored secret would be carried over while an endpoint-defining key
      (host, url, uri, dsn, port, ...) or the connector kind changed. A
      viewer-visible mask must not become a way to send a stored credential
      to another host; the secret has to be re-entered.
    """
    merged = dict(incoming)
    carried: list[str] = []
    missing: list[str] = []
    for key, value in incoming.items():
        if value == MASK:
            if key not in stored:
                missing.append(key)
                continue
            merged[key] = stored[key]
            carried.append(key)
        elif MASK in _value_credentials(value):
            old = stored.get(key)
            if old is not None and _redact_value(old) == value:
                merged[key] = old
                if _value_credentials(old):
                    carried.append(key)
            else:
                raise ValueError(
                    f"{key} contains a masked credential but differs from the stored "
                    f"value; re-enter the full {key} including its credential")
    if carried:
        before, after = _endpoint_view(stored), _endpoint_view(merged)
        changed = sorted(k for k in set(before) | set(after)
                         if before.get(k) != after.get(k))
        if kind_changed or changed:
            what = "the connector kind" if kind_changed else ", ".join(changed)
            raise ValueError(
                f"{', '.join(sorted(carried))} is masked but {what} changed; "
                "re-enter the secret to use it with the new endpoint")
    return merged, missing


def _is_secret_key(key: str) -> bool:
    if is_reference_key(key):
        return False
    lk = key.lower()
    return lk in _SECRET_KEYS or any(part in lk for part in _SECRET_KEY_PARTS)


def _validate_detector_settings(data: dict[str, Any]) -> None:
    _positive_float(data.get("cooldown_s"), "cooldown_s", allow_zero=True)

    bulk = data["bulk_volume"]
    _bool(bulk.get("enabled"), "bulk_volume.enabled")
    _positive_int(bulk.get("threshold"), "bulk_volume.threshold")
    _positive_float(bulk.get("window_s"), "bulk_volume.window_s")
    _severity(bulk.get("severity"), "bulk_volume.severity")

    sweep = data["collection_sweep"]
    _bool(sweep.get("enabled"), "collection_sweep.enabled")
    _range_float(sweep.get("fraction"), "collection_sweep.fraction", 0.0, 1.0)
    _positive_float(sweep.get("window_s"), "collection_sweep.window_s")
    _severity(sweep.get("severity"), "collection_sweep.severity")

    enum = data["enumeration"]
    _bool(enum.get("enabled"), "enumeration.enabled")
    _range_float(enum.get("sim_threshold"), "enumeration.sim_threshold", -1.0, 1.0)
    _positive_int(enum.get("run_length"), "enumeration.run_length")
    _positive_float(enum.get("max_gap_s"), "enumeration.max_gap_s", allow_zero=True)
    _severity(enum.get("severity"), "enumeration.severity")

    rate = data["rate_baseline"]
    _bool(rate.get("enabled"), "rate_baseline.enabled")
    _positive_float(rate.get("window_s"), "rate_baseline.window_s")
    _positive_float(rate.get("spike_factor"), "rate_baseline.spike_factor")
    _positive_int(rate.get("warmup_samples"), "rate_baseline.warmup_samples", allow_zero=True)
    _positive_float(rate.get("min_rate"), "rate_baseline.min_rate", allow_zero=True)
    _range_float(rate.get("alpha"), "rate_baseline.alpha", 0.0, 1.0, lower_open=True)
    _severity(rate.get("severity"), "rate_baseline.severity")


def _bool(value: Any, field: str) -> None:
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be a boolean")


def _positive_int(value: Any, field: str, *, allow_zero: bool = False) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{field} must be an integer")
    if value < 0 or (value == 0 and not allow_zero):
        raise ValueError(f"{field} must be {'non-negative' if allow_zero else 'positive'}")


def _positive_float(value: Any, field: str, *, allow_zero: bool = False) -> None:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError(f"{field} must be a number")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError(f"{field} must be a finite number")
    if value < 0 or (value == 0 and not allow_zero):
        raise ValueError(f"{field} must be {'non-negative' if allow_zero else 'positive'}")


def _range_float(
    value: Any,
    field: str,
    lower: float,
    upper: float,
    *,
    lower_open: bool = False,
) -> None:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError(f"{field} must be a number")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError(f"{field} must be a finite number")
    lower_ok = value > lower if lower_open else value >= lower
    if not lower_ok or value > upper:
        left = "(" if lower_open else "["
        raise ValueError(f"{field} must be in range {left}{lower}, {upper}]")


def _severity(value: Any, field: str) -> None:
    try:
        Severity(str(value))
    except Exception as e:
        raise ValueError(f"{field} must be a valid severity") from e


# --------------------------------------------------------------------------- #
# Store controls: retention schedules, residency policy, processor register,  #
# inventory declarations, source manifests, CCPA inputs, feed credentials.     #
#                                                                              #
# Every validator is pure and returns ``(normalised, problems)`` so an editor  #
# can show every problem at once; the ConfigStore setters raise                #
# :class:`SettingsError` carrying that list and persist nothing on failure.    #
# --------------------------------------------------------------------------- #

class SettingsError(ValueError):
    """A settings document that cannot be saved. Lists every problem."""

    def __init__(self, problems: list[str]):
        self.problems = list(problems)
        super().__init__("; ".join(self.problems))


#: ISO 3166-1 alpha-2 codes (officially assigned), for residency policies.
ISO_COUNTRY_CODES = frozenset("""
AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM
BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX
CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG
GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR
IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV
LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE
NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO
RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF
TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF
WS YE YT ZA ZM ZW
""".split())

#: Data-subject regimes a residency policy may name. Only GDPR and UK_GDPR
#: have adequacy data (``posture/data/transfer_adequacy.json``); the others are
#: recorded with the policy and reported by the residency check as not
#: evaluated for transfer adequacy.
RESIDENCY_REGIMES = ("GDPR", "UK_GDPR", "SWISS_FADP", "CCPA", "HIPAA", "US_DOJ_DSP",
                     "PIPEDA", "LGPD", "APPI", "PIPL", "DPDP", "PDPA_SG")
RESIDENCY_POLICY_KEYS = ("allowed_regions", "allowed_countries", "allowed_jurisdictions",
                         "data_subject_regimes", "notes")
_JURISDICTION_TAGS = frozenset({"EU", "EEA", "UK"})

MAX_NOTE_CHARS = 2000
MAX_DECLARED_TEXT = 500
MAX_LIST_ITEMS = 200
MAX_PROCESSORS = 200
MAX_DECLARED_COLLECTIONS = 5000
#: A source manifest is kept in the config file, so it is capped; larger
#: document sets should be split per store or supplied by the CLI per run.
MAX_MANIFEST_ENTRIES = 20000
MAX_MANIFEST_VALUE = 2048
MAX_CCPA_VERSIONS = 500

#: Secret-reference keys the vulnerability feed accepts. Only references are
#: stored (the value of an env var or a mounted file is read at refresh time).
VULNFEED_CREDENTIAL_KEYS = ("github_token_env", "github_token_file",
                            "nvd_api_key_env", "nvd_api_key_file")


def canonical_hash(value: Any) -> Optional[str]:
    """SHA-256 of the canonical JSON of ``value``; None for None."""
    import hashlib

    if value is None:
        return None
    blob = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _text(value: Any, where: str, problems: list[str], *, limit: int,
          required: bool = False) -> Optional[str]:
    if value is None or (isinstance(value, str) and not value.strip()):
        if required:
            problems.append(f"{where} is required.")
        return None
    if not isinstance(value, str):
        problems.append(f"{where} must be text.")
        return None
    text = value.strip()
    if len(text) > limit:
        problems.append(f"{where} is longer than {limit} characters.")
        return None
    return text


def _str_list(value: Any, where: str, problems: list[str]) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
        problems.append(f"{where} must be a list of non-empty strings.")
        return []
    if len(value) > MAX_LIST_ITEMS:
        problems.append(f"{where} has more than {MAX_LIST_ITEMS} entries.")
        return []
    return [v.strip() for v in value]


def _region_ok(region: str) -> bool:
    """A region id the cloud catalogue knows, as ``region`` or ``cloud:region``."""
    from vecshield_platform.posture.residency import region_catalogue, resolve_region

    if ":" in region:
        cloud, name = region.split(":", 1)
        return resolve_region(cloud.strip().lower(), name.strip()) is not None
    clouds = [c for c in region_catalogue()["clouds"] if not c.startswith("_")]
    return any(resolve_region(cloud, region) is not None for cloud in clouds)


def validate_residency_policy(raw: Any, where: str = "policy"
                              ) -> tuple[Optional[dict], list[str]]:
    """Strictly validate one residency policy (``assess_residency``'s input)."""
    problems: list[str] = []
    if raw is None:
        return None, problems
    if not isinstance(raw, dict):
        return None, [f"{where} must be an object."]
    unknown = sorted(set(raw) - set(RESIDENCY_POLICY_KEYS))
    if unknown:
        problems.append(f"{where} has unknown fields: {', '.join(unknown)}.")
    regions = _str_list(raw.get("allowed_regions"), f"{where}.allowed_regions", problems)
    bad = [r for r in regions if not _region_ok(r)]
    if bad:
        problems.append(f"{where}.allowed_regions: not in the cloud region catalogue: "
                        f"{', '.join(bad[:10])}.")
    countries = [c.upper() for c in _str_list(raw.get("allowed_countries"),
                                              f"{where}.allowed_countries", problems)]
    countries = ["GB" if c == "UK" else c for c in countries]
    bad = [c for c in countries if c not in ISO_COUNTRY_CODES]
    if bad:
        problems.append(f"{where}.allowed_countries: not ISO 3166-1 alpha-2 codes: "
                        f"{', '.join(bad[:10])}.")
    jurisdictions = [j.upper() for j in _str_list(raw.get("allowed_jurisdictions"),
                                                  f"{where}.allowed_jurisdictions", problems)]
    bad = [j for j in jurisdictions if j not in _JURISDICTION_TAGS and j not in ISO_COUNTRY_CODES]
    if bad:
        problems.append(f"{where}.allowed_jurisdictions: expected EU, EEA, UK or an ISO "
                        f"country code, got: {', '.join(bad[:10])}.")
    regimes = [r.upper() for r in _str_list(raw.get("data_subject_regimes"),
                                            f"{where}.data_subject_regimes", problems)]
    bad = [r for r in regimes if r not in RESIDENCY_REGIMES]
    if bad:
        problems.append(f"{where}.data_subject_regimes: unknown regimes {', '.join(bad[:10])} "
                        f"(known: {', '.join(RESIDENCY_REGIMES)}).")
    notes = _text(raw.get("notes"), f"{where}.notes", problems, limit=MAX_NOTE_CHARS)
    if problems:
        return None, problems
    policy: dict[str, Any] = {
        "allowed_regions": sorted(set(regions)),
        "allowed_countries": sorted(set(countries)),
        "allowed_jurisdictions": sorted(set(jurisdictions)),
        "data_subject_regimes": sorted(set(regimes)),
    }
    if notes:
        policy["notes"] = notes
    return policy, problems


def _scoped_document(raw: Any, *, default_key: str, validate, store_ids,
                     label: str) -> tuple[dict, list[str]]:
    """``{<default_key>: item|None, stores: {id: item}}`` validated item by item."""
    if raw is None:
        return {default_key: None, "stores": {}}, []
    if not isinstance(raw, dict):
        return {}, [f"The {label} document must be an object."]
    problems: list[str] = []
    unknown = sorted(set(raw) - {default_key, "stores"})
    if unknown:
        problems.append(f"Unknown {label} fields: {', '.join(unknown)}.")
    default, found = validate(raw.get(default_key), default_key)
    problems.extend(found)
    stores_raw = raw.get("stores") or {}
    stores: dict[str, Any] = {}
    if not isinstance(stores_raw, dict):
        problems.append("'stores' must map store ids to entries.")
        stores_raw = {}
    for store_id, item in sorted(stores_raw.items()):
        if store_ids is not None and store_id not in store_ids:
            problems.append(f"stores.{store_id}: unknown store.")
            continue
        if item is None:
            continue  # no override: the default applies
        value, found = validate(item, f"stores.{store_id}")
        problems.extend(found)
        stores[store_id] = value
    return {default_key: default, "stores": stores}, problems


def validate_residency_document(raw: Any, *, store_ids=None) -> tuple[dict, list[str]]:
    return _scoped_document(raw, default_key="default", validate=validate_residency_policy,
                            store_ids=store_ids, label="residency policy")


def _validate_schedule_entry(raw: Any, where: str) -> tuple[Optional[dict], list[str]]:
    from vecshield_platform.scan.retention_schedule import ScheduleError, validate_schedule

    if raw is None:
        return None, []
    try:
        schedule = validate_schedule(raw)
    except ScheduleError as e:
        return None, [f"{where}: {p}" for p in e.problems]
    if schedule is None:
        # Declared as empty: for a store this deliberately replaces the
        # global schedule with "no schedule".
        return {"rules": [], "default_max_age_days": None, "default_basis": ""}, []
    return schedule.to_dict(), []


def validate_retention_document(raw: Any, *, store_ids=None) -> tuple[dict, list[str]]:
    """``{global, stores}`` in ``resolve_schedule``'s shape (store replaces global)."""
    return _scoped_document(raw, default_key="global", validate=_validate_schedule_entry,
                            store_ids=store_ids, label="retention schedule")


def validate_processor_register(raw: Any) -> tuple[list[dict], list[str]]:
    """The sub-processor register ``assess_model_egress`` reads."""
    from vecshield_platform.posture.egress import provider_registry

    if raw is None:
        return [], []
    if not isinstance(raw, list):
        return [], ["The processor register must be a list."]
    if len(raw) > MAX_PROCESSORS:
        return [], [f"The processor register has more than {MAX_PROCESSORS} entries."]
    registry = provider_registry()
    providers, aliases = registry["providers"], registry["aliases"]
    problems: list[str] = []
    out: list[dict] = []
    seen: set[str] = set()
    for index, item in enumerate(raw):
        where = f"Entry {index + 1}"
        found: list[str] = []
        if not isinstance(item, dict):
            problems.append(f"{where} must be an object.")
            continue
        unknown = sorted(set(item) - {"provider", "dpa", "baa", "regions", "notes"})
        if unknown:
            found.append(f"{where} has unknown fields: {', '.join(unknown)}.")
        provider = item.get("provider")
        pid: Optional[str] = None
        if isinstance(provider, str) and provider.strip():
            name = provider.strip()
            if name.lower().startswith("other:"):
                label = name.split(":", 1)[1].strip()
                if not label or len(label) > 200:
                    found.append(f"{where}: 'other:<name>' needs a name of 1-200 characters.")
                else:
                    pid = f"other:{label}"
            else:
                key = name.lower()
                key = aliases.get(key, key)
                if key in providers and key != "unknown":
                    pid = key
                else:
                    found.append(f"{where}: unknown provider {provider!r}; use a registry id "
                                 "(GET /admin/model-providers) or 'other:<name>'.")
        else:
            found.append(f"{where}: provider is required.")
        for flag in ("dpa", "baa"):
            if not isinstance(item.get(flag, False), bool):
                found.append(f"{where}: {flag} must be true or false.")
        regions = _str_list(item.get("regions"), f"{where}.regions", found)
        bad = [r for r in regions if not (_region_ok(r) or r.upper() in ISO_COUNTRY_CODES
                                          or r.upper() in _JURISDICTION_TAGS)]
        if bad:
            found.append(f"{where}.regions: not a catalogued cloud region, ISO country or "
                         f"EU/EEA/UK: {', '.join(bad[:10])}.")
        notes = _text(item.get("notes"), f"{where}.notes", found, limit=MAX_NOTE_CHARS)
        if pid is not None and pid in seen:
            found.append(f"{where}: duplicates an earlier entry for {pid}.")
        problems.extend(found)
        if found or pid is None:
            continue
        seen.add(pid)
        entry: dict[str, Any] = {"provider": pid, "dpa": item.get("dpa", False) is True,
                                 "baa": item.get("baa", False) is True,
                                 "regions": sorted(set(regions))}
        if notes:
            entry["notes"] = notes
        out.append(entry)
    return (out if not problems else []), problems


def _declared_block(raw: Any, fields: tuple[str, ...], where: str,
                    problems: list[str]) -> dict[str, Any]:
    from datetime import date

    if raw is None:
        return {}
    if not isinstance(raw, dict):
        problems.append(f"{where} must be an object.")
        return {}
    unknown = sorted(set(raw) - set(fields))
    if unknown:
        problems.append(f"{where} has unknown fields: {', '.join(unknown)} "
                        f"(allowed: {', '.join(fields)}).")
    out: dict[str, Any] = {}
    for name in fields:
        value = raw.get(name)
        if value is None or (isinstance(value, str) and not value.strip()):
            continue
        if name == "support_expiration_date":
            try:
                out[name] = date.fromisoformat(str(value).strip()).isoformat()
            except ValueError:
                problems.append(f"{where}.{name} must be an ISO date (YYYY-MM-DD).")
            continue
        if isinstance(value, bool) or not isinstance(value, (str, int, float)):
            problems.append(f"{where}.{name} must be text.")
            continue
        if isinstance(value, float) and not math.isfinite(value):
            problems.append(f"{where}.{name} must be a finite number.")
            continue
        text = value.strip() if isinstance(value, str) else value
        if isinstance(text, str) and len(text) > MAX_DECLARED_TEXT:
            problems.append(f"{where}.{name} is longer than {MAX_DECLARED_TEXT} characters.")
            continue
        out[name] = text
    return out


def validate_declarations(raw: Any) -> tuple[dict, list[str]]:
    """Owner, purpose, RTO, support contact/expiry for a store and its collections.

    Shape: ``{"store": {...}, "collections": {<name>: {...}}}`` — the
    ``declarations`` argument of ``inventory.build_inventory``.
    """
    from vecshield_platform.inventory import (COLLECTION_DECLARED_FIELDS,
                                                STORE_DECLARED_FIELDS)

    if raw is None:
        return {"store": {}, "collections": {}}, []
    if not isinstance(raw, dict):
        return {}, ["Declarations must be an object with 'store' and 'collections'."]
    problems: list[str] = []
    unknown = sorted(set(raw) - {"store", "collections"})
    if unknown:
        problems.append(f"Unknown declaration fields: {', '.join(unknown)}.")
    store = _declared_block(raw.get("store"), STORE_DECLARED_FIELDS, "store", problems)
    cols_raw = raw.get("collections") or {}
    collections: dict[str, dict] = {}
    if not isinstance(cols_raw, dict):
        problems.append("'collections' must map collection names to declarations.")
        cols_raw = {}
    if len(cols_raw) > MAX_DECLARED_COLLECTIONS:
        problems.append(f"More than {MAX_DECLARED_COLLECTIONS} collections declared.")
        cols_raw = {}
    for name, block in sorted(cols_raw.items()):
        if not name or len(name) > 512:
            problems.append("Collection names must be 1-512 characters.")
            continue
        value = _declared_block(block, COLLECTION_DECLARED_FIELDS,
                                f"collections.{name}", problems)
        if value:
            collections[name] = value
    return {"store": store, "collections": collections}, problems


def validate_source_manifest(raw: Any) -> tuple[Optional[list[dict]], list[str]]:
    """A customer list of ``{source, version|hash|updated_at|..., deleted}``.

    Only scalar values under the keys the chunk-versions check reads are kept.
    """
    from vecshield_platform.integrity.provenance import _SOURCE_KEYS
    from vecshield_platform.integrity.versions import _MANIFEST_VERSION_KEYS

    if raw is None:
        return None, []
    if isinstance(raw, dict) and set(raw) <= {"entries"}:
        raw = raw.get("entries")
    if not isinstance(raw, list):
        return None, ["A source manifest must be a list of entries (or {\"entries\": [...]})."]
    if len(raw) > MAX_MANIFEST_ENTRIES:
        return None, [f"A source manifest may hold at most {MAX_MANIFEST_ENTRIES} entries."]
    allowed = set(_SOURCE_KEYS) | set(_MANIFEST_VERSION_KEYS) | {"deleted"}
    problems: list[str] = []
    out: list[dict] = []
    for index, item in enumerate(raw):
        where = f"Entry {index + 1}"
        if not isinstance(item, dict):
            problems.append(f"{where} must be an object.")
            continue
        unknown = sorted(set(item) - allowed)
        if unknown:
            problems.append(f"{where} has unknown fields: {', '.join(unknown[:5])}.")
            continue
        if not any(isinstance(item.get(k), str) and str(item[k]).strip()
                   for k in _SOURCE_KEYS):
            problems.append(f"{where} needs a source identifier "
                            f"({', '.join(_SOURCE_KEYS[:3])}, ...).")
            continue
        if "deleted" in item and not isinstance(item["deleted"], bool):
            problems.append(f"{where}: deleted must be true or false.")
            continue
        entry: dict[str, Any] = {}
        for key, value in item.items():
            if key == "deleted":
                entry[key] = value
            elif isinstance(value, bool) or not isinstance(value, (str, int, float)):
                problems.append(f"{where}: {key} must be text or a number.")
                break
            elif isinstance(value, str) and len(value) > MAX_MANIFEST_VALUE:
                problems.append(f"{where}: {key} is longer than {MAX_MANIFEST_VALUE}.")
                break
            else:
                entry[key] = value
        else:
            out.append(entry)
        if len(problems) > 50:
            problems.append("Stopped after 50 problems.")
            break
    return (out if not problems else None), problems


def validate_vulnfeed_credentials(raw: Any) -> tuple[dict, list[str]]:
    """Secret *references* for the feed's optional GitHub/NVD tokens."""
    import re

    if raw is None:
        return {}, []
    if not isinstance(raw, dict):
        return {}, ["Feed credentials must be an object of secret references."]
    problems: list[str] = []
    out: dict[str, str] = {}
    for key, value in raw.items():
        if key not in VULNFEED_CREDENTIAL_KEYS:
            problems.append(f"{key}: only secret references are accepted "
                            f"({', '.join(VULNFEED_CREDENTIAL_KEYS)}); a token value is "
                            "never stored.")
            continue
        if value is None or value == "":
            continue
        if not isinstance(value, str) or len(value) > 1024:
            problems.append(f"{key} must be an environment variable name or a file path.")
            continue
        if key.endswith("_env") and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", value):
            problems.append(f"{key} must be an environment variable name.")
            continue
        if key.endswith("_file") and not os.path.isabs(value):
            problems.append(f"{key} must be an absolute path.")
            continue
        out[key] = value
    return out, problems


def merge_declarations(inventory: Optional[dict], declarations: Optional[dict]) -> Optional[dict]:
    """An inventory with the currently declared facts applied.

    Declarations saved after the audit still show; an undeclared field stays
    ``{"value": None, "declared": False}``. The inventory hash is recomputed
    so it matches what is served.
    """
    from vecshield_platform.inventory import (COLLECTION_DECLARED_FIELDS,
                                                STORE_DECLARED_FIELDS, inventory_hash)

    if inventory is None:
        return None
    inv = copy.deepcopy(inventory)
    decl = declarations or {}

    def apply(block: dict, fields: tuple[str, ...], supplied: dict) -> dict:
        block = dict(block or {})
        for name in fields:
            if supplied.get(name) is not None:
                block[name] = {"value": supplied[name], "declared": True}
            else:
                block.setdefault(name, {"value": None, "declared": False})
        return block

    store = inv.setdefault("store", {})
    store["declared"] = apply(store.get("declared"), STORE_DECLARED_FIELDS,
                              decl.get("store") or {})
    for col in inv.get("collections") or []:
        col["declared"] = apply(col.get("declared"), COLLECTION_DECLARED_FIELDS,
                                (decl.get("collections") or {}).get(col.get("name")) or {})
    totals = inv.get("totals")
    if isinstance(totals, dict):
        totals["undeclared_fields"] = sum(
            not entry.get("declared") for entry in store["declared"].values()) + sum(
            not entry.get("declared") for col in inv.get("collections") or []
            for entry in col["declared"].values())
    inv["inventory_hash"] = inventory_hash(inv)
    return inv
