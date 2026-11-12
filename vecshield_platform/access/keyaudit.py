"""API key / credential auditor.

Pure function over a list of ApiKey objects so it's testable without a live
store and reusable across connectors. Flags over-privilege (wildcard scope,
mutating actions on sensitive namespaces, admin) and hygiene issues (stale or
never-used keys).
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from vecshield.models import (
    Action,
    ApiKey,
    Finding,
    MUTATING_ACTIONS,
    Severity,
)


#: Names that suggest a credential is used by more than one person or service.
#: PCI DSS Requirement 8.2.1 prohibits shared, group and generic IDs outright —
#: it is a rule, not a risk judgement — and HIPAA 45 CFR 164.312(a)(2)(i) makes
#: unique user identification a *required* implementation specification.
#:
#: A name is evidence of sharing, not proof of it. The finding says so, and it
#: is rated MEDIUM rather than HIGH for that reason: a key called "default" may
#: well have one owner, and a key called "svc-ingest-prod" may be pasted into
#: six laptops. What a name can do is tell a reviewer where to look.
#: Only words that name a *collective or generic principal*. An earlier draft
#: also matched environment and purpose words — prod, staging, backup,
#: migration — and that was wrong: "svc-ingest-prod" tells you where a key is
#: used, not that two people hold it. Those matches are noise, and a hygiene
#: check that cries wolf is one a team turns off.
SHARED_KEY_NAME_HINTS = (
    "default", "shared", "common", "generic", "team", "group", "everyone",
    "admin", "root", "service", "svc",
)

#: Age at which a credential is old enough that a reviewer should be able to
#: point at a rotation record. PCI DSS Requirement 8.3.9 and the key-management
#: requirements in 3.7 both turn on a defined interval; this is a default, not
#: the standard's number, and it is configurable for that reason.
DEFAULT_ROTATION_DAYS = 365


def shared_name_hint(name: str) -> Optional[str]:
    """The hint a key name matches, or None. Whole words only.

    Substring matching would flag "svcatalog" for "svc" and "prodigy" for
    "prod", which is how a hygiene check becomes noise a team switches off.
    """
    tokens = {t for t in re.split(r"[^a-z0-9]+", (name or "").lower()) if t}
    for hint in SHARED_KEY_NAME_HINTS:
        if hint in tokens:
            return hint
    return None


def audit_api_keys(
    keys: list[ApiKey],
    *,
    store_name: str = "unknown",
    sensitive_namespaces: Optional[set[str]] = None,
    stale_days: int = 90,
    rotation_days: int = DEFAULT_ROTATION_DAYS,
    now: Optional[datetime] = None,
) -> list[Finding]:
    now = now or datetime.now(timezone.utc)
    sensitive_namespaces = sensitive_namespaces or set()
    cutoff = now - timedelta(days=stale_days)
    findings: list[Finding] = []

    def add(title, severity, key, desc, remediation):
        findings.append(
            Finding(
                id=f"find-{uuid.uuid4().hex[:10]}",
                title=title,
                severity=severity,
                category="access_control",
                store=store_name,
                description=desc,
                evidence={"key_id": key.id, "key_name": key.name,
                          "actions": key.actions, "namespaces": key.namespaces},
                remediation=remediation,
            )
        )

    for key in keys:
        mutating = [a for a in key.actions if a in {x.value for x in MUTATING_ACTIONS}]
        is_admin = key.can(Action.ADMIN)

        # --- over-privilege ---
        if key.has_wildcard and (mutating or is_admin):
            add(
                f"Over-privileged key '{key.name or key.id}': mutating access to all namespaces",
                Severity.HIGH, key,
                f"Key grants {sorted(set(mutating)) or ['admin']} across ALL namespaces "
                "(wildcard scope). A leak of this key compromises every collection.",
                "Scope the key to the specific namespaces it needs and drop "
                "write/delete/admin unless required. Prefer per-service keys.",
            )
        elif key.has_wildcard:
            add(
                f"Broad read key '{key.name or key.id}': read access to all namespaces",
                Severity.MEDIUM, key,
                "Key can read every collection (wildcard scope). Read-only, but a "
                "leak exposes all data — including any PII/PHI-bearing collections.",
                "Restrict the key to required namespaces.",
            )
        elif is_admin:
            add(
                f"Admin key '{key.name or key.id}'",
                Severity.HIGH, key,
                "Key holds admin rights. Admin keys should be rare, named, and "
                "tightly held.",
                "Replace with least-privilege keys for routine operations.",
            )

        # --- mutating access to sensitive namespaces ---
        risky_ns = sorted(
            ns for ns in key.namespaces
            if ns in sensitive_namespaces and (mutating or key.has_wildcard)
        )
        if risky_ns:
            add(
                f"Key '{key.name or key.id}' can mutate sensitive namespace(s)",
                Severity.HIGH, key,
                f"Key has {sorted(set(mutating)) or ['wildcard']} on sensitive "
                f"namespace(s): {risky_ns}. Deletion or poisoning of sensitive data "
                "is possible with this credential.",
                "Make sensitive collections read-only for this key, or remove access.",
            )

        # --- hygiene: stale / unused ---
        if key.last_used is not None and key.last_used < cutoff:
            days = (now - key.last_used).days
            add(
                f"Stale key '{key.name or key.id}' (unused {days}d)",
                Severity.MEDIUM, key,
                f"Key has not been used in {days} days (> {stale_days}d). Stale "
                "credentials widen the attack surface with no operational benefit.",
                "Rotate or revoke unused keys.",
            )
        # --- shared or generic identity (PCI Req 8.2.1) ---
        hint = shared_name_hint(key.name or "")
        if hint:
            add(
                f"Key '{key.name or key.id}' is named as a shared credential",
                Severity.MEDIUM, key,
                f"The name contains '{hint}', which suggests the key is used by "
                "more than one person or service. PCI DSS Requirement 8.2.1 "
                "prohibits shared, group and generic IDs, and HIPAA "
                "45 CFR 164.312(a)(2)(i) requires unique user identification. "
                "A name is evidence of sharing, not proof of it: confirm who "
                "holds this key before acting on it.",
                "Issue one credential per person or per service, named for its "
                "holder, so use can be attributed. Revoke the shared key once "
                "its holders have their own.",
            )

        # --- rotation age (PCI Req 8.3.9, 3.7) ---
        if key.created_at is not None:
            age = (now - key.created_at).days
            if age > rotation_days:
                add(
                    f"Key '{key.name or key.id}' has not been rotated in {age}d",
                    Severity.MEDIUM, key,
                    f"The credential was created {age} days ago, beyond the "
                    f"{rotation_days}-day interval this check was configured "
                    "with. VecShield sees creation time, not rotation history: "
                    "a key re-issued under the same record would look the same. "
                    "The rotation interval itself is set by your policy, not by "
                    "this tool.",
                    "Rotate the credential and record when. If the interval is "
                    "wrong for this store, configure it rather than ignoring "
                    "the finding.",
                )

        if key.last_used is None and key.created_at is not None and key.created_at < cutoff:
            add(
                f"Never-used key '{key.name or key.id}'",
                Severity.LOW, key,
                "Key was created over the staleness window ago and has never been "
                "used.",
                "Revoke if it isn't needed.",
            )

    return findings


def api_keys_from_dicts(items: list[dict[str, Any]]) -> list[ApiKey]:
    """Parse provider/API key inventory exports into VecShield ApiKey objects.

    Expected fields are intentionally simple and provider-neutral:
    id, name, actions, namespaces, last_used, created_at, metadata.
    Datetimes may be ISO-8601 strings or omitted.
    """
    keys: list[ApiKey] = []
    for item in items:
        keys.append(ApiKey(
            id=str(item.get("id") or item.get("key_id") or item.get("name") or ""),
            name=str(item.get("name") or ""),
            actions=[str(a) for a in item.get("actions", [])],
            namespaces=[str(n) for n in item.get("namespaces", [])],
            last_used=_parse_dt(item.get("last_used")),
            created_at=_parse_dt(item.get("created_at")),
            metadata=dict(item.get("metadata", {}) or {}),
        ))
    return keys


def _parse_dt(value) -> Optional[datetime]:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        s = value.replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            return None
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return None
