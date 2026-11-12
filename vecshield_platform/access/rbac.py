"""RBAC diff: intended access policy vs. actual grants.

Pure set difference over AccessGrant tuples. Over-grants (present in actual but
not intended) are privilege-escalation risk; missing grants (intended but
absent) are reported at low severity as drift.
"""

from __future__ import annotations

import uuid

from vecshield.models import AccessGrant, Finding, MUTATING_ACTIONS, Severity

_MUTATING = {a.value for a in MUTATING_ACTIONS}


def grants_from_dicts(items: list[dict]) -> list[AccessGrant]:
    """Build AccessGrant tuples from plain dicts (e.g. loaded from JSON).

    Each item needs a 'principal' and 'action'; 'namespace' defaults to '*'
    (store-wide). Accepts either a string or an object with a '.value'
    attribute for 'action'.
    """
    grants: list[AccessGrant] = []
    for it in items:
        action = it["action"]
        grants.append(AccessGrant(
            principal=str(it["principal"]),
            namespace=str(it.get("namespace", "*")),
            action=action.value if hasattr(action, "value") else str(action),
        ))
    return grants


def diff_access(
    intended: list[AccessGrant],
    actual: list[AccessGrant],
    *,
    store_name: str = "unknown",
) -> list[Finding]:
    intended_set = {g.as_tuple() for g in intended}
    actual_set = {g.as_tuple() for g in actual}

    over = sorted(actual_set - intended_set)
    missing = sorted(intended_set - actual_set)
    findings: list[Finding] = []

    for principal, namespace, action in over:
        mutating = action in _MUTATING
        findings.append(
            Finding(
                id=f"find-{uuid.uuid4().hex[:10]}",
                title=f"Unintended grant: {principal} can {action} {namespace}",
                severity=Severity.HIGH if mutating else Severity.MEDIUM,
                category="access_control",
                store=store_name,
                collection=None if namespace == "*" else namespace,
                description=(
                    f"Principal '{principal}' has '{action}' on '{namespace}' in "
                    "the live policy but not in the intended policy "
                    f"({'mutating' if mutating else 'read'} access)."
                ),
                evidence={"principal": principal, "namespace": namespace,
                          "action": action},
                remediation=f"Revoke '{action}' on '{namespace}' from '{principal}' "
                            "or add it to the intended policy if legitimate.",
            )
        )

    for principal, namespace, action in missing:
        findings.append(
            Finding(
                id=f"find-{uuid.uuid4().hex[:10]}",
                title=f"Missing grant: {principal} should have {action} on {namespace}",
                severity=Severity.LOW,
                category="access_control",
                store=store_name,
                collection=None if namespace == "*" else namespace,
                description=(
                    f"Intended policy grants '{principal}' '{action}' on "
                    f"'{namespace}', but the live policy does not. Likely drift or "
                    "a broken integration."
                ),
                evidence={"principal": principal, "namespace": namespace,
                          "action": action},
                remediation="Reconcile the live policy with intent.",
            )
        )

    return findings
