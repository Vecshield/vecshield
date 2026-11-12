"""access_grants: who can read and change the vector tables, as the store reports it.

Judges the connector's ``access_model()`` against the cited rules in
``posture/data/pg_hardening_rules.json`` (section ``access_grants``):
whether the retrieval principal bypasses row security, owns a table its
policies do not bind, can write what it reads or administer roles, and
whether every role can read a table or plant objects in a schema the
extension or search path uses.

**The retrieval principal.** The rules about least privilege are about the
role the RAG application connects as. When the store declares it
(``retrieval_role``) the findings carry their full severity. When it does
not, VecShield assumes the role it connected as, says so in the title and
evidence, caps those findings at MEDIUM, and leaves the check inconclusive:
it cannot judge least privilege without knowing who retrieves. A superuser
or BYPASSRLS *auditor* is reported once, as ``privileged_auditor``, rather
than also as an assumed retrieval role.
"""

from __future__ import annotations

from typing import Any, Optional

from vecshield_platform.access.states import (
    ACCESS_GRANTS,
    NOT_OBSERVABLE,
    NOT_VERIFIED,
    OBSERVED_EXPOSURE,
    VERIFIED,
    access_outcome,
)
from vecshield_platform.posture.pg_hardening import pg_rules, rule_finding
from vecshield.models import Finding, Severity, VectorStore

_WRITE_PRIVILEGES = ("INSERT", "UPDATE", "DELETE", "TRUNCATE")

#: Rules whose subject is the retrieval principal; capped when it is assumed.
_PRINCIPAL_RULES = ("retrieval_superuser", "retrieval_bypassrls",
                    "retrieval_owner_without_force", "retrieval_can_write",
                    "retrieval_createrole")

_ASSUMED_SUFFIX = " (assumed retrieval role: the role VecShield connected as)"


def unsupported_access_grants(store: VectorStore, *, reason: str = "") -> dict:
    """The outcome for a connector that cannot report roles and grants."""
    return access_outcome(
        ACCESS_GRANTS, store.name, state=NOT_OBSERVABLE,
        reason=reason or "This connector does not report the store's roles and grants, "
                         "so least privilege of the retrieval credential is not assessed.",
        capability_limit=True)


def _hits(model: dict[str, Any]) -> list[tuple[str, Optional[str], str, dict]]:
    """``(rule id, collection, detail, evidence)`` for every rule that fires."""
    hits: list[tuple[str, Optional[str], str, dict]] = []
    auditor = model.get("observed_as") or {}
    principal = model.get("retrieval_principal") or {}
    tables = model.get("tables") or []
    rls_tables = [t["table"] for t in tables if t.get("rls")]
    known = principal.get("exists") is True
    name = principal.get("name")
    assumed = bool(principal.get("assumed"))

    privileged_auditor = bool(auditor.get("superuser") or auditor.get("bypassrls"))
    if privileged_auditor:
        attr = "a superuser" if auditor.get("superuser") else "a BYPASSRLS role"
        hits.append(("privileged_auditor", None,
                     f"VecShield connected as '{auditor.get('principal')}', {attr}. Row "
                     "security does not apply to it, so the tenant-isolation and retrieval "
                     "results show every row rather than what an application role sees.",
                     {"auditor": auditor.get("principal"),
                      "superuser": bool(auditor.get("superuser")),
                      "bypassrls": bool(auditor.get("bypassrls"))}))

    if known:
        superuser = bool(principal.get("superuser") or principal.get("member_of_superuser"))
        bypass = bool(principal.get("bypassrls") or principal.get("member_of_bypassrls"))
        # An assumed principal that is the privileged auditor is the same
        # fact as privileged_auditor; report it once.
        skip_bypass = assumed and privileged_auditor
        if superuser and not skip_bypass:
            via = principal.get("member_of_superuser") or []
            hits.append(("retrieval_superuser", None,
                         f"'{name}' " + ("is a superuser." if principal.get("superuser") else
                                         f"is a member of superuser role(s) {', '.join(via)}."),
                         {"member_of_superuser": via}))
        elif bypass and rls_tables and not skip_bypass:
            via = principal.get("member_of_bypassrls") or []
            hits.append(("retrieval_bypassrls", None,
                         f"'{name}' " + ("has BYPASSRLS" if principal.get("bypassrls") else
                                         f"is a member of BYPASSRLS role(s) {', '.join(via)}")
                         + f", and {len(rls_tables)} vector table(s) rely on row security: "
                         + ", ".join(rls_tables[:10]) + ".",
                         {"rls_tables": rls_tables[:20], "member_of_bypassrls": via}))
        if not superuser:
            for t in tables:
                if t.get("rls") and not t.get("force_rls") and t.get("owner") == name \
                        and not bypass:
                    hits.append(("retrieval_owner_without_force", t["table"],
                                 f"'{name}' owns '{t['table']}', whose {t.get('policies')} "
                                 "row-security polic(ies) do not apply to its owner.",
                                 {"owner": name, "policies": t.get("policies")}))
                writes = [p for p in t.get("retrieval_privileges") or []
                          if p in _WRITE_PRIVILEGES]
                if writes:
                    hits.append(("retrieval_can_write", t["table"],
                                 f"'{name}' holds {', '.join(writes)} on '{t['table']}'.",
                                 {"privileges": writes}))
            if principal.get("createrole"):
                hits.append(("retrieval_createrole", None,
                             f"'{name}' has CREATEROLE.", {}))

    for t in tables:
        ann = t.get("ann_index") or {}
        if t.get("rls") and ann and str(t.get("iterative_scan") or "").lower() == "off":
            setting = f"{ann.get('index_type')}.iterative_scan"
            hits.append(("rls_ann_without_iterative_scan", t["table"],
                         f"'{t['table']}' relies on row security and is searched through "
                         f"{ann.get('index_type')} index '{ann.get('index')}' with {setting} "
                         "off. The policies filter the rows the index returns, so a search "
                         "can return fewer results than asked for, or none. Nothing leaks: "
                         "rows the policies hide are never returned.",
                         {"index": ann.get("index"), "index_type": ann.get("index_type"),
                          "iterative_scan": t.get("iterative_scan"), "leaks_data": False}))
        if t.get("public_select") and not t.get("rls"):
            hits.append(("public_select_without_rls", t["table"],
                         f"PUBLIC holds SELECT on '{t['table']}' and row security is off, "
                         "so every role in the cluster can read all of its chunks.", {}))
    for s in model.get("schemas") or []:
        if s.get("public_create"):
            uses = " and ".join({"vector_extension": "holds the vector extension",
                                 "search_path": "is on the search path"}.get(u, u)
                                for u in s.get("uses") or [])
            hits.append(("public_create_on_schema", None,
                         f"PUBLIC holds CREATE on schema '{s['schema']}', which {uses}. A "
                         "role can create a same-named function or operator there that "
                         "other roles' queries then resolve to.",
                         {"schema": s["schema"], "uses": s.get("uses") or []}))
    return hits


def assess_access_grants(model: dict[str, Any],
                         store: VectorStore) -> tuple[list[Finding], dict]:
    """Findings and the ``access_grants`` outcome for one ``access_model()``."""
    readable = model.get("sections_readable") or {}
    reasons = model.get("reasons") or {}
    if model.get("engine") != "postgresql":
        return [], unsupported_access_grants(
            store, reason=f"No access rules exist yet for {model.get('engine') or 'this store'}.")
    if readable.get("roles") is not True:
        return [], access_outcome(
            ACCESS_GRANTS, store.name, state=NOT_OBSERVABLE,
            reason=reasons.get("roles") or "The store's roles could not be read.")

    rules = pg_rules("access_grants")
    principal = model.get("retrieval_principal") or {}
    assumed = bool(principal.get("assumed"))
    findings: list[Finding] = []
    for rule_id, collection, detail, evidence in _hits(model):
        rule = rules[rule_id]
        severity, suffix = None, ""
        if rule_id in _PRINCIPAL_RULES and assumed:
            declared = Severity(rule["severity"])
            severity = Severity.MEDIUM if declared.rank > Severity.MEDIUM.rank else declared
            suffix = _ASSUMED_SUFFIX
        findings.append(rule_finding(
            rule, store=store.name, category=ACCESS_GRANTS, collection=collection,
            detail=detail, severity=severity, title_suffix=suffix,
            evidence={"retrieval_principal": principal.get("name"),
                      "principal_assumed": assumed, **evidence}))

    unreadable = sorted(k for k, ok in readable.items() if ok is not True)
    worst = max((f.severity.rank for f in findings), default=-1)
    complete = bool(model.get("inventory_complete")) and not assumed
    coverage: dict[str, Any] = {
        "retrieval_principal": principal.get("name"),
        "principal_assumed": assumed,
        "auditor": (model.get("observed_as") or {}).get("principal"),
        "tables": len(model.get("tables") or []),
        "rls_tables": sum(1 for t in model.get("tables") or [] if t.get("rls")),
        "sections_not_readable": unreadable}
    notes = [reasons[k] for k in unreadable if reasons.get(k)]
    if principal.get("exists") is not True and reasons.get("retrieval_principal"):
        notes.insert(0, reasons["retrieval_principal"] + ".")
    if worst >= Severity.HIGH.rank:
        return findings, access_outcome(
            ACCESS_GRANTS, store.name, state=OBSERVED_EXPOSURE, outcome="failed",
            complete=complete, reason=" ".join(
                [f"{sum(1 for f in findings if f.severity.rank >= Severity.HIGH.rank)} "
                 "high or critical access finding(s)."] + notes), **coverage)
    if worst >= Severity.MEDIUM.rank:
        return findings, access_outcome(
            ACCESS_GRANTS, store.name, state=OBSERVED_EXPOSURE, outcome="inconclusive",
            complete=complete, reason=" ".join(
                ["Access weaknesses were observed whose weight depends on which roles "
                 "connect."] + (["The retrieval role was not declared; VecShield assumed "
                                 "the role it connected as."] if assumed else []) + notes),
            **coverage)
    if assumed:
        return findings, access_outcome(
            ACCESS_GRANTS, store.name, state=NOT_VERIFIED, complete=False,
            reason=" ".join(["No retrieval role is declared for this store, so least "
                             "privilege was judged for the role VecShield connected as. "
                             "Declare retrieval_role to assess the application's role."]
                            + notes), **coverage)
    if not complete:
        return findings, access_outcome(
            ACCESS_GRANTS, store.name, state=NOT_VERIFIED, complete=False,
            reason=" ".join(notes) or "Part of the access model could not be read.",
            **coverage)
    return findings, access_outcome(
        ACCESS_GRANTS, store.name, state=VERIFIED, complete=True,
        reason=f"'{principal.get('name')}' reads the vector tables without bypassing row "
               "security, writing them or administering roles.", **coverage)


def check_access_grants(connector: Any, store: VectorStore,
                        caps: set[str]) -> tuple[list[Finding], dict]:
    """Read the connector's access model (when it has one) and judge it."""
    if "access_introspection" not in caps:
        return [], unsupported_access_grants(store)
    try:
        model = connector.access_model()
    except Exception as exc:  # noqa: BLE001 - introspection must never break a scan
        return [], access_outcome(
            ACCESS_GRANTS, store.name, state=NOT_OBSERVABLE, outcome="error",
            reason=f"The access model could not be read ({type(exc).__name__}).")
    if not isinstance(model, dict):
        return [], unsupported_access_grants(store)
    return assess_access_grants(model, store)
