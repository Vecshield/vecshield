"""server_hardening: PostgreSQL configuration that weakens a pgvector store.

The rules, their severities and the documentation each rests on are data
(``posture/data/pg_hardening_rules.json``); the conditions are below, one
function per rule id. Inputs come from three reads the assessment already
makes:

* ``server_info`` features (store_facts/pgvector.py): ``settings`` — an
  allowlisted ``pg_settings`` snapshot — ``shared_preload_libraries``,
  ``extensions`` and ``pg_read_all_stats_members``;
* ``pg_hba_file_rules`` through the connector's ``tls_enforcement_info()``
  (superuser-only by default).

A rule whose inputs the auditing role could not read is listed as not
evaluated, with the reason, and never counts as passed. ``ssl``,
``listen_addresses`` and ``password_encryption`` are visible to every role;
``shared_preload_libraries`` and the ``pgaudit.*`` settings need
``pg_read_all_settings``.
"""

from __future__ import annotations

import json
import uuid
from functools import lru_cache
from importlib import resources
from typing import Any, Callable, Optional

from vecshield_platform.coverage import check_outcome
from vecshield.models import Finding, Severity, VectorStore

SERVER_HARDENING = "server_hardening"

#: The ``pg_settings`` names store_facts reads, and nothing else.
SETTINGS = ("ssl", "ssl_min_protocol_version", "password_encryption", "listen_addresses",
            "log_statement", "log_parameter_max_length", "log_min_error_statement",
            "shared_preload_libraries", "pgaudit.log", "pgaudit.log_parameter")

_LOOPBACK_LISTENERS = {"localhost", "127.0.0.1", "::1", ""}


@lru_cache(maxsize=1)
def _rules_file() -> dict[str, Any]:
    text = resources.files("vecshield_platform.posture").joinpath(
        "data/pg_hardening_rules.json").read_text(encoding="utf-8")
    return json.loads(text)


def pg_rules(section: str) -> dict[str, dict[str, Any]]:
    """``{rule id: rule}`` for ``server_hardening`` or ``access_grants``."""
    return {r["id"]: dict(r) for r in _rules_file()[section]}


def rule_finding(rule: dict[str, Any], *, store: str, category: str,
                 collection: Optional[str] = None, detail: str = "",
                 evidence: Optional[dict] = None,
                 severity: Optional[Severity] = None, title_suffix: str = "") -> Finding:
    """A finding built from a cited rule: its title, quote and remediation."""
    return Finding(
        id=f"find-{uuid.uuid4().hex[:10]}",
        title=rule["title"] + title_suffix,
        severity=severity or Severity(rule["severity"]),
        category=category,
        store=store,
        collection=collection,
        description=(f"{detail} " if detail else "") + f"Rule: {rule['threshold']}.",
        evidence={"rule": rule["id"], "source_url": rule["source_url"],
                  "quote": rule["quote"], **(evidence or {})},
        remediation=rule["remediation"],
    )


# ----------------------------------------------------------------- inputs #

def _settings(features: dict[str, Any]) -> dict[str, str]:
    """``features.settings`` (pg_settings rows) as ``{name: setting}``."""
    raw = features.get("settings")
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    out: dict[str, str] = {}
    for row in raw if isinstance(raw, list) else []:
        if isinstance(row, dict) and row.get("name") in SETTINGS:
            out[str(row["name"])] = str(row.get("setting") or "")
    return out


def _listens_remotely(value: Optional[str]) -> Optional[bool]:
    if value is None:
        return None
    entries = {e.strip().strip("'\"").lower() for e in value.split(",")}
    return bool(entries - _LOOPBACK_LISTENERS)


def _on(value: Optional[str]) -> Optional[bool]:
    if value is None:
        return None
    return value.strip().lower() in ("on", "true", "1", "yes")


def _pgaudit_loaded(features: dict[str, Any]) -> Optional[bool]:
    preload = features.get("shared_preload_libraries")
    if not isinstance(preload, list):
        return None
    return any(str(p).lower() == "pgaudit" for p in preload)


# ---------------------------------------------------------------- rules #
#
# Each returns None when an input is unreadable, else a list of
# (detail, evidence, collection) — empty when the rule does not fire.

Hit = tuple[str, dict[str, Any], Optional[str]]


def _weak_hba(method: str) -> Callable[[dict, Optional[dict]], Optional[list[Hit]]]:
    def rule(_features: dict, hba: Optional[dict]) -> Optional[list[Hit]]:
        if not hba or hba.get("readable") is not True:
            return None
        lines = [r for r in (hba.get("evidence") or {}).get("weak_auth_rules") or []
                 if r.get("auth_method") == method]
        if not lines:
            return []
        numbers = ", ".join(str(r.get("line")) for r in lines[:10])
        return [(f"pg_hba.conf line(s) {numbers} use {method} for non-local clients.",
                 {"hba_lines": lines[:10]}, None)]
    return rule


def _ssl_off_remote(features: dict, _hba: Optional[dict]) -> Optional[list[Hit]]:
    settings = _settings(features)
    ssl, remote = _on(settings.get("ssl")), _listens_remotely(settings.get("listen_addresses"))
    if ssl is None or remote is None:
        return None
    if ssl or not remote:
        return []
    return [(f"ssl is off and listen_addresses is '{settings['listen_addresses']}'.",
             {"ssl": settings["ssl"], "listen_addresses": settings["listen_addresses"]}, None)]


def _password_md5(features: dict, _hba: Optional[dict]) -> Optional[list[Hit]]:
    value = _settings(features).get("password_encryption")
    if value is None:
        return None
    if value.strip().lower() != "md5":
        return []
    return [("password_encryption is md5.", {"password_encryption": value}, None)]


def _log_statement(features: dict, _hba: Optional[dict]) -> Optional[list[Hit]]:
    settings = _settings(features)
    value = settings.get("log_statement")
    if value is None:
        return None
    if value.strip().lower() not in ("mod", "all"):
        return []
    evidence = {"log_statement": value}
    if settings.get("log_parameter_max_length") is not None:
        evidence["log_parameter_max_length"] = settings["log_parameter_max_length"]
    reach = ("every statement, including retrieval queries and their query vectors"
             if value.strip().lower() == "all" else
             "every INSERT, UPDATE and COPY FROM, so ingested chunk text and embeddings")
    return [(f"log_statement is '{value}': the server log records {reach}.", evidence, None)]


def _pgaudit_parameters(features: dict, _hba: Optional[dict]) -> Optional[list[Hit]]:
    settings = _settings(features)
    loaded = _pgaudit_loaded(features)
    if loaded is None:
        return None
    if not loaded:
        return []
    classes = settings.get("pgaudit.log")
    parameter = _on(settings.get("pgaudit.log_parameter"))
    if classes is None or parameter is None:
        return None
    logged = {c.strip().lower() for c in classes.split(",")}
    if not parameter or not logged & {"read", "write", "all"}:
        return []
    return [(f"pgaudit.log is '{classes}' with pgaudit.log_parameter on.",
             {"pgaudit.log": classes, "pgaudit.log_parameter": settings["pgaudit.log_parameter"]},
             None)]


def _stat_statements(features: dict, _hba: Optional[dict]) -> Optional[list[Hit]]:
    extensions = features.get("extensions")
    members = features.get("pg_read_all_stats_members")
    if not isinstance(extensions, dict):
        return None
    if "pg_stat_statements" not in extensions:
        return []
    if not isinstance(members, list):
        return None
    if not members:
        return []
    return [(f"Login roles that can read every role's statement text: "
             f"{', '.join(members[:10])}.", {"roles": members[:20]}, None)]


def _tls_min(features: dict, _hba: Optional[dict]) -> Optional[list[Hit]]:
    settings = _settings(features)
    ssl, minimum = _on(settings.get("ssl")), settings.get("ssl_min_protocol_version")
    if ssl is None or minimum is None:
        return None
    if not ssl or minimum.strip() not in ("TLSv1", "TLSv1.1"):
        return []
    return [(f"ssl_min_protocol_version is {minimum}.",
             {"ssl_min_protocol_version": minimum}, None)]


def _no_pgaudit(features: dict, _hba: Optional[dict]) -> Optional[list[Hit]]:
    loaded = _pgaudit_loaded(features)
    if loaded is None:
        return None
    if loaded:
        return []
    return [("shared_preload_libraries does not load pgaudit, so reads of the vector "
             "tables are not recorded by the database.",
             {"shared_preload_libraries": features.get("shared_preload_libraries")}, None)]


CONDITIONS: dict[str, Callable[[dict, Optional[dict]], Optional[list[Hit]]]] = {
    "hba_trust_remote": _weak_hba("trust"),
    "ssl_off_remote_listener": _ssl_off_remote,
    "password_encryption_md5": _password_md5,
    "hba_md5_remote": _weak_hba("md5"),
    "hba_password_remote": _weak_hba("password"),
    "log_statement_records_data": _log_statement,
    "pgaudit_logs_parameters": _pgaudit_parameters,
    "pg_stat_statements_readers": _stat_statements,
    "ssl_min_protocol_below_tls12": _tls_min,
    "no_pgaudit": _no_pgaudit,
}

#: Products with hardening rules. Others report the check unsupported.
PRODUCTS = ("postgresql",)


def check_server_hardening(store: VectorStore, server_info: Optional[dict], *,
                           hba: Optional[dict] = None,
                           info_error: str = "") -> tuple[list[Finding], dict]:
    """Evaluate every rule; return findings and the check outcome.

    ``server_info`` is the store_facts record (``product``, ``features``);
    ``hba`` the connector's ``tls_enforcement_info()``, or None when it has
    none. Rules with an unreadable input are listed as not evaluated.
    """
    product = (server_info or {}).get("product")
    if not server_info or not server_info.get("version"):
        return [], check_outcome(
            SERVER_HARDENING, store.name, None, outcome="inconclusive",
            reason=info_error or (server_info or {}).get("reason")
            or "The server's configuration could not be read.")
    if product not in PRODUCTS:
        return [], check_outcome(
            SERVER_HARDENING, store.name, None, outcome="unsupported",
            reason=f"VecShield has no server-hardening rules for {product or 'this store'}.",
            capability_limit=True)
    features = server_info.get("features") or {}
    rules = pg_rules("server_hardening")
    findings: list[Finding] = []
    evaluated, not_evaluated, fired = [], [], []
    for rule_id, condition in CONDITIONS.items():
        rule = rules[rule_id]
        hits = condition(features, hba)
        if hits is None:
            not_evaluated.append({"rule": rule_id, "inputs": rule.get("inputs", [])})
            continue
        evaluated.append(rule_id)
        if hits:
            fired.append(rule_id)
        for detail, evidence, collection in hits:
            findings.append(rule_finding(rule, store=store.name, category=SERVER_HARDENING,
                                         collection=collection, detail=detail,
                                         evidence=evidence))
    worst = max((f.severity.rank for f in findings), default=-1)
    complete = not not_evaluated
    if worst >= Severity.HIGH.rank:
        outcome = "failed"
    elif complete:
        outcome = "passed"
    else:
        outcome = "inconclusive"
    reasons = []
    if fired:
        reasons.append(f"{len(fired)} of {len(evaluated)} evaluated rules fired.")
    if not_evaluated:
        reasons.append(f"{len(not_evaluated)} rule(s) could not be evaluated because "
                       "their settings were not readable by the auditing role "
                       "(pg_hba_file_rules needs superuser or a grant; "
                       "shared_preload_libraries and pgaudit.* need pg_read_all_settings).")
    return findings, check_outcome(
        SERVER_HARDENING, store.name, None, outcome=outcome, complete=complete,
        reason=" ".join(reasons) or "Every rule was evaluated and none fired.",
        rules_evaluated=evaluated, rules_fired=fired, rules_not_evaluated=not_evaluated,
        rules_reviewed_at=_rules_file().get("reviewed_at"))
