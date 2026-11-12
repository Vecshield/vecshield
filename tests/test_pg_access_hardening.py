"""access_grants and server_hardening: the pgvector access and hardening rules.

The evaluators are pure functions over the connector's access model and the
store_facts server record, so these tests build those dicts directly. The
catalog reads behind them are covered in test_pgvector_unit.py, and against a
real server in tests/integration/test_pgvector_integration.py.
"""

from __future__ import annotations

import copy
import json
from importlib import resources

import pytest

from vecshield_platform.access.grants import _hits as access_hits
from vecshield_platform.access.grants import assess_access_grants, check_access_grants
from vecshield_platform.access.states import access_outcome
from vecshield_platform.posture.pg_hardening import (
    CONDITIONS,
    check_server_hardening,
    pg_rules,
)
from vecshield.models import Severity, VectorStore

STORE = VectorStore(kind="pgvector", name="pg", endpoint="host=db dbname=app")


def _model(**overrides):
    model = {
        "engine": "postgresql",
        "observed_as": {"principal": "vs_auditor", "superuser": False, "bypassrls": False,
                        "createrole": False},
        "retrieval_principal": {"name": "rag_reader", "assumed": False, "exists": True,
                                "superuser": False, "bypassrls": False,
                                "createrole": False, "can_login": True,
                                "member_of_superuser": [], "member_of_bypassrls": []},
        "tables": [{"table": "docs", "owner": "app_owner", "rls": True, "force_rls": False,
                    "public_select": False, "policies": 1,
                    "retrieval_privileges": ["SELECT"]}],
        "schemas": [{"schema": "public", "public_create": False,
                     "uses": ["vector_extension", "search_path"]}],
        "functions": {"vector_leakproof_functions": 0, "security_definer_executable": []},
        "sections_readable": {"roles": True, "tables": True, "policies": True,
                              "grants": True, "schemas": True, "functions": True},
        "reasons": {},
        "inventory_complete": True,
    }
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(model.get(key), dict):
            model[key] = {**model[key], **value}
        else:
            model[key] = value
    return model


def _rules(findings):
    return sorted(f.evidence["rule"] for f in findings)


# ------------------------------------------------------------------ states -- #

def test_access_states_mirror_crypto_states():
    with pytest.raises(ValueError):
        access_outcome("access_grants", "pg", state="nonsense")
    with pytest.raises(ValueError):
        access_outcome("access_grants", "pg", state="observed_exposure")
    with pytest.raises(ValueError):
        access_outcome("access_grants", "pg", state="not_observable", outcome="failed")
    out = access_outcome("access_grants", "pg", state="not_observable")
    assert out["outcome"] == "unsupported"
    assert out["coverage"]["access_state"] == "not_observable"


# ------------------------------------------------------------ access_grants -- #

def test_a_least_privileged_declared_role_is_verified():
    findings, outcome = assess_access_grants(_model(), STORE)
    assert findings == []
    assert outcome["outcome"] == "passed" and outcome["coverage"]["complete"] is True
    assert outcome["coverage"]["access_state"] == "verified"
    assert outcome["coverage"]["retrieval_principal"] == "rag_reader"


@pytest.mark.parametrize("principal,rule", [
    ({"superuser": True}, "retrieval_superuser"),
    ({"member_of_superuser": ["postgres"]}, "retrieval_superuser"),
    ({"bypassrls": True}, "retrieval_bypassrls"),
    ({"member_of_bypassrls": ["etl_admin"]}, "retrieval_bypassrls"),
])
def test_a_retrieval_role_that_bypasses_row_security_is_critical(principal, rule):
    findings, outcome = assess_access_grants(
        _model(retrieval_principal=principal), STORE)
    assert _rules(findings) == [rule]
    assert findings[0].severity is Severity.CRITICAL
    assert outcome["outcome"] == "failed"
    assert outcome["coverage"]["access_state"] == "observed_exposure"


def test_bypassrls_matters_only_where_row_security_is_relied_on():
    tables = [dict(_model()["tables"][0], rls=False)]
    findings, _ = assess_access_grants(
        _model(retrieval_principal={"bypassrls": True}, tables=tables), STORE)
    assert "retrieval_bypassrls" not in _rules(findings)


def test_owner_without_force_and_write_grants_are_high_per_table():
    tables = [{"table": "docs", "owner": "rag_reader", "rls": True, "force_rls": False,
               "public_select": False, "policies": 2,
               "retrieval_privileges": ["SELECT", "INSERT", "DELETE"]}]
    findings, outcome = assess_access_grants(_model(tables=tables), STORE)
    assert _rules(findings) == ["retrieval_can_write", "retrieval_owner_without_force"]
    assert {f.collection for f in findings} == {"docs"}
    assert all(f.severity is Severity.HIGH for f in findings)
    write = next(f for f in findings if f.evidence["rule"] == "retrieval_can_write")
    assert write.evidence["privileges"] == ["INSERT", "DELETE"]
    assert outcome["outcome"] == "failed"


def test_force_row_security_binds_the_owner():
    tables = [dict(_model()["tables"][0], owner="rag_reader", force_rls=True)]
    findings, _ = assess_access_grants(_model(tables=tables), STORE)
    assert findings == []


def test_public_reads_without_rls_and_public_create_are_principal_independent():
    tables = [dict(_model()["tables"][0], rls=False, public_select=True)]
    schemas = [{"schema": "public", "public_create": True, "uses": ["search_path"]}]
    findings, outcome = assess_access_grants(
        _model(tables=tables, schemas=schemas,
               retrieval_principal={"assumed": True}), STORE)
    by_rule = {f.evidence["rule"]: f for f in findings}
    # Not capped: they do not depend on who retrieves.
    assert by_rule["public_select_without_rls"].severity is Severity.HIGH
    assert by_rule["public_create_on_schema"].severity is Severity.MEDIUM
    assert "search path" in by_rule["public_create_on_schema"].description
    assert outcome["outcome"] == "failed"


def test_a_medium_weakness_alone_is_inconclusive_not_failed():
    schemas = [{"schema": "public", "public_create": True,
                "uses": ["vector_extension"]}]
    findings, outcome = assess_access_grants(_model(schemas=schemas), STORE)
    assert _rules(findings) == ["public_create_on_schema"]
    assert outcome["outcome"] == "inconclusive"
    assert outcome["coverage"]["access_state"] == "observed_exposure"


def test_an_assumed_principal_is_capped_and_labelled():
    tables = [dict(_model()["tables"][0],
                   retrieval_privileges=["SELECT", "INSERT", "UPDATE"])]
    findings, outcome = assess_access_grants(
        _model(tables=tables, retrieval_principal={"assumed": True, "name": "vs_auditor"}),
        STORE)
    assert _rules(findings) == ["retrieval_can_write"]
    assert findings[0].severity is Severity.MEDIUM
    assert "assumed retrieval role" in findings[0].title
    assert findings[0].evidence["principal_assumed"] is True
    assert outcome["outcome"] == "inconclusive" and outcome["coverage"]["complete"] is False


def test_an_assumed_clean_principal_is_not_verified():
    findings, outcome = assess_access_grants(
        _model(retrieval_principal={"assumed": True}), STORE)
    assert findings == []
    assert outcome["outcome"] == "inconclusive"
    assert outcome["coverage"]["access_state"] == "not_verified"
    assert "retrieval_role" in outcome["reason"]


def test_a_superuser_auditor_is_reported_once_as_privileged_auditor():
    auditor = {"principal": "postgres", "superuser": True, "bypassrls": True,
               "createrole": True}
    principal = {"name": "postgres", "assumed": True, "superuser": True, "bypassrls": True,
                 "createrole": True}
    findings, outcome = assess_access_grants(
        _model(observed_as=auditor, retrieval_principal=principal), STORE)
    assert _rules(findings) == ["privileged_auditor"]
    assert findings[0].severity is Severity.LOW
    assert "tenant-isolation" in findings[0].description
    assert outcome["outcome"] == "inconclusive"


def test_a_privileged_auditor_and_a_declared_superuser_role_are_both_reported():
    auditor = {"principal": "postgres", "superuser": True, "bypassrls": False,
               "createrole": False}
    findings, _ = assess_access_grants(
        _model(observed_as=auditor, retrieval_principal={"superuser": True}), STORE)
    assert _rules(findings) == ["privileged_auditor", "retrieval_superuser"]


def test_a_declared_role_that_does_not_exist_is_not_verified():
    model = _model(retrieval_principal={"name": "typo", "assumed": False, "exists": False},
                   inventory_complete=False,
                   reasons={"retrieval_principal": "the declared retrieval role 'typo' "
                                                   "does not exist in this database"})
    findings, outcome = assess_access_grants(model, STORE)
    assert findings == []
    assert outcome["outcome"] == "inconclusive"
    assert "'typo' does not exist" in outcome["reason"]


def test_unreadable_roles_are_not_observable_never_failed():
    model = _model(sections_readable={"roles": False},
                   reasons={"roles": "pg_roles could not be read (permission denied)"})
    findings, outcome = assess_access_grants(model, STORE)
    assert findings == []
    assert outcome["outcome"] == "unsupported"
    assert outcome["coverage"]["access_state"] == "not_observable"
    assert "permission denied" in outcome["reason"]


def test_a_partly_unreadable_model_is_not_verified():
    model = _model(sections_readable={"policies": False}, inventory_complete=False,
                   reasons={"policies": "pg_policy could not be read (permission denied)"})
    _findings, outcome = assess_access_grants(model, STORE)
    assert outcome["outcome"] == "inconclusive"
    assert outcome["coverage"]["sections_not_readable"] == ["policies"]
    assert "pg_policy" in outcome["reason"]


class _Conn:
    def __init__(self, result):
        self.result = result

    def access_model(self):
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def test_a_connector_without_the_capability_is_a_capability_limit():
    _findings, outcome = check_access_grants(_Conn(_model()), STORE, set())
    assert outcome["outcome"] == "unsupported"
    assert outcome["coverage"]["capability_limit"] is True
    assert outcome["coverage"]["access_state"] == "not_observable"


def test_a_failing_access_model_is_an_error_not_a_pass():
    _findings, outcome = check_access_grants(_Conn(RuntimeError("boom")), STORE,
                                             {"access_introspection"})
    assert outcome["outcome"] == "error"


# ---------------------------------------------------------- server_hardening -- #

def _info(settings=None, **features):
    base = {"ssl": "on", "ssl_min_protocol_version": "TLSv1.2",
            "password_encryption": "scram-sha-256", "listen_addresses": "*",
            "log_statement": "none", "log_parameter_max_length": "-1",
            "log_min_error_statement": "error"}
    base.update(settings or {})
    feats = {"settings": base, "shared_preload_libraries": ["pgaudit"],
             "extensions": {"vector": "0.8.7"}}
    feats["settings"].setdefault("pgaudit.log", "ddl")
    feats["settings"].setdefault("pgaudit.log_parameter", "off")
    feats.update(features)
    return {"product": "postgresql", "version": "16.4", "features": feats}


_HBA_OK = {"readable": True, "evidence": {"weak_auth_rules": []}}


def test_a_hardened_server_passes_every_rule():
    findings, outcome = check_server_hardening(STORE, _info(), hba=_HBA_OK)
    assert findings == []
    assert outcome["outcome"] == "passed" and outcome["coverage"]["complete"] is True
    assert sorted(outcome["coverage"]["rules_evaluated"]) == sorted(CONDITIONS)


@pytest.mark.parametrize("settings,features,rule,severity", [
    ({"ssl": "off"}, {}, "ssl_off_remote_listener", Severity.HIGH),
    ({"password_encryption": "md5"}, {}, "password_encryption_md5", Severity.MEDIUM),
    ({"log_statement": "all"}, {}, "log_statement_records_data", Severity.MEDIUM),
    ({"log_statement": "mod"}, {}, "log_statement_records_data", Severity.MEDIUM),
    ({"pgaudit.log": "read,ddl", "pgaudit.log_parameter": "on"}, {},
     "pgaudit_logs_parameters", Severity.MEDIUM),
    ({}, {"extensions": {"vector": "0.8.7", "pg_stat_statements": "1.10"},
          "pg_read_all_stats_members": ["reporting"]},
     "pg_stat_statements_readers", Severity.MEDIUM),
    ({"ssl_min_protocol_version": "TLSv1.1"}, {}, "ssl_min_protocol_below_tls12",
     Severity.LOW),
    ({}, {"shared_preload_libraries": ["pg_stat_statements"]}, "no_pgaudit", Severity.LOW),
])
def test_each_rule_fires_with_its_cited_severity(settings, features, rule, severity):
    findings, _ = check_server_hardening(STORE, _info(settings, **features), hba=_HBA_OK)
    assert _rules(findings) == [rule]
    assert findings[0].severity is severity
    assert findings[0].category == "server_hardening"
    cited = pg_rules("server_hardening")[rule]
    assert findings[0].evidence["source_url"] == cited["source_url"]
    assert findings[0].evidence["quote"] == cited["quote"]


def test_settings_arrive_as_pg_settings_rows_from_store_facts():
    info = _info()
    info["features"]["settings"] = [
        {"name": name, "setting": value}
        for name, value in dict(info["features"]["settings"],
                                password_encryption="md5").items()]
    findings, _ = check_server_hardening(STORE, info, hba=_HBA_OK)
    assert _rules(findings) == ["password_encryption_md5"]


def test_ssl_off_on_a_loopback_listener_is_not_a_finding():
    findings, _ = check_server_hardening(
        STORE, _info({"ssl": "off", "listen_addresses": "localhost, ::1"}), hba=_HBA_OK)
    assert findings == []


@pytest.mark.parametrize("method,rule,severity", [
    ("trust", "hba_trust_remote", Severity.CRITICAL),
    ("md5", "hba_md5_remote", Severity.MEDIUM),
    ("password", "hba_password_remote", Severity.MEDIUM),
])
def test_weak_hba_methods(method, rule, severity):
    hba = {"readable": True, "evidence": {"weak_auth_rules": [
        {"line": 7, "type": "host", "auth_method": method}]}}
    findings, outcome = check_server_hardening(STORE, _info(), hba=hba)
    assert _rules(findings) == [rule]
    assert findings[0].severity is severity
    assert "line(s) 7" in findings[0].description
    assert outcome["outcome"] == ("failed" if severity.rank >= Severity.HIGH.rank
                                  else "passed")


def test_unreadable_inputs_leave_rules_not_evaluated_never_passed():
    """What a least-privileged role sees: no hba, no superuser-only settings."""
    info = _info()
    for name in ("pgaudit.log", "pgaudit.log_parameter"):
        info["features"]["settings"].pop(name)
    info["features"].pop("shared_preload_libraries")
    hba = {"readable": False, "plaintext_accepted": None}
    findings, outcome = check_server_hardening(STORE, info, hba=hba)
    assert findings == []
    assert outcome["outcome"] == "inconclusive" and outcome["coverage"]["complete"] is False
    not_evaluated = {r["rule"] for r in outcome["coverage"]["rules_not_evaluated"]}
    assert {"hba_trust_remote", "hba_md5_remote", "hba_password_remote",
            "pgaudit_logs_parameters", "no_pgaudit"} == not_evaluated
    assert "pg_read_all_settings" in outcome["reason"]


def test_other_products_are_unsupported_and_an_unread_server_is_inconclusive():
    other = {"product": "qdrant", "version": "1.9.0", "features": {}}
    _f, outcome = check_server_hardening(STORE, other)
    assert outcome["outcome"] == "unsupported" and outcome["coverage"]["capability_limit"]
    _f, outcome = check_server_hardening(STORE, {"product": "postgresql", "version": None,
                                                 "reason": "permission denied"})
    assert outcome["outcome"] == "inconclusive" and "permission denied" in outcome["reason"]


# ------------------------------------------------------------- rules file -- #

def _rules_file():
    return json.loads(resources.files("vecshield_platform.posture").joinpath(
        "data/pg_hardening_rules.json").read_text(encoding="utf-8"))


def test_every_rule_has_code_a_citation_and_a_known_severity():
    data = _rules_file()
    assert set(r["id"] for r in data["server_hardening"]) == set(CONDITIONS)
    hits = {rule for model in _models_firing_every_rule()
            for rule, *_rest in access_hits(model)}
    assert set(r["id"] for r in data["access_grants"]) == hits
    assert [r["id"] for r in data["tenant_isolation"]] == ["ann_filter_without_iterative_scan"]
    for rule in data["server_hardening"] + data["access_grants"] + data["tenant_isolation"]:
        assert rule["source_url"].startswith("https://"), rule["id"]
        assert len(rule["quote"]) > 20, rule["id"]
        assert Severity(rule["severity"]), rule["id"]
        assert rule["threshold"] and rule["remediation"], rule["id"]


def _models_firing_every_rule():
    """Three models that between them fire every access rule."""
    model = _model(observed_as={"superuser": True},
                   tables=[{"table": "a", "owner": "rag_reader", "rls": True,
                            "force_rls": False, "public_select": False, "policies": 1,
                            "retrieval_privileges": ["SELECT", "INSERT"],
                            "ann_index": {"index": "a_hnsw", "index_type": "hnsw",
                                          "metric": "cosine"},
                            "iterative_scan": "off"},
                           {"table": "b", "owner": "x", "rls": False, "force_rls": False,
                            "public_select": True, "policies": 0,
                            "retrieval_privileges": ["SELECT"]}],
                   schemas=[{"schema": "public", "public_create": True,
                             "uses": ["search_path"]}],
                   retrieval_principal={"createrole": True})
    super_model = copy.deepcopy(model)
    super_model["retrieval_principal"]["superuser"] = True
    bypass_model = copy.deepcopy(model)
    bypass_model["retrieval_principal"]["member_of_bypassrls"] = ["r"]
    return [model, super_model, bypass_model]


# ---------------------------------------------------------------- engine -- #

class _PgStore:
    kind = "pgvector"

    def __init__(self, model, info=None, hba=None):
        self.model, self.info, self.hba = model, info, hba

    def capabilities(self):
        return {"access_introspection", "tls_enforcement_introspection"}

    def describe(self):
        return VectorStore(kind="pgvector", name="pg", endpoint="host=10.0.0.7 dbname=app")

    def access_model(self):
        return self.model

    def tls_enforcement_info(self):
        return self.hba


def test_posture_audit_records_access_grants_and_its_findings():
    from vecshield_platform.posture import run_posture_audit

    job = run_posture_audit(_PgStore(_model(retrieval_principal={"superuser": True})),
                            resolve_dns=False, include_cve=False, include_auth=False)
    grants = next(o for o in job.stats["check_outcomes"] if o["check"] == "access_grants")
    assert grants["outcome"] == "failed"
    assert grants["coverage"]["access_state"] == "observed_exposure"
    assert "access_grants" in job.stats["checks"]
    assert [f.evidence["rule"] for f in job.findings
            if f.category == "access_grants"] == ["retrieval_superuser"]


def test_server_hardening_runs_for_pgvector_and_is_unsupported_elsewhere():
    from vecshield_platform.posture.engine import _server_hardening

    hba = {"readable": True, "evidence": {"weak_auth_rules": [
        {"line": 3, "type": "host", "auth_method": "trust"}]}}
    findings, outcome = _server_hardening(_PgStore(_model(), hba=hba), STORE,
                                          lambda: _info())
    assert outcome["outcome"] == "failed"
    assert [f.evidence["rule"] for f in findings] == ["hba_trust_remote"]

    class _Other(_PgStore):
        kind = "qdrant"

    _f, outcome = _server_hardening(_Other(_model()), STORE, lambda: _info())
    assert outcome["outcome"] == "unsupported" and outcome["coverage"]["capability_limit"]

    def refused():
        raise PermissionError("denied")

    _f, outcome = _server_hardening(_PgStore(_model(), hba=hba), STORE, refused)
    assert outcome["outcome"] == "inconclusive" and "PermissionError" in outcome["reason"]


def test_remediation_and_policies_know_the_new_checks():
    from vecshield_platform import remediation
    from vecshield_platform.compliance.policy import evaluate_policies
    from vecshield_platform.posture import posture_policies

    findings, _ = assess_access_grants(_model(retrieval_principal={"bypassrls": True}),
                                       STORE)
    found = findings[0]
    finding = {"id": found.id, "title": found.title, "category": found.category,
               "severity": found.severity.value, "description": found.description,
               "remediation": found.remediation, "evidence": found.evidence}
    assert remediation.finding_kind(finding) == "access_grants"
    guided = remediation.catalogue(finding, store_id="pg", store_kind="pgvector").guided
    assert len(guided) == 1 and guided[0].steps[0] == found.remediation
    assert any(found.evidence["source_url"] in step for step in guided[0].steps)
    fired = {v.policy_id for v in evaluate_policies(posture_policies(), findings)}
    assert {"no-rls-bypass-on-retrieval", "retrieval-credential-least-privilege"} <= fired


def test_retrieval_role_reaches_the_connector_from_config_and_cli(monkeypatch):
    import sys
    import types

    from vecshield_platform.cli import _CONNECTOR_OPTIONS
    from vecshield_platform.connectors import build_connector

    fake = types.ModuleType("psycopg")
    fake.connect = lambda *a, **k: object()
    monkeypatch.setitem(sys.modules, "psycopg", fake)
    conn = build_connector("pgvector", dsn="host=db dbname=app", retrieval_role=" rag_reader ")
    assert conn._retrieval_role == "rag_reader"
    assert build_connector("pgvector", dsn="host=db")._retrieval_role is None
    # And the CLI offers it as --retrieval-role.
    names = {p.name for opt in _CONNECTOR_OPTIONS for p in opt(lambda **k: None).__click_params__}
    assert "retrieval_role" in names


@pytest.mark.parametrize("iterative,fires", [("off", True), ("strict_order", False),
                                             (None, False)])
def test_row_security_on_an_approximate_index_is_low_and_says_nothing_leaks(iterative,
                                                                            fires):
    tables = [dict(_model()["tables"][0],
                   ann_index={"index": "docs_hnsw", "index_type": "hnsw", "metric": "l2"},
                   iterative_scan=iterative)]
    findings, outcome = assess_access_grants(_model(tables=tables), STORE)
    if not fires:
        assert findings == [] and outcome["outcome"] == "passed"
        return
    [finding] = findings
    assert finding.evidence["rule"] == "rls_ann_without_iterative_scan"
    assert finding.severity is Severity.LOW and finding.collection == "docs"
    assert "Nothing leaks" in finding.description
    assert outcome["outcome"] == "passed"  # LOW does not fail or blur the check


def test_the_isolation_availability_finding_has_its_own_remediation():
    from vecshield_platform import remediation

    finding = {"id": "f1", "category": "isolation", "severity": "low",
               "title": "Filtered searches on the approximate index can come back short "
                        "in 'docs'",
               "description": "d", "remediation": "ALTER ROLE app SET ...",
               "evidence": {"index_type": "ivfflat", "source_url": "https://x",
                            "quote": "q"}}
    assert remediation.finding_kind(finding) == "ann_post_filter"
    [guide] = remediation.catalogue(finding, store_id="pg", store_kind="pgvector").guided
    assert guide.settings[0].key == "ivfflat.iterative_scan"
    assert guide.settings[0].value == "relaxed_order"
    assert any("bypasses row security" in step for step in guide.steps)
