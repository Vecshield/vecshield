"""The crypto gate blocks on observed failures, and evidence clears only gaps."""

from __future__ import annotations

from datetime import datetime, timezone

from click.testing import CliRunner
from test_criteria import api_client

from vecshield.models import Finding, ScanJob, Severity
from vecshield_platform.coverage import check_outcome
from vecshield_platform.crypto import crypto_outcome
from vecshield_platform.crypto.gate import (
    DECISIONS,
    accepted_pairs,
    default_gate_rules,
    evaluate_gate,
)
from vecshield_platform.orchestrator import AuditResult

A2IV = ("HIPAA-164-312-A2IV-ENCRYPTION-01", "encryption_at_rest_statement")


#: A collection read and classified in full, so the labels are established.
CLASSIFIED = check_outcome("data_classification", "s", "docs", outcome="passed",
                           complete=True, chunks_scanned=10, chunks_expected=10)


def snapshot(*outcomes, labels=(), audit_id="audit-g", classified=True):
    findings = [{"category": "data_classification",
                 "evidence": {"label_counts": {label: 3 for label in labels}}}]
    return {"id": audit_id, "finished_at": "2026-09-24T10:00:00+00:00",
            "jobs": [{"findings": findings}],
            "check_outcomes": ([CLASSIFIED] if classified else []) + list(outcomes)}


def rule(result, rule_id):
    return next(r for r in result["rules"] if r["id"] == rule_id)


NOT_SUPPORTED = check_outcome(
    "at_rest_encryption", "s", outcome="unsupported",
    reason="Qdrant has no encryption-at-rest setting in its API.",
    crypto_state="not_observable", support="not_supported", capability_limit=True)
VERIFIED = crypto_outcome("at_rest_encryption", "s", state="verified", complete=True)


def test_rules_are_well_formed():
    rules = default_gate_rules()
    assert len({r.id for r in rules}) == len(rules)
    assert all(r.decision in DECISIONS for r in rules)


def test_a_clean_audit_passes():
    result = evaluate_gate(snapshot(VERIFIED, labels=["pii"]), store_id="s")
    assert result["decision"] == "pass"
    assert "not a compliance determination" in result["note"]


def test_readable_full_pan_blocks_and_no_document_clears_it():
    pan = crypto_outcome("pan_representation", "s", "cards", state="observed_exposure",
                         outcome="failed", complete=True, reason="5 full PANs")
    everything = {pair for r in default_gate_rules() for pair in r.cleared_by}
    result = evaluate_gate(snapshot(pan, VERIFIED, labels=["pci"]), store_id="s",
                           accepted_evidence=everything)
    assert result["decision"] == "block"
    assert rule(result, "pan-must-be-unreadable")["status"] == "fired"
    assert "[cards]" in rule(result, "pan-must-be-unreadable")["reasons"][0]


def test_phi_where_at_rest_cannot_be_verified_blocks_until_the_statement_is_accepted():
    blocked = evaluate_gate(snapshot(NOT_SUPPORTED, labels=["phi"]), store_id="s")
    assert blocked["decision"] == "block"
    assert {"criterion_id": A2IV[0], "requirement": A2IV[1]} in blocked["evidence_needed"]
    cleared = evaluate_gate(snapshot(NOT_SUPPORTED, labels=["phi"]), store_id="s",
                            accepted_evidence={A2IV})
    assert cleared["decision"] == "pass"
    assert rule(cleared, "phi-needs-verified-at-rest")["status"] == "cleared"
    assert rule(cleared, "phi-needs-verified-at-rest")["cleared_by"] == [
        {"criterion_id": A2IV[0], "requirement": A2IV[1]}]


def test_phi_with_verified_encryption_at_rest_does_not_trigger():
    result = evaluate_gate(snapshot(VERIFIED, labels=["phi"]), store_id="s")
    assert rule(result, "phi-needs-verified-at-rest")["status"] == "not_triggered"


def test_an_audit_that_never_checked_at_rest_cannot_clear_phi():
    result = evaluate_gate(snapshot(labels=["phi"]), store_id="s")
    fired = rule(result, "phi-needs-verified-at-rest")
    assert fired["status"] == "fired"
    assert "was not recorded in this audit" in fired["reasons"][-1]


def test_encryption_reported_off_blocks_even_with_a_statement():
    off = crypto_outcome("at_rest_encryption", "s", state="observed_exposure",
                         outcome="failed", complete=True)
    result = evaluate_gate(snapshot(off, labels=["phi"]), store_id="s",
                           accepted_evidence={A2IV})
    assert result["decision"] == "block"
    assert rule(result, "at-rest-encryption-reported-off")["status"] == "fired"


def test_plaintext_transport_blocks_only_where_the_data_is_sensitive():
    plaintext = crypto_outcome("transport_encryption", "s", state="observed_exposure",
                               outcome="failed", complete=True)
    assert evaluate_gate(snapshot(plaintext, VERIFIED, labels=["pii"]),
                         store_id="s")["decision"] == "block"
    assert evaluate_gate(snapshot(plaintext, VERIFIED),
                         store_id="s")["decision"] == "pass"


def test_a_required_at_rest_policy_requests_evidence_and_evidence_clears_it():
    requested = evaluate_gate(snapshot(NOT_SUPPORTED), store_id="s",
                              settings={"requires_at_rest_encryption": True})
    assert requested["decision"] == "request_evidence"
    assert evaluate_gate(snapshot(NOT_SUPPORTED), store_id="s")["decision"] == "pass"
    cleared = evaluate_gate(snapshot(NOT_SUPPORTED), store_id="s",
                            settings={"requires_at_rest_encryption": True},
                            accepted_evidence={("SOC2-CC6.1-ENCRYPTION-01",
                                                "encryption_policy")})
    assert cleared["decision"] == "pass"


def test_protection_drift_warns():
    drift = crypto_outcome("data_representation", "s", "patients",
                           state="observed_exposure", outcome="failed", complete=True)
    assert evaluate_gate(snapshot(drift, VERIFIED), store_id="s")["decision"] == "warn"


def test_only_usable_artifacts_for_this_store_count_as_accepted():
    reviews = [
        {"state": "accepted", "requirement": A2IV[1], "criterion_id": A2IV[0],
         "artifact_id": "ok", "scope": "s"},
        {"state": "accepted", "requirement": "encryption_policy",
         "criterion_id": "SOC2-CC6.1-ENCRYPTION-01", "artifact_id": "revoked", "scope": ""},
        {"state": "accepted", "requirement": "encryption_risk_assessment",
         "criterion_id": "GDPR-32-1A-ENCRYPTION-01", "artifact_id": "ok",
         "scope": "other-store"},
        {"state": "submitted", "requirement": "x", "criterion_id": "y",
         "artifact_id": "ok", "scope": "s"},
    ]
    artifacts = {"ok": {"usable": True}, "revoked": {"usable": False}}
    assert accepted_pairs(reviews, artifacts, scope="s") == {A2IV}


# ---- API and CLI ----------------------------------------------------------

def _pan_audit(audit_id="audit-gate"):
    job = ScanJob(id=f"job-{audit_id}", store="prod")
    job.add(Finding(id=f"f-{audit_id}", title="PCI", severity=Severity.HIGH,
                    category="data_classification", store="prod",
                    evidence={"label_counts": {"pci": 2}}))
    job.finished_at = datetime.now(timezone.utc)
    result = AuditResult(id=audit_id, store="prod", jobs=[job],
                         started_at=job.started_at.isoformat(),
                         finished_at=job.finished_at.isoformat())
    result.check_outcomes.append(check_outcome(
        "data_classification", "prod", "cards", outcome="failed", complete=True,
        chunks_scanned=2, chunks_expected=2))
    result.check_outcomes.append(crypto_outcome(
        "pan_representation", "prod", "cards", state="observed_exposure",
        outcome="failed", complete=True, reason="2 full PANs"))
    return result


def test_the_gate_route_decides_from_the_saved_audit_and_logs_it(tmp_path):
    client, history, app = api_client(tmp_path)
    try:
        assert client.get("/stores/prod/crypto-gate").status_code == 409
        assert client.get("/stores/nope/crypto-gate").status_code == 404
        history.save_audit(_pan_audit(), store_id="prod")
        body = client.get("/stores/prod/crypto-gate").json()
        assert body["decision"] == "block" and body["audit_id"] == "audit-gate"
        assert body["labels"] == ["pci"]
        assert client.get("/stores/prod/crypto-gate?audit_id=missing").status_code == 404
        listed = client.get("/compliance/crypto-gate/rules").json()
        assert listed["decisions"] == list(DECISIONS)
        assert [r["id"] for r in listed["rules"]] == [
            r.id for r in default_gate_rules()]
        events = [e for e in app.state.audit_log.entries
                  if e.action == "crypto_gate_decided"]
        assert events and events[-1].details["decision"] == "block"
        assert events[-1].details["fired"] == ["pan-must-be-unreadable"]
        before = len(app.state.audit_log.entries)
        preview = client.get("/stores/prod/crypto-gate?record=false").json()
        assert preview["decision"] == "block"
        assert len(app.state.audit_log.entries) == before
        assert rule(preview, "phi-needs-verified-at-rest")["clears_with"] == "any"
    finally:
        app.state.jobs.shutdown(wait=False)
        history.close()


def test_the_cli_exit_code_is_the_decision(tmp_path):
    from vecshield_platform.api.state import resolve_state_paths
    from vecshield_platform.cli import cli
    from vecshield_platform.history import ScanHistory

    config = tmp_path / "vecshield.json"
    state = tmp_path / "state"
    with ScanHistory(resolve_state_paths(config, state).history_db) as history:
        history.save_audit(_pan_audit(), store_id="prod")
    out = tmp_path / "gate.json"
    run = CliRunner().invoke(cli, ["crypto-gate", "--config", str(config),
                                   "--state-dir", str(state), "--store", "prod",
                                   "--json", str(out)])
    assert run.exit_code == 2, run.output
    assert "BLOCK" in run.output and out.exists()
    missing = CliRunner().invoke(cli, ["crypto-gate", "--config", str(config),
                                       "--state-dir", str(state), "--store", "other"])
    assert missing.exit_code == 2


# ---- sensitivity has to be established before it can pass ----------------

PHI_TEXT = ("Patient John Smith, MRN 48213377, diagnosed with type 2 diabetes; "
            "prescribed metformin.")


def _real_audit(conn, **kw):
    from vecshield.classify import RegexClassifier
    from vecshield_platform.orchestrator import run_full_audit

    return run_full_audit(conn, classifier=RegexClassifier(), include_integrity=False,
                          cve_offline=True, **kw).to_dict()


def _chunk(i, text):
    from vecshield.models import Chunk

    return Chunk(id=str(i), collection="notes", text=text,
                 metadata={"source": "ehr"}, embedding=[0.1, 0.2])


def test_the_gate_does_not_pass_a_phi_store_it_only_partly_read():
    from test_assessment_coverage import MemoryConnector

    conn = MemoryConnector({"notes": [_chunk(1, "Ordinary text."), _chunk(2, PHI_TEXT)]})
    result = evaluate_gate(_real_audit(conn, max_chunks_per_collection=1), store_id="s")
    assert result["decision"] == "request_evidence"
    assert result["coverage"]["complete"] is False
    assert result["coverage"]["sensitivity"] == "not_established"
    coverage_rule = rule(result, "sensitivity-must-be-established")
    assert coverage_rule["status"] == "fired"
    assert any("chunk limit" in r for r in coverage_rule["reasons"])
    # PHI rules hold as unknown and ask for evidence; they cannot block on a
    # label nobody observed.
    phi = rule(result, "phi-needs-verified-at-rest")
    assert phi["status"] == "fired" and phi["decision"] == "request_evidence"
    assert phi["rule_decision"] == "block" and phi["sensitivity"] == "not_established"
    assert any("sensitivity not established" in r for r in phi["reasons"])


def test_the_gate_does_not_pass_a_store_whose_content_cannot_be_read():
    from test_assessment_coverage import MemoryConnector

    conn = MemoryConnector({"notes": [_chunk(2, PHI_TEXT)]}, enumerable=False)
    result = evaluate_gate(_real_audit(conn), store_id="s")
    assert result["decision"] == "request_evidence"
    assert result["coverage"]["classification"] == "partial"


def test_the_gate_does_not_pass_a_store_whose_read_failed():
    from test_assessment_coverage import MemoryConnector

    conn = MemoryConnector({"notes": [_chunk(2, PHI_TEXT)]}, broken="notes")
    conn.data = {"notes": []}
    result = evaluate_gate(_real_audit(conn), store_id="s")
    assert result["decision"] == "request_evidence"
    assert not result["coverage"]["complete"]


def test_phi_read_in_full_still_blocks_even_when_other_coverage_is_partial():
    from test_assessment_coverage import MemoryConnector

    conn = MemoryConnector({"notes": [_chunk(1, PHI_TEXT), _chunk(2, "Ordinary text.")]})
    result = evaluate_gate(_real_audit(conn), store_id="s")
    assert "phi" in result["labels"]
    assert result["decision"] == "block"
    phi = rule(result, "phi-needs-verified-at-rest")
    assert phi["decision"] == "block" and phi["sensitivity"] is None


def test_degraded_or_disabled_nlp_leaves_sensitivity_unestablished():
    for status in ("degraded", "disabled"):
        snap = snapshot(VERIFIED, labels=["pii"])
        snap["scope"] = {"detection": {"status": status}}
        result = evaluate_gate(snap, store_id="s")
        assert result["decision"] == "request_evidence", status
        assert any(f"NLP detection was {status}" in r
                   for r in result["coverage"]["reasons"])


def test_an_audit_without_classification_does_not_pass():
    result = evaluate_gate(snapshot(VERIFIED, classified=False), store_id="s")
    assert result["decision"] == "request_evidence"
    assert result["coverage"]["classification"] == "not_recorded"


def test_a_complete_classification_with_nothing_found_still_passes():
    result = evaluate_gate(snapshot(VERIFIED), store_id="s")
    assert result["decision"] == "pass"
    assert result["coverage"] == {"classification": "complete", "complete": True,
                                  "sensitivity": "established", "reasons": []}


def test_the_cli_exits_1_when_sensitivity_is_not_established(tmp_path):
    from vecshield_platform.api.state import resolve_state_paths
    from vecshield_platform.cli import cli
    from vecshield_platform.history import ScanHistory

    audit = _pan_audit("audit-partial")
    audit.jobs[0].findings.clear()
    audit.check_outcomes[:] = [check_outcome(
        "data_classification", "prod", "cards", outcome="inconclusive",
        reason="The configured chunk limit was reached.", complete=False)]
    config, state = tmp_path / "vecshield.json", tmp_path / "state"
    with ScanHistory(resolve_state_paths(config, state).history_db) as history:
        history.save_audit(audit, store_id="prod")
    run = CliRunner().invoke(cli, ["crypto-gate", "--config", str(config),
                                   "--state-dir", str(state), "--store", "prod"])
    assert run.exit_code == 1, run.output
    assert "REQUEST_EVIDENCE" in run.output
