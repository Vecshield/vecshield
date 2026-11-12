"""Crypto posture wired through a full audit, the criteria, and the API."""

from __future__ import annotations

from test_assessment_coverage import MemoryConnector, chunk
from test_assessment_snapshots import audit_result
from test_criteria import api_client

from vecshield.classify import RegexClassifier
from vecshield_platform.compliance.criteria import evaluate_pack
from vecshield_platform.compliance.packs import get_criterion
from vecshield_platform.coverage import check_outcome, not_requested, summarize_coverage
from vecshield_platform.crypto import CRYPTO_CHECKS
from vecshield_platform.orchestrator import run_full_audit

PAN = "4111 1111 1111 1111"


def _audit(**kwargs):
    conn = MemoryConnector({"cards": [chunk(1, collection="cards",
                                            text=f"Card on file {PAN} for refund."),
                                      chunk(2, collection="cards")]},
                           query=True)
    return run_full_audit(conn, classifier=RegexClassifier(), include_integrity=False,
                          cve_offline=True, **kwargs)


def test_every_crypto_check_reports_in_a_default_audit():
    result = _audit()
    checks = {o["check"] for o in result.all_check_outcomes()}
    assert set(CRYPTO_CHECKS) <= checks
    assert result.scope["tls_probe"] is False
    assert result.scope["retrieval_probe"] is False


def test_unrequested_probes_are_recorded_but_do_not_make_a_run_partial():
    requested = check_outcome("data_classification", "s", outcome="passed",
                              complete=True)
    probe = check_outcome("retrieval_exposure", "s", outcome="skipped",
                          reason="not requested", crypto_state="not_verified",
                          opt_in=True)
    assert not_requested(probe) and not not_requested(requested)
    summary = summarize_coverage([requested, probe])
    assert summary["complete"] is True and summary["status"] == "complete"
    assert summary["checks_expected"] == 1 and summary["checks_not_requested"] == 1
    # A skip the run configuration chose is still a gap.
    excluded = check_outcome("rag_integrity", "s", outcome="skipped", reason="off")
    assert summarize_coverage([requested, excluded])["complete"] is False


def test_the_unrequested_tls_probe_leaves_transit_criteria_asking_for_evidence():
    result = _audit()
    outcomes = result.all_check_outcomes()
    enforcement = [o for o in outcomes if o["check"] == "transport_tls_enforcement"]
    assert enforcement and all(o["outcome"] != "failed" for o in enforcement)
    [e2ii] = evaluate_pack([get_criterion("HIPAA-164-312-E2II-ENCRYPTION-01")],
                           check_outcomes=outcomes)
    # VecShield using TLS, or the store having no transport, never shows that
    # other clients are refused plaintext.
    assert e2ii.status != "gap_identified"


def test_a_readable_pan_fails_pci_storage_whatever_the_storage_encryption():
    result = _audit()
    outcomes = result.all_check_outcomes()
    pan = [o for o in outcomes if o["check"] == "pan_representation"]
    assert pan and pan[0]["outcome"] == "failed"
    assert PAN not in str(result.to_dict())
    verified_storage = check_outcome("at_rest_encryption", result.store,
                                     outcome="passed", complete=True,
                                     crypto_state="verified")
    [storage] = evaluate_pack([get_criterion("PCI-DSS-3-STORAGE-01")],
                              check_outcomes=[*outcomes, verified_storage])
    assert storage.technical_result == "failed"
    assert {v.policy_id for v in result.violations} >= {"pan-rendered-unreadable"}


def test_retrieval_probe_runs_only_when_requested():
    off = [o for o in _audit().all_check_outcomes() if o["check"] == "retrieval_exposure"]
    assert [o["outcome"] for o in off] == ["skipped"]
    on = [o for o in _audit(retrieval_probe=True).all_check_outcomes()
          if o["check"] == "retrieval_exposure"]
    assert on and all(o["outcome"] != "skipped" for o in on)


def test_excluding_crypto_records_its_checks_as_skipped():
    result = _audit(include_crypto=False)
    skipped = {o["check"] for o in result.all_check_outcomes()
               if o["outcome"] == "skipped"}
    assert {"data_representation", "pan_representation",
            "direct_identifier_exposure", "retrieval_exposure"} <= skipped


def test_criteria_response_carries_the_at_rest_context_for_the_pci_rows(tmp_path):
    client, history, app = api_client(tmp_path)
    try:
        result = audit_result(audit_id="audit-ctx", job_id="job-ctx")
        at_rest = check_outcome("at_rest_encryption", "prod", outcome="unsupported",
                                crypto_state="not_observable")
        result.check_outcomes.append(at_rest)
        history.save_audit(result, store_id="prod")
        body = client.post("/stores/prod/criteria", json={"framework": "PCI-DSS"}).json()
        assert [o["check"] for o in body["crypto_context"]] == ["at_rest_encryption"]
        # No PCI criterion cites it; it is context for the storage row only.
        assert all(o["check"] != "at_rest_encryption"
                   for a in body["assessments"] for o in a["observations"])
    finally:
        app.state.jobs.shutdown(wait=False)
        history.close()


def test_a_property_the_database_cannot_report_does_not_make_a_run_partial():
    from vecshield_platform.coverage import capability_limited

    ran = check_outcome("data_classification", "s", outcome="passed", complete=True)
    limit = check_outcome("at_rest_encryption", "s", outcome="unsupported",
                          reason="Qdrant has no encryption-at-rest setting in its API.",
                          crypto_state="not_observable", capability_limit=True)
    assert capability_limited(limit)
    summary = summarize_coverage([ran, limit])
    assert summary["complete"] is True and summary["checks_not_supported"] == 1
    # An unsupported outcome that is not a documented database limit is still a gap.
    crashed = check_outcome("at_rest_encryption", "s", outcome="unsupported",
                            reason="The connector call failed.")
    assert summarize_coverage([ran, crashed])["complete"] is False
    # Criteria still ask for the evidence.
    [a2iv] = evaluate_pack([get_criterion("HIPAA-164-312-A2IV-ENCRYPTION-01")],
                           check_outcomes=[limit])
    assert a2iv.fallback_required == ["encryption_at_rest_statement"]
