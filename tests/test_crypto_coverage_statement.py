"""The crypto coverage statement and the estate route that lists it per store.

The statement says, per layer, what was observed, what was only declared, what
is unknown or not observable, and what was not checked. The one thing it must
never do is let an unchecked or unobservable layer read as verified.
"""

from __future__ import annotations

from test_assessment_snapshots import audit_result
from test_criteria import api_client
from test_crypto_view import STORE, full_outcomes

from vecshield_platform.coverage import check_outcome
from vecshield_platform.crypto.states import crypto_outcome
from vecshield_platform.crypto.view import (
    build_crypto_posture,
    coverage_bucket,
    coverage_statement,
    crypto_coverage,
)


def _snapshot(outcomes, *, audit_id="audit-1", scope=None):
    return {"id": audit_id, "finished_at": "2026-09-25T10:00:00+00:00",
            "check_outcomes": outcomes, "scope": scope or {}}


def _layer(statement, name):
    return next(s for s in statement["layers"] if s["layer"] == name)


def test_bucket_keeps_observed_declared_unknown_and_unchecked_apart():
    assert coverage_bucket({"outcome": "passed", "crypto_state": "verified"}) == "verified"
    assert coverage_bucket({"outcome": "passed",
                            "crypto_state": "protected_representation"}) == "verified"
    assert coverage_bucket({"outcome": "inconclusive",
                            "crypto_state": "observed_exposure"}) == "exposure"
    assert coverage_bucket({"outcome": "passed",
                            "crypto_state": "not_applicable"}) == "not_applicable"
    assert coverage_bucket({"outcome": "unsupported",
                            "crypto_state": "not_observable"}) == "not_observable"
    assert coverage_bucket({"outcome": "inconclusive",
                            "crypto_state": "not_verified"}) == "unknown"
    # A skipped check is not checked, whatever state it carries for bookkeeping.
    assert coverage_bucket({"outcome": "skipped", "crypto_state": "verified"}) == "not_checked"
    assert coverage_bucket({"outcome": "not_run", "crypto_state": "not_verified"}) == "not_checked"
    # Vendor documentation or configuration is declared, never verified.
    documented = {"outcome": "unsupported", "crypto_state": "not_observable",
                  "details": {"documented_default": {"text": "Always encrypted."}}}
    assert coverage_bucket(documented) == "declared"
    configured = {"outcome": "inconclusive", "crypto_state": "not_verified",
                  "details": {"sslmode": "prefer"}}
    assert coverage_bucket(configured) == "declared"


def test_statement_counts_rows_and_never_calls_a_mixed_layer_verified():
    model = build_crypto_posture(_snapshot(full_outcomes()), store_id="prod")
    statement = model["coverage"]["statement"]
    transport = _layer(statement, "transport")
    # TLS verified, enforcement not established: the layer is not "verified".
    assert transport["counts"]["verified"] == 1
    assert transport["counts"]["unknown"] == 1
    assert transport["headline"] == "unknown"
    assert transport["text"] == "Transport: 1 could not be established, 1 verified"

    data = _layer(statement, "data")
    assert data["headline"] == "exposure"
    assert data["collections_with_exposure"] == ["docs"]
    retrieval = _layer(statement, "retrieval")
    assert retrieval["headline"] == "not_checked"
    assert retrieval["basis"] == "not_checked"

    assert statement["rows"] == sum(len(l["rows"]) for l in model["layers"])
    assert sum(statement["totals"].values()) == statement["rows"]
    assert sum(statement["by_basis"].values()) == statement["rows"]
    assert "%" not in statement["text"]
    assert "Cloud KMS / Key Vault configuration" in statement["outside_connector"]


def test_a_layer_is_verified_only_when_every_row_is():
    outcomes = [
        crypto_outcome("transport_encryption", STORE, state="verified", complete=True,
                       reason="TLS observed.", source="session"),
        crypto_outcome("transport_tls_enforcement", STORE, state="verified",
                       complete=True, reason="Plaintext refused."),
    ]
    transport = _layer(crypto_coverage(_snapshot(outcomes)), "transport")
    assert transport["headline"] == "verified"
    assert transport["basis"] == "observed"
    assert transport["text"] == "Transport: verified"


def test_excluded_posture_reads_as_not_checked_with_the_reason():
    snapshot = _snapshot([check_outcome("configuration_posture", STORE, outcome="skipped",
                                        reason="Posture scanning was excluded.")])
    statement = crypto_coverage(snapshot)
    for name in ("transport", "storage"):
        layer = _layer(statement, name)
        assert layer["headline"] == "not_checked"
        assert "excluded from this run" in layer["text"]
    retrieval = _layer(statement, "retrieval")
    assert retrieval["text"] == "Retrieval: not checked (the audit predates the check)"


def test_opt_in_probe_and_unsupported_database_are_named():
    outcomes = [
        crypto_outcome("at_rest_encryption", STORE, state="not_observable",
                       reason="Chroma documents no encryption-at-rest setting.",
                       support="not_supported", database="Chroma",
                       capability_limit=True, documented_default=None),
        check_outcome("retrieval_exposure", STORE, outcome="skipped",
                      reason="The retrieval probe is an active check and was not requested.",
                      crypto_state="not_verified", opt_in=True),
    ]
    statement = crypto_coverage(_snapshot(outcomes))
    assert _layer(statement, "storage")["text"] == "At rest: not observable for Chroma"
    assert _layer(statement, "storage")["databases_not_observable"] == ["Chroma"]
    assert _layer(statement, "retrieval")["text"] == \
        "Retrieval: not checked (opt-in probe not requested)"


def test_empty_layers_are_not_checked():
    statement = coverage_statement([{"layer": "transport", "title": "Transport",
                                     "rows": []}])
    layer = statement["layers"][0]
    assert layer["headline"] == "not_checked" and layer["basis"] == "not_checked"
    assert layer["text"] == "Transport: nothing recorded"


def _save(history, audit_id, *, outcomes, store_id="prod"):
    result = audit_result(audit_id=audit_id, job_id=f"job-{audit_id}")
    result.check_outcomes.extend(outcomes)
    history.save_audit(result, store_id=store_id)
    return result.id


def test_crypto_estate_lists_every_store_and_marks_the_unassessed(tmp_path):
    client, history, app = api_client(tmp_path)
    try:
        body = client.get("/admin/crypto-estate").json()
        assert body["history_available"] is True
        assert body["stores"] == [{"store_id": "prod", "kind": "fake",
                                   "state": "never_assessed"}]

        audit_id = _save(history, "audit-est", outcomes=full_outcomes())
        body = client.get("/admin/crypto-estate").json()
        row = body["stores"][0]
        assert row["state"] == "assessed" and row["audit_id"] == audit_id
        layers = [s["layer"] for s in row["statement"]["layers"]]
        assert layers == ["transport", "storage", "data", "retrieval"]
        assert row["gate"]["decision"] in ("block", "request_evidence", "warn", "pass")
        # The estate route previews the gate; it is not a recorded release decision.
        def decisions():
            return sum(e.get("action") == "crypto_gate_decided"
                       for e in client.get("/audit-log").json()["entries"])

        assert client.get("/stores/prod/crypto-gate").status_code == 200
        assert decisions() == 1, "a pipeline's gate call is recorded"
        client.get("/admin/crypto-estate")
        assert decisions() == 1
    finally:
        app.state.jobs.shutdown(wait=False)
        history.close()


def test_crypto_posture_serves_the_statement(tmp_path):
    client, history, app = api_client(tmp_path)
    try:
        _save(history, "audit-st", outcomes=full_outcomes())
        body = client.get("/stores/prod/crypto-posture").json()
        statement = body["coverage"]["statement"]
        assert [s["layer"] for s in statement["layers"]] == [
            "transport", "storage", "data", "retrieval"]
        assert statement["text"].startswith("Transport: ")
    finally:
        app.state.jobs.shutdown(wait=False)
        history.close()


def test_home_links_several_blocked_stores_to_the_crypto_estate(tmp_path, monkeypatch):
    import pytest

    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    import vecshield_platform.crypto.gate as gate
    from vecshield_platform.api import create_app
    from vecshield_platform.api.registry import StoreRegistry
    from vecshield_platform.history import ScanHistory

    monkeypatch.setattr(gate, "evaluate_gate", lambda snap, **_: {
        "decision": "block", "rules": [], "audit_id": snap.get("id")})
    registry = StoreRegistry()
    for sid in ("alpha", "beta"):
        registry.register(sid, "fake", factory=lambda: None)
    history = ScanHistory(tmp_path / "history.db")
    app = create_app(registry=registry, scan_history=history, serve_ui=False)
    try:
        client = TestClient(app)
        _save(history, "audit-alpha", outcomes=[], store_id="alpha")
        item = next(i for i in client.get("/admin/home").json()["needs_you"]
                    if i["kind"] == "crypto_gate_blocks")
        assert item["target"] == {"view": "crypto", "params": {"store": "alpha"}}
        _save(history, "audit-beta", outcomes=[], store_id="beta")
        item = next(i for i in client.get("/admin/home").json()["needs_you"]
                    if i["kind"] == "crypto_gate_blocks")
        assert item["stores"] == ["alpha", "beta"]
        assert item["target"] == {"view": "crypto", "params": {"scope": "estate"}}
    finally:
        app.state.jobs.shutdown(wait=False)
        history.close()
