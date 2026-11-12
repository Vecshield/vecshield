"""The Crypto Posture read model: layered, counted, never scored."""

from __future__ import annotations

import json
import sys
import types

import pytest

from vecshield_platform.coverage import check_outcome
from vecshield_platform.crypto.states import CRYPTO_CHECKS, LAYERS, crypto_outcome
from vecshield_platform.crypto.view import PREDATES_REASON, build_crypto_posture

STORE = "fake://observed"
COLLECTIONS = [f"c{i:02d}" for i in range(42)]


def _at_rest(verified: int, unencrypted: int, unknown: int, **kwargs) -> dict:
    per = ([{"collection": c, "state": "enabled"} for c in COLLECTIONS[:verified]]
           + [{"collection": c, "state": "disabled"}
              for c in COLLECTIONS[verified:verified + unencrypted]]
           + [{"collection": c, "state": "not_observable"}
              for c in COLLECTIONS[verified + unencrypted:]])
    return crypto_outcome(
        "at_rest_encryption", STORE, source="index.encryption_key", scope="collection",
        mechanism=None, key_reference="kms-****-7f",
        collections={"total": verified + unencrypted + unknown,
                     "verified_encrypted": verified,
                     "verified_unencrypted": unencrypted, "unknown": unknown},
        per_collection=per, **kwargs)


def full_outcomes(*, at_rest: dict | None = None) -> list[dict]:
    """One outcome for every crypto check, shaped as the contract describes."""
    return [
        check_outcome("data_classification", STORE, outcome="passed", complete=True),
        crypto_outcome("transport_encryption", STORE, state="verified", complete=True,
                       reason="TLS observed on the session.", scheme="https",
                       encrypted=True, source="session", protocol="TLSv1.3",
                       cipher="TLS_AES_256_GCM_SHA384"),
        crypto_outcome("transport_tls_enforcement", STORE, state="not_verified",
                       reason="The enforcement probe was not run.",
                       method=None, plaintext_accepted=None),
        at_rest or _at_rest(38, 0, 4, state="not_verified", outcome="inconclusive",
                            reason="38 collections report encryption; 4 do not say."),
        crypto_outcome("field_encryption", STORE, "docs", state="not_observable",
                       reason="This connector does not expose field encryption.",
                       fields=[], supported=False),
        crypto_outcome("data_representation", STORE, "docs",
                       state="observed_exposure", outcome="inconclusive",
                       reason="Sensitive values are stored as plaintext.",
                       record_structure={"embedding": "present", "text": "present",
                                         "metadata": "present"},
                       surfaces={"text": {"plaintext": 3}, "metadata": {"masked": 2}},
                       fields=[], sensitive_values=5, protected_values=2,
                       plaintext_values=3, drift_fields=[], chunks_examined=40,
                       inversion_risk=0.4,
                       statement="Embeddings are not treated as cryptographic "
                                 "protection."),
        crypto_outcome("data_representation", STORE, "archive", state="not_applicable",
                       complete=True, reason="No sensitive values."),
        crypto_outcome("pan_representation", STORE, "docs",
                       state="protected_representation", complete=True,
                       reason="No full PAN.",
                       counts={"full": 0, "truncated": 2, "tokenized": 0,
                               "hash_candidate": 0, "opaque": 0},
                       records_with_pan=2, examples=["411111******1111"]),
        crypto_outcome("direct_identifier_exposure", STORE, "docs",
                       state="not_applicable", complete=True, reason="None found.",
                       fields=[]),
        check_outcome("retrieval_exposure", STORE, outcome="skipped",
                      reason="The retrieval probe was not enabled for this run.",
                      crypto_state="not_verified"),
    ]


def snapshot(outcomes: list[dict], *, audit_id: str = "audit-new",
             scope: dict | None = None) -> dict:
    return {"id": audit_id, "store": STORE, "store_id": "prod",
            "started_at": "2026-09-24T10:00:00+00:00",
            "finished_at": "2026-09-24T10:05:00+00:00",
            "scope": scope if scope is not None else {"collections": COLLECTIONS},
            "jobs": [], "check_outcomes": outcomes}


def _keys(value) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {k for v in value.values() for k in _keys(v)}
    if isinstance(value, list):
        return {k for v in value for k in _keys(v)}
    return set()


def _rows(view: dict) -> list[dict]:
    return [row for layer in view["layers"] for row in layer["rows"]]


def test_every_layer_in_order_with_labels_and_counts():
    view = build_crypto_posture(snapshot(full_outcomes()), store_id="prod")

    assert [layer["layer"] for layer in view["layers"]] == [
        "transport", "storage", "data", "retrieval"]
    for layer in view["layers"]:
        assert [r["check"] for r in layer["rows"]] == [
            c for c in LAYERS[layer["layer"]]
            for _ in range(sum(o["check"] == c for o in full_outcomes()))]
    labels = {r["check"]: r["label"] for r in _rows(view)}
    assert labels["transport_encryption"] == "TLS on VecShield's connection"
    assert labels["transport_tls_enforcement"] == "Plaintext connections refused"
    assert labels["at_rest_encryption"] == "Database-native encryption at rest"
    assert labels["retrieval_exposure"] == "Retrieval-time plaintext exposure"
    # Store-level rows before per-collection rows, collections in order.
    data_rows = [r for r in _rows(view) if r["check"] == "data_representation"]
    assert [r["collection"] for r in data_rows] == ["archive", "docs"]

    transport = _rows(view)[0]
    assert transport["control"] == "VCR-01"
    assert transport["crypto_state"] == "verified"
    assert transport["details"]["protocol"] == "TLSv1.3"
    assert "crypto_state" not in transport["details"]

    assert view["coverage"]["collections_total"] == 42
    assert view["coverage"]["checks"]["data_representation"] == {
        "inconclusive": 1, "passed": 1}
    assert view["coverage"]["checks"]["retrieval_exposure"] == {"skipped": 1}
    assert set(view["coverage"]["checks"]) == set(CRYPTO_CHECKS)
    assert view["audit_id"] == "audit-new"
    assert view["assessed_at"] == "2026-09-24T10:05:00+00:00"
    assert view["pack_version"].startswith("vecshield-vector-store-")
    assert view["note"] == ("No crypto score. Counts describe what the connector "
                            "could observe.")
    assert "Embeddings are not treated as cryptographic protection." in view["statements"]
    assert {i["state"] for i in view["out_of_scope"]} == {
        "not_observable", "outside_connector_scope"}


def test_no_percentage_and_no_score_anywhere():
    view = build_crypto_posture(snapshot(full_outcomes()), store_id="prod")
    text = json.dumps(view)
    assert "%" not in text
    assert not {k for k in _keys(view) if "score" in k.lower()
                or "percent" in k.lower()}


def test_38_verified_and_4_unknown_is_never_complete():
    view = build_crypto_posture(snapshot(full_outcomes()), store_id="prod")
    assert view["coverage"]["at_rest"] == {
        "verified_encrypted": 38, "verified_unencrypted": 0, "unknown": 4, "not_supported": 0}
    at_rest = next(r for r in _rows(view) if r["check"] == "at_rest_encryption")
    assert at_rest["crypto_state"] == "not_verified"
    assert at_rest["outcome"] == "inconclusive"
    # Nothing on the page claims the property is fully covered.
    assert not {k for k in _keys(view) if k in ("complete", "status", "percentage",
                                                 "fully_encrypted")}
    assert "100" not in json.dumps(view["coverage"])


def test_an_audit_before_crypto_checks_keeps_every_layer():
    old = snapshot([check_outcome("data_classification", STORE, outcome="passed",
                                  complete=True),
                    check_outcome("configuration_posture", STORE, outcome="passed",
                                  complete=True)],
                   scope={"collections": ["docs"], "include_posture": True})
    view = build_crypto_posture(old, store_id="prod")

    assert [layer["layer"] for layer in view["layers"]] == [
        "transport", "storage", "data", "retrieval"]
    rows = _rows(view)
    assert [r["check"] for r in rows] == [c for checks in LAYERS.values()
                                          for c in checks]
    assert all(r["outcome"] == "not_run" and r["crypto_state"] == "not_verified"
               and r["reason"] == PREDATES_REASON for r in rows)
    # With no rollup, every collection's at-rest state is unknown, not unencrypted.
    assert view["coverage"]["at_rest"] == {
        "verified_encrypted": 0, "verified_unencrypted": 0, "unknown": 1, "not_supported": 0}
    assert view["coverage"]["checks"]["at_rest_encryption"] == {"not_run": 1}


def test_a_check_excluded_by_the_run_says_so_rather_than_predating():
    excluded = snapshot([check_outcome(
        "configuration_posture", STORE, outcome="skipped",
        reason="Posture scanning was excluded by the run configuration.")],
        scope={"collections": ["docs"], "include_posture": False})
    rows = {r["check"]: r for r in _rows(build_crypto_posture(excluded,
                                                              store_id="prod"))}
    transport = rows["transport_encryption"]
    assert transport["outcome"] == "skipped"
    assert transport["reason"].startswith("Not included in this run")
    assert "excluded by the run configuration" in transport["reason"]
    assert rows["data_representation"]["reason"] == PREDATES_REASON


def test_eu_ai_act_is_supporting_only_and_carries_no_criteria():
    view = build_crypto_posture(snapshot(full_outcomes()), store_id="prod")
    ai_act = next(r for r in view["regulatory"] if r["framework"] == "EU AI Act")
    assert ai_act["relationship"] == "supporting"
    assert ai_act["relationship_label"] == "Supporting evidence only"
    assert ai_act["criteria"] == []


def test_regulatory_rows_report_technical_reduction_not_status():
    view = build_crypto_posture(snapshot(full_outcomes()), store_id="prod")
    criteria = [c for row in view["regulatory"] for c in row["criteria"]]
    assert criteria
    assert all("status" not in c for c in criteria)
    hipaa = next(r for r in view["regulatory"] if r["framework"] == "HIPAA")
    at_rest = next(c for c in hipaa["criteria"]
                   if c["criterion_id"] == "HIPAA-164-312-A2IV-ENCRYPTION-01")
    # 38 verified + 4 unknown is inconclusive, so the fallback artifact is asked for.
    assert at_rest["technical_result"] == "inconclusive"
    assert at_rest["fallback_required"] == ["encryption_at_rest_statement"]
    assert at_rest["checks"] == ["at_rest_encryption"]


def test_pci_storage_follows_pan_representation_not_at_rest():
    outcomes = full_outcomes(at_rest=_at_rest(
        30, 12, 0, state="observed_exposure", outcome="failed", complete=True,
        reason="12 collections report encryption disabled."))
    view = build_crypto_posture(snapshot(outcomes), store_id="prod")
    pci = next(r for r in view["regulatory"] if r["framework"] == "PCI-DSS")
    storage = next(c for c in pci["criteria"]
                   if c["criterion_id"] == "PCI-DSS-3-STORAGE-01")
    assert storage["checks"] == ["data_classification", "pan_representation"]
    assert storage["technical_result"] == "passed"
    ccpa = next(r for r in view["regulatory"] if r["framework"] == "CCPA/CPRA")
    assert ccpa["criteria"][0]["technical_result"] == "failed"
    assert view["coverage"]["at_rest"] == {
        "verified_encrypted": 30, "verified_unencrypted": 12, "unknown": 0, "not_supported": 0}

    full_pan = [o for o in outcomes if o["check"] != "pan_representation"] + [
        crypto_outcome("pan_representation", STORE, "docs", state="observed_exposure",
                       outcome="failed", complete=True, reason="Full PAN stored.",
                       counts={"full": 1}, records_with_pan=1, examples=[])]
    pci = next(r for r in build_crypto_posture(snapshot(full_pan), store_id="prod")
               ["regulatory"] if r["framework"] == "PCI-DSS")
    assert pci["criteria"][0]["technical_result"] == "failed"


def test_legacy_transport_outcome_without_a_crypto_state_reads_conservatively():
    legacy = snapshot([check_outcome("transport_encryption", STORE,
                                     outcome="inconclusive",
                                     reason="Transport could not be verified.")])
    row = _rows(build_crypto_posture(legacy, store_id="prod"))[0]
    assert row["crypto_state"] == "not_verified"
    assert row["control"] == "VCR-01"


def test_drift_lists_only_changed_crypto_checks(monkeypatch):
    # Track C's diff_snapshots is stubbed so the view's filtering is tested on
    # its own; its real output shape is the contract's.
    seen = {}

    def diff_snapshots(before, after):
        seen["args"] = (before["id"], after["id"])
        return {"checks": [
            {"check": "at_rest_encryption", "collection": None, "change": "changed",
             "before": {"outcome": "unsupported", "crypto_state": "not_observable"},
             "after": {"outcome": "inconclusive", "crypto_state": "not_verified"}},
            {"check": "transport_encryption", "collection": None,
             "change": "unchanged",
             "before": {"outcome": "passed", "crypto_state": "verified"},
             "after": {"outcome": "passed", "crypto_state": "verified"}},
            {"check": "tenant_isolation", "collection": "docs", "change": "changed",
             "before": {"outcome": "passed"}, "after": {"outcome": "failed"}},
            {"check": "pan_representation", "collection": "docs", "change": "added",
             "before": None,
             "after": {"outcome": "passed",
                       "coverage": {"crypto_state": "protected_representation"}}},
        ], "crypto_state_changes": []}

    monkeypatch.setitem(sys.modules, "vecshield_platform.drift",
                        types.SimpleNamespace(diff_snapshots=diff_snapshots))
    previous = snapshot([], audit_id="audit-old")
    view = build_crypto_posture(snapshot(full_outcomes()), store_id="prod",
                                previous=previous)
    assert seen["args"] == ("audit-old", "audit-new")
    drift = view["drift"]
    assert drift["previous_audit_id"] == "audit-old"
    assert drift["compared"] is True
    assert [(c["check"], c["collection"]) for c in drift["changes"]] == [
        ("at_rest_encryption", None), ("pan_representation", "docs")]
    assert drift["changes"][0]["after"] == {"outcome": "inconclusive",
                                            "crypto_state": "not_verified"}
    assert drift["changes"][1]["before"] is None
    assert drift["changes"][1]["after"]["crypto_state"] == "protected_representation"


def test_no_previous_audit_is_not_reported_as_no_change(monkeypatch):
    view = build_crypto_posture(snapshot(full_outcomes()), store_id="prod")
    assert view["drift"] == {"previous_audit_id": None, "compared": False,
                             "changes": []}
    monkeypatch.setitem(sys.modules, "vecshield_platform.drift", None)
    view = build_crypto_posture(snapshot(full_outcomes()), store_id="prod",
                                previous=snapshot([], audit_id="audit-old"))
    assert view["drift"]["compared"] is False
    assert view["drift"]["previous_audit_id"] == "audit-old"


def test_the_view_does_not_mutate_its_snapshot():
    source = snapshot(full_outcomes())
    before = json.dumps(source, sort_keys=True)
    view = build_crypto_posture(source, store_id="prod")
    view["layers"][0]["rows"][0]["details"]["protocol"] = "changed"
    assert json.dumps(source, sort_keys=True) == before


def test_drift_with_the_real_snapshot_comparison():
    pytest.importorskip("vecshield_platform.drift")
    before = full_outcomes()
    after = [o for o in full_outcomes() if o["check"] != "at_rest_encryption"] + [
        _at_rest(42, 0, 0, state="verified", complete=True,
                 reason="Every collection reports encryption.")]
    view = build_crypto_posture(snapshot(after), store_id="prod",
                                previous=snapshot(before, audit_id="audit-old"))
    assert view["drift"]["compared"] is True
    assert [(c["check"], c["change"]) for c in view["drift"]["changes"]] == [
        ("at_rest_encryption", "changed")]
    assert view["drift"]["changes"][0]["before"] == {
        "outcome": "inconclusive", "crypto_state": "not_verified"}
    assert view["drift"]["changes"][0]["after"] == {
        "outcome": "passed", "crypto_state": "verified"}


def test_a_database_that_cannot_report_at_rest_is_counted_as_not_supported():
    snapshot = {"id": "audit-q", "store": "q", "scope": {"collections": ["a", "b"]},
                "check_outcomes": [check_outcome(
                    "at_rest_encryption", "q", outcome="unsupported",
                    reason="Qdrant has no encryption-at-rest setting in its API.",
                    crypto_state="not_observable", support="not_supported",
                    database="Qdrant", capability_limit=True)]}
    view = build_crypto_posture(snapshot, store_id="q")
    assert view["coverage"]["at_rest"] == {
        "verified_encrypted": 0, "verified_unencrypted": 0, "unknown": 0,
        "not_supported": 2}
