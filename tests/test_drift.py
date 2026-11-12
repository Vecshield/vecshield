"""Snapshot drift: honest new/absent semantics and crypto state changes."""

from __future__ import annotations

import copy
import importlib.util

import pytest

from test_assessment_coverage import MemoryConnector, chunk
from test_crypto_retrieval import RetrievalConnector, _mask, store
from vecshield.classify import RegexClassifier
from vecshield_platform.crypto.states import crypto_outcome
from vecshield_platform.drift import NOTE, diff_snapshots, finding_changes, latest_pair
from vecshield_platform.history import ScanHistory
from vecshield_platform.orchestrator import run_full_audit


def snapshot(audit_id, outcomes, findings=(), store_id="s1"):
    return {"id": audit_id, "store": "memory", "store_id": store_id,
            "check_outcomes": list(outcomes),
            "jobs": [{"id": f"job-{audit_id}", "store": "memory", "stats": {},
                      "findings": list(findings)}]}


def at_rest(state, outcome=None):
    return crypto_outcome("at_rest_encryption", "memory", state=state,
                          outcome=outcome, reason="")


def finding(fp, category="data_classification", collection="docs"):
    return {"id": f"find-{fp}", "title": "PII in 'docs'", "severity": "high",
            "category": category, "store": "memory", "collection": collection,
            "evidence": {"fingerprint": fp}}


def by_key(diff):
    return {(c["check"], c["collection"]): c for c in diff["checks"]}


def test_at_rest_verified_to_exposure_is_a_crypto_state_change():
    before = snapshot("a1", [at_rest("verified")])
    after = snapshot("a2", [at_rest("observed_exposure", outcome="failed")])
    diff = diff_snapshots(before, after)
    assert diff["before_audit_id"] == "a1" and diff["after_audit_id"] == "a2"
    entry = by_key(diff)[("at_rest_encryption", None)]
    assert entry["change"] == "changed"
    assert entry["before"] == {"outcome": "passed", "crypto_state": "verified"}
    assert entry["after"] == {"outcome": "failed", "crypto_state": "observed_exposure"}
    [change] = diff["crypto_state_changes"]
    assert "encryption at rest changed from verified to observed_exposure" in change["summary"]
    assert diff["note"] == NOTE


def test_missing_in_older_is_new_and_missing_in_newer_is_absent():
    field = crypto_outcome("field_encryption", "memory", "docs", state="verified")
    before = snapshot("a1", [at_rest("verified")])
    after = snapshot("a2", [field])
    checks = by_key(diff_snapshots(before, after))
    assert checks[("field_encryption", "docs")]["change"] == "new"
    assert checks[("field_encryption", "docs")]["before"] is None
    assert checks[("at_rest_encryption", None)]["change"] == "absent"
    assert checks[("at_rest_encryption", None)]["after"] is None
    changes = {c["check"]: c for c in diff_snapshots(before, after)["crypto_state_changes"]}
    assert "untested, not passed" in changes["at_rest_encryption"]["summary"]
    assert "first time" in changes["field_encryption"]["summary"]


def test_unchanged_and_first_audit():
    snap = snapshot("a1", [at_rest("verified")])
    diff = diff_snapshots(snap, copy.deepcopy(snap))
    assert by_key(diff)[("at_rest_encryption", None)]["change"] == "unchanged"
    assert diff["crypto_state_changes"] == []
    first = diff_snapshots(None, snap)
    assert first["before_audit_id"] is None
    assert {c["change"] for c in first["checks"]} == {"new"}


def test_worst_outcome_stands_for_duplicate_keys():
    ok = crypto_outcome("data_representation", "memory", "docs", state="not_applicable")
    bad = crypto_outcome("data_representation", "memory", "docs",
                         state="observed_exposure", outcome="failed")
    diff = diff_snapshots(snapshot("a1", [ok]), snapshot("a2", [ok, bad]))
    assert by_key(diff)[("data_representation", "docs")]["after"]["outcome"] == "failed"


def test_findings_new_resolved_persistent_and_not_retested():
    ran = {"check": "data_classification", "store": "memory", "collection": "docs",
           "outcome": "passed", "reason": "", "coverage": {"complete": True}}
    before = snapshot("a1", [ran], [finding("fp-old"), finding("fp-kept"),
                                    finding("fp-iso", category="isolation")])
    after = snapshot("a2", [ran], [finding("fp-kept"), finding("fp-new")])
    result = diff_snapshots(before, after)["findings"]
    assert result["new"] == ["fp-new"]
    assert result["resolved"] == ["fp-old"]
    # Isolation did not run in the newer audit: gone, but not resolved.
    assert result["not_retested"] == ["fp-iso"]
    assert result["persistent"] == 1


def test_finding_changes_resolves_fingerprints_to_summaries():
    ran = {"check": "data_classification", "store": "memory", "collection": "docs",
           "outcome": "passed", "reason": "", "coverage": {"complete": True}}
    low = {**finding("fp-low"), "severity": "low", "title": "Low thing"}
    secret = {**finding("fp-new"), "evidence": {"fingerprint": "fp-new",
                                                 "examples": [{"value": "123-45-6789"}]}}
    before = snapshot("a1", [ran], [finding("fp-old"), finding("fp-kept"),
                                    finding("fp-iso", category="isolation")])
    after = snapshot("a2", [ran], [finding("fp-kept"), low, secret])
    result = finding_changes(before, after)
    assert (result["before_audit_id"], result["after_audit_id"]) == ("a1", "a2")
    # Worst first, then title.
    assert [e["fingerprint"] for e in result["new"]] == ["fp-new", "fp-low"]
    assert result["new"][0] == {"fingerprint": "fp-new", "id": "find-fp-new",
                                "title": "PII in 'docs'", "severity": "high",
                                "category": "data_classification", "collection": "docs"}
    # Resolved and not-retested findings are described from the older audit.
    assert [e["id"] for e in result["resolved"]] == ["find-fp-old"]
    assert [e["category"] for e in result["not_retested"]] == ["isolation"]
    assert (result["new_total"], result["resolved_total"],
            result["not_retested_total"], result["persistent"]) == (2, 1, 1, 1)
    assert "evidence" not in repr(result) and "123-45-6789" not in repr(result)
    assert result["note"] == NOTE


def test_finding_changes_caps_lists_but_keeps_totals():
    after = snapshot("a2", [], [finding(f"fp-{i}") for i in range(5)])
    result = finding_changes(None, after, limit=2)
    assert result["before_audit_id"] is None
    assert len(result["new"]) == 2 and result["new_total"] == 5


def test_finding_whose_check_was_skipped_is_not_resolved():
    skipped = {"check": "data_classification", "store": "memory", "collection": "docs",
               "outcome": "error", "reason": "", "coverage": {}}
    result = diff_snapshots(snapshot("a1", [], [finding("fp-x")]),
                            snapshot("a2", [skipped]))["findings"]
    assert result["resolved"] == [] and result["not_retested"] == ["fp-x"]


@pytest.mark.parametrize("outcome, complete", [
    ("inconclusive", False), ("passed", False), ("inconclusive", True)])
def test_partial_rerun_does_not_resolve_a_vanished_finding(outcome, complete):
    rerun = {"check": "data_classification", "store": "memory", "collection": "docs",
             "outcome": outcome, "reason": "", "coverage": {"complete": complete,
                                                           "limit_reached": not complete}}
    result = diff_snapshots(snapshot("a1", [], [finding("fp-x")]),
                            snapshot("a2", [rerun]))["findings"]
    if complete:
        assert result["resolved"] == ["fp-x"]
    else:
        assert result["resolved"] == [] and result["not_retested"] == ["fp-x"]


def test_failed_rerun_counts_as_retested_even_when_partial():
    rerun = {"check": "data_classification", "store": "memory", "collection": "docs",
             "outcome": "failed", "reason": "", "coverage": {"complete": False}}
    result = diff_snapshots(snapshot("a1", [], [finding("fp-x")]),
                            snapshot("a2", [rerun]))["findings"]
    assert result["resolved"] == ["fp-x"]


def test_rerun_of_another_collection_does_not_retest():
    rerun = {"check": "data_classification", "store": "memory", "collection": "other",
             "outcome": "passed", "reason": "", "coverage": {"complete": True}}
    result = diff_snapshots(snapshot("a1", [], [finding("fp-x")]),
                            snapshot("a2", [rerun]))["findings"]
    assert result["not_retested"] == ["fp-x"]


def test_capped_real_audit_leaves_vanished_finding_not_retested():
    before = _real_audit("Customer SSN on file: 123-45-6789.")
    conn = MemoryConnector({"docs": [chunk(2), chunk(1, text="Customer SSN on file: 123-45-6789.")]})
    capped = _audit(conn, max_chunks_per_collection=1).to_dict()
    result = diff_snapshots(before, capped)["findings"]
    # Both the PII finding and its "no retention horizon" companion vanish;
    # neither may be called resolved on a capped re-scan.
    assert result["resolved"] == [] and len(result["not_retested"]) == 2


def test_different_stores_are_rejected():
    with pytest.raises(ValueError):
        diff_snapshots(snapshot("a1", [], store_id="s1"), snapshot("a2", [], store_id="s2"))


def test_legacy_snapshot_without_fingerprints_or_top_level_outcomes():
    legacy = {"id": "a0", "store": "memory", "jobs": [{
        "id": "j", "store": "memory",
        "stats": {"check_outcomes": [at_rest("verified")]},
        "findings": [{"id": "f", "title": "PII in 'docs'", "severity": "high",
                      "category": "data_classification", "store": "memory",
                      "collection": "docs", "evidence": {}}]}]}
    diff = diff_snapshots(legacy, snapshot("a2", [at_rest("verified")]))
    assert by_key(diff)[("at_rest_encryption", None)]["change"] == "unchanged"
    assert len(diff["findings"]["not_retested"] + diff["findings"]["resolved"]) == 1


#: The representation pass is built alongside this module; until it lands the
#: real-audit tests run without the crypto checks rather than failing on import.
CRYPTO = importlib.util.find_spec("vecshield_platform.crypto.representation") is not None


def _audit(conn, **kwargs):
    return run_full_audit(conn, classifier=RegexClassifier(), include_posture=False,
                          include_crypto=CRYPTO, **kwargs)


def _real_audit(text):
    return _audit(MemoryConnector({"docs": [chunk(1, text=text), chunk(2)]})).to_dict()


def test_real_audit_snapshots_diff():
    before = _real_audit("Customer SSN on file: 123-45-6789.")
    after = _real_audit("Ordinary documentation.")
    diff = diff_snapshots(before, after)
    checks = by_key(diff)
    assert checks[("data_classification", "docs")]["change"] == "changed"
    assert checks[("data_classification", "docs")]["before"]["outcome"] == "failed"
    assert checks[("data_classification", "docs")]["after"]["outcome"] == "passed"
    assert checks[("configuration_posture", None)]["change"] == "unchanged"
    # The PII finding and the "no retention horizon" finding that rides on it
    # (emitted only where sensitive data was found) both resolve.
    assert len(diff["findings"]["resolved"]) == 2
    assert diff["findings"]["new"] == []
    same = diff_snapshots(before, _real_audit("Customer SSN on file: 123-45-6789."))
    assert same["findings"]["persistent"] == 2 and not same["findings"]["new"]


def test_latest_pair_reads_history(tmp_path):
    history = ScanHistory(tmp_path / "h.db")
    assert latest_pair(history, "s1") == (None, None)
    conn = MemoryConnector({"docs": [chunk(1)]})
    first = _audit(conn)
    history.save_audit(first, store_id="s1")
    assert latest_pair(history, "s1")[0] is None
    assert latest_pair(history, "s1")[1]["id"] == first.id
    second = _audit(conn)
    history.save_audit(second, store_id="s1")
    older, newer = latest_pair(history, "s1")
    assert (older["id"], newer["id"]) == (first.id, second.id)
    assert diff_snapshots(older, newer)["after_audit_id"] == second.id


@pytest.mark.skipif(not CRYPTO, reason="crypto representation pass not built yet")
def test_real_audit_retrieval_exposure_drift():
    exposed = _audit(RetrievalConnector(store()), retrieval_probe=True).to_dict()
    masked = _audit(RetrievalConnector(store(), render=_mask),
                    retrieval_probe=True).to_dict()
    diff = diff_snapshots(exposed, masked)
    changes = {(c["check"], c["collection"]): c for c in diff["crypto_state_changes"]}
    change = changes[("retrieval_exposure", "docs")]
    assert change["before"]["crypto_state"] == "observed_exposure"
    assert change["after"]["crypto_state"] != "observed_exposure"
    assert "changed from observed_exposure" in change["summary"]
    # The probe samples, so it never completes: its vanished finding is not
    # proof of a fix and stays not_retested rather than resolved.
    [gone] = diff["findings"]["not_retested"]
    assert gone in {f["evidence"]["fingerprint"] for job in exposed["jobs"]
                        for f in job["findings"] if f["category"] == "retrieval_exposure"}
