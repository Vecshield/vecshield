"""The seeded demo estate: every scenario it claims to show, it shows.

Runs the real seeder into a temporary directory and reads back its own
verification. A demo whose scenarios quietly stop firing would teach a room
full of people the wrong thing about the product, so the seeder's honesty
check is held here as a test rather than trusted.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SEEDER = REPO / "demo" / "seed.py"

pytest.importorskip("chromadb")


@pytest.fixture(scope="module")
def seeded(tmp_path_factory):
    state = tmp_path_factory.mktemp("demo")
    # These assertions describe the Chroma-only estate, so the inputs are
    # pinned: the seeder falls back to $VECSHIELD_PG_DSN for its pgvector
    # stores, and a developer with that set would otherwise be running a
    # different demo than the one asserted here.
    env = {k: v for k, v in os.environ.items() if k != "VECSHIELD_PG_DSN"}
    proc = subprocess.run(
        [sys.executable, str(SEEDER), "--state", str(state), "--strict"],
        capture_output=True, text=True, timeout=600, env=env)
    assert proc.returncode == 0, proc.stdout[-3000:] + proc.stderr[-3000:]
    return state, json.loads((state / "demo.json").read_text())


def test_every_scenario_that_expects_a_signal_produces_it(seeded):
    _, summary = seeded
    states = {row["id"]: row["state"] for row in summary["scenarios"]}
    assert all(s in ("confirmed", "not_applicable") for s in states.values()), states
    assert sum(1 for s in states.values() if s == "confirmed") == 14


def test_the_estate_is_the_size_the_scenarios_describe(seeded):
    _, summary = seeded
    assert len(summary["stores"]) == 5
    assert summary["collections"] == 14
    assert summary["documents"] >= 150
    assert summary["findings"] >= 25


def test_each_regulation_has_at_least_one_confirmed_scenario(seeded):
    _, summary = seeded
    confirmed = {row["framework"] for row in summary["scenarios"]
                 if row["state"] == "confirmed"}
    for framework in ("HIPAA", "GDPR", "PCI-DSS", "SOC 2", "CCPA/CPRA", "EU AI Act"):
        assert framework in confirmed, f"{framework} has no confirmed scenario"


def test_the_demo_config_registers_every_store_with_its_policies(seeded):
    state, summary = seeded
    config = json.loads(Path(summary["config"]).read_text())
    registered = {s["store_id"] for s in config["stores"]}
    # The scenario stores, plus one registered and deliberately never assessed
    # so the Overview's "stores never assessed" item has a real store.
    assert registered == set(summary["stores"]) | set(summary["unassessed_stores"])
    scoped = {p["scope_store"] for p in config["policies"]}
    assert scoped == registered, "every store carries at least one policy"


def test_the_one_planted_cross_tenant_leak_is_found_and_no_other(seeded):
    """merchant_disputes leaks because its merchant ids collide as floats;
    every other collection's filter is verified with no bleed."""
    _, summary = seeded
    rows = summary["isolation"]
    assert all(not row["problems"] for row in rows), [r for r in rows if r["problems"]]
    leaks = [(r["store"], r["collection"]) for r in rows if r["expected_leak"]]
    assert leaks == [("payments-ops", "merchant_disputes")]
    assert [(r["store"], r["collection"]) for r in rows if r["bleeds"]] == leaks
    [row] = [r for r in rows if r["expected_leak"]]
    assert row["outcome"] == "failed" and row["method"] == "exhaustive"


def _app(summary):
    from vecshield_platform.api import create_app
    from vecshield_platform.api.config_store import ConfigStore
    from vecshield_platform.api.state import resolve_state_paths
    from vecshield_platform.history import ScanHistory
    from vecshield_platform.runtime import AlertStore

    paths = resolve_state_paths(summary["config"], summary["state_dir"])
    history = ScanHistory(paths.history_db)
    app = create_app(config_store=ConfigStore(path=summary["config"]), scan_history=history,
                     alert_store=AlertStore(paths.alerts_db), serve_ui=False)
    return app, history


def test_the_console_shows_the_leak_as_critical_with_its_cause(seeded):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    _, summary = seeded
    app, history = _app(summary)
    try:
        body = TestClient(app).get("/admin/findings",
                                   params={"category": "isolation", "limit": 500}).json()
    finally:
        app.state.jobs.shutdown(wait=False)
        history.close()
    critical = [f for f in body["findings"] if f["severity"] == "critical"]
    assert {f["collection"] for f in critical} == {"merchant_disputes"}
    finding = critical[0]
    assert finding["title"] == "Tenant filter NOT enforced in 'merchant_disputes'"
    evidence = finding["evidence"]
    if isinstance(evidence, str):
        evidence = json.loads(evidence)
    assert evidence["cause"] == "numeric_tenant_collision"
    assert "2^53" in finding["description"]


def test_the_inbox_has_an_item_of_every_kind_it_checks(seeded):
    """The Overview's "Needs you" is populated from real records, one per kind."""
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    _, summary = seeded
    app, history = _app(summary)
    try:
        home = TestClient(app).get("/admin/home").json()
    finally:
        app.state.jobs.shutdown(wait=False)
        history.close()
    kinds = {item["kind"] for item in home["needs_you"]}
    for kind in ("plans_awaiting_approval", "evidence_reviews_awaiting_decision",
                 "exceptions_awaiting_approval", "exceptions_expiring",
                 "exceptions_expired", "stores_never_assessed", "crypto_gate_blocks"):
        assert kind in kinds, f"the seeded inbox has no {kind}"
    assert home["stores"]["never_assessed"] == len(summary["unassessed_stores"])


PG_DSN = os.environ.get("VECSHIELD_PG_DSN")


def _pg_available() -> bool:
    if not PG_DSN:
        return False
    try:
        import psycopg
    except ImportError:
        return False
    try:
        with psycopg.connect(PG_DSN, connect_timeout=2) as c:
            c.execute("SELECT 1 FROM pg_extension WHERE extname = 'vector'")
        return True
    except Exception:
        return False


@pytest.fixture(scope="module")
def seeded_with_pgvector(tmp_path_factory):
    state = tmp_path_factory.mktemp("demo-pg")
    proc = subprocess.run(
        [sys.executable, str(SEEDER), "--state", str(state), "--strict",
         "--pgvector-dsn", PG_DSN],
        capture_output=True, text=True, timeout=900)
    assert proc.returncode == 0, proc.stdout[-3000:] + proc.stderr[-3000:]
    return state, json.loads((state / "demo.json").read_text())


def test_pgvector_scenarios_are_skipped_not_missed_without_a_database(seeded):
    """A scenario that never ran must never read as one that found nothing."""
    _, summary = seeded
    pgv = summary["pgvector"]
    assert pgv["enabled"] is False
    assert pgv["stores"] == []
    assert [row["state"] for row in pgv["scenarios"]] == ["skipped", "skipped"]


@pytest.mark.skipif(not _pg_available(),
                    reason="pgvector DB not reachable at VECSHIELD_PG_DSN")
def test_pgvector_stores_are_built_and_their_scenarios_fire(seeded_with_pgvector):
    _, summary = seeded_with_pgvector
    assert len(summary["stores"]) == 7
    pgv = summary["pgvector"]
    assert pgv["enabled"] is True
    assert pgv["stores"] == ["pgvector-clinical", "pgvector-support"]
    states = {row["id"]: row["state"] for row in pgv["scenarios"]}
    assert all(state == "confirmed" for state in states.values()), states


@pytest.mark.skipif(not _pg_available(),
                    reason="pgvector DB not reachable at VECSHIELD_PG_DSN")
def test_pgvector_isolation_matches_the_chroma_collection(seeded_with_pgvector):
    """The same corpus through a second connector must probe the same.

    `partner_shared` is seeded identically in Chroma and pgvector, so any
    difference in what the isolation probe reports is a property of the
    connector rather than of the data — which is the whole reason the demo
    carries the collection twice.
    """
    _, summary = seeded_with_pgvector
    rows = {(r["store"], r["collection"]): r for r in summary["isolation"]
            if not r["capped"]}
    chroma = rows[("customer-360", "partner_shared")]
    pgvector = rows[("pgvector-support", "partner_shared")]
    for field in ("outcome", "coverage", "method", "cross_tenant_queries",
                  "bleeds", "untagged"):
        assert chroma[field] == pgvector[field], field
    assert not pgvector["problems"]


@pytest.mark.skipif(not _pg_available(),
                    reason="pgvector DB not reachable at VECSHIELD_PG_DSN")
def test_the_demo_config_never_stores_the_postgres_password(seeded_with_pgvector):
    """Secrets stay out of `vecshield.json` (ADR 0003)."""
    state, _ = seeded_with_pgvector
    raw = (state / "vecshield.json").read_text()
    config = json.loads(raw)
    stores = {s["store_id"]: s for s in config["stores"]}
    for store_id in ("pgvector-clinical", "pgvector-support"):
        conn = stores[store_id]["conn"]
        assert "password" not in conn
        assert "dsn" not in conn
        assert conn["password_env"] == "VECSHIELD_STORE_DEMO_PG_PASSWORD"
    # Belt and braces: the literal password does not appear anywhere in the file.
    import urllib.parse
    password = urllib.parse.urlparse(PG_DSN).password
    if password:
        assert password not in raw
