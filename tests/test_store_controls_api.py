"""Store controls: advisory feed, retention schedules, residency, processors,
inventory, source manifests and the CCPA risk-assessment workbook.

Role contract (SECURITY.md): viewers read; operators write assessment inputs
(inventory declarations, source manifests); settings writes are admin-only and
audit-logged; CCPA inputs and approval are compliance artefacts, approved by a
second person unless separation of duties allows otherwise.
"""

from __future__ import annotations

import csv
import io
import json
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from test_assessment_snapshots import audit_result  # noqa: E402
from test_auth import make_jwt  # noqa: E402

from vecshield.models import Collection, Finding, Severity, VectorStore  # noqa: E402
from vecshield_platform.api import create_app  # noqa: E402
from vecshield_platform.api.config_store import (  # noqa: E402
    ConfigStore,
    merge_declarations,
)
from vecshield_platform.api.feed_scheduler import EGRESS_HOSTS, FeedScheduler  # noqa: E402
from vecshield_platform.assessment_settings import (  # noqa: E402
    resolve_audit_settings,
    resolve_store_controls,
    supported_audit_kwargs,
)
from vecshield_platform.compliance import AuditLog  # noqa: E402
from vecshield_platform.history import ScanHistory  # noqa: E402
from vecshield_platform.inventory import CSV_COLUMNS, build_inventory  # noqa: E402
from vecshield_platform.posture import vulnfeed  # noqa: E402

SECRET = "store-controls-secret"


def tok(sub, *roles):
    return {"Authorization": "Bearer " + make_jwt({"sub": sub, "roles": list(roles)}, SECRET)}


VIEWER = tok("vera", "viewer")
OPERATOR = tok("otto", "operator")
ALICE = tok("alice", "compliance")
BOB = tok("bob", "compliance")
ADMIN = tok("root", "admin")

SCHEDULE = {"rules": [{"category": "phi", "max_age_days": 365,
                       "basis": "Records policy 4.2"}]}
POLICY = {"allowed_regions": ["eu-west-1"], "allowed_countries": ["DE"],
          "allowed_jurisdictions": ["EU"], "data_subject_regimes": ["GDPR"]}


@pytest.fixture
def env(tmp_path, monkeypatch):
    for name in ("VECSHIELD_SEPARATION_OF_DUTIES", "VECSHIELD_JWT_MAX_LIFETIME",
                 "VECSHIELD_GITHUB_TOKEN", "VECSHIELD_NVD_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    cfg = ConfigStore(path=str(tmp_path / "config.json"))
    cfg.add_store("s1", "chroma", conn={"path": str(tmp_path / "chroma")})
    cfg.add_store("s2", "chroma", conn={"path": str(tmp_path / "chroma2")})
    hist = ScanHistory(str(tmp_path / "history.db"))
    log = AuditLog()
    state = tmp_path / "state"
    state.mkdir()
    app = create_app(config_store=cfg, scan_history=hist, audit_log=log, serve_ui=False,
                     jwt_secret=SECRET, state_dir=str(state))
    client = TestClient(app)
    yield client, cfg, hist, log, app, state
    app.state.jobs.shutdown(wait=False)
    hist.close()


def _actions(log, action):
    return [e for e in log.entries if e.action == action]


def _inventory(store_id="s1", *names):
    cols = [Collection(n, count=10, dimension=4) for n in (names or ("customers",))]
    return build_inventory(VectorStore(kind="chroma", name="local", endpoint="local",
                                       collections=cols),
                           store_id=store_id,
                           classification_by_collection={
                               cols[0].name: {"label_counts": {"pii": 3},
                                              "chunks_scanned": 10}})


def _save_audit(hist, audit_id, *, store_id="s1", inventory=None):
    result = audit_result(audit_id=audit_id, job_id=f"job-{audit_id}")
    result.scope = {"store_id": store_id}
    if inventory is not None:
        result.scope["inventory"] = inventory
    hist.save_audit(result, store_id=store_id)
    return result.id


# --------------------------------------------------------------------------- #
# Role gates                                                                  #
# --------------------------------------------------------------------------- #

ADMIN_WRITES = [
    ("put", "/admin/vulnfeed/settings", {"auto_update": False}),
    ("post", "/admin/vulnfeed/refresh", None),
    ("put", "/admin/retention-schedules", {"global": SCHEDULE}),
    ("put", "/admin/residency-policy", {"default": POLICY}),
    ("put", "/admin/processor-register", {"processors": []}),
]
OPERATOR_ROUTES = [
    ("put", "/stores/s1/inventory/declarations", {"store": {"owner": "Data team"}}),
    ("get", "/stores/s1/source-manifest", None),
    ("put", "/stores/s1/source-manifest", {"entries": [{"source": "a.pdf", "version": "2"}]}),
    ("delete", "/stores/s1/source-manifest", None),
]
COMPLIANCE_WRITES = [
    ("put", "/stores/s1/ccpa-risk-assessment/inputs", {"purpose": "Support search"}),
    ("post", "/stores/s1/ccpa-risk-assessment/approve", {}),
]
READS = [
    "/admin/vulnfeed", "/admin/retention-schedules", "/admin/retention-schedules/categories",
    "/admin/residency-policy", "/admin/processor-register", "/admin/model-providers",
    "/stores/s1/inventory/declarations", "/stores/s1/ccpa-risk-assessment/inputs",
    "/admin/inventory/export?format=json", "/stores/s1/changes",
]


def _call(client, method, url, body, headers):
    kwargs = {"headers": headers}
    if body is not None:
        kwargs["json"] = body
    return getattr(client, method)(url, **kwargs)


@pytest.mark.parametrize("method,url,body", ADMIN_WRITES)
@pytest.mark.parametrize("who", [VIEWER, OPERATOR, ALICE])
def test_settings_writes_are_admin_only(env, method, url, body, who):
    client, *_ = env
    r = _call(client, method, url, body, who)
    assert r.status_code == 403, r.text
    assert r.json()["detail"] == "requires role: admin"


@pytest.mark.parametrize("method,url,body", OPERATOR_ROUTES)
@pytest.mark.parametrize("who", [VIEWER, ALICE])
def test_declarations_and_manifests_need_operator(env, method, url, body, who):
    client, *_ = env
    r = _call(client, method, url, body, who)
    assert r.status_code == 403, r.text
    assert r.json()["detail"] == "requires role: operator"


@pytest.mark.parametrize("method,url,body", OPERATOR_ROUTES)
@pytest.mark.parametrize("who", [OPERATOR, ADMIN])
def test_operator_and_admin_may_write_declarations_and_manifests(env, method, url, body, who):
    client, *_ = env
    assert _call(client, method, url, body, who).status_code == 200


@pytest.mark.parametrize("method,url,body", COMPLIANCE_WRITES)
@pytest.mark.parametrize("who", [VIEWER, OPERATOR])
def test_ccpa_writes_need_compliance(env, method, url, body, who):
    client, *_ = env
    r = _call(client, method, url, body, who)
    assert r.status_code == 403, r.text
    assert r.json()["detail"] == "requires role: compliance"


@pytest.mark.parametrize("url", READS)
def test_viewers_read_every_settings_view(env, url):
    client, *_ = env
    assert client.get(url, headers=VIEWER).status_code == 200, url
    assert client.get(url).status_code == 401


def test_admin_writes_succeed_and_are_audit_logged_without_contents(env):
    client, cfg, _, log, _, _ = env
    r = client.put("/admin/retention-schedules",
                   json={"global": SCHEDULE, "stores": {"s2": {"rules": []}}}, headers=ADMIN)
    assert r.status_code == 200, r.text
    assert r.json()["global"]["rules"][0]["category"] == "phi"
    assert r.json()["stores"]["s2"]["rules"] == []
    r = client.put("/admin/residency-policy",
                   json={"default": POLICY, "stores": {"s1": {"allowed_countries": ["uk"]}}},
                   headers=ADMIN)
    assert r.status_code == 200, r.text
    assert r.json()["stores"]["s1"]["allowed_countries"] == ["GB"]
    r = client.put("/admin/processor-register",
                   json={"processors": [{"provider": "OpenAI", "dpa": True,
                                         "regions": ["US"]},
                                        {"provider": "other:Acme Embeddings"}]},
                   headers=ADMIN)
    assert r.status_code == 200, r.text
    assert [p["provider"] for p in r.json()["processors"]] == ["openai",
                                                               "other:Acme Embeddings"]

    for action in ("retention_schedules_updated", "residency_policy_updated",
                   "processor_register_updated"):
        (entry,) = _actions(log, action)
        assert entry.actor == "root" and len(entry.details["hash"]) == 64
    assert "Records policy" not in json.dumps([e.details for e in log.entries])

    # Persisted, and read back by a fresh ConfigStore.
    reloaded = ConfigStore(path=cfg.path)
    assert reloaded.retention_schedules["global"]["rules"][0]["max_age_days"] == 365
    assert reloaded.residency_policy_for("s1")[1] == "store"
    assert reloaded.residency_policy_for("s2") == (reloaded.residency_policy["default"],
                                                   "default")
    assert client.get("/admin/processor-register", headers=VIEWER).json()["processors"]


@pytest.mark.parametrize("url,body,needle", [
    ("/admin/retention-schedules", {"global": {"rules": [{"category": "nope",
                                                          "max_age_days": 0}]}},
     "unknown category"),
    ("/admin/retention-schedules", {"stores": {"ghost": SCHEDULE}}, "unknown store"),
    ("/admin/residency-policy", {"default": {"allowed_countries": ["XX"]}}, "ISO 3166"),
    ("/admin/residency-policy", {"default": {"allowed_regions": ["mars-1"]}},
     "region catalogue"),
    ("/admin/residency-policy", {"default": {"data_subject_regimes": ["MADEUP"]}},
     "unknown regimes"),
    ("/admin/residency-policy", {"default": {"colour": "red"}}, "unknown fields"),
    ("/admin/processor-register", {"processors": [{"provider": "bogus"}]},
     "unknown provider"),
    ("/admin/processor-register", {"processors": [{"provider": "openai", "dpa": "yes"}]},
     "dpa must be"),
    ("/admin/vulnfeed/settings", {"interval_hours": 2}, "interval_hours"),
    ("/admin/vulnfeed/settings", {"credentials": {"github_token": "ghp_secret"}},
     "never stored"),
])
def test_invalid_settings_are_refused_with_every_problem(env, url, body, needle):
    client, cfg, _, log, _, _ = env
    r = client.put(url, json=body, headers=ADMIN)
    assert r.status_code == 422, r.text
    assert any(needle in p for p in r.json()["detail"]["problems"]), r.json()
    assert log.entries == []  # nothing applied, nothing logged
    assert "ghp_secret" not in open(cfg.path).read()


def test_declaration_and_manifest_validation(env):
    client, *_ = env
    r = client.put("/stores/s1/inventory/declarations",
                   json={"store": {"support_expiration_date": "next year"}}, headers=OPERATOR)
    assert r.status_code == 422 and "ISO date" in r.json()["detail"]["problems"][0]
    r = client.put("/stores/s1/source-manifest", json={"entries": [{"version": "1"}]},
                   headers=OPERATOR)
    assert r.status_code == 422 and "source identifier" in r.json()["detail"]["problems"][0]
    assert client.put("/stores/nope/source-manifest", json={"entries": []},
                      headers=OPERATOR).status_code == 404


def test_source_manifest_round_trip_and_audit_log(env):
    client, cfg, _, log, _, _ = env
    body = {"entries": [{"source": "a.pdf", "version": "3"},
                        {"source": "b.pdf", "deleted": True}]}
    r = client.put("/stores/s1/source-manifest", json=body, headers=OPERATOR)
    assert r.status_code == 200 and r.json()["count"] == 2
    view = client.get("/stores/s1/source-manifest", headers=OPERATOR).json()
    assert view["supplied"] and view["updated_by"] == "otto" and len(view["hash"]) == 64
    (entry,) = _actions(log, "source_manifest_updated")
    assert entry.details == {"entries": 2, "hash": view["hash"]}
    assert client.delete("/stores/s1/source-manifest", headers=OPERATOR).json()[
        "supplied"] is False
    assert _actions(log, "source_manifest_cleared")
    assert cfg.get_source_manifest("s1") is None


# --------------------------------------------------------------------------- #
# Advisory feed                                                               #
# --------------------------------------------------------------------------- #

def test_feed_status_reports_seed_and_egress_without_secrets(env, monkeypatch):
    client, cfg, _, _, _, state = env
    monkeypatch.setenv("VECSHIELD_GITHUB_TOKEN", "ghp_live_token_value")
    monkeypatch.setenv("FEED_NVD", "nvd-secret-value")
    r = client.put("/admin/vulnfeed/settings",
                   json={"credentials": {"nvd_api_key_env": "FEED_NVD"}}, headers=ADMIN)
    assert r.status_code == 200, r.text
    body = client.get("/admin/vulnfeed", headers=VIEWER)
    text = body.text
    assert "ghp_live_token_value" not in text and "nvd-secret-value" not in text
    assert "FEED_NVD" not in text  # not even the reference name
    data = body.json()
    assert data["feed"]["origin"] in ("seed", "none")
    assert data["schedule"]["auto_update"] is False
    assert data["credentials"]["github_token"] == {"configured": True,
                                                   "source": "environment",
                                                   "reference_kind": None}
    assert data["credentials"]["nvd_api_key"]["source"] == "reference"
    assert data["egress_hosts"] == list(EGRESS_HOSTS)
    assert data["limits"]["min_interval_hours"] == 6
    assert "nvd-secret-value" not in open(cfg.path).read()


def test_enabling_auto_update_records_egress_consent(env):
    client, _, _, log, _, state = env
    r = client.put("/admin/vulnfeed/settings",
                   json={"auto_update": True, "interval_hours": 12}, headers=ADMIN)
    assert r.status_code == 200, r.text
    assert r.json()["schedule"]["auto_update"] is True
    assert vulnfeed.load_schedule(state).interval_hours == 12
    (entry,) = _actions(log, "vulnfeed_settings_updated")
    consent = entry.details["egress_consent"]
    assert consent["granted_by"] == "root" and consent["hosts"] == list(EGRESS_HOSTS)
    # Changing the interval later is not a second consent.
    client.put("/admin/vulnfeed/settings", json={"interval_hours": 24}, headers=ADMIN)
    assert "egress_consent" not in _actions(log, "vulnfeed_settings_updated")[-1].details


def test_feed_settings_need_a_state_dir(tmp_path):
    app = create_app(config_store=ConfigStore(), serve_ui=False, jwt_secret=SECRET)
    try:
        client = TestClient(app)
        assert client.put("/admin/vulnfeed/settings", json={"auto_update": True},
                          headers=ADMIN).status_code == 409
        assert client.post("/admin/vulnfeed/refresh", headers=ADMIN).status_code == 409
        assert client.get("/admin/vulnfeed", headers=VIEWER).json()[
            "state_dir_configured"] is False
        assert app.state.feed_scheduler is None
    finally:
        app.state.jobs.shutdown(wait=False)


def _wait_job(app, job_id, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = app.state.jobs.get(job_id)
        if job and job["status"] in ("succeeded", "failed"):
            return job
        time.sleep(0.02)
    raise AssertionError("job did not finish")


def test_manual_refresh_is_a_background_job_and_rate_limited(env, monkeypatch):
    client, _, _, log, app, state = env
    monkeypatch.setenv("VECSHIELD_GITHUB_TOKEN", "ghp_token_for_refresh")
    calls = []

    def fake_refresh(state_dir, settings=None, *, force=False, **kwargs):
        calls.append({"state_dir": str(state_dir), "force": force, **kwargs})
        s = vulnfeed.FeedSchedule(last_success="2026-09-29T00:00:00+00:00")
        return s, vulnfeed.RefreshResult(ok=True, updated_at="2026-09-29T00:00:00+00:00",
                                         feed_hash="abc", sources={"osv:x": {"ok": True}},
                                         path=str(state_dir))

    monkeypatch.setattr(vulnfeed, "refresh_if_due", fake_refresh)
    r = client.post("/admin/vulnfeed/refresh", headers=ADMIN)
    assert r.status_code == 202, r.text
    job = _wait_job(app, r.json()["job_id"])
    assert job["status"] == "succeeded" and job["result"]["ok"] is True
    assert calls == [{"state_dir": str(state), "force": True, "persist": False,
                      "now": None, "github_token": "ghp_token_for_refresh",
                      "nvd_api_key": None}]
    assert vulnfeed.load_schedule(state).last_success == "2026-09-29T00:00:00+00:00"
    assert "ghp_token_for_refresh" not in json.dumps(job)

    again = client.post("/admin/vulnfeed/refresh", headers=ADMIN)
    assert again.status_code == 429 and int(again.headers["Retry-After"]) > 0
    assert len(calls) == 1
    assert len(_actions(log, "vulnfeed_refresh_requested")) == 1
    (done,) = _actions(log, "vulnfeed_refreshed")
    assert done.details["feed_hash"] == "abc"
    assert "ghp_token_for_refresh" not in json.dumps([e.details for e in log.entries])


# --------------------------------------------------------------------------- #
# Scheduler                                                                   #
# --------------------------------------------------------------------------- #

class _Clock:
    def __init__(self):
        self.now = datetime(2026, 9, 29, tzinfo=timezone.utc)

    def __call__(self):
        return self.now


def _fake_refresh(calls):
    def refresh(state_dir, settings, *, now, **kwargs):
        calls.append((now, kwargs))
        settings.last_attempt = settings.last_success = now.isoformat()
        vulnfeed.save_schedule(state_dir, settings)
        return settings, "result"
    return refresh


def test_scheduler_is_a_no_op_unless_auto_update_is_on(tmp_path):
    calls = []
    sched = FeedScheduler(tmp_path, refresh=_fake_refresh(calls), clock=_Clock())
    assert sched.tick() is None and calls == []
    vulnfeed.save_schedule(tmp_path, vulnfeed.FeedSchedule(auto_update=False))
    assert sched.tick() is None and calls == []


def test_scheduler_refreshes_when_due_and_waits_the_interval(tmp_path):
    calls, reported = [], []
    clock = _Clock()
    vulnfeed.save_schedule(tmp_path, vulnfeed.FeedSchedule(auto_update=True,
                                                           interval_hours=6))
    sched = FeedScheduler(tmp_path, refresh=_fake_refresh(calls), clock=clock,
                          credentials=lambda: {"github_token": "t"},
                          on_refresh=lambda s, r: reported.append(r))
    assert sched.tick() == "result"
    assert calls[0][1] == {"github_token": "t"} and reported == ["result"]
    clock.now += timedelta(hours=1)
    assert sched.tick() is None and len(calls) == 1
    clock.now += timedelta(hours=6)
    assert sched.tick() == "result" and len(calls) == 2


def test_scheduler_never_raises_and_skips_while_a_refresh_holds_the_lock(tmp_path):
    vulnfeed.save_schedule(tmp_path, vulnfeed.FeedSchedule(auto_update=True))

    def boom(*a, **k):
        raise RuntimeError("network down")

    lock = threading.Lock()
    sched = FeedScheduler(tmp_path, refresh=boom, clock=_Clock(), lock=lock)
    assert sched.tick() is None
    calls = []
    sched = FeedScheduler(tmp_path, refresh=_fake_refresh(calls), clock=_Clock(), lock=lock)
    with lock:
        assert sched.tick() is None
    assert calls == []


def test_scheduler_thread_starts_and_stops_cleanly(tmp_path):
    ticked = threading.Event()

    class Probe(FeedScheduler):
        def tick(self):
            ticked.set()
            return None

    sched = Probe(tmp_path, tick_s=0.01, first_tick_s=0.01).start()
    assert ticked.wait(2.0) and sched.running
    sched.stop(timeout=2.0)
    assert not sched.running


def test_the_app_starts_no_scheduler_unless_asked(env):
    _, _, _, _, app, _ = env
    assert app.state.feed_scheduler is None


def test_the_server_scheduler_is_started_and_stopped_with_the_app(tmp_path, monkeypatch):
    monkeypatch.delenv("VECSHIELD_VULNFEED_SCHEDULER", raising=False)
    app = create_app(config_store=ConfigStore(), serve_ui=False, jwt_secret=SECRET,
                     state_dir=str(tmp_path), vulnfeed_scheduler=True)
    try:
        sched = app.state.feed_scheduler
        assert sched is not None and sched.running
        assert sched.stop in app.router.on_shutdown
    finally:
        app.state.feed_scheduler.stop()
        app.state.jobs.shutdown(wait=False)
    assert not sched.running
    monkeypatch.setenv("VECSHIELD_VULNFEED_SCHEDULER", "off")
    app = create_app(config_store=ConfigStore(), serve_ui=False, jwt_secret=SECRET,
                     state_dir=str(tmp_path), vulnfeed_scheduler=True)
    assert app.state.feed_scheduler is None
    app.state.jobs.shutdown(wait=False)


# --------------------------------------------------------------------------- #
# Inventory                                                                   #
# --------------------------------------------------------------------------- #

def test_inventory_404_explains_why(env):
    client, _, hist, *_ = env
    r = client.get("/stores/s1/inventory", headers=VIEWER)
    assert r.status_code == 404 and "operator must run" in r.json()["detail"]
    _save_audit(hist, "audit-old")
    r = client.get("/stores/s1/inventory", headers=VIEWER)
    assert r.status_code == 404 and "carries an inventory" in r.json()["detail"]
    assert client.get("/stores/s1/inventory/changes", headers=VIEWER).status_code == 404


def test_inventory_serves_latest_with_declarations_and_changes(env):
    client, _, hist, log, _, _ = env
    _save_audit(hist, "audit-a", inventory=_inventory("s1", "customers"))
    _save_audit(hist, "audit-b", inventory=_inventory("s1", "customers", "customers_copy"))
    r = client.put("/stores/s1/inventory/declarations",
                   json={"store": {"owner": "Data Platform", "recovery_time_objective": "4h"},
                         "collections": {"customers": {"business_purpose": "Support"}}},
                   headers=OPERATOR)
    assert r.status_code == 200, r.text
    assert _actions(log, "inventory_declarations_updated")[0].details["store_fields"] == [
        "owner", "recovery_time_objective"]
    body = client.get("/stores/s1/inventory", headers=VIEWER).json()
    assert body["audit_id"] == "audit-b"
    inv = body["inventory"]
    assert inv["store"]["declared"]["owner"] == {"value": "Data Platform", "declared": True}
    col = next(c for c in inv["collections"] if c["name"] == "customers")
    assert col["declared"]["business_purpose"]["value"] == "Support"
    assert inv["inventory_hash"] != _inventory("s1", "customers", "customers_copy")[
        "inventory_hash"]
    changes = client.get("/stores/s1/inventory/changes", headers=VIEWER).json()
    assert changes["store_id"] == "s1"
    assert "customers_copy" in json.dumps(changes)


def test_store_changes_says_when_there_is_nothing_to_compare(env):
    client, _, hist, *_ = env
    assert client.get("/stores/nope/changes", headers=VIEWER).status_code == 404
    assert client.get("/stores/s1/changes").status_code == 401
    r = client.get("/stores/s1/changes", headers=VIEWER)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["compared"] is False and "no saved audit" in body["reason"]
    assert "new" not in body
    _save_audit(hist, "audit-only")
    body = client.get("/stores/s1/changes", headers=VIEWER).json()
    assert body["compared"] is False and body["after_audit_id"] == "audit-only"
    assert "next audit will be compared" in body["reason"]


def test_store_changes_compares_the_latest_two_audits(env):
    client, _, hist, *_ = env
    _save_audit(hist, "audit-a")
    result = audit_result(audit_id="audit-b", job_id="job-audit-b")
    result.scope = {"store_id": "s1"}
    result.jobs[0].add(Finding(id="finding-extra", title="Second synthetic finding",
                               severity=Severity.MEDIUM, category="rag_integrity",
                               store=result.jobs[0].store, collection="docs"))
    hist.save_audit(result, store_id="s1")
    body = client.get("/stores/s1/changes", headers=VIEWER).json()
    assert body["compared"] is True
    assert (body["before_audit_id"], body["after_audit_id"]) == ("audit-a", "audit-b")
    assert body["before_at"] and body["after_at"]
    assert [e["title"] for e in body["new"]] == ["Second synthetic finding"]
    assert body["new"][0]["severity"] == "medium" and body["new"][0]["collection"] == "docs"
    assert body["persistent"] == 1 and body["new_total"] == 1
    assert body["resolved"] == [] and body["not_retested"] == []
    assert "evidence" not in json.dumps(body)


def test_estate_csv_export_is_safe_and_names_missing_stores(env):
    client, _, hist, log, _, _ = env
    _save_audit(hist, "audit-x", inventory=_inventory("s1", "=HYPERLINK(\"http://x\")"))
    client.put("/stores/s1/inventory/declarations",
               json={"store": {"owner": "+cmd|' /C calc'!A0"}}, headers=ADMIN)
    r = client.get("/admin/inventory/export?format=csv", headers=VIEWER)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert 'filename="vecshield-inventory-' in r.headers["content-disposition"]
    assert r.headers["x-vecshield-stores-without-inventory"] == "1"
    rows = list(csv.reader(io.StringIO(r.text)))
    assert tuple(rows[0]) == CSV_COLUMNS
    row = dict(zip(rows[0], rows[1]))
    assert row["collection"].startswith("'=") and row["store_owner"].startswith("'+")
    j = client.get("/admin/inventory/export?format=json", headers=VIEWER)
    assert j.headers["content-type"].startswith("application/json")
    doc = j.json()
    assert [i["store"]["id"] for i in doc["inventories"]] == ["s1"]
    assert doc["stores_without_inventory"][0]["store_id"] == "s2"
    assert client.get("/admin/inventory/export?format=xml",
                      headers=VIEWER).status_code == 422
    assert [e.details["format"] for e in _actions(log, "inventory_exported")] == ["csv", "json"]


def test_merge_declarations_keeps_undeclared_fields_visible():
    merged = merge_declarations(_inventory(), {"store": {"owner": "A"}})
    assert merged["store"]["declared"]["support_contact"] == {"value": None,
                                                              "declared": False}
    assert merged["totals"]["undeclared_fields"] == 4 + 2  # 4 store + 2 collection


# --------------------------------------------------------------------------- #
# CCPA risk assessment                                                        #
# --------------------------------------------------------------------------- #

def test_ccpa_needs_a_saved_audit(env):
    client, *_ = env
    r = client.get("/stores/s1/ccpa-risk-assessment", headers=VIEWER)
    assert r.status_code == 404


def test_ccpa_inputs_are_versioned_and_approved_by_a_second_person(env):
    client, cfg, hist, log, _, _ = env
    _save_audit(hist, "audit-c", inventory=_inventory())
    assert client.post("/stores/s1/ccpa-risk-assessment/approve", json={},
                       headers=BOB).status_code == 409  # nothing saved yet

    bad = client.put("/stores/s1/ccpa-risk-assessment/inputs",
                     json={"processing_started": "soon", "mystery": 1}, headers=ALICE)
    assert bad.status_code == 422
    assert len(bad.json()["detail"]["problems"]) == 2
    forged = client.put("/stores/s1/ccpa-risk-assessment/inputs",
                        json={"review_and_approval": {"date": "2026-09-01",
                                                      "approvers": ["me"]}},
                        headers=ALICE)
    assert forged.status_code == 422

    v1 = client.put("/stores/s1/ccpa-risk-assessment/inputs",
                    json={"purpose": "Customer support retrieval"}, headers=ALICE)
    assert v1.status_code == 200 and v1.json()["version"] == 1
    v2 = client.put("/stores/s1/ccpa-risk-assessment/inputs",
                    json={"purpose": "Customer support retrieval over tickets",
                          "benefits": "Faster answers"}, headers=ALICE)
    assert v2.json()["version"] == 2
    history = client.get("/stores/s1/ccpa-risk-assessment/inputs", headers=VIEWER).json()
    assert [v["version"] for v in history["versions"]] == [1, 2]
    assert history["versions"][0]["inputs"] == {"purpose": "Customer support retrieval"}

    self_approval = client.post("/stores/s1/ccpa-risk-assessment/approve",
                                json={}, headers=ALICE)
    assert self_approval.status_code == 409
    assert client.post("/stores/s1/ccpa-risk-assessment/approve", json={"version": 1},
                       headers=BOB).status_code == 409  # not the latest
    ok = client.post("/stores/s1/ccpa-risk-assessment/approve",
                     json={"position": "Privacy Counsel"}, headers=BOB)
    assert ok.status_code == 200, ok.text
    assert ok.json()["approved_by"] == "bob" and ok.json()["version"] == 2
    assert client.post("/stores/s1/ccpa-risk-assessment/approve", json={},
                       headers=BOB).status_code == 409  # already approved

    body = client.get("/stores/s1/ccpa-risk-assessment", headers=VIEWER).json()
    assert body["inputs_version"] == 2 and body["approval_current"] is True
    approval = next(e for e in body["elements"] if e["key"] == "review_and_approval")
    assert approval["status"] == "business_provided"
    assert approval["business_input"]["approvers"] == [{"name": "bob",
                                                        "position": "Privacy Counsel"}]
    assert body["audit_id"] == "audit-c"

    client.put("/stores/s1/ccpa-risk-assessment/inputs",
               json={"purpose": "Changed"}, headers=ALICE)
    body = client.get("/stores/s1/ccpa-risk-assessment", headers=VIEWER).json()
    assert body["inputs_version"] == 3 and body["approval_current"] is False
    assert len(cfg.ccpa_record("s1")["versions"]) == 3  # nothing overwritten

    saved = _actions(log, "ccpa_risk_inputs_saved")
    assert len(saved) == 3 and "Customer support" not in json.dumps(saved[0].details)
    (approved,) = _actions(log, "ccpa_risk_approved")
    assert approved.actor == "bob" and approved.details["version"] == 2

    html = client.get("/stores/s1/ccpa-risk-assessment?format=html", headers=VIEWER)
    assert html.status_code == 200 and html.headers["content-type"].startswith("text/html")
    assert _actions(log, "ccpa_risk_assessment_downloaded")


def test_ccpa_rejects_an_audit_from_another_store(env):
    client, _, hist, *_ = env
    _save_audit(hist, "audit-other", store_id="s2")
    r = client.get("/stores/s1/ccpa-risk-assessment?audit_id=audit-other", headers=VIEWER)
    assert r.status_code == 404


# --------------------------------------------------------------------------- #
# Settings reach the audit                                                    #
# --------------------------------------------------------------------------- #

def test_resolved_settings_carry_controls_and_freeze_hashes_not_contents(tmp_path):
    cfg = ConfigStore(path=str(tmp_path / "c.json"))
    store = cfg.add_store("s1", "chroma", conn={"path": str(tmp_path / "x")})
    cfg.set_retention_schedules({"global": SCHEDULE})
    cfg.set_residency_policy({"default": POLICY})
    cfg.set_processor_register([{"provider": "openai", "dpa": True}])
    cfg.set_source_manifest("s1", [{"source": "a.pdf", "version": "1"}],
                            actor="otto", now="2026-09-29T00:00:00+00:00")
    settings = resolve_audit_settings(cfg, store, state_dir=str(tmp_path))
    kw = settings.audit_kwargs
    assert kw["retention_schedule"].rules[0].category == "phi"
    assert kw["residency_policy"]["allowed_countries"] == ["DE"]
    assert kw["processor_register"][0]["provider"] == "openai"
    assert kw["source_manifest"] == [{"source": "a.pdf", "version": "1"}]
    assert kw["vuln_feed_dir"] == str(tmp_path)
    controls = settings.scope["store_controls"]
    assert controls["retention_schedule"]["declared"] is True
    assert controls["retention_schedule"]["source"] == "global"
    assert controls["residency_policy"]["source"] == "default"
    assert controls["source_manifest"]["entries"] == 1
    text = json.dumps(controls)
    assert "Records policy" not in text and "a.pdf" not in text and "DE" not in text

    # A store override replaces the global schedule.
    cfg.set_retention_schedules({"global": SCHEDULE, "stores": {"s1": {"rules": []}}})
    kw, scope = resolve_store_controls(cfg, "s1")
    assert kw["retention_schedule"] is None and scope["retention_schedule"]["source"] == "store"


def test_supported_kwargs_record_controls_the_orchestrator_does_not_take():
    def old_audit(conn, *, retention_schedule=None):
        return None

    scope = {"store_controls": {}}
    kwargs = supported_audit_kwargs(old_audit, {"retention_schedule": 1,
                                                "residency_policy": 2}, scope)
    assert kwargs == {"retention_schedule": 1}
    assert scope["store_controls"]["not_applied"] == ["residency_policy"]
    assert supported_audit_kwargs(lambda c, **kw: None, {"a": 1}) == {"a": 1}


def test_removing_a_store_drops_its_overrides_but_keeps_ccpa_records(tmp_path):
    cfg = ConfigStore(path=str(tmp_path / "c.json"))
    cfg.add_store("s1", "chroma", conn={"path": str(tmp_path / "x")})
    cfg.set_retention_schedules({"stores": {"s1": SCHEDULE}})
    cfg.set_inventory_declarations("s1", {"store": {"owner": "A"}}, actor="a", now="t")
    cfg.add_ccpa_inputs("s1", {"purpose": "x"}, actor="a", now="t")
    cfg.remove_store("s1")
    assert cfg.retention_schedules["stores"] == {}
    assert cfg.get_inventory_declarations("s1") == {"store": {}, "collections": {}}
    assert len(cfg.ccpa_record("s1")["versions"]) == 1


# --------------------------------------------------------------------------- #
# CLI                                                                         #
# --------------------------------------------------------------------------- #

def test_cli_audit_rejects_an_invalid_schedule_before_connecting(tmp_path, monkeypatch):
    from click.testing import CliRunner

    from vecshield_platform import cli as cli_module

    bad = tmp_path / "schedule.json"
    bad.write_text(json.dumps({"rules": [{"category": "nope", "max_age_days": 1,
                                          "basis": "x"}]}))
    monkeypatch.setattr(cli_module, "_connector_from_opts",
                        lambda conn: pytest.fail("connected before validating"))
    result = CliRunner().invoke(cli_module.cli, ["audit", "--no-nlp",
                                                 "--retention-schedule", str(bad)])
    assert result.exit_code != 0 and "unknown category" in result.output


def test_cli_inventory_export_and_ccpa(tmp_path):
    from click.testing import CliRunner

    from vecshield_platform import cli as cli_module

    config = tmp_path / "vecshield.json"
    cfg = ConfigStore(path=str(config))
    cfg.add_store("s1", "chroma", conn={"path": str(tmp_path / "x")})
    cfg.set_inventory_declarations("s1", {"store": {"owner": "Ops"}}, actor="a", now="t")
    state = tmp_path / "state"
    from vecshield_platform.api.state import resolve_state_paths
    hist = ScanHistory(resolve_state_paths(str(config), str(state)).history_db)
    _save_audit(hist, "audit-cli", inventory=_inventory())
    hist.close()

    out = tmp_path / "inv.csv"
    runner = CliRunner()
    result = runner.invoke(cli_module.cli, ["inventory", "export", "--config", str(config),
                                            "--state-dir", str(state), "--format", "csv",
                                            "--out", str(out)])
    assert result.exit_code == 0, result.output
    rows = list(csv.DictReader(io.StringIO(out.read_text())))
    assert rows[0]["store_id"] == "s1" and rows[0]["store_owner"] == "Ops"

    inputs = tmp_path / "inputs.json"
    inputs.write_text(json.dumps({"purpose": "Support"}))
    html = tmp_path / "ccpa.html"
    result = runner.invoke(cli_module.cli, ["ccpa-risk", "--config", str(config),
                                            "--state-dir", str(state), "--store", "s1",
                                            "--inputs", str(inputs), "--html", str(html)])
    assert result.exit_code == 0, result.output
    assert "<html" in html.read_text().lower()
    # Without --html/--json the workbook goes to stdout alone, so it can be piped;
    # the completeness summary goes to stderr.
    result = runner.invoke(cli_module.cli, ["ccpa-risk", "--config", str(config),
                                            "--state-dir", str(state), "--store", "s1",
                                            "--inputs", str(inputs)])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["store"] == "s1"
    assert result.stderr.strip()
    inputs.write_text(json.dumps({"not_a_field": 1}))
    result = runner.invoke(cli_module.cli, ["ccpa-risk", "--config", str(config),
                                            "--state-dir", str(state), "--store", "s1",
                                            "--inputs", str(inputs)])
    assert result.exit_code != 0 and "not a recognised input" in result.output


def test_cli_vulnfeed_status_wraps_the_module(tmp_path):
    from click.testing import CliRunner

    from vecshield_platform import cli as cli_module

    result = CliRunner().invoke(cli_module.cli, ["vulnfeed", "status",
                                                 "--state-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["origin"] in ("seed", "none")


def test_settings_scope_merges_with_what_the_orchestrator_observed():
    from vecshield_platform.assessment_settings import apply_settings_scope

    scope = {"store_controls": {"residency_policy": {"supplied": True, "allowed_countries": 1},
                                "vuln_feed": {"source": "seed"}}}
    apply_settings_scope(scope, {"store_id": "s1", "store_controls": {
        "residency_policy": {"source": "default", "hash": "h"},
        "vuln_feed": {"state_dir_configured": False}, "not_applied": ["x"]}})
    assert scope["store_id"] == "s1"
    assert scope["store_controls"]["residency_policy"] == {
        "supplied": True, "allowed_countries": 1, "source": "default", "hash": "h"}
    assert scope["store_controls"]["vuln_feed"] == {"source": "seed",
                                                    "state_dir_configured": False}
    assert scope["store_controls"]["not_applied"] == ["x"]


def test_an_api_audit_applies_the_saved_controls_end_to_end(tmp_path, monkeypatch):
    chromadb = pytest.importorskip("chromadb")
    for name in ("VECSHIELD_SEPARATION_OF_DUTIES", "VECSHIELD_NLP_MODEL"):
        monkeypatch.delenv(name, raising=False)
    path = str(tmp_path / "chroma")
    col = chromadb.PersistentClient(path=path).create_collection("tickets")
    col.add(ids=["a", "b"], documents=["call jane@example.com", "lunch menu"],
            embeddings=[[0.1, 0.2], [0.3, 0.1]],
            metadatas=[{"source": "t1.txt"}, {"source": "t2.txt"}])
    cfg = ConfigStore(path=str(tmp_path / "config.json"))
    cfg.add_store("demo", "chroma", conn={"path": path})
    cfg.set_retention_schedules({"global": SCHEDULE})
    cfg.set_residency_policy({"default": POLICY})
    cfg.set_inventory_declarations("demo", {"store": {"owner": "Support"}},
                                   actor="otto", now="2026-09-29T00:00:00+00:00")
    hist = ScanHistory(str(tmp_path / "history.db"))
    state = tmp_path / "state"
    state.mkdir()
    app = create_app(config_store=cfg, scan_history=hist, audit_log=AuditLog(),
                     serve_ui=False, jwt_secret=SECRET, state_dir=str(state))
    try:
        client = TestClient(app)
        r = client.post("/stores/demo/audit",
                        json={"no_nlp": True, "include_integrity": False}, headers=OPERATOR)
        assert r.status_code == 200, r.text
        scope = r.json()["scope"]
        controls = scope["store_controls"]
        assert controls["retention_schedule"]["declared"] is True
        assert controls["retention_schedule"]["source"] == "global"
        assert controls["residency_policy"]["source"] == "default"
        assert "not_applied" not in controls, controls
        inv = client.get("/stores/demo/inventory", headers=VIEWER)
        assert inv.status_code == 200, inv.text
        assert inv.json()["inventory"]["store"]["id"] == "demo"
        assert inv.json()["inventory"]["store"]["declared"]["owner"]["value"] == "Support"
        ccpa = client.get("/stores/demo/ccpa-risk-assessment", headers=VIEWER)
        assert ccpa.status_code == 200, ccpa.text
        assert "jane@example.com" not in ccpa.text
    finally:
        app.state.jobs.shutdown(wait=False)
        hist.close()


def test_a_refresh_does_not_undo_a_settings_change_made_while_it_ran(tmp_path, monkeypatch):
    from vecshield_platform.api.feed_scheduler import refresh_preserving_settings

    vulnfeed.save_schedule(tmp_path, vulnfeed.FeedSchedule(auto_update=True))

    def slow_refresh(state_dir, settings=None, *, now=None, force=False, persist=True, **kw):
        assert persist is False
        loaded = vulnfeed.load_schedule(state_dir)
        # An admin turns auto-update off while the refresh is still running.
        vulnfeed.save_schedule(state_dir, vulnfeed.FeedSchedule(auto_update=False,
                                                                interval_hours=48))
        loaded.last_attempt = loaded.last_success = "2026-09-29T01:00:00+00:00"
        return loaded, "result"

    monkeypatch.setattr(vulnfeed, "refresh_if_due", slow_refresh)
    settings, result = refresh_preserving_settings(tmp_path, force=True)
    saved = vulnfeed.load_schedule(tmp_path)
    assert result == "result"
    assert saved.auto_update is False and saved.interval_hours == 48
    assert saved.last_success == "2026-09-29T01:00:00+00:00"
