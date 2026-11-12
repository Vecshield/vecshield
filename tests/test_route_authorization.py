"""Server-side role gates and deletion guards (bug hunt: authz F1-F4, F9, F11;
approvals H1, L3; connectors M3; coverage C-9; console F6).

Roles, as decided for the product:

* ``viewer`` reads everything (reports, logs, masked views) and starts nothing.
* ``operator`` (or admin) runs assessments that write results.
* ``compliance`` (or admin) previews erasure and opens and executes DSARs.
* Deletion obeys safe mode for everyone and needs a second person unless the
  caller is an admin or separation of duties is off.
"""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("chromadb")

from fastapi.testclient import TestClient  # noqa: E402

from test_auth import make_jwt  # noqa: E402

from vecshield_platform.api import StoreRegistry, create_app  # noqa: E402
from vecshield_platform.api.app import (  # noqa: E402
    DSAR_SELF_EXECUTE_DETAIL,
    ERASURE_NEEDS_DSAR_DETAIL,
    NO_SAVED_AUDIT_DETAIL,
)
from vecshield_platform.compliance import AuditLog  # noqa: E402
from vecshield_platform.history import ScanHistory  # noqa: E402

SECRET = "route-authz-secret"
SUBJECT = "jane@example.com"


def tok(sub, *roles):
    return {"Authorization": "Bearer " + make_jwt({"sub": sub, "roles": list(roles)}, SECRET)}


VIEWER = tok("vera", "viewer")
OPERATOR = tok("otto", "operator")
ALICE = tok("alice", "compliance")
BOB = tok("bob", "compliance")
ADMIN = tok("root", "admin")


def _chroma(path):
    import chromadb
    col = chromadb.PersistentClient(path=path).create_collection("runbooks")
    col.add(ids=["c1", "c2", "c3"],
            documents=["rotate AKIAIOSFODNN7EXAMPLE tonight", "benign note about lunch",
                       f"Ticket from {SUBJECT} re billing"],
            embeddings=[[0.1, 0.2], [0.9, 0.1], [0.3, 0.3]],
            metadatas=[{"team": "sre"}, {"team": "sre"}, {"team": "billing"}])


def _ids(path):
    import chromadb
    return sorted(chromadb.PersistentClient(path=path).get_collection("runbooks").get()["ids"])


@pytest.fixture
def env(tmp_path, monkeypatch):
    for name in ("VECSHIELD_SAFE_MODE", "VECSHIELD_SEPARATION_OF_DUTIES",
                 "VECSHIELD_NLP_MODEL", "VECSHIELD_JWT_MAX_LIFETIME"):
        monkeypatch.delenv(name, raising=False)
    path = str(tmp_path / "chroma")
    _chroma(path)
    reg = StoreRegistry()
    reg.register("demo", "chroma", path=path)
    hist = ScanHistory(str(tmp_path / "history.db"))
    log = AuditLog()
    apps = []

    def make(**kw):
        app = create_app(reg, scan_history=hist, audit_log=log, serve_ui=False,
                         jwt_secret=SECRET, **kw)
        apps.append(app)
        return TestClient(app)

    yield make(), hist, log, path, make
    for app in apps:
        app.state.jobs.shutdown(wait=False)


def _actions(log, action):
    return [e for e in log.entries if e.action == action]


# --------------------------------------------------------------------------- #
# Assessments that write results need operator                                #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("method,url,body", [
    ("post", "/stores/demo/scan?no_nlp=true", None),
    ("post", "/stores/demo/scan/integrity?collection=runbooks", None),
    ("post", "/stores/demo/audit", {"no_nlp": True}),
    ("post", "/stores/demo/posture", None),
    ("post", "/stores/demo/probe-isolation?collection=runbooks&tenant_field=team", None),
    ("post", "/stores/demo/pia", {"no_nlp": True}),
    ("post", "/stores/demo/pia/html", {"no_nlp": True}),
])
@pytest.mark.parametrize("who", ["viewer", "compliance"])
def test_assessments_refuse_callers_without_operator(env, method, url, body, who):
    client, hist, log, _, _ = env
    headers = VIEWER if who == "viewer" else ALICE
    r = getattr(client, method)(url, headers=headers, json=body)
    assert r.status_code == 403, r.text
    assert r.json()["detail"] == "requires role: operator"
    assert hist.list_jobs() == [] and hist.list_audits(store_id="demo") == []


def test_operator_and_admin_can_scan(env):
    client, hist, log, _, _ = env
    assert client.post("/stores/demo/scan?no_nlp=true", headers=OPERATOR).status_code == 200
    assert client.post("/stores/demo/scan?no_nlp=true", headers=ADMIN).status_code == 200
    assert len(hist.list_jobs()) == 2


def test_reading_a_report_never_runs_an_audit_for_a_viewer(env):
    client, hist, log, _, _ = env
    for url in ("/stores/demo/report", "/stores/demo/pia/html"):
        r = client.get(url, headers=VIEWER)
        assert r.status_code == 404, url
        assert r.json() == {"detail": NO_SAVED_AUDIT_DETAIL}
    r = client.post("/stores/demo/report", headers=VIEWER, json={})
    assert r.status_code == 404 and r.json()["detail"] == NO_SAVED_AUDIT_DETAIL
    assert hist.list_audits(store_id="demo") == []
    assert not _actions(log, "full_audit") and not _actions(log, "pia_generated")
    # Unknown store is still a 404 about the store, not about the audit.
    assert "unknown store" in client.get("/stores/nope/pia/html", headers=VIEWER).json()["detail"]

    # An operator's read keeps the fallback; afterwards the viewer reads it.
    assert client.get("/stores/demo/report", headers=OPERATOR).status_code == 200
    assert len(hist.list_audits(store_id="demo")) == 1
    assert client.get("/stores/demo/report", headers=VIEWER).status_code == 200
    assert len(hist.list_audits(store_id="demo")) == 1


def test_viewer_still_reads(env):
    client, *_ = env
    # The log's shape and chain status, with entry details withheld (F3).
    r = client.get("/audit-log", headers=VIEWER)
    assert r.status_code == 200 and r.json()["details_withheld"] is True
    assert client.get("/stores/demo/schema", headers=VIEWER).status_code == 200
    assert client.post("/admin/stores/demo/test", headers=VIEWER).status_code == 200
    # Read-only views of saved history: viewers read them, anonymous callers do not.
    for url in ("/stores/demo/changes", "/admin/findings/export?format=csv"):
        assert client.get(url, headers=VIEWER).status_code == 200, url
        assert client.get(url).status_code == 401, url


# --------------------------------------------------------------------------- #
# Erasure and DSAR are compliance actions                                     #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("headers", [VIEWER, OPERATOR])
def test_erasure_preview_and_dsar_need_compliance(env, headers):
    client, hist, log, _, _ = env
    r = client.post("/stores/demo/erasure", headers=headers, json={"subject": SUBJECT})
    assert r.status_code == 403 and r.json()["detail"] == "requires role: compliance"
    r = client.post("/admin/dsar", headers=headers, json={"subject": SUBJECT})
    assert r.status_code == 403
    assert hist.list_dsars() == []
    assert not _actions(log, "erasure_assessment")
    assert client.post("/stores/demo/erasure", headers=ALICE,
                       json={"subject": SUBJECT}).status_code == 200


def test_datasource_scan_is_admin_only(env, tmp_path):
    client, *_ = env
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "a.txt").write_text("hello\n")
    body = {"kind": "local", "path": str(tmp_path / "d"), "no_nlp": True}
    for headers in (VIEWER, OPERATOR, ALICE):
        r = client.post("/datasources/scan", headers=headers, json=body)
        assert r.status_code == 403 and r.json()["detail"] == "requires role: admin"
    assert client.post("/datasources/scan", headers=ADMIN, json=body).status_code == 200


def test_erasure_execute_obeys_safe_mode_before_touching_the_store(env, monkeypatch):
    client, hist, log, path, _ = env
    opened = []
    import vecshield_platform.api.registry as registry_mod
    real_open = registry_mod.StoreRegistry.open
    monkeypatch.setattr(registry_mod.StoreRegistry, "open",
                        lambda self, sid: opened.append(sid) or real_open(self, sid))
    r = client.post("/stores/demo/erasure/execute", headers=ADMIN, json={"subject": SUBJECT})
    assert r.status_code == 409
    assert "VECSHIELD_SAFE_MODE=0" in r.json()["detail"]
    assert opened == []
    assert "c3" in _ids(path)
    assert _actions(log, "erasure_execution_refused")[-1].details["reason"] == "safe_mode"


def test_direct_erasure_is_admin_only(env, monkeypatch):
    client, hist, log, path, _ = env
    monkeypatch.setenv("VECSHIELD_SAFE_MODE", "0")
    r = client.post("/stores/demo/erasure/execute", headers=ALICE, json={"subject": SUBJECT})
    assert r.status_code == 403 and r.json()["detail"] == ERASURE_NEEDS_DSAR_DETAIL
    assert "c3" in _ids(path)
    r = client.post("/stores/demo/erasure/execute", headers=ADMIN, json={"subject": SUBJECT})
    assert r.status_code == 200, r.text
    assert "c3" not in _ids(path)
    entry = _actions(log, "erasure_executed")[-1]
    assert entry.details["execution_mode"] == "admin"


def test_direct_erasure_by_compliance_when_separation_is_off(env, monkeypatch):
    _, hist, log, path, make = env
    monkeypatch.setenv("VECSHIELD_SAFE_MODE", "0")
    client = make(separation_of_duties="off")
    r = client.post("/stores/demo/erasure/execute", headers=ALICE, json={"subject": SUBJECT})
    assert r.status_code == 200, r.text
    assert _actions(log, "erasure_executed")[-1].details["execution_mode"] == "policy_permitted"


def test_dsar_execute_needs_a_second_person(env, monkeypatch):
    client, hist, log, path, _ = env
    d = client.post("/admin/dsar", headers=ALICE, json={"subject": SUBJECT}).json()
    assert hist.get_dsar(d["id"])["created_by"] == "alice"
    # F3: a DSAR names a person; reading one is a compliance task.
    assert client.get(f"/admin/dsar/{d['id']}", headers=VIEWER).status_code == 403
    assert client.get("/admin/dsar", headers=VIEWER).status_code == 403
    assert client.get(f"/admin/dsar/{d['id']}", headers=BOB).json()["created_by"] == "alice"
    listed = client.get("/admin/dsar", headers=BOB).json()["dsars"]
    assert listed[0]["created_by"] == "alice"
    # Safe mode first, for everyone, before the store is touched.
    r = client.post(f"/admin/dsar/{d['id']}/execute", headers=BOB, json={})
    assert r.status_code == 409 and "VECSHIELD_SAFE_MODE=0" in r.json()["detail"]
    assert "c3" in _ids(path)
    monkeypatch.setenv("VECSHIELD_SAFE_MODE", "0")
    r = client.post(f"/admin/dsar/{d['id']}/execute", headers=ALICE, json={})
    assert r.status_code == 403 and r.json()["detail"] == DSAR_SELF_EXECUTE_DETAIL
    assert "c3" in _ids(path)
    r = client.post(f"/admin/dsar/{d['id']}/execute", headers=BOB, json={})
    assert r.status_code == 200, r.text
    assert "c3" not in _ids(path)
    details = _actions(log, "dsar_executed")[-1].details
    assert details["execution_mode"] == "second_person" and details["created_by"] == "alice"


def test_admin_may_execute_their_own_dsar(env, monkeypatch):
    client, hist, log, path, _ = env
    monkeypatch.setenv("VECSHIELD_SAFE_MODE", "0")
    d = client.post("/admin/dsar", headers=ADMIN, json={"subject": SUBJECT}).json()
    r = client.post(f"/admin/dsar/{d['id']}/execute", headers=ADMIN, json={})
    assert r.status_code == 200, r.text
    assert _actions(log, "dsar_executed")[-1].details["execution_mode"] == "admin"


# --------------------------------------------------------------------------- #
# Exceptions, connector errors, isolation probe, NLP model                    #
# --------------------------------------------------------------------------- #

def test_an_approved_exception_cannot_be_approved_again(env):
    client, *_ = env
    r = client.post("/compliance/exceptions", headers=ALICE, json={
        "criterion_id": "HIPAA-1", "scope": "demo", "rationale": "Compensating control.",
        "expires_at": "2099-01-01T00:00:00+00:00"})
    assert r.status_code == 200, r.text
    ex_id = r.json()["id"]
    assert client.post(f"/compliance/exceptions/{ex_id}/approve", headers=BOB,
                       json={"reason": "Accepted until the fix ships."}).status_code == 200
    again = client.post(f"/compliance/exceptions/{ex_id}/approve", headers=tok("carol", "compliance"),
                        json={"reason": "Re-approving."})
    assert again.status_code == 409
    assert "already approved by bob" in again.json()["detail"]


def test_store_test_failure_reports_category_not_connector_text(env):
    client, hist, log, path, _ = env

    class Broken:
        kind = "broken"

        def describe(self):
            raise RuntimeError("could not connect to postgres://svc:hunter2@db:5432/x")

        def close(self):
            pass

    client.app.state.registry.register("broken", "broken", factory=Broken)
    r = client.post("/admin/stores/broken/test", headers=VIEWER)
    assert r.status_code == 400
    detail = r.json()["detail"]
    assert "hunter2" not in detail and "RuntimeError" in detail and "error" in detail


def test_isolation_probe_failure_is_a_clean_error_and_audited(env, monkeypatch):
    client, hist, log, path, _ = env
    import vecshield_platform.api.app as app_mod

    def boom(*a, **k):
        raise OverflowError("Python int too large to convert to SQLite INTEGER")

    monkeypatch.setattr(app_mod, "probe_isolation", boom)
    r = client.post("/stores/demo/probe-isolation?collection=runbooks&tenant_field=team",
                    headers=OPERATOR)
    assert r.status_code == 502
    assert "OverflowError" in r.json()["detail"]
    failed = _actions(log, "probe_isolation_failed")
    assert failed and failed[-1].target == "demo/runbooks"


@pytest.mark.parametrize("model", ["/tmp/evil_model", "../models/x", "..\\x", ".hidden",
                                   "not_a_catalog_model"])
def test_nlp_model_from_the_api_is_restricted(env, model, monkeypatch):
    client, *_ = env
    import vecshield_platform.api.app as app_mod
    called = []
    monkeypatch.setattr(app_mod, "build_classifier",
                        lambda **kw: called.append(kw) or (_ for _ in ()).throw(AssertionError))
    r = client.post("/ingest/gate", headers=VIEWER,
                    json={"chunks": [{"id": "1", "text": "hi"}], "nlp_model": model})
    assert r.status_code == 400, r.text
    assert called == []


def test_nlp_model_catalog_name_and_configured_default_pass_the_check(env, monkeypatch):
    client, *_ = env
    import vecshield_platform.api.app as app_mod
    real = app_mod.build_classifier
    seen = []

    def fake(**kw):
        seen.append(kw.get("model"))
        return real(use_nlp=False)  # the model is not installed here

    monkeypatch.setattr(app_mod, "build_classifier", fake)
    monkeypatch.setenv("VECSHIELD_NLP_MODEL", "/opt/models/site_model")
    for model in ("en_core_web_sm", "/opt/models/site_model"):
        r = client.post("/ingest/gate", headers=VIEWER,
                        json={"chunks": [{"id": "1", "text": "hi"}], "nlp_model": model})
        assert r.status_code == 200, r.text
    assert seen == ["en_core_web_sm", "/opt/models/site_model"]
