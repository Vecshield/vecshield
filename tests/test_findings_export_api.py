"""Findings export: the list's filters, every match up to a cap, never evidence.

Role contract: any signed-in role may export what it can already read in the
findings list, and every export is audit-logged.
"""

from __future__ import annotations

import csv
import datetime
import io

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from test_assessment_snapshots import audit_result  # noqa: E402
from test_auth import make_jwt  # noqa: E402

from vecshield.models import Finding, ScanJob, Severity  # noqa: E402
from vecshield_platform.api import StoreRegistry, create_app  # noqa: E402
from vecshield_platform.api import app as app_mod  # noqa: E402
from vecshield_platform.compliance import AuditLog  # noqa: E402
from vecshield_platform.history import ScanHistory  # noqa: E402

SECRET = "findings-export-secret"
VIEWER = {"Authorization": "Bearer " + make_jwt({"sub": "vera", "roles": ["viewer"]}, SECRET)}
SECRET_VALUE = "123-45-6789"


@pytest.fixture
def env():
    registry = StoreRegistry()
    registry.register("prod", "chroma", path="unused")
    history = ScanHistory()
    job = ScanJob(id="j1", store="prod")
    job.add(Finding(id="f-high", title="PII in 'docs'", severity=Severity.HIGH,
                    category="data_classification", store="prod", collection="docs",
                    description="3/10 scanned chunks contain sensitive data.",
                    evidence={"fingerprint": "fp-high",
                              "examples": [{"chunk_id": "c1", "value": SECRET_VALUE}]}))
    job.add(Finding(id="f-formula", title="=HYPERLINK(\"http://x\")", severity=Severity.LOW,
                    category="rag_integrity", store="prod", collection="+cmd",
                    evidence={"fingerprint": "fp-formula"}))
    job.finished_at = datetime.datetime.now(datetime.timezone.utc)
    history.save_job(job)
    log = AuditLog()
    app = create_app(registry=registry, scan_history=history, audit_log=log,
                     serve_ui=False, jwt_secret=SECRET)
    yield TestClient(app), history, log
    app.state.jobs.shutdown(wait=False)


def _csv(text):
    rows = list(csv.reader(io.StringIO(text)))
    return [dict(zip(rows[0], row)) for row in rows[1:]], tuple(rows[0])


def test_csv_export_has_every_match_and_no_evidence(env):
    client, _, log = env
    r = client.get("/admin/findings/export?format=csv", headers=VIEWER)
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("text/csv")
    assert 'filename="vecshield-findings-' in r.headers["content-disposition"]
    assert r.headers["x-vecshield-total"] == "2"
    assert r.headers["x-vecshield-truncated"] == "false"
    rows, header = _csv(r.text)
    assert header == app_mod.FINDINGS_EXPORT_COLUMNS
    assert "evidence" not in header and SECRET_VALUE not in r.text
    by_id = {row["id"]: row for row in rows}
    assert by_id["f-high"]["description"] == "3/10 scanned chunks contain sensitive data."
    assert by_id["f-high"]["fingerprint"] == "fp-high"
    assert by_id["f-high"]["case_state"] == "new" and by_id["f-high"]["suppressed"] == "false"
    assert by_id["f-high"]["store_id"] == "prod"
    # Text a spreadsheet would run is neutralised.
    assert by_id["f-formula"]["title"].startswith("'=")
    assert by_id["f-formula"]["collection"] == "'+cmd"
    (entry,) = [e for e in log.entries if e.action == "findings_exported"]
    assert entry.actor == "vera"
    assert entry.details == {"format": "csv", "filters": {"scope": "all"}, "rows": 2,
                             "total": 2, "truncated": False}


def test_json_export_applies_the_list_filters(env):
    client, *_ = env
    r = client.get("/admin/findings/export?format=json&min_severity=high&store=prod",
                   headers=VIEWER)
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("application/json")
    doc = r.json()
    assert [f["id"] for f in doc["findings"]] == ["f-high"]
    assert doc["filters"] == {"store": "prod", "min_severity": "high", "scope": "all"}
    assert (doc["total"], doc["exported"], doc["truncated"]) == (1, 1, False)
    assert "evidence" not in doc["findings"][0] and SECRET_VALUE not in r.text


def test_latest_scope_exports_only_the_latest_audit(env):
    client, history, _ = env
    history.save_audit(audit_result(), store_id="prod")
    doc = client.get("/admin/findings/export?format=json&scope=latest", headers=VIEWER).json()
    assert [f["title"] for f in doc["findings"]] == ["Synthetic finding"]
    # Recorded under the connector's name; exported with the registered id too.
    assert (doc["findings"][0]["store"], doc["findings"][0]["store_id"]) == ("fake://observed", "prod")
    assert doc["stores_assessed"] == 1 and doc["note"]
    listed = client.get("/admin/findings?scope=latest", headers=VIEWER).json()
    assert listed["total"] == doc["total"], "the export matches the list it was taken from"


def test_a_capped_export_says_it_is_partial(env, monkeypatch):
    client, *_ = env
    monkeypatch.setattr(app_mod, "FINDINGS_EXPORT_CAP", 1)
    r = client.get("/admin/findings/export?format=json", headers=VIEWER)
    assert r.headers["x-vecshield-total"] == "2"
    assert r.headers["x-vecshield-truncated"] == "true"
    doc = r.json()
    assert (doc["total"], doc["exported"], doc["truncated"]) == (2, 1, True)


def test_export_refuses_bad_input_and_anonymous_callers(env):
    client, *_ = env
    assert client.get("/admin/findings/export").status_code == 401
    assert client.get("/admin/findings/export?format=xml", headers=VIEWER).status_code == 422
    assert client.get("/admin/findings/export?sort=nonsense", headers=VIEWER).status_code == 422
    # The path is not mistaken for a finding id.
    assert client.get("/admin/findings/export", headers=VIEWER).status_code == 200
