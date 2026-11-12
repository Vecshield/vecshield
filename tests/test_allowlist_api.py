"""Admin API tests for false-positive management (improvement plan 1.12).

Covers the /admin/allowlist and /admin/suppressions control-plane routes plus
the suppression wiring into the audit path: suppressed findings must still be
detected and counted, but must be excluded from policy violations.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from vecshield_platform.api import create_app  # noqa: E402
from vecshield_platform.api.config_store import ConfigStore  # noqa: E402


def _future(days: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


@pytest.fixture
def chroma_path(tmp_path):
    import chromadb

    client = chromadb.PersistentClient(path=str(tmp_path / "chroma"))
    col = client.create_collection("prod-kb")
    col.add(ids=["a", "b"],
            documents=["Contact jane@example.com for details", "benign note"],
            embeddings=[[0.1, 0.2]] * 2,
            metadatas=[{"tenant_id": "t1"}, {"tenant_id": "t2"}])
    return str(tmp_path / "chroma")


@pytest.fixture
def client(tmp_path):
    cfg = ConfigStore(path=str(tmp_path / "config.json"))
    app = create_app(config_store=cfg, serve_ui=False)
    return TestClient(app), cfg


def test_allowlist_crud(client):
    c, _ = client
    # built-ins are present by default
    listing = c.get("/admin/allowlist").json()["allowlist"]
    assert any(r["source"] == "builtin" for r in listing)

    r = c.post("/admin/allowlist", json={
        "reason": "known benign test fixture",
        "category": "data_classification", "store": "prod",
        "owner": "sec-team"})
    assert r.status_code == 200
    rid = r.json()["id"]
    assert r.json()["source"] == "custom"

    after = c.get("/admin/allowlist").json()["allowlist"]
    assert any(x["id"] == rid for x in after)

    d = c.delete(f"/admin/allowlist/{rid}")
    assert d.status_code == 200 and d.json()["removed"] == rid
    assert not any(x["id"] == rid
                   for x in c.get("/admin/allowlist").json()["allowlist"])


def test_allowlist_unscoped_rejected(client):
    c, _ = client
    # no scope and no matcher would silence everything -> rejected
    r = c.post("/admin/allowlist", json={"reason": "oops", "owner": "x"})
    assert r.status_code == 422


def test_allowlist_excludes_builtin_when_requested(client):
    c, _ = client
    only_custom = c.get("/admin/allowlist?include_builtin=false").json()["allowlist"]
    assert only_custom == []


def test_suppression_crud(client):
    c, _ = client
    r = c.post("/admin/suppressions", json={
        "fingerprint": "fp-0123456789abcdef", "reason": "accepted for Q1",
        "owner": "sec-lead", "expires_at": _future(10), "ticket": "SEC-42"})
    assert r.status_code == 200
    sid = r.json()["id"]

    active = c.get("/admin/suppressions").json()["suppressions"]
    assert any(s["id"] == sid for s in active)

    d = c.delete(f"/admin/suppressions/{sid}")
    assert d.status_code == 200 and d.json()["removed"] == sid
    assert c.get("/admin/suppressions").json()["suppressions"] == []


def test_suppression_rejects_past_expiry(client):
    c, _ = client
    r = c.post("/admin/suppressions", json={
        "fingerprint": "fp-deadbeefdeadbeef", "reason": "late",
        "owner": "x", "expires_at": _future(-1)})
    assert r.status_code == 422


def test_suppression_sensitive_ttl_capped(client):
    c, _ = client
    # a CRITICAL finding may not be muted for a whole year
    r = c.post("/admin/suppressions", json={
        "fingerprint": "fp-aaaabbbbccccdddd", "reason": "too long",
        "owner": "x", "expires_at": _future(200), "severity": "critical"})
    assert r.status_code == 422


def test_suppressed_finding_excluded_from_violations(client, chroma_path):
    c, _ = client
    c.post("/admin/stores", json={"store_id": "prod", "kind": "chroma",
                                  "conn": {"path": chroma_path},
                                  "tenant_field": "tenant_id"})

    # baseline audit surfaces at least one finding
    base = c.post("/stores/prod/audit", json={}).json()
    total = sum(base["summary"].values())
    assert total >= 1

    # find a fingerprint to suppress
    fp = None
    for job in base["jobs"]:
        for f in job["findings"]:
            fp = (f.get("evidence") or {}).get("fingerprint")
            if fp:
                break
        if fp:
            break
    assert fp, "expected a fingerprint on findings"

    v_before = len(base["violations"])
    c.post("/admin/suppressions", json={
        "fingerprint": fp, "reason": "known benign", "owner": "sec",
        "expires_at": _future(5)})

    after = c.post("/stores/prod/audit", json={}).json()
    # finding is still detected and counted...
    assert sum(after["summary"].values()) == total
    assert after["suppressed"] >= 1
    # ...but no longer produces a violation for that fingerprint's finding
    assert len(after["violations"]) <= v_before


def test_sensitive_ttl_cap_follows_the_recorded_finding(tmp_path, chroma_path):
    # The cap used to read only the severity/category the caller sent, so
    # leaving them out muted a sensitive finding for the general maximum.
    from vecshield_platform.compliance.allowlist import (
        SENSITIVE_MAX_TTL_DAYS,
        is_sensitive,
    )
    from vecshield_platform.history import ScanHistory

    cfg = ConfigStore(path=str(tmp_path / "config.json"))
    c = TestClient(create_app(config_store=cfg, serve_ui=False,
                              scan_history=ScanHistory(str(tmp_path / "h.db"))))
    c.post("/admin/stores", json={"store_id": "prod", "kind": "chroma",
                                  "conn": {"path": chroma_path},
                                  "tenant_field": "tenant_id"})
    audit = c.post("/stores/prod/audit", json={}).json()
    fp = next(f["evidence"]["fingerprint"] for job in audit["jobs"]
              for f in job["findings"]
              if (f.get("evidence") or {}).get("fingerprint")
              and is_sensitive(category=f.get("category")))

    long_mute = {"fingerprint": fp, "reason": "accepted", "owner": "sec",
                 "expires_at": _future(SENSITIVE_MAX_TTL_DAYS + 170)}
    r = c.post("/admin/suppressions", json=long_mute)
    assert r.status_code == 422, r.text
    # Understating the finding does not help either.
    r = c.post("/admin/suppressions", json={**long_mute, "severity": "low",
                                            "category": "misc"})
    assert r.status_code == 422, r.text
    # Within the sensitive ceiling it is accepted.
    r = c.post("/admin/suppressions", json={**long_mute, "expires_at": _future(10)})
    assert r.status_code == 200, r.text
    # An unrecorded fingerprint keeps the caller's own values.
    r = c.post("/admin/suppressions", json={**long_mute,
                                            "fingerprint": "fp-0000111122223333"})
    assert r.status_code == 200, r.text
