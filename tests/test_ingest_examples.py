"""Contract tests for the console's Ingest example library.

Each example in ``INGEST_EXAMPLES`` (vecshield_platform/api/dashboard/dist/
assets/dashboard.js) declares what the engine should report for it. The console
describes an example's lesson on the strength of that declaration, so it is
checked here against the real ingest API: if a detector changes and an example
stops demonstrating what it says, this fails rather than the page misleading a
reader.

Every current example declares ``requires: "regex"``, so each runs with NLP off
to pin the pattern-only behaviour it describes.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from vecshield_platform.api.app import create_app

DASHBOARD = (Path(__file__).resolve().parents[1] / "vecshield_platform" / "api" /
             "dashboard" / "dist" / "assets" / "dashboard.js")
TASKS = {"gate", "redact", "boundaries"}
CATEGORIES = {"personal", "payments", "credentials", "health", "mixed", "benign", "boundaries"}
CHUNK_LIMIT = 5000


def _examples() -> list[dict]:
    source = DASHBOARD.read_text(encoding="utf-8")
    match = re.search(r"/\* INGEST_EXAMPLES:BEGIN \*/(.*?)/\* INGEST_EXAMPLES:END \*/", source, re.S)
    assert match, "the example catalog markers are missing from dashboard.js"
    return json.loads(match.group(1))


EXAMPLES = _examples()


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(create_app())


def _chunks(example: dict) -> list[dict]:
    return [{"id": f"chunk-{i + 1}", "text": text, "collection": "console"}
            for i, text in enumerate(example["chunks"])]


def test_catalog_shape() -> None:
    ids = [e["id"] for e in EXAMPLES]
    assert len(ids) == len(set(ids)), "example ids are unique"
    assert 10 <= len(EXAMPLES) <= 12
    assert {e["category"] for e in EXAMPLES} == CATEGORIES, "every category has an example"
    covered = set()
    for e in EXAMPLES:
        for key in ("id", "version", "category", "title", "explanation", "lesson", "chunks",
                    "tasks", "suggested", "expected", "limitations", "requires"):
            assert key in e, f"{e.get('id')}: missing {key}"
        assert e["category"] in CATEGORIES
        assert e["requires"] == "regex"
        assert set(e["tasks"]) <= TASKS and e["tasks"]
        assert e["suggested"]["task"] in e["tasks"]
        assert set(e["expected"]) <= set(e["tasks"]), f"{e['id']}: expectations only for its tasks"
        assert all(0 < len(c) <= CHUNK_LIMIT for c in e["chunks"])
        if "boundaries" in e["tasks"]:
            assert len(e["chunks"]) >= 2, f"{e['id']}: a boundary example needs adjacent chunks"
        covered.update(e["expected"])
    assert covered == TASKS, "the library exercises all three tasks"


@pytest.mark.parametrize("example", [e for e in EXAMPLES if "gate" in e["expected"]],
                         ids=lambda e: e["id"])
def test_gate_expectation(client: TestClient, example: dict) -> None:
    expected = example["expected"]["gate"]
    severity = example["suggested"].get("block_severity", "high")
    resp = client.post("/ingest/gate", json={"chunks": _chunks(example), "no_nlp": True,
                                             "block_severity": severity})
    assert resp.status_code == 200
    data = resp.json()
    assert sorted(data["blocked_chunk_ids"]) == sorted(expected["blocked"])
    assert sorted({f["evidence"]["label"] for f in data["findings"]}) == sorted(expected["labels"])
    assert "detection" in data, "the gate reports which detectors ran"


@pytest.mark.parametrize("example", [e for e in EXAMPLES if "redact" in e["expected"]],
                         ids=lambda e: e["id"])
def test_redact_expectation(client: TestClient, example: dict) -> None:
    expected = example["expected"]["redact"]
    resp = client.post("/ingest/redact", json={"chunks": _chunks(example), "no_nlp": True,
                                               "show_preview": True})
    assert resp.status_code == 200
    n = resp.json()["spans_redacted"]
    assert n >= expected["min_spans"]
    if "max_spans" in expected:
        assert n <= expected["max_spans"]


@pytest.mark.parametrize("example", [e for e in EXAMPLES if "boundaries" in e["expected"]],
                         ids=lambda e: e["id"])
def test_boundary_expectation(client: TestClient, example: dict) -> None:
    expected = example["expected"]["boundaries"]
    zone = example["suggested"].get("zone_chars", 64)
    resp = client.post("/ingest/analyze-boundaries",
                       json={"chunks": _chunks(example), "no_nlp": True, "zone_chars": zone})
    assert resp.status_code == 200
    findings = resp.json()["findings"]
    assert sorted(f["evidence"]["label"] for f in findings) == sorted(expected["labels"])
    for f in findings:
        # The console shows the masked preview; the raw value must not be in it.
        joined = "".join(example["chunks"])
        assert f["evidence"]["preview"] not in joined


def test_split_examples_are_missed_per_chunk(client: TestClient) -> None:
    """The lesson of a boundary example is that per-chunk checks miss it."""
    for e in (x for x in EXAMPLES if x["category"] == "boundaries"):
        resp = client.post("/ingest/gate", json={"chunks": _chunks(e), "no_nlp": True,
                                                 "block_severity": "info"})
        assert resp.json()["findings"] == [], f"{e['id']}: a per-chunk check should find nothing"


# The console qualifies every ingest result with the run's `detection` record,
# so all three routes must carry it, and must tell degraded coverage apart
# from a required model that is missing.

INGEST_ROUTES = [
    ("/ingest/gate", {}),
    ("/ingest/redact", {"show_preview": False}),
    ("/ingest/analyze-boundaries", {}),
]


@pytest.fixture
def nlp_unavailable(monkeypatch):
    from vecshield_platform import detection

    def unavailable(model):
        raise detection.DetectionUnavailableError("Selected model is not installed")

    monkeypatch.setattr(detection, "_build_nlp", unavailable)
    detection.reset_classifier_cache()
    yield monkeypatch
    detection.reset_classifier_cache()


@pytest.mark.parametrize("path,extra", INGEST_ROUTES, ids=[p for p, _ in INGEST_ROUTES])
def test_optional_nlp_missing_degrades_and_says_so(nlp_unavailable, path, extra) -> None:
    nlp_unavailable.setenv("VECSHIELD_NLP_MODE", "auto")
    client = TestClient(create_app())
    body = {"chunks": [{"id": "chunk-1", "text": "reply to jordan.lee@example.com"},
                       {"id": "chunk-2", "text": "thanks"}], **extra}
    resp = client.post(path, json=body)
    assert resp.status_code == 200
    detection = resp.json()["detection"]
    assert detection["status"] == "degraded"
    assert detection["nlp_loaded"] is False
    assert "not installed" in detection["reason"]


@pytest.mark.parametrize("path,extra", INGEST_ROUTES, ids=[p for p, _ in INGEST_ROUTES])
def test_required_nlp_missing_fails_rather_than_falling_back(nlp_unavailable, path, extra) -> None:
    nlp_unavailable.setenv("VECSHIELD_NLP_MODE", "required")
    client = TestClient(create_app())
    body = {"chunks": [{"id": "chunk-1", "text": "reply to jordan.lee@example.com"},
                       {"id": "chunk-2", "text": "thanks"}], **extra}
    resp = client.post(path, json=body)
    assert resp.status_code == 503
    assert "detection unavailable" in resp.json()["detail"]
