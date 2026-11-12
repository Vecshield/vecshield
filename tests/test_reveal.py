"""One chunk, fetched now, with its matches marked and its values masked."""

import pytest

from vecshield_platform.reveal import (MASKED, RAW, RevealError, fetch_chunk,
                                         reveal_chunk)
from vecshield.classify import RegexClassifier
from vecshield.models import Chunk


def _chunk(text="Contact p.smith@example.test about card 4111 1111 1111 1111.",
           metadata=None):
    return Chunk(id="c1", collection="docs", text=text,
                 metadata=metadata if metadata is not None else {"tenant_id": "acme"})


def test_masked_keeps_the_context_and_hides_the_values():
    out = reveal_chunk(_chunk(), classifier=RegexClassifier(), store="demo",
                       collection="docs", level=MASKED)
    text = out.surfaces[0].text
    assert "Contact" in text and "about card" in text
    assert "p.smith@example.test" not in text
    assert "4111 1111 1111 1111" not in text
    assert out.surfaces[0].spans, "the matches are marked"
    for span in out.surfaces[0].spans:
        assert span.revealed is False
        # The mask is length-preserving, so offsets still point at the mask.
        assert set(text[span.start:span.end]) & {"*"}
    assert "email" in out.detectors
    assert out.level == MASKED


def test_raw_shows_the_values_and_says_so():
    out = reveal_chunk(_chunk(), classifier=RegexClassifier(), store="demo",
                       collection="docs", level=RAW)
    assert "p.smith@example.test" in out.surfaces[0].text
    assert all(s.revealed for s in out.surfaces[0].spans)
    assert "recorded in the audit log" in out.note


def test_metadata_is_masked_the_same_way_as_its_surface():
    chunk = _chunk(metadata={"contact": "p.smith@example.test", "count": 3})
    out = reveal_chunk(chunk, classifier=RegexClassifier(), store="demo",
                       collection="docs")
    assert "p.smith@example.test" not in str(out.metadata)
    assert out.metadata["count"] == 3


def test_drift_is_reported_against_recorded_spans():
    classifier = RegexClassifier()
    live = reveal_chunk(_chunk(), classifier=classifier, store="demo",
                        collection="docs", recorded_spans=[])
    assert live.drift is True, "the finding recorded nothing; the store has matches"
    recorded = [{"surface": "text", "start": s.start, "end": s.end, "detector": s.detector}
                for s in live.surfaces[0].spans]
    same = reveal_chunk(_chunk(), classifier=classifier, store="demo",
                        collection="docs", recorded_spans=recorded)
    assert same.drift is False
    none = reveal_chunk(_chunk(), classifier=classifier, store="demo", collection="docs")
    assert none.drift is None


def test_two_detectors_on_one_range_are_both_listed_and_the_text_masked_once():
    out = reveal_chunk(_chunk(), classifier=RegexClassifier(), store="demo",
                       collection="docs")
    card = [s for s in out.surfaces[0].spans if s.start == 40]
    assert {s.detector for s in card} >= {"credit_card", "card_like_number"}
    assert out.surfaces[0].text.count("*") < 60, "the mask was not written twice"


def test_the_explanation_travels_with_each_span():
    out = reveal_chunk(_chunk(), classifier=RegexClassifier(), store="demo",
                       collection="docs")
    email = next(s for s in out.surfaces[0].spans if s.detector == "email")
    assert email.confidence in ("likely", "possible", "uncertain")
    assert any(c.get("code") == "reserved_domain" for c in email.counter_signals)
    assert email.disputed is True


def test_an_unknown_level_is_refused():
    with pytest.raises(RevealError):
        reveal_chunk(_chunk(), classifier=RegexClassifier(), store="demo",
                     collection="docs", level="partial")


class _Iterating:
    """A connector with no lookup by id."""
    content_enumerable = True

    def __init__(self, chunks):
        self._chunks = chunks

    def iter_chunks(self, collection, batch_size=256):
        yield from self._chunks


def test_fetch_falls_back_to_iteration_and_stops_at_a_bound(monkeypatch):
    import vecshield_platform.reveal as reveal

    conn = _Iterating([Chunk(id=f"c{i}", collection="docs", text="x") for i in range(5)])
    # No get_chunks at all, so the lookup iterates.
    assert fetch_chunk(conn, "docs", "c3").id == "c3"
    assert fetch_chunk(conn, "docs", "nope") is None
    monkeypatch.setattr(reveal, "MAX_ITERATED", 2)
    with pytest.raises(RevealError, match="Refusing to scan"):
        fetch_chunk(conn, "docs", "c4")


# ------------------------------------------------------------------ API ---

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from vecshield_platform.api import create_app  # noqa: E402
from vecshield_platform.api.config_store import ConfigStore  # noqa: E402
from vecshield_platform.compliance import AuditLog  # noqa: E402
from vecshield_platform.history import ScanHistory  # noqa: E402


@pytest.fixture
def api(tmp_path, chroma_path):
    cfg = ConfigStore(path=str(tmp_path / "config.json"))
    history = ScanHistory(str(tmp_path / "history.db"))
    audit = AuditLog.open(str(tmp_path / "audit.jsonl"))
    app = create_app(config_store=cfg, serve_ui=False, scan_history=history, audit_log=audit)
    client = TestClient(app)
    client.post("/admin/stores", json={
        "store_id": "demo", "kind": "chroma", "conn": {"path": chroma_path}})
    yield client, history, audit
    app.state.jobs.shutdown(wait=False)


def _sensitive_chunk_id(client):
    # d45..d49 are the seeded sensitive documents in prod-docs.
    return "d45"


def test_masked_is_the_default_and_never_stores_anything(api):
    client, history, audit = api
    r = client.get(f"/stores/demo/collections/prod-docs/chunks/{_sensitive_chunk_id(client)}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["level"] == "masked"
    assert body["surfaces"] and body["surfaces"][0]["spans"], "matches are marked"
    assert r.headers["cache-control"] == "no-store"
    assert not any(e.action == "chunk_revealed" for e in audit.entries)


def test_raw_needs_a_reason_and_is_audited(api):
    client, history, audit = api
    path = f"/stores/demo/collections/prod-docs/chunks/{_sensitive_chunk_id(client)}"
    assert client.get(path, params={"reveal": "raw"}).status_code == 422
    r = client.get(path, params={"reveal": "raw", "reason": "DSAR review"})
    assert r.status_code == 200, r.text
    assert all(s["revealed"] for s in r.json()["surfaces"][0]["spans"])
    revealed = [e for e in audit.entries if e.action == "chunk_revealed"]
    assert len(revealed) == 1
    assert revealed[0].details["reason"] == "DSAR review"
    assert revealed[0].details["chunk_id"] == _sensitive_chunk_id(client)


def test_a_chunk_that_is_gone_says_so(api):
    client, _, _ = api
    r = client.get("/stores/demo/collections/prod-docs/chunks/never-existed")
    assert r.status_code == 404
    assert "may have been deleted" in r.json()["detail"]


def test_an_unknown_level_is_refused_by_the_api(api):
    client, _, _ = api
    r = client.get("/stores/demo/collections/prod-docs/chunks/d45", params={"reveal": "spans"})
    assert r.status_code == 422


def test_sampling_a_collection_is_masked_bounded_and_records_nothing(api):
    client, history, audit = api
    r = client.get("/stores/demo/collections/prod-docs/sample", params={"limit": 10})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["returned"] == 10 and body["exhausted"] is False
    assert body["next_offset"] == 10
    assert all("*" in c["preview"] or not c["matches"] for c in body["chunks"])
    rest = client.get("/stores/demo/collections/prod-docs/sample",
                      params={"limit": 200, "offset": 40}).json()
    assert rest["exhausted"] is True
    assert rest["sensitive"] >= 5, "the seeded sensitive documents sit at the end"
    assert not any(c["preview"].count("john.doe@example.com") for c in rest["chunks"])
    assert history.list_findings() == [], "sampling records no findings"


# ---------------------------------------------- masked metadata and overlaps ---

def _leaks(value, needles):
    import json
    blob = json.dumps(value, default=str)
    return [n for n in needles if n in blob]


def test_masked_metadata_masks_nested_listed_duplicate_and_numeric_values():
    """A view that says 'masked' must not hand the values over one panel away."""
    chunk = _chunk(text="Ticket about a billing dispute.", metadata={
        "contact": {"email": "jane.doe@example.org", "ssn": "123-45-6789"},
        "email": "jane@example.com",
        "reporter": "jane@example.com",          # same value: deduplicated surface
        "contacts": ["jane@example.com", "ops@example.com"],
        "phones": ["+1 415 555 0132"],
        "card": 4111111111111111,
        "ssn": 123456789,
        "count": 3, "flag": True, "none": None, "team": "sre",
    })
    out = reveal_chunk(chunk, classifier=RegexClassifier(), store="demo",
                       collection="docs", level=MASKED)
    meta = out.metadata
    assert _leaks(meta, ["jane.doe@example.org", "123-45-6789", "jane@example.com",
                         "ops@example.com", "415 555 0132", "4111111111111111",
                         "123456789"]) == []
    # Structure is kept, not flattened into a raw str(dict).
    assert isinstance(meta["contact"], dict) and isinstance(meta["contacts"], list)
    assert meta["count"] == 3 and meta["flag"] is True and meta["none"] is None
    assert meta["team"] == "sre"


def test_masked_metadata_masks_credential_named_keys():
    """A bare opaque secret has no context for a detector; its key is the context."""
    chunk = _chunk(text="Service config.", metadata={
        "password": "S3cr3tPassw0rdXyz",
        "api_key": "zq81Lm0pQr77abcd",
        "clientSecret": "k9Vt2RxQ8wLmN4",
        "auth": {"token": "tok_7Hc2PqZx91"},
        "max_tokens": 512,
        "author": "Jane Doe",
    })
    out = reveal_chunk(chunk, classifier=RegexClassifier(), store="demo",
                       collection="docs", level=MASKED)
    meta = out.metadata
    assert _leaks(meta, ["S3cr3tPassw0rdXyz", "zq81Lm0pQr77abcd", "k9Vt2RxQ8wLmN4",
                         "tok_7Hc2PqZx91"]) == []
    # Whole-token matching: these name no credential and stay readable.
    assert meta["max_tokens"] == 512
    assert meta["author"] == "Jane Doe"


def test_raw_level_still_returns_metadata_values():
    chunk = _chunk(metadata={"email": "jane@example.com", "ssn": 123456789})
    out = reveal_chunk(chunk, classifier=RegexClassifier(), store="demo",
                       collection="docs", level=RAW)
    assert out.metadata["email"] == "jane@example.com"
    assert out.metadata["ssn"] == 123456789


def test_overlapping_spans_are_masked_as_their_union_and_all_listed():
    text = "postgres://admin:S3cretPass@10.0.0.5/db"
    out = reveal_chunk(_chunk(text=text, metadata={}), classifier=RegexClassifier(),
                       store="demo", collection="docs", level=MASKED)
    masked = out.surfaces[0].text
    assert len(masked) == len(text), "the mask is length-preserving"
    assert "S3cretPass" not in masked and "0.0.0.5" not in masked
    assert {s.detector for s in out.surfaces[0].spans} >= {
        "database_url_credentials", "ipv4_address"}
