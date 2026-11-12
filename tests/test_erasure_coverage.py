"""Regression coverage for false-clean erasure and DSAR results."""

import json
from types import SimpleNamespace

import pytest
from vecshield.models import Chunk, Collection, VectorStore

from vecshield_platform.compliance.dsar import (
    DSARRecord, create_dsar, execute_dsar, scan_all_stores,
)
from vecshield_platform.compliance.erasure import (
    ErasureReport, ErasureVerification, erasure_impact, execute_erasure,
    plan_erasure, verify_erasure,
)
from vecshield_platform.connectors.base import Connector


@pytest.fixture(autouse=True)
def writes_permitted(monkeypatch):
    """These tests execute erasures, which safe mode refuses. The safe-mode
    tests below clear the variable again to see the refusal."""
    monkeypatch.setenv("VECSHIELD_SAFE_MODE", "0")


class MemoryConnector(Connector):
    kind = "memory"

    def __init__(self, texts=(), *, count=None, enumerable=True, failure=None,
                 read_errors=None):
        self.chunks = [Chunk(id=str(i), collection="records", text=text)
                       for i, text in enumerate(texts)]
        self.count = count
        self.content_enumerable = enumerable
        self.failure = failure
        self.reported_errors = read_errors or []
        self.delete_calls = 0
        self.visible = True

    def capabilities(self):
        return {"delete"}

    def describe(self):
        if self.failure == "inventory":
            raise RuntimeError("inventory denied")
        return VectorStore(kind=self.kind, name="memory", endpoint="memory",
                           collections=self.list_collections())

    def list_collections(self):
        if not self.visible:
            return []
        count = len(self.chunks) if self.count is None else self.count
        return [Collection(name="records", count=count)]

    def iter_chunks(self, collection, batch_size=256):
        for chunk in self.chunks:
            yield chunk
        if self.failure == "enumeration":
            raise RuntimeError("page retrieval failed")

    def read_errors(self):
        return self.reported_errors

    def delete_chunks(self, collection, ids):
        self.delete_calls += 1
        before = len(self.chunks)
        self.chunks = [c for c in self.chunks if c.id not in ids]
        return before - len(self.chunks)


class Registry:
    def __init__(self, **connectors):
        self.connectors = connectors

    def list(self):
        return [SimpleNamespace(store_id=name, kind="memory") for name in self.connectors]

    def open(self, store_id):
        return self.connectors[store_id]


@pytest.mark.parametrize("kwargs,options,status", [
    ({"enumerable": False}, {}, "unsupported"),
    ({"failure": "inventory"}, {}, "error"),
    ({"failure": "enumeration"}, {}, "error"),
    ({"count": 2}, {}, "partial"),
    ({"read_errors": [{"file_id": "f", "error": "denied"}]}, {}, "error"),
    ({"texts": ["other", "another"]}, {"max_chunks_per_collection": 1}, "partial"),
    ({}, {"collections": ["missing"]}, "error"),
    ({}, {"collections": []}, "partial"),
])
def test_zero_matches_require_complete_coverage(kwargs, options, status):
    verification = verify_erasure(MemoryConnector(**kwargs), "subject", **options)
    assert verification.remaining.chunks_to_delete == 0
    assert verification.remaining.coverage_status == status
    assert not verification.ok
    assert not verification.remaining.coverage_complete
    restored = ErasureVerification.from_dict(json.loads(json.dumps(verification.to_dict())))
    assert restored.to_dict() == verification.to_dict()
    assert not restored.ok


def test_exact_limit_with_exhausted_iterator_is_complete():
    verification = verify_erasure(MemoryConnector(["other"]), "subject",
                                 max_chunks_per_collection=1)
    assert verification.ok
    assert verification.outcome == "passed"


def test_complete_empty_collection_is_distinct_from_unknown_coverage():
    verification = verify_erasure(MemoryConnector(), "subject")
    assert verification.ok
    legacy = verification.to_dict()
    legacy["remaining"].pop("coverage_status")
    restored = ErasureVerification.from_dict(legacy)
    assert restored.remaining.coverage_status == "unknown"
    assert restored.outcome == "inconclusive"
    assert not restored.ok
    assert not ErasureVerification.from_dict({
        "subject": "subject", "generated_at": "today", "ok": True,
    }).ok


def test_partial_enumeration_preserves_observed_matches_and_counts():
    report = erasure_impact(MemoryConnector(["subject", "other"], failure="enumeration"),
                           "subject")
    assert report.chunks_to_delete == 1
    assert report.scanned_chunks == {"records": 2}
    assert report.coverage_status == "partial"
    assert report.errors[0]["stage"] == "enumeration"
    restored = ErasureReport.from_dict(json.loads(json.dumps(report.to_dict())))
    assert restored.to_dict() == report.to_dict()
    assert restored.reindex_chunk_cost == 2


def test_unreadable_chunk_and_duplicate_ids_cannot_prove_absence():
    connector = MemoryConnector([None, None])
    connector.chunks[0].metadata = {"content_unreadable": True}
    connector.chunks[1].id = connector.chunks[0].id
    report = erasure_impact(connector, "subject")
    assert not report.coverage_complete
    assert report.errors
    assert report.scanned_chunks == {"records": 1}
    assert any("duplicate" in item for item in report.limitations)


def test_nested_metadata_and_long_text_are_fully_inspected():
    connector = MemoryConnector([None, "other " * 2000 + "subject"])
    connector.chunks[0].metadata = {"owners": [{"email": "subject"}]}
    report = erasure_impact(connector, "subject")
    assert report.coverage_complete
    assert report.chunks_to_delete == 2
    assert report.matches[0].matched_on == "metadata:owners[0].email"


def test_execution_refuses_incomplete_discovery_without_mutation():
    connector = MemoryConnector(["subject"], count=2)
    execution = execute_erasure(connector, plan_erasure(erasure_impact(connector, "subject")))
    assert not execution.ok
    assert not execution.verified
    assert execution.errors["coverage"]
    assert connector.delete_calls == 0


def test_verification_cannot_shrink_previously_inspected_scope():
    connector = MemoryConnector()
    connector.visible = False
    verification = verify_erasure(connector, "subject", required_collections=["records"])
    assert not verification.ok
    assert verification.remaining.errors[0]["stage"] == "verification"


@pytest.mark.parametrize("connector", [
    MemoryConnector(enumerable=False), MemoryConnector(failure="inventory"),
    MemoryConnector(count=1),
])
def test_dsar_does_not_skip_zero_match_stores_with_discovery_gaps(connector):
    registry = Registry(uncertain=connector, clean=MemoryConnector())
    record = scan_all_stores(create_dsar("subject"), registry)
    execute_dsar(record, registry, store_ids=["clean"])
    assert record.status == "partial_error"
    assert not record.ok
    assert not record.verified
    assert not record.evidence_bundle()["verified"]
    restored = DSARRecord.from_dict(json.loads(json.dumps(record.to_dict())))
    assert not restored.ok
    assert restored.status == "partial_error"


def test_dsar_partial_selection_cannot_close_unexecuted_store():
    registry = Registry(first=MemoryConnector(["subject"]), second=MemoryConnector(["subject"]))
    record = scan_all_stores(create_dsar("subject"), registry)
    execute_dsar(record, registry, store_ids=["first"])
    assert record.total_chunks_deleted == 1
    assert record.status == "partial_error"
    assert not record.verified
    execute_dsar(record, registry, store_ids=["second"])
    assert record.status == "executed"
    assert record.verified
    assert registry.connectors["first"].delete_calls == 1


def test_dsar_requires_verification_and_retry_does_not_repeat_deletion():
    connector = MemoryConnector(["subject"])
    registry = Registry(records=connector)
    record = scan_all_stores(create_dsar("subject"), registry)
    execute_dsar(record, registry, verify=False)
    assert record.status == "awaiting_verification"
    assert not record.ok
    assert not record.verified
    record = DSARRecord.from_dict(json.loads(json.dumps(record.to_dict())))
    execute_dsar(record, registry, verify=True)
    assert record.status == "executed"
    assert record.verified
    assert connector.delete_calls == 1


def test_legacy_executed_dsar_is_not_verified_after_reload():
    registry = Registry(records=MemoryConnector())
    record = scan_all_stores(create_dsar("subject"), registry)
    execute_dsar(record, registry)
    payload = record.to_dict()
    payload["stores"][0]["impact"].pop("coverage_status")
    restored = DSARRecord.from_dict(payload)
    assert restored.status == "partial_error"
    assert not restored.ok
    assert not restored.evidence_bundle()["verified"]


@pytest.mark.parametrize("store_ids", [[], ["missing"]])
def test_empty_or_missing_dsar_scope_is_not_verified(store_ids):
    registry = Registry(records=MemoryConnector())
    record = scan_all_stores(create_dsar("subject"), registry, store_ids=store_ids)
    execute_dsar(record, registry)
    assert record.status == "partial_error"
    assert not record.ok
    assert not record.verified


# ------------------------------------------------ previews, safe mode, surfaces ---

RAW_CONTEXT = ["rotate AKIAIOSFODNN7EXAMPLE tonight",
               "Ticket from jane@example.com SSN 123-45-6789 re billing"]


@pytest.mark.parametrize("subject,raw", [
    ("rotate", ["AKIAIOSFODNN7EXAMPL"]),
    ("SSN", ["123-45-6789", "jane@example.com"]),
])
def test_erasure_preview_masks_detected_values_around_the_subject(subject, raw):
    """A viewer may run an impact assessment; the context must come back masked."""
    report = erasure_impact(MemoryConnector(RAW_CONTEXT), subject)
    assert report.matches
    assert all("‹SUBJECT›" in m.preview for m in report.matches)
    blob = json.dumps(report.to_dict())
    assert [value for value in raw if value in blob] == []


def test_erasure_preview_drops_context_when_nothing_can_classify_it():
    class Broken:
        def classify(self, text):
            raise RuntimeError("model failed to load")

    report = erasure_impact(MemoryConnector(RAW_CONTEXT), "SSN", classifier=Broken())
    assert report.matches[0].preview.strip("…") == "‹SUBJECT›"


def test_dsar_record_carries_no_raw_value_from_the_context():
    registry = Registry(records=MemoryConnector(RAW_CONTEXT))
    record = scan_all_stores(create_dsar("SSN"), registry)
    blob = json.dumps(record.to_dict()) + json.dumps(record.evidence_bundle())
    assert "123-45-6789" not in blob and "jane@example.com" not in blob


def test_erasure_execution_obeys_safe_mode_before_touching_the_store(monkeypatch):
    from vecshield_platform.execution import ExecutionError, SafeModeRefused

    assert issubclass(SafeModeRefused, ExecutionError)
    monkeypatch.delenv("VECSHIELD_SAFE_MODE", raising=False)
    connector = MemoryConnector(["subject"])
    plan = plan_erasure(erasure_impact(connector, "subject"))
    with pytest.raises(SafeModeRefused, match="VECSHIELD_SAFE_MODE=0"):
        execute_erasure(connector, plan)
    assert connector.delete_calls == 0 and [c.id for c in connector.chunks] == ["0"]


def test_dsar_execution_obeys_safe_mode_before_opening_a_store(monkeypatch):
    from vecshield_platform.execution import SafeModeRefused

    monkeypatch.delenv("VECSHIELD_SAFE_MODE", raising=False)
    connector = MemoryConnector(["subject"])
    registry = Registry(records=connector)
    record = scan_all_stores(create_dsar("subject"), registry)
    with pytest.raises(SafeModeRefused, match="VECSHIELD_SAFE_MODE=0"):
        execute_dsar(record, registry)
    assert connector.delete_calls == 0
    assert record.status == "scanned"


def test_erasure_does_not_count_surface_less_chunks_as_inspected():
    """The scan engine's rule: a chunk with nothing to read is not evidence of absence."""
    connector = MemoryConnector([None, None, None])
    report = erasure_impact(connector, "maria.gonzalez@example.com")
    assert report.chunks_to_delete == 0
    assert report.coverage_status == "partial"
    assert not report.coverage_complete
    assert any("no text or metadata" in item for item in report.limitations)
