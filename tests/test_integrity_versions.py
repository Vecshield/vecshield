"""Outdated, superseded and conflicting chunks (chunk_versions)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from vecshield.models import Chunk, Collection, Severity, VectorStore
from vecshield_platform.connectors.base import Connector
from vecshield_platform.integrity import (
    IntegrityLimits,
    analyze_versions,
    build_record,
    scan_integrity,
)

KEY = b"v" * 16
T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def rec(cid, text, **meta):
    return build_record(cid, text, meta, has_embedding=True, key=KEY)


def analyze(records, **kw):
    kw.setdefault("time_field", None)
    return analyze_versions(store="s", collection="docs", records=records,
                            limits=IntegrityLimits(), **kw)


def stable_docs(n=5):
    return [rec(f"d{s}-{j}", f"doc {s} part {j}", source=f"doc-{s}.pdf", chunk_index=j,
                version="1") for s in range(n) for j in range(3)]


def test_single_generation_passes():
    rep = analyze(stable_docs())
    assert not rep.findings and not rep.detected and not rep.data_gap


def test_superseded_generation_is_medium_with_old_ids():
    records = stable_docs()
    records += [rec(f"old-{j}", f"policy v1 part {j}", source="policy.pdf", chunk_index=j,
                    version="1.2") for j in range(3)]
    records += [rec(f"new-{j}", f"policy v2 part {j}", source="policy.pdf", chunk_index=j,
                    version="1.10") for j in range(3)]
    rep = analyze(records)
    f = rep.findings[0]
    assert f.severity == Severity.MEDIUM and f.category == "chunk_versions"
    ex = f.evidence["examples"][0]
    # 1.10 is newer than 1.2: version order is numeric per component, not lexical.
    assert ex["order_known"] and set(ex["superseded_ids"]) == {"old-0", "old-1", "old-2"}
    assert rep.detected
    # Positions collide across generations, but that is supersession, not a conflict.
    assert not any("Conflicting" in x.title for x in rep.findings)


def test_superseded_sensitive_generation_is_high():
    records = stable_docs()
    records += [rec("old", "address: 1 old road", source="patient.json", version="1"),
                rec("new", "address: 2 new street", source="patient.json", version="2")]
    rep = analyze(records, sensitive_ids={"old"})
    assert rep.findings[0].severity == Severity.HIGH
    assert rep.findings[0].evidence["sensitive_superseded_chunks"] == 1


def test_per_chunk_write_times_are_one_generation():
    records = [rec(f"c{j}", f"part {j}", source="a.pdf", chunk_index=j,
                   updated_at=(T0 + timedelta(seconds=j)).isoformat()) for j in range(10)]
    assert not analyze(records).findings
    records += [rec(f"n{j}", f"new part {j}", source="a.pdf", chunk_index=j,
                    updated_at=(T0 + timedelta(days=30, seconds=j)).isoformat())
                for j in range(10)]
    rep = analyze(records)
    assert rep.findings[0].evidence["examples"][0]["superseded_chunks"] == 10


def test_per_chunk_hash_is_not_a_document_version():
    records = [rec(f"c{s}-{j}", f"text {s} {j}", source=f"doc-{s}", chunk_index=j,
                   content_hash=f"h{s}-{j}") for s in range(4) for j in range(4)]
    rep = analyze(records)
    assert not rep.findings
    assert rep.stats["per_chunk_fields_ignored"] == ["content_hash"]


def test_opaque_etag_generations_ordered_by_ingestion_time():
    records = stable_docs()
    for g, etag in enumerate(("aaa", "bbb")):
        for j in range(2):
            records.append(rec(f"{etag}-{j}", f"gen {g} part {j}", source="page.html",
                               etag=etag, ingested_at=(T0 + timedelta(days=g)).isoformat()))
    rep = analyze(records, time_field="ingested_at")
    ex = rep.findings[0].evidence["examples"][0]
    assert ex["order_known"] and set(ex["superseded_ids"]) == {"aaa-0", "aaa-1"}


def test_conflicting_positions_low_and_reingested_medium():
    records = stable_docs()
    records += [rec("x1", "clause says thirty days", source="terms.pdf", chunk_index=4),
                rec("x2", "clause says sixty days", source="terms.pdf", chunk_index=4)]
    rep = analyze(records)
    f = next(x for x in rep.findings if "Conflicting" in x.title)
    assert f.severity == Severity.LOW
    # The same source also has an identical re-ingested position: a stale copy.
    records += [rec("y1", "intro", source="terms.pdf", chunk_index=0),
                rec("y2", "intro", source="terms.pdf", chunk_index=0)]
    f = next(x for x in analyze(records).findings if "Conflicting" in x.title)
    assert f.severity == Severity.MEDIUM


def test_non_unique_position_key_is_not_reported_as_conflict():
    # chunk_index restarts on every page, and pages are not recorded.
    records = [rec(f"p{s}-{pg}-{j}", f"doc {s} page {pg} chunk {j}", source=f"doc-{s}",
                   chunk_index=j) for s in range(5) for pg in range(3) for j in range(2)]
    rep = analyze(records)
    assert not rep.findings
    assert rep.stats["position_key_not_unique"] is True


def test_manifest_deleted_stale_and_unknown_sources():
    records = stable_docs(3)
    records += [rec("gone-0", "removed text", source="gone.pdf"),
                rec("stale-0", "old text", source="kb.md", version="3"),
                rec("mystery-0", "who put this here", source="mystery.txt")]
    manifest = [{"source": f"doc-{s}.pdf", "version": "1"} for s in range(3)] + [
        {"source": "gone.pdf", "deleted": True},
        {"source": "kb.md", "version": "4"}]
    rep = analyze(records, source_manifest=manifest, sensitive_ids={"gone-0"})
    by_title = {f.title.split(" in ")[0]: f for f in rep.findings}
    assert by_title["Chunks from deleted sources still stored"].severity == Severity.HIGH
    assert by_title["Chunks older than the current source version"].severity == Severity.MEDIUM
    assert by_title["Chunks from sources missing from the manifest"].severity == Severity.LOW
    assert rep.stats["sources_unknown_to_manifest"] == 1


def test_manifest_updated_at_against_ingestion_time():
    records = [rec("a", "t", source="kb.md", ingested_at=T0.isoformat())]
    manifest = [{"source": "kb.md", "updated_at": (T0 + timedelta(days=2)).isoformat()}]
    rep = analyze(records, source_manifest=manifest, time_field="ingested_at")
    assert any("older than the current" in f.title for f in rep.findings)


def test_no_version_keys_is_a_data_gap():
    records = [rec(f"c{i}", f"t{i}", source="a.pdf") for i in range(5)]
    rep = analyze(records)
    assert rep.data_gap and "100%" in rep.data_gap and not rep.detected


class Mem(Connector):
    kind = "memory"

    def __init__(self, chunks):
        self.chunks = chunks

    def describe(self):
        return VectorStore(kind="memory", name="memory", endpoint="memory://",
                           collections=self.list_collections())

    def list_collections(self):
        return [Collection(name="docs", count=len(self.chunks))]

    def iter_chunks(self, collection, batch_size=256):
        yield from self.chunks


def test_engine_outcomes_for_versions():
    plain = [Chunk(id=f"c{i}", collection="docs", text=f"t{i}", metadata={"source": "a"})
             for i in range(5)]
    job = scan_integrity(Mem(plain), "docs")
    out = next(o for o in job.stats["check_outcomes"] if o["check"] == "chunk_versions")
    # No version field is a gap in the data, not in coverage.
    assert out["outcome"] == "inconclusive" and out["coverage"]["complete"] is True
    assert out["coverage"]["data_gap"] is True

    versioned = plain + [Chunk(id="v1", collection="docs", text="old",
                               metadata={"source": "b", "version": 1}),
                         Chunk(id="v2", collection="docs", text="new",
                               metadata={"source": "b", "version": 2})]
    job = scan_integrity(Mem(versioned), "docs",
                         source_manifest=[{"source": "a"}, {"source": "b", "version": "2"}])
    out = next(o for o in job.stats["check_outcomes"] if o["check"] == "chunk_versions")
    assert out["outcome"] == "failed" and out["coverage"]["manifest_supplied"] is True
