"""Ingestion bursts and the provenance contract (ingestion_burst)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from vecshield.models import Chunk, Collection, Severity, VectorStore
from vecshield_platform.connectors.base import Connector
from vecshield_platform.integrity import (
    IntegrityLimits,
    analyze_ingestion,
    build_record,
    scan_integrity,
)

T0 = datetime(2026, 3, 1, tzinfo=timezone.utc)
KEY = b"k" * 16


def _rec(i, when, source, **meta):
    return build_record(f"c{i}", f"text {i}", {"source": source,
                                                "ingested_at": when.isoformat(), **meta},
                        has_embedding=True, key=KEY)


def _baseline(hours=30, per_hour=5, sources=6):
    recs, i = [], 0
    for h in range(hours):
        for j in range(per_hour):
            recs.append(_rec(i, T0 + timedelta(hours=h, minutes=j),
                             f"doc-{(h + j) % sources}.pdf"))
            i += 1
    return recs, i


def _analyze(records, **kw):
    return analyze_ingestion(store="s", collection="docs", records=records,
                             limits=IntegrityLimits(), **kw)


def test_steady_ingestion_has_no_burst():
    recs, _ = _baseline()
    rep = _analyze(recs)
    assert not rep.findings and not rep.detected and not rep.data_gap
    assert rep.stats["time_field"] == "ingested_at"


def test_burst_from_new_source_is_low_and_corroborated_burst_is_medium():
    recs, i = _baseline()
    burst = [_rec(i + j, T0 + timedelta(hours=12, minutes=30, seconds=j), "bulk-upload.txt")
             for j in range(60)]
    rep = _analyze(recs + burst)
    f = rep.findings[0]
    assert f.severity == Severity.LOW and f.category == "ingestion_burst"
    ex = f.evidence["examples"][0]
    assert ex["chunks"] == 65 and ex["new_sources"] == ["bulk-upload.txt"]
    assert rep.detected

    rep = _analyze(recs + burst, corroborating_ids={burst[3].id})
    assert rep.findings[0].severity == Severity.MEDIUM
    assert rep.findings[0].evidence["examples"][0]["flagged_chunks"] == [burst[3].id]


def test_burst_from_established_sources_is_not_reported():
    recs, i = _baseline()
    reindex = [_rec(i + j, T0 + timedelta(hours=20, seconds=j), f"doc-{j % 6}.pdf")
               for j in range(60)]
    rep = _analyze(recs + reindex)
    assert not rep.findings
    assert rep.stats["spikes"] == 1 and rep.stats["reported_spikes"] == 0


def test_no_timestamps_and_one_bulk_load_are_data_gaps():
    recs = [build_record(f"c{i}", "t", {"source": "a"}, has_embedding=True, key=KEY)
            for i in range(20)]
    assert "cannot be observed" in _analyze(recs).data_gap
    bulk = [_rec(i, T0 + timedelta(seconds=i), "a") for i in range(50)]
    assert "baseline" in _analyze(bulk).data_gap


def test_subject_dates_are_never_ingestion_times():
    recs = [build_record(f"c{i}", "t", {"source": "a", "date_of_birth": "1970-01-01"},
                         has_embedding=True, key=KEY) for i in range(20)]
    rep = _analyze(recs)
    assert rep.stats["time_field"] is None and rep.data_gap


def test_provenance_contract_shares():
    full = {"source": "a.pdf", "ingested_at": T0.isoformat(), "content_hash": "abc",
            "embedding_model": "text-embedding-3-small", "ingested_by": "svc-ingest"}
    recs = [build_record("c0", "t", full, has_embedding=True, key=KEY),
            build_record("c1", "t", {"source": "b.pdf"}, has_embedding=True, key=KEY)]
    fields = _analyze(recs).stats["provenance_contract"]["fields"]
    assert fields["source_id"]["share"] == 1.0
    for name in ("ingestion_timestamp", "content_hash", "embedding_model",
                 "ingesting_principal"):
        assert fields[name]["share"] == 0.5, name


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


def test_engine_outcome_and_contract_in_stats():
    chunks = []
    for h in range(30):
        for j in range(5):
            chunks.append(Chunk(id=f"c{h}-{j}", collection="docs", text=f"note {h} {j}",
                                metadata={"source": f"doc-{j}.pdf",
                                          "ingested_at": (T0 + timedelta(hours=h)).isoformat()}))
    chunks += [Chunk(id=f"b{j}", collection="docs", text=f"burst {j}",
                     metadata={"source": "new.txt",
                               "ingested_at": (T0 + timedelta(hours=40)).isoformat()})
               for j in range(80)]
    job = scan_integrity(Mem(chunks), "docs")
    out = next(o for o in job.stats["check_outcomes"] if o["check"] == "ingestion_burst")
    assert out["outcome"] == "failed"
    assert job.stats["provenance_contract"]["fields"]["ingestion_timestamp"]["share"] == 1.0


def test_provenance_rarity_is_relative_to_typical_source_size():
    from vecshield_platform.integrity import analyze_provenance

    many_small = [{"source": f"ticket-{i // 20}"} for i in range(2000)]
    assert analyze_provenance(many_small).rare_sources == []
    planted = many_small + [{"source": "stranger.txt"}]
    assert analyze_provenance(planted).rare_sources == ["stranger.txt"]
