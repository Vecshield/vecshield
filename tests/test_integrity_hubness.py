"""Retrieval hubness via k-occurrence (retrieval_hubness)."""

from __future__ import annotations

import numpy as np

from vecshield.models import Chunk, Collection, Severity, VectorStore
from vecshield_platform.connectors.base import Connector
from vecshield_platform.integrity import (
    ChunkRecord,
    IntegrityLimits,
    analyze_hubness,
    k_occurrence,
    scan_integrity,
)


def _records(ids, *, source="wiki", text_len=200, overrides=None):
    overrides = overrides or {}
    return [ChunkRecord(id=i, **{"source": source, "text_len": text_len,
                                 **overrides.get(i, {})}) for i in ids]


def _cloud(n=400, dim=32, seed=0):
    rng = np.random.default_rng(seed)
    mu = np.zeros(dim)
    mu[0] = 2.0
    return mu, (mu + rng.normal(0, 1, (n, dim))).astype(np.float32)


def _hub_report(X, ids, records, metric="cosine", limits=None, **kw):
    return analyze_hubness(store="s", collection="docs", vector_ids=ids, vectors=X,
                           vectors_sampled=False, metric=metric, records=records,
                           limits=limits or IntegrityLimits(), **kw)


def test_clean_cloud_has_no_hubs():
    _, X = _cloud()
    ids = [f"c{i}" for i in range(len(X))]
    rep = _hub_report(X, ids, _records(ids))
    assert not rep.findings and not rep.detected
    assert rep.stats["hubs"] == 0


def test_planted_centroid_hub_from_rare_source_is_medium():
    mu, X = _cloud()
    X = np.vstack([X, mu.astype(np.float32)])
    ids = [f"c{i}" for i in range(len(X) - 1)] + ["hub"]
    recs = _records(ids, overrides={"hub": {"source": "unknown-upload"}})
    rep = _hub_report(X, ids, recs)
    f = rep.findings[0]
    assert f.severity == Severity.MEDIUM and f.category == "retrieval_hubness"
    ex = f.evidence["examples"][0]
    assert ex["chunk_id"] == "hub" and "rare_or_unattributed_source" in ex["signals"]
    assert ex["probe_share"] > 0.1
    assert "proxy queries" in f.evidence["caveat"]
    assert rep.detected


def test_uncorroborated_hub_is_low_and_short_chunk_hub_is_info():
    mu, X = _cloud()
    X = np.vstack([X, mu.astype(np.float32)])
    ids = [f"c{i}" for i in range(len(X) - 1)] + ["hub"]
    low = _hub_report(X, ids, _records(ids))
    assert [f.severity for f in low.findings] == [Severity.LOW]
    short = _hub_report(X, ids, _records(ids, overrides={"hub": {"text_len": 0}}))
    assert [f.severity for f in short.findings] == [Severity.INFO]
    assert short.detected is False  # natural hubs alone do not fail the check


def test_exact_duplicates_do_not_become_artificial_hubs():
    _, X = _cloud(n=300)
    X = np.vstack([X, np.repeat(X[:1], 60, axis=0)])  # a repeated template
    ids = [f"c{i}" for i in range(len(X))]
    reps, sizes, counts, stats = k_occurrence(X, metric="cosine", k=10, pool_size=10_000,
                                              probe_count=1_000, seed=0)
    assert stats["unique_pool"] == 300
    assert sizes.max() == 61
    assert not _hub_report(X, ids, _records(ids)).findings


def test_dot_metric_finds_norm_inflated_hub_cosine_does_not():
    rng = np.random.default_rng(3)
    X = rng.normal(0, 1, (400, 16)).astype(np.float32)
    X /= np.linalg.norm(X, axis=1, keepdims=True)
    direction = X.mean(axis=0) + rng.normal(0, 0.05, 16).astype(np.float32)
    hub = (direction / np.linalg.norm(direction) * 40).astype(np.float32)
    X = np.vstack([X, hub])
    ids = [f"c{i}" for i in range(400)] + ["big"]
    dot = _hub_report(X, ids, _records(ids), metric="dot")
    assert any(e["chunk_id"] == "big" for f in dot.findings for e in f.evidence["examples"])
    cos = _hub_report(X, ids, _records(ids), metric="cosine")
    assert not any(e["chunk_id"] == "big" for f in cos.findings
                   for e in f.evidence["examples"])


def test_pool_cap_is_partial_and_reruns_agree():
    mu, X = _cloud(n=600)
    ids = [f"c{i}" for i in range(len(X))]
    limits = IntegrityLimits(hub_pool_size=200, hub_probe_count=50)
    a = _hub_report(X, ids, _records(ids), limits=limits)
    b = _hub_report(X, ids, _records(ids), limits=limits)
    assert a.stats == b.stats
    assert "capped" in a.limitation and a.coverage["pool"] == 200


def test_unknown_metric_is_noted_and_small_collections_are_partial():
    _, X = _cloud(n=50)
    ids = [f"c{i}" for i in range(50)]
    rep = _hub_report(X, ids, _records(ids), metric=None)
    assert "cosine was assumed" in rep.note
    small = _hub_report(X[:5], ids[:5], _records(ids[:5]))
    assert small.limitation


class Mem(Connector):
    kind = "memory"

    def __init__(self, chunks):
        self.chunks = chunks

    def describe(self):
        return VectorStore(kind="memory", name="memory", endpoint="memory://",
                           collections=[Collection(name="docs", count=len(self.chunks),
                                                   distance_metric="cosine")])

    def list_collections(self):
        return self.describe().collections

    def iter_chunks(self, collection, batch_size=256):
        yield from self.chunks


def test_engine_emits_retrieval_hubness_outcome():
    mu, X = _cloud(n=200)
    chunks = [Chunk(id=f"c{i}", collection="docs", text=f"entry {i} " * 10,
                    embedding=v.tolist(), metadata={"source": "wiki"})
              for i, v in enumerate(X)]
    chunks.append(Chunk(id="hub", collection="docs", text="planted " * 20,
                        embedding=mu.tolist(), metadata={}))
    job = scan_integrity(Mem(chunks), "docs")
    out = next(o for o in job.stats["check_outcomes"] if o["check"] == "retrieval_hubness")
    assert out["outcome"] == "failed" and out["coverage"]["complete"] is True
    hub = next(f for f in job.findings if f.category == "retrieval_hubness")
    assert hub.severity == Severity.MEDIUM  # unattributed + near-centroid anomaly
    assert set(hub.evidence["examples"][0]["signals"]) >= {"rare_or_unattributed_source"}
