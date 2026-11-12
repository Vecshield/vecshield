"""Two-sided (black-hole) and norm-aware embedding anomaly detection."""

from __future__ import annotations

import numpy as np
import pytest

from vecshield.models import Chunk, Collection, VectorStore
from vecshield_platform.connectors.base import Connector
from vecshield_platform.integrity import (
    CHECKS,
    IntegrityLimits,
    StreamingAnomalyDetector,
    detect_anomalies,
    scan_integrity,
)


class MetricConnector(Connector):
    kind = "memory"

    def __init__(self, chunks, metric=None):
        self.chunks = chunks
        self.metric = metric

    def describe(self):
        return VectorStore(kind="memory", name="memory", endpoint="memory://",
                           collections=self.list_collections())

    def list_collections(self):
        return [Collection(name="docs", count=len(self.chunks), distance_metric=self.metric)]

    def iter_chunks(self, collection, batch_size=256):
        yield from self.chunks


def _concentrated(n=300, dim=32, seed=0):
    """Vectors concentrated around one direction, as real embeddings are."""
    rng = np.random.default_rng(seed)
    mu = np.zeros(dim)
    mu[0] = 3.0
    return mu, mu + rng.normal(0, 1, size=(n, dim))


def test_black_hole_vector_near_centroid_is_flagged():
    mu, X = _concentrated()
    X = np.vstack([X, mu])  # exactly the collection's mean direction
    ids = [f"n{i}" for i in range(len(X) - 1)] + ["hole"]
    scores = {s.id: s for s in detect_anomalies(ids, X.tolist())}
    assert scores["hole"].is_anomaly and scores["hole"].direction == "near"
    assert scores["hole"].score < -3.5
    # The healthy core is not flagged: near needs z AND a distance ratio.
    assert sum(s.direction == "near" for s in scores.values()) <= 3


def test_one_sided_mode_keeps_previous_behaviour():
    mu, X = _concentrated()
    X = np.vstack([X, mu])
    ids = [f"n{i}" for i in range(len(X) - 1)] + ["hole"]
    scores = {s.id: s for s in detect_anomalies(ids, X.tolist(), two_sided=False)}
    assert not scores["hole"].is_anomaly
    assert all(s.direction in ("", "far") for s in scores.values())


def test_far_outliers_still_flagged_as_far():
    rng = np.random.default_rng(3)
    X = np.vstack([rng.normal(0, 1, size=(200, 16)), np.full((1, 16), 20.0)])
    ids = [f"n{i}" for i in range(200)] + ["out"]
    scores = {s.id: s for s in detect_anomalies(ids, X.tolist(), metric="euclidean")}
    assert scores["out"].direction == "far"


def test_dot_norm_outliers_flagged_only_when_requested():
    rng = np.random.default_rng(4)
    X = rng.normal(0, 1, size=(200, 16))
    X /= np.linalg.norm(X, axis=1, keepdims=True)  # normalised: MAD of norms is 0
    X = np.vstack([X, X[0] * 12.0])
    ids = [f"v{i}" for i in range(200)] + ["big"]
    plain = {s.id: s for s in detect_anomalies(ids, X.tolist())}
    assert not plain["big"].norm_outlier and plain["big"].norm is None
    scored = {s.id: s for s in detect_anomalies(ids, X.tolist(), score_norms=True)}
    assert scored["big"].norm_outlier
    assert sum(s.norm_outlier for s in scored.values()) == 1


def test_equal_norms_have_no_norm_outliers():
    rng = np.random.default_rng(5)
    X = rng.normal(0, 1, size=(100, 8))
    X /= np.linalg.norm(X, axis=1, keepdims=True)
    scored = detect_anomalies([str(i) for i in range(100)], X.tolist(), score_norms=True)
    assert not any(s.norm_outlier for s in scored)


def test_streaming_exposes_sample_without_duplicating():
    det = StreamingAnomalyDetector(sample_size=50, seed=1)
    rng = np.random.default_rng(0)
    det.add_batch([f"a{i}" for i in range(20)], rng.normal(size=(20, 4)).tolist())
    M = det.sample_matrix()
    assert M.shape == (20, 4) and M.dtype == np.float32
    assert det.sample_ids() == [f"a{i}" for i in range(20)]
    assert det.finalize().total_seen == 20
    with pytest.raises(ValueError):
        det.add_batch(["x"], [[1.0, 2.0]])  # dimension change


def _chunks(X, ids):
    return [Chunk(id=i, collection="docs", text=f"Distinct entry number {i} about topic {i}.",
                  embedding=list(map(float, v)), metadata={"source": "wiki"})
            for i, v in zip(ids, X)]


def test_engine_reports_black_hole_and_norm_findings_by_metric():
    mu, X = _concentrated(n=200, dim=32, seed=6)
    X = X / np.linalg.norm(X, axis=1, keepdims=True)
    big = X[1] * 15.0
    X = np.vstack([X, mu / np.linalg.norm(mu), big])
    ids = [f"n{i}" for i in range(200)] + ["hole", "big"]
    dot = scan_integrity(MetricConnector(_chunks(X, ids), metric="dot"), "docs")
    titles = [f.title for f in dot.findings]
    assert any("close to the centroid" in t for t in titles)
    norm = next(f for f in dot.findings if "vector norms" in f.title)
    assert norm.category == "rag_integrity"
    assert [e["chunk_id"] for e in norm.evidence["examples"]] == ["big"]
    outcomes = {o["check"]: o for o in dot.stats["check_outcomes"]}
    assert outcomes["embedding_anomaly"]["outcome"] == "failed"
    assert dot.stats["distance_metric"] == "dot"

    cosine = scan_integrity(MetricConnector(_chunks(X, ids), metric="cosine"), "docs")
    assert not any("vector norms" in f.title for f in cosine.findings)
    # An explicit collection_meta overrides the inventory.
    override = scan_integrity(MetricConnector(_chunks(X, ids), metric="cosine"), "docs",
                              collection_meta=Collection(name="docs", distance_metric="dot"))
    assert any("vector norms" in f.title for f in override.findings)


def test_unknown_metric_is_noted_and_all_checks_recorded():
    mu, X = _concentrated(n=50, dim=8)
    job = scan_integrity(MetricConnector(_chunks(X, [f"c{i}" for i in range(50)])), "docs")
    outcomes = {o["check"]: o for o in job.stats["check_outcomes"]}
    assert set(outcomes) == set(CHECKS)
    assert "cosine geometry was assumed" in outcomes["embedding_anomaly"]["reason"]


def test_limits_env_override(monkeypatch):
    monkeypatch.setenv("VECSHIELD_INTEGRITY_HUB_POOL_SIZE", "123")
    monkeypatch.setenv("VECSHIELD_INTEGRITY_NEAR_Z", "4.5")
    limits = IntegrityLimits.from_env()
    assert limits.hub_pool_size == 123 and limits.near_z == 4.5
    monkeypatch.setenv("VECSHIELD_INTEGRITY_HUB_K", "ten")
    with pytest.raises(ValueError):
        IntegrityLimits.from_env()
