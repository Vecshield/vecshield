"""Unit tests for the embedding-anomaly detector."""

from __future__ import annotations

import numpy as np

from vecshield_platform.integrity import detect_anomalies


def test_planted_outlier_is_flagged():
    rng = np.random.default_rng(0)
    normal = rng.normal(0, 1, size=(200, 16))
    outlier = np.full((1, 16), 20.0)
    X = np.vstack([normal, outlier])
    ids = [f"n{i}" for i in range(200)] + ["outlier"]

    scores = {s.id: s for s in detect_anomalies(ids, X.tolist(), metric="euclidean")}
    assert scores["outlier"].is_anomaly
    assert scores["outlier"].score > scores["n0"].score


def test_uniform_cluster_has_no_anomalies():
    rng = np.random.default_rng(1)
    X = rng.normal(0, 1, size=(300, 8))
    ids = [f"v{i}" for i in range(300)]
    scores = detect_anomalies(ids, X.tolist(), z_threshold=3.5)
    # A tight gaussian cluster should produce few/no extreme outliers.
    assert sum(s.is_anomaly for s in scores) <= 3


def test_empty_input():
    assert detect_anomalies([], []) == []
