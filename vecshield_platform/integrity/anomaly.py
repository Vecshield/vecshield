"""Embedding-distribution anomaly detector.

Poisoned or off-distribution vectors tend to sit far from the bulk of a
collection. We measure each point's distance from the collection centroid and
convert it to a robust z-score using the median and MAD (median absolute
deviation), which — unlike mean/stdev — isn't dragged around by the very
outliers we're hunting.

The test is **two-sided**. A vector planted abnormally *close* to the centroid
is close to every query at once and is retrieved for almost anything: the
"black-hole" attack (Li et al., 2026, arXiv 2604.05480). Such a vector has a
strongly negative robust z; it is flagged when z <= -``near_z`` *and* its
distance is under ``near_ratio`` x the median distance, so a tight but healthy
distribution never flags its own core.

For inner-product ("dot") collections the raw vector norm is scored as well:
inner product rewards magnitude, so an attacker can inflate a vector's norm to
win retrieval without changing its direction. Norm outliers are one-sided
(large only) and must also exceed ``norm_ratio`` x the median norm.

Cosine geometry by default (vectors are L2-normalized first), since most text
embedding models are trained for cosine similarity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

import numpy as np

# MAD -> stdev consistency constant for normally distributed data.
_MAD_SCALE = 1.4826


@dataclass
class AnomalyScore:
    id: str
    score: float        # robust z-score of distance from centroid
    distance: float     # raw distance from centroid
    is_anomaly: bool
    #: "far", "near" (black-hole side) or "" when not an outlier by direction.
    direction: str = ""
    #: Raw L2 norm, and its robust z, when norm scoring was requested.
    norm: float | None = None
    norm_z: float | None = None
    norm_outlier: bool = False


def _robust_z(values: np.ndarray) -> np.ndarray:
    median = float(np.median(values))
    mad = float(np.median(np.abs(values - median)))
    scale = mad * _MAD_SCALE if mad > 0 else (float(values.std()) or 1.0)
    return (values - median) / scale


def _fit_and_score(
    ids: list[str],
    X: np.ndarray,
    *,
    z_threshold: float,
    metric: str,
    two_sided: bool = False,
    near_z: float | None = None,
    near_ratio: float = 0.5,
    score_norms: bool = False,
    norm_z: float | None = None,
    norm_ratio: float = 1.5,
) -> list[AnomalyScore]:
    """Core distance-to-centroid + robust-z scoring over a 2D float array."""
    raw_norms = np.linalg.norm(X, axis=1)
    if metric == "cosine":
        norms = raw_norms.copy()[:, None]
        norms[norms == 0] = 1.0
        Xn = X / norms
        centroid = Xn.mean(axis=0)
        c_norm = np.linalg.norm(centroid) or 1.0
        centroid = centroid / c_norm
        # cosine distance = 1 - cosine similarity
        dists = 1.0 - Xn @ centroid
    else:  # euclidean
        centroid = X.mean(axis=0)
        dists = np.linalg.norm(X - centroid, axis=1)

    median = float(np.median(dists))
    z = _robust_z(dists)
    near_limit = z_threshold if near_z is None else near_z

    nz = None
    norm_flags = np.zeros(len(ids), dtype=bool)
    if score_norms:
        nz = _robust_z(raw_norms)
        norm_median = float(np.median(raw_norms))
        n_thr = z_threshold if norm_z is None else norm_z
        norm_flags = (nz >= n_thr) & (raw_norms >= norm_ratio * norm_median)
        # Degenerate spread (every norm identical but a few): _robust_z fell
        # back to the standard deviation, which the outliers themselves
        # inflate. The ratio test above still guards precision.

    out: list[AnomalyScore] = []
    for i, _id in enumerate(ids):
        zi = float(z[i])
        far = zi >= z_threshold
        near = (two_sided and zi <= -near_limit
                and float(dists[i]) <= near_ratio * median)
        out.append(
            AnomalyScore(
                id=_id,
                score=round(zi, 4),
                distance=round(float(dists[i]), 6),
                is_anomaly=bool(far or near),
                direction="far" if far else "near" if near else "",
                norm=round(float(raw_norms[i]), 6) if score_norms else None,
                norm_z=round(float(nz[i]), 4) if nz is not None else None,
                norm_outlier=bool(norm_flags[i]),
            )
        )
    return out


def detect_anomalies(
    ids: list[str],
    embeddings: list[list[float]],
    *,
    z_threshold: float = 3.5,
    metric: str = "cosine",
    two_sided: bool = True,
    near_z: float | None = None,
    near_ratio: float = 0.5,
    score_norms: bool = False,
    norm_z: float | None = None,
    norm_ratio: float = 1.5,
) -> list[AnomalyScore]:
    """Score every vector. ``is_anomaly`` covers both far and (when
    ``two_sided``) black-hole-near outliers; ``norm_outlier`` is separate and
    only computed with ``score_norms`` (use it for inner-product stores)."""
    if not embeddings:
        return []

    X = np.asarray(embeddings, dtype=np.float64)
    if X.ndim != 2:
        raise ValueError("embeddings must be a 2D list")
    return _fit_and_score(ids, X, z_threshold=z_threshold, metric=metric,
                          two_sided=two_sided, near_z=near_z, near_ratio=near_ratio,
                          score_norms=score_norms, norm_z=norm_z, norm_ratio=norm_ratio)


@dataclass
class StreamingAnomalyResult:
    """Outcome of a streaming anomaly scan.

    ``scores`` are for the retained sample (which equals the full population when
    ``total_seen <= sample_size``). ``sampled`` is True when the population
    exceeded the reservoir and statistics were fit on a uniform random sample.
    """

    scores: list[AnomalyScore] = field(default_factory=list)
    total_seen: int = 0
    sample_size: int = 0
    sampled: bool = False


class StreamingAnomalyDetector:
    """Bounded-memory embedding-anomaly detector using reservoir sampling.

    Feed embeddings in batches with :meth:`add_batch`; the detector keeps at most
    ``sample_size`` raw vectors (Algorithm R, seeded for determinism) regardless
    of how many are streamed, then fits the centroid + robust-z model on that
    reservoir in :meth:`finalize`. Memory is O(sample_size x dim), not O(N x dim).

    When the total number of vectors is <= ``sample_size`` the reservoir holds
    every vector in arrival order, so the result is identical to
    :func:`detect_anomalies` — small/medium collections are unaffected; only
    very large ones are sampled.

    The retained sample is also exposed (:meth:`sample_matrix`) so the other
    vector detectors (micro-clusters, hubness) reuse it instead of holding a
    second copy of the embeddings.
    """

    def __init__(
        self,
        *,
        z_threshold: float = 3.5,
        metric: str = "cosine",
        sample_size: int = 50000,
        seed: int = 0,
        two_sided: bool = True,
        near_z: float | None = None,
        near_ratio: float = 0.5,
        score_norms: bool = False,
        norm_z: float | None = None,
        norm_ratio: float = 1.5,
    ):
        if sample_size < 1:
            raise ValueError("sample_size must be >= 1")
        self.z_threshold = z_threshold
        self.metric = metric
        self.sample_size = sample_size
        self.two_sided = two_sided
        self.near_z = near_z
        self.near_ratio = near_ratio
        self.score_norms = score_norms
        self.norm_z = norm_z
        self.norm_ratio = norm_ratio
        self._rng = np.random.default_rng(seed)
        self._ids: list[str] = []
        self._rows: list[np.ndarray] = []  # each a 1D float32 vector
        self._total = 0
        self._matrix: np.ndarray | None = None
        self._dim: int | None = None

    @property
    def total_seen(self) -> int:
        return self._total

    def add_batch(self, ids: Iterable[str], embeddings: Iterable[Iterable[float]]) -> None:
        ids = list(ids)
        if not ids:
            return
        X = np.asarray(list(embeddings), dtype=np.float32)
        if X.ndim != 2 or X.shape[0] != len(ids):
            raise ValueError("ids and embeddings must align as (n,) and (n, dim)")
        if self._dim is None:
            self._dim = X.shape[1]
        elif X.shape[1] != self._dim:
            raise ValueError("embedding dimension changed within the collection")
        self._matrix = None
        for i, _id in enumerate(ids):
            self._total += 1
            if len(self._rows) < self.sample_size:
                self._ids.append(_id)
                self._rows.append(X[i])
            else:
                # Algorithm R: replace an existing sample with prob k/total.
                j = int(self._rng.integers(0, self._total))
                if j < self.sample_size:
                    self._ids[j] = _id
                    self._rows[j] = X[i]

    def sample_ids(self) -> list[str]:
        return list(self._ids)

    def sample_matrix(self) -> np.ndarray:
        """The retained vectors as one float32 (n, dim) array.

        Stacked once; the per-row list is then re-pointed at views into it so
        the sample is not held twice.
        """
        if self._matrix is None:
            if not self._rows:
                return np.zeros((0, self._dim or 0), dtype=np.float32)
            self._matrix = np.vstack(self._rows).astype(np.float32, copy=False)
            self._rows = list(self._matrix)
        return self._matrix

    def finalize(self) -> StreamingAnomalyResult:
        if not self._rows:
            return StreamingAnomalyResult(
                scores=[], total_seen=self._total,
                sample_size=self.sample_size, sampled=False)
        X = self.sample_matrix().astype(np.float64)
        scores = _fit_and_score(self._ids, X, z_threshold=self.z_threshold,
                                metric=self.metric, two_sided=self.two_sided,
                                near_z=self.near_z, near_ratio=self.near_ratio,
                                score_norms=self.score_norms, norm_z=self.norm_z,
                                norm_ratio=self.norm_ratio)
        return StreamingAnomalyResult(
            scores=scores,
            total_seen=self._total,
            sample_size=self.sample_size,
            sampled=self._total > self.sample_size,
        )
