"""Bounds and thresholds for the integrity detectors, in one overridable place.

Every detector in :mod:`vecshield_platform.integrity` is report-only and must
stay bounded in memory and time on a large collection. The caps below are the
knobs; each can be overridden per run (pass an :class:`IntegrityLimits`) or per
deployment with an environment variable named ``VECSHIELD_INTEGRITY_<FIELD>``
(upper-cased), e.g. ``VECSHIELD_INTEGRITY_HUB_POOL_SIZE=5000``.

All sampling is seeded from :attr:`IntegrityLimits.seed`, so two runs over the
same data select the same sample and can be compared.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, fields, replace
from typing import Any, Mapping

_ENV_PREFIX = "VECSHIELD_INTEGRITY_"


@dataclass(frozen=True)
class IntegrityLimits:
    #: Seed for every sampler in the integrity pass (reservoir, hashing, probes).
    seed: int = 0
    #: Compact per-chunk records kept for duplication, versions and ingestion.
    #: Beyond this the metadata detectors report partial coverage.
    record_cap: int = 200_000

    # --- embedding anomaly (two-sided + norm) -------------------------------
    #: Robust z at or below ``-near_z`` marks a vector abnormally close to the
    #: centroid ("black-hole" vectors).
    near_z: float = 3.5
    #: ...and it must also sit within this fraction of the median distance, so
    #: a narrow but healthy distribution does not flag its own core.
    near_ratio: float = 0.5
    #: Robust z on raw norms for inner-product ("dot") collections.
    norm_z: float = 3.5
    #: ...and at least this multiple of the median norm.
    norm_ratio: float = 1.5

    # --- text duplication (MinHash) -----------------------------------------
    min_chunk_chars: int = 64
    max_text_chars: int = 20_000
    shingle_words: int = 5
    minhash_perms: int = 64
    minhash_bands: int = 16
    near_dup_jaccard: float = 0.8
    #: Signatures held (one uint32 row of ``minhash_perms`` per chunk).
    text_signature_cap: int = 100_000
    #: A text shared by at least this many distinct sources is boilerplate.
    boilerplate_min_sources: int = 5
    #: LSH buckets larger than this are verified against a few anchors only.
    lsh_bucket_cap: int = 64
    max_groups_reported: int = 20

    # --- embedding micro-clusters -------------------------------------------
    cluster_min_size: int = 3
    #: Pairwise-similarity quantile that defines "abnormally similar".
    cluster_quantile: float = 0.99
    #: The threshold is never below this cosine, whatever the quantile says.
    cluster_similarity_floor: float = 0.90
    cluster_threshold_sample: int = 2_000
    simhash_bands: int = 12
    simhash_bits_per_band: int = 16
    #: Upper bound on exact pairwise similarity evaluations for verification.
    cluster_max_pair_evaluations: int = 20_000_000
    #: A source is "rare" when it contributes at most this share of chunks
    #: (and never fewer than ``cluster_min_size`` chunks counts as rare).
    rare_source_fraction: float = 0.05
    #: Cluster members ingested within this many seconds are "one burst".
    cluster_time_window_seconds: float = 3600.0

    # --- hubness ------------------------------------------------------------
    hub_k: int = 10
    hub_pool_size: int = 10_000
    hub_probe_count: int = 1_000
    hub_z: float = 4.0
    #: N_k must also be at least this multiple of its expectation (k*P/n)...
    hub_factor: float = 5.0
    #: ...and appear for at least this many probes...
    hub_min_occurrences: int = 10
    #: ...but the bar never exceeds this share of probes (small collections).
    hub_max_share_bar: float = 0.5
    hub_block: int = 256
    #: Minimum breadth (0 = retrieved only by one topic's probes, 1 = by
    #: probes as spread out as random pairs) for a hub to be reported.
    hub_min_breadth: float = 0.5
    #: Candidates (by N_k) whose breadth is measured.
    hub_max_candidates: int = 50

    # --- ingestion bursts ---------------------------------------------------
    burst_z: float = 5.0
    burst_ratio: float = 5.0
    burst_min_chunks: int = 20
    burst_min_buckets: int = 5
    burst_max_buckets: int = 100_000

    # --- versions -----------------------------------------------------------
    #: Timestamp-valued version fields closer than this are one generation.
    generation_gap_seconds: float = 3600.0
    #: If more than this share of positioned sources collide on position, the
    #: position key is not unique per document and conflicts are not reported.
    position_collision_share: float = 0.3
    max_examples: int = 10

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None,
                 **overrides: Any) -> "IntegrityLimits":
        env = os.environ if environ is None else environ
        values: dict[str, Any] = {}
        for f in fields(cls):
            raw = env.get(_ENV_PREFIX + f.name.upper())
            if raw is None or raw.strip() == "":
                continue
            kind = type(getattr(cls, f.name))
            try:
                values[f.name] = kind(raw)
            except (TypeError, ValueError):
                raise ValueError(f"{_ENV_PREFIX}{f.name.upper()} must be {kind.__name__}")
        limits = replace(cls(), **values)
        return replace(limits, **overrides) if overrides else limits

    def __post_init__(self) -> None:
        positive = ("record_cap", "minhash_perms", "minhash_bands", "text_signature_cap",
                    "cluster_min_size", "cluster_threshold_sample", "simhash_bands",
                    "simhash_bits_per_band", "hub_k", "hub_pool_size", "hub_probe_count",
                    "hub_block", "burst_max_buckets", "shingle_words", "lsh_bucket_cap")
        for name in positive:
            if getattr(self, name) < 1:
                raise ValueError(f"{name} must be positive")
        if self.minhash_perms % self.minhash_bands:
            raise ValueError("minhash_perms must be a multiple of minhash_bands")
        if not 0.0 < self.cluster_quantile < 1.0:
            raise ValueError("cluster_quantile must be in (0, 1)")
        if self.simhash_bits_per_band > 62:
            raise ValueError("simhash_bits_per_band must be <= 62")
