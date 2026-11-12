"""Retrieval hubness (check ``retrieval_hubness``).

A *hub* is a vector that appears in the top-k neighbours of an unusually
large share of queries. High-dimensional embedding spaces produce some hubs
naturally, and adversarial hubs are a known way to make one planted chunk
surface for many unrelated questions (Zhang et al., arXiv 2412.14113;
HubScan, Habler et al., arXiv 2602.22427).

Method (HubScan-style k-occurrence): a seeded sample of stored vectors is used
as proxy queries against a pool of stored vectors (the whole collection when
it fits within ``hub_pool_size``). For each pool item, N_k counts the probes
whose top-k (metric-aware: cosine, inner product or Euclidean) contains it.
Exact-duplicate vectors are collapsed first, so a repeated template does not
turn its lowest-index copy into an artificial hub.

A pool item is a hub only when **all** of these hold (precision first):

- robust z of N_k (median/MAD) >= ``hub_z``;
- N_k >= ``hub_factor`` x its expectation k*P/n (capped at
  ``hub_max_share_bar`` of probes so small collections remain assessable);
- N_k >= ``hub_min_occurrences``.

A hub must also be **broad**: the probes that retrieve it must be spread
across the collection rather than drawn from one topic. The medoid of a tight
topic is retrieved by every probe in that topic, which is a local hub and
entirely benign. Breadth = (local - spread) / (local - global), where
*spread* is the mean cosine among the hub's retrieving probes, *local* the
mean cosine between probes and their own top-k, and *global* the mean cosine
of random probe pairs; a hub is broad when breadth >= ``hub_min_breadth``.
Local hubs are counted in the stats, not reported. (Planted passages that
target one topic are the micro-cluster detector's concern.)

Severity: INFO for empty or very short chunks (natural hubs: an empty string
embeds near the centre of everything); LOW for other hubs; MEDIUM when the hub
is corroborated by a rare/unattributed source, a prompt-injection hit, or an
embedding-anomaly flag.

**Caveat:** stored documents are an asymmetric stand-in for real user queries
(different length and phrasing). A hub under document probes is a lead to
review, not proof that it wins real retrieval.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Iterable, Sequence

import numpy as np

from vecshield.models import Severity
from vecshield_platform.integrity.limits import IntegrityLimits
from vecshield_platform.integrity.records import (
    ChunkRecord,
    DetectorReport,
    make_finding,
    rare_threshold,
    rarity_informative,
)

CHECK = "retrieval_hubness"
_MAD_SCALE = 1.4826
CAVEAT = ("Stored chunks were used as proxy queries. Documents differ from real "
          "questions in length and phrasing, so a hub here is a lead to review, not "
          "proof that it wins live retrieval.")


def k_occurrence(X: np.ndarray, *, metric: str, k: int, pool_size: int,
                 probe_count: int, seed: int, block: int = 256
                 ) -> tuple[np.ndarray, np.ndarray, np.ndarray, dict[str, Any]]:
    """N_k over a pool of unique vectors.

    Returns (pool_rows, pool_group_sizes, n_k, stats). ``pool_rows`` index X
    (one representative per exact-duplicate group, in first-seen order).
    ``stats["top"]`` holds each probe's top-k pool indices and
    ``stats["probe_index"]`` the probes' pool indices.
    """
    n = X.shape[0]
    rng = np.random.default_rng(seed)
    # Pool: all rows when they fit, else a seeded sample (sorted for stability).
    rows = np.arange(n) if n <= pool_size else np.sort(rng.choice(n, pool_size, replace=False))
    # Collapse exact duplicates.
    first: dict[bytes, int] = {}
    group_of = np.empty(len(rows), dtype=np.int64)
    reps: list[int] = []
    for j, r in enumerate(rows):
        key = X[r].tobytes()
        g = first.get(key)
        if g is None:
            g = len(reps)
            first[key] = g
            reps.append(int(r))
        group_of[j] = g
    reps_arr = np.asarray(reps, dtype=np.int64)
    sizes = np.bincount(group_of, minlength=len(reps)).astype(np.int64)
    u = len(reps)
    kk = min(k, u - 1)
    stats: dict[str, Any] = {"pool": int(len(rows)), "unique_pool": int(u), "k": int(kk)}
    counts = np.zeros(u, dtype=np.int64)
    if kk < 1:
        stats.update(probes=0, top=np.zeros((0, 0), dtype=np.int64),
                     probe_index=np.zeros(0, dtype=np.int64))
        return reps_arr, sizes, counts, stats
    probes = np.arange(u) if u <= probe_count else np.sort(
        rng.choice(u, probe_count, replace=False))
    stats["probes"] = int(len(probes))

    with np.errstate(all="ignore"):
        pool = X[reps_arr].astype(np.float32, copy=False)
        if metric == "cosine":
            nrm = np.linalg.norm(pool, axis=1)
            nrm[~np.isfinite(nrm) | (nrm == 0)] = 1.0
            pool = pool / nrm[:, None]
            sq = None
        elif metric == "euclidean":
            sq = (pool.astype(np.float64) ** 2).sum(axis=1)
        else:  # dot
            sq = None
        tops: list[np.ndarray] = []
        for start in range(0, len(probes), block):
            pb = probes[start:start + block]
            Q = pool[pb]
            S = (Q @ pool.T).astype(np.float64)
            if metric == "euclidean":
                S = 2.0 * S - sq[None, :]  # -(|p|^2 - 2q.p) ranks as -||q-p||^2
            S[~np.isfinite(S)] = -np.inf
            S[np.arange(len(pb)), pb] = -np.inf  # a probe is not its own neighbour
            # Stable sort: equal scores break toward the lower pool index, so
            # reruns agree exactly.
            top = np.argsort(-S, axis=1, kind="stable")[:, :kk]
            counts += np.bincount(top.ravel(), minlength=u)
            tops.append(top)
    stats["top"] = np.vstack(tops) if tops else np.zeros((0, kk), dtype=np.int64)
    stats["probe_index"] = probes
    return reps_arr, sizes, counts, stats


def _breadth(V: np.ndarray, top: np.ndarray, probe_index: np.ndarray,
             candidates: list[int], seed: int, cap: int = 64) -> dict[int, float]:
    """Breadth of each candidate hub's retrieving probes (see module doc)."""
    rng = np.random.default_rng(seed + 1)
    with np.errstate(all="ignore"):
        nrm = np.linalg.norm(V, axis=1)
        nrm[~np.isfinite(nrm) | (nrm == 0)] = 1.0

        def unit(rows):
            return V[rows] / nrm[rows, None]

        P = len(probe_index)
        a = rng.integers(0, P, 2000)
        b = rng.integers(0, P, 2000)
        keep = a != b
        pa, pb = probe_index[a[keep]], probe_index[b[keep]]
        global_mean = float(np.mean(np.sum(unit(pa) * unit(pb), axis=1))) if keep.any() else 0.0
        sample = rng.choice(P, min(P, 500), replace=False)
        local = float(np.mean(np.sum(unit(np.repeat(probe_index[sample], top.shape[1]))
                                     * unit(top[sample].ravel()), axis=1)))
        out: dict[int, float] = {}
        for h in candidates:
            rows = np.flatnonzero((top == h).any(axis=1))
            if len(rows) > cap:
                rows = np.sort(rng.choice(rows, cap, replace=False))
            U = unit(probe_index[rows])
            G = U @ U.T
            iu = np.triu_indices(len(rows), 1)
            spread = float(G[iu].mean()) if iu[0].size else local
            denom = local - global_mean
            out[h] = float((local - spread) / denom) if denom > 1e-6 else 1.0
    return out


def analyze_hubness(
    *,
    store: str,
    collection: str,
    vector_ids: Sequence[str],
    vectors: np.ndarray,
    vectors_sampled: bool,
    metric: str | None,
    records: list[ChunkRecord],
    limits: IntegrityLimits,
    injection_ids: Iterable[str] = (),
    anomaly_ids: Iterable[str] = (),
) -> DetectorReport:
    report = DetectorReport(check=CHECK)
    n = vectors.shape[0] if vectors.ndim == 2 else 0
    notes = []
    geometry = {"cosine": "cosine", "dot": "dot", "euclidean": "euclidean"}.get(metric or "")
    if geometry is None:
        geometry = "cosine" if metric in (None, "") else "euclidean"
        notes.append(
            "The store did not report its distance metric; cosine was assumed."
            if metric in (None, "") else
            f"The store's '{metric}' metric was approximated with Euclidean distance.")
    if n < 10:
        report.limitation = "At least 10 vectors are required for hubness analysis."
        report.coverage = {"vectors": n}
        report.note = " ".join(notes)
        return report

    reps, sizes, counts, stats = k_occurrence(
        vectors, metric=geometry, k=limits.hub_k, pool_size=limits.hub_pool_size,
        probe_count=limits.hub_probe_count, seed=limits.seed, block=limits.hub_block)
    probes, kk, u = stats["probes"], stats["k"], stats["unique_pool"]
    hubs: list[dict[str, Any]] = []
    if probes and kk:
        c = counts.astype(np.float64)
        median = float(np.median(c))
        mad = float(np.median(np.abs(c - median)))
        scale = mad * _MAD_SCALE if mad > 0 else max(float(c.std()), 1.0)
        z = (c - median) / scale
        expected = kk * probes / u
        bar = max(float(limits.hub_min_occurrences),
                  min(limits.hub_factor * expected, limits.hub_max_share_bar * probes))
        stats.update({"expected_occurrence": round(expected, 3),
                      "occurrence_bar": round(bar, 2), "median_occurrence": median})
        hub_idx = np.flatnonzero((z >= limits.hub_z) & (c >= bar))
        hub_idx = hub_idx[np.argsort(-c[hub_idx], kind="stable")][:limits.hub_max_candidates]
        breadth = _breadth(vectors[reps], stats["top"], stats["probe_index"],
                           [int(h) for h in hub_idx], limits.seed)
        local_hubs = [int(h) for h in hub_idx if breadth[int(h)] < limits.hub_min_breadth]
        hub_idx = [int(h) for h in hub_idx if breadth[int(h)] >= limits.hub_min_breadth]
        stats["local_hubs"] = len(local_hubs)
        index = {r.id: r for r in records}
        source_counts = Counter(r.source for r in records if r.source)
        rare_thr = rare_threshold(len(records), limits.rare_source_fraction,
                                  limits.cluster_min_size, source_counts)
        rarity_ok = rarity_informative(records, rare_thr, source_counts)
        stats["source_rarity_informative"] = rarity_ok
        injected, anomalous = set(injection_ids), set(anomaly_ids)
        for h in hub_idx:
            cid = str(vector_ids[int(reps[h])])
            rec = index.get(cid)
            short = rec is None or rec.text_len < limits.min_chunk_chars
            rare = rarity_ok and rec is not None and (
                rec.source is None or source_counts[rec.source] <= rare_thr)
            signals = [s for s, on in (("rare_or_unattributed_source", rare),
                                       ("prompt_injection", cid in injected),
                                       ("embedding_anomaly", cid in anomalous)) if on]
            hubs.append({
                "chunk_id": cid,
                "n_k": int(counts[h]),
                "probe_share": round(float(counts[h]) / probes, 4),
                "z": round(float(z[h]), 2),
                "breadth": round(breadth[h], 3),
                "duplicate_copies": int(sizes[h]),
                "source": rec.source if rec else None,
                "text_chars": rec.text_len if rec else 0,
                "low_content": short,
                "signals": signals,
            })
    corroborated = [h for h in hubs if h["signals"] and not h["low_content"]]
    plain = [h for h in hubs if not h["signals"] and not h["low_content"]]
    natural = [h for h in hubs if h["low_content"]]
    # A low-content hub that is also corroborated is still reported with the
    # corroborated group: the corroboration is the reason to look.
    corroborated += [h for h in natural if h["signals"]]
    natural = [h for h in natural if not h["signals"]]
    base_ev = {"k": kk, "probes": probes, "pool": stats["pool"], "metric": geometry,
               "hub_z": limits.hub_z, "occurrence_bar": stats.get("occurrence_bar"),
               "sampled": vectors_sampled or stats["pool"] < n, "caveat": CAVEAT,
               "references": ["HubScan (arXiv 2602.22427)", "Zhang et al. (arXiv 2412.14113)"]}
    for group, severity, title, desc in (
        (corroborated, Severity.MEDIUM,
         f"Retrieval hubs with corroborating signals in '{collection}'",
         "appear in the top-{k} neighbours of far more stored chunks than expected "
         "and also come from a rare or unattributed source, carry a prompt-injection "
         "hit, or are embedding outliers. A planted hub surfaces for many unrelated "
         "questions."),
        (plain, Severity.LOW, f"Retrieval hubs in '{collection}'",
         "appear in the top-{k} neighbours of far more stored chunks than expected. "
         "Some hubness is natural in high-dimensional spaces; review what these "
         "chunks say, since they reach many answers."),
        (natural, Severity.INFO, f"Low-content chunks acting as retrieval hubs in "
                                 f"'{collection}'",
         "are empty or very short and appear in the top-{k} neighbours of many "
         "stored chunks. Near-empty text embeds close to everything; these crowd out "
         "useful context rather than indicate an attack."),
    ):
        if not group:
            continue
        report.findings.append(make_finding(
            title=title, severity=severity, category=CHECK, store=store,
            collection=collection,
            description=f"{len(group)} chunk(s) " + desc.format(k=kk) + " " + CAVEAT,
            evidence={**base_ev, "count": len(group),
                      "examples": group[:limits.max_examples]},
            remediation=(
                "Review the hub chunks. Remove or re-chunk empty and boilerplate "
                "chunks; quarantine hubs from unexpected sources; consider a "
                "retrieval-time diversity or hub-penalty filter.")))
        if severity != Severity.INFO:
            report.flagged_ids.update(h["chunk_id"] for h in group)
    report.detected = bool(corroborated or plain)
    limits_hit = []
    if vectors_sampled:
        limits_hit.append("Only a sample of the embeddings was available to the pool.")
    if stats["pool"] < n:
        limits_hit.append(f"The neighbour pool was capped at {stats['pool']:,} of "
                          f"{n:,} vectors.")
    report.limitation = " ".join(limits_hit)
    report.note = " ".join(notes + [CAVEAT])
    stats.pop("top", None)
    stats.pop("probe_index", None)
    report.stats = {**stats, "hubs": len(hubs), "corroborated_hubs": len(corroborated),
                    "low_content_hubs": len(natural), "metric": geometry}
    report.coverage = {"vectors": n, "pool": stats["pool"], "probes": probes,
                       "metric": geometry}
    return report
