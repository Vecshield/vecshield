"""Near-duplicate text and poison-cluster detection (check ``corpus_duplication``).

Two signals, both report-only:

**Text near-duplicates.** MinHash over word shingles with LSH banding finds
chunks whose text is (nearly) the same. Most duplication is benign, so the
detector removes the expected kinds before reporting anything:

- chunks shorter than ``min_chunk_chars`` are ignored (headings, stubs);
- text matching a caller-supplied allow-list pattern is ignored (templates);
- a text shared by ``boilerplate_min_sources`` or more distinct sources is
  boilerplate (headers, footers, disclaimers), not poison;
- repetition within one source document (overlapping chunk windows, repeated
  sections) is expected; it is reported only when the *same position* of the
  same document was stored twice (a duplicate ingestion).

What remains — the same text under a few different sources, or with no source
at all — is a LOW data-quality/minimisation observation. Duplicates that
include chunks the classifier marked sensitive (``sensitive_ids``) are
reported separately: every extra copy of personal data is one more to find at
erasure time. A :class:`SensitiveFingerprintRegistry` shared across collection
scans extends that to copies in *other* collections.

**Embedding micro-clusters.** Corpus-poisoning attacks plant several crafted
passages that are each highly similar to a target query and therefore to each
other (PoisonedRAG: Zou et al., USENIX Security 2025, arXiv 2402.07867;
TrustRAG, arXiv 2501.00879, filters exactly such abnormally dense groups).
Groups of at least ``cluster_min_size`` vectors whose pairwise cosine exceeds
both the collection's own ``cluster_quantile`` (p99 by default, estimated from
a seeded sample) and an absolute floor are found with random-hyperplane LSH on
centred vectors, verified with exact cosine. Density alone is common in real
corpora (one document, one topic), so a cluster is reported only with a
corroborating signal:

- MEDIUM when at least half of its members come from rare or unattributed
  sources (and rarity is informative in this collection), or at least half
  also carry a prompt-injection hit;
- LOW when it spans two or more distinct sources ingested within a narrow
  time window (coordinated insertion);
- otherwise it is counted in the stats and not reported. A "cluster" holding
  more than half of the collection is its bulk, not a micro-cluster, and is
  never reported.

Vectors are the embedding-anomaly reservoir: no second copy is held.
"""

from __future__ import annotations

import re
import threading
import zlib
from collections import Counter, defaultdict
from typing import Any, Iterable, Sequence

import numpy as np

from vecshield.models import Severity
from vecshield_platform.integrity.limits import IntegrityLimits
from vecshield_platform.integrity.records import (
    ChunkRecord,
    DetectorReport,
    ingest_time,
    make_finding,
    new_run_key,
    rare_threshold,
    rarity_informative,
    text_digest,
)

CHECK = "corpus_duplication"
_P = np.uint64((1 << 31) - 1)
_MASK32 = np.uint64(0xFFFFFFFF)
_SHINGLE_MUL = np.uint64(1_000_003)
_WORD_CACHE_CAP = 200_000


class _UnionFind:
    def __init__(self, n: int):
        self.parent = list(range(n))

    def find(self, x: int) -> int:
        parent = self.parent
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            # Smaller root wins, so components are labelled deterministically.
            if rb < ra:
                ra, rb = rb, ra
            self.parent[rb] = ra

    def groups(self) -> dict[int, list[int]]:
        out: dict[int, list[int]] = defaultdict(list)
        for i in range(len(self.parent)):
            out[self.find(i)].append(i)
        return out


class MinHasher:
    """Deterministic MinHash over word shingles (numpy, no dependencies)."""

    def __init__(self, *, perms: int, shingle_words: int, seed: int):
        rng = np.random.default_rng(seed)
        self.a = rng.integers(1, int(_P), size=perms, dtype=np.uint64)
        self.b = rng.integers(0, int(_P), size=perms, dtype=np.uint64)
        self.shingle_words = shingle_words
        self._cache: dict[str, int] = {}

    def _word_hashes(self, words: list[str]) -> np.ndarray:
        cache = self._cache
        if len(cache) > _WORD_CACHE_CAP:
            cache.clear()
        out = np.empty(len(words), dtype=np.uint64)
        for i, w in enumerate(words):
            h = cache.get(w)
            if h is None:
                h = zlib.crc32(w.encode("utf-8", "replace"))
                cache[w] = h
            out[i] = h
        return out

    def signature(self, normalized: str) -> np.ndarray | None:
        words = normalized.split(" ")
        if len(words) < 3:
            return None
        s = min(self.shingle_words, len(words))
        w = self._word_hashes(words)
        m = len(words) - s + 1
        h = w[:m].copy()
        for j in range(1, s):
            h = (h * _SHINGLE_MUL + w[j:j + m]) & _MASK32
        sig = ((self.a[:, None] * h[None, :] + self.b[:, None]) % _P).min(axis=1)
        return sig.astype(np.uint32)


class TextDuplicationCollector:
    """Streaming side of the text detector: one signature per eligible chunk."""

    def __init__(self, limits: IntegrityLimits, *,
                 allow_patterns: Sequence[str] = ()):
        self.limits = limits
        self.hasher = MinHasher(perms=limits.minhash_perms,
                                shingle_words=limits.shingle_words, seed=limits.seed)
        self.patterns = [re.compile(p, re.I) for p in allow_patterns]
        self.record_index: list[int] = []   # index into the engine's record list
        self.signatures: list[np.ndarray] = []
        self.too_short = 0
        self.allow_listed = 0
        self.capped = 0

    def add(self, record_index: int, normalized: str | None) -> None:
        if not normalized or len(normalized) < self.limits.min_chunk_chars:
            self.too_short += 1
            return
        if any(p.search(normalized) for p in self.patterns):
            self.allow_listed += 1
            return
        if len(self.signatures) >= self.limits.text_signature_cap:
            self.capped += 1
            return
        sig = self.hasher.signature(normalized)
        if sig is None:
            self.too_short += 1
            return
        self.record_index.append(record_index)
        self.signatures.append(sig)


class SensitiveFingerprintRegistry:
    """In-memory digests of sensitive chunk text, shared across collection scans.

    Holds keyed digests only (the key never leaves the process), so copies of
    the same sensitive text in different collections can be matched without
    retaining the text. Thread-safe for parallel per-collection scans.
    """

    def __init__(self) -> None:
        self.key = new_run_key()
        self._seen: dict[str, list[tuple[str, str]]] = {}
        self._lock = threading.Lock()

    def digest(self, normalized: str) -> str:
        return text_digest(normalized, self.key)

    def register(self, digest: str, collection: str, chunk_id: str) -> list[tuple[str, str]]:
        """Record a sensitive chunk; return prior (collection, id) copies elsewhere."""
        with self._lock:
            prior = [p for p in self._seen.get(digest, []) if p[0] != collection]
            bucket = self._seen.setdefault(digest, [])
            if len(bucket) < 50:
                bucket.append((collection, chunk_id))
            return prior


# --------------------------------------------------------------------------- #
# Text groups                                                                  #
# --------------------------------------------------------------------------- #

def _text_groups(collector: TextDuplicationCollector,
                 records: list[ChunkRecord]) -> tuple[list[list[int]], dict[str, Any]]:
    """Groups (record indices) of exact or near-duplicate text."""
    limits = collector.limits
    # Collapse exact duplicates first: one representative signature per text.
    rep_of_hash: dict[str, int] = {}
    members: list[list[int]] = []
    rep_sigs: list[np.ndarray] = []
    for pos, ridx in enumerate(collector.record_index):
        key = records[ridx].text_hash or f"#{ridx}"
        rep = rep_of_hash.get(key)
        if rep is None:
            rep_of_hash[key] = len(members)
            members.append([ridx])
            rep_sigs.append(collector.signatures[pos])
        else:
            members[rep].append(ridx)
    n = len(members)
    uf = _UnionFind(n)
    comparisons = 0
    if n > 1:
        sigs = np.vstack(rep_sigs)
        rows = limits.minhash_perms // limits.minhash_bands
        for band in range(limits.minhash_bands):
            buckets: dict[bytes, list[int]] = defaultdict(list)
            block = np.ascontiguousarray(sigs[:, band * rows:(band + 1) * rows])
            for i in range(n):
                buckets[block[i].tobytes()].append(i)
            for bucket in buckets.values():
                if len(bucket) < 2:
                    continue
                anchors = bucket if len(bucket) <= limits.lsh_bucket_cap else bucket[:4]
                for ai, a in enumerate(anchors):
                    rest = bucket[ai + 1:] if len(bucket) <= limits.lsh_bucket_cap else bucket
                    rest = [b for b in rest if b != a]
                    if not rest:
                        continue
                    comparisons += len(rest)
                    agree = (sigs[rest] == sigs[a]).mean(axis=1)
                    for b, j in zip(rest, agree):
                        if j >= limits.near_dup_jaccard:
                            uf.union(a, b)
    groups: list[list[int]] = []
    for reps in uf.groups().values():
        idxs = sorted(i for r in reps for i in members[r])
        if len(idxs) >= 2:
            groups.append(idxs)
    groups.sort(key=lambda g: (-len(g), g[0]))
    exact = sum(1 for m in members if len(m) >= 2)
    return groups, {"distinct_texts": n, "exact_duplicate_texts": exact,
                    "lsh_comparisons": comparisons}


def _classify_text_group(group: list[int], records: list[ChunkRecord],
                         limits: IntegrityLimits) -> str:
    recs = [records[i] for i in group]
    sources = {r.source for r in recs if r.source}
    unattributed = any(r.source is None for r in recs)
    if len(sources) >= limits.boilerplate_min_sources:
        return "boilerplate"
    if len(sources) >= 2:
        return "cross_source"
    if unattributed and not sources:
        return "unattributed"
    if unattributed:
        return "cross_source"
    # One source. The same position stored twice is a duplicate ingestion;
    # anything else is repetition inside one document, which is expected.
    positions = [r.position for r in recs if r.position is not None]
    if positions and len(positions) != len(set(positions)):
        return "duplicate_ingestion"
    return "intra_document"


# --------------------------------------------------------------------------- #
# Embedding micro-clusters                                                     #
# --------------------------------------------------------------------------- #

def find_embedding_clusters(X: np.ndarray, limits: IntegrityLimits
                            ) -> tuple[list[list[int]], dict[str, Any], str]:
    """Components (row indices) of abnormally similar vectors.

    Returns (clusters, stats, limitation). Cosine geometry: clusters are about
    direction; norm manipulation is the anomaly detector's concern.
    """
    n = X.shape[0] if X.ndim == 2 else 0
    k = limits.cluster_min_size
    if n < max(10, k):
        return [], {"vectors": n}, "Fewer than 10 vectors; clusters were not assessed."
    rng = np.random.default_rng(limits.seed)
    with np.errstate(all="ignore"):
        norms = np.linalg.norm(X, axis=1)
        norms[~np.isfinite(norms) | (norms == 0)] = 1.0
        inv = (1.0 / norms).astype(np.float32)

        m = min(n, limits.cluster_threshold_sample)
        sidx = np.sort(rng.choice(n, m, replace=False)) if m < n else np.arange(n)
        S = X[sidx] * inv[sidx, None]
        G = S @ S.T
        vals = G[np.triu_indices(m, 1)]
        vals = vals[np.isfinite(vals)]
        q = float(np.quantile(vals, limits.cluster_quantile)) if vals.size else 1.0
        threshold = max(q, limits.cluster_similarity_floor)
        cut = threshold - 1e-5

        bands, bpb = limits.simhash_bands, limits.simhash_bits_per_band
        R = rng.standard_normal((X.shape[1], bands * bpb)).astype(np.float32)
        mu = (X.T @ inv) / n
        P = (X @ R) * inv[:, None] - (mu @ R)[None, :]
        bits = (P > 0)
        del P
        weights = (1 << np.arange(bpb, dtype=np.int64))

        uf = _UnionFind(n)
        evaluations = 0
        limitation = ""
        for band in range(bands):
            keys = bits[:, band * bpb:(band + 1) * bpb].astype(np.int64) @ weights
            order = np.argsort(keys, kind="stable")
            sk = keys[order]
            starts = np.flatnonzero(np.r_[True, sk[1:] != sk[:-1]])
            ends = np.r_[starts[1:], n]
            for s, e in zip(starts, ends):
                size = int(e - s)
                if size < 2:
                    continue
                idx = order[s:e]
                V = X[idx] * inv[idx, None]
                if size <= limits.lsh_bucket_cap:
                    sims = V @ V.T
                    evaluations += size * size
                    ii, jj = np.nonzero(np.triu(sims >= cut, 1))
                else:
                    sims = V[:8] @ V.T
                    evaluations += 8 * size
                    ii, jj = np.nonzero(sims >= cut)
                for a, b in zip(ii.tolist(), jj.tolist()):
                    if a != b:
                        uf.union(int(idx[a]), int(idx[b]))
                if evaluations > limits.cluster_max_pair_evaluations:
                    limitation = ("The similarity budget was reached before every "
                                  "candidate group was verified.")
                    break
            if limitation:
                break
    clusters = [sorted(g) for g in uf.groups().values() if len(g) >= k]
    clusters.sort(key=lambda g: (-len(g), g[0]))
    stats = {"vectors": n, "similarity_threshold": round(threshold, 4),
             "pairwise_quantile": limits.cluster_quantile,
             "pairwise_quantile_value": round(q, 4),
             "threshold_sample": int(m), "pair_evaluations": int(evaluations),
             "tight_clusters": len(clusters)}
    return clusters, stats, limitation


def _mean_pairwise(V: np.ndarray, cap: int = 500) -> float:
    if V.shape[0] > cap:
        V = V[:cap]
    with np.errstate(all="ignore"):
        norms = np.linalg.norm(V, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        Vn = V / norms
        G = Vn @ Vn.T
    iu = np.triu_indices(G.shape[0], 1)
    return float(G[iu].mean()) if iu[0].size else 1.0


# --------------------------------------------------------------------------- #
# The check                                                                    #
# --------------------------------------------------------------------------- #

def analyze_duplication(
    *,
    store: str,
    collection: str,
    records: list[ChunkRecord],
    collector: TextDuplicationCollector,
    vector_ids: Sequence[str],
    vectors: np.ndarray,
    vectors_sampled: bool,
    limits: IntegrityLimits,
    time_field: str | None,
    sensitive_ids: Iterable[str] | None = None,
    injection_ids: Iterable[str] = (),
    cross_collection: dict[str, list[tuple[str, str]]] | None = None,
) -> DetectorReport:
    report = DetectorReport(check=CHECK)
    sensitive = set(sensitive_ids or ())
    injected = set(injection_ids)
    source_counts = Counter(r.source for r in records if r.source)
    total = len(records)

    # --- text -----------------------------------------------------------
    groups, text_stats = _text_groups(collector, records)
    by_kind: dict[str, list[list[int]]] = defaultdict(list)
    for g in groups:
        by_kind[_classify_text_group(g, records, limits)].append(g)
    reportable = (by_kind["cross_source"] + by_kind["duplicate_ingestion"]
                  + by_kind["unattributed"])
    reportable.sort(key=lambda g: (-len(g), g[0]))
    if reportable:
        examples = []
        for g in reportable[:limits.max_groups_reported]:
            recs = [records[i] for i in g]
            examples.append({
                "chunk_id": recs[0].id,
                "chunk_ids": [r.id for r in recs[:limits.max_examples]],
                "size": len(g),
                "kind": _classify_text_group(g, records, limits),
                "distinct_sources": len({r.source for r in recs if r.source}),
                "exact": len({r.text_hash for r in recs}) == 1,
            })
        chunks = sum(len(g) for g in reportable)
        report.findings.append(make_finding(
            title=f"Duplicated chunk text in '{collection}'",
            severity=Severity.LOW, category=CHECK, store=store, collection=collection,
            description=(
                f"{len(reportable)} group(s) covering {chunks} chunks hold the same or "
                "nearly the same text under different sources, without a source, or "
                "as a second copy of the same document position. Duplicates skew "
                "retrieval toward whichever copy wins and multiply the places a "
                "correction or erasure must reach. Boilerplate repeated across "
                f"{limits.boilerplate_min_sources}+ sources and repetition within one "
                "document were excluded."),
            evidence={"groups": len(reportable), "chunks": chunks,
                      "near_duplicate_jaccard": limits.near_dup_jaccard,
                      "excluded": {"boilerplate_groups": len(by_kind["boilerplate"]),
                                   "intra_document_groups": len(by_kind["intra_document"]),
                                   "short_chunks": collector.too_short,
                                   "allow_listed_chunks": collector.allow_listed},
                      "examples": examples},
            remediation=(
                "Deduplicate at ingestion (content hash per document position) and "
                "delete the stale copy. If the copies are intentional templates, add "
                "them to the boilerplate allow-list.")))
        report.detected = True

    # --- sensitive copies -----------------------------------------------
    sensitive_groups = [g for g in groups
                        if sum(records[i].id in sensitive for i in g) >= 1]
    cross = {cid: copies for cid, copies in (cross_collection or {}).items() if copies}
    if sensitive_groups or cross:
        examples = [{"chunk_id": records[g[0]].id,
                     "chunk_ids": [records[i].id for i in g[:limits.max_examples]],
                     "copies": len(g),
                     "sensitive_copies": sum(records[i].id in sensitive for i in g)}
                    for g in sensitive_groups[:limits.max_groups_reported]]
        for cid, copies in sorted(cross.items())[:limits.max_groups_reported]:
            examples.append({"chunk_id": cid, "other_collections":
                             sorted({c for c, _ in copies}),
                             "copies": len(copies) + 1})
        report.findings.append(make_finding(
            title=f"Sensitive content stored more than once in '{collection}'",
            severity=Severity.LOW, category=CHECK, store=store, collection=collection,
            description=(
                f"{len(sensitive_groups)} duplicate group(s) here, and {len(cross)} "
                "chunk(s) with a copy in another collection, contain content the "
                "classification pass marked sensitive. Each copy is another place the "
                "data must be found, protected and erased (data minimisation)."),
            evidence={"groups": len(sensitive_groups), "cross_collection": len(cross),
                      "examples": examples},
            remediation=(
                "Keep one authoritative copy of sensitive content; remove or redact "
                "the others and deduplicate at ingestion.")))
        report.detected = True

    # --- embedding micro-clusters ---------------------------------------
    clusters, cluster_stats, limitation = find_embedding_clusters(vectors, limits)
    rare_thr = rare_threshold(total, limits.rare_source_fraction, limits.cluster_min_size,
                              source_counts)
    # When most chunks come from small sources (tickets, emails), "rare" says
    # nothing about a cluster; the rarity signal is then switched off.
    rarity_ok = rarity_informative(records, rare_thr, source_counts)
    index = {r.id: r for r in records}
    suspicious: list[dict[str, Any]] = []
    coordinated: list[dict[str, Any]] = []
    benign = 0
    for cl in clusters:
        ids = [str(vector_ids[i]) for i in cl]
        recs = [index.get(i) for i in ids]
        srcs = [r.source if r else None for r in recs]
        distinct = {s for s in srcs if s}
        rare_members = sum(1 for s in srcs if s is None or source_counts[s] <= rare_thr)
        rare_share = rare_members / len(cl)
        times = [ingest_time(r, time_field) for r in recs if r is not None]
        times = [t for t in times if t is not None]
        window = (max(times) - min(times)) if len(times) == len(cl) and times else None
        narrow = window is not None and window <= limits.cluster_time_window_seconds
        overlap = sorted(set(ids) & injected)
        entry = {
            "chunk_id": ids[0],
            "chunk_ids": ids[:limits.max_examples],
            "size": len(cl),
            "mean_similarity": round(_mean_pairwise(vectors[cl]), 4),
            "distinct_sources": len(distinct),
            "sources": sorted(distinct)[:5],
            "rare_or_unattributed_share": round(rare_share, 3),
            "ingest_window_seconds": round(window, 1) if window is not None else None,
            "also_injection": overlap[:5],
        }
        if len(cl) > 0.5 * vectors.shape[0]:
            # Most of the collection: its bulk, not a planted micro-cluster.
            benign += 1
        elif len(overlap) >= 0.5 * len(cl) or (rarity_ok and rare_share >= 0.5):
            suspicious.append(entry)
            report.flagged_ids.update(ids)
        elif len(distinct) >= 2 and narrow and len(distinct) < limits.boilerplate_min_sources:
            coordinated.append(entry)
            report.flagged_ids.update(ids)
        else:
            benign += 1
    basis = (" Vectors were a random sample of the collection, so a cluster outside "
             "the sample would not be seen." if vectors_sampled else "")
    common_ev = {"similarity_threshold": cluster_stats.get("similarity_threshold"),
                 "pairwise_quantile": limits.cluster_quantile,
                 "sampled": vectors_sampled,
                 "method": ("Random-hyperplane LSH on centred vectors; candidate pairs "
                            "verified with exact cosine."),
                 "references": ["PoisonedRAG (Zou et al., USENIX Security 2025)",
                                "TrustRAG (arXiv 2501.00879)"]}
    if suspicious:
        report.findings.append(make_finding(
            title=f"Tightly clustered chunks with poisoning signals in '{collection}'",
            severity=Severity.MEDIUM, category=CHECK, store=store, collection=collection,
            description=(
                f"{len(suspicious)} group(s) of {limits.cluster_min_size}+ chunks are "
                "more similar to each other than almost any other pair in the "
                "collection (above its p99 pairwise similarity) and come mostly from "
                "rare or unattributed sources, or are mostly prompt-injection hits. "
                "Corpus-poisoning attacks plant exactly such groups so several "
                "crafted passages win retrieval for a target question." + basis),
            evidence={**common_ev, "count": len(suspicious),
                      "rare_source_threshold_chunks": rare_thr,
                      "examples": suspicious[:limits.max_groups_reported]},
            remediation=(
                "Review the clustered chunks and their sources. If the source is not "
                "an expected, authorised publisher, quarantine the chunks and trace "
                "how they were ingested.")))
        report.detected = True
    if coordinated:
        report.findings.append(make_finding(
            title=f"Near-identical chunks from several sources ingested together "
                  f"in '{collection}'",
            severity=Severity.LOW, category=CHECK, store=store, collection=collection,
            description=(
                f"{len(coordinated)} group(s) of abnormally similar chunks span "
                "several distinct sources yet were ingested within "
                f"{int(limits.cluster_time_window_seconds)} seconds of each other. "
                "This can be a legitimate batch import; it is also what a coordinated "
                "insertion looks like." + basis),
            evidence={**common_ev, "count": len(coordinated),
                      "examples": coordinated[:limits.max_groups_reported]},
            remediation="Confirm the batch and its sources were expected."))
        report.detected = True

    report.stats = {
        **text_stats,
        "text_groups": len(groups),
        "text_groups_by_kind": {k: len(v) for k, v in sorted(by_kind.items())},
        "short_chunks": collector.too_short,
        "allow_listed_chunks": collector.allow_listed,
        "signatures_capped": collector.capped,
        **{f"cluster_{k}": v for k, v in cluster_stats.items()},
        "suspicious_clusters": len(suspicious),
        "coordinated_clusters": len(coordinated),
        "benign_tight_clusters": benign,
        "source_rarity_informative": rarity_ok,
    }
    limits_hit = []
    if collector.capped:
        limits_hit.append(f"{collector.capped} chunks exceeded the text signature cap "
                          "and were not compared.")
    if vectors_sampled:
        limits_hit.append("Only a sample of the embeddings was clustered.")
    if limitation:
        limits_hit.append(limitation)
    report.limitation = " ".join(limits_hit)
    report.coverage = {"text_chunks_compared": len(collector.signatures),
                       "vectors_clustered": int(vectors.shape[0]) if vectors.ndim == 2 else 0}
    return report
