"""Near-duplicate text and poison micro-cluster detection (corpus_duplication)."""

from __future__ import annotations

import numpy as np

from vecshield.models import Chunk, Collection, Severity, VectorStore
from vecshield_platform.connectors.base import Connector
from vecshield_platform.integrity import (
    IntegrityLimits,
    MinHasher,
    SensitiveFingerprintRegistry,
    find_embedding_clusters,
    scan_integrity,
)
from vecshield_platform.integrity.records import normalize_text

WORDS = ("alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima mike "
         "november oscar papa quebec romeo sierra tango uniform victor whiskey xray yankee "
         "zulu amber basalt cobalt dune ember fjord granite harbor island jasper").split()


class Mem(Connector):
    kind = "memory"

    def __init__(self, data, metric="cosine"):
        self.data = data
        self.metric = metric

    def describe(self):
        return VectorStore(kind="memory", name="memory", endpoint="memory://",
                           collections=self.list_collections())

    def list_collections(self):
        return [Collection(name=n, count=len(c), distance_metric=self.metric)
                for n, c in self.data.items()]

    def iter_chunks(self, collection, batch_size=256):
        yield from self.data[collection]


def _text(i: int, n: int = 30) -> str:
    rng = np.random.default_rng(10_000 + i)
    return " ".join(rng.choice(WORDS, size=n))


def _corpus(n_sources=20, per_source=10, dim=64, seed=0, collection="docs"):
    rng = np.random.default_rng(seed)
    chunks = []
    for s in range(n_sources):
        for j in range(per_source):
            i = s * per_source + j
            chunks.append(Chunk(id=f"c{i}", collection=collection, text=_text(i),
                                embedding=rng.normal(0, 1, dim).tolist(),
                                metadata={"source": f"doc-{s}.pdf", "chunk_index": j}))
    return chunks


def _dup_findings(job):
    return [f for f in job.findings if f.category == "corpus_duplication"]


def _outcome(job, check="corpus_duplication"):
    return next(o for o in job.stats["check_outcomes"] if o["check"] == check)


def test_minhash_near_duplicates_and_unrelated():
    h = MinHasher(perms=64, shingle_words=5, seed=0)
    a = normalize_text(_text(1, 60), 20_000)
    b = a.replace(a.split(" ")[30], "zzzz", 1)
    c = normalize_text(_text(2, 60), 20_000)
    sa, sb, sc = h.signature(a), h.signature(b), h.signature(c)
    assert (sa == sb).mean() >= 0.7
    assert (sa == sc).mean() < 0.2
    assert h.signature("too short") is None


def test_clean_corpus_has_no_duplication_findings():
    job = scan_integrity(Mem({"docs": _corpus()}), "docs")
    assert not _dup_findings(job)
    assert _outcome(job)["outcome"] == "passed"
    assert _outcome(job)["coverage"]["complete"] is True


def test_planted_cluster_from_rare_source_is_medium():
    chunks = _corpus()
    rng = np.random.default_rng(99)
    target = rng.normal(0, 1, 64)
    for j in range(5):
        chunks.append(Chunk(
            id=f"poison-{j}", collection="docs", text=_text(900 + j),
            embedding=(target + rng.normal(0, 0.05, 64)).tolist(),
            metadata={"source": f"upload-{j}.txt"}))
    job = scan_integrity(Mem({"docs": chunks}), "docs")
    f = next(f for f in _dup_findings(job) if "poisoning signals" in f.title)
    assert f.severity == Severity.MEDIUM
    ids = set(f.evidence["examples"][0]["chunk_ids"])
    assert ids == {f"poison-{j}" for j in range(5)}
    assert f.evidence["similarity_threshold"] >= 0.9
    assert _outcome(job)["outcome"] == "failed"


def test_tight_cluster_from_established_source_is_not_reported():
    chunks = _corpus()
    rng = np.random.default_rng(7)
    topic = rng.normal(0, 1, 64)
    # One established document legitimately repeats one topic.
    for j in range(10):
        chunks[j].embedding = (topic + rng.normal(0, 0.05, 64)).tolist()
    job = scan_integrity(Mem({"docs": chunks}), "docs")
    assert not _dup_findings(job)
    assert job.stats["duplication"]["benign_tight_clusters"] >= 1


def test_cluster_detection_is_deterministic():
    rng = np.random.default_rng(1)
    X = rng.normal(0, 1, (300, 32)).astype(np.float32)
    X[:4] = X[0] + rng.normal(0, 0.01, (4, 32))
    limits = IntegrityLimits()
    a, sa, _ = find_embedding_clusters(X, limits)
    b, sb, _ = find_embedding_clusters(X, limits)
    assert a == b and sa == sb
    assert [0, 1, 2, 3] in a


def test_boilerplate_across_many_sources_is_ignored_but_few_sources_reported():
    footer = ("confidential internal document distributed under the standard terms of "
              "the corporate information handling policy version four")
    chunks = _corpus()
    for s in range(6):  # six distinct sources carry the same footer
        chunks.append(Chunk(id=f"footer-{s}", collection="docs", text=footer,
                            embedding=np.random.default_rng(s).normal(0, 1, 64).tolist(),
                            metadata={"source": f"doc-{s}.pdf", "chunk_index": 99}))
    job = scan_integrity(Mem({"docs": chunks}), "docs")
    assert not _dup_findings(job)
    assert job.stats["duplication"]["text_groups_by_kind"].get("boilerplate") == 1

    copied = _text(5000, 40)
    chunks = _corpus()
    for s in (0, 1):
        chunks.append(Chunk(id=f"copy-{s}", collection="docs", text=copied,
                            embedding=np.random.default_rng(50 + s).normal(0, 1, 64).tolist(),
                            metadata={"source": f"doc-{s}.pdf", "chunk_index": 50}))
    job = scan_integrity(Mem({"docs": chunks}), "docs")
    f = next(f for f in _dup_findings(job) if "Duplicated chunk text" in f.title)
    assert f.severity == Severity.LOW
    assert f.evidence["examples"][0]["kind"] == "cross_source"


def test_same_document_overlap_is_expected_but_repeat_ingestion_is_not():
    text = _text(7000, 40)
    chunks = _corpus()
    chunks += [Chunk(id=f"ov-{j}", collection="docs", text=text,
                     embedding=np.random.default_rng(70 + j).normal(0, 1, 64).tolist(),
                     metadata={"source": "doc-3.pdf", "chunk_index": 20 + j})
               for j in range(2)]
    assert not _dup_findings(scan_integrity(Mem({"docs": chunks}), "docs"))

    chunks = _corpus()
    chunks += [Chunk(id=f"re-{j}", collection="docs", text=text,
                     embedding=np.random.default_rng(80 + j).normal(0, 1, 64).tolist(),
                     metadata={"source": "doc-3.pdf", "chunk_index": 20})
               for j in range(2)]
    f = _dup_findings(scan_integrity(Mem({"docs": chunks}), "docs"))[0]
    assert f.evidence["examples"][0]["kind"] == "duplicate_ingestion"


def test_short_chunks_and_allow_listed_templates_are_skipped():
    chunks = _corpus()
    for s in range(2):
        chunks.append(Chunk(id=f"short-{s}", collection="docs", text="See page 4.",
                            embedding=np.random.default_rng(s).normal(0, 1, 64).tolist(),
                            metadata={"source": f"doc-{s}.pdf"}))
        chunks.append(Chunk(id=f"tpl-{s}", collection="docs",
                            text="TEMPLATE: " + _text(8000, 30),
                            embedding=np.random.default_rng(9 + s).normal(0, 1, 64).tolist(),
                            metadata={"source": f"doc-{s}.pdf"}))
    job = scan_integrity(Mem({"docs": chunks}), "docs", boilerplate_patterns=[r"^template:"])
    assert not _dup_findings(job)
    assert job.stats["duplication"]["allow_listed_chunks"] == 2
    assert job.stats["duplication"]["short_chunks"] >= 2


def test_sensitive_duplicates_within_and_across_collections():
    secret = _text(9000, 40)
    a = _corpus(collection="a")
    a += [Chunk(id=f"s-{j}", collection="a", text=secret,
                embedding=np.random.default_rng(j).normal(0, 1, 64).tolist(),
                metadata={"source": f"doc-{j}.pdf"}) for j in range(2)]
    b = _corpus(collection="b", seed=5)
    b.append(Chunk(id="s-b", collection="b", text=secret,
                   embedding=np.random.default_rng(3).normal(0, 1, 64).tolist(),
                   metadata={"source": "other.pdf"}))
    registry = SensitiveFingerprintRegistry()
    conn = Mem({"a": a, "b": b})
    job_a = scan_integrity(conn, "a", sensitive_ids={"s-0"}, sensitive_registry=registry)
    f = next(f for f in _dup_findings(job_a) if "Sensitive" in f.title)
    assert f.evidence["groups"] == 1
    job_b = scan_integrity(conn, "b", sensitive_ids={"s-b"}, sensitive_registry=registry)
    f = next(f for f in _dup_findings(job_b) if "Sensitive" in f.title)
    assert f.evidence["cross_collection"] == 1
    assert f.evidence["examples"][0]["other_collections"] == ["a"]
    # Digests never leave the process: nothing hash-like in evidence or stats.
    assert secret not in str([f.to_dict() for f in job_b.findings])
    assert secret not in str(job_b.stats)


def test_signature_cap_makes_coverage_partial():
    limits = IntegrityLimits(text_signature_cap=50)
    job = scan_integrity(Mem({"docs": _corpus()}), "docs", limits=limits)
    out = _outcome(job)
    assert out["coverage"]["complete"] is False
    assert out["outcome"] == "inconclusive"
    assert job.stats["duplication"]["signatures_capped"] == 150


def test_reruns_produce_the_same_observations():
    chunks = _corpus()
    rng = np.random.default_rng(42)
    target = rng.normal(0, 1, 64)
    chunks += [Chunk(id=f"p{j}", collection="docs", text=_text(950 + j),
                     embedding=(target + rng.normal(0, 0.05, 64)).tolist(),
                     metadata={}) for j in range(4)]

    def sig(job):
        return sorted((f.title, str(f.evidence.get("examples"))) for f in _dup_findings(job))

    first = scan_integrity(Mem({"docs": chunks}), "docs")
    second = scan_integrity(Mem({"docs": chunks}), "docs")
    assert sig(first) == sig(second) and sig(first)
