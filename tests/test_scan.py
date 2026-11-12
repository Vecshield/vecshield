"""End-to-end scan test against a seeded local Chroma store."""

from __future__ import annotations

from typing import Iterator

from vecshield.classify import RegexClassifier
from vecshield_platform.connectors.base import Connector
from vecshield_platform.connectors.chroma import ChromaConnector
from vecshield.models import Chunk, Collection, Severity, VectorStore
from vecshield_platform.scan import scan_store

# Engine-mechanics tests pin the deterministic regex classifier so counts are
# stable regardless of whether the optional NLP layer is installed. NLP recall
# is validated separately in test_recall.py.


def test_scan_finds_sensitive_collection(chroma_path):
    with ChromaConnector(path=chroma_path) as conn:
        job = scan_store(conn, classifier=RegexClassifier())

    assert job.stats["chunks_scanned"] == 70  # 50 + 20
    assert job.stats["sensitive_chunks"] == 5

    # prod-docs should be flagged; clean-kb should not.
    flagged = {f.collection for f in job.findings}
    assert "prod-docs" in flagged
    assert "clean-kb" not in flagged

    # A secret (AWS key) is present -> overall critical.
    assert job.max_severity == Severity.CRITICAL


def test_scan_serializable(chroma_path):
    with ChromaConnector(path=chroma_path) as conn:
        job = scan_store(conn, classifier=RegexClassifier())
    d = job.to_dict()
    assert d["store"]
    assert isinstance(d["findings"], list)
    assert d["max_severity"] == "critical"


def test_describe_lists_collections(chroma_path):
    with ChromaConnector(path=chroma_path) as conn:
        store = conn.describe()
    names = {c.name for c in store.collections}
    assert {"prod-docs", "clean-kb"} <= names


class _MetadataOnlyConnector(Connector):
    kind = "fake"

    def describe(self) -> VectorStore:
        return VectorStore(
            kind=self.kind,
            name="fake://metadata",
            endpoint="fake://metadata",
            collections=[Collection(name="payloads", count=3)],
        )

    def list_collections(self) -> list[Collection]:
        return self.describe().collections

    def iter_chunks(self, collection: str, batch_size: int = 256) -> Iterator[Chunk]:
        yield Chunk(
            id="m1",
            collection=collection,
            text="ordinary support ticket",
            metadata={"reporter_email": "jane.customer@example.com"},
        )
        yield Chunk(
            id="m2",
            collection=collection,
            text="ordinary account record",
            metadata={"profile": {"dob": "1980-01-02", "customer_id": "cus_12345"}},
        )
        yield Chunk(
            id="m3",
            collection=collection,
            text="benign",
            metadata={"source": "manual.pdf"},
        )


def test_scan_classifies_metadata_surfaces_horizontally():
    job = scan_store(_MetadataOnlyConnector(), classifier=RegexClassifier())
    assert job.stats["chunks_scanned"] == 3
    assert job.stats["sensitive_chunks"] == 2

    finding = job.findings[0]
    assert finding.evidence["label_counts"]["pii"] >= 2
    assert finding.evidence["metadata_surfaces_scanned"] >= 3
    surfaces = {
        span["surface"]
        for ex in finding.evidence["examples"]
        for span in ex["spans"]
    }
    assert "metadata.reporter_email" in surfaces
    assert "metadata_key.profile.customer_id" in surfaces


def test_scan_label_counts_include_secondary_labels():
    class MixedConnector(_MetadataOnlyConnector):
        def iter_chunks(self, collection: str, batch_size: int = 256) -> Iterator[Chunk]:
            yield Chunk(
                id="mixed",
                collection=collection,
                text="email bob@example.com key AKIAIOSFODNN7EXAMPLE",
            )

    job = scan_store(MixedConnector(), classifier=RegexClassifier())
    labels = job.findings[0].evidence["label_counts"]
    assert labels["secret"] == 1
    assert labels["pii"] == 1


def test_inventory_only_store_emits_coverage_finding():
    """A scan of an inventory-only store must flag its coverage gap, not look clean."""

    class InventoryOnly(Connector):
        kind = "inv"
        content_enumerable = False

        def describe(self) -> VectorStore:
            return VectorStore(
                kind=self.kind, name="inv://kb", endpoint="inv://kb",
                collections=[Collection(name="kb", count=100,
                                        metadata={"backing_store": "opensearch"})],
            )

        def list_collections(self) -> list[Collection]:
            return self.describe().collections

        def iter_chunks(self, collection: str, batch_size: int = 256) -> Iterator[Chunk]:
            return iter(())

    job = scan_store(InventoryOnly(), classifier=RegexClassifier())
    assert job.stats["content_enumerable"] is False
    coverage = [f for f in job.findings if f.category == "coverage"]
    assert len(coverage) == 1
    assert coverage[0].severity == Severity.MEDIUM
    assert "opensearch" in coverage[0].description
    assert coverage[0].evidence["backing_stores"] == ["opensearch"]


def test_enumerable_store_has_no_coverage_finding():
    job = scan_store(_MetadataOnlyConnector(), classifier=RegexClassifier())
    assert job.stats["content_enumerable"] is True
    assert [f for f in job.findings if f.category == "coverage"] == []



class _TwoCollectionConnector(Connector):
    """Two collections; reading ``broken`` records one unreadable item."""

    kind = "fake"

    def __init__(self, *, counts=None, count_known=True, model=None):
        self.counts = counts or {"broken": 2, "fine": 2}
        self.count_known = count_known
        self.model = model

    def describe(self) -> VectorStore:
        return VectorStore(kind=self.kind, name="fake://two", endpoint="fake://two",
                           collections=self.list_collections())

    def list_collections(self) -> list[Collection]:
        meta = {} if self.count_known else {"count_known": False}
        return [Collection(name=n, count=c, metadata=dict(meta),
                           embedding_model=self.model)
                for n, c in self.counts.items()]

    def iter_chunks(self, collection: str, batch_size: int = 256) -> Iterator[Chunk]:
        if collection == "broken":
            self._record_read_error(collection, item_id="file-9", error_type="Timeout")
        for i in range(2):
            yield Chunk(id=f"{collection}-{i}", collection=collection,
                        text="The quarterly roadmap focuses on latency improvements.")


def _outcomes(job, check="data_classification"):
    return {o["collection"]: o for o in job.stats["check_outcomes"] if o["check"] == check}


def test_read_errors_downgrade_only_the_collection_they_name():
    job = scan_store(_TwoCollectionConnector(), classifier=RegexClassifier())
    rows = _outcomes(job)
    assert rows["broken"]["outcome"] == "inconclusive"
    assert rows["broken"]["coverage"]["content_read_errors"] == 1
    assert rows["fine"]["outcome"] == "passed"
    assert rows["fine"]["coverage"]["complete"] is True
    inputs = job.stats["inventory_inputs"]["classification"]
    assert inputs["broken"]["complete"] is False
    assert inputs["fine"]["complete"] is True


def test_read_errors_from_an_earlier_pass_are_cleared():
    conn = _TwoCollectionConnector(counts={"fine": 2})
    conn._record_read_error("fine", item_id="stale", error_type="Timeout")
    job = scan_store(conn, classifier=RegexClassifier())
    assert _outcomes(job)["fine"]["outcome"] == "passed"
    assert job.stats["content_read_errors"] == 0


def test_store_wide_read_error_downgrades_every_collection():
    class StoreWide(_TwoCollectionConnector):
        def iter_chunks(self, collection, batch_size=256):
            if collection == "fine":
                self._record_read_error(None, operation="list_files", error_type="Boom")
            yield from super().iter_chunks(collection, batch_size)

    rows = _outcomes(scan_store(StoreWide(counts={"a": 2, "fine": 2}),
                                classifier=RegexClassifier()))
    assert {r["outcome"] for r in rows.values()} == {"inconclusive"}


def test_unknown_count_is_not_a_complete_read():
    job = scan_store(_TwoCollectionConnector(counts={"fine": 0}, count_known=False),
                     classifier=RegexClassifier())
    row = _outcomes(job)["fine"]
    assert row["outcome"] == "inconclusive" and row["coverage"]["complete"] is False
    assert row["coverage"]["count_known"] is False
    assert "count could not be read" in row["reason"]


def test_language_is_kept_as_codes_not_text():
    class German(_TwoCollectionConnector):
        def iter_chunks(self, collection, batch_size=256):
            for i in range(3):
                yield Chunk(id=f"{collection}-{i}", collection=collection,
                            text=("Der Bericht ist nicht fertig und die Daten sind mit "
                                  "dem neuen System auch nicht verbunden, sagt der Leiter "
                                  "der Abteilung."))

    row = _outcomes(scan_store(German(counts={"de": 3}), classifier=RegexClassifier()))["de"]
    assert row["coverage"]["languages"] == {"de": 3}


def test_a_failing_post_processing_step_is_recorded_and_the_scan_continues(monkeypatch):
    from vecshield_platform.scan import engine

    def broken(*_a, **_k):
        raise RuntimeError("bad metadata")

    monkeypatch.setattr(engine, "detect_biometric_collection", broken)
    job = scan_store(_TwoCollectionConnector(counts={"a": 2, "b": 2}),
                     classifier=RegexClassifier())
    errors = _outcomes(job, "biometric_templates")
    assert set(errors) == {"a", "b"}
    assert {o["outcome"] for o in errors.values()} == {"error"}
    assert "RuntimeError" in errors["a"]["reason"]
    assert set(_outcomes(job)) == {"a", "b"}  # classification still recorded


def _embedding_outcome(job):
    [row] = [o for o in job.stats["check_outcomes"] if o["check"] == "embedding_consistency"]
    return row


def test_embedding_consistency_with_no_declared_model_is_inconclusive():
    row = _embedding_outcome(scan_store(_TwoCollectionConnector(),
                                        classifier=RegexClassifier()))
    assert row["outcome"] == "inconclusive"
    # A gap in the store's declarations, not in this run's read.
    assert row["coverage"]["declaration_gap"] is True
    assert row["coverage"]["complete"] is True


def test_embedding_model_declared_in_store_config_fills_the_gap():
    from vecshield_platform.connectors.base import fill_declared_embedding_model

    conn = _TwoCollectionConnector()
    conn.declared_embedding_model = "all-MiniLM-L6-v2"
    job = scan_store(conn, classifier=RegexClassifier())
    row = _embedding_outcome(job)
    assert row["outcome"] == "passed" and row["coverage"]["complete"] is True
    assert job.stats["embedding_models"] == ["all-minilm-l6-v2"]

    # A model the store records itself is never overridden by the config.
    cols = _TwoCollectionConnector(model="text-embedding-3-small").list_collections()
    assert fill_declared_embedding_model(conn, cols) == 0
    assert {c.embedding_model for c in cols} == {"text-embedding-3-small"}


def test_build_connector_carries_the_configured_embedding_model(tmp_path):
    import chromadb

    from vecshield_platform.connectors import build_connector

    chromadb.PersistentClient(path=str(tmp_path))  # an existing (empty) store
    conn = build_connector("chroma", path=str(tmp_path), embedding_model="bge-m3")
    assert conn.declared_embedding_model == "bge-m3"
