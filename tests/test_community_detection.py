"""The current `vecshield` detectors must reach platform scan and ingest flows.

All identifiers are synthetic. These tests need no network, model download, or
optional NLP installation; the model-selection test supplies a small NLP double.
"""

from __future__ import annotations

import pytest

from vecshield.classify.base import Classifier
from vecshield.ingest import IngestGate
from vecshield.models import Chunk, Classification, Collection, SensitivityLabel, VectorStore
from vecshield_platform.connectors.base import Connector
from vecshield_platform import detection
from vecshield_platform.detection import build_classifier, reset_classifier_cache
from vecshield_platform.runtime.ingest_monitor import IngestMonitor
from vecshield_platform.runtime.sinks import InMemorySink
from vecshield_platform.scan.engine import scan_store


class MemoryConnector(Connector):
    kind = "memory"

    def __init__(self, chunks):
        self.chunks = chunks

    def describe(self):
        return VectorStore(kind=self.kind, name="synthetic", endpoint="memory://synthetic",
                           collections=self.list_collections())

    def list_collections(self):
        return [Collection(name="records", count=len(self.chunks))]

    def iter_chunks(self, collection, batch_size=256):
        yield from self.chunks


@pytest.fixture(autouse=True)
def clear_classifier_cache(monkeypatch):
    monkeypatch.setenv("VECSHIELD_NLP_MODE", "disabled")
    monkeypatch.delenv("VECSHIELD_NLP_MODEL", raising=False)
    reset_classifier_cache()
    yield
    reset_classifier_cache()


@pytest.mark.parametrize("detector,text,label", [
    ("india_pan", "PAN card ABCPE1234F", "pii"),
    ("singapore_nric", "NRIC S1234567D", "pii"),
    ("uk_nhs_context", "NHS number 401 023 2137", "phi"),
    ("ethereum_address", "wallet 0xabcdef0123456789abcdef0123456789abcdef01", "pci"),
    ("gps_coordinate", "location [-27.7672,27.6475]", "pii"),
    ("imei_number", "device IMEI 49-015420-323751-8", "pii"),
    ("vehicle_vin", "VIN 1HGBH41JXMN109186", "pii"),
    ("intl_phone", "call +39-66-565 2431", "pii"),
    ("us_ssn_context", "SSN 987-65-4321", "pii"),
])
def test_latest_community_detectors_reach_enterprise_scan(detector, text, label):
    connector = MemoryConnector([Chunk(id="synthetic", collection="records", text=text)])
    job = scan_store(connector, classifier=build_classifier(use_nlp=False))
    findings = [f for f in job.findings if f.category == "data_classification"]
    assert len(findings) == 1
    evidence = findings[0].evidence
    assert evidence["label_counts"][label] == 1
    assert evidence["detector_counts"][detector] == 1
    assert any(span["detector"] == detector for span in evidence["examples"][0]["spans"])
    assert job.stats["chunks_scanned"] == 1
    assert job.stats["sensitive_chunks"] == 1


def test_latest_detector_rejects_invalid_international_id_in_scan():
    connector = MemoryConnector([
        Chunk(id="invalid", collection="records", text="NRIC S1234567E"),
    ])
    job = scan_store(connector, classifier=build_classifier(use_nlp=False))
    assert not [f for f in job.findings if f.category == "data_classification"]
    assert job.stats["chunks_scanned"] == 1
    assert job.stats["sensitive_chunks"] == 0


def test_metadata_scan_and_ingest_use_the_same_latest_detectors():
    classifier = build_classifier(use_nlp=False)
    chunks = [
        Chunk(id="device", collection="records", text="Support ticket.",
              metadata={"payload": {"diagnostics": ["device IMEI 49-015420-323751-8"]}}),
        Chunk(id="clean", collection="records", text="The deployment completed successfully."),
    ]
    job = scan_store(MemoryConnector(chunks), classifier=classifier)
    finding = next(f for f in job.findings if f.category == "data_classification")
    spans = finding.evidence["examples"][0]["spans"]
    device_span = next(s for s in spans if s["detector"] == "imei_number")
    assert device_span["surface"] == "metadata.payload.diagnostics.0"
    assert finding.evidence["metadata_surfaces_scanned"] >= 1

    sink = InMemorySink()
    monitor = IngestMonitor(IngestGate(classifier=classifier), sinks=[sink])
    report = monitor.observe(chunks, principal="loader", dataset="records", timestamp=1.0)
    assert [c.id for c in report.blocked_chunks] == ["device"]
    assert [c.id for c in report.allowed_chunks] == ["clean"]
    assert "imei_number" in report.findings[0].evidence["detectors"]
    assert len(sink.alerts) == 1
    assert sink.alerts[0].evidence["blocked_chunk_ids"] == ["device"]


def test_regex_mode_applies_clinical_context_without_upgrading_age_alone():
    classifier = build_classifier(use_nlp=False)
    clinical = classifier.classify("Patient email privacy@example.com after surgery.")
    ordinary = classifier.classify("Contact privacy@example.com for the deployment notes.")
    age_only = classifier.classify("The patient is 55 years old and receiving treatment.")
    assert clinical.label == SensitivityLabel.PHI
    assert next(s for s in clinical.spans if s["detector"] == "email")["label"] == "phi"
    assert ordinary.label == SensitivityLabel.PII
    assert age_only.label == SensitivityLabel.PII
    assert "age_context" in age_only.detectors


def test_model_selection_reaches_community_and_reuses_loaded_model(monkeypatch):
    constructed_models = []

    class FakePresidio(Classifier):
        name = "presidio"

        @staticmethod
        def available():
            return True

        def __init__(self, model="default"):
            constructed_models.append(model)
            self.model = model

        def classify(self, text):
            if text and "Alice" in text:
                start = text.index("Alice")
                return Classification(
                    SensitivityLabel.PII, 0.65, detectors=["presidio:PERSON"],
                    spans=[{"detector": "presidio:PERSON", "label": "pii",
                            "start": start, "end": start + 5, "preview": "A***e"}],
                )
            return Classification(SensitivityLabel.NONE, 0.0)

    monkeypatch.setattr(detection, "_build_nlp", FakePresidio)
    first = build_classifier(use_nlp=True, model="en_core_web_trf")
    second = build_classifier(use_nlp=True, model="en_core_web_trf")
    assert constructed_models == ["en_core_web_trf"]
    assert first.classify("Patient Alice returns after surgery.").label == SensitivityLabel.PHI
    assert "presidio:PERSON" in second.classify("Alice filed the report.").detectors


def test_status_reports_latest_detectors_without_loading_nlp(monkeypatch):
    def unexpected_model_load(model):
        raise AssertionError("Status inspection must not load a model")

    monkeypatch.setattr(detection, "_build_nlp", unexpected_model_load)
    status = detection.detection_status()
    assert status["status"] == "disabled"
    assert status["nlp_loaded"] is False
    assert status["active_model"] is None
    assert status["requested_model"] == "en_core_web_trf"
    assert status["regex_detector_count"] >= 75
    assert {"nested_metadata", "clinical_context", "batch_classification"} <= set(status["features"])


def test_unavailable_nlp_is_explicit_and_required_mode_fails(monkeypatch):
    def unavailable(model):
        raise detection.DetectionUnavailableError("Selected model is not installed")

    monkeypatch.setenv("VECSHIELD_NLP_MODE", "auto")
    monkeypatch.setattr(detection, "_build_nlp", unavailable)
    classifier = build_classifier()
    assert classifier.classify("PAN card ABCPE1234F").is_sensitive
    status = detection.detection_status()
    assert status["status"] == "degraded"
    assert "not installed" in status["reason"]
    with pytest.raises(detection.DetectionUnavailableError, match="not installed"):
        build_classifier(use_nlp=True)


def test_batch_uses_nlp_batch_api_and_preserves_order_and_cached_spans(monkeypatch):
    batches = []
    cached_result = Classification(
        SensitivityLabel.PII, 0.65, detectors=["presidio:PERSON"],
        spans=[{"detector": "presidio:PERSON", "label": "pii",
                "start": 0, "end": 5, "preview": "A***e"}],
    )

    class BatchNlp(Classifier):
        name = "presidio"

        def classify(self, text):
            raise AssertionError("Batch requests should use the NLP batch API")

        def classify_batch(self, texts, spacy_batch_size=64):
            texts = list(texts)
            batches.append((texts, spacy_batch_size))
            return [cached_result if text else Classification(SensitivityLabel.NONE, 0.0)
                    for text in texts]

    monkeypatch.setattr(detection, "_build_nlp", lambda model: BatchNlp())
    classifier = build_classifier(use_nlp=True, model="synthetic-model")
    results = classifier.classify_batch(iter(["Alice is a patient", None, "Alice", ""]), batch_size=2)
    assert [r.label for r in results] == [SensitivityLabel.PHI, SensitivityLabel.NONE,
                                        SensitivityLabel.PII, SensitivityLabel.NONE]
    assert batches == [(["Alice is a patient", None], 2), (["Alice", ""], 2)]
    results[0].spans[0]["surface"] = "metadata.person"
    results[2].spans[0]["label"] = "secret"
    assert cached_result.spans[0]["label"] == "pii"
    assert "surface" not in cached_result.spans[0]


def test_enterprise_nlp_batch_reads_each_distinct_text_once(monkeypatch):
    """Repeated surfaces (a source file, a tenant) reach the model once per
    batch, and each position still gets its own result to mutate."""
    from types import SimpleNamespace

    from vecshield.classify import presidio_classifier

    def stub_init(self, *, model, entities, allow_list):
        self.entities, self.allow_list = entities, allow_list
        self.score_floor, self._calibration = 0.0, {}
        self.languages = ("en",)

    monkeypatch.setattr(detection, "_model_installed", lambda model: True)
    monkeypatch.setattr(detection, "_missing_requirements", lambda model: [])
    monkeypatch.setattr(presidio_classifier, "pin_offline_runtime", lambda: None)
    monkeypatch.setattr(presidio_classifier.PresidioClassifier, "__init__", stub_init)
    nlp = detection._build_nlp("synthetic-model")
    analysed: list[list[str]] = []

    def analyze_batch(texts, spacy_batch_size=64):
        analysed.append(list(texts))
        return [[SimpleNamespace(entity_type="PERSON", score=0.9, start=0, end=5)]
                for _ in texts]

    nlp._analyze_batch = analyze_batch
    texts = ["Alice wrote this", "report.pdf", None, "Alice wrote this", "", "report.pdf"]
    results = nlp.classify_batch(texts)

    assert analysed == [["Alice wrote this", "report.pdf"]]
    assert [r.label for r in results] == [SensitivityLabel.PII, SensitivityLabel.PII,
                                        SensitivityLabel.NONE, SensitivityLabel.PII,
                                        SensitivityLabel.NONE, SensitivityLabel.PII]
    assert results[0] == results[3] and results[1] == results[5]
    assert results[0] is not results[3]
    results[0].spans[0]["surface"] = "text"
    assert "surface" not in results[3].spans[0]


def test_nlp_runtime_error_cannot_produce_a_clean_enterprise_scan(monkeypatch):
    class BrokenNlp(Classifier):
        name = "presidio"

        def classify(self, text):
            raise RuntimeError("analyzer failed")

    monkeypatch.setattr(detection, "_build_nlp", lambda model: BrokenNlp())
    connector = MemoryConnector([Chunk(id="unread", collection="records", text="Alice")])
    job = scan_store(connector, classifier=build_classifier(use_nlp=True))
    assert not job.stats["coverage"]["complete"]
    assert job.stats["coverage"]["outcomes"]["error"] == 1
    assert job.stats["check_outcomes"][0]["outcome"] == "error"


def test_api_scan_and_ingest_share_configured_community_provider():
    from fastapi.testclient import TestClient
    from vecshield_platform.api import StoreRegistry, create_app

    text = "Patient contact privacy@example.com after surgery."
    reg = StoreRegistry()
    reg.register("synthetic", "memory", factory=lambda: MemoryConnector([
        Chunk(id="patient", collection="records", text=text),
    ]))
    with TestClient(create_app(reg, serve_ui=False)) as client:
        scan = client.post("/stores/synthetic/scan")
        assert scan.status_code == 200
        finding = next(f for f in scan.json()["findings"] if f["category"] == "data_classification")
        assert finding["evidence"]["label_counts"]["phi"] == 1

        gate = client.post("/ingest/gate", json={"chunks": [{
            "id": "patient", "collection": "records", "text": "Imported record.",
            "metadata": {"contact": {"note": text}},
        }]})
        assert gate.status_code == 200
        assert gate.json()["blocked_chunk_ids"] == ["patient"]
        assert gate.json()["findings"][0]["evidence"]["label"] == "phi"
