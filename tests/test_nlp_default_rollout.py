"""NLP on by default.

Covers the gate severity policy for spans found only by NLP (D-N2), the
allow-list and entity configuration (D-N3), background warm-up and the
``loading`` status, batched scan classification, the per-scan NLP time
budget, and the coverage record for truncated surfaces. The model doubles are
synthetic; the real-load tests at the end run only where a model is installed.
"""

from __future__ import annotations

import re
import threading

import pytest

from vecshield.classify.base import Classifier
from vecshield.classify.surfaces import (
    MAX_SURFACE_CHARS,
    chunk_text_surfaces,
    classify_chunk,
    classify_chunks,
)
from vecshield.ingest import IngestGate
from vecshield.ingest.gate import PiiDetectedError, rate_chunk
from vecshield.models import Chunk, Classification, Collection, SensitivityLabel, Severity, VectorStore
from vecshield_platform import detection, nlp_models
from vecshield_platform.connectors.base import Connector
from vecshield_platform.detection import EnterpriseClassifier, reset_classifier_cache
from vecshield_platform.scan.batching import ClassifiedStream, NlpBudget
from vecshield_platform.scan.engine import scan_store

_NAME = re.compile(r"Taylor Swift|Alice Johnson|Boston")


class NameNlp(Classifier):
    """Tags "Taylor Swift" and "Alice Johnson" as PERSON, "Boston" as LOCATION."""

    name = "presidio"

    def __init__(self):
        self.batches: list[int] = []

    def classify(self, text):
        spans = []
        for match in _NAME.finditer(text or ""):
            kind = "LOCATION" if match.group() == "Boston" else "PERSON"
            spans.append({"detector": f"presidio:{kind}", "label": "pii",
                          "start": match.start(), "end": match.end(), "score": 0.553})
        if not spans:
            return Classification(SensitivityLabel.NONE, 0.0)
        return Classification(SensitivityLabel.PII, 0.553,
                              detectors=sorted({s["detector"] for s in spans}), spans=spans)

    def classify_batch(self, texts, spacy_batch_size=64):
        texts = list(texts)
        self.batches.append(len(texts))
        return [self.classify(text) for text in texts]


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
def clean_state(monkeypatch):
    for name in ("VECSHIELD_NLP_MODEL", "VECSHIELD_NLP_ENTITIES", "VECSHIELD_NLP_ALLOW_LIST",
                 "VECSHIELD_NLP_ALLOW_LIST_FILE", "VECSHIELD_NLP_TIME_BUDGET_S"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("VECSHIELD_NER_MODELS", "none")
    reset_classifier_cache()
    yield
    reset_classifier_cache()


def _ensemble(nlp=None):
    return EnterpriseClassifier(mode="required", model="synthetic", nlp=nlp or NameNlp())


def _classification(job):
    return next(o for o in job.stats["check_outcomes"] if o["check"] == "data_classification")


# ---- default model ---------------------------------------------------------

def test_default_is_trf_and_hftrf_stays_in_the_catalog():
    assert detection.DEFAULT_NLP_MODEL == "en_core_web_trf" == nlp_models.DEFAULT_MODEL
    assert nlp_models.CATALOG["en_core_web_trf"].default
    assert not nlp_models.CATALOG["en_core_web_hftrf"].default
    assert nlp_models.SLIM_MODEL == "en_core_web_lg" in nlp_models.CATALOG
    assert any(r.startswith("torch>=2.6") for r in nlp_models.CATALOG["en_core_web_trf"].requires)


# ---- gate severity policy (D-N2) ------------------------------------------

def test_nlp_only_person_is_not_blocked_at_high():
    gate = IngestGate(classifier=_ensemble(), mode="hard")
    chunk = Chunk(id="alexa", collection="prompts", text="Ask Alexa to play Taylor Swift")
    report = gate.check([chunk])  # hard mode: raises if anything is blocked
    assert not report.blocked and report.allowed_chunks == [chunk]
    assert report.below_threshold == [{
        "chunk_id": "alexa", "label": "pii", "severity": "medium",
        "severity_basis": "nlp_only", "detectors": ["presidio:PERSON"]}]
    assert report.to_dict()["below_threshold"][0]["severity_basis"] == "nlp_only"


def test_regex_corroborated_person_is_blocked():
    gate = IngestGate(classifier=_ensemble(), mode="hard")
    chunk = Chunk(id="mail", collection="prompts",
                  text="Ask Alexa to play Taylor Swift, then email taylor.fan@example.com")
    with pytest.raises(PiiDetectedError) as caught:
        gate.check([chunk])
    finding = caught.value.report.findings[0]
    assert finding.severity is Severity.HIGH
    assert finding.evidence["severity_basis"] == "pattern"


def test_clinical_context_and_a_second_identifier_corroborate():
    gate = IngestGate(classifier=_ensemble(), mode="soft")
    clinical = Chunk(id="clinic", collection="c", text="Patient Alice Johnson seen for diagnosis")
    two_ids = Chunk(id="where", collection="c", text="Alice Johnson moved to Boston")
    report = gate.inspect([clinical, two_ids])
    assert [c.id for c in report.blocked_chunks] == ["clinic", "where"]
    bases = {f.evidence["chunk_id"]: f.evidence["severity_basis"] for f in report.findings}
    assert bases == {"clinic": "nlp_corroborated", "where": "nlp_corroborated"}


def test_rating_without_nlp_spans_is_unchanged():
    secret = Classification(SensitivityLabel.SECRET, 0.9, detectors=["aws_key"],
                            spans=[{"detector": "aws_key", "label": "secret",
                                    "start": 0, "end": 4}])
    assert rate_chunk(secret) == (SensitivityLabel.SECRET, Severity.CRITICAL, "pattern")
    org_only = Classification(SensitivityLabel.PII, 0.5, detectors=["presidio:ORGANIZATION"],
                              spans=[{"detector": "presidio:ORGANIZATION", "label": "pii",
                                      "start": 0, "end": 4}])
    assert rate_chunk(org_only) == (SensitivityLabel.PII, Severity.MEDIUM, "nlp_only")


def test_special_category_label_does_not_crash_the_gate():
    special = Classification(SensitivityLabel.SPECIAL_CATEGORY, 0.8, detectors=["x"],
                             spans=[{"detector": "x", "label": "special_category",
                                     "start": 0, "end": 1}])
    assert rate_chunk(special)[1] is Severity.HIGH


def test_gate_reports_truncated_surfaces():
    gate = IngestGate(classifier=_ensemble(), mode="soft")
    long = Chunk(id="long", collection="c", text="x" * (MAX_SURFACE_CHARS + 250))
    report = gate.inspect([long])
    assert report.truncated_surfaces == [
        {"chunk_id": "long", "surfaces": ["text"], "chars_not_classified": 250}]


# ---- allow-list and entity configuration (D-N3) ----------------------------

def test_allow_list_and_entities_resolve_from_the_environment(monkeypatch, tmp_path):
    from vecshield.classify.presidio_classifier import (
        resolve_allow_list,
        resolve_requested_entities,
    )

    assert "ORGANIZATION" in resolve_requested_entities()  # D-N3: kept by default
    monkeypatch.setenv("VECSHIELD_NLP_ENTITIES", "person, location")
    assert resolve_requested_entities() == ["PERSON", "LOCATION"]
    monkeypatch.setenv("VECSHIELD_NLP_ENTITIES", "PERSON,ORGANISATION")
    with pytest.raises(ValueError, match="ORGANISATION"):
        resolve_requested_entities()
    terms = tmp_path / "allow.txt"
    terms.write_text("# brands\nOrion  Studio\nAlexa # assistant\n")
    monkeypatch.setenv("VECSHIELD_NLP_ALLOW_LIST", "Taylor Swift, ")
    monkeypatch.setenv("VECSHIELD_NLP_ALLOW_LIST_FILE", str(terms))
    assert resolve_allow_list() == {"taylor swift", "orion studio", "alexa"}


def test_bad_nlp_configuration_is_reported_not_ignored(monkeypatch, tmp_path):
    monkeypatch.setenv("VECSHIELD_NLP_MODE", "auto")
    monkeypatch.setattr(detection, "_model_installed", lambda model: True)
    monkeypatch.setattr(detection, "_missing_requirements", lambda model: [])
    monkeypatch.setenv("VECSHIELD_NLP_ALLOW_LIST_FILE", str(tmp_path / "missing.txt"))
    status = detection.detection_status()
    assert status["status"] == "unavailable"
    assert "VECSHIELD_NLP_ALLOW_LIST_FILE" in status["reason"]
    with pytest.raises(detection.DetectionConfigurationError):
        detection._build_nlp("en_core_web_trf")


def test_allow_listed_span_is_dropped_by_the_presidio_adapter():
    from types import SimpleNamespace

    from vecshield.classify.presidio_classifier import PresidioClassifier

    clf = PresidioClassifier.__new__(PresidioClassifier)
    clf.score_floor, clf._calibration = 0.5, {}
    clf.allow_list = frozenset({"taylor swift"})
    text = "Ask Alexa to play Taylor  SWIFT"
    hit = SimpleNamespace(entity_type="PERSON", start=18, end=len(text), score=0.85)
    assert not clf._results_to_classification(text, [hit]).is_sensitive
    clf.allow_list = frozenset()
    assert clf._results_to_classification(text, [hit]).is_sensitive


# ---- warm-up and status ------------------------------------------------------

def test_warm_up_reads_loading_then_ready(monkeypatch):
    monkeypatch.setenv("VECSHIELD_NLP_MODE", "required")
    monkeypatch.setattr(detection, "_model_installed", lambda model: True)
    monkeypatch.setattr(detection, "_missing_requirements", lambda model: [])
    release = threading.Event()

    def slow_load(model):
        assert release.wait(10)
        return NameNlp()

    monkeypatch.setattr(detection, "_build_nlp", slow_load)
    assert detection.detection_status()["status"] == "unverified"
    thread = detection.start_warm_up()
    assert thread is not None
    loading = detection.detection_status()  # answers at once, mid-load
    assert loading["status"] == "loading" and "background" in loading["reason"]
    release.set()
    thread.join(10)
    ready = detection.detection_status()
    assert ready["status"] == "ready" and ready["nlp_loaded"] is True
    assert detection.start_warm_up() is None  # already loaded: nothing to do


def test_failed_required_warm_up_reads_unavailable_with_the_reason(monkeypatch):
    monkeypatch.setenv("VECSHIELD_NLP_MODE", "required")
    monkeypatch.setattr(detection, "_model_installed", lambda model: True)
    monkeypatch.setattr(detection, "_missing_requirements", lambda model: [])

    def broken(model):
        raise detection.DetectionUnavailableError("weights could not be read")

    monkeypatch.setattr(detection, "_build_nlp", broken)
    thread = detection.start_warm_up()
    thread.join(10)
    status = detection.detection_status()
    assert status["status"] == "unavailable"
    assert status["reason"] == "weights could not be read"


def test_startup_warning_names_the_install_command_in_auto_mode(monkeypatch):
    monkeypatch.setenv("VECSHIELD_NLP_MODE", "auto")
    monkeypatch.setattr(detection, "_model_installed", lambda model: False)
    warning = detection.startup_warning()
    assert warning and "\n" not in warning
    assert "vecshield-platform nlp install en_core_web_trf" in warning
    monkeypatch.setenv("VECSHIELD_NLP_MODE", "disabled")
    assert detection.startup_warning() is None


# ---- batching ----------------------------------------------------------------

def _chunks(n):
    texts = ["Ask Alexa to play Taylor Swift", "order 4411 shipped",
             "Alice Johnson moved to Boston", "email ops@example.com please"]
    return [Chunk(id=str(i), collection="records", text=texts[i % len(texts)],
                  metadata={"author": "Alice Johnson"} if i % 3 == 0 else {})
            for i in range(n)]


def test_batched_classification_equals_per_chunk_classification():
    nlp = NameNlp()
    classifier = _ensemble(nlp)
    chunks = _chunks(10)
    single = [classify_chunk(classifier, chunk) for chunk in chunks]
    batched = classify_chunks(classifier, chunks)
    assert [r.to_dict() if hasattr(r, "to_dict") else vars(r) for r in batched] == \
        [r.to_dict() if hasattr(r, "to_dict") else vars(r) for r in single]
    assert nlp.batches  # the NLP leg really went through classify_batch


def test_scan_routes_through_the_batch_api_and_counts_every_chunk():
    nlp = NameNlp()
    job = scan_store(MemoryConnector(_chunks(130)), classifier=_ensemble(nlp))
    assert job.stats["chunks_scanned"] == 130
    assert len(nlp.batches) >= 3  # 64 + 64 + 2 chunks, not 130 single calls
    assert _classification(job)["coverage"]["chunks_scanned"] == 130


def test_stream_honours_the_chunk_limit_like_the_old_loop():
    stream = ClassifiedStream(_ensemble(), _chunks(10), limit=4, batch_chunks=3)
    assert [chunk.id for chunk, _, _ in stream] == ["0", "1", "2", "3"]
    assert stream.capped
    exact = ClassifiedStream(_ensemble(), _chunks(4), limit=4)
    assert len(list(exact)) == 4 and not exact.capped


# ---- time budget ---------------------------------------------------------------

def test_exhausted_budget_records_partial_coverage_and_skips_nothing(monkeypatch):
    nlp = NameNlp()
    classifier = _ensemble(nlp)
    clock = iter(range(0, 10_000, 5))  # every perf_counter call advances 5 s
    monkeypatch.setattr("time.perf_counter", lambda: float(next(clock)))
    job = scan_store(MemoryConnector(_chunks(200)), classifier=classifier,
                     nlp_time_budget_s=1)
    outcome = _classification(job)
    assert job.stats["chunks_scanned"] == 200  # all chunks still classified
    assert outcome["coverage"]["complete"] is False
    assert outcome["coverage"]["nlp_budget_exhausted"] is True
    without = outcome["coverage"]["chunks_without_nlp"]
    assert 0 < without < 200
    assert "time budget" in outcome["reason"]
    assert job.stats["nlp_budget"]["chunks_without_nlp"] == without
    nlp_outcome = next(o for o in job.stats["check_outcomes"]
                       if o["check"] == "nlp_classification")
    assert nlp_outcome["outcome"] == "inconclusive"
    assert nlp_outcome["coverage"]["complete"] is False
    assert nlp_outcome["coverage"]["status"] == "budget_exhausted"
    assert job.stats["coverage"]["complete"] is False
    # Pattern detectors still ran on the chunks read without NLP.
    assert job.stats["sensitive_chunks"] >= 50


def test_budget_resolution(monkeypatch):
    assert NlpBudget.resolve(None) is None
    monkeypatch.setenv("VECSHIELD_NLP_TIME_BUDGET_S", "off")
    assert NlpBudget.resolve(None) is None
    monkeypatch.setenv("VECSHIELD_NLP_TIME_BUDGET_S", "900")
    assert NlpBudget.resolve(None).seconds == 900
    monkeypatch.setenv("VECSHIELD_NLP_TIME_BUDGET_S", "soon")
    with pytest.raises(ValueError):
        NlpBudget.resolve(None)
    with pytest.raises(ValueError):
        NlpBudget.resolve(-1)


def test_generous_budget_changes_nothing():
    job = scan_store(MemoryConnector(_chunks(20)), classifier=_ensemble(),
                     nlp_time_budget_s=3600)
    assert "nlp_budget_exhausted" not in _classification(job)["coverage"]
    assert job.stats["nlp_budget"]["exhausted"] is False


# ---- truncated surfaces ----------------------------------------------------------

def test_truncated_surface_is_recorded_in_scan_coverage():
    text = "notes " * 1200  # 7,200 characters
    surfaces = chunk_text_surfaces(Chunk(id="1", collection="records", text=text))
    assert surfaces[0].truncated_chars == len(text.strip()) - MAX_SURFACE_CHARS
    job = scan_store(MemoryConnector([Chunk(id="1", collection="records", text=text)]),
                     classifier=_ensemble())
    outcome = _classification(job)
    assert outcome["coverage"]["complete"] is False
    assert outcome["coverage"]["surfaces_truncated"] == 1
    assert outcome["coverage"]["chars_not_classified"] == surfaces[0].truncated_chars
    assert "5,000 characters" in outcome["reason"]
    assert outcome["outcome"] == "inconclusive"


# ---- real model loads (no mocks) ------------------------------------------------

def _installed(model):
    present = (nlp_models.installed_version(model) is not None
               and not detection._missing_requirements(model))
    # The CI NLP job sets this so a model that failed to install fails the job
    # instead of skipping every real-load test and passing green.
    required = {name.strip() for name in
                __import__("os").environ.get("VECSHIELD_NLP_TESTS_REQUIRE", "").split(",")}
    if not present and model in required:
        pytest.fail(f"{model} is required by VECSHIELD_NLP_TESTS_REQUIRE but not installed")
    return present


_REAL_MODELS = [name for name in ("en_core_web_trf", "en_core_web_lg", "en_core_web_sm")
                if name in nlp_models.CATALOG]


@pytest.mark.nlp_model
@pytest.mark.parametrize("model", _REAL_MODELS)
def test_real_model_loads_and_finds_a_name(model, monkeypatch):
    if not _installed(model):
        pytest.skip(f"{model} and its runtime are not installed")
    monkeypatch.setenv("VECSHIELD_NLP_MODE", "required")
    monkeypatch.setenv("VECSHIELD_NLP_MODEL", model)
    classifier = detection.build_classifier()
    assert classifier.detection_metadata()["status"] == "ready"
    result = classifier.classify("Deliver the parcel to Aoife Brennan at 14 Calder Row, Leeds.")
    assert "presidio:PERSON" in result.detectors
    batch = classifier.classify_batch(["Deliver the parcel to Aoife Brennan.", "", "no names"])
    assert "presidio:PERSON" in batch[0].detectors and not batch[1].is_sensitive
    assert detection.detection_status()["status"] == "ready"


@pytest.mark.nlp_model
@pytest.mark.parametrize("model", _REAL_MODELS)
def test_catalog_pin_matches_the_loadable_pipeline(model):
    """The pinned catalog version is what is installed, and it verifies offline."""
    import subprocess
    import sys

    if not _installed(model):
        pytest.skip(f"{model} and its runtime are not installed")
    spec = nlp_models.CATALOG[model]
    assert nlp_models.installed_version(model) == spec.version
    import os

    proc = subprocess.run(nlp_models.verify_argv(sys.executable, model), capture_output=True,
                          text=True, timeout=600, env={**os.environ, **nlp_models.OFFLINE_ENV})
    result = nlp_models.evaluate_verification(model, proc.returncode, proc.stdout, proc.stderr)
    assert result["ok"], result
    assert result["version"] == spec.version and not result["warnings"]


@pytest.mark.nlp_model
def test_real_default_model_gate_probe_set(monkeypatch):
    """Product, brand and fiction sentences are not hard-blocked (acceptance 4)."""
    model = detection.DEFAULT_NLP_MODEL
    if not _installed(model):
        pytest.skip(f"{model} and its runtime are not installed")
    monkeypatch.setenv("VECSHIELD_NLP_MODE", "required")
    gate = IngestGate(classifier=detection.build_classifier(), mode="hard")
    probes = ["Install Orion Studio, then open Jasper and select the Falcon template.",
              "Ask Alexa to play Taylor Swift in the kitchen.",
              "The Chancellor of the Exchequer announced the budget on Wednesday.",
              "Escalated by Priya Raman on Tuesday."]
    report = gate.check([Chunk(id=str(i), collection="probe", text=text)
                         for i, text in enumerate(probes)])
    assert not report.blocked
