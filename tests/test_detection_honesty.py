"""Detection never silently degrades, and never phones home at scan time.

Regressions for the bug hunt: NLP that is degraded or turned off must reach
check outcomes and criteria as partial coverage; classification must not open
network connections; loaded non-English NER models must actually be used; and
detection status must not read ``ready`` for a model that cannot load.

All data is synthetic. Tests that need a real spaCy model use the small ones
installed in the development environment and skip when they are absent.
"""

from __future__ import annotations

import socket

import pytest

from vecshield.classify.base import Classifier
from vecshield.models import Chunk, Classification, Collection, SensitivityLabel, VectorStore
from vecshield_platform import detection
from vecshield_platform.compliance.criteria import evaluate_criterion
from vecshield_platform.compliance.packs import criteria_for
from vecshield_platform.connectors.base import Connector
from vecshield_platform.detection import build_classifier, reset_classifier_cache
from vecshield_platform.scan import scan_store

NAMES = "Maria Gonzalez (born 1984) lives at Rosenweg 4, Berlin, and banks with Siemens."


class MemoryConnector(Connector):
    kind = "memory"

    def __init__(self, chunks):
        self.chunks = chunks

    def describe(self):
        return VectorStore(kind=self.kind, name="memory", endpoint="memory://",
                           collections=self.list_collections())

    def list_collections(self):
        return [Collection(name="notes", count=len(self.chunks))]

    def iter_chunks(self, collection, batch_size=256):
        yield from self.chunks


class QuietNlp(Classifier):
    """An NLP member that loaded and finds nothing."""

    name = "presidio"

    def classify(self, text):
        return Classification(SensitivityLabel.NONE, 0.0)


def _conn():
    return MemoryConnector([Chunk(id="1", collection="notes", text=NAMES,
                                  metadata={"source": "ehr"})])


@pytest.fixture(autouse=True)
def fresh_cache(monkeypatch):
    monkeypatch.delenv("VECSHIELD_NLP_MODE", raising=False)
    monkeypatch.delenv("VECSHIELD_NLP_MODEL", raising=False)
    reset_classifier_cache()
    yield
    reset_classifier_cache()


@pytest.fixture
def degraded(monkeypatch):
    def unavailable(model):
        raise detection.DetectionUnavailableError(f"NLP model {model!r} is not installed")

    monkeypatch.setattr(detection, "_build_nlp", unavailable)
    clf = build_classifier()
    assert clf.detection_metadata()["status"] == "degraded"
    return clf


@pytest.fixture
def ready(monkeypatch):
    monkeypatch.setattr(detection, "_build_nlp", lambda model: QuietNlp())
    clf = build_classifier()
    assert clf.detection_metadata()["status"] == "ready"
    return clf


def _classification(job):
    return next(o for o in job.stats["check_outcomes"] if o["check"] == "data_classification")


# ---- NLP not ready reaches outcomes and criteria ----------------------------

@pytest.mark.parametrize("which", ["degraded", "disabled"])
def test_nlp_not_ready_makes_classification_partial(which, request):
    clf = (request.getfixturevalue("degraded") if which == "degraded"
           else build_classifier(use_nlp=False))
    job = scan_store(_conn(), classifier=clf)
    outcome = _classification(job)
    assert outcome["coverage"]["complete"] is False
    assert outcome["outcome"] != "passed"
    assert outcome["coverage"]["nlp_status"] == which
    assert "NLP" in outcome["reason"]
    assert job.stats["coverage"]["complete"] is False
    assert job.stats["coverage"]["status"] == "partial"
    nlp = [o for o in job.stats["check_outcomes"] if o["check"] == "nlp_classification"]
    assert len(nlp) == 1 and nlp[0]["coverage"]["complete"] is False


def test_ready_nlp_keeps_a_fully_read_collection_complete(ready):
    job = scan_store(_conn(), classifier=ready)
    outcome = _classification(job)
    assert (outcome["outcome"], outcome["coverage"]["complete"]) == ("passed", True)
    assert not [o for o in job.stats["check_outcomes"] if o["check"] == "nlp_classification"]
    assert job.stats["coverage"]["complete"] is True


@pytest.mark.parametrize("which", ["degraded", "disabled"])
def test_deidentification_criterion_cannot_read_passed_over_full_scope(which, request):
    clf = (request.getfixturevalue("degraded") if which == "degraded"
           else build_classifier(use_nlp=False))
    job = scan_store(_conn(), classifier=clf)
    crit = next(c for c in criteria_for() if c.id == "HIPAA-164-514-B-DEIDENT-01")
    plain = evaluate_criterion(crit, check_outcomes=job.stats["check_outcomes"])
    assert (plain.technical_result, plain.technical_coverage) != ("passed", "complete")
    reviewed = evaluate_criterion(
        crit, check_outcomes=job.stats["check_outcomes"],
        applicability_answers={q: "yes" for q in crit.applicability_questions},
        evidence={e: "accepted" for e in crit.manual_evidence})
    assert "full scope" not in reviewed.rationale


def test_retrieval_exposure_records_the_nlp_gap(degraded):
    from vecshield_platform.crypto.retrieval import probe_retrieval_exposure
    from vecshield.models import QueryHit

    class Queryable(MemoryConnector):
        def capabilities(self):
            return {"query"}

        def query(self, collection, vector, top_k=10, where=None):
            return [QueryHit(id="1", score=1.0, text=NAMES, metadata={})]

    conn = Queryable([Chunk(id="1", collection="notes", text=NAMES, embedding=[0.1, 0.2])])
    job = probe_retrieval_exposure(conn, "notes", classifier=degraded)
    outcome = job.stats["check_outcomes"][0]
    assert outcome["coverage"]["complete"] is False
    assert outcome["coverage"]["nlp_status"] == "degraded"
    assert "NLP" in outcome["reason"]


# ---- classification never opens a network connection ----------------------

def _installed(model: str) -> bool:
    from importlib import util

    return util.find_spec(model) is not None


needs_sm = pytest.mark.skipif(not _installed("en_core_web_sm"),
                              reason="en_core_web_sm is not installed")


@pytest.fixture
def blocked_network(monkeypatch, tmp_path):
    """Refuse and record every outbound connection; start with empty caches,
    as a fresh host or container would."""
    attempts: list = []

    def connect(self, address, *args, **kwargs):
        attempts.append(("connect", address))
        raise OSError("network blocked by test")

    real_getaddrinfo = socket.getaddrinfo

    def getaddrinfo(host, *args, **kwargs):
        if host not in (None, "localhost", "127.0.0.1", "::1"):
            attempts.append(("getaddrinfo", host))
            raise socket.gaierror("network blocked by test")
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setenv("TLDEXTRACT_CACHE", str(tmp_path / "tld"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    for name in ("HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE"):
        # setenv first so teardown restores the original state, including absence.
        monkeypatch.setenv(name, "unset-by-test")
        monkeypatch.delenv(name)
    # A process that has not yet resolved any domain: the library's default
    # extractor, with nothing loaded.
    import tldextract.tldextract as tld

    monkeypatch.setattr(tld, "TLD_EXTRACTOR", tld.TLDExtract())
    return attempts


EMAILS = ["Contact Alice Johnson at alice.johnson@example.org about the refund.",
          "Server www.corp-intranet.example.com; email bob@sub.domain.example.net"]


@needs_sm
def test_community_presidio_classifies_email_without_network(blocked_network):
    from vecshield.classify.presidio_classifier import PresidioClassifier

    clf = PresidioClassifier(model="en_core_web_sm", extra_models={})
    single = clf.classify(EMAILS[0])
    batch = clf.classify_batch(EMAILS)
    assert blocked_network == []
    assert "presidio:EMAIL_ADDRESS" in single.detectors
    assert all("presidio:EMAIL_ADDRESS" in r.detectors for r in batch)


@needs_sm
def test_enterprise_scan_classifier_opens_no_connection(blocked_network, monkeypatch):
    import os

    monkeypatch.setenv("VECSHIELD_NER_MODELS", "none")
    clf = build_classifier(model="en_core_web_sm")
    assert clf.detection_metadata()["status"] == "ready"
    clf.classify(EMAILS[0])
    clf.classify_batch(EMAILS)
    assert blocked_network == []
    # Model loading is pinned offline as well.
    assert os.environ.get("HF_HUB_OFFLINE") == "1"
    assert os.environ.get("TRANSFORMERS_OFFLINE") == "1"


# ---- loaded non-English NER models are used ---------------------------------

needs_de = pytest.mark.skipif(not (_installed("en_core_web_sm") and _installed("de_core_news_sm")),
                              reason="en_core_web_sm and de_core_news_sm are required")

GERMAN = ("Frau Anna Schmidt wohnt in der Hauptstrasse in München und ist nicht mit dem "
          "Auto unterwegs, die Stadt wird auch eine neue Schule mit den Kindern bauen "
          "und das ist gut.")
ENGLISH = "Alice Johnson moved to Boston last spring and works at the city library."


def _person_texts(text, result):
    return sorted(text[s["start"]:s["end"]] for s in result.spans or []
                  if s["detector"] == "presidio:PERSON")


class _LanguageSpy:
    """Wraps an analyzer to record which language each text was analysed in."""

    def __init__(self, inner, calls):
        self.inner, self.calls = inner, calls

    def analyze(self, text, language, **kwargs):
        self.calls.append((text[:12], language))
        return self.inner.analyze(text=text, language=language, **kwargs)

    def analyze_iterator(self, texts, language, **kwargs):
        texts = list(texts)
        self.calls.extend((t[:12], language) for t in texts)
        return self.inner.analyze_iterator(texts, language=language, **kwargs)


@pytest.fixture(scope="module")
def german_models():
    import os

    previous = os.environ.get("VECSHIELD_NER_MODELS")
    os.environ["VECSHIELD_NER_MODELS"] = "de=de_core_news_sm"
    try:
        from vecshield.classify.presidio_classifier import PresidioClassifier

        enterprise = detection._build_nlp("en_core_web_sm")
        community = PresidioClassifier(model="en_core_web_sm")
    finally:
        if previous is None:
            os.environ.pop("VECSHIELD_NER_MODELS", None)
        else:
            os.environ["VECSHIELD_NER_MODELS"] = previous
    assert enterprise.languages == community.languages == ("de", "en")
    return {"enterprise": enterprise, "community": community}


@needs_de
@pytest.mark.parametrize("which", ["enterprise", "community"])
def test_german_text_is_analysed_with_the_german_model(german_models, which, monkeypatch):
    clf = german_models[which]
    calls: list = []
    monkeypatch.setattr(clf, "_analyzer", _LanguageSpy(clf._analyzer, calls))
    monkeypatch.setattr(clf, "_batch_analyzer", _LanguageSpy(clf._batch_analyzer, calls))
    single = clf.classify(GERMAN)
    batch = clf.classify_batch([GERMAN, None, ENGLISH, GERMAN])
    assert ("Frau Anna Sc", "de") in calls and ("Alice Johnso", "en") in calls
    assert all(lang == "de" for text, lang in calls if text.startswith("Frau"))
    # Order is preserved across the language groups, and empty text is NONE.
    assert batch[1].label == SensitivityLabel.NONE
    assert _person_texts(GERMAN, batch[0]) == _person_texts(GERMAN, batch[3]) \
        == _person_texts(GERMAN, single)
    assert "Anna Schmidt" in _person_texts(GERMAN, single)
    # The English model misreads German words as people; the German one does not.
    assert "Kindern" not in _person_texts(GERMAN, single)
    assert "Alice Johnson" in _person_texts(ENGLISH, batch[2])


@needs_de
def test_a_loaded_german_model_closes_the_language_gap_it_covers(german_models, ready):
    german = german_models["enterprise"]
    with_de = detection.EnterpriseClassifier(mode="required", model="en_core_web_sm",
                                             nlp=german)
    assert with_de.detection_metadata()["ner_languages"] == ["de", "en"]
    conn = MemoryConnector([Chunk(id=str(i), collection="notes", text=GERMAN)
                            for i in range(3)])
    covered = _classification(scan_store(conn, classifier=with_de))
    assert "not in English" not in covered["reason"]
    assert "ner_languages" not in covered["reason"]
    # The same collection read by an English-only NER layer reports the gap.
    english_only = _classification(scan_store(conn, classifier=ready))
    assert english_only["coverage"]["complete"] is False
    assert "not in English" in english_only["reason"]


# ---- detection status does not read ready before a load ----------------------

def test_installed_transformer_model_missing_its_runtime_is_not_ready(monkeypatch):
    real_version = detection._version
    monkeypatch.setenv("VECSHIELD_NLP_MODE", "auto")
    monkeypatch.setattr(detection, "_model_installed", lambda model: True)
    monkeypatch.setattr(detection, "_version",
                        lambda p: None if p == "spacy-curated-transformers" else real_version(p))
    status = detection.detection_status()
    assert status["requested_model"] == "en_core_web_trf"
    assert status["status"] == "degraded" and status["nlp_available"] is False
    assert "spacy-curated-transformers" in status["reason"]
    monkeypatch.setenv("VECSHIELD_NLP_MODE", "required")
    assert detection.detection_status()["status"] == "unavailable"


def test_status_is_unverified_until_a_load_succeeds(monkeypatch):
    monkeypatch.setenv("VECSHIELD_NLP_MODEL", "en_core_web_sm")
    monkeypatch.setattr(detection, "_model_installed", lambda model: True)
    before = detection.detection_status()
    assert before["status"] == "unverified"
    assert before["nlp_available"] is True and before["nlp_loaded"] is False
    assert "not been loaded" in before["reason"]
    monkeypatch.setattr(detection, "_build_nlp", lambda model: QuietNlp())
    build_classifier()
    after = detection.detection_status()
    assert after["status"] == "ready" and after["nlp_loaded"] is True


def test_a_model_whose_runtime_is_missing_is_refused_before_loading(monkeypatch):
    real_version = detection._version
    monkeypatch.setattr(detection, "_model_installed", lambda model: True)
    monkeypatch.setattr(detection, "_version",
                        lambda p: None if p == "spacy-transformers" else real_version(p))
    with pytest.raises(detection.DetectionUnavailableError, match="spacy-transformers"):
        detection._build_nlp("en_core_web_hftrf")
