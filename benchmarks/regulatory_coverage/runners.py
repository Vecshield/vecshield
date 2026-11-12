"""Classifiers under test, behind one protocol.

The comparison this benchmark exists for is not "which tool finds more spans".
It is "which tool would answer the regulator's question", and the honest
version of that has to account for a fact the leaderboard hides: **most
candidates have no label for most of these categories.**

A fixed-label model trained on an email/phone/SSN taxonomy cannot report trade
union membership at any threshold. It will score zero on GDPR Art. 9 not
because it is inaccurate but because the category is not in its vocabulary,
and a benchmark that reports that as "0.00 recall" without saying so is
misleading in the tool's favour on every other row. So each runner declares
which of our categories it can express, and the report separates *missed* from
*cannot express*.

Every runner is optional. A dependency that is not installed yields an
unavailable runner with the reason, never an import error at module load: the
regex layer is the only thing guaranteed present in a checkout.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from benchmarks.ai4privacy.normalize.schema import CATEGORIES, Annotation


@dataclass
class Availability:
    ok: bool
    reason: str = ""
    detail: str = ""


@runtime_checkable
class Runner(Protocol):
    """A classifier that can be scored against the corpus."""

    name: str

    def availability(self) -> Availability: ...

    def expressible(self) -> frozenset[str]:
        """Categories this classifier has any label for."""
        ...

    def predict(self, texts: list[str]) -> list[list[Annotation]]: ...


# --------------------------------------------------------------------------- #
# VecShield                                                                    #
# --------------------------------------------------------------------------- #
@dataclass
class VecShieldRunner:
    """The shipped engine: regex detectors, plus NER when it is installed."""

    use_nlp: bool = False
    #: Which spaCy model the NER layer runs. Left as None the product's own
    #: default applies. The benchmark sets it to the same model Presidio
    #: standalone uses, so the two differ in orchestration rather than in the
    #: NER model underneath — otherwise the comparison measures the model
    #: choice and reports it as a difference between the tools.
    model: str | None = None
    name: str = field(default="vecshield")

    def __post_init__(self) -> None:
        self.name = "vecshield+nlp" if self.use_nlp else "vecshield-regex"
        if self.use_nlp and self.model:
            self.name = f"vecshield+nlp[{self.model}]"

    def availability(self) -> Availability:
        try:
            from vecshield.classify.regex_classifier import RegexClassifier  # noqa: F401
        except Exception as exc:  # noqa: BLE001
            return Availability(False, f"vecshield not importable: {exc}")
        if not self.use_nlp:
            return Availability(True)
        # Deliberately does not set VECSHIELD_NLP_MODEL. An earlier version
        # did, and because `availability()` is called on every runner during
        # discovery, it left the variable set for the rest of the process --
        # which contaminated unrelated tests in the shared suite. A benchmark
        # runner must not reconfigure the product globally just to ask whether
        # it could run. The model is passed explicitly to `build_classifier`
        # in `predict` instead.
        from vecshield_platform.detection import _model_installed, detection_status

        status = detection_status()
        if not (status.get("spacy_version") and status.get("presidio_version")):
            return Availability(
                False, status.get("reason", "spacy/presidio not installed"))
        model = self.model or status.get("requested_model")
        if not _model_installed(str(model)):
            return Availability(False, f"spaCy model {model!r} is not installed")
        return Availability(True, detail=f"model {model}")

    def expressible(self) -> frozenset[str]:
        # The engine has a label for every category in the schema, which is
        # the point of the taxonomy work: the comparison is on accuracy, not
        # on vocabulary.
        return frozenset(CATEGORIES)

    def predict(self, texts: list[str]) -> list[list[Annotation]]:
        # Both modes go through the shipped factory rather than instantiating
        # RegexClassifier directly. The bare regex layer does not apply the
        # PII->PHI context upgrade, so a date of birth in a discharge letter
        # comes back labelled PII and the benchmark scored the product as
        # missing three PHI spans it does in fact report. Benchmarking a path
        # no customer runs is worse than not benchmarking at all.
        from vecshield_platform.detection import build_classifier

        classifier = build_classifier(use_nlp=self.use_nlp, model=self.model)
        return [_spans_to_annotations(classifier.classify(t)) for t in texts]


def _spans_to_annotations(result) -> list[Annotation]:
    out: list[Annotation] = []
    for span in result.spans:
        category = str(span.get("label", "")).upper()
        if category not in CATEGORIES:
            continue
        out.append(Annotation(
            start=int(span.get("start", 0)), end=int(span.get("end", 0)),
            entity_type=category, subtype=str(span.get("detector", "")),
            text=str(span.get("preview", "")), score=1.0))
    return out


# --------------------------------------------------------------------------- #
# Microsoft Presidio, standalone                                               #
# --------------------------------------------------------------------------- #
#: Presidio's entity types, mapped onto the schema. Everything it can say is
#: PII or PCI; it has no vocabulary for Art. 9, Art. 10 or credentials.
PRESIDIO_MAP = {
    "PERSON": "PII", "EMAIL_ADDRESS": "PII", "PHONE_NUMBER": "PII",
    "LOCATION": "PII", "US_SSN": "PII", "US_DRIVER_LICENSE": "PII",
    "US_PASSPORT": "PII", "IP_ADDRESS": "PII", "NRP": "PII",
    "URL": "PII", "DATE_TIME": "PII", "US_ITIN": "PII",
    "CREDIT_CARD": "PCI", "US_BANK_NUMBER": "PCI", "IBAN_CODE": "PCI",
    "CRYPTO": "PCI", "MEDICAL_LICENSE": "PHI", "UK_NHS": "PHI",
}


@dataclass
class PresidioRunner:
    """The incumbent free baseline, run on its own rather than inside ours."""

    model: str = "en_core_web_lg"
    name: str = "presidio"

    def availability(self) -> Availability:
        try:
            import presidio_analyzer  # noqa: F401
            import spacy  # noqa: F401
        except Exception as exc:  # noqa: BLE001
            return Availability(False, f"presidio-analyzer/spacy not installed: {exc}")
        return Availability(True, detail=f"model {self.model}")

    def expressible(self) -> frozenset[str]:
        return frozenset(PRESIDIO_MAP.values())

    def predict(self, texts: list[str]) -> list[list[Annotation]]:
        import spacy
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import SpacyNlpEngine

        nlp = spacy.load(self.model)
        engine = SpacyNlpEngine(models=[{"lang_code": "en", "model_name": self.model}])
        engine.nlp = {"en": nlp}  # type: ignore[attr-defined]
        analyzer = AnalyzerEngine(nlp_engine=engine, supported_languages=["en"])
        out: list[list[Annotation]] = []
        for text in texts:
            spans: list[Annotation] = []
            for r in analyzer.analyze(text=text, language="en"):
                category = PRESIDIO_MAP.get(r.entity_type)
                if category:
                    spans.append(Annotation(
                        start=r.start, end=r.end, entity_type=category,
                        subtype=r.entity_type, text=text[r.start:r.end],
                        score=float(r.score)))
            out.append(spans)
        return out


# --------------------------------------------------------------------------- #
# GLiNER — zero-shot, open vocabulary                                          #
# --------------------------------------------------------------------------- #
#: The reason a zero-shot model is interesting here: the label is a phrase, so
#: categories no fixed-label model covers can simply be asked for.
GLINER_LABELS: dict[str, str] = {
    "person name": "PII",
    "email address": "PII",
    "phone number": "PII",
    "national identification number": "PII",
    "date of birth": "PII",
    "medical record number": "PHI",
    "medical condition or diagnosis": "PHI",
    "credit card number": "PCI",
    "bank account number": "PCI",
    "api key or password": "SECRET",
    "trade union membership": "SPECIAL_CATEGORY",
    "sexual orientation": "SPECIAL_CATEGORY",
    "political affiliation": "SPECIAL_CATEGORY",
    "religious belief": "SPECIAL_CATEGORY",
    "racial or ethnic origin": "SPECIAL_CATEGORY",
    "genetic information": "SPECIAL_CATEGORY",
    "biometric identifier": "SPECIAL_CATEGORY",
    "criminal conviction": "CRIMINAL_OFFENCE",
}


@dataclass
class GlinerRunner:
    model: str = "urchade/gliner_multi_pii-v1"
    threshold: float = 0.5
    name: str = "gliner"

    def availability(self) -> Availability:
        try:
            from gliner import GLiNER  # noqa: F401
        except Exception as exc:  # noqa: BLE001
            return Availability(False, f"gliner not installed: {exc}")
        return Availability(True, detail=f"model {self.model}")

    def expressible(self) -> frozenset[str]:
        return frozenset(GLINER_LABELS.values())

    def predict(self, texts: list[str]) -> list[list[Annotation]]:
        from gliner import GLiNER

        model = GLiNER.from_pretrained(self.model)
        labels = list(GLINER_LABELS)
        out: list[list[Annotation]] = []
        for text in texts:
            spans: list[Annotation] = []
            for e in model.predict_entities(text, labels, threshold=self.threshold):
                category = GLINER_LABELS.get(e["label"])
                if category:
                    spans.append(Annotation(
                        start=int(e["start"]), end=int(e["end"]),
                        entity_type=category, subtype=str(e["label"]),
                        text=str(e.get("text", "")), score=float(e.get("score", 1.0))))
            out.append(spans)
        return out


# --------------------------------------------------------------------------- #
# A fine-tuned token classifier (Piiranha, deberta-pii, starpii, ...)           #
# --------------------------------------------------------------------------- #
@dataclass
class TokenClassifierRunner:
    """Any HuggingFace token-classification model with a PII label set.

    `label_map` has to be supplied per model, because every one of them names
    its labels differently and guessing the mapping is how a benchmark quietly
    scores the wrong thing.
    """

    model: str = "iiiorg/piiranha-v1-detect-personal-information"
    label_map: dict[str, str] = field(default_factory=dict)
    name: str = "token-classifier"

    def availability(self) -> Availability:
        try:
            import transformers  # noqa: F401
        except Exception as exc:  # noqa: BLE001
            return Availability(False, f"transformers not installed: {exc}")
        if not self.label_map:
            return Availability(
                False,
                "no label_map supplied; a model's own label names must be "
                "mapped explicitly rather than guessed")
        return Availability(True, detail=f"model {self.model}")

    def expressible(self) -> frozenset[str]:
        return frozenset(self.label_map.values())

    def predict(self, texts: list[str]) -> list[list[Annotation]]:
        from transformers import pipeline

        ner = pipeline("token-classification", model=self.model,
                       aggregation_strategy="simple")
        out: list[list[Annotation]] = []
        for text in texts:
            spans: list[Annotation] = []
            for e in ner(text):
                category = self.label_map.get(str(e.get("entity_group", "")))
                if category:
                    spans.append(Annotation(
                        start=int(e["start"]), end=int(e["end"]),
                        entity_type=category, subtype=str(e.get("entity_group", "")),
                        text=str(e.get("word", "")), score=float(e.get("score", 1.0))))
            out.append(spans)
        return out


# --------------------------------------------------------------------------- #
# Jev — TypeSafe AI's System One model                                         #
# --------------------------------------------------------------------------- #
#: Jev is not an LLM and not a span tagger. It takes a block of state and a set
#: of *typed questions*, and returns a typed answer per question with a
#: calibrated probability — no text generation, nothing to parse. PII detection
#: is one of the applications TypeSafe names.
#:
#: That shape is a genuine fit for this product, and for a reason that has
#: nothing to do with speed. Every detector here reports confidence
#: `uncertain`, with the reason "no measured precision on the benchmark", and
#: the Actions page refuses irreversible remediation on that basis. A model
#: whose output is a *calibrated* probability is the shape of thing that could
#: move a detection off that class. Whether Jev's calibration survives our
#: distribution is exactly what this benchmark would measure.
#:
#: It is asked one question per category rather than "find the spans", because
#: that is the interface. The consequence for scoring is stated in
#: `expressible()`: document-level answers cannot be matched against character
#: offsets, so a Jev run is scored as detection-or-not per case, not per span.
JEV_QUESTIONS: dict[str, str] = {
    "PII": "Does this text contain personal data identifying a living individual?",
    "PHI": "Does this text contain health information about an identifiable person?",
    "PCI": "Does this text contain payment card or financial account data?",
    "SECRET": "Does this text contain a credential, API key, token or password?",
    "SPECIAL_CATEGORY": (
        "Does this text reveal racial or ethnic origin, political opinions, "
        "religious beliefs, trade union membership, genetic or biometric data, "
        "health, or sexual orientation?"),
    "CRIMINAL_OFFENCE": (
        "Does this text concern a criminal conviction, offence or related "
        "security measure?"),
}


@dataclass
class JevRunner:
    """TypeSafe AI's hosted Jev. Proprietary: needs an API key.

    Jev is not open source and has no open weights, so this cannot be run from
    a checkout alone. The runner exists so that the moment an key is available
    the same 48 cases can be scored against it without anyone rebuilding a
    harness — and so that its absence is reported as "no credential" rather
    than as a missing capability.
    """

    api_key_env: str = "TYPESAFE_API_KEY"
    model: str = "jev-1"
    name: str = "jev"

    def availability(self) -> Availability:
        import os

        try:
            import typesafe  # noqa: F401
        except Exception:  # noqa: BLE001
            return Availability(
                False,
                "typesafe client not installed; Jev is proprietary (no open "
                "weights) and is reachable only through TypeSafe's API")
        if not os.environ.get(self.api_key_env):
            return Availability(False, f"{self.api_key_env} is not set")
        return Availability(True, detail=f"model {self.model}")

    def expressible(self) -> frozenset[str]:
        # Every category, because the question is an input rather than a fixed
        # label — the same property that makes zero-shot NER interesting here.
        return frozenset(JEV_QUESTIONS)

    def predict(self, texts: list[str]) -> list[list[Annotation]]:
        """Document-level answers, widened to a whole-text span.

        Jev returns a decision about the text, not offsets within it. Emitting
        a span covering the document means an overlap match succeeds whenever
        the category is right, which scores recall honestly and makes
        localisation incomparable. A report that mixed this with span-level
        runners without saying so would be comparing two different tasks.
        """
        import os

        from typesafe import TypeSafe  # type: ignore[import-not-found]

        client = TypeSafe(api_key=os.environ[self.api_key_env])
        out: list[list[Annotation]] = []
        for text in texts:
            spans: list[Annotation] = []
            for category, question in JEV_QUESTIONS.items():
                answer = client.decide(model=self.model, state=text,
                                       question=question, type="bool")
                if bool(getattr(answer, "value", False)):
                    spans.append(Annotation(
                        start=0, end=len(text), entity_type=category,
                        subtype="jev", text="",
                        score=float(getattr(answer, "confidence", 1.0))))
            out.append(spans)
        return out


@dataclass
class OpenJevRunner:
    """`kyegomez/open-jev` — Apache 2.0, and **untrained**.

    Included deliberately rather than omitted. It is the only open-source Jev
    there is, so "is an open-source Jev good at classifying personal data" has
    to be answered against it, and the answer is that it ships random weights:
    its own README says "this is an unofficial research implementation with
    random weights. It is not the production Jev model."

    Running it therefore measures nothing about Jev. What it does do is make
    that concrete instead of asserted — the report shows the outputs moving
    between runs on identical input, which no trained classifier does.
    """

    name: str = "open-jev (untrained)"

    def availability(self) -> Availability:
        try:
            import open_jev  # noqa: F401
        except Exception as exc:  # noqa: BLE001
            return Availability(False, f"open-jev not installed: {exc}")
        return Availability(
            True,
            detail="WARNING: random weights; any score is noise, not accuracy")

    def expressible(self) -> frozenset[str]:
        return frozenset(JEV_QUESTIONS)

    def predict(self, texts: list[str]) -> list[list[Annotation]]:
        raise NotImplementedError(
            "open-jev has random weights. Scoring it would produce a number "
            "that looks like an accuracy result and is not one. Train it "
            "first, or use the hosted model.")


def default_runners() -> list[Runner]:
    """Everything worth comparing, whether or not it is installed here."""
    return [
        VecShieldRunner(use_nlp=False),
        VecShieldRunner(use_nlp=True, model="en_core_web_lg"),
        PresidioRunner(),
        GlinerRunner(),
        TokenClassifierRunner(),
        JevRunner(),
        OpenJevRunner(),
    ]
