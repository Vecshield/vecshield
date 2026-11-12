"""Presidio-backed classifier — adds NER recall for the entities regex can't
catch reliably: person names, locations, addresses, medical license numbers.

Presidio + a spaCy model are heavy and optional. The classifier imports them
lazily and `available()` lets the ensemble degrade gracefully when they're
absent (regex-only). Install with: pip install 'vecshield[nlp]'
"""

from __future__ import annotations

import re
from collections import OrderedDict
from collections.abc import Iterable
from typing import Any, cast

from vecshield.classify.base import PHI_CONTEXT as _PHI_CONTEXT
from vecshield.classify.base import Classifier
from vecshield.classify.language import detect as detect_language
from vecshield.models import Classification, SensitivityLabel

#: Small spaCy models for the languages the language detector can recognise.
#: Small rather than large on purpose: this is about covering text that is
#: currently not looked at at all, and a small model that finds most names
#: beats a large one nobody installs. Override per language with
#: ``VECSHIELD_NER_MODELS="de=de_core_news_lg,fr=fr_core_news_lg"``.
DEFAULT_EXTRA_MODELS: dict[str, str] = {
    "de": "de_core_news_sm",
    "fr": "fr_core_news_sm",
    "es": "es_core_news_sm",
    "it": "it_core_news_sm",
    "nl": "nl_core_news_sm",
    "pt": "pt_core_news_sm",
    "pl": "pl_core_news_sm",
    "sv": "sv_core_news_sm",
}


def pin_offline_runtime() -> None:
    """Keep classification and model loading on this host.

    Two dependencies reach for the network by default. Presidio's e-mail
    recognizer validates each match with ``tldextract``, whose default
    extractor downloads the Public Suffix List the first time it runs -- in
    the middle of a scan, and, on a host whose egress is silently dropped,
    after a long timeout. The bundled snapshot answers the same question
    offline, so the default extractor is replaced with one that reads only
    the snapshot and writes no cache. Hugging Face loaders (transformer spaCy
    pipelines) are told to stay offline unless the operator already chose.
    Idempotent and cheap; safe to call before every model load.
    """
    import os

    os.environ.setdefault("HF_HUB_OFFLINE", "1")
    os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
    try:
        import tldextract.tldextract as tld
    except ImportError:  # pragma: no cover - presidio depends on it
        return
    current = getattr(tld, "TLD_EXTRACTOR", None)
    if getattr(current, "_vecshield_offline", False):
        return
    extractor = tld.TLDExtract(cache_dir=None, suffix_list_urls=(),
                               fallback_to_snapshot=True)
    extractor._vecshield_offline = True  # type: ignore[attr-defined]
    tld.TLD_EXTRACTOR = extractor


def resolve_extra_models() -> dict[str, str]:
    """Which non-English models to try, honouring the environment override."""
    import os

    raw = os.environ.get("VECSHIELD_NER_MODELS", "").strip()
    if not raw:
        return dict(DEFAULT_EXTRA_MODELS)
    if raw.lower() in {"none", "off", "0"}:
        return {}
    chosen: dict[str, str] = {}
    for pair in raw.split(","):
        lang, _, model = pair.partition("=")
        if lang.strip() and model.strip():
            chosen[lang.strip()] = model.strip()
    return chosen


def choose_language(text: str | None, supported: Iterable[str]) -> str:
    """Pick the analyzer language for one chunk.

    English is the fallback for everything, and deliberately so: when the
    language cannot be identified -- which is most short metadata values --
    running the English model is what the product did before, and abstaining
    would silently drop detection it used to have. A non-English model is used
    only when the text was positively identified *and* that model is loaded.
    """
    available = set(supported)
    detected = detect_language(text)
    if detected and detected in available:
        return detected
    return "en"

# Presidio entity type -> our sensitivity label.
_ENTITY_LABEL = {
    "PERSON": SensitivityLabel.PII,
    "EMAIL_ADDRESS": SensitivityLabel.PII,
    "PHONE_NUMBER": SensitivityLabel.PII,
    "LOCATION": SensitivityLabel.PII,
    "US_SSN": SensitivityLabel.PII,
    "US_DRIVER_LICENSE": SensitivityLabel.PII,
    "US_PASSPORT": SensitivityLabel.PII,
    "IP_ADDRESS": SensitivityLabel.PII,
    # GDPR Article 9 special categories: racial/ethnic origin, political
    # opinions, religious/philosophical beliefs, trade union membership.
    # SpacyRecognizer maps spaCy NORP labels to NRP natively.
    "NRP": SensitivityLabel.PII,
    # Employer/covered-entity names: PII under GDPR (profiling), PHI under
    # HIPAA when a healthcare provider name is linked to a patient record.
    # PHI upgrade is applied automatically via _PHI_CONTEXT (same as PERSON).
    "ORGANIZATION": SensitivityLabel.PII,
    # URLs can embed PII in paths/query params (OAuth tokens, profile links,
    # reset links with user identifiers, webhook URLs with secrets).
    "URL": SensitivityLabel.PII,
    # DATE_TIME: noisy alone; conditionally upgraded to PHI when health
    # context is present (HIPAA Safe Harbor identifier #3 — dates related to
    # an individual).  Kept as NONE here so it is excluded from the default
    # entity request; added back explicitly in _REQUESTED_ENTITIES below.
    "DATE_TIME": SensitivityLabel.NONE,
    "CREDIT_CARD": SensitivityLabel.PCI,
    "US_BANK_NUMBER": SensitivityLabel.PCI,
    "IBAN_CODE": SensitivityLabel.PCI,
    "MEDICAL_LICENSE": SensitivityLabel.PHI,
}

# Only ask Presidio for the entity types we actually consume.  Passing an
# explicit ``entities`` list to ``analyze()`` skips unused recognizers
# (US_ITIN, CRYPTO, MAC_ADDRESS, UK_NHS — covered by regex — and others)
# giving a meaningful speedup with zero accuracy loss on final output.
# DATE_TIME maps to NONE in _ENTITY_LABEL (too noisy as a standalone signal)
# but is appended here so classify() can upgrade it to PHI when
# _PHI_CONTEXT fires (HIPAA identifier #3).
_REQUESTED_ENTITIES: list[str] = [
    entity
    for entity, label in _ENTITY_LABEL.items()
    if label is not SensitivityLabel.NONE
] + ["DATE_TIME"]

#: Entity types a statistical NER model produces (spaCy labels mapped by
#: Presidio). The rest of ``_ENTITY_LABEL`` comes from Presidio's pattern
#: recognizers. The ingest gate treats a span of one of these types, found by
#: the model alone, as weaker evidence than a pattern match.
NER_ENTITY_TYPES: frozenset[str] = frozenset(
    {"PERSON", "LOCATION", "ORGANIZATION", "NRP", "DATE_TIME"})

#: Every entity type this adapter can map, i.e. the accepted values of
#: ``VECSHIELD_NLP_ENTITIES``.
SUPPORTED_ENTITIES: tuple[str, ...] = tuple(sorted(_ENTITY_LABEL))


def resolve_requested_entities(raw: str | None = None) -> list[str]:
    """The entity types to ask Presidio for.

    ``VECSHIELD_NLP_ENTITIES`` (comma-separated) overrides the default, for
    example to drop ``ORGANIZATION`` where company and product names are not
    personal data for the deployment. An unknown name is a configuration error,
    not something to ignore: a typo would otherwise silently narrow detection.
    ``DATE_TIME`` only ever yields PHI dates in clinical context; leave it out
    and those dates are found only by the date pattern.
    """
    import os

    value = os.environ.get("VECSHIELD_NLP_ENTITIES", "") if raw is None else raw
    names = [part.strip().upper() for part in value.split(",") if part.strip()]
    if not names:
        return list(_REQUESTED_ENTITIES)
    unknown = sorted(set(names) - set(_ENTITY_LABEL))
    if unknown:
        raise ValueError(
            f"VECSHIELD_NLP_ENTITIES names unknown entity type(s) {', '.join(unknown)}; "
            f"supported: {', '.join(SUPPORTED_ENTITIES)}")
    return list(dict.fromkeys(names))


def normalise_allow_term(term: str) -> str:
    """Allow-list matching is case-insensitive and whitespace-insensitive."""
    return " ".join(term.split()).casefold()


def resolve_allow_list(raw: str | None = None, path: str | None = None) -> frozenset[str]:
    """Terms the NER layer must never report (product, brand, fictional names).

    ``VECSHIELD_NLP_ALLOW_LIST`` is a comma-separated list and
    ``VECSHIELD_NLP_ALLOW_LIST_FILE`` a file with one term per line (``#``
    starts a comment); both may be set and are combined. A term suppresses a
    Presidio span whose text equals it, ignoring case and spacing -- the
    ``allow_list`` semantics of Presidio's analyzer. Pattern (regex) detectors
    are unaffected, so allow-listing a name never hides an e-mail address or a
    card number. A file that cannot be read raises: an allow-list that was
    meant to apply and silently did not would change results unannounced.
    """
    import os

    value = os.environ.get("VECSHIELD_NLP_ALLOW_LIST", "") if raw is None else raw
    terms = [part for part in value.split(",")]
    file_path = os.environ.get("VECSHIELD_NLP_ALLOW_LIST_FILE", "") if path is None else path
    if file_path.strip():
        with open(file_path.strip(), encoding="utf-8") as handle:
            terms.extend(line.split("#", 1)[0] for line in handle)
    return frozenset(normalised for term in terms if (normalised := normalise_allow_term(term)))

# Default spaCy model. Larger = more accurate NER, slower on CPU:
#   en_core_web_sm (12MB) < en_core_web_md (43MB) < en_core_web_lg (560MB).
_DEFAULT_MODEL = "en_core_web_lg"

# spaCy pipeline components Presidio does not consume for PII detection.  We
# drop the dependency ``parser`` (the most expensive component) plus the
# unused ``senter``/``morphologizer``, which cuts a large chunk off the spaCy
# call.  We deliberately KEEP ``tagger`` + ``attribute_ruler`` + ``lemmatizer``:
# Presidio's context-aware score enhancer is *lemma-based*, so removing the
# lemmatizer silently drops context-boosted scores (e.g. a phone number next to
# the word "phone" falls 0.75 -> 0.40, below the score floor, and disappears).
# Keeping them preserves accuracy while still skipping the parser.
_EXCLUDE_PIPES = ["parser", "senter", "morphologizer"]

# Default per-entity confidence floor — Presidio scores below this are dropped.
_SCORE_FLOOR = 0.5

# Calibration multipliers applied to Presidio confidence scores before they
# are used as the document-level signal.  These are set below 1.0 for entity
# types that frequently fire on genuinely-negative documents (e.g. a name
# mentioned in passing), so that regex-only hits always rank higher than
# NLP-only hits in the document-level ROC-AUC.  Entities not listed here
# are passed through unchanged (multiplier = 1.0).
_CALIBRATION: dict[str, float] = {
    "PERSON": 0.65,  # very common false positive on any mention of a name
    "LOCATION": 0.60,  # GPE/LOC fires on city/country names in non-PII text
    "PHONE_NUMBER": 0.75,  # Presidio phone patterns have moderate noise
    "US_SSN": 0.85,  # Presidio's own SSN patterns are fairly precise
    "NRP": 0.60,  # fires on nationality adjectives ("American", "French")
    "ORGANIZATION": 0.65,  # org mentions are often non-PII context
    "URL": 0.85,  # UrlRecognizer is fairly precise
    "DATE_TIME": 0.80,  # only emitted in PHI context; moderate precision
}

# Lightweight PHI context (``_PHI_CONTEXT``) lives in ``base`` so the ensemble
# can apply the same PII→PHI rule to regex spans; imported at module top.

# A date is PHI only when it is *more specific than a year* and tied to an
# individual (HIPAA Safe Harbor identifier #3).  A bare year, an age, or a
# duration ("2021", "over 60", "6-month") is NOT an identifier — but spaCy tags
# all of them DATE_TIME.  This pattern flags a DATE_TIME span as PHI only when it
# contains a month name + day, or a numeric M/D(/Y), or an ISO date; bare-year /
# duration DATE_TIME spans are dropped, which is the main over-redaction guard on
# the clinically-loaded hard negatives.
_SPECIFIC_DATE = re.compile(
    r"\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.?\s+"
    r"\d{1,2}(?:st|nd|rd|th)?\b"
    r"|\b\d{1,2}[/-]\d{1,2}(?:[/-]\d{2,4})?\b"
    r"|\b\d{4}-\d{2}-\d{2}\b",
    re.IGNORECASE,
)

# Full calendar dates spaCy's DATE_TIME recognizer frequently misses entirely —
# abbreviated months ("Feb 21, 2023"), ordinal days ("May 30th, 2022"), numeric
# forms ("4/3/2023").  Emitted as PHI only under the _PHI_CONTEXT gate.  A day
# component is required (no bare years), for the same reason as _SPECIFIC_DATE.
_FULL_DATE = re.compile(
    r"\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.?\s+"
    r"\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4}\b"
    r"|\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b"
    r"|\b\d{4}-\d{2}-\d{2}\b",
    re.IGNORECASE,
)
_DATE_SCORE = 0.6  # calibrated confidence for regex-recovered dates


def _redact(s: str) -> str:
    if len(s) <= 4:
        return "*" * len(s)
    return s[:2] + "*" * (len(s) - 4) + s[-2:]


class PresidioClassifier(Classifier):
    name = "presidio"

    def __init__(
        self,
        score_floor: float = _SCORE_FLOOR,
        calibration: dict[str, float] | None = None,
        model: str = _DEFAULT_MODEL,
        cache_size: int = 0,
        extra_models: dict[str, str] | None = None,
        entities: Iterable[str] | None = None,
        allow_list: Iterable[str] | None = None,
    ):
        # Configuration first, so a bad entity name or unreadable allow-list
        # fails before an expensive model load.
        self.entities: list[str] = (resolve_requested_entities() if entities is None
                                    else resolve_requested_entities(",".join(entities)))
        self.allow_list: frozenset[str] = (
            resolve_allow_list() if allow_list is None
            else frozenset(t for t in map(normalise_allow_term, allow_list) if t))
        pin_offline_runtime()
        import spacy  # lazy
        from presidio_analyzer import AnalyzerEngine, BatchAnalyzerEngine
        from presidio_analyzer.nlp_engine import SpacyNlpEngine

        self.model = model
        # Load spaCy with only the components the NER pipeline needs, then
        # inject the stripped model into a SpacyNlpEngine.  Setting ``nlp``
        # directly makes ``is_loaded()`` return True so AnalyzerEngine does not
        # reload the full (un-stripped) pipeline.
        nlp = spacy.load(model, exclude=_EXCLUDE_PIPES)
        specs = [{"lang_code": "en", "model_name": model}]
        loaded = {"en": nlp}
        # Additional languages, each optional. A model that is not installed is
        # skipped rather than raising: the deployment that has only English
        # must keep working exactly as before, and the coverage statement
        # already reports non-English text as text the name detectors did not
        # reach. Adding a model here narrows that gap; adding none changes
        # nothing.
        for lang, extra_model in sorted((extra_models or resolve_extra_models()).items()):
            if lang == "en":
                continue
            try:
                loaded[lang] = spacy.load(extra_model, exclude=_EXCLUDE_PIPES)
            except Exception:  # noqa: BLE001 - an absent model is not an error
                continue
            specs.append({"lang_code": lang, "model_name": extra_model})
        self.languages = tuple(sorted(loaded))
        nlp_engine = SpacyNlpEngine(models=specs)
        cast(Any, nlp_engine).nlp = loaded
        self._analyzer = AnalyzerEngine(
            nlp_engine=nlp_engine, supported_languages=list(self.languages)
        )
        # Batch wrapper reuses the same AnalyzerEngine (and its loaded spaCy
        # model) but feeds documents through ``nlp.pipe`` for a large speedup
        # when many texts are classified at once (see ``classify_batch``).
        self._batch_analyzer = BatchAnalyzerEngine(analyzer_engine=self._analyzer)
        self.score_floor = score_floor
        self._calibration: dict[str, float] = (
            calibration if calibration is not None else _CALIBRATION
        )
        # Optional bounded result cache (B4).  Disabled by default (size 0) so
        # existing behaviour is unchanged and there is no unbounded memory
        # growth.  Cached ``Classification`` objects are treated as immutable;
        # callers that mutate spans (e.g. redaction) must copy first.
        self._cache_size = max(0, int(cache_size))
        self._cache: OrderedDict[str, Classification] = OrderedDict()

    @staticmethod
    def available() -> bool:
        try:
            import presidio_analyzer  # noqa: F401
            import spacy  # noqa: F401

            return True
        except ImportError:
            return False

    def language_for(self, text: str | None) -> str:
        """The analyzer language for this chunk, from the models actually loaded."""
        return choose_language(text, self.languages)

    @property
    def requested_entities(self) -> list[str]:
        # getattr: instances built without __init__ (tests) keep the default.
        return getattr(self, "entities", None) or list(_REQUESTED_ENTITIES)

    def _allowed(self, text: str, result) -> bool:
        allow = getattr(self, "allow_list", None)
        return bool(allow) and normalise_allow_term(text[result.start:result.end]) in allow

    def classify(self, text: str | None) -> Classification:
        if not text:
            return Classification(SensitivityLabel.NONE, 0.0)

        cache_size = getattr(self, "_cache_size", 0)
        if cache_size:
            cached = self._cache.get(text)
            if cached is not None:
                self._cache.move_to_end(text)
                return cached

        try:
            results = self._analyzer.analyze(
                text=text, language=self.language_for(text),
                entities=self.requested_entities
            )
        except Exception:  # pragma: no cover - optional dependency runtime failure
            return Classification(SensitivityLabel.NONE, 0.0)

        classification = self._results_to_classification(text, results)
        if cache_size:
            self._cache[text] = classification
            self._cache.move_to_end(text)
            while len(self._cache) > cache_size:
                self._cache.popitem(last=False)
        return classification

    def classify_batch(
        self, texts: Iterable[str | None], spacy_batch_size: int = 64
    ) -> list[Classification]:
        """Classify many texts at once, streaming them through ``nlp.pipe``.

        This is functionally equivalent to calling :meth:`classify` on each
        element (same scores, spans and labels) but processes the batch through
        Presidio's :class:`BatchAnalyzerEngine`, which runs the spaCy model with
        ``nlp.pipe`` instead of one document at a time.  On CPU this is
        typically 2-4x faster for the NLP leg.  Order is preserved; ``None`` and
        empty strings yield a ``NONE`` classification without invoking spaCy.

        ``spacy_batch_size`` is the number of documents spaCy buffers per
        ``nlp.pipe`` step.  Larger values amortise per-call overhead better but
        use more memory; 32-256 is a sensible range on CPU.
        """
        items = list(texts)
        # Map non-empty texts to their original positions so we can scatter the
        # batch results back in order.
        indexed = [(i, t) for i, t in enumerate(items) if t]
        out: list[Classification] = [
            Classification(SensitivityLabel.NONE, 0.0) for _ in items
        ]
        if not indexed:
            return out
        batch_texts = [t for _, t in indexed]
        try:
            batch_results = self._analyze_batch(batch_texts, spacy_batch_size)
        except Exception:  # pragma: no cover - optional dependency runtime failure
            return out
        for (orig_idx, text), results in zip(indexed, batch_results, strict=True):
            out[orig_idx] = self._results_to_classification(text, results)
        return out

    def _analyze_batch(self, texts: list[str], spacy_batch_size: int = 64) -> list:
        """Analyzer results for each text, in order, each in its own language.

        Texts are grouped by :meth:`language_for` so a German chunk goes
        through the German model when one is loaded, exactly as
        :meth:`classify` would route it, and each group is streamed through
        ``nlp.pipe``. Exceptions propagate; callers decide how to surface them.
        """
        groups: dict[str, list[int]] = {}
        for position, text in enumerate(texts):
            groups.setdefault(self.language_for(text), []).append(position)
        results: list = [None] * len(texts)
        for language, positions in sorted(groups.items()):
            group = [texts[p] for p in positions]
            analysed = list(
                self._batch_analyzer.analyze_iterator(
                    group,
                    language=language,
                    entities=self.requested_entities,
                    batch_size=max(1, min(spacy_batch_size, len(group))),
                )
            )
            for position, values in zip(positions, analysed, strict=True):
                results[position] = values
        return results

    def _results_to_classification(self, text: str, results) -> Classification:
        phi_context = bool(_PHI_CONTEXT.search(text))

        spans: list[dict] = []
        detectors: list[str] = []
        best_label = SensitivityLabel.NONE
        best_conf = 0.0

        from vecshield.classify.base import LABEL_PRIORITY

        for r in results:
            if r.score < self.score_floor or self._allowed(text, r):
                continue
            # DATE_TIME is only emitted as PHI when health context is present
            # (HIPAA Safe Harbor identifier #3: dates directly related to an
            # individual).  Outside that context it is too noisy to be useful.
            if r.entity_type == "DATE_TIME":
                # PHI only when clinical context AND the span is a specific date
                # (month+day / numeric / ISO) — not a bare year, age, or
                # duration spaCy also tags DATE_TIME.
                if not phi_context or not _SPECIFIC_DATE.search(text[r.start : r.end]):
                    continue
                label = SensitivityLabel.PHI
            else:
                label = _ENTITY_LABEL.get(r.entity_type, SensitivityLabel.NONE)
                if label == SensitivityLabel.NONE:
                    continue
            # Apply calibration: scale down confidence for noisy entity types
            # so that regex-only hits always outrank NLP-only hits in ranking
            # metrics (doc AUC).  Calibrated score is also used as the span
            # score so the ensemble merge picks the highest-quality signal.
            cal = self._calibration.get(r.entity_type, 1.0)
            calibrated_score = round(r.score * cal, 3)
            # Upgrade PII -> PHI when health context surrounds an identifier.
            if phi_context and label == SensitivityLabel.PII:
                label = SensitivityLabel.PHI
            detectors.append(f"presidio:{r.entity_type}")
            spans.append(
                {
                    "detector": f"presidio:{r.entity_type}",
                    "label": label.value,
                    "start": r.start,
                    "end": r.end,
                    "score": calibrated_score,
                    "preview": _redact(text[r.start : r.end]),
                }
            )
            if LABEL_PRIORITY[label] > LABEL_PRIORITY[best_label] or (
                label == best_label and calibrated_score > best_conf
            ):
                best_label = label
                best_conf = calibrated_score

        # Recover full calendar dates spaCy's DATE_TIME recognizer missed, under
        # the same health-context gate.  Only add a match that does not already
        # overlap a span emitted above (avoids double-counting a date spaCy did
        # find).
        if phi_context:
            for m in _FULL_DATE.finditer(text):
                if any(m.start() < s["end"] and m.end() > s["start"] for s in spans):
                    continue
                detectors.append("regex:DATE_TIME")
                spans.append(
                    {
                        "detector": "regex:DATE_TIME",
                        "label": SensitivityLabel.PHI.value,
                        "start": m.start(),
                        "end": m.end(),
                        "score": _DATE_SCORE,
                        "preview": _redact(text[m.start() : m.end()]),
                    }
                )
                phi_pri = LABEL_PRIORITY[SensitivityLabel.PHI]
                higher = phi_pri > LABEL_PRIORITY[best_label]
                same_higher_conf = best_label == SensitivityLabel.PHI and (
                    best_conf < _DATE_SCORE
                )
                if higher or same_higher_conf:
                    best_label = SensitivityLabel.PHI
                    best_conf = _DATE_SCORE

        if best_label == SensitivityLabel.NONE:
            return Classification(SensitivityLabel.NONE, 0.0)
        return Classification(
            label=best_label,
            confidence=round(best_conf, 3),
            detectors=sorted(set(detectors)),
            spans=spans,
        )
