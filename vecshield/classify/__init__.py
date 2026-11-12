"""Classification engine.

Two layers: dependency-free regex detectors (high precision), and optional
Presidio/spaCy NER (recall for names, locations, addresses, PHI), combined
via EnsembleClassifier. Embedding inversion risk is handled in
`vecshield.score`.

Use `default_classifier()` to get regex + Presidio when available, regex-only
otherwise.
"""

from __future__ import annotations

from functools import cache

from vecshield.classify.base import Classifier, merge
from vecshield.classify.ensemble import EnsembleClassifier
from vecshield.classify.regex_classifier import RegexClassifier, classify_text


@cache
def _cached_classifier(use_nlp: bool, model: str | None) -> Classifier:
    classifiers: list[Classifier] = [RegexClassifier()]
    if use_nlp:
        from vecshield.classify.presidio_classifier import PresidioClassifier

        if PresidioClassifier.available():
            if model is not None:
                classifiers.append(PresidioClassifier(model=model))
            else:
                classifiers.append(PresidioClassifier())
    if len(classifiers) == 1:
        return classifiers[0]
    return EnsembleClassifier(classifiers)


def default_classifier(use_nlp: bool = True, model: str | None = None) -> Classifier:
    """Regex + Presidio (if installed). Falls back to regex-only.

    The built classifier is cached and reused across calls with the same
    ``(use_nlp, model)`` arguments so the heavy spaCy model is loaded only
    once per process.  Call :func:`reset_default_classifier` to clear the
    cache (e.g. in tests that monkeypatch the classifiers).
    """
    return _cached_classifier(use_nlp, model)


def reset_default_classifier() -> None:
    """Drop the cached classifiers built by :func:`default_classifier`.

    Useful in tests that patch classifier internals, or to release the loaded
    spaCy model.  The next :func:`default_classifier` call rebuilds fresh
    instances.
    """
    _cached_classifier.cache_clear()


__all__ = [
    "Classifier",
    "EnsembleClassifier",
    "RegexClassifier",
    "classify_text",
    "default_classifier",
    "reset_default_classifier",
    "merge",
]
