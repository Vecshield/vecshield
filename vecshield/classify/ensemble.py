"""EnsembleClassifier — run several classifiers and merge their results."""

from __future__ import annotations

from vecshield.classify.base import Classifier, apply_phi_context, merge
from vecshield.models import Classification


class EnsembleClassifier(Classifier):
    name = "ensemble"

    def __init__(self, classifiers: list[Classifier]):
        if not classifiers:
            raise ValueError("EnsembleClassifier needs at least one classifier")
        self.classifiers = classifiers

    @property
    def members(self) -> list[str]:
        return [c.name for c in self.classifiers]

    def classify(self, text: str | None) -> Classification:
        merged = merge([c.classify(text) for c in self.classifiers])
        # Consistent PHI labeling: upgrade any PII identifier to PHI when the
        # document carries clinical context, regardless of which member found it.
        return apply_phi_context(merged, text)
