"""Add a project-specific detector by composing a custom classifier.

This example treats internal ticket IDs as sensitive because they can expose
support workflow metadata in some organizations.
"""

from __future__ import annotations

import re

from vecshield import check_text
from vecshield.classify import Classifier, RegexClassifier, merge
from vecshield.models import Classification, SensitivityLabel


class TicketIdClassifier(Classifier):
    name = "ticket_id"
    pattern = re.compile(r"\b(?:INC|CASE)-\d{6}\b")

    def classify(self, text: str | None) -> Classification:
        spans = []
        for match in self.pattern.finditer(text or ""):
            spans.append(
                {
                    "label": SensitivityLabel.PII.value,
                    "detector": self.name,
                    "start": match.start(),
                    "end": match.end(),
                    "preview": match.group(0),
                }
            )
        if not spans:
            return Classification(SensitivityLabel.NONE, 0.0)
        return Classification(
            SensitivityLabel.PII,
            0.80,
            detectors=[self.name],
            spans=spans,
        )


class ProjectClassifier(Classifier):
    name = "project_classifier"

    def __init__(self) -> None:
        self.classifiers = [RegexClassifier(), TicketIdClassifier()]

    def classify(self, text: str | None) -> Classification:
        return merge([classifier.classify(text) for classifier in self.classifiers])


if __name__ == "__main__":
    result = check_text(
        "See CASE-123456 and jane@example.com", classifier=ProjectClassifier()
    )
    print(result.to_dict())
