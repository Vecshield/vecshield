"""Classifier interface + merge logic shared across detectors.

A Classifier turns text into a Classification. Multiple classifiers (regex,
Presidio NER, future ML) are combined by EnsembleClassifier, which merges their
spans and picks the dominant (most-sensitive, then highest-confidence) label.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod

from vecshield.models import Classification, SensitivityLabel

# Higher number = more sensitive. Used to pick the dominant label when several
# detectors fire on the same chunk.
# Only the *order* is meaningful; the numbers are renumbered whenever a label
# is inserted, and nothing outside this module depends on their values.
# Art. 9 and Art. 10 data sit above plain PII and below PHI: not because they
# are less serious -- they are not -- but because this ranking answers one
# narrow question, "which single label describes the chunk", and a chunk that
# holds both a diagnosis and an ethnicity is most usefully described by the
# health label the HIPAA criteria key off.
LABEL_PRIORITY: dict[SensitivityLabel, int] = {
    SensitivityLabel.SECRET: 7,
    SensitivityLabel.PCI: 6,
    SensitivityLabel.PHI: 5,
    SensitivityLabel.SPECIAL_CATEGORY: 4,
    SensitivityLabel.CRIMINAL_OFFENCE: 3,
    SensitivityLabel.PII: 2,
    SensitivityLabel.SOURCE_CODE: 1,
    SensitivityLabel.NONE: 0,
}

# Health context: a clinical term near an identifier means the identifier is
# Protected Health Information (HIPAA), even when a detector only knew it as
# generic PII.  Shared by the Presidio classifier (which upgrades its own PII
# spans inline) and by :func:`apply_phi_context`, which the ensemble uses to
# apply the same rule to *regex*-detected identifiers so labeling is consistent
# regardless of which engine fired.  Kept here (no heavy deps) so a regex-only
# ensemble can use it without importing Presidio.
PHI_CONTEXT = re.compile(
    r"\b(diagnos\w+|patient\w*|prescri\w+|symptom\w*|treat\w*|mg\b|dosage|dose|"
    r"medication\w*|therap\w+|surg\w+|post[\s-]?op\w*|blood pressure|lab results?|"
    r"MRI|biopsy|oncolog\w+|HIV|cancer|tumou?r|medical record|ICD-?10|"
    r"hospital|clinic\w*|"
    # Clinical code systems. Naming one of these is as strong a health signal
    # as any prose term above, and it is what makes a bare identifier beside a
    # code table read as PHI rather than as an order number.
    r"CPT|HCPCS|LOINC|SNOMED|RxNorm|RxCUI|NDC|DRG|"
    r"formulary|discharge|admission|referral|immunisation|immunization|"
    r"vaccin\w+|pathology|radiolog\w+|specimen|accession)\b",
    re.IGNORECASE,
)


# PII detectors whose hit is NOT, on its own, a HIPAA identifier and so must not
# be elevated to PHI by clinical context. Age is the canonical case: under Safe
# Harbor an age below 90 is not identifying, so "55-year-old" in a clinical query
# stays PII (still detected) rather than becoming PHI — this is the single
# biggest source of over-redaction on ASQ-PHI's hard negatives.
_NO_PHI_UPGRADE: frozenset[str] = frozenset({"age_context"})


def apply_phi_context(result: Classification, text: str | None) -> Classification:
    """Upgrade PII spans to PHI when ``text`` carries clinical context.

    Mirrors the Presidio classifier's own PII→PHI upgrade, but applies it to the
    *merged* span set so identifiers found only by regex (SSN, phone, plan/member
    IDs, ...) are labeled PHI in a health context too. Span dicts are copied
    (never mutated in place) so cached member results stay intact. Detectors in
    :data:`_NO_PHI_UPGRADE` (e.g. age) are left as PII. A no-op when ``text`` has
    no health context or nothing was flagged.
    """
    if (
        result.label == SensitivityLabel.NONE
        or not text
        or not PHI_CONTEXT.search(text)
    ):
        return result
    changed = False
    new_spans: list[dict] = []
    for sp in result.spans:
        if (
            sp.get("label") == SensitivityLabel.PII.value
            and sp.get("detector") not in _NO_PHI_UPGRADE
        ):
            sp = {**sp, "label": SensitivityLabel.PHI.value}
            changed = True
        new_spans.append(sp)
    if not changed:
        return result
    # Any PII in the document is now PHI; the document label is at least PHI
    # (a higher-priority PCI/SECRET label, if present, is preserved).
    label = result.label
    if LABEL_PRIORITY[SensitivityLabel.PHI] > LABEL_PRIORITY[label]:
        label = SensitivityLabel.PHI
    return Classification(
        label=label,
        confidence=result.confidence,
        detectors=result.detectors,
        spans=new_spans,
    )


class Classifier(ABC):
    name: str = "base"

    @abstractmethod
    def classify(self, text: str | None) -> Classification: ...


def merge(results: list[Classification]) -> Classification:
    """Combine several Classifications into one.

    Dominant label = most sensitive label present; ties broken by confidence.
    Spans and detectors are unioned across all inputs.
    """
    fired_spans: list[dict] = []
    detectors: list[str] = []
    best_label = SensitivityLabel.NONE
    best_conf = 0.0

    for r in results:
        if not r.is_sensitive:
            continue
        detectors.extend(r.detectors)
        fired_spans.extend(r.spans)
        better_label = LABEL_PRIORITY[r.label] > LABEL_PRIORITY[best_label]
        same_label_higher_conf = r.label == best_label and r.confidence > best_conf
        if better_label or same_label_higher_conf:
            best_label = r.label
            best_conf = r.confidence

    if best_label == SensitivityLabel.NONE:
        return Classification(SensitivityLabel.NONE, 0.0)
    return Classification(
        label=best_label,
        confidence=best_conf,
        detectors=sorted(set(detectors)),
        spans=fired_spans,
    )
