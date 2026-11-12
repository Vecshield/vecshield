"""IngestGate — classify a chunk batch before it reaches the embedder.

Two modes:
  * soft (default): classify, return an IngestGateReport, never raise. Callers
    decide what to do with blocked_chunks.
  * hard: raise PiiDetectedError if any chunk classifies at >= block_severity.

A chunk is "blocked" when its merged classification rates at or above
`block_severity` (default HIGH). Secrets/PCI/PHI map to HIGH+, so they block by
default; bare low-confidence PII can be allowed through under a higher bar.

Named entities found only by the NLP model (a PERSON, LOCATION, ORGANIZATION
or NRP span with nothing else behind it) rate MEDIUM, not HIGH: the model gives
"Taylor Swift" in "Ask Alexa to play Taylor Swift" the same fixed score as a
customer's name, so on its own it is not strong enough to stop an ingest. Such
a span keeps its label's severity when it is corroborated by

  * a pattern (regex) detector firing anywhere in the same chunk,
  * clinical context (the span was labelled PHI), or
  * a second, different kind of direct identifier from the model in the same
    chunk (for example a person *and* a location).

The rated basis is recorded on each blocked finding (``severity_basis``), and
every sensitive chunk that was let through below the bar is listed in the
report's ``below_threshold`` entries, so a downgrade is never silent.
"""

from __future__ import annotations

import copy
import uuid

from vecshield.classify import Classifier, default_classifier
from vecshield.classify.base import LABEL_PRIORITY
from vecshield.classify.surfaces import (
    chunk_text_surfaces,
    classify_chunk,
    truncated_surfaces,
)
from vecshield.models import (
    Chunk,
    Finding,
    IngestGateReport,
    SensitivityLabel,
    Severity,
)

# Label -> severity used to decide blocking. Mirrors the store-side scan intent.
_LABEL_SEVERITY = {
    SensitivityLabel.SECRET: Severity.CRITICAL,
    SensitivityLabel.PCI: Severity.HIGH,
    SensitivityLabel.PHI: Severity.HIGH,
    # GDPR Art. 9 / Art. 10 data: processing needs its own legal basis, so it
    # is at least as serious as ordinary personal data.
    SensitivityLabel.SPECIAL_CATEGORY: Severity.HIGH,
    SensitivityLabel.CRIMINAL_OFFENCE: Severity.HIGH,
    SensitivityLabel.PII: Severity.HIGH,
    SensitivityLabel.SOURCE_CODE: Severity.MEDIUM,
    SensitivityLabel.NONE: Severity.INFO,
}

#: Model-derived entity types (see ``presidio_classifier.NER_ENTITY_TYPES``);
#: kept literal so the gate does not import the optional NLP adapter.
_NER_DETECTORS = frozenset(
    f"presidio:{name}" for name in ("PERSON", "LOCATION", "ORGANIZATION", "NRP", "DATE_TIME"))
#: Model-derived types that identify a person on their own. Organisation and
#: nationality/religion/politics mentions are not a *second identifier*.
_NER_IDENTIFIERS = frozenset({"presidio:PERSON", "presidio:LOCATION"})
#: Severity of an uncorroborated NLP-only span.
NLP_ONLY_SEVERITY = Severity.MEDIUM


def _span_label(span: dict) -> SensitivityLabel | None:
    try:
        return SensitivityLabel(span.get("label"))
    except ValueError:
        return None


def rate_chunk(result) -> tuple[SensitivityLabel, Severity, str]:
    """(top label, gate severity, basis) for one merged chunk classification.

    ``basis`` is ``"pattern"`` when a pattern (non-NER) detector carries the
    rating, ``"nlp_corroborated"`` when model spans carry it and one of the
    corroboration rules in the module docstring holds, and ``"nlp_only"`` when
    the rating rests on uncorroborated model output and was capped at
    :data:`NLP_ONLY_SEVERITY`.
    """
    spans = [(span, label) for span in (result.spans or [])
             if (label := _span_label(span)) not in (None, SensitivityLabel.NONE)]
    ner = [(span, label) for span, label in spans if span.get("detector") in _NER_DETECTORS]
    pattern = [(span, label) for span, label in spans
               if span.get("detector") not in _NER_DETECTORS]
    # A document label no span explains (a detector that reports a label
    # without offsets) is rated as it always was.
    if result.is_sensitive and result.label not in {label for _, label in spans}:
        pattern.append(({}, result.label))
    identifier_kinds = {span.get("detector") for span, _ in ner} & _NER_IDENTIFIERS
    corroborated = bool(pattern) or len(identifier_kinds) >= 2

    rated: list[tuple[Severity, SensitivityLabel, str]] = []
    for _, label in pattern:
        rated.append((_LABEL_SEVERITY[label], label, "pattern"))
    for _, label in ner:
        severity = _LABEL_SEVERITY[label]
        if corroborated or label is SensitivityLabel.PHI:
            rated.append((severity, label, "nlp_corroborated"))
        elif severity.rank > NLP_ONLY_SEVERITY.rank:
            rated.append((NLP_ONLY_SEVERITY, label, "nlp_only"))
        else:
            rated.append((severity, label, "nlp_only"))
    if not rated:
        return result.label, _LABEL_SEVERITY[result.label], "pattern"
    # Highest severity wins; then the higher-priority label; then a pattern
    # basis over a model one, since that is the stronger explanation.
    order = {"pattern": 2, "nlp_corroborated": 1, "nlp_only": 0}
    severity, label, basis = max(
        rated, key=lambda r: (r[0].rank, LABEL_PRIORITY[r[1]], order[r[2]]))
    return label, severity, basis


class PiiDetectedError(Exception):
    """Raised by a hard-mode IngestGate when a batch contains blocked content."""

    def __init__(self, report: IngestGateReport):
        self.report = report
        super().__init__(
            f"ingest blocked: {len(report.blocked_chunks)} of {report.total} "
            f"chunks contain sensitive data"
        )


class IngestGate:
    def __init__(
        self,
        *,
        classifier: Classifier | None = None,
        mode: str = "soft",  # "soft" | "hard"
        block_severity: Severity = Severity.HIGH,
        dataset: str = "ingest",
    ):
        if mode not in ("soft", "hard"):
            raise ValueError("mode must be 'soft' or 'hard'")
        self.classifier = classifier or default_classifier()
        self.mode = mode
        self.block_severity = block_severity
        self.dataset = dataset

    def inspect(self, chunks: list[Chunk]) -> IngestGateReport:
        """Classify a batch and return a report. Never raises (use check() for hard)."""
        report = IngestGateReport()
        for chunk in chunks:
            # Surfaces longer than the classification window are read only in
            # part; say so rather than let the tail pass as inspected.
            cut = truncated_surfaces(chunk_text_surfaces(chunk))
            if cut:
                report.truncated_surfaces.append({
                    "chunk_id": chunk.id,
                    "surfaces": [s.name for s in cut],
                    "chars_not_classified": sum(s.truncated_chars for s in cut),
                })
            result = classify_chunk(self.classifier, chunk)
            chunk.classification = result
            if not result.is_sensitive:
                report.allowed_chunks.append(chunk)
                continue

            top, severity, basis = rate_chunk(result)

            if severity.rank >= self.block_severity.rank:
                report.blocked_chunks.append(chunk)
                report.findings.append(
                    Finding(
                        id=f"find-{uuid.uuid4().hex[:10]}",
                        title=f"{top.value.upper()} blocked at ingest",
                        severity=severity,
                        category="ingest_gate",
                        store=self.dataset,
                        collection=chunk.collection,
                        description=(
                            f"Chunk '{chunk.id}' contains {top.value.upper()} "
                            f"({', '.join(result.detectors)}) and was blocked before "
                            "embedding."
                        ),
                        evidence={
                            "chunk_id": chunk.id,
                            "label": top.value,
                            "detectors": result.detectors,
                            "spans": result.spans,
                            "severity_basis": basis,
                        },
                        remediation=(
                            "Redact or drop the sensitive span upstream, "
                            "then re-ingest. Embedding this content would "
                            "persist it in the vector store."
                        ),
                    )
                )
            else:
                report.allowed_chunks.append(chunk)
                report.below_threshold.append({
                    "chunk_id": chunk.id, "label": top.value,
                    "severity": severity.value, "severity_basis": basis,
                    "detectors": list(result.detectors),
                })

        report.pii_density = (
            len(report.blocked_chunks) / report.total if report.total else 0.0
        )
        return report

    def check(self, chunks: list[Chunk]) -> IngestGateReport:
        """Inspect; in hard mode raise PiiDetectedError when anything is blocked."""
        report = self.inspect(chunks)
        if self.mode == "hard" and report.blocked:
            raise PiiDetectedError(report)
        return report

    def redact(self, chunks: list[Chunk]) -> tuple[list[Chunk], int]:
        """Anonymization pipeline: mask sensitive spans instead of blocking.

        Returns (clean_chunks, spans_redacted). Each returned chunk is a copy —
        the inputs are never mutated. Matched spans in `text` and in string
        metadata values are replaced with a `[REDACTED:LABEL]` token, so the
        chunk can be embedded with the sensitive substring removed while the
        surrounding context is preserved.
        """
        out: list[Chunk] = []
        total_redacted = 0
        for chunk in chunks:
            clean = copy.deepcopy(chunk)
            n = 0
            if clean.text:
                clean.text, c = self._redact_text(clean.text)
                n += c
            clean.metadata, c = self._redact_value(clean.metadata)
            n += c
            clean.classification = None  # stale after redaction
            total_redacted += n
            out.append(clean)
        return out, total_redacted

    def _redact_value(self, value):
        """Redact strings anywhere in a metadata value, including nested ones."""
        if isinstance(value, str):
            return self._redact_text(value)
        if isinstance(value, dict):
            total = 0
            for key, item in list(value.items()):
                value[key], c = self._redact_value(item)
                total += c
            return value, total
        if isinstance(value, list):
            total = 0
            for i, item in enumerate(value):
                value[i], c = self._redact_value(item)
                total += c
            return value, total
        return value, 0

    def _redact_text(self, text: str) -> tuple[str, int]:
        """Replace every classified span in a string with a label token.

        Detectors overlap (a generic ``secret=`` rule and a provider key rule
        on the same value; a card number and its track data), so spans are
        merged into disjoint intervals first. Splicing overlapping spans one
        by one would cut into a token already inserted and leave part of the
        value behind. A merged interval takes the most sensitive label in it.
        """
        result = self.classifier.classify(text)
        if not result.is_sensitive or not result.spans:
            return text, 0
        intervals: list[list] = []
        for span in sorted(
            (s for s in result.spans if "start" in s and "end" in s),
            key=lambda s: (s["start"], s["end"]),
        ):
            start, end = span["start"], span["end"]
            label = _span_label(span) or SensitivityLabel.PII
            if intervals and start <= intervals[-1][1]:
                last = intervals[-1]
                last[1] = max(last[1], end)
                if LABEL_PRIORITY[label] > LABEL_PRIORITY[last[2]]:
                    last[2] = label
            else:
                intervals.append([start, end, label])
        # Splice from the end so earlier offsets stay valid.
        for start, end, label in reversed(intervals):
            text = text[:start] + f"[REDACTED:{label.value.upper()}]" + text[end:]
        return text, len(intervals)
