"""Batched classification for the scan loop, with an NLP time budget.

The scan used to classify one surface at a time, each call taking the
classifier's process-wide lock and running the NER model on a single
document. :class:`ClassifiedStream` reads chunks in groups, classifies all of
their surfaces in one ``classify_batch`` call (``nlp.pipe`` underneath), and
yields ``(chunk, surfaces, classification)`` in the original order, so the
scan body is unchanged. The results equal :func:`classify_chunk` per chunk.

At roughly 40 ms per chunk for the transformer model, a 50,000-chunk
collection is over half an hour of NLP. :class:`NlpBudget` bounds that per
scan. When it is spent, the remaining chunks are still classified -- by the
pattern detectors -- and counted, so the scan can record partial coverage for
them. Nothing is skipped silently.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Callable, Iterable, Iterator

from vecshield.classify import Classifier
from vecshield.classify.surfaces import (
    MAX_SURFACE_CHARS,
    TextSurface,
    batch_classify_texts,
    chunk_text_surfaces,
    classify_surface_groups,
    truncated_surfaces,
)
from vecshield.models import Chunk, Classification

#: Chunks read and classified together. Bounds the memory held per batch.
BATCH_CHUNKS = 64
#: Documents per ``nlp.pipe`` step inside the classifier.
NLP_BATCH_SIZE = 64
BUDGET_ENV = "VECSHIELD_NLP_TIME_BUDGET_S"
_END = object()


@dataclass
class NlpBudget:
    """Seconds of NER model time one scan may spend."""

    seconds: float
    timings: dict = field(default_factory=dict)
    chunks_without_nlp: int = 0

    @property
    def spent(self) -> float:
        return float(self.timings.get("nlp_seconds", 0.0))

    @property
    def exhausted(self) -> bool:
        return self.spent >= self.seconds

    def to_dict(self) -> dict:
        return {"seconds": self.seconds, "spent_seconds": round(self.spent, 3),
                "exhausted": self.exhausted, "chunks_without_nlp": self.chunks_without_nlp}

    @classmethod
    def resolve(cls, seconds: float | None) -> "NlpBudget | None":
        """``seconds`` when given, else ``VECSHIELD_NLP_TIME_BUDGET_S``.

        Unset, empty, ``0`` or ``off`` means no budget (the default). Anything
        else must be a positive number of seconds; a malformed value is an
        error rather than a silently unlimited scan.
        """
        if seconds is None:
            raw = os.environ.get(BUDGET_ENV, "").strip().lower()
            if raw in ("", "0", "off", "none"):
                return None
            try:
                seconds = float(raw)
            except ValueError as exc:
                raise ValueError(f"{BUDGET_ENV} must be a number of seconds, "
                                 f"or 0/off for no budget") from exc
        if seconds == 0:
            return None
        if not seconds > 0:
            raise ValueError("the NLP time budget must be positive seconds (0 turns it off)")
        return cls(seconds=float(seconds))


def _budgeted(classifier: Classifier) -> bool:
    """Only a classifier with a separable NLP leg can honour a budget."""
    from vecshield_platform.detection import EnterpriseClassifier

    return isinstance(classifier, EnterpriseClassifier) and classifier.nlp is not None


class ClassifiedStream:
    """Iterate ``(chunk, surfaces, classification)`` over a collection.

    ``limit`` caps the chunks read, as ``max_chunks_per_collection`` does;
    ``capped`` is set only when a further chunk existed. Counters record what
    the caller must report as coverage: chunks classified without NLP after
    the budget ran out, and surfaces cut at the classification window.
    """

    def __init__(self, classifier: Classifier,
                 chunks: Iterable[Chunk] | Callable[[], Iterable[Chunk]], *,
                 limit: int | None = None, budget: NlpBudget | None = None,
                 batch_chunks: int = BATCH_CHUNKS):
        self.classifier = classifier
        self.chunks = chunks
        self.limit = limit
        self.budget = budget if budget is not None and _budgeted(classifier) else None
        self.batch_chunks = max(1, batch_chunks)
        self.capped = False
        self.chunks_without_nlp = 0
        self.surfaces_truncated = 0
        self.chars_not_classified = 0
        self._classify_texts = batch_classify_texts(classifier)

    def _classify(self, groups: list[list[TextSurface]]) -> list[Classification]:
        budget = self.budget
        if budget is None:
            return classify_surface_groups(groups, self._classify_texts)
        use_nlp = not budget.exhausted
        results = classify_surface_groups(
            groups, lambda texts: self.classifier.classify_batch(  # type: ignore[attr-defined]
                texts, NLP_BATCH_SIZE, use_nlp=use_nlp, timings=budget.timings))
        if not use_nlp:
            self.chunks_without_nlp += len(groups)
            budget.chunks_without_nlp += len(groups)
        return results

    def __iter__(self) -> Iterator[tuple[Chunk, list[TextSurface], Classification]]:
        # A callable source is opened here, when iteration starts, so an error
        # opening it surfaces where the caller iterates (inside its handler).
        iterator = iter(self.chunks() if callable(self.chunks) else self.chunks)
        read = 0
        while True:
            batch: list[Chunk] = []
            failure: BaseException | None = None
            done = False
            try:
                while len(batch) < self.batch_chunks:
                    if self.limit and read >= self.limit:
                        # Peek once: the cap only matters if it cut something.
                        self.capped = next(iterator, _END) is not _END
                        done = True
                        break
                    chunk = next(iterator, _END)
                    if chunk is _END:
                        done = True
                        break
                    batch.append(chunk)  # type: ignore[arg-type]
                    read += 1
            except Exception as exc:  # noqa: BLE001 - re-raised after the batch
                # Chunks read before a connector failure are still classified
                # and counted; the failure is raised once they are.
                failure = exc
            if batch:
                groups = [chunk_text_surfaces(chunk) for chunk in batch]
                for chunk, surfaces, result in zip(batch, groups, self._classify(groups),
                                                   strict=True):
                    cut = truncated_surfaces(surfaces)
                    self.surfaces_truncated += len(cut)
                    self.chars_not_classified += sum(s.truncated_chars for s in cut)
                    yield chunk, surfaces, result
            if failure is not None:
                raise failure
            if done or not batch:
                return

    def coverage_gaps(self, scanned: int) -> tuple[list[str], dict]:
        """Reasons and outcome details for what this collection's pass left out."""
        reasons: list[str] = []
        details: dict = {}
        if self.chunks_without_nlp:
            assert self.budget is not None
            reasons.append(
                f"The scan's NLP time budget ({self.budget.seconds:g}s) ran out: "
                f"{self.chunks_without_nlp} of {scanned} chunk(s) were classified by "
                "pattern detectors only, so names, locations and organisations in "
                "them were not examined.")
            details.update(nlp_budget_exhausted=True,
                           chunks_without_nlp=self.chunks_without_nlp)
        if self.surfaces_truncated:
            reasons.append(
                f"{self.surfaces_truncated} text surface(s) were longer than "
                f"{MAX_SURFACE_CHARS:,} characters; the {self.chars_not_classified:,} "
                "character(s) past that point were not classified.")
            details.update(surfaces_truncated=self.surfaces_truncated,
                           chars_not_classified=self.chars_not_classified)
        return reasons, details
