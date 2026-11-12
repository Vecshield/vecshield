"""One corpus, one embedding model — or a reason why not.

`Collection` already carries `dimension` and `embedding_model`. Nothing reads
them together, so the data is collected on every scan and discarded.

Three things downstream depend on knowing which model produced a vector, and
all three degrade *silently* when the label is missing:

* **inversion risk** falls back to 0.55 with no model name — below every
  threshold that asks whether embeddings are recoverable, so an unlabelled
  collection reads as the safe one;
* **erasure** — re-embedding without deleting leaves an orphan vector for a
  subject whose record was erased;
* **embedding anomaly** compares vectors that may not share a space.

This check reads what is already there and says when it disagrees with itself.
It is cheap in the way that matters: it needs no content read at all, so it
runs on stores where enumeration is capped, unsupported, or refused.

**It cannot confirm that a declared model produced the vectors.** It detects
contradiction, not correctness. A collection whose declared model and
dimension agree may still have been written by something else entirely.

Pure: no I/O, no connector.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Optional

from vecshield.models import Collection

#: Output width of embedding models common in retrieval stacks. Used only to
#: contradict a declared model, never to infer one: several models share a
#: width, so a match proves nothing while a mismatch is informative.
KNOWN_DIMENSIONS: dict[str, int] = {
    "text-embedding-ada-002": 1536,
    "text-embedding-3-small": 1536,
    "text-embedding-3-large": 3072,
    "all-minilm-l6-v2": 384,
    "all-minilm-l12-v2": 384,
    "all-mpnet-base-v2": 768,
    "bge-small-en-v1.5": 384,
    "bge-base-en-v1.5": 768,
    "bge-large-en-v1.5": 1024,
    "e5-small-v2": 384,
    "e5-base-v2": 768,
    "e5-large-v2": 1024,
    "gte-small": 384,
    "gte-base": 768,
    "gte-large": 1024,
    "voyage-2": 1024,
    "voyage-3": 1024,
    "embed-english-v3.0": 1024,
    "nomic-embed-text-v1": 768,
}

#: Models whose embeddings published research can substantially invert. Kept
#: here because the same table already has to know model names, and a declared
#: model is the only way the scan learns this without a content read.
_NOTE_INVERTIBLE = ("text-embedding-ada-002", "text-embedding-3-small")


@dataclass(frozen=True)
class CollectionEmbedding:
    """What one collection says about its own vectors."""

    name: str
    dimension: Optional[int] = None
    model: Optional[str] = None
    issue: str = ""            # "" when nothing contradicts

    @property
    def declared(self) -> bool:
        return bool(self.model)


@dataclass(frozen=True)
class EmbeddingConsistency:
    """The store's embedding story, and where it contradicts itself."""

    collections: tuple[CollectionEmbedding, ...] = ()
    #: Distinct declared models across the store.
    models: tuple[str, ...] = ()
    #: Distinct dimensions across the store.
    dimensions: tuple[int, ...] = ()
    issues: tuple[str, ...] = ()
    unlabelled: tuple[str, ...] = ()

    @property
    def consistent(self) -> bool:
        return not self.issues

    @property
    def status(self) -> str:
        if self.issues:
            return "contradicted"
        if self.unlabelled:
            return "undeclared"
        return "consistent"

    def summary(self) -> str:
        if self.issues:
            return self.issues[0] if len(self.issues) == 1 else (
                f"{len(self.issues)} collections contradict their declared "
                f"embedding model: {self.issues[0]}")
        if self.unlabelled:
            names = ", ".join(self.unlabelled[:3])
            more = f" and {len(self.unlabelled) - 3} more" if len(self.unlabelled) > 3 else ""
            return (f"No embedding model is recorded for {names}{more}. "
                    "Inversion risk cannot be scored for an unlabelled "
                    "collection and defaults to the benign end of the scale.")
        if not self.collections:
            return "The store reported no collections."
        return (f"All {len(self.collections)} collections declare a model "
                f"consistent with their vector width.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "models": list(self.models),
            "dimensions": list(self.dimensions),
            "distinct_models": len(self.models),
            "issues": list(self.issues),
            "unlabelled": list(self.unlabelled),
            "collections": [
                {"collection": c.name, "dimension": c.dimension,
                 "model": c.model, "issue": c.issue}
                for c in self.collections
            ],
            "summary": self.summary(),
            "note": ("A model and a width that agree do not prove the model "
                     "produced the vectors. This detects contradiction, not "
                     "correctness."),
        }


def _normalise(model: Optional[str]) -> Optional[str]:
    if not model:
        return None
    name = str(model).strip().lower()
    return name.rsplit("/", 1)[-1] or None


def check_embedding_consistency(
        collections: Iterable[Collection]) -> EmbeddingConsistency:
    """Compare each collection's declared model against its vector width."""
    seen: list[CollectionEmbedding] = []
    issues: list[str] = []
    unlabelled: list[str] = []
    models: list[str] = []
    dimensions: list[int] = []

    for col in collections:
        model = _normalise(col.embedding_model)
        dimension = col.dimension if isinstance(col.dimension, int) and col.dimension > 0 else None
        issue = ""
        if model:
            if model not in models:
                models.append(model)
            expected = KNOWN_DIMENSIONS.get(model)
            if expected and dimension and expected != dimension:
                issue = (f"Collection '{col.name}' declares '{model}', which "
                         f"produces {expected}-dimension vectors, but its "
                         f"vectors are {dimension}-dimension. One of the two "
                         "is wrong, and neither can be trusted until it is "
                         "resolved.")
                issues.append(issue)
        else:
            unlabelled.append(col.name)
        if dimension and dimension not in dimensions:
            dimensions.append(dimension)
        seen.append(CollectionEmbedding(col.name, dimension, model, issue))

    return EmbeddingConsistency(
        collections=tuple(seen), models=tuple(sorted(models)),
        dimensions=tuple(sorted(dimensions)), issues=tuple(issues),
        unlabelled=tuple(unlabelled))


def invertible_models(consistency: EmbeddingConsistency) -> list[str]:
    """Declared models with published inversion results, for context only."""
    return [m for m in consistency.models if m in _NOTE_INVERTIBLE]
