"""Chunk text-surface extraction and classification helpers.

Vector stores are inconsistent about where retrievable text lives. Chroma has
documents, Pinecone/Qdrant commonly use metadata/payload fields, and managed
stores can expose file attributes. These helpers make classification scan the
same logical surfaces for every connector.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from vecshield.classify.base import Classifier, merge
from vecshield.models import Chunk, Classification, SensitivityLabel

_SENSITIVE_KEY_PARTS = (
    "email",
    "phone",
    "ssn",
    "social_security",
    "dob",
    "birth",
    "address",
    "passport",
    "driver",
    "license",
    "tax_id",
    "tin",
    "ein",
    "routing",
    "bank",
    "account_number",
    "customer_id",
    "user_id",
    "patient_id",
    "member_id",
    "employee_id",
    "subscriber_id",
    "contact_id",
    "mrn",
    "medical_record",
    "ip_address",
)


#: Characters of one surface that are classified. Longer values are cut to
#: this length, and the cut is recorded on the surface (``truncated_chars``) so
#: callers can report the unexamined tail as a coverage gap rather than
#: presenting it as read.
MAX_SURFACE_CHARS = 5000


@dataclass(frozen=True)
class TextSurface:
    name: str
    text: str
    #: Characters dropped from the end of the value before classification.
    truncated_chars: int = 0


def chunk_text_surfaces(
    chunk: Chunk, *, max_surface_chars: int = MAX_SURFACE_CHARS
) -> list[TextSurface]:
    """Return deduplicated text-like surfaces for a chunk.

    The first surface is always `text` when raw chunk text exists. Metadata is
    then recursively scanned. Sensitive-looking metadata keys also emit a
    key-aware surface such as `customer_id: cus_123`, which lets contextual
    detectors catch opaque identifiers without special casing each connector.
    """
    surfaces: list[TextSurface] = []
    seen: set[str] = set()

    def add(name: str, value: Any) -> None:
        if value is None:
            return
        text = str(value).strip()
        if not text:
            return
        dropped = max(0, len(text) - max_surface_chars)
        text = text[:max_surface_chars]
        if text in seen:
            return
        seen.add(text)
        surfaces.append(TextSurface(name=name, text=text, truncated_chars=dropped))

    add("text", chunk.text)
    for path, value in _metadata_scalars(chunk.metadata or {}):
        if isinstance(value, str):
            add(f"metadata.{path}", value)
        if _sensitive_key(path):
            add(f"metadata_key.{path}", f"{path.split('.')[-1]}: {value}")

    return surfaces


def truncated_surfaces(surfaces: Iterable[TextSurface]) -> list[TextSurface]:
    """The surfaces whose tail was not classified."""
    return [surface for surface in surfaces if surface.truncated_chars]


def _merge_surface_results(
    surfaces: Sequence[TextSurface], results: Sequence[Classification]
) -> Classification:
    fired: list[Classification] = []
    for surface, result in zip(surfaces, results, strict=True):
        if not result.is_sensitive:
            continue
        for span in result.spans:
            span.setdefault("surface", surface.name)
        fired.append(result)
    return merge(fired)


def classify_chunk(classifier: Classifier, chunk: Chunk) -> Classification:
    """Classify chunk text and metadata surfaces as one merged result."""
    surfaces = chunk_text_surfaces(chunk)
    return _merge_surface_results(
        surfaces, [classifier.classify(surface.text) for surface in surfaces])


def batch_classify_texts(classifier: Classifier) -> Callable[[list[str]], list[Classification]]:
    """A ``texts -> results`` function using the classifier's batch API when it
    has one (``classify_batch``), and one call per text otherwise."""
    batch = getattr(classifier, "classify_batch", None)
    if callable(batch):
        return lambda texts: list(batch(texts))
    return lambda texts: [classifier.classify(text) for text in texts]


def classify_surface_groups(
    groups: Sequence[Sequence[TextSurface]],
    classify_texts: Callable[[list[str]], list[Classification]],
) -> list[Classification]:
    """Classify several chunks' surfaces in one batch call.

    ``groups`` holds each chunk's surfaces (from :func:`chunk_text_surfaces`);
    the result is one merged classification per chunk, equal to what
    :func:`classify_chunk` returns for it, provided ``classify_texts`` returns
    what per-text ``classify`` would. Batching is what lets an NLP model run
    ``nlp.pipe`` over many surfaces instead of one document at a time.
    """
    texts = [surface.text for group in groups for surface in group]
    results = classify_texts(texts) if texts else []
    if len(results) != len(texts):
        raise RuntimeError(
            f"batch classification returned {len(results)} results for {len(texts)} texts")
    merged: list[Classification] = []
    offset = 0
    for group in groups:
        merged.append(_merge_surface_results(group, results[offset:offset + len(group)]))
        offset += len(group)
    return merged


def classify_chunks(classifier: Classifier, chunks: Sequence[Chunk]) -> list[Classification]:
    """:func:`classify_chunk` for many chunks, batched through the classifier."""
    return classify_surface_groups([chunk_text_surfaces(chunk) for chunk in chunks],
                                   batch_classify_texts(classifier))


def labels_from_spans(result: Classification) -> set[SensitivityLabel]:
    labels: set[SensitivityLabel] = set()
    for span in result.spans:
        label = span.get("label")
        if not label:
            continue
        try:
            labels.add(SensitivityLabel(label))
        except ValueError:
            continue
    if result.is_sensitive:
        labels.add(result.label)
    return labels


def _metadata_scalars(value: Any, prefix: str = "") -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for k, v in value.items():
            key = str(k)
            path = f"{prefix}.{key}" if prefix else key
            out.extend(_metadata_scalars(v, path))
    elif isinstance(value, list):
        for i, v in enumerate(value[:20]):
            path = f"{prefix}.{i}" if prefix else str(i)
            out.extend(_metadata_scalars(v, path))
    elif isinstance(value, (str, int, float, bool)):
        out.append((prefix, value))
    return out


#: Whole tokens that name a credential. Plural ``tokens`` is left out so that
#: ``max_tokens`` stays readable.
_CREDENTIAL_TOKENS = frozenset({"password", "passwd", "passphrase", "secret",
                                "token", "credential", "credentials", "apikey"})
_CREDENTIAL_SEQUENCES = (("api", "key"), ("access", "key"), ("private", "key"),
                         ("client", "secret"))


def _credential_key(path: str) -> bool:
    """Whether the last key segment names a credential (whole tokens only)."""
    segment = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(path).split(".")[-1])
    tokens = [t for t in re.split(r"[^A-Za-z0-9]+", segment.lower()) if t]
    if any(t in _CREDENTIAL_TOKENS for t in tokens):
        return True
    return any(tuple(tokens[i:i + len(seq)]) == seq
               for seq in _CREDENTIAL_SEQUENCES
               for i in range(len(tokens) - len(seq) + 1))


def _sensitive_key(path: str) -> bool:
    key = path.lower().replace("-", "_")
    return any(part in key for part in _SENSITIVE_KEY_PARTS) or _credential_key(path)
