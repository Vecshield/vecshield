"""One chunk, as it is in the store right now, with its matches marked.

A finding stores what a scan saw: chunk ids, span offsets, and a masked
preview. It never stores the text (see :mod:`vecshield_platform.explain`,
"Redaction by default"). This module is the other half of that decision: when
a person needs to see the chunk, it is fetched from the store on request,
classified again, and returned with every match highlighted — and nothing about
it is written to history.

Two levels, and the difference between them is audited:

* ``masked`` — the whole surface with each detected span replaced by its
  length-preserving mask. The reader sees the context, the label, the detector,
  and what argues against the match; they do not see the value.
* ``raw`` — the same, with the values in place. Seeing raw personal data is a
  processing activity of its own, so the caller supplies a reason and the API
  records who looked at what.

``drift`` says whether the spans found now are the spans the finding recorded.
A chunk edited since the scan is shown as it is, with that fact stated, rather
than with the old highlights painted over new text.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from vecshield_platform.connectors.base import Connector, UnsupportedCapability
from vecshield_platform.explain import explain_span

MASKED = "masked"
RAW = "raw"
LEVELS = (MASKED, RAW)

#: How far a connector without random access is iterated before this module
#: refuses rather than scans a whole collection to find one chunk.
MAX_ITERATED = 20_000


class RevealError(ValueError):
    """The chunk could not be produced, with the reason a reader needs."""


@dataclass(frozen=True)
class RevealedSpan:
    start: int
    end: int
    detector: str
    label: str
    preview: str
    confidence: str
    confidence_reason: str
    counter_signals: tuple[dict[str, Any], ...]
    disputed: bool
    #: Whether the text between ``start`` and ``end`` is the value or its mask.
    revealed: bool

    def to_dict(self) -> dict[str, Any]:
        return {"start": self.start, "end": self.end, "detector": self.detector,
                "label": self.label, "preview": self.preview,
                "confidence": self.confidence,
                "confidence_reason": self.confidence_reason,
                "counter_signals": list(self.counter_signals),
                "disputed": self.disputed, "revealed": self.revealed}


@dataclass(frozen=True)
class RevealedSurface:
    name: str
    text: str
    spans: tuple[RevealedSpan, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "text": self.text,
                "spans": [s.to_dict() for s in self.spans]}


@dataclass(frozen=True)
class RevealedChunk:
    store: str
    collection: str
    chunk_id: str
    level: str
    fetched_at: str
    surfaces: tuple[RevealedSurface, ...]
    metadata: dict[str, Any]
    #: Whether live spans differ from the ones a finding recorded. ``None``
    #: when no recorded spans were given to compare against.
    drift: Optional[bool]
    recorded_spans: int
    live_spans: int
    labels: tuple[str, ...] = ()
    detectors: tuple[str, ...] = ()
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"store": self.store, "collection": self.collection,
                "chunk_id": self.chunk_id, "level": self.level,
                "fetched_at": self.fetched_at,
                "surfaces": [s.to_dict() for s in self.surfaces],
                "metadata": self.metadata, "drift": self.drift,
                "recorded_spans": self.recorded_spans, "live_spans": self.live_spans,
                "labels": list(self.labels), "detectors": list(self.detectors),
                "note": self.note}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _mask(value: str) -> str:
    """Length-preserving, so span offsets stay valid after substitution."""
    text = str(value)
    if len(text) <= 4:
        return "*" * len(text)
    return text[:2] + "*" * (len(text) - 4) + text[-2:]


def merge_spans(spans: Iterable[dict[str, Any]], length: int) -> list[tuple[int, int]]:
    """The union of every well-formed span, as sorted non-overlapping ranges.

    Two detectors often report overlapping ranges (a database URL and the IP
    address inside it). Masking each on its own, or skipping the second, leaves
    part of one of them readable; masking the union does not.
    """
    ranges: list[tuple[int, int]] = []
    for span in spans:
        try:
            start, end = int(span.get("start", 0)), int(span.get("end", 0))
        except (TypeError, ValueError):
            continue
        if start < 0 or end > length or end <= start:
            continue
        ranges.append((start, end))
    merged: list[list[int]] = []
    for start, end in sorted(ranges):
        if merged and start < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [(s, e) for s, e in merged]


def mask_spans(text: str, spans: Iterable[dict[str, Any]]) -> str:
    """``text`` with every span masked, overlapping spans as one range.

    Length-preserving, so offsets computed on the original still point at the
    right characters of the result. The one masking rule for every view that
    says it is masked: the chunk view, the sample, plan previews and erasure
    previews.
    """
    out: list[str] = []
    cursor = 0
    for start, end in merge_spans(spans, len(text)):
        out.append(text[cursor:start])
        out.append(_mask(text[start:end]))
        cursor = end
    out.append(text[cursor:])
    return "".join(out)


def mask_detected(text: str, classifier: Any) -> str:
    """Classify ``text`` and mask what the classifier found in it."""
    if not text:
        return text
    result = classifier.classify(text)
    return mask_spans(text, getattr(result, "spans", None) or [])


def fetch_chunk(connector: Connector, collection: str, chunk_id: str) -> Any:
    """Read one chunk by id, refusing to scan an unbounded collection for it."""
    if not getattr(connector, "content_enumerable", True):
        raise UnsupportedCapability(
            "This connector cannot read chunk content back, so the chunk cannot be shown.")
    own = getattr(type(connector), "get_chunks", None)
    overridden = own is not None and own is not Connector.get_chunks
    if overridden:
        found = connector.get_chunks(collection, [chunk_id])
        return found[0] if found else None
    # No random access: iterate, but only so far.
    seen = 0
    for chunk in connector.iter_chunks(collection):
        if chunk.id == chunk_id:
            return chunk
        seen += 1
        if seen >= MAX_ITERATED:
            raise RevealError(
                f"This connector has no lookup by id, and the chunk was not among the "
                f"first {MAX_ITERATED:,} in '{collection}'. Refusing to scan the rest "
                "of the collection to find it.")
    return None


def mask_metadata_value(value: Any, *, key: str, classifier: Any,
                        matched: Iterable[str] = (),
                        cache: Optional[dict[str, str]] = None) -> Any:
    """One metadata value as the masked views show it.

    The value is masked when its key is one the scan treats as identifying
    (``ssn``, ``email``, ``customer_id`` and the rest), and otherwise wherever
    the classifier finds something in it or it contains one of ``matched``.
    A number is returned as its masked string when any of those hold;
    otherwise it is returned unchanged. Booleans and nulls carry nothing to
    mask. ``cache`` (text to masked text) lets a caller classify each distinct
    value once.
    """
    from vecshield.classify.surfaces import _sensitive_key

    if value is None or isinstance(value, bool):
        return value
    text = str(value)
    if not text:
        return value
    if key and _sensitive_key(key):
        return _mask(text)
    if cache is None:
        cache = {}
    if text not in cache:
        spans = list(getattr(classifier.classify(text), "spans", None) or [])
        for needle in matched:
            at = text.find(needle)
            while at != -1:
                spans.append({"start": at, "end": at + len(needle)})
                at = text.find(needle, at + 1)
        cache[text] = mask_spans(text, spans)
    shown = cache[text]
    if shown == text and not isinstance(value, str) and isinstance(value, (int, float)):
        return value
    return shown


def _mask_metadata(metadata: Any, *, classifier: Any, matched: Iterable[str],
                   cache: Optional[dict[str, str]] = None) -> Any:
    """Metadata as the masked view returns it: the structure kept, every value masked.

    Each leaf goes through :func:`mask_metadata_value` under its own key.
    """
    if cache is None:
        cache = {}

    def walk(value: Any, key: str) -> Any:
        if isinstance(value, dict):
            return {k: walk(v, str(k)) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            # An index is not a key: an element of 'emails' is judged by 'emails'.
            return [walk(v, key) for v in value]
        return mask_metadata_value(value, key=key, classifier=classifier,
                                   matched=matched, cache=cache)

    return walk(metadata, "")


def _span_key(span: dict[str, Any]) -> tuple[str, int, int, str]:
    return (str(span.get("surface", "text")), int(span.get("start", 0)),
            int(span.get("end", 0)), str(span.get("detector", "")))


def reveal_chunk(chunk: Any, *, classifier: Any, store: str, collection: str,
                 level: str = MASKED,
                 recorded_spans: Optional[Iterable[dict[str, Any]]] = None) -> RevealedChunk:
    """Classify the chunk as it is now and mark every match.

    ``classifier`` is any object with ``classify(text) -> Classification``; the
    chunk is split into the same surfaces the scan uses, so offsets line up
    with what a finding recorded.
    """
    if level not in LEVELS:
        raise RevealError(f"unknown reveal level '{level}'; expected one of {', '.join(LEVELS)}")
    from vecshield.classify.surfaces import chunk_text_surfaces

    surfaces = chunk_text_surfaces(chunk)
    by_name = {s.name: s.text for s in surfaces}
    live: list[dict[str, Any]] = []
    for surface in surfaces:
        result = classifier.classify(surface.text)
        for span in getattr(result, "spans", None) or []:
            live.append({**span, "surface": span.get("surface") or surface.name})

    out_surfaces: list[RevealedSurface] = []
    labels: set[str] = set()
    detectors: set[str] = set()
    for surface in surfaces:
        mine = sorted((s for s in live if s.get("surface") == surface.name),
                      key=lambda s: (int(s.get("start", 0)), int(s.get("end", 0))))
        text = surface.text
        revealed: list[RevealedSpan] = []
        for span in mine:
            start, end = int(span.get("start", 0)), int(span.get("end", 0))
            if start < 0 or end > len(text) or end <= start:
                continue  # malformed: there is nothing in the text to point at
            explanation = explain_span(span, text=text, collection=collection,
                                       metadata=getattr(chunk, "metadata", None) or {},
                                       matched=text[start:end]).to_dict()
            value = text[start:end]
            # Every span is listed, including two detectors on one range and
            # ranges that overlap; the text is masked once, over their union
            # (below), so an overlap never leaves part of a value readable.
            revealed.append(RevealedSpan(
                start=start, end=end,
                detector=str(span.get("detector", "unknown")),
                label=str(span.get("label", "")),
                preview=str(span.get("preview") or _mask(value)),
                confidence=str(explanation.get("confidence", "uncertain")),
                confidence_reason=str(explanation.get("confidence_reason", "")),
                counter_signals=tuple(explanation.get("counter_signals") or ()),
                disputed=bool(explanation.get("disputed")),
                revealed=level == RAW))
            labels.add(str(span.get("label", "")))
            detectors.add(str(span.get("detector", "unknown")))
        shown_text = text if level == RAW else mask_spans(text, mine)
        out_surfaces.append(RevealedSurface(name=surface.name, text=shown_text,
                                            spans=tuple(revealed)))

    metadata = getattr(chunk, "metadata", None) or {}
    if level == RAW:
        shown_meta: dict[str, Any] = {}
        masked_by_surface = {s.name: s.text for s in out_surfaces}
        for key, value in metadata.items():
            name = f"metadata.{key}"
            if isinstance(value, str) and name in by_name:
                shown_meta[key] = masked_by_surface.get(name, value)
            elif isinstance(value, (str, int, float, bool)) or value is None:
                shown_meta[key] = value
            else:
                shown_meta[key] = str(value)[:200]
    else:
        # Masked per value, by path, rather than per surface: surfaces are
        # deduplicated by text and stop at nested containers, so a value that
        # appears twice, sits in a nested object or list, or is a number would
        # otherwise come back raw in a view that says it is masked.
        matched = {text[int(s.get("start", 0)):int(s.get("end", 0))]
                   for s in live
                   for text in (by_name.get(str(s.get("surface")), ""),)}
        shown_meta = _mask_metadata(metadata, classifier=classifier,
                                    matched={m for m in matched if len(m.strip()) >= 3})

    recorded = [s for s in (recorded_spans or []) if isinstance(s, dict)]
    drift: Optional[bool] = None
    if recorded_spans is not None:
        drift = {_span_key(s) for s in recorded} != {_span_key(s) for s in live}

    note = ("Shown as the store holds it now, with detected values masked. "
            "Revealing a value is recorded in the audit log."
            if level == MASKED else
            "Shown as the store holds it now, values in place. This view was "
            "recorded in the audit log.")
    if drift:
        note += (" The matches differ from the ones the finding recorded: the chunk "
                 "or the detectors have changed since that assessment.")

    return RevealedChunk(
        store=store, collection=collection, chunk_id=str(getattr(chunk, "id", "")),
        level=level, fetched_at=_now(), surfaces=tuple(out_surfaces),
        metadata=shown_meta, drift=drift, recorded_spans=len(recorded),
        live_spans=len(live), labels=tuple(sorted(l for l in labels if l)),
        detectors=tuple(sorted(detectors)), note=note)


# --------------------------------------------------------------------------- #
# Sampling a collection                                                        #
# --------------------------------------------------------------------------- #

#: The most chunks one sampling call will classify. Enough to see what a
#: collection is like; not an assessment, which is what the Assess screen runs.
MAX_SAMPLE = 200


@dataclass(frozen=True)
class SampledChunk:
    chunk_id: str
    labels: tuple[str, ...]
    detectors: tuple[str, ...]
    matches: int
    preview: str          # first characters of the text surface, masked
    disputed: bool

    def to_dict(self) -> dict[str, Any]:
        return {"chunk_id": self.chunk_id, "labels": list(self.labels),
                "detectors": list(self.detectors), "matches": self.matches,
                "preview": self.preview, "disputed": self.disputed}


def sample_collection(connector: Connector, collection: str, *, classifier: Any,
                      limit: int = 50, offset: int = 0,
                      preview_chars: int = 140) -> dict[str, Any]:
    """Classify the next ``limit`` chunks of a collection, live.

    Returns rows and a coverage statement. Nothing here is a finding: the
    rows are what the classifier sees now, over a window, and the response
    says how big the window was and whether the collection continued past it.
    """
    if not getattr(connector, "content_enumerable", True):
        raise UnsupportedCapability(
            "This connector cannot enumerate chunk content, so it cannot be sampled.")
    limit = max(1, min(int(limit), MAX_SAMPLE))
    offset = max(0, int(offset))
    rows: list[SampledChunk] = []
    seen = 0
    exhausted = True
    for chunk in connector.iter_chunks(collection):
        if seen < offset:
            seen += 1
            continue
        if len(rows) >= limit:
            exhausted = False
            break
        seen += 1
        revealed = reveal_chunk(chunk, classifier=classifier, store="", collection=collection)
        text_surface = next((s for s in revealed.surfaces if s.name == "text"), None)
        preview = (text_surface.text if text_surface else "")[:preview_chars]
        spans = [sp for surface in revealed.surfaces for sp in surface.spans]
        rows.append(SampledChunk(
            chunk_id=str(getattr(chunk, "id", "")),
            labels=revealed.labels, detectors=revealed.detectors,
            matches=len(spans), preview=preview,
            disputed=any(sp.disputed for sp in spans)))
    return {
        "collection": collection, "offset": offset, "limit": limit,
        "returned": len(rows), "next_offset": offset + len(rows),
        "exhausted": exhausted,
        "sensitive": sum(1 for r in rows if r.matches),
        "chunks": [r.to_dict() for r in rows],
        "note": ("A live sample over one window of the collection, masked. It is not "
                 "an assessment and records nothing; run one from Assessments to "
                 "produce findings."),
    }
