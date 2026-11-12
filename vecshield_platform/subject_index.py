"""Where each data subject appears, recorded at scan time.

The failure this answers is concrete: a right-to-erasure request arrives, and
nobody can say which embeddings derive from that person's data, so the request
is answered by re-reading every chunk in every store. `compliance/dsar.py` does
exactly that today. It is correct and it does not scale.

**This index is itself personal data.** A list of where every data subject
appears in an estate is a high-value target — arguably more sensitive than any
single chunk it points at. Three rules follow, and they are enforced here
rather than written down somewhere else:

1. **Identifiers are never stored.** A row holds a keyed hash of the normalized
   identifier and nothing else — no address, no number, no preview. An index
   that leaked would not hand anyone a list of the people in it.
2. **The key is not in the database.** It lives in a file beside it, so a
   database copied or backed up on its own cannot be tested against a guessed
   identifier list. This raises the bar; it does not clear it. Anyone holding
   both files can confirm a guess, and the identifier space for an email
   address is small enough to enumerate. The index is not safe to publish.
3. **It is an accelerator, not an authority.** A lookup says where the subject
   *was seen*; it never says where they are not. A row can be stale, a scan can
   have been capped, and a store may never have been scanned at all. Every
   caller re-verifies against the live store before reporting, and a miss falls
   back to scanning rather than answering "not found".

Erasing a subject erases their rows too: an index that outlived the data it
pointed at would be a record of a person who asked to be forgotten.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

from vecshield.classify.surfaces import chunk_text_surfaces
from vecshield.models import Chunk

#: Detectors whose matches identify a *person a rights request would name*.
#: Deliberately narrow. A credit-card number identifies an instrument, an IP
#: address identifies a connection, and a street address identifies a building
#: — all of them are personal data, none of them is what someone writes in a
#: deletion request. Indexing everything would turn this into a second copy of
#: the findings table with a worse privacy profile.
IDENTIFIER_DETECTORS: frozenset[str] = frozenset({
    "email",
    "us_phone",
    "intl_phone",
    "us_ssn",
    "us_ssn_spaced",
    "us_ssn_context",
    "us_itin",
    "username_handle",
    "prefixed_id",
    "metadata_identifier",
    "medical_record_context",
    "uk_nino_context",
    "canada_sin_context",
    "india_aadhaar_context",
    "singapore_nric",
})

#: Detectors whose value is a run of digits that should compare equal however
#: it was punctuated: "555-867-5309" and "(555) 867 5309" are one subject.
_DIGIT_DETECTORS = frozenset({
    "us_phone", "intl_phone", "us_ssn", "us_ssn_spaced", "us_ssn_context",
    "us_itin", "uk_nino_context", "canada_sin_context", "india_aadhaar_context",
})

_WHITESPACE = re.compile(r"\s+")

SALT_BYTES = 32


@dataclass(frozen=True)
class SubjectLocation:
    """One place one subject was observed. Carries no identifier."""

    subject_key: str
    store_id: str
    collection: str
    chunk_id: str
    detector: str
    surface: str

    def to_dict(self) -> dict[str, Any]:
        return {"subject_key": self.subject_key, "store_id": self.store_id,
                "collection": self.collection, "chunk_id": self.chunk_id,
                "detector": self.detector, "surface": self.surface}


def salt_path_for(db_path: str | Path) -> Path:
    """Where the key for a given history database lives."""
    return Path(str(db_path) + ".subject-key")


def load_or_create_salt(path: str | Path) -> bytes:
    """Read the index key, creating it once if it is not there.

    The key must be stable for the life of a deployment: rotating it makes
    every existing row unmatchable, which is a silent way to lose an index
    rather than an error anyone would notice. Written 0600 and never logged.

    The key is raw random bytes, so any of them can be whitespace and it is
    read back exactly as written. Two older forms are still accepted: a file
    earlier releases wrote in Windows text mode (each 0x0A stored as 0x0D
    0x0A), and an operator-provisioned key with surrounding whitespace.
    """
    p = Path(path)
    if p.exists():
        raw = p.read_bytes()
        if len(raw) == SALT_BYTES:
            return raw
        untranslated = raw.replace(b"\r\n", b"\n")
        if len(untranslated) == SALT_BYTES:
            return untranslated
        stripped = raw.strip()
        if len(stripped) >= SALT_BYTES:
            return stripped
        raise ValueError(
            f"{p} is too short to be an index key. Refusing to continue: "
            "replacing it silently would orphan every row already indexed.")
    p.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(SALT_BYTES)
    # Create with the right mode from the start; a chmod after the write leaves
    # a window where the key is world-readable. O_BINARY (Windows only) stops
    # the write from turning each 0x0A byte of the key into 0x0D 0x0A.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(p, flags, 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    return key


def normalize_identifier(value: str, detector: str = "") -> str:
    """Fold an identifier to the form the index compares on.

    A subject writing "Maya.Brooks@Example.test " in a deletion request must
    match the chunk holding "maya.brooks@example.test". Normalization is the
    only reason a lookup works at all, so it has to be applied identically when
    indexing and when looking up — which is why both paths call this.
    """
    text = _WHITESPACE.sub(" ", (value or "").strip())
    if detector in _DIGIT_DETECTORS:
        digits = re.sub(r"\D", "", text)
        return digits or text.lower()
    return text.lower()


def subject_key(value: str, salt: bytes, *, detector: str = "") -> str:
    """The keyed hash a row is filed under. One-way, and useless without the key."""
    normalized = normalize_identifier(value, detector)
    if not normalized:
        return ""
    return hmac.new(salt, normalized.encode("utf-8"), hashlib.sha256).hexdigest()


def candidate_keys(subject: str, salt: bytes) -> list[str]:
    """Every key a free-text subject string could be filed under.

    A rights request names a person in one form; the index filed them under
    whichever detector matched. An email normalizes one way and a phone number
    another, and the caller does not know which the subject gave, so both are
    tried rather than guessing.
    """
    keys: list[str] = []
    for detector in ("", "us_phone"):
        key = subject_key(subject, salt, detector=detector)
        if key and key not in keys:
            keys.append(key)
    return keys


def locations_from_chunk(
    chunk: Chunk,
    classification: Any,
    *,
    store_id: str,
    salt: bytes,
    detectors: Iterable[str] = IDENTIFIER_DETECTORS,
) -> list[SubjectLocation]:
    """Extract indexable subject locations from one classified chunk.

    Pure, and it never returns the identifier it hashed. The raw value is read
    back out of the chunk's own surfaces using the span offsets, hashed, and
    dropped on the way out of this function.
    """
    spans = getattr(classification, "spans", None) or []
    if not spans:
        return []
    wanted = frozenset(detectors)
    surfaces = {s.name: s.text for s in chunk_text_surfaces(chunk)}

    # Detectors overlap: `username_handle` matches the local part of an address
    # that `email` already matched in full. Indexing both would file one person
    # under two subjects, and the shorter one is a fragment, not an identifier
    # anybody would put on a request. The longest match on a given stretch of
    # text wins and the ones inside it are dropped.
    indexable = [sp for sp in spans
                 if str(sp.get("detector") or "") in wanted
                 and isinstance(sp.get("start"), int)
                 and isinstance(sp.get("end"), int)]
    indexable.sort(key=lambda sp: (sp["start"] - sp["end"], sp["start"]))

    out: list[SubjectLocation] = []
    seen: set[tuple[str, str]] = set()
    claimed: dict[str, list[tuple[int, int]]] = {}
    for span in indexable:
        detector = str(span["detector"])
        surface_name = str(span.get("surface") or "text")
        text = surfaces.get(surface_name)
        if text is None:
            continue
        start, end = int(span["start"]), int(span["end"])
        spans_here = claimed.setdefault(surface_name, [])
        if any(start < kept_end and end > kept_start for kept_start, kept_end in spans_here):
            continue
        spans_here.append((start, end))
        value = text[start:end]
        key = subject_key(value, salt, detector=detector)
        if not key or (key, detector) in seen:
            continue
        seen.add((key, detector))
        out.append(SubjectLocation(
            subject_key=key, store_id=store_id, collection=chunk.collection,
            chunk_id=chunk.id, detector=detector, surface=surface_name))
    return out


def make_sink(store_id: str, salt: bytes, sink: Any,
              detectors: Iterable[str] = IDENTIFIER_DETECTORS):
    """Adapt a (chunk, classification) callback onto a location collector.

    ``sink`` is anything callable with a list of SubjectLocation. Returning a
    closure keeps the scan engine ignorant of both the key and the store id.
    """
    def record(chunk: Chunk, classification: Any) -> None:
        locations = locations_from_chunk(chunk, classification, store_id=store_id,
                                         salt=salt, detectors=detectors)
        if locations:
            sink(locations)
    return record


def lookup_limits(rows: Iterable[dict], *, stores_scanned: Optional[int] = None) -> list[str]:
    """What a lookup result cannot be read as saying.

    Returned alongside every lookup so a caller cannot treat an empty result as
    an answer. These are statements about the index, not about the data.
    """
    limits = [
        "The index records where a subject was seen by a scan. It does not "
        "record where they are absent: a store never scanned, a scan that was "
        "capped, or data written since the last scan will not appear here.",
    ]
    partial = [r for r in rows if not r.get("coverage_complete")]
    if partial:
        limits.append(
            f"{len(partial)} row(s) came from a scan that did not inspect its "
            "whole scope, so the subject may appear in places that scan never "
            "reached.")
    if stores_scanned == 0:
        limits.append("No store in this deployment has been indexed yet.")
    return limits
