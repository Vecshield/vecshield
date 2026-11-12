"""How sensitive values are represented in a collection (VCR-03 to VCR-09).

The classifier answers *what* a value is. This module answers *in what form it
is stored*: readable, masked, truncated, tokenized, a pseudonymous surrogate, a
hash candidate, or opaque. It runs as an observer on the classification pass
(``scan_store(..., observer=RepresentationObserver())``), so the store is read
once, and it keeps counts and masked previews only — never a raw value.

Rules, in the order they are applied to one value:

- ``masked``: mask characters (``**``, ``•``, ``xxx``, ``###``) or a redaction
  marker such as ``[REDACTED]`` — ``****1234``, ``j***@e***.com``.
- ``truncated``: a digit string that keeps at most eight leading and four
  trailing digits, and either spans 13-19 positions (``411111******1111``),
  sits under a card-like key, or hides at least six positions
  (``******1111``). PCI truncation keeps the PAN's shape; a short mask such
  as ``****1234`` is only ``masked``.
- ``tokenized``: an explicit token prefix (``tok_``, ``tkn_``, ``token:``,
  ``vault:``), or format-preserving digits that fail Luhn under a card-like key.
- ``hash_candidate``: crypt-style prefixes (``$2b$``, ``$argon2id$``, ...), or
  a whole value of 32/40/64/128 hexadecimal characters.
- ``pseudonymous``: a UUID, or a prefixed random identifier, under a key that
  names a data subject or is itself sensitive.
- ``opaque``: 20+ characters of base64/hex alphabet mixing letters and digits
  with high character entropy. High entropy is only ever "opaque": nothing
  here names an algorithm or calls a value encrypted.
- ``plaintext``: a detector recognised the value itself, a key-context detector
  fired (``patient_id: 4481726``), or the value has a readable format (email,
  phone, SSN, Luhn-valid PAN, date; words under a sensitive key).
- ``unknown``: anything else.

A detector firing on a value outranks the entropy-based classes: an access key
is high-entropy by nature, and calling a leaked credential "opaque" would turn
an exposure into protection. Only explicit markers (mask characters, token and
crypt prefixes, Luhn-failing digits under a card key) survive detection.

``masked``, ``truncated``, ``tokenized``, ``pseudonymous``, ``hash_candidate``
and ``opaque`` count as protected values. Protection drift (VCR-08) is
narrower: a metadata field drifts when, within one scan, at least one of its
whole values shows a protection *mechanism* (every protected class except
``opaque``, because entropy is not evidence of a mechanism) and at least one
of its whole values is plaintext. Free-text metadata fields are not judged for
drift: prose naturally mixes a masked card and a readable name.
"""

from __future__ import annotations

import math
import re
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Iterable, Optional

from vecshield.classify.regex_classifier import _card_number_ok, _luhn_ok, _redact
from vecshield.classify.surfaces import (
    _SENSITIVE_KEY_PARTS,
    _metadata_scalars,
    chunk_text_surfaces,
)
from vecshield.models import (
    Chunk,
    Classification,
    Collection,
    Finding,
    ScanJob,
    Severity,
)
from vecshield.score.inversion import inversion_risk
from vecshield_platform.compliance.fingerprint import apply_fingerprints
from vecshield_platform.compliance.policy import Policy
from vecshield_platform.coverage import set_job_coverage
from vecshield_platform.crypto.states import (
    DATA_REPRESENTATION,
    DIRECT_IDENTIFIER_EXPOSURE,
    NOT_APPLICABLE,
    NOT_OBSERVABLE,
    NOT_VERIFIED,
    OBSERVED_EXPOSURE,
    PAN_REPRESENTATION,
    PROTECTED_REPRESENTATION,
    crypto_outcome,
)

# ---- Representation classes ----------------------------------------------

PLAINTEXT = "plaintext"
MASKED = "masked"
TRUNCATED = "truncated"
TOKENIZED = "tokenized"
PSEUDONYMOUS = "pseudonymous"
HASH_CANDIDATE = "hash_candidate"
OPAQUE = "opaque"
UNKNOWN = "unknown"

REPRESENTATION_CLASSES = (PLAINTEXT, MASKED, TRUNCATED, TOKENIZED, PSEUDONYMOUS,
                          HASH_CANDIDATE, OPAQUE, UNKNOWN)
PROTECTED_CLASSES = frozenset({MASKED, TRUNCATED, TOKENIZED, PSEUDONYMOUS,
                               HASH_CANDIDATE, OPAQUE})
#: Protected classes that show a deliberate mechanism; only these establish drift.
MECHANISM_CLASSES = PROTECTED_CLASSES - {OPAQUE}

#: PAN forms, reported whether or not the classifier labelled the value PCI.
PAN_FULL = "full"
PAN_CLASSES = (PAN_FULL, TRUNCATED, TOKENIZED, HASH_CANDIDATE, OPAQUE)

STATEMENT = "Embeddings are not treated as cryptographic protection."

#: Bounds on what one collection's accumulator keeps.
MAX_FIELDS = 200
MAX_EXAMPLES = 5
_MAX_ALTERNATIVES = 50

# ---- Shapes --------------------------------------------------------------

# A run of x only masks when it is not part of a word: "maxxxwell@example.com"
# is a readable address, not a masked one.
_MASK_RUN = re.compile(r"[*•]{2,}|#{3,}|(?<![A-Za-z])[xX]{3,}(?![A-Za-z])")
_REDACTION_MARKER = re.compile(r"^[\[<(]?(?:redacted|masked|removed|hidden)[\]>)]?$", re.I)
_TRUNCATION = re.compile(r"^(\d{0,8})([*•xX#]{3,})(\d{2,4})$")
_TOKEN_PREFIX = re.compile(r"^(?:tok|tkn|token)[_:-][A-Za-z0-9_-]{6,}$|^vault[:_]", re.I)
_CRYPT_PREFIX = re.compile(r"^\$(?:2[abxy]?|argon2(?:id|i|d)|scrypt|pbkdf2[-\w]*|[156y])\$")
_HEX_DIGEST = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128})$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_PREFIXED_ID = re.compile(r"^[a-z]{2,6}_[A-Za-z0-9]{10,}$")
_OPAQUE_ALPHABET = re.compile(r"^[A-Za-z0-9+/_=-]{20,}$")
_DIGITS = re.compile(r"^\d{13,19}$")

_EMAIL = re.compile(r"^[\w.+-]+@[\w-]+(?:\.[\w-]+)+$")
_PHONE = re.compile(r"^\+?\d[\d\s().-]{6,18}\d$")
_SSN = re.compile(r"^\d{3}-\d{2}-\d{4}$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$|^\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}$")
_WORDS = re.compile(r"[A-Za-z]{2,}")

# Free-text protected forms: counted as protected sensitive values in text even
# when no detector fired, so a collection that stores only masked cards can
# show a protected representation rather than "nothing sensitive".
_TEXT_PROTECTED = (
    re.compile(r"(?<![\w*•#])[0-9*•xX#][0-9*•xX# -]{2,24}[0-9](?![\w*•#])"),
    re.compile(r"[\w.+-]*[*•][\w.+*•-]*@[\w.*•-]+\.[A-Za-z]{2,}"
               r"|[\w.+-]+@[\w.-]*[*•][\w.*•-]*\.[A-Za-z]{2,}"),
    re.compile(r"\b(?:tok|tkn)_[A-Za-z0-9]{8,}\b|\bvault:v\d+:[A-Za-z0-9+/=]+"),
    re.compile(r"\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}|\$argon2(?:id|i|d)\$\S+"),
    re.compile(r"\[(?:REDACTED|MASKED)\]|<redacted>", re.I),
)
_FULL_PAN = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_SHORT_CARD_MASK = re.compile(r"(?<![A-Za-z])[*•xX#]{4,}[ -]?\d{4}\b")
_CARD_CONTEXT = re.compile(r"\b(?:card|ending|visa|mastercard|amex|pan)\b", re.I)

# ---- Keys ----------------------------------------------------------------

_CARD_TOKENS = frozenset({"card", "cards", "cc", "ccn", "ccnum", "pan", "cardnumber",
                          "cardnum", "cardno", "creditcard", "debitcard", "paymentcard"})
_SUBJECT_TOKENS = frozenset({"customer", "user", "patient", "member", "employee",
                             "subscriber", "contact", "person", "subject", "client",
                             "account", "holder", "cardholder", "individual", "party",
                             "beneficiary"})
_ID_TOKENS = frozenset({"id", "uuid", "guid", "identifier", "ref", "token", "key"})
_PERSON_QUALIFIERS = _SUBJECT_TOKENS | {"first", "last", "full", "given", "family",
                                        "middle", "maiden"}
_SENSITIVE_SEQUENCES = tuple(tuple(part.split("_")) for part in _SENSITIVE_KEY_PARTS)


#: Distinct key paths whose analysis is remembered. A collection has few
#: distinct keys, but every value of every chunk asks about its key.
_KEY_CACHE = 4096


def _path_key(path: Any) -> str:
    """The text the key helpers analyse: ``str(path)``, or ``""`` when falsy."""
    return str(path) if path else ""


@lru_cache(maxsize=_KEY_CACHE)
def _key_token_tuple(path: str) -> tuple[str, ...]:
    """Lower-case word tokens of a path's last two segments.

    Matching on tokens rather than substrings keeps ``meeting_notes`` from
    reading as a TIN field and ``cardinality`` from reading as a card field.
    """
    if not path:
        return ()
    segments = [s for s in path.split(".") if s and not s.isdigit()][-2:]
    words: list[str] = []
    for segment in segments:
        segment = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", segment)
        words.extend(w for w in re.split(r"[^A-Za-z0-9]+", segment.lower()) if w)
    return tuple(words)


def _has_sequence(tokens: tuple[str, ...], sequence: tuple[str, ...]) -> bool:
    n = len(sequence)
    return any(tuple(tokens[i:i + n]) == sequence for i in range(len(tokens) - n + 1))


def sensitive_key(path: Optional[str]) -> bool:
    """Whether a key names sensitive data, by whole-token ``_SENSITIVE_KEY_PARTS``."""
    return _sensitive_key(_path_key(path))


@lru_cache(maxsize=_KEY_CACHE)
def _sensitive_key(path: str) -> bool:
    tokens = _key_token_tuple(path)
    return (any(_has_sequence(tokens, seq) for seq in _SENSITIVE_SEQUENCES)
            or _card_key(path) or _key_identifier_kind(path) is not None)


def card_key(path: Optional[str]) -> bool:
    return _card_key(_path_key(path))


@lru_cache(maxsize=_KEY_CACHE)
def _card_key(path: str) -> bool:
    tokens = _key_token_tuple(path)
    return (any(t in _CARD_TOKENS for t in tokens)
            or _has_sequence(tokens, ("credit", "card"))
            or _has_sequence(tokens, ("card", "number")))


def subject_id_key(path: Optional[str]) -> bool:
    """A key holding an identifier for a data subject (``customer_id``, ``userId``)."""
    return _subject_id_key(_path_key(path))


@lru_cache(maxsize=_KEY_CACHE)
def _subject_id_key(path: str) -> bool:
    tokens = _key_token_tuple(path)
    if "pseudonym" in tokens:
        return True
    return bool(tokens) and tokens[-1] in _ID_TOKENS and bool(set(tokens) & _SUBJECT_TOKENS)


_DETECTOR_KINDS = (("email", "email"), ("phone", "phone"), ("ssn", "national_id"),
                   ("iban", "account_number"), ("bank", "account_number"),
                   ("person", "name"), ("passport", "passport"))


def direct_identifier_kind(path: Optional[str], detectors: Iterable[str] = ()) -> Optional[str]:
    """The kind of direct identifier a field holds, from its key or its detectors.

    Subject-id keys (``customer_id``) are not direct identifiers by name: they
    are where a pseudonymous alternative lives. They become one only when a
    detector recognises, say, an email address in them.
    """
    kind = _key_identifier_kind(_path_key(path))
    if kind is not None:
        return kind
    for fragment, kind in _DETECTOR_KINDS:
        if any(fragment in str(d).lower() for d in detectors):
            return kind
    return None


@lru_cache(maxsize=_KEY_CACHE)
def _key_identifier_kind(path: str) -> Optional[str]:
    """The kind of direct identifier a key names, from its tokens alone."""
    tokens = _key_token_tuple(path)
    token_set = set(tokens)
    if token_set & {"email", "emailaddress", "mail"}:
        return "email"
    if token_set & {"phone", "mobile", "telephone", "tel", "cell", "phonenumber", "fax"}:
        return "phone"
    if token_set & {"ssn", "nino", "sin"} or _has_sequence(tokens, ("social", "security")):
        return "national_id"
    if token_set & {"tin", "ein"} or _has_sequence(tokens, ("tax", "id")):
        return "tax_id"
    if token_set & {"dob", "birthdate", "dateofbirth"} or "birth" in token_set:
        return "date_of_birth"
    if token_set & {"surname", "firstname", "lastname", "fullname", "givenname"} or (
            "name" in token_set and token_set & _PERSON_QUALIFIERS):
        return "name"
    if "ip" in token_set or "ipaddress" in token_set:
        return "ip_address"
    if (token_set & {"street", "postcode", "zipcode", "zip", "postal"}
            or ("address" in token_set and not token_set & {"email", "mac", "wallet"})):
        return "address"
    if "passport" in token_set:
        return "passport"
    if "driver" in token_set and token_set & {"license", "licence"}:
        return "driver_license"
    if token_set & {"iban", "routing"} or _has_sequence(tokens, ("account", "number")):
        return "account_number"
    if "mrn" in token_set or _has_sequence(tokens, ("medical", "record")):
        return "medical_record_number"
    return None


def _entropy(text: str) -> float:
    counts = Counter(text)
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _shape(text: str, key: Optional[str]) -> tuple[Optional[str], bool]:
    """The protected class a value's shape shows, and whether it is explicit.

    Explicit shapes carry a deliberate marker (mask characters, a token or crypt
    prefix, Luhn-failing digits under a card key) and survive a detector hit.
    Inferred shapes (hex length, UUID, entropy) do not.
    """
    compact = re.sub(r"[\s-]", "", text)
    is_card = card_key(key)
    subject = subject_id_key(key) or sensitive_key(key)

    m = _TRUNCATION.fullmatch(compact)
    if m and (13 <= len(compact) <= 19 or is_card or len(m.group(2)) >= 6):
        return TRUNCATED, True
    if _MASK_RUN.search(text) or _REDACTION_MARKER.fullmatch(text):
        return MASKED, True
    if _TOKEN_PREFIX.match(text):
        return TOKENIZED, True
    if is_card and _DIGITS.fullmatch(compact) and not _luhn_ok(compact):
        return TOKENIZED, True
    if _CRYPT_PREFIX.match(text):
        return HASH_CANDIDATE, True
    if _HEX_DIGEST.fullmatch(text):
        return HASH_CANDIDATE, False
    if _UUID.fullmatch(text) or _PREFIXED_ID.fullmatch(text):
        if is_card:
            return TOKENIZED, False
        if subject:
            return PSEUDONYMOUS, False
        if _UUID.fullmatch(text):
            return None, False
    if (_OPAQUE_ALPHABET.fullmatch(text) and re.search(r"\d", text)
            and re.search(r"[A-Za-z]", text) and _entropy(text) >= 3.5):
        if is_card:
            return TOKENIZED, False
        return (PSEUDONYMOUS if subject_id_key(key) else OPAQUE), False
    return None, False


def _readable(text: str, key: Optional[str]) -> bool:
    compact = re.sub(r"[\s-]", "", text)
    if (_EMAIL.fullmatch(text) or _SSN.fullmatch(text) or _DATE.fullmatch(text)
            or (_DIGITS.fullmatch(compact) and _card_number_ok(compact))):
        return True
    if _PHONE.fullmatch(text) and (text.startswith("+") or re.search(r"[\s().-]", text)):
        return True
    return bool(key) and sensitive_key(key) and bool(_WORDS.search(text))


def _represent(value: Any, key: Optional[str], detected: bool,
               key_context: bool) -> tuple[str, bool]:
    text = str(value).strip() if value is not None else ""
    if not text:
        return UNKNOWN, False
    shape, explicit = _shape(text, key)
    if shape and (explicit or not detected):
        return shape, explicit
    if detected or key_context or _readable(text, key):
        return PLAINTEXT, False
    return UNKNOWN, False


def classify_representation(value: Any, *, key: Optional[str] = None,
                            detected: bool = False, key_context: bool = False) -> str:
    """Classify how one value is represented. Pure; see the module docstring.

    ``detected``: a detector recognised the value itself as sensitive.
    ``key_context``: a detector fired on the ``key: value`` surface only.
    """
    return _represent(value, key, detected, key_context)[0]


def pan_representation(value: Any, *, key: Optional[str] = None) -> Optional[str]:
    """The PAN form of one whole value, or None when it is not PAN-related.

    Full PAN is Luhn-valid 13-19 digits (the classifier's own validator), under
    any key. A positional truncation counts anywhere; tokens, hashes and opaque
    values count only under a card-like key, where they stand in for a PAN.
    """
    text = str(value).strip() if value is not None else ""
    if not text:
        return None
    compact = re.sub(r"[\s-]", "", text)
    if _DIGITS.fullmatch(compact) and _card_number_ok(compact):
        return PAN_FULL
    m = _TRUNCATION.fullmatch(compact)
    if m and 13 <= len(compact) <= 19:
        return TRUNCATED
    if not card_key(key):
        return None
    shape, _ = _shape(text, key)
    if shape in (TRUNCATED, MASKED):
        return TRUNCATED
    if shape in (TOKENIZED, PSEUDONYMOUS):
        return TOKENIZED
    if shape in (HASH_CANDIDATE, OPAQUE):
        return shape
    return None


def find_pan_representations(text: str) -> list[tuple[str, int, int]]:
    """PAN forms in free text as ``(class, start, end)``, independent of labels."""
    found: list[tuple[str, int, int]] = []
    taken: list[tuple[int, int]] = []

    def free(start: int, end: int) -> bool:
        return all(end <= s or start >= e for s, e in taken)

    for m in _FULL_PAN.finditer(text):
        if _card_number_ok(m.group(0)):
            found.append((PAN_FULL, m.start(), m.end()))
            taken.append((m.start(), m.end()))
    for m in _TEXT_PROTECTED[0].finditer(text):
        compact = re.sub(r"[\s-]", "", m.group(0))
        if _TRUNCATION.fullmatch(compact) and 13 <= len(compact) <= 19 and free(*m.span()):
            found.append((TRUNCATED, m.start(), m.end()))
            taken.append(m.span())
    for m in _SHORT_CARD_MASK.finditer(text):
        if free(*m.span()) and _CARD_CONTEXT.search(text[max(0, m.start() - 24):m.start()]):
            found.append((TRUNCATED, m.start(), m.end()))
            taken.append(m.span())
    return sorted(found, key=lambda item: item[1])


# ---- Accumulation ---------------------------------------------------------

@dataclass
class _Field:
    labels: set = field(default_factory=set)
    classes: Counter = field(default_factory=Counter)
    mechanism: int = 0
    plaintext: int = 0


@dataclass
class _Direct:
    kind: str
    count: int = 0
    alternatives: Counter = field(default_factory=Counter)


@dataclass
class _State:
    chunks: int = 0
    embedding: bool = False
    text: bool = False
    metadata: bool = False
    dimension: Optional[int] = None
    surfaces: dict = field(default_factory=lambda: {"text": Counter(), "metadata": Counter()})
    fields: dict = field(default_factory=dict)
    fields_not_tracked: int = 0
    pan: Counter = field(default_factory=Counter)
    pan_surfaces: Counter = field(default_factory=Counter)
    records_with_pan: int = 0
    examples: list = field(default_factory=list)
    direct: dict = field(default_factory=dict)
    alternatives: set = field(default_factory=set)
    errors: int = 0


def _normalise_path(path: str) -> str:
    return ".".join("*" if part.isdigit() else part for part in path.split("."))


def _merged_spans(text: str, spans: list[dict]) -> list[tuple[int, int, set]]:
    """Overlapping spans merged, so two detectors on one value count it once."""
    valid = []
    for span in spans:
        start, end = span.get("start"), span.get("end")
        if isinstance(start, int) and isinstance(end, int) and 0 <= start < end <= len(text):
            valid.append((start, end, span.get("label")))
    valid.sort(key=lambda item: (item[0], -item[1]))
    merged: list[tuple[int, int, set]] = []
    for start, end, label in valid:
        if merged and start < merged[-1][1]:
            s, e, labels = merged[-1]
            merged[-1] = (s, max(e, end), labels | ({label} if label else set()))
        else:
            merged.append((start, end, {label} if label else set()))
    return merged


def _text_values(text: str, spans: list[dict]) -> list[tuple[str, set]]:
    """Sensitive values in free text: detector spans, then unflagged protected forms."""
    values: list[tuple[str, set]] = []
    taken: list[tuple[int, int]] = []
    for start, end, labels in _merged_spans(text, spans):
        values.append((classify_representation(text[start:end], detected=True), labels))
        taken.append((start, end))
    for pattern in _TEXT_PROTECTED:
        for m in pattern.finditer(text):
            if any(not (m.end() <= s or m.start() >= e) for s, e in taken):
                continue
            cls = classify_representation(m.group(0))
            if cls in PROTECTED_CLASSES:
                values.append((cls, set()))
                taken.append(m.span())
    return values


def _free_text(text: str, value_spans: list[dict]) -> bool:
    if not re.search(r"\s", text):
        return False
    if len(text) > 40:
        return True
    covered = sum(e - s for s, e, _ in _merged_spans(text, value_spans))
    return bool(value_spans) and covered < len(text) / 2


class RepresentationObserver:
    """Accumulates representation evidence per collection during ``scan_store``.

    Call it as the scan's ``observer``; then call :meth:`job`. It never raises:
    a chunk it cannot read is counted as an error and makes that collection's
    coverage partial.

    ``collections`` (optional) supplies inventory: the embedding model and
    dimension feed ``inversion_risk``, and ``count`` decides completeness when
    no classification job is supplied to :meth:`job`.
    """

    def __init__(self, collections: Optional[Iterable[Collection]] = None) -> None:
        self._inventory: dict[str, Collection] = {c.name: c for c in (collections or ())}
        self._states: dict[str, _State] = {}
        self._capped: set[str] = set()
        self._errors = 0

    def mark_capped(self, collection: str) -> None:
        """Record that the scan stopped before reading the whole collection."""
        self._capped.add(collection)

    def __call__(self, chunk: Chunk, classification: Classification) -> None:
        state: Optional[_State] = None
        try:
            state = self._states.setdefault(str(chunk.collection or ""), _State())
            self._observe(state, chunk, classification)
        except Exception:  # noqa: BLE001 - an observer must not cost the scan
            if state is not None:
                state.errors += 1
            else:
                self._errors += 1

    def _observe(self, st: _State, chunk: Chunk, classification: Classification) -> None:
        st.chunks += 1
        if chunk.embedding is not None and len(chunk.embedding):
            st.embedding = True
            st.dimension = st.dimension or len(chunk.embedding)
        if chunk.text and str(chunk.text).strip():
            st.text = True
        if chunk.metadata:
            st.metadata = True

        surfaces = {s.name: s.text for s in chunk_text_surfaces(chunk)}
        by_surface: dict[str, list[dict]] = {}
        for span in (classification.spans if classification else None) or []:
            by_surface.setdefault(str(span.get("surface", "text")), []).append(span)

        full_pan = False
        if "text" in surfaces:
            text = surfaces["text"]
            for cls, _ in _text_values(text, by_surface.get("text", [])):
                st.surfaces["text"][cls] += 1
            for cls, start, end in find_pan_representations(text):
                full_pan |= cls == PAN_FULL
                self._pan(st, cls, text[start:end], "text")

        chunk_alternatives: set[str] = set()
        chunk_direct: set[str] = set()
        for raw_path, value in _metadata_scalars(chunk.metadata or {}):
            text = str(value).strip()[:5000]
            if not text:
                continue
            path = _normalise_path(raw_path)
            value_spans = by_surface.get(f"metadata.{raw_path}", [])
            key_spans = by_surface.get(f"metadata_key.{raw_path}", [])
            detectors = {str(s.get("detector", "")) for s in value_spans}

            if _free_text(text, value_spans):
                values = _text_values(text, value_spans)
                for cls, labels in values:
                    st.surfaces["metadata"][cls] += 1
                    self._field(st, path, cls, labels, atomic=False)
                for cls, start, end in find_pan_representations(text):
                    full_pan |= cls == PAN_FULL
                    self._pan(st, cls, text[start:end], f"metadata.{path}")
                continue

            cls, explicit = _represent(text, raw_path, bool(value_spans), bool(key_spans))
            sensitive = (bool(value_spans) or bool(key_spans) or sensitive_key(raw_path)
                         or (explicit and cls in PROTECTED_CLASSES))
            pan = pan_representation(text, key=raw_path)
            if pan:
                full_pan |= pan == PAN_FULL
                self._pan(st, pan, text, f"metadata.{path}")
            if not sensitive:
                continue
            labels = {s.get("label") for s in value_spans + key_spans if s.get("label")}
            st.surfaces["metadata"][cls] += 1
            self._field(st, path, cls, labels, atomic=True)

            if cls == PLAINTEXT:
                kind = direct_identifier_kind(raw_path, detectors)
                if kind and (path in st.direct or len(st.direct) < MAX_FIELDS):
                    st.direct.setdefault(path, _Direct(kind)).count += 1
                    chunk_direct.add(path)
            elif cls in PROTECTED_CLASSES and subject_id_key(raw_path):
                chunk_alternatives.add(path)

        for path in chunk_direct:
            st.direct[path].alternatives.update(chunk_alternatives)
        for path in chunk_alternatives:
            if len(st.alternatives) < _MAX_ALTERNATIVES:
                st.alternatives.add(path)
        if full_pan:
            st.records_with_pan += 1

    @staticmethod
    def _field(st: _State, path: str, cls: str, labels: set, *, atomic: bool) -> None:
        f = st.fields.get(path)
        if f is None:
            if len(st.fields) >= MAX_FIELDS:
                st.fields_not_tracked += 1
                return
            f = st.fields[path] = _Field()
        f.labels |= labels
        f.classes[cls] += 1
        if atomic and cls in MECHANISM_CLASSES:
            f.mechanism += 1
        if atomic and cls == PLAINTEXT:
            f.plaintext += 1

    @staticmethod
    def _pan(st: _State, cls: str, raw: str, surface: str) -> None:
        st.pan[cls] += 1
        st.pan_surfaces[surface.split(".", 1)[0]] += cls == PAN_FULL
        if len(st.examples) < MAX_EXAMPLES:
            # Masked with the classifier's own redaction; the raw value is dropped here.
            st.examples.append(f"{_redact(raw)} ({cls}, {surface})")

    # ---- Results ----------------------------------------------------------

    def job(self, store: str, *, classification: Optional[ScanJob] = None) -> ScanJob:
        """One ScanJob holding the three checks per collection, plus findings.

        Completeness comes from ``classification`` (the scan_store job this
        observer rode on) when given: each collection's ``data_classification``
        outcome says whether the scan read it all, and why not. Without it, a
        collection is complete when it was read, was not ``mark_capped``, and
        at least its inventory ``count`` of chunks was seen.

        Each outcome's ``reason`` is one short sentence for a table cell; the
        caveats that qualify it (risk dependence, sampling gaps) are kept in
        the details as ``note``.
        """
        job = ScanJob(id=f"repr-{uuid.uuid4().hex[:12]}", store=store)
        per_collection, store_level = _scan_coverage(classification)
        names = list(dict.fromkeys([*per_collection, *self._inventory, *self._states]))
        outcomes: list[dict] = []
        if not names:
            outcomes.extend(self._outcomes(job, store, None, store_level))
        for name in names:
            outcomes.extend(self._outcomes(job, store, name,
                                           per_collection.get(name, store_level)))
        set_job_coverage(job, outcomes, collections_expected=len(names),
                         collections_inspected=sum(1 for s in self._states.values() if s.chunks),
                         chunks_scanned=sum(s.chunks for s in self._states.values()))
        job.stats["check"] = DATA_REPRESENTATION
        if self._errors or any(s.errors for s in self._states.values()):
            job.stats["observer_errors"] = self._errors + sum(
                s.errors for s in self._states.values())
        apply_fingerprints(job.findings)
        job.finished_at = datetime.now(timezone.utc)
        return job

    def _outcomes(self, job: ScanJob, store: str, name: Optional[str],
                  scan: Optional[dict]) -> list[dict]:
        st = self._states.get(name or "") or _State()
        scan_outcome = (scan or {}).get("outcome")
        scan_reason = (scan or {}).get("reason") or ""
        inventory = self._inventory.get(name or "")

        if st.chunks == 0 and scan_outcome in ("unsupported", "error"):
            state, outcome = ((NOT_OBSERVABLE, "unsupported") if scan_outcome == "unsupported"
                              else (NOT_VERIFIED, "error"))
            reason = "The records could not be read, so their representation is unknown."
            return [crypto_outcome(check, store, name, state=state, outcome=outcome,
                                   reason=reason, complete=False, chunks_scanned=0,
                                   **details, note=scan_reason)
                    for check, details in self._details(st, inventory).items()]

        if scan is not None:
            complete = scan.get("coverage", {}).get("complete") is True
        else:
            expected = inventory.count if inventory is not None else None
            complete = st.chunks > 0 or expected == 0
            if expected:
                complete = st.chunks >= expected
        gap = ""
        if name in self._capped:
            complete, gap = False, "The configured chunk limit was reached."
        elif st.errors:
            complete = False
            gap = f"{_count(st.errors, 'record')} could not be analysed."
        elif not complete:
            gap = scan_reason or "Not every record in the collection was examined."
        if st.fields_not_tracked:
            gap = _note(gap, f"{_count(st.fields_not_tracked, 'value')} "
                             f"{_verb(st.fields_not_tracked, 'was', 'were')} in fields beyond "
                             f"the {MAX_FIELDS}-field limit and counted by surface only.")

        details = self._details(st, inventory)
        results = [
            self._data_outcome(store, name, st, details[DATA_REPRESENTATION], complete, gap),
            self._pan_outcome(store, name, st, details[PAN_REPRESENTATION], complete, gap),
            self._direct_outcome(store, name, details[DIRECT_IDENTIFIER_EXPOSURE],
                                 complete, gap),
        ]
        self._findings(job, store, name, st, details)
        return results

    def _details(self, st: _State, inventory: Optional[Collection]) -> dict[str, dict]:
        def presence(seen: bool) -> str:
            return "unknown" if st.chunks == 0 else ("present" if seen else "absent")

        embedding = st.embedding or bool(inventory and inventory.dimension)
        model = inventory.embedding_model if inventory else None
        dimension = (inventory.dimension if inventory else None) or st.dimension
        risk = inversion_risk(model, dimension) if embedding and (model or dimension) else None

        fields = []
        for path in sorted(st.fields):
            f = st.fields[path]
            protected = sum(n for c, n in f.classes.items() if c in PROTECTED_CLASSES)
            plain = f.classes.get(PLAINTEXT, 0)
            fields.append({
                "path": path, "surface": "metadata", "labels": sorted(f.labels),
                "classes": dict(sorted(f.classes.items())),
                "protected_fraction": (round(protected / (protected + plain), 3)
                                       if protected + plain else None),
                "drift": f.mechanism >= 1 and f.plaintext >= 1,
            })
        totals: Counter = Counter()
        for counts in st.surfaces.values():
            totals.update(counts)
        protected_values = sum(n for c, n in totals.items() if c in PROTECTED_CLASSES)

        direct = []
        for path in sorted(st.direct):
            d = st.direct[path]
            alternative = (d.alternatives.most_common(1)[0][0] if d.alternatives
                           else min(st.alternatives) if st.alternatives else None)
            direct.append({"path": path, "kind": d.kind, "count": d.count,
                           "pseudonymous_alternative": alternative})

        return {
            DATA_REPRESENTATION: {
                "record_structure": {"embedding": presence(embedding) if st.chunks else
                                     ("present" if embedding else "unknown"),
                                     "text": presence(st.text),
                                     "metadata": presence(st.metadata)},
                "surfaces": {surface: {c: counts.get(c, 0) for c in REPRESENTATION_CLASSES}
                             for surface, counts in st.surfaces.items()},
                "fields": fields,
                "sensitive_values": sum(totals.values()),
                "protected_values": protected_values,
                "plaintext_values": totals.get(PLAINTEXT, 0),
                "drift_fields": [f["path"] for f in fields if f["drift"]],
                "chunks_examined": st.chunks,
                "inversion_risk": risk,
                "statement": STATEMENT,
            },
            PAN_REPRESENTATION: {
                "counts": {c: st.pan.get(c, 0) for c in PAN_CLASSES},
                "records_with_pan": st.records_with_pan,
                "examples": list(st.examples),
            },
            DIRECT_IDENTIFIER_EXPOSURE: {"fields": direct},
        }

    @staticmethod
    def _data_outcome(store, name, st, d, complete, gap) -> dict:
        sensitive, protected = d["sensitive_values"], d["protected_values"]
        plain = d["plaintext_values"]
        unknown = sensitive - protected - plain
        drift = d["drift_fields"]
        note = ""
        if drift:
            state, outcome = OBSERVED_EXPOSURE, "failed"
            reason = (f"Field {_short(drift[0])} mixes protected and plaintext values."
                      if len(drift) == 1 else
                      f"{_count(len(drift), 'metadata field')} mix protected and "
                      "plaintext values.")
            note = ("A field protected in some records and plaintext in others shows "
                    "protection applied inconsistently.")
        elif plain:
            state, outcome = OBSERVED_EXPOSURE, "inconclusive"
            reason = (f"{_count(plain, 'sensitive value')} {_verb(plain, 'is', 'are')} "
                      "stored as plaintext with no protection observed.")
            note = ("Whether plaintext breaches a requirement depends on risk. Readable "
                    "to an authenticated client says nothing about disk encryption.")
        elif not complete:
            state, outcome = NOT_VERIFIED, "inconclusive"
            reason = (f"No plaintext among {_count(sensitive, 'sensitive value')} read, "
                      "but not every record was read." if sensitive else
                      "No sensitive values in the records read, but not every record was read.")
        elif unknown:
            state, outcome = NOT_VERIFIED, "inconclusive"
            reason = (f"The representation of {_count(unknown, 'sensitive value')} "
                      "could not be determined.")
        elif sensitive:
            state, outcome = PROTECTED_REPRESENTATION, "passed"
            reason = ("The one sensitive value examined is in a protected form."
                      if sensitive == 1 else
                      f"All {sensitive} sensitive values examined are in a protected form.")
            note = _PROTECTED_NOTE
        else:
            state, outcome = NOT_APPLICABLE, "passed"
            reason = "No sensitive values were found in the records examined."
        return crypto_outcome(DATA_REPRESENTATION, store, name, state=state, outcome=outcome,
                              reason=reason, complete=complete, chunks_scanned=st.chunks,
                              **d, note=_note(note, gap))

    @staticmethod
    def _pan_outcome(store, name, st, d, complete, gap) -> dict:
        counts = d["counts"]
        total = sum(counts.values())
        full = counts[PAN_FULL]
        note = ""
        if full:
            state, outcome = OBSERVED_EXPOSURE, "failed"
            records = d["records_with_pan"]
            reason = (f"{_count(full, 'full PAN')} {_verb(full, 'is', 'are')} stored "
                      f"readable in {_count(records, 'record')}.")
            note = ("A full PAN is a Luhn-valid number of 13 to 19 digits, found whether "
                    "or not the classifier labelled it.")
        elif not complete:
            state, outcome = NOT_VERIFIED, "inconclusive"
            reason = ("No PAN in the records read, but not every record was read."
                      if not total else
                      f"No full PAN among {_count(total, 'PAN value')} read, but not "
                      "every record was read.")
        elif total:
            state, outcome = PROTECTED_REPRESENTATION, "passed"
            reason = ("No full PAN; the one PAN value found is in a protected form."
                      if total == 1 else
                      f"No full PAN; all {total} PAN values found are in a protected form.")
            note = ("Protected PAN forms are truncated, tokenized, hash candidates or "
                    "opaque; counts are in the details.")
        else:
            state, outcome = NOT_APPLICABLE, "passed"
            reason = "No PAN in any form was found."
        return crypto_outcome(PAN_REPRESENTATION, store, name, state=state, outcome=outcome,
                              reason=reason, complete=complete, chunks_scanned=st.chunks,
                              **d, note=_note(note, gap))

    def _direct_outcome(self, store, name, d, complete, gap) -> dict:
        fields = d["fields"]
        st = self._states.get(name or "") or _State()
        note = ""
        if fields:
            n = len(fields)
            with_alt = sum(1 for f in fields if f["pseudonymous_alternative"])
            state, outcome = OBSERVED_EXPOSURE, "inconclusive"
            reason = (f"{_count(n, 'metadata field')} {_verb(n, 'holds', 'hold')} "
                      "direct identifiers in plaintext.")
            note = (f"{with_alt} of {n} {_verb(n, 'sits', 'sit')} beside a pseudonymous "
                    "identifier that could be used instead." if with_alt else
                    "No pseudonymous identifier was found beside "
                    f"{_verb(n, 'it', 'them')}.")
            note = _note(note, "This is a passive observation of stored metadata.")
        elif not complete:
            state, outcome = NOT_VERIFIED, "inconclusive"
            reason = ("No plaintext direct identifiers in the metadata read, but not "
                      "every record was read.")
        else:
            state, outcome = NOT_APPLICABLE, "passed"
            reason = "No plaintext direct identifiers were found in metadata."
        return crypto_outcome(DIRECT_IDENTIFIER_EXPOSURE, store, name, state=state,
                              outcome=outcome, reason=reason, complete=complete,
                              chunks_scanned=st.chunks, **d, note=_note(note, gap))

    @staticmethod
    def _findings(job: ScanJob, store: str, name: Optional[str], st: _State,
                  details: dict) -> None:
        pan = details[PAN_REPRESENTATION]
        full = pan["counts"][PAN_FULL]
        label = name or store
        if full:
            structured = st.pan_surfaces.get("metadata", 0) > 0
            job.add(Finding(
                id=f"find-{uuid.uuid4().hex[:10]}",
                title=f"Full PAN stored readable in collection '{label}'",
                severity=Severity.CRITICAL if structured else Severity.HIGH,
                category="pan_representation", store=store, collection=name,
                description=(
                    f"{_count(full, 'full primary account number')} "
                    f"{_verb(full, 'is', 'are')} stored readable in "
                    f"{_count(pan['records_with_pan'], 'record')}"
                    + (", including structured metadata fields" if structured else
                       " of free text") + ". Truncated, tokenized and opaque forms "
                    "are counted separately and are not part of this finding."),
                evidence={"check": PAN_REPRESENTATION, "crypto_state": OBSERVED_EXPOSURE,
                          "counts": pan["counts"], "records_with_pan": pan["records_with_pan"],
                          "full_by_surface": {k: v for k, v in st.pan_surfaces.items() if v},
                          "examples": pan["examples"]},
                remediation=(
                    "Render stored PAN unreadable (PCI DSS Requirement 3.5.1): tokenize "
                    "or truncate it upstream, before chunking and embedding, then purge "
                    "and re-embed the affected records. Storage or disk encryption "
                    "alone does not meet this for the vector store (Requirement 3.5.1.2)."),
            ))
        data = details[DATA_REPRESENTATION]
        if data["drift_fields"]:
            drifting = [f for f in data["fields"] if f["drift"]]
            job.add(Finding(
                id=f"find-{uuid.uuid4().hex[:10]}",
                title=f"Protection applied inconsistently in collection '{label}'",
                severity=Severity.MEDIUM, category="data_representation",
                store=store, collection=name,
                description=(
                    f"{_count(len(drifting), 'metadata field')} "
                    f"{_verb(len(drifting), 'holds', 'hold')} protected values in some "
                    "records and plaintext in others. A mechanism that is applied to "
                    "most records usually means one ingestion path bypasses it."),
                evidence={"check": DATA_REPRESENTATION, "crypto_state": OBSERVED_EXPOSURE,
                          "fields": [{k: f[k] for k in ("path", "labels", "classes",
                                                        "protected_fraction")}
                                     for f in drifting]},
                remediation=(
                    "Find the ingestion path that writes these fields without the "
                    "protection the rest of the collection uses, apply it there, and "
                    "re-process the plaintext records."),
            ))


_PROTECTED_NOTE = ("Protected means masked, truncated, tokenized, pseudonymous, a hash "
                   "candidate or opaque. It describes the representation, not an algorithm.")


def _count(n: int, singular: str, plural: Optional[str] = None) -> str:
    """``1 record`` / ``4 records``: reasons are read in a table cell, not parsed."""
    return f"{n} {singular if n == 1 else plural or singular + 's'}"


def _verb(n: int, singular: str, plural: str) -> str:
    return singular if n == 1 else plural


def _short(path: str, limit: int = 40) -> str:
    return path if len(path) <= limit else path[:limit - 1] + "…"


def _note(*parts: str) -> str:
    """Caveats that do not fit a one-sentence reason, joined as prose."""
    return " ".join(p.strip() for p in parts if p and p.strip())


def _scan_coverage(classification: Optional[ScanJob]) -> tuple[dict[str, dict], Optional[dict]]:
    """Per-collection ``data_classification`` outcomes, and any store-level one."""
    per_collection: dict[str, dict] = {}
    store_level = None
    if classification is None:
        return per_collection, None
    for item in (classification.stats or {}).get("check_outcomes") or []:
        if item.get("check") != "data_classification":
            continue
        if item.get("collection") is None:
            store_level = item
        else:
            per_collection[str(item["collection"])] = item
    return per_collection, store_level


def representation_policies() -> list[Policy]:
    """Posture policies over this module's findings (plan: Policies)."""
    return [
        Policy(
            id="pan-rendered-unreadable",
            description="Full PAN is stored readable in a vector collection",
            when={"category": "pan_representation"},
            action="tokenize_or_truncate_pan",
            severity=Severity.CRITICAL,
        ),
        Policy(
            id="protection-applied-consistently",
            description="A field mixes protected and plaintext values",
            when={"category": "data_representation"},
            action="apply_protection_consistently",
            severity=Severity.HIGH,
        ),
    ]
