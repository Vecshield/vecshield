"""Adapter for ``ai4privacy/pii-masking-200k`` (HuggingFace Hub, fully public).

Dataset: https://huggingface.co/datasets/ai4privacy/pii-masking-200k

Each row carries ``source_text`` plus a ``privacy_mask`` — a list of
``{"label", "start", "end", "value"}`` character spans. Labels are fine-grained
and often carry a numeric suffix (e.g. ``FIRSTNAME_1``); we strip the suffix and
map the base label to one of VecShield's four categories: PII / PCI / SECRET.
(The dataset has no clinical PHI, so PHI is unused here.)

Design choice — *direct identifiers only*
-----------------------------------------
ai4privacy annotates many quasi-identifiers that are not personal data on their
own (job title, company name, currency, amount, eye colour, ...). Marking those
as gold would unfairly punish a precision-first engine that intentionally does
not flag them. We therefore score against **direct identifiers** and route
quasi-identifiers to an ``IGNORE`` bucket that is excluded from gold. Every
mapping decision is explicit in ``_LABEL_MAP`` / ``_IGNORE`` below and unknown
labels are collected in :func:`unmapped_labels` so coverage is auditable.
"""

from __future__ import annotations

import ast
import json
import re
import warnings
from collections import Counter

from benchmarks.ai4privacy.normalize.schema import Annotation, EvalSample

DATASET_ID = "ai4privacy/pii-masking-200k"

# Base label (suffix-stripped, upper-cased) -> VecShield category.
_LABEL_MAP: dict[str, str] = {
    # ── Names / personal identity ──────────────────────────────────────────
    "FIRSTNAME": "PII",
    "MIDDLENAME": "PII",
    "LASTNAME": "PII",
    "FULLNAME": "PII",
    "NAME": "PII",
    "USERNAME": "PII",
    "ACCOUNTNAME": "PII",
    # ── Contact ────────────────────────────────────────────────────────────
    "EMAIL": "PII",
    "PHONENUMBER": "PII",
    "PHONE": "PII",
    "TEL": "PII",
    "PHONEIMEI": "PII",
    # ── Government / national identifiers ──────────────────────────────────
    "SSN": "PII",
    "SOCIALNUMBER": "PII",
    "PASSPORT": "PII",
    "DRIVERLICENSE": "PII",
    "DRIVINGLICENSE": "PII",
    "VEHICLEVIN": "PII",
    "VEHICLEVRM": "PII",
    # ── Network identifiers ────────────────────────────────────────────────
    "IP": "PII",
    "IPV4": "PII",
    "IPV6": "PII",
    "MAC": "PII",
    "USERAGENT": "PII",
    # ── Location / address ─────────────────────────────────────────────────
    "STREET": "PII",
    "STREETADDRESS": "PII",
    "SECONDARYADDRESS": "PII",
    "BUILDINGNUMBER": "PII",
    "ZIPCODE": "PII",
    "CITY": "PII",
    "STATE": "PII",
    "COUNTY": "PII",
    "NEARBYGPSCOORDINATE": "PII",
    # ── Personal attributes that are direct identifiers ────────────────────
    "DOB": "PII",
    "DATEOFBIRTH": "PII",
    "AGE": "PII",
    # ── Payment / financial (PCI) ──────────────────────────────────────────
    "CREDITCARDNUMBER": "PCI",
    "CREDITCARDCVV": "PCI",
    "CREDITCARDISSUER": "PCI",
    "IBAN": "PCI",
    "BIC": "PCI",
    "ACCOUNTNUMBER": "PCI",
    "MASKEDNUMBER": "PCI",
    "BITCOINADDRESS": "PCI",
    "ETHEREUMADDRESS": "PCI",
    "LITECOINADDRESS": "PCI",
    # ── Secrets ────────────────────────────────────────────────────────────
    "PASSWORD": "SECRET",
    "PIN": "SECRET",
}

# Quasi-identifiers and non-personal fields that are intentionally NOT scored.
# Kept explicit so reviewers can see they were considered, not overlooked.
_IGNORE: frozenset[str] = frozenset(
    {
        "JOBAREA",
        "JOBTYPE",
        "JOBTITLE",
        "JOBDESCRIPTOR",
        "COMPANYNAME",
        "CURRENCY",
        "CURRENCYCODE",
        "CURRENCYNAME",
        "CURRENCYSYMBOL",
        "AMOUNT",
        "EYECOLOR",
        "HEIGHT",
        "GENDER",
        "SEX",
        "ORDINALDIRECTION",
        "TIMEZONE",
        "TIME",
        "DATE",
        "URL",
        "DISPLAYNAME",
        "PREFIX",
    }
)

# Only strip an index suffix when a separator precedes the digits (e.g.
# ``FIRSTNAME_1`` -> ``FIRSTNAME``). A bare trailing digit is meaningful and must
# be kept (``IPV4``, ``IPV6`` must NOT collapse to ``IPV``).
_SUFFIX = re.compile(r"[_\-]\d+$")


def _base_label(raw: str) -> str:
    """Normalise a raw ai4privacy label to its category-map key."""
    label = str(raw).strip().upper()
    label = _SUFFIX.sub("", label)  # drop trailing _1 / -2 (separator required)
    return label.replace("_", "").replace("-", "")


def _coerce_mask(value: object) -> list[dict]:
    """Return ``privacy_mask`` as a list of dicts regardless of source encoding."""
    if value is None:
        return []
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    if isinstance(value, dict):
        return [value]
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        for parser in (json.loads, ast.literal_eval):
            try:
                parsed = parser(text)
            except (ValueError, SyntaxError):
                continue
            return _coerce_mask(parsed)
    return []


def _span_fields(entry: dict) -> tuple[str, int, int, str] | None:
    """Extract (raw_label, start, end, value) from one privacy_mask entry."""
    raw_label = entry.get("label") or entry.get("entity") or entry.get("entity_type")
    start = entry.get("start")
    end = entry.get("end")
    value = entry.get("value") or entry.get("text") or ""
    if raw_label is None or start is None or end is None:
        return None
    try:
        return str(raw_label), int(start), int(end), str(value)
    except (TypeError, ValueError):
        return None


_UNMAPPED: Counter[str] = Counter()


def unmapped_labels() -> dict[str, int]:
    """Labels seen during the last load that were neither mapped nor ignored."""
    return dict(_UNMAPPED)


def _annotations_from_mask(mask: list[dict], text: str) -> list[Annotation]:
    annotations: list[Annotation] = []
    for entry in mask:
        fields = _span_fields(entry)
        if fields is None:
            continue
        raw_label, start, end, value = fields
        if not (0 <= start < end <= len(text)):
            continue
        base = _base_label(raw_label)
        if base in _IGNORE:
            continue
        category = _LABEL_MAP.get(base)
        if category is None:
            _UNMAPPED[base] += 1
            continue
        annotations.append(
            Annotation(
                start=start,
                end=end,
                entity_type=category,
                subtype=base,
                text=value or text[start:end],
            )
        )
    return annotations


def _is_english(row: dict) -> bool:
    lang = str(row.get("language") or row.get("lang") or "").strip().lower()
    if not lang:
        return True  # no language column -> keep
    return lang in {"en", "english", "en-us", "en-gb"}


def load_ai4privacy(
    max_samples: int = 5000,
    *,
    split: str = "validation",
    english_only: bool = True,
    seed: int = 42,
) -> list[EvalSample]:
    """Load and normalize ai4privacy/pii-masking-200k into ``EvalSample`` list.

    Parameters
    ----------
    max_samples:
        Cap on returned samples (0 or negative = no cap).
    split:
        Dataset split. Falls back to ``train`` if the requested split is absent.
    english_only:
        Keep only English rows when a language column is present.
    seed:
        Shuffle seed used when capping, for reproducibility.
    """
    try:
        from datasets import load_dataset
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise RuntimeError(
            "The 'datasets' package is required for the ai4privacy benchmark. "
            "Install it with: pip install datasets"
        ) from exc

    _UNMAPPED.clear()

    try:
        dataset = load_dataset(DATASET_ID, split=split)
    except (ValueError, FileNotFoundError):
        # Requested split may not exist for every config; fall back to train.
        dataset = load_dataset(DATASET_ID, split="train")
    except Exception as exc:  # pragma: no cover - network/auth issues
        warnings.warn(f"Could not load {DATASET_ID}: {exc}", stacklevel=2)
        return []

    if max_samples and max_samples > 0 and len(dataset) > max_samples:
        # Shuffle before capping so we sample across the whole split. When
        # filtering to English we keep a larger buffer, since English is only a
        # fraction of the multilingual split.
        buffer = max_samples * (6 if english_only else 2)
        dataset = dataset.shuffle(seed=seed).select(range(min(buffer, len(dataset))))

    samples: list[EvalSample] = []
    for i, row in enumerate(dataset):
        if english_only and not _is_english(row):
            continue
        text = row.get("source_text") or row.get("text") or ""
        if not text:
            continue
        mask = _coerce_mask(row.get("privacy_mask"))
        gold = _annotations_from_mask(mask, text)
        uid = str(row.get("uid") or row.get("id") or i)
        samples.append(
            EvalSample(
                id=f"ai4privacy-{uid}",
                text=text,
                gold=gold,
                source="ai4privacy",
                split=split,
            )
        )
        if max_samples and max_samples > 0 and len(samples) >= max_samples:
            break

    if _UNMAPPED:
        warnings.warn(
            f"ai4privacy: {sum(_UNMAPPED.values())} spans with unmapped labels "
            f"were skipped: {dict(_UNMAPPED.most_common(10))}",
            stacklevel=2,
        )
    return samples
