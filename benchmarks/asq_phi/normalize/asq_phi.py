"""Adapter for ``ASQ-PHI`` — Adversarial Synthetic Queries for PHI.

Paper:  https://doi.org/10.1016/j.dib.2026.100... (Data in Brief)
        https://pmc.ncbi.nlm.nih.gov/articles/PMC12926592/
Code:   https://github.com/JamesWeatherhead/asq-phi
Data:   https://data.mendeley.com/datasets/csz5dzp7nx/1

A fully synthetic benchmark for the "safe handoff" boundary — the point where a
HIPAA-compliant clinical LLM would forward a query to a non-BAA external tool.
1,051 single-line clinician-style search queries: 832 PHI-positive (79.2%) and
219 hard negatives (20.8%) crafted to *look* PHI-like (ages, diagnoses, meds,
symptoms) while carrying no HIPAA identifier. 2,973 PHI spans across 13 HIPAA
Safe Harbor identifier types. No real patient or EHR data is used. MIT licensed.

Native file format (``synthetic_clinical_queries.txt``) — record-delimited text::

    ===QUERY===
    <the full query on one line>
    ===PHI_TAGS===
    {"identifier_type": "NAME", "value": "Anna S."}
    {"identifier_type": "GEOGRAPHIC_LOCATION", "value": "Methodist Hospital"}
    ... (zero JSON lines for a hard negative) ...

Crucially, gold PHI is annotated by **value string**, not character offset. This
adapter resolves each ``value`` to a ``[start, end)`` span by locating it in the
query, consuming matched ranges left-to-right so a value that appears twice (or a
value that is a substring of another) maps to distinct spans. Case-insensitive
fallback covers minor casing drift between tag and query.

Label mapping — every one of the 13 HIPAA identifier types is Protected Health
Information, so all map to VecShield's ``PHI`` category. The native identifier
type is preserved as the annotation ``subtype`` for per-type breakdowns.
"""

from __future__ import annotations

import json
import urllib.request
import warnings
from collections import Counter
from pathlib import Path

from benchmarks.asq_phi.normalize.schema import Annotation, EvalSample

# Raw dataset file, as mirrored in the GitHub repo (main branch).
DATA_URL = (
    "https://raw.githubusercontent.com/JamesWeatherhead/asq-phi/"
    "main/data/synthetic_clinical_queries.txt"
)
# Default on-disk location (copied into the package for reproducible runs).
DEFAULT_DATA_PATH = Path(__file__).resolve().parents[1] / "data" / (
    "synthetic_clinical_queries.txt"
)

_QUERY_DELIM = "===QUERY==="
_TAGS_DELIM = "===PHI_TAGS==="

# Typographic punctuation that drifts between a PHI tag's ``value`` and the
# query text (e.g. tag ``Children's Clinic`` with an ASCII apostrophe vs. the
# query's curly ``Children’s Clinic``).  Normalized on both sides only for the
# *matching* fallback — the resolved span still indexes the original text.
_PUNCT_NORM = str.maketrans(
    {
        "‘": "'", "’": "'", "ʼ": "'", "′": "'",  # apostrophes
        "“": '"', "”": '"',  # double quotes
        "‐": "-", "‑": "-", "‒": "-", "–": "-",  # dashes
        "—": "-", "−": "-",
    }
)


def _norm_punct(s: str) -> str:
    return s.translate(_PUNCT_NORM)

# All 13 HIPAA Safe Harbor identifier types are PHI.
_LABEL_MAP: dict[str, str] = {
    "NAME": "PHI",
    "GEOGRAPHIC_LOCATION": "PHI",
    "DATE": "PHI",
    "MEDICAL_RECORD_NUMBER": "PHI",
    "HEALTH_PLAN_BENEFICIARY_NUMBER": "PHI",
    "PHONE_NUMBER": "PHI",
    "SOCIAL_SECURITY_NUMBER": "PHI",
    "EMAIL_ADDRESS": "PHI",
    "UNIQUE_IDENTIFIER": "PHI",
    "ACCOUNT_NUMBER": "PHI",
    "FAX_NUMBER": "PHI",
    "CERTIFICATE_LICENSE_NUMBER": "PHI",
    "IP_ADDRESS": "PHI",
}

_UNMAPPED: Counter[str] = Counter()
_UNRESOLVED: Counter[str] = Counter()


def unmapped_labels() -> dict[str, int]:
    """Identifier types seen during the last load that were not in _LABEL_MAP."""
    return dict(_UNMAPPED)


def unresolved_values() -> dict[str, int]:
    """Gold tags whose ``value`` could not be located in the query text."""
    return dict(_UNRESOLVED)


def ensure_dataset(path: Path | str = DEFAULT_DATA_PATH) -> Path:
    """Return a local path to the dataset file, downloading it if missing.

    The file is small (~370 KB) and MIT-licensed synthetic data, so caching it
    inside the package is fine. Set ``ASQ_PHI_PATH`` to point at a copy you have
    already downloaded (e.g. from Mendeley Data) to skip the network entirely.
    """
    path = Path(path)
    if path.exists():
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    warnings.warn(
        f"ASQ-PHI dataset not found at {path}; downloading from {DATA_URL}",
        stacklevel=2,
    )
    urllib.request.urlretrieve(DATA_URL, path)  # noqa: S310 - fixed https URL
    return path


def _parse_records(raw: str) -> list[tuple[str, list[dict]]]:
    """Split the delimited file into ``(query_text, [tag_dict, ...])`` records."""
    records: list[tuple[str, list[dict]]] = []
    # Every record starts at a ===QUERY=== delimiter; the leading split chunk
    # (before the first delimiter) is preamble/empty and is discarded.
    for block in raw.split(_QUERY_DELIM)[1:]:
        if _TAGS_DELIM in block:
            query_part, tags_part = block.split(_TAGS_DELIM, 1)
        else:
            query_part, tags_part = block, ""
        query = query_part.strip()
        if not query:
            continue
        tags: list[dict] = []
        for line in tags_part.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict) and "identifier_type" in obj:
                tags.append(obj)
        records.append((query, tags))
    return records


def _find_free(text: str, value: str, consumed: list[tuple[int, int]]) -> int:
    """Earliest index of ``value`` in ``text`` not overlapping a consumed span.

    Returns -1 if no free occurrence exists.
    """
    if not value:
        return -1
    search_from = 0
    while True:
        idx = text.find(value, search_from)
        if idx < 0:
            return -1
        end = idx + len(value)
        if not any(idx < c_end and end > c_start for c_start, c_end in consumed):
            return idx
        search_from = idx + 1


def _annotations_from_tags(text: str, tags: list[dict]) -> list[Annotation]:
    """Resolve value-based gold tags to offset spans, left-to-right."""
    annotations: list[Annotation] = []
    consumed: list[tuple[int, int]] = []
    lower_text = text.lower()
    # Punctuation-normalized view — same length as ``text`` (every mapping is
    # 1:1) so an index found here is valid in the original text.
    norm_text = _norm_punct(text).lower()
    for tag in tags:
        raw_type = str(tag.get("identifier_type", "")).strip().upper()
        value = tag.get("value")
        if not raw_type or not isinstance(value, str) or not value:
            continue
        mapped = _LABEL_MAP.get(raw_type)
        if mapped is None:
            _UNMAPPED[raw_type] += 1
            continue
        start = _find_free(text, value, consumed)
        if start < 0:
            # Casing drift between tag and query (e.g. "st. vincent's").
            start = _find_free(lower_text, value.lower(), consumed)
        if start < 0:
            # Typographic-punctuation drift (curly vs. ASCII apostrophe, en-dash
            # vs. hyphen).  Both sides normalized; offsets preserved (1:1 map).
            start = _find_free(norm_text, _norm_punct(value).lower(), consumed)
        if start < 0:
            _UNRESOLVED[raw_type] += 1
            continue
        end = start + len(value)
        consumed.append((start, end))
        annotations.append(
            Annotation(
                start=start,
                end=end,
                entity_type=mapped,
                subtype=raw_type,
                text=text[start:end],
            )
        )
    return annotations


def load_asq_phi(
    max_samples: int = 0,
    *,
    path: Path | str = DEFAULT_DATA_PATH,
    download: bool = True,
    seed: int = 42,
) -> list[EvalSample]:
    """Load and normalize ASQ-PHI into a list of :class:`EvalSample`.

    Parameters
    ----------
    max_samples:
        Cap on returned samples (0 or negative = all 1,051 rows, the default —
        the dataset is small enough to always run in full). When capped, a
        deterministic shuffle (``seed``) is applied first so the subset keeps a
        representative positive/hard-negative mix.
    path:
        Local dataset file. Defaults to the copy bundled in ``asq_phi/data/``.
    download:
        Fetch the file from GitHub when it is not present at ``path``.
    seed:
        Shuffle seed used only when ``max_samples`` caps the corpus.
    """
    _UNMAPPED.clear()
    _UNRESOLVED.clear()

    path = Path(path)
    if not path.exists():
        if download:
            path = ensure_dataset(path)
        else:
            raise FileNotFoundError(
                f"ASQ-PHI dataset not found at {path}. Pass download=True or "
                f"place synthetic_clinical_queries.txt there."
            )

    raw = path.read_text(encoding="utf-8")
    records = _parse_records(raw)

    if max_samples and max_samples > 0 and len(records) > max_samples:
        import random

        rng = random.Random(seed)
        records = records[:]
        rng.shuffle(records)
        records = records[:max_samples]

    samples: list[EvalSample] = []
    for i, (text, tags) in enumerate(records):
        gold = _annotations_from_tags(text, tags)
        samples.append(
            EvalSample(
                id=f"asq_phi-{i}",
                text=text,
                gold=gold,
                source="asq_phi",
                split="test",
            )
        )

    if _UNMAPPED:
        warnings.warn(
            f"asq_phi: unmapped identifier types skipped: {dict(_UNMAPPED)}",
            stacklevel=2,
        )
    if _UNRESOLVED:
        warnings.warn(
            f"asq_phi: {sum(_UNRESOLVED.values())} gold values could not be "
            f"located in their query and were dropped: {dict(_UNRESOLVED)}",
            stacklevel=2,
        )
    return samples
