"""CVSS vector parsing and scoring shared by the vulnerability checks.

Only what the advisory sources actually give us is used. CVSS v3.0/v3.1 base
scores are computed from the vector with the FIRST specification formulas, so a
source that ships a vector without a number (OSV does) still yields a score.
CVSS v4.0 and v2 scores are taken from the source when it states one; they are
never estimated, because v4.0 scoring needs FIRST's macro-vector lookup table
and a guessed number would look more precise than it is.
"""

from __future__ import annotations

import math
import re
from typing import Optional

from vecshield.models import Severity

_V3_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_V3_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
_V3_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

#: GitHub / OSV qualitative labels, used only when no numeric score exists.
LABEL_TO_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def _roundup_31(value: float) -> float:
    """CVSS v3.1 Roundup: avoids floating-point artefacts (spec appendix A)."""
    as_int = round(value * 100000)
    if as_int % 10000 == 0:
        return as_int / 100000.0
    return (math.floor(as_int / 10000) + 1) / 10.0


def _roundup_30(value: float) -> float:
    return math.ceil(value * 10) / 10.0


def cvss_version(vector: str) -> Optional[str]:
    match = re.match(r"^CVSS:(\d\.\d)/", (vector or "").strip())
    if match:
        return match.group(1)
    # A bare v2 vector ("AV:N/AC:L/Au:N/...") has no prefix.
    if "Au:" in (vector or ""):
        return "2.0"
    return None


def parse_vector(vector: str) -> dict[str, str]:
    """Metric -> value for any CVSS vector string; unknown parts are ignored."""
    metrics: dict[str, str] = {}
    for part in (vector or "").strip().split("/"):
        if ":" not in part or part.startswith("CVSS:"):
            continue
        key, _, value = part.partition(":")
        metrics[key.strip()] = value.strip()
    return metrics


def v3_base_score(vector: str) -> Optional[float]:
    """Base score for a CVSS v3.0/v3.1 vector, or None when it is not one.

    A vector without the ``CVSS:3.x/`` prefix but with every v3 base metric
    (the PostgreSQL security page prints them bare) is scored as v3.1.
    """
    version = cvss_version(vector)
    metrics = parse_vector(vector)
    if version not in ("3.0", "3.1", None) or not all(k in metrics for k in _V3_REQUIRED):
        return None
    try:
        scope = metrics["S"]
        av = _V3_WEIGHTS["AV"][metrics["AV"]]
        ac = _V3_WEIGHTS["AC"][metrics["AC"]]
        pr = _V3_PR[scope][metrics["PR"]]
        ui = _V3_WEIGHTS["UI"][metrics["UI"]]
        c = _V3_WEIGHTS["C"][metrics["C"]]
        i = _V3_WEIGHTS["I"][metrics["I"]]
        a = _V3_WEIGHTS["A"][metrics["A"]]
    except KeyError:
        return None
    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    roundup = _roundup_30 if version == "3.0" else _roundup_31
    if scope == "U":
        return roundup(min(impact + exploitability, 10))
    return roundup(min(1.08 * (impact + exploitability), 10))


def score_to_severity(score: Optional[float], label: str = "") -> Optional[Severity]:
    """The qualitative band for a score (FIRST ranges), else the source's label."""
    if score is not None:
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        if score > 0.0:
            return Severity.LOW
        return Severity.INFO
    return LABEL_TO_SEVERITY.get((label or "").strip().upper())


def normalise_cvss(vector: str, score: Optional[float] = None, *,
                   source: str = "") -> Optional[dict]:
    """A compact ``{"version", "vector", "score", "score_basis", "source"}`` entry.

    The score is the stated one when the source gives it, otherwise computed
    for v3.x vectors; v4.0/v2 vectors without a stated score keep ``None``.
    """
    vector = (vector or "").strip()
    if not vector:
        return None
    version = cvss_version(vector) or ("3.1" if v3_base_score(vector) is not None else None)
    computed = v3_base_score(vector) if version in ("3.0", "3.1") else None
    basis = "stated"
    if score is None:
        score, basis = computed, ("computed_from_vector" if computed is not None else "none")
    entry = {"version": version, "vector": vector, "score": score, "score_basis": basis}
    if source:
        entry["source"] = source
    return entry


def band_step(severity: Severity, steps: int) -> Severity:
    """Move a severity up (+) or down (-) by bands, clamped to LOW..CRITICAL."""
    order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    if severity not in order:
        return severity
    index = max(0, min(len(order) - 1, order.index(severity) + steps))
    return order[index]
