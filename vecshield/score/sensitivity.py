"""Per-collection sensitivity scoring.

Combines three signals into a single 0-1 score and a HIGH/MED/LOW rating:

  exposure       how reachable the sensitive content is
                 = 1.0 if raw text is stored alongside vectors (it's right there)
                 else inversion_risk(model, dim)
  data_weight    how bad the worst label present is (secret > pci/phi > pii)
  density        fraction of scanned chunks that are sensitive (saturating)

  score = exposure * data_weight * density_factor(density)

The point: a collection of plain vectors from an invertible model carrying PHI
is dangerous even with no raw text stored — exposure stays high via inversion.
"""

from __future__ import annotations

from dataclasses import dataclass

from vecshield.models import SensitivityLabel
from vecshield.score.inversion import inversion_risk

# How damaging each label is if exposed.
_DATA_WEIGHT = {
    SensitivityLabel.SECRET: 1.0,
    SensitivityLabel.PCI: 0.9,
    SensitivityLabel.PHI: 0.9,
    # GDPR Art. 9 / Art. 10: processing is prohibited or restricted outright,
    # so exposure weighs like health data rather than ordinary personal data.
    SensitivityLabel.SPECIAL_CATEGORY: 0.9,
    SensitivityLabel.CRIMINAL_OFFENCE: 0.9,
    SensitivityLabel.PII: 0.6,
    SensitivityLabel.SOURCE_CODE: 0.5,
    SensitivityLabel.NONE: 0.0,
}


@dataclass
class SensitivityScore:
    score: float  # 0-1
    rating: str  # LOW | MEDIUM | HIGH
    exposure: float
    data_weight: float
    density: float
    inversion_risk: float
    raw_text_stored: bool
    rationale: str

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "rating": self.rating,
            "exposure": self.exposure,
            "data_weight": self.data_weight,
            "density": round(self.density, 4),
            "inversion_risk": self.inversion_risk,
            "raw_text_stored": self.raw_text_stored,
            "rationale": self.rationale,
        }


def _density_factor(density: float) -> float:
    """Saturating: even a little sensitive data matters; lots maxes out fast."""
    if density <= 0:
        return 0.0
    if density >= 0.10:
        return 1.0
    # linear ramp from a 0.4 floor (one hit still counts) up to 1.0 at 10%
    return 0.4 + (density / 0.10) * 0.6


def _rate(score: float) -> str:
    if score >= 0.6:
        return "HIGH"
    if score >= 0.3:
        return "MEDIUM"
    return "LOW"


def score_collection(
    *,
    labels_present: dict[SensitivityLabel, int],
    scanned: int,
    raw_text_stored: bool,
    embedding_model: str | None = None,
    dimension: int | None = None,
    sensitive: int | None = None,
) -> SensitivityScore:
    """Score one collection.

    ``labels_present`` counts chunks per label, so a chunk holding two labels
    is counted twice there. Pass ``sensitive`` (distinct sensitive chunks) so
    density is a true fraction of the scanned chunks; without it the label
    counts are summed, which overstates density for multi-label chunks.
    """
    if sensitive is None:
        sensitive = sum(labels_present.values())
    density = min(sensitive / scanned, 1.0) if scanned else 0.0

    inv = inversion_risk(embedding_model, dimension)
    exposure = 1.0 if raw_text_stored else inv

    data_weight = max((_DATA_WEIGHT[lbl] for lbl in labels_present), default=0.0)

    score = round(exposure * data_weight * _density_factor(density), 3)
    rating = _rate(score)

    exposure_src = (
        "raw text stored alongside vectors"
        if raw_text_stored
        else (
            f"inversion risk {inv} "
            f"(model={embedding_model or 'unknown'}, dim={dimension})"
        )
    )
    worst = (
        max(labels_present, key=lambda label: _DATA_WEIGHT[label])
        if labels_present
        else None
    )
    rationale = (
        f"{sensitive}/{scanned} sensitive ({density:.1%}); "
        f"worst label {worst.value if worst else 'none'} "
        f"(weight {data_weight}); exposure via {exposure_src}."
    )

    return SensitivityScore(
        score=score,
        rating=rating,
        exposure=round(exposure, 3),
        data_weight=data_weight,
        density=density,
        inversion_risk=inv,
        raw_text_stored=raw_text_stored,
        rationale=rationale,
    )
