"""Risk scoring: embedding-inversion risk and per-collection sensitivity."""

from __future__ import annotations

from vecshield.score.inversion import inversion_risk, model_risk
from vecshield.score.sensitivity import SensitivityScore, score_collection

__all__ = ["inversion_risk", "model_risk", "SensitivityScore", "score_collection"]
