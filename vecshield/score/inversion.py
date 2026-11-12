"""Embedding-inversion risk model.

Research (vec2text, Morris et al. 2023; "Text Embeddings Reveal (Almost) As
Much As Text") shows dense text embeddings from common models can be inverted
to recover most of the source text. This module estimates, per collection, how
exposed the *vectors themselves* are — independent of whether raw text is also
stored.

This is a heuristic risk score, not an actual reconstruction. The hook
`reconstruct()` is where a real vec2text model plugs in later; until then it
raises NotImplementedError so we never silently pretend to have inverted data.
"""

from __future__ import annotations

import re

# Per-model-family base invertibility (0-1). Higher = more recoverable.
# Grounded in published inversion results; unknown models get a cautious mid score.
_MODEL_RISK = {
    "text-embedding-ada-002": 0.85,
    "text-embedding-3-small": 0.80,
    "text-embedding-3-large": 0.85,
    "gtr-t5": 0.90,  # vec2text's primary demonstrated target
    "sentence-t5": 0.85,
    "all-mpnet-base-v2": 0.75,
    "all-minilm-l6-v2": 0.70,
    "e5-": 0.72,
    "bge-": 0.72,
    "cohere-embed": 0.70,
    "voyage-": 0.65,
}

_UNKNOWN_MODEL_RISK = 0.55  # cautious default: assume meaningfully invertible

_DEFAULT_DIM_RISK = 0.6


def _normalize(model: str | None) -> str | None:
    if not model:
        return None
    return re.sub(r"\s+", "", model.strip().lower())


def model_risk(model: str | None) -> float:
    """Base invertibility for an embedding model name (prefix/substring match)."""
    m = _normalize(model)
    if not m:
        return _UNKNOWN_MODEL_RISK
    for key, risk in _MODEL_RISK.items():
        if m.startswith(key) or key in m:
            return risk
    return _UNKNOWN_MODEL_RISK


def dimension_factor(dim: int | None) -> float:
    """Higher-dimensional embeddings carry more recoverable information."""
    if not dim:
        return _DEFAULT_DIM_RISK
    if dim >= 1536:
        return 1.0
    if dim >= 768:
        return 0.9
    if dim >= 384:
        return 0.75
    if dim >= 128:
        return 0.5
    return 0.3


def inversion_risk(model: str | None, dim: int | None) -> float:
    """Combined 0-1 risk that the raw vectors can be inverted to source text."""
    return round(model_risk(model) * dimension_factor(dim), 3)


def reconstruct(embedding: list[float], model: str | None) -> str:
    """Reconstruct source text from an embedding (vec2text). Not yet wired."""
    raise NotImplementedError(
        "Embedding reconstruction (vec2text) is not yet implemented. "
        "inversion_risk() estimates exposure without performing reconstruction."
    )
