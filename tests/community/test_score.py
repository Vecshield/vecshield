"""Unit tests for inversion-risk and sensitivity scoring."""

from __future__ import annotations

from vecshield.models import SensitivityLabel
from vecshield.score import inversion_risk, model_risk, score_collection
from vecshield.score.inversion import reconstruct


def test_known_model_higher_risk_than_unknown():
    assert model_risk("text-embedding-ada-002") > model_risk("some-random-model")


def test_inversion_risk_scales_with_dimension():
    low = inversion_risk("all-minilm-l6-v2", 384)
    high = inversion_risk("text-embedding-ada-002", 1536)
    assert high > low
    assert 0.0 <= low <= 1.0 and 0.0 <= high <= 1.0


def test_raw_text_forces_full_exposure():
    s = score_collection(
        labels_present={SensitivityLabel.PII: 5},
        scanned=50,
        raw_text_stored=True,
        embedding_model=None,
        dimension=None,
    )
    assert s.exposure == 1.0


def test_secret_collection_rates_high():
    s = score_collection(
        labels_present={SensitivityLabel.SECRET: 5},
        scanned=50,
        raw_text_stored=True,
    )
    assert s.rating == "HIGH"


def test_bare_vectors_invertible_model_still_exposed():
    # No raw text, but an invertible model -> exposure stays meaningful.
    s = score_collection(
        labels_present={SensitivityLabel.PHI: 10},
        scanned=100,
        raw_text_stored=False,
        embedding_model="text-embedding-ada-002",
        dimension=1536,
    )
    assert s.exposure > 0.5
    assert s.rating in {"MEDIUM", "HIGH"}


def test_low_density_low_sensitivity_rates_low():
    s = score_collection(
        labels_present={SensitivityLabel.PII: 1},
        scanned=1000,
        raw_text_stored=False,
        embedding_model="all-minilm-l6-v2",
        dimension=384,
    )
    assert s.rating == "LOW"


def test_gdpr_article_9_and_10_labels_score_like_health_data():
    # These labels used to raise KeyError and abort the whole store scan.
    for label in (SensitivityLabel.SPECIAL_CATEGORY, SensitivityLabel.CRIMINAL_OFFENCE):
        s = score_collection(labels_present={label: 5}, scanned=50, raw_text_stored=True)
        assert s.data_weight == 0.9
        assert label.value in s.rationale


def test_density_counts_chunks_not_labels():
    # 10 chunks, each carrying both PII and PHI: density is 100%, not 200%.
    labels = {SensitivityLabel.PII: 10, SensitivityLabel.PHI: 10}
    assert score_collection(labels_present=labels, scanned=10, raw_text_stored=True,
                            sensitive=10).density == 1.0
    s = score_collection(labels_present=labels, scanned=100, raw_text_stored=True,
                         sensitive=10)
    assert s.density == 0.1
    assert s.rationale.startswith("10/100 sensitive")


def test_reconstruct_not_implemented():
    import pytest

    with pytest.raises(NotImplementedError):
        reconstruct([0.1, 0.2], "text-embedding-ada-002")
