"""Which analyzer language a chunk is handed to.

The NER layer was English-only, so any non-English text had its names,
locations and organisations left unexamined. These tests cover the selection
rule rather than the models: the models are optional installs, and the rule
has to be right whether none, some or all of them are present.

The invariant that matters most is the fallback. A deployment with no extra
models must behave exactly as it did before, because the alternative -- 
abstaining on text we cannot place -- would silently drop detection the
product already had.
"""

from __future__ import annotations

import pytest

from vecshield.classify.presidio_classifier import (
    DEFAULT_EXTRA_MODELS,
    choose_language,
    resolve_extra_models,
)

GERMAN = ("Der Patient wurde in die Klinik überwiesen und das ist der Bericht "
          "mit den Ergebnissen die nicht mehr sind.")
FRENCH = ("Les patients sont dans une clinique pour des soins qui ne sont pas "
          "encore avec nous cette fois des jours.")
ENGLISH = ("The patient was referred to the clinic and this is the record of "
           "that visit with the results that are in it.")


def test_english_only_deployment_behaves_exactly_as_before():
    """No extra models installed: everything goes to the English analyzer."""
    for text in (ENGLISH, GERMAN, FRENCH, "order 4711", None):
        assert choose_language(text, {"en"}) == "en"


def test_a_loaded_model_is_used_for_text_in_that_language():
    assert choose_language(GERMAN, {"en", "de"}) == "de"
    assert choose_language(FRENCH, {"en", "fr"}) == "fr"


def test_text_falls_back_to_english_when_its_model_is_not_loaded():
    """German text with only the French model loaded is still analysed."""
    assert choose_language(GERMAN, {"en", "fr"}) == "en"


def test_unidentifiable_text_falls_back_to_english():
    """Short metadata values have no language; they must not be skipped."""
    for text in ("order 4711", "SELECT * FROM users", "", None):
        assert choose_language(text, {"en", "de", "fr"}) == "en"


def test_english_text_is_unaffected_by_other_loaded_models():
    assert choose_language(ENGLISH, {"en", "de", "fr", "es"}) == "en"


@pytest.mark.parametrize("lang", sorted(DEFAULT_EXTRA_MODELS))
def test_every_default_model_matches_a_language_the_detector_can_identify(lang):
    """A model for a language we cannot detect would never be selected."""
    from vecshield.classify.language import STOPWORDS

    assert lang in STOPWORDS


def test_the_override_can_disable_extra_models_entirely(monkeypatch):
    monkeypatch.setenv("VECSHIELD_NER_MODELS", "none")
    assert resolve_extra_models() == {}


def test_the_override_replaces_the_defaults(monkeypatch):
    monkeypatch.setenv("VECSHIELD_NER_MODELS", "de=de_core_news_lg,fr=fr_core_news_lg")
    assert resolve_extra_models() == {
        "de": "de_core_news_lg", "fr": "fr_core_news_lg"
    }


def test_an_unset_override_gives_the_defaults(monkeypatch):
    monkeypatch.delenv("VECSHIELD_NER_MODELS", raising=False)
    assert resolve_extra_models() == DEFAULT_EXTRA_MODELS
