"""Language identification, and the coverage statement that depends on it.

The point of these tests is not that the detector is a good general-purpose
language identifier -- it is not, and does not claim to be. It is that it
abstains when it should, and that abstaining and deciding both reach the
coverage statement correctly. A wrong call in either direction produces a
dishonest coverage number, which is the failure this whole mechanism exists
to prevent.
"""

from __future__ import annotations

import pytest

from vecshield.classify.language import (
    NON_ENGLISH_COVERAGE_THRESHOLD,
    detect,
    ner_coverage_gap,
    summarise,
)

SAMPLES = {
    "en": "The patient was referred to the clinic and this is the record of "
          "that visit with the results that are in it.",
    "de": "Der Patient wurde in die Klinik überwiesen und das ist der Bericht "
          "mit den Ergebnissen die nicht mehr sind.",
    "fr": "Les patients sont dans une clinique pour des soins qui ne sont pas "
          "encore avec nous cette fois des jours.",
    "es": "Los pacientes estan en una clinica para los cuidados con las "
          "personas por esta razon como todo una vez.",
    "it": "Che non per una sono come anche nella degli alla questo paziente "
          "che non sono per una clinica come anche.",
    "nl": "Het is een van niet zijn worden deze naar ook maar door het een van "
          "de patient niet zijn worden deze.",
}


@pytest.mark.parametrize("expected", sorted(SAMPLES))
def test_detect_identifies_each_supported_language(expected):
    assert detect(SAMPLES[expected]) == expected


@pytest.mark.parametrize(
    "text",
    [
        "",
        None,
        "order 4711",
        "SELECT * FROM users WHERE id = 3",
        "4111 1111 1111 1111",
    ],
)
def test_detect_abstains_rather_than_guessing(text):
    """Short or language-free strings get None, never a coin flip.

    Most of a real corpus is metadata values, ids and code. Calling those
    English would report that the name detectors covered text they never saw.
    """
    assert detect(text) is None


def test_undecided_chunks_are_reported_apart_from_english():
    summary = summarise([SAMPLES["en"], "order 4711", None])
    assert summary["chunks"] == 3
    assert summary["undecided"] == 2
    assert summary["decided"] == 1
    # The share is of text that could be placed, not of the whole store.
    assert summary["non_english_share"] == 0.0


def test_an_english_collection_reports_no_coverage_gap():
    summary = summarise([SAMPLES["en"]] * 5)
    assert summary["non_english_share"] == 0.0
    assert ner_coverage_gap(summary) is None


def test_a_few_foreign_quotes_do_not_downgrade_an_english_collection():
    summary = summarise([SAMPLES["en"]] * 9 + [SAMPLES["de"]])
    assert summary["non_english_share"] < NON_ENGLISH_COVERAGE_THRESHOLD
    assert ner_coverage_gap(summary) is None


def test_a_mostly_german_collection_reports_the_gap_and_names_it():
    summary = summarise([SAMPLES["de"]] * 4 + [SAMPLES["en"]])
    gap = ner_coverage_gap(summary)
    assert gap is not None
    assert "de" in gap
    # It must say what was still detected, so the sentence is not read as
    # "nothing was scanned".
    assert "identifiers were still matched" in gap
    assert "people were not" in gap


def test_the_gap_sentence_does_not_overstate_what_was_missed():
    """Regex detection is language-independent and the wording must say so."""
    gap = ner_coverage_gap(summarise([SAMPLES["fr"]] * 3))
    assert gap is not None
    assert "English model only" in gap
    # No claim that the collection was unscanned or that coverage was zero.
    assert "not scanned" not in gap
    assert "no coverage" not in gap
