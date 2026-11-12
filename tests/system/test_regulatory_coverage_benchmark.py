"""System test: the regulatory-coverage benchmark, end to end.

This runs the real corpus through the real shipped classifier and scores it —
no fixtures, no mocks, no stubbed runner. It exists for two reasons.

**It is the benchmark's regression gate.** The other two benchmarks in this
repository silently stopped importing when their package moved under
`benchmarks/`, and nobody noticed because `testpaths = ["tests"]`
excludes `benchmarks/` from every run. A benchmark nothing executes is a
benchmark that rots. This test lives under `tests/` so the default suite
exercises the harness on every run.

**It pins the floors, not the numbers.** Asserting an exact recall would make
the suite fail every time a detector improves, which trains people to update
the number rather than read it. What is asserted instead is what must never
regress: every framework covered, every category expressible, the new
special-category and criminal-offence labels actually reachable, and the hard
negatives mostly quiet. The measured figures belong in the report the CLI
prints, where a human reads them.
"""

from __future__ import annotations

import pytest

from benchmarks.ai4privacy.normalize.schema import CATEGORIES
from benchmarks.regulatory_coverage.corpus import (
    CASES, REGULATIONS, corpus_manifest, load_corpus)
from benchmarks.regulatory_coverage.report import render, run
from benchmarks.regulatory_coverage.runners import (
    VecShieldRunner, default_runners)


@pytest.fixture(scope="module")
def samples():
    return load_corpus()


@pytest.fixture(scope="module")
def vecshield_report(samples):
    report = run(VecShieldRunner(use_nlp=False), samples)
    assert report.available, report.reason
    return report


# --------------------------------------------------------------- the corpus
def test_the_corpus_builds_and_every_gold_span_resolves(samples):
    """A gold span that is absent or ambiguous raises at load time."""
    assert len(samples) == len(CASES)
    assert sum(len(s.gold) for s in samples) == corpus_manifest()["gold_spans"]


def test_every_framework_in_the_pack_has_cases():
    covered = {c.regulation for c in CASES}
    assert covered == set(REGULATIONS), f"no cases for {set(REGULATIONS) - covered}"


def test_every_category_the_schema_knows_has_at_least_one_gold_span():
    """A category with no case is a category nothing is measuring."""
    seen = {category for case in CASES for _, category in case.spans}
    assert seen == set(CATEGORIES), f"unmeasured categories: {set(CATEGORIES) - seen}"


def test_hard_negatives_name_what_they_are_bait_for():
    """A negative without a stated bait cannot be acted on when it fails."""
    for case in CASES:
        if case.is_negative:
            assert case.bait, f"{case.id} is a negative with no bait described"


def test_the_corpus_states_its_provenance():
    """It is synthetic and redistributable, and has to say so."""
    manifest = corpus_manifest()
    assert "Synthetic" in str(manifest["provenance"])
    assert manifest["hard_negatives"] >= 10


# --------------------------------------------------------------- the harness
def test_every_runner_reports_availability_without_raising():
    """A missing optional dependency is a reason, never an import error."""
    for runner in default_runners():
        availability = runner.availability()
        assert isinstance(availability.ok, bool)
        if not availability.ok:
            assert availability.reason, f"{runner.name} unavailable with no reason"


def test_an_unavailable_runner_is_reported_not_skipped(samples):
    """'Not installed' and 'scored zero' must never look the same."""
    from benchmarks.regulatory_coverage.runners import GlinerRunner

    report = run(GlinerRunner(), samples)
    if not report.available:
        assert report.reason
        assert not report.by_category, "an unavailable runner must not score"


def test_the_report_renders_without_a_single_headline_number(vecshield_report):
    text = render(vecshield_report)
    assert "vecshield-regex" in text
    for banned in ("%", "score:", "overall", "F1"):
        assert banned not in text, f"the report should not present {banned!r}"


# ------------------------------------------------- what must not regress
def test_the_shipped_classifier_can_express_every_category():
    """The comparison is on accuracy, not vocabulary — for us at least."""
    assert VecShieldRunner(use_nlp=False).expressible() == set(CATEGORIES)


def test_special_category_and_criminal_offence_are_actually_reachable(
        vecshield_report):
    """These labels were added to the taxonomy; this proves they fire."""
    for category in ("SPECIAL_CATEGORY", "CRIMINAL_OFFENCE"):
        score = vecshield_report.by_category.get(category)
        assert score is not None, f"{category} was never scored"
        assert score.found > 0, f"{category} has a label but nothing detected it"


@pytest.mark.parametrize("regulation", sorted(REGULATIONS))
def test_every_framework_finds_something(vecshield_report, regulation):
    """A framework scoring nothing at all means the pack claims coverage it
    does not have — a different failure from scoring poorly."""
    bucket = vecshield_report.by_regulation.get(regulation)
    assert bucket, f"{regulation} produced no scored spans"
    assert bucket["found"] > 0, f"{regulation}: nothing detected out of {bucket['gold']}"


def test_recall_floor_per_category(vecshield_report):
    """A floor, deliberately well below the current figures.

    This catches a category collapsing — a detector removed, a label renamed,
    a regex broken by an escape. It is not a quality target, and raising it to
    track the current numbers would defeat its purpose.
    """
    for score in vecshield_report.by_category.values():
        if score.recall is None:
            continue
        assert score.recall >= 0.5, (
            f"{score.category} recall {score.recall:.2f} below the floor; "
            f"missed {score.missed} of {score.found + score.missed}")


def test_most_hard_negatives_stay_quiet(vecshield_report):
    """Over-flagging is the failure that makes a compliance tool unusable."""
    assert vecshield_report.negatives >= 10
    assert vecshield_report.clean_negatives >= vecshield_report.negatives - 4, (
        "too many hard negatives fired: "
        + "; ".join(f"{m['case']} ({m['predicted']})"
                    for m in vecshield_report.over_flagged))


def test_known_over_flags_are_the_ones_we_know_about(vecshield_report):
    """Pinned by name. A *new* over-flag should fail here loudly rather than
    hide inside the tolerance above."""
    known = {"neg-pci-order", "neg-pci-masked"}
    actual = {m["case"] for m in vecshield_report.over_flagged}
    assert actual <= known, f"new over-flagging: {sorted(actual - known)}"
