"""Unit tests for benchmark detection metrics."""

from __future__ import annotations

from benchmarks.ai4privacy.normalize.schema import Annotation, EvalSample
from benchmarks.ai4privacy.runners import metrics as M


def _ann(start, end, etype="PII", subtype="x", score=1.0):
    return Annotation(
        start=start, end=end, entity_type=etype, subtype=subtype, score=score
    )


def _sample(text, gold, pred, sid="s"):
    return EvalSample(id=sid, text=text, gold=gold, pred=pred, source="test")


def _row(results, match_mode, entity="ALL"):
    return next(
        r for r in results if r.match_mode == match_mode and r.entity_type == entity
    )


def test_perfect_prediction_all_modes():
    s = _sample("aaaa", [_ann(0, 4)], [_ann(0, 4)])
    results = M.evaluate([s], benchmark="t", mode="regex")
    for mm in ("exact", "partial", "type_relaxed", "binary_doc"):
        r = _row(results, mm)
        assert (r.precision, r.recall, r.f1) == (1.0, 1.0, 1.0), mm


def test_no_predictions_zero_recall():
    s = _sample("aaaa", [_ann(0, 4)], [])
    r = _row(M.evaluate([s], benchmark="t", mode="regex"), "partial")
    assert r.recall == 0.0
    assert r.f1 == 0.0
    assert r.fn == 1


def test_no_gold_all_false_positive():
    s = _sample("aaaa", [], [_ann(0, 4)])
    r = _row(M.evaluate([s], benchmark="t", mode="regex"), "partial")
    assert r.precision == 0.0
    assert r.fp == 1
    assert r.tp == 0


def test_partial_overlap_counts_as_match():
    s = _sample("aaaaaaaa", [_ann(0, 5)], [_ann(3, 8)])
    exact = _row(M.evaluate([s], benchmark="t", mode="regex"), "exact")
    partial = _row(M.evaluate([s], benchmark="t", mode="regex"), "partial")
    assert exact.tp == 0  # boundaries differ
    assert partial.tp == 1  # they overlap


def test_type_mismatch_not_matched_in_partial():
    s = _sample("aaaaaaaa", [_ann(0, 5, "PII")], [_ann(0, 5, "PCI")])
    partial = _row(M.evaluate([s], benchmark="t", mode="regex"), "partial")
    assert partial.tp == 0
    assert partial.fp == 1
    assert partial.fn == 1


def test_type_mismatch_matched_in_type_relaxed():
    s = _sample("aaaaaaaa", [_ann(0, 5, "PII")], [_ann(0, 5, "PCI")])
    relaxed = _row(M.evaluate([s], benchmark="t", mode="regex"), "type_relaxed")
    assert relaxed.tp == 1
    assert relaxed.fp == 0


def test_binary_doc_mixed_samples():
    samples = [
        _sample("a", [_ann(0, 1)], [_ann(0, 1)], "tp"),  # TP
        _sample("b", [], [_ann(0, 1)], "fp"),  # FP
        _sample("c", [_ann(0, 1)], [], "fn"),  # FN
        _sample("d", [], [], "tn"),  # TN
    ]
    r = _row(M.evaluate(samples, benchmark="t", mode="regex"), "binary_doc")
    assert (r.tp, r.fp, r.fn) == (1, 1, 1)
    assert r.precision == 0.5
    assert r.recall == 0.5


def test_roc_auc_perfect_separation():
    samples = [
        _sample("a", [_ann(0, 1)], [_ann(0, 1, score=0.9)], "p"),
        _sample("b", [], [], "n"),
    ]
    r = _row(M.evaluate(samples, benchmark="t", mode="regex"), "binary_doc")
    assert r.roc_auc == 1.0


def test_roc_auc_single_class_is_none():
    samples = [_sample("a", [_ann(0, 1)], [_ann(0, 1)], "p")]
    r = _row(M.evaluate(samples, benchmark="t", mode="regex"), "binary_doc")
    assert r.roc_auc is None  # only positives present


def test_dedup_overlapping_predictions():
    preds = [_ann(0, 5, score=0.9), _ann(2, 6, score=0.8), _ann(10, 12, score=0.7)]
    kept = M.dedup_overlapping(preds)
    assert len(kept) == 2  # first two overlap; highest score kept
    assert kept[0].score == 0.9


def test_dedup_prevents_double_counting_fp():
    # Two overlapping predictions, no gold: should count as ONE false positive.
    s = _sample("aaaaaa", [], [_ann(0, 5, score=0.9), _ann(1, 6, score=0.8)])
    r = _row(M.evaluate([s], benchmark="t", mode="regex"), "partial")
    assert r.fp == 1


def test_fbeta_ordering_precision_favoured():
    # precision=1.0, recall=0.5 -> F0.5 > F1 > F2
    tp, fp, fn = 1, 0, 1
    p, rec, f1, f05, f2 = M._prf(tp, fp, fn)
    assert p == 1.0 and rec == 0.5
    assert f05 > f1 > f2


def test_per_entity_breakdown_isolates_categories():
    s = _sample(
        "aaaabbbb",
        [_ann(0, 4, "PII"), _ann(4, 8, "PCI")],
        [_ann(0, 4, "PII")],
    )
    results = M.evaluate([s], benchmark="t", mode="regex")
    pii = _row(results, "partial", "PII")
    pci = _row(results, "partial", "PCI")
    assert pii.recall == 1.0
    assert pci.recall == 0.0
    assert pci.fn == 1


def test_false_positive_by_detector():
    s = _sample(
        "aaaaaaaa",
        [_ann(0, 4, "PII")],
        [_ann(0, 4, "PII", subtype="email"), _ann(5, 8, "PII", subtype="us_phone")],
    )
    fp = M.false_positive_by_detector([s])
    assert fp.get("us_phone") == 1  # the 5-8 span matches no gold
    assert "email" not in fp  # the 0-4 span matches gold
