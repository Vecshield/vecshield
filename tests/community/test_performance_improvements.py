"""Tests for the CPU performance improvements.

Covers the parts that do not require the optional Presidio/spaCy stack:

* A2 — keyword ``gate`` pre-screen must not change regex output.
* A1 — ``fast`` early-exit must preserve the document-level label.
* C2 — ``default_classifier`` caching + ``reset_default_classifier``.

Presidio-dependent behaviour (B1 ``classify_batch``, B4 result cache) is tested
separately and skipped when the stack is unavailable.
"""

from __future__ import annotations

import copy

import pytest

from vecshield.classify import (
    RegexClassifier,
    default_classifier,
    reset_default_classifier,
)
from vecshield.classify.regex_classifier import DETECTORS, _derive_gate
from vecshield.models import SensitivityLabel

# A representative mix touching every gated detector plus non-gated ones.
_TEXTS = [
    "ping me at alice@corp.io and bob.smith@example.co.uk",
    "SSN 123-45-6789, card 4111 1111 1111 1111",
    "google key AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456",
    "slack xoxb-1234567890-abcdefghij token",
    "auth: Bearer abcdefghijklmnopqrstuvwxyz012345",
    "-----BEGIN RSA PRIVATE KEY-----",
    "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkw.dozjgNryP4J3jVmNHl0wabc",
    "hf_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    "sk-ant-" + "A" * 64,
    "just some ordinary prose with no identifiers at all",
    "call 415-555-0132 or visit 123 Main Street Apt 4B",
]


def _key(c):
    return (c.label, sorted((s["detector"], s["start"], s["end"]) for s in c.spans))


def _ungated_classifier() -> RegexClassifier:
    """A classifier with every gate forcibly disabled.

    ``dataclasses.replace``/construction re-runs ``__post_init__`` (which
    auto-derives a gate), so we shallow-copy each detector and clear ``gate``
    directly to get a genuinely ungated baseline.
    """
    dets = []
    for d in DETECTORS:
        d2 = copy.copy(d)
        d2.gate = None
        dets.append(d2)
    return RegexClassifier(detectors=dets)


def test_gate_prescreen_matches_ungated_output():
    """A2/A1: gating must be a pure speed optimisation, not a behaviour change."""
    gated = RegexClassifier()
    ungated = _ungated_classifier()
    for text in _TEXTS:
        assert _key(gated.classify(text)) == _key(ungated.classify(text)), text


def test_every_detector_canonical_positive_is_unaffected_by_gates():
    """The strongest gate-safety net: every detector's own canonical positive
    (from the coverage suite) must classify identically with gates on vs off.

    A gate that is stricter than its pattern would drop that detector's sample
    and fail here.
    """
    from test_detection_coverage import DETECTION_CASES  # sibling module; pytest puts this dir on sys.path

    gated = RegexClassifier()
    ungated = _ungated_classifier()
    for name, (text, _label) in DETECTION_CASES.items():
        assert _key(gated.classify(text)) == _key(ungated.classify(text)), name


def test_gates_are_lowercase_literals():
    """Gates are matched against ``text.lower()`` so they must be lowercase."""
    for det in DETECTORS:
        if det.gate is None:
            continue
        anchors = (det.gate,) if isinstance(det.gate, str) else det.gate
        for anchor in anchors:
            assert anchor == anchor.lower(), (det.name, anchor)
            assert anchor, det.name


def test_derive_gate_rejects_structural_prefixes():
    """Auto-derivation must not gate patterns whose prefix is not a pure literal
    alternation (which could produce a false-negative gate)."""
    assert _derive_gate(r"\b(?:\d[ -]?){13,19}\b") is None  # credit_card
    assert _derive_gate(r"\b(?:\+?1[-.\s]?)?\(?\d{3}") is None  # us_phone (optional)
    assert _derive_gate(r"\b(?:(?:25[0-5]|2[0-4]\d)\.){3}") is None  # ipv4 (nested)
    # A clean literal alternation is derived.
    assert _derive_gate(r"\b(?:dob|born)\b") == ("dob", "born")


def test_fast_mode_preserves_doc_label():
    """A1: the opt-in early exit keeps the top-priority label."""
    full = RegexClassifier()
    fast = RegexClassifier(fast=True)
    for text in _TEXTS:
        assert fast.classify(text).label == full.classify(text).label, text


def test_fast_mode_short_circuits_on_secret():
    fast = RegexClassifier(fast=True)
    r = fast.classify("-----BEGIN RSA PRIVATE KEY-----")
    assert r.label == SensitivityLabel.SECRET


def test_default_classifier_is_cached():
    """C2: repeated calls with the same args reuse one instance."""
    reset_default_classifier()
    a = default_classifier(use_nlp=False)
    b = default_classifier(use_nlp=False)
    assert a is b


def test_reset_default_classifier_rebuilds():
    a = default_classifier(use_nlp=False)
    reset_default_classifier()
    b = default_classifier(use_nlp=False)
    assert a is not b


# ── Presidio-dependent (optional) ────────────────────────────────────────────

_presidio_available = False
try:  # pragma: no cover - availability probe
    from vecshield.classify.presidio_classifier import PresidioClassifier

    _presidio_available = PresidioClassifier.available()
    if _presidio_available:
        # The libraries alone do not make a loadable pipeline: these tests
        # load en_core_web_sm, so they need that model package too.
        import spacy.util

        _presidio_available = spacy.util.is_package("en_core_web_sm")
except Exception:  # pragma: no cover
    _presidio_available = False

_needs_presidio = pytest.mark.skipif(
    not _presidio_available, reason="Presidio/spaCy or en_core_web_sm not installed"
)


@_needs_presidio
def test_classify_batch_matches_single():
    """B1: batched inference is functionally identical to per-document calls."""
    clf = PresidioClassifier(model="en_core_web_sm")
    texts = [
        "Contact John Smith in Paris about the invoice.",
        "",
        None,
        "Dr. Emily Carter reviewed the patient chart in London.",
        "no entities here",
    ]
    single = [clf.classify(t) for t in texts]
    batch = clf.classify_batch(texts)
    assert len(batch) == len(texts)
    for s, b in zip(single, batch, strict=True):
        assert (s.label, round(s.confidence, 3)) == (b.label, round(b.confidence, 3))


@_needs_presidio
def test_presidio_result_cache_returns_same_object():
    """B4: an enabled cache returns the identical Classification on a hit."""
    clf = PresidioClassifier(model="en_core_web_sm", cache_size=16)
    text = "Contact John Smith in Paris."
    first = clf.classify(text)
    second = clf.classify(text)
    assert first is second


@_needs_presidio
def test_presidio_cache_disabled_by_default():
    clf = PresidioClassifier(model="en_core_web_sm")
    text = "Contact John Smith in Paris."
    assert clf.classify(text) is not clf.classify(text)
