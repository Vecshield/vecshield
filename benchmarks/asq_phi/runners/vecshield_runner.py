"""Run VecShield over ``EvalSample`` objects and populate ``EvalSample.pred``.

Three detection strategies are evaluated (the "mode" axis of the ablation):

``regex``
    ``RegexClassifier`` only — no optional dependencies, model-independent.
    High precision, misses NLP-native entities (names, cities, ...).
``cascade``
    Regex first; run the NLP classifier **only on documents where regex found
    nothing**. This recovers doc-level recall on name-only documents while
    paying the spaCy cost on the regex-miss subset only.
``nlp``
    ``PresidioClassifier`` (spaCy NER) **alone** — no regex. Shows what pure
    NLP achieves on its own. Requires ``pip install 'vecshield[nlp]'``.
``ensemble``
    Regex **∪** NLP on every document, merged exactly as the shipped
    ``vecshield.default_classifier(use_nlp=True)`` does. Highest recall — this is
    the mode that reflects real product behaviour. Requires the NLP extra.

The NLP-backed modes (``cascade``, ``nlp``) accept a ``model`` argument so the
ablation can compare ``en_core_web_sm`` / ``_md`` / ``_lg``.

VecShield span → :class:`Annotation` mapping::

    span["label"]     -> entity_type   (upper-cased: PII / PHI / PCI / SECRET)
    span["detector"]  -> subtype
    span["start"]     -> start
    span["end"]       -> end
    span["score"]     -> score         (falls back to result.confidence)
    text[start:end]   -> text
"""

from __future__ import annotations

import vecshield
from benchmarks.asq_phi.normalize.schema import (
    CATEGORIES,
    Annotation,
    EvalSample,
)
from vecshield.classify import RegexClassifier
from vecshield.classify.base import apply_phi_context, merge

MODES = ("regex", "cascade", "nlp", "ensemble")
DEFAULT_MODEL = "en_core_web_lg"


def _build_nlp_classifier(model: str):
    """Instantiate a stand-alone Presidio classifier for ``model``."""
    from vecshield.classify.presidio_classifier import PresidioClassifier

    if not PresidioClassifier.available():
        raise RuntimeError(
            "NLP-backed modes need Presidio + spaCy. Install with:\n"
            "  pip install 'vecshield[nlp]'\n"
            f"  python -m spacy download {model}"
        )
    return PresidioClassifier(model=model)


def _spans_to_annotations(
    text: str, spans: list[dict], default_score: float
) -> list[Annotation]:
    annotations: list[Annotation] = []
    for span in spans:
        start = span.get("start")
        end = span.get("end")
        label = str(span.get("label", "")).upper()
        if start is None or end is None or label not in CATEGORIES:
            continue
        start, end = int(start), int(end)
        if not (0 <= start < end <= len(text)):
            continue
        score = span.get("score")
        annotations.append(
            Annotation(
                start=start,
                end=end,
                entity_type=label,
                subtype=str(span.get("detector", "")),
                text=text[start:end],
                score=float(score if score is not None else default_score),
            )
        )
    return annotations


def run_vecshield(
    samples: list[EvalSample],
    mode: str = "regex",
    *,
    model: str = DEFAULT_MODEL,
    nlp_classifier=None,
    progress_every: int = 500,
    batch_size: int = 1,
    min_nlp_chars: int = 0,
) -> list[EvalSample]:
    """Populate ``sample.pred`` in place (no gold leakage) and return the list.

    ``mode`` selects the detection strategy (see module docstring). For the
    NLP-backed modes, either pass a pre-built ``nlp_classifier`` (so a spaCy
    model is loaded once and reused across modes) or a ``model`` name to build
    one on demand.

    ``batch_size`` (B1): when >1, NLP inference is streamed through
    ``PresidioClassifier.classify_batch`` (``nlp.pipe``) instead of one document
    at a time — a large CPU speedup for the ``cascade`` / ``nlp`` modes.  Results
    are identical to the per-document path, so it is safe to enable.

    ``min_nlp_chars`` (B2): when >0, in ``cascade`` mode the NLP leg is skipped
    for regex-miss documents shorter than this many (stripped) characters — such
    snippets almost never contain a name/address spaCy would catch, so this
    trims the NLP call rate for free.  Ignored in ``nlp``-only mode (which must
    exercise the model on every document).
    """
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}, got {mode!r}")

    regex_clf = RegexClassifier() if mode in ("regex", "cascade", "ensemble") else None
    nlp_clf = None
    if mode in ("cascade", "nlp", "ensemble"):
        nlp_clf = (
            nlp_classifier
            if nlp_classifier is not None
            else _build_nlp_classifier(model)
        )

    total = len(samples)

    # ---- ensemble: regex ∪ NLP on *every* document (the shipped pipeline) ---
    # This is what ``vecshield.default_classifier(use_nlp=True)`` does — regex
    # and Presidio spans are unioned via ``merge`` and the dominant label picked.
    # Unlike ``cascade`` (regex-or-NLP per doc), ensemble runs both, so a query
    # carrying an MRN *and* a name is fully covered.  NLP is batched for speed.
    if mode == "ensemble":
        texts = [s.text or "" for s in samples]
        nlp_results = _run_nlp(nlp_clf, texts, batch_size)
        for i, sample in enumerate(samples):
            text = texts[i]
            if not text.strip():
                sample.pred = []
                continue
            regex_res = regex_clf.classify(text)
            merged = apply_phi_context(merge([regex_res, nlp_results[i]]), text)
            sample.pred = _spans_to_annotations(
                text, merged.spans, default_score=merged.confidence
            )
            if progress_every and (i + 1) % progress_every == 0:
                print(f"  [{mode}] {i + 1}/{total} samples classified", flush=True)
        return samples

    # ---- regex-only: no NLP, no batching needed -------------------------
    if mode == "regex":
        for i, sample in enumerate(samples):
            text = sample.text or ""
            if not text.strip():
                sample.pred = []
                continue
            result = vecshield.check_text(text, classifier=regex_clf)
            sample.pred = _spans_to_annotations(
                text, result.spans, default_score=result.confidence
            )
            if progress_every and (i + 1) % progress_every == 0:
                print(f"  [{mode}] {i + 1}/{total} samples classified", flush=True)
        return samples

    # ---- nlp / cascade: optionally batch the spaCy inference ------------
    # 1. Decide, per sample, whether it needs an NLP pass and (for cascade)
    #    capture the regex result.  2. Run NLP (batched or per-doc).  3. Merge.
    regex_spans: list[tuple] = [None] * total  # (spans, conf) when regex fired
    nlp_indices: list[int] = []
    nlp_texts: list[str] = []

    for i, sample in enumerate(samples):
        text = sample.text or ""
        if not text.strip():
            sample.pred = []
            continue

        if mode == "nlp":
            nlp_indices.append(i)
            nlp_texts.append(text)
            continue

        # cascade: regex first
        result = vecshield.check_text(text, classifier=regex_clf)
        if result.spans:
            regex_spans[i] = (result.spans, result.confidence)
        elif min_nlp_chars and len(text.strip()) < min_nlp_chars:
            # B2: too short to plausibly hold an NLP-only entity -> treat as
            # a clean regex miss (no spans) without paying the spaCy cost.
            sample.pred = []
        else:
            nlp_indices.append(i)
            nlp_texts.append(text)

    # Fill in the cascade docs that regex already resolved.
    for i, rs in enumerate(regex_spans):
        if rs is not None:
            spans, conf = rs
            samples[i].pred = _spans_to_annotations(
                samples[i].text or "", spans, default_score=conf
            )

    # Run the NLP leg over the collected docs.
    if nlp_texts:
        if batch_size > 1 and hasattr(nlp_clf, "classify_batch"):
            results = _classify_in_batches(nlp_clf, nlp_texts, batch_size)
        else:
            results = [nlp_clf.classify(t) for t in nlp_texts]
        for done, (idx, res) in enumerate(zip(nlp_indices, results, strict=True)):
            text = samples[idx].text or ""
            samples[idx].pred = _spans_to_annotations(
                text, res.spans, default_score=res.confidence
            )
            if progress_every and (done + 1) % progress_every == 0:
                print(
                    f"  [{mode}] {done + 1}/{len(nlp_texts)} NLP docs classified",
                    flush=True,
                )
    return samples


def _run_nlp(nlp_clf, texts: list[str], batch_size: int):
    """Classify every text with the NLP leg (batched when ``batch_size`` > 1)."""
    if batch_size > 1 and hasattr(nlp_clf, "classify_batch"):
        return _classify_in_batches(nlp_clf, texts, batch_size)
    return [nlp_clf.classify(t) for t in texts]


def _classify_in_batches(nlp_clf, texts: list[str], batch_size: int):
    """Yield ``Classification`` results for ``texts`` in ``batch_size`` chunks.

    Chunking keeps peak memory bounded (``nlp.pipe`` would otherwise buffer the
    whole corpus) while still feeding spaCy enough documents to amortise
    per-call overhead.
    """
    out = []
    for start in range(0, len(texts), batch_size):
        chunk = texts[start : start + batch_size]
        out.extend(nlp_clf.classify_batch(chunk, spacy_batch_size=batch_size))
    return out
