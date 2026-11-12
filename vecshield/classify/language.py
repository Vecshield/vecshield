"""Which language a chunk is written in, and why that is a coverage question.

The named-entity layer runs an English model and is configured for English
only. Regex detectors are language-independent -- an IBAN is an IBAN -- but
names, locations and organisations come exclusively from the NER layer. So a
German or French corpus gets structured identifiers detected and every person
in it missed.

That is a recall problem, and left unsaid it is also an honesty problem: a
store the classifier cannot read would otherwise report the same coverage as
one it can. This module exists so the scan can say "this collection is largely
not in English, and the name detection did not apply to it" instead of
reporting a clean pass over text it never understood.

The method is deliberately the dullest one available: frequency of very common
function words. It needs no model, no download and no new dependency, it is
pure, and on a paragraph it is accurate enough for the only decision being
made -- is this English or is it not. It is not a general-purpose language
identifier and does not claim to be: short strings return None rather than a
guess, because a guess is what would make the coverage statement wrong in the
other direction.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable
from typing import Optional, cast

#: Function words that are common in one language and rare in the others here.
#: Chosen for discrimination rather than raw frequency: "de" is the commonest
#: word in several Romance languages and so earns its place in none of them.
STOPWORDS: dict[str, frozenset[str]] = {
    "en": frozenset("the and of to in is was that for with have this are it".split()),
    "de": frozenset("der die das und ist nicht mit sich auch eine dem den wird".split()),
    "fr": frozenset("les des est une pour dans qui pas sur avec ils cette nous".split()),
    "es": frozenset("los las una por con para como pero este esta son todo".split()),
    "it": frozenset("che non per una sono come anche nella degli alla questo".split()),
    "nl": frozenset("het een van niet zijn worden deze naar ook maar door".split()),
    "pt": frozenset("uma para com nao mais como seu sao pelo esta isso".split()),
    "pl": frozenset("jest nie sie oraz tego przez ktore tylko jako jeszcze".split()),
    "sv": frozenset("och att det som för inte den med har hon han var".split()),
}

#: Below this many word tokens, no call is made. A five-word log line has no
#: language in any useful sense and guessing at one would be worse than
#: abstaining.
MIN_TOKENS = 12

#: The winner must beat the runner-up by this many hits. Related languages
#: share function words, and a one-hit lead is noise.
MIN_MARGIN = 2

_WORD = re.compile(r"[^\W\d_]+", re.UNICODE)


def detect(text: Optional[str]) -> Optional[str]:
    """Return a language code, or None when the text does not support a call."""
    if not text:
        return None
    tokens = [t.lower() for t in _WORD.findall(text)]
    if len(tokens) < MIN_TOKENS:
        return None
    seen = Counter(tokens)
    scores = {
        lang: sum(seen[word] for word in words)
        for lang, words in STOPWORDS.items()
    }
    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    best, best_score = ranked[0]
    runner_up = ranked[1][1] if len(ranked) > 1 else 0
    if best_score == 0 or best_score - runner_up < MIN_MARGIN:
        return None
    return best


def summarise(texts: Iterable[Optional[str]]) -> dict[str, object]:
    """Language mix over a set of chunks, and what it means for NER coverage.

    `undecided` is reported rather than folded into either side. Most of a
    real corpus is short metadata values and code fragments that genuinely
    have no language, and counting those as English would overstate how much
    of the store the name detection actually reached.
    """
    return summarise_codes(detect(text) for text in texts)


def summarise_codes(codes: Iterable[Optional[str]]) -> dict[str, object]:
    """:func:`summarise` over language codes already detected, one per chunk.

    For callers that detect as they read, so they need not keep every chunk's
    text until the end. ``None`` is a chunk whose language was not decided.
    """
    counts: Counter[str] = Counter()
    undecided = 0
    total = 0
    for lang in codes:
        total += 1
        if lang is None:
            undecided += 1
        else:
            counts[lang] += 1
    decided = total - undecided
    non_english = sum(n for lang, n in counts.items() if lang != "en")
    return {
        "languages": dict(counts.most_common()),
        "chunks": total,
        "undecided": undecided,
        "decided": decided,
        "non_english": non_english,
        # Share of the text we could place, not of the whole store: a corpus
        # of mostly untyped metadata should not read as 100% English because
        # its three prose chunks were.
        "non_english_share": (non_english / decided) if decided else 0.0,
    }


#: A collection is reported as only partly covered by the name detectors once
#: this much of its identifiable text is in a language the NER layer does not
#: run. Set well above zero so a handful of foreign-language quotes in an
#: English corpus does not downgrade it.
NON_ENGLISH_COVERAGE_THRESHOLD = 0.20


def ner_coverage_gap(summary: dict[str, object],
                     covered: Iterable[str] = ("en",)) -> Optional[str]:
    """A sentence for the coverage statement, or None when NER applied fine.

    ``covered`` is the languages the NER layer actually has a model loaded
    for. With English only (the default) the statement is about non-English
    text; with more, it is about text in languages none of them covers.
    """
    covered_set = set(covered) or {"en"}
    if covered_set != {"en"}:
        counts = cast(dict[str, int], summary.get("languages") or {})
        decided = int(cast(int, summary.get("decided", 0) or 0))
        missing = {lang: n for lang, n in counts.items() if lang not in covered_set}
        share = (sum(missing.values()) / decided) if decided else 0.0
        if share < NON_ENGLISH_COVERAGE_THRESHOLD:
            return None
        return (
            f"{share:.0%} of the classifiable text is in a language the name "
            f"detectors have no model for ({', '.join(missing)}). They run models "
            f"for {', '.join(sorted(covered_set))} only, so they did not apply to "
            "that text. Structured identifiers were still matched; people were not."
        )
    share = float(summary.get("non_english_share", 0.0) or 0.0)
    if share < NON_ENGLISH_COVERAGE_THRESHOLD:
        return None
    languages = summary.get("languages") or {}
    named = ", ".join(
        lang for lang in languages if lang != "en"  # type: ignore[union-attr]
    )
    return (
        f"{share:.0%} of the classifiable text is not in English"
        + (f" ({named})" if named else "")
        + ". The name, location and organisation detectors run an English "
        "model only, so they did not apply to that text. Structured "
        "identifiers were still matched; people were not."
    )
