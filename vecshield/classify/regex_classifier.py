"""Regex-based classifier for high-precision PII/PCI/secret patterns.

Precision-first by design: every detector here should rarely false-positive on
prose. Recall (names, addresses, contextual PII) is the job of the optional
Presidio/NER layer.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass

from vecshield.classify.base import LABEL_PRIORITY, Classifier
from vecshield.classify.checksums import (
    belgium_rrn_ok,
    denmark_cpr_ok,
    finland_hetu_ok,
    france_nir_ok,
    germany_steuer_id_ok,
    greece_amka_ok,
    imei_ok,
    ireland_ppsn_ok,
    norway_fodselsnummer_ok,
    poland_pesel_ok,
    portugal_nif_ok,
    spain_dni_nie_ok,
    sweden_personnummer_ok,
    vin_ok,
)
from vecshield.models import Classification, SensitivityLabel

# Highest priority value in LABEL_PRIORITY (SECRET).  Used by the optional
# ``fast`` early-exit: once a SECRET has fired the doc verdict is maximal.
_MAX_PRIORITY = max(LABEL_PRIORITY.values())


@dataclass
class Detector:
    name: str
    label: SensitivityLabel
    pattern: re.Pattern
    confidence: float
    validator: Callable[[str], bool] | None = None
    # Optional cheap pre-screen: a lowercase literal (``str``) or a tuple of
    # lowercase literals (any-of) that MUST be present in the text for this
    # detector's pattern to have any chance of matching.  When set, ``classify``
    # skips the (much more expensive) regex scan unless the gate appears in
    # ``text.lower()``.  It must be a *necessary* condition of the pattern (never
    # causes a false negative): only a literal the pattern requires
    # unconditionally (e.g. "@" for email, "aiza" for a Google API key).
    #
    # When left ``None``, ``__post_init__`` tries to auto-derive a gate from a
    # leading required literal-alternation (e.g. ``\b(?:dob|born|...)`` →
    # ``("dob", "born", ...)``).  Auto-derivation only fires when every branch of
    # the leading group is a pure literal, so it can never be stricter than the
    # pattern.  Detectors whose leading token is structural (``\d``, char class,
    # optional group) get no gate and scan as before.
    gate: str | tuple[str, ...] | None = None
    #: A cross-cutting fact about the match rather than its kind, carried on
    #: every span this detector emits. See `Classification.qualifiers`.
    qualifier: str | None = None

    def __post_init__(self) -> None:
        if self.gate is None:
            self.gate = _derive_gate(self.pattern.pattern)


# Matches a pattern that begins with a required, non-nested literal alternation
# such as ``\b(?:dob|born)\b...`` or ``(?:Mozilla|Opera)/...``.  Group 1 is the
# alternation body; group 2 is the single character that follows it (used to
# reject optional groups like ``(?:...)?``).
_LEADING_ALT = re.compile(r"^(?:\\b)?\(\?:([^()]*)\)(.?)")
# A branch is a usable literal anchor iff it consists only of safe literal
# characters or escaped ``.`` / ``-`` / ``/`` (i.e. no regex metacharacters that
# would make the branch match more than its literal spelling).
_LITERAL_BRANCH = re.compile(r"^(?:[A-Za-z0-9 _'/-]|\\[.\-/])+$")


def _derive_gate(pattern_src: str) -> tuple[str, ...] | None:
    """Extract an any-of keyword gate from a leading literal alternation.

    Returns a tuple of lowercase anchors when the pattern *must* begin with one
    of a fixed set of literal words, else ``None``.  Being derived directly from
    the compiled pattern, the gate is guaranteed to be a necessary condition of
    a match, so gating can only skip scans that could never have matched.
    """
    m = _LEADING_ALT.match(pattern_src)
    if not m:
        return None
    group, following = m.group(1), m.group(2)
    # A ``?``/``*``/``{`` right after the group makes it optional/variable, so
    # the alternation is no longer a required prefix.
    if following in ("?", "*", "{"):
        return None
    anchors: list[str] = []
    for branch in group.split("|"):
        if not branch or not _LITERAL_BRANCH.match(branch):
            return None
        # Drop the escaping backslashes to recover the literal spelling.
        literal = re.sub(r"\\([.\-/])", r"\1", branch).lower()
        anchors.append(literal)
    if not anchors:
        return None
    return tuple(dict.fromkeys(anchors))


def _minor_age_ok(match: str) -> bool:
    """True when the matched age is under 18.

    The pattern deliberately matches any age so this can reject the rest:
    doing the bound in the regex would mean a second, near-identical pattern
    for the two-digit case and a silent disagreement between them.
    """
    m = re.search(r"\d{1,2}", match)
    return bool(m) and int(m.group(0)) < 18


def _card_number_ok(number: str) -> bool:
    """Luhn, plus the one length/issuer rule that removes a real collision.

    IMEIs carry a Luhn check digit by design, so every valid IMEI is a valid
    Luhn string of exactly fifteen digits -- and was therefore being reported
    as payment card data. A device inventory produced PCI findings.

    The only fifteen-digit payment cards in circulation are American Express,
    which begin 34 or 37. (Diners Club enRoute was the other, and has not been
    issued since the nineties.) Requiring that prefix at that one length costs
    no real card and removes the whole IMEI collision. Other lengths are left
    alone: the point is to fix a known overlap, not to start maintaining an
    issuer table.
    """
    if not _luhn_ok(number):
        return False
    digits = re.sub(r"\D", "", number)
    if len(digits) == 15 and not digits.startswith(("34", "37")):
        return False
    return True


def _track_pan_ok(track: str) -> bool:
    """Luhn-check the PAN inside a magnetic-stripe track, not the whole track.

    The discretionary data after the service code is arbitrary digits, so
    running Luhn across the match would reject almost every real track. The PAN
    is the run of digits before the first field separator.
    """
    m = re.search(r"[%;]?[Bb]?(\d{13,19})[\^=]", track)
    return bool(m) and _luhn_ok(m.group(1))


def _luhn_ok(number: str) -> bool:
    """Luhn checksum — cuts credit-card false positives dramatically."""
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if not 12 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _aba_routing_ok(number: str) -> bool:
    digits = re.sub(r"\D", "", number)
    if len(digits) != 9:
        return False
    weights = (3, 7, 1) * 3
    return sum(int(d) * w for d, w in zip(digits, weights, strict=True)) % 10 == 0


def _iban_ok(value: str) -> bool:
    compact = re.sub(r"\s+", "", value).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", compact):
        return False
    rearranged = compact[4:] + compact[:4]
    numeric = "".join(str(ord(ch) - 55) if ch.isalpha() else ch for ch in rearranged)
    remainder = 0
    for ch in numeric:
        remainder = (remainder * 10 + int(ch)) % 97
    return remainder == 1


def _ip_ok(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _luhn_digits_ok(digits: str) -> bool:
    digits_only = re.sub(r"\D", "", digits)
    if not digits_only:
        return False
    checksum = 0
    parity = len(digits_only) % 2
    for i, ch in enumerate(digits_only):
        digit = int(ch)
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _canada_sin_ok(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    return len(digits) == 9 and _luhn_digits_ok(digits)


def _npi_ok(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    return len(digits) == 10 and _luhn_digits_ok("80840" + digits)


def _brazil_cpf_ok(value: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", value)]
    if len(digits) != 11 or len(set(digits)) == 1:
        return False
    s = sum(d * (10 - i) for i, d in enumerate(digits[:9]))
    r = (s * 10) % 11
    if r >= 10:
        r = 0
    if digits[9] != r:
        return False
    s = sum(d * (11 - i) for i, d in enumerate(digits[:10]))
    r = (s * 10) % 11
    if r >= 10:
        r = 0
    return digits[10] == r


def _netherlands_bsn_ok(value: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", value)]
    if len(digits) != 9:
        return False
    weights = [9, 8, 7, 6, 5, 4, 3, 2, -1]
    return sum(d * w for d, w in zip(digits, weights, strict=True)) % 11 == 0


def _uk_nhs_ok(value: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", value)]
    if len(digits) != 10:
        return False
    weights = [10, 9, 8, 7, 6, 5, 4, 3, 2]
    total = sum(d * w for d, w in zip(digits[:9], weights, strict=True))
    remainder = total % 11
    check = 0 if remainder == 0 else 11 - remainder
    return check == digits[9] and check != 10


def _china_resident_id_ok(value: str) -> bool:
    value = re.sub(r"[\s\-]", "", value).upper()
    if not re.fullmatch(r"\d{17}[\dX]", value):
        return False
    weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    check_chars = "10X98765432"
    try:
        total = sum(int(value[i]) * weights[i] for i in range(17))
        return check_chars[total % 11] == value[17]
    except (ValueError, IndexError):
        return False


def _singapore_nric_ok(value: str) -> bool:
    value = value.upper()
    if not re.fullmatch(r"[STFGM]\d{7}[A-Z]", value):
        return False
    prefix = value[0]
    digits = [int(d) for d in value[1:8]]
    weights = [2, 7, 6, 5, 4, 3, 2]
    total = sum(d * w for d, w in zip(digits, weights, strict=True))
    if prefix in ("T", "G"):
        total += 4
    elif prefix == "M":
        total += 3
    tables = {
        "S": "JZIHGFEDCBA",
        "T": "JZIHGFEDCBA",
        "F": "XWUTRQPNMLK",
        "G": "XWUTRQPNMLK",
        "M": "XWUTRQPNMLK",
    }
    return value[8] == tables[prefix][total % 11]


def _australia_tfn_ok(value: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", value)]
    if len(digits) not in (8, 9):
        return False
    weights = (
        [1, 4, 3, 7, 5, 8, 6, 9, 10] if len(digits) == 9 else [10, 3, 7, 5, 8, 6, 9, 10]
    )
    return sum(d * w for d, w in zip(digits, weights, strict=True)) % 11 == 0


def _us_dea_ok(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if len(digits) != 7:
        return False
    odd_sum = sum(int(digits[i]) for i in (0, 2, 4))
    even_sum = sum(int(digits[i]) for i in (1, 3, 5))
    return int(digits[6]) == (odd_sum + 2 * even_sum) % 10


def _south_africa_id_ok(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    return len(digits) == 13 and _luhn_digits_ok(digits)


DETECTORS: list[Detector] = [
    Detector(
        "us_ssn",
        SensitivityLabel.PII,
        re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
        0.95,
    ),
    Detector(
        "email",
        SensitivityLabel.PII,
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        0.90,
        gate="@",
    ),
    Detector(
        "us_phone",
        SensitivityLabel.PII,
        re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        0.75,
    ),
    Detector(
        "ipv4_address",
        SensitivityLabel.PII,
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
        ),
        0.70,
        validator=_ip_ok,
    ),
    Detector(
        "ipv6_address",
        SensitivityLabel.PII,
        re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b"),
        0.70,
        validator=_ip_ok,
    ),
    Detector(
        "mac_address",
        SensitivityLabel.PII,
        re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),
        0.68,
    ),
    Detector(
        "date_of_birth",
        SensitivityLabel.PII,
        re.compile(
            r"\b(?:dob|d\.o\.b\.|date of birth|birthdate|born)\b"
            r"[^A-Za-z0-9]{0,12}"
            r"(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|"
            r"\d{4}-\d{2}-\d{2}|"
            r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*"
            r"\s+\d{1,2},?\s+\d{4})",
            re.I,
        ),
        0.82,
    ),
    Detector(
        "us_street_address",
        SensitivityLabel.PII,
        re.compile(
            r"\b\d{1,6}\s+[A-Za-z0-9][A-Za-z0-9.'-]*(?:\s+[A-Za-z0-9][A-Za-z0-9.'-]*){0,5}"
            r"\s+(?:street|st\.?|avenue|ave\.?|road|rd\.?|boulevard|blvd\.?|"
            r"drive|dr\.?|lane|ln\.?|court|ct\.?|way|place|pl\.?|terrace|ter\.?)\b"
            r"(?:\s+(?:apt|apartment|unit|suite|ste\.?|#)\s*[A-Za-z0-9-]+)?",
            re.I,
        ),
        0.78,
    ),
    Detector(
        "us_zip_context",
        SensitivityLabel.PII,
        re.compile(
            r"\b(?:zip|zip code|postal code)\b[^A-Za-z0-9]{0,12}"
            r"\d{5}(?:-\d{4})?\b",
            re.I,
        ),
        0.68,
    ),
    Detector(
        "us_driver_license_context",
        SensitivityLabel.PII,
        re.compile(
            r"\b(?:driver'?s? licen[cs]e|dl number|driver id)\b[^A-Za-z0-9]{0,12}"
            r"[A-Z]?[0-9A-Z][0-9A-Z -]{5,18}\b",
            re.I,
        ),
        0.82,
    ),
    Detector(
        "passport_context",
        SensitivityLabel.PII,
        re.compile(
            r"\bpassport(?:\s+(?:number|no\.?|id))?\b[^A-Za-z0-9]{0,12}"
            r"[A-Z0-9]{6,12}\b",
            re.I,
        ),
        0.82,
    ),
    Detector(
        "tax_id_context",
        SensitivityLabel.PII,
        re.compile(
            r"\b(?:ein|tin|tax id|taxpayer id)\b[^A-Za-z0-9]{0,12}"
            r"(?:\d{2}-\d{7}|\d{9})\b",
            re.I,
        ),
        0.80,
    ),
    Detector(
        "uk_nino_context",
        SensitivityLabel.PII,
        re.compile(
            r"\b(?:national insurance|nino|ni number)\b[^A-Za-z0-9]{0,12}"
            r"[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b",
            re.I,
        ),
        0.82,
    ),
    Detector(
        "canada_sin_context",
        SensitivityLabel.PII,
        re.compile(
            r"\b(?:sin|social insurance number)\b[^A-Za-z0-9]{0,12}"
            r"\d{3}[ -]?\d{3}[ -]?\d{3}\b",
            re.I,
        ),
        0.84,
        validator=_canada_sin_ok,
    ),
    # ── International government-issued identifiers ──────────────────────────
    Detector(
        "india_pan",
        SensitivityLabel.PII,
        re.compile(
            r"\b(?:pan|pan card|permanent account number)\b"
            r"[^A-Za-z0-9]{0,12}[A-Z]{5}[0-9]{4}[A-Z]\b",
            re.I,
        ),
        0.88,
    ),
    Detector(
        "india_aadhaar_context",
        SensitivityLabel.PII,
        re.compile(
            r"\b(?:aadhaar|aadhar|uid(?: number)?)\b"
            r"[^A-Za-z0-9]{0,12}\d{4}\s?\d{4}\s?\d{4}\b",
            re.I,
        ),
        0.86,
    ),
    Detector(
        "brazil_cpf_context",
        SensitivityLabel.PII,
        re.compile(
            r"\b(?:cpf|cadastro de pessoas)\b[^A-Za-z0-9]{0,12}"
            r"\d{3}[.\s\-]?\d{3}[.\s\-]?\d{3}[\-.]?\d{2}\b",
            re.I,
        ),
        0.88,
        validator=_brazil_cpf_ok,
    ),
    Detector(
        "china_resident_id",
        SensitivityLabel.PII,
        re.compile(
            r"\b\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])"
            r"(?:0[1-9]|[12]\d|3[01])\d{3}[\dX]\b"
        ),
        0.88,
        validator=_china_resident_id_ok,
    ),
    Detector(
        "singapore_nric",
        SensitivityLabel.PII,
        re.compile(r"\b[STFGM]\d{7}[A-Z]\b"),
        0.90,
        validator=_singapore_nric_ok,
    ),
    Detector(
        "italy_fiscal_code",
        SensitivityLabel.PII,
        re.compile(r"\b[A-Z]{6}\d{2}[ABCDEHLMPRST]\d{2}[A-Z]\d{3}[A-Z]\b"),
        0.88,
    ),
    Detector(
        "mexico_curp",
        SensitivityLabel.PII,
        re.compile(
            r"\b[A-Z][AEIOU][A-Z]{2}\d{2}(?:0[1-9]|1[0-2])"
            r"(?:0[1-9]|[12]\d|3[01])[HM][A-Z]{2}"
            r"[BCDFGHJKLMNPQRSTVWXYZ]{3}[A-Z0-9]\d\b"
        ),
        0.90,
    ),
    Detector(
        "netherlands_bsn_context",
        SensitivityLabel.PII,
        re.compile(
            r"\b(?:bsn|burgerservicenummer)\b"
            r"[^A-Za-z0-9]{0,12}\d{9}\b",
            re.I,
        ),
        0.88,
        validator=_netherlands_bsn_ok,
    ),
    Detector(
        "south_africa_id_context",
        SensitivityLabel.PII,
        re.compile(
            r"\b(?:south africa(?:n)?(?:\s+id)?|za\s+id)\b"
            r"[^A-Za-z0-9]{0,16}\d{13}\b",
            re.I,
        ),
        0.86,
        validator=_south_africa_id_ok,
    ),
    Detector(
        "australia_tfn_context",
        SensitivityLabel.PII,
        re.compile(
            r"\b(?:tfn|tax file number)\b"
            r"[^A-Za-z0-9]{0,12}\d{3}\s?\d{3}\s?\d{3}\b",
            re.I,
        ),
        0.88,
        validator=_australia_tfn_ok,
    ),
    Detector(
        "uk_nhs_context",
        SensitivityLabel.PHI,
        re.compile(
            r"\b(?:nhs|national health service)\s*(?:number|no\.?|#)?\b"
            r"[^A-Za-z0-9]{0,12}\d{3}\s?\d{3}\s?\d{4}\b",
            re.I,
        ),
        0.88,
        validator=_uk_nhs_ok,
    ),
    Detector(
        "uk_utr_context",
        SensitivityLabel.PII,
        re.compile(
            r"\b(?:utr|unique taxpayer reference)\b"
            r"[^A-Za-z0-9]{0,12}\d{10}\b",
            re.I,
        ),
        0.82,
    ),
    Detector(
        "bank_routing",
        SensitivityLabel.PII,
        re.compile(
            r"\b(?:routing|aba)\s*(?:number|no\.?|#)?\s*[:=]?\s*(\d{9})\b",
            re.I,
        ),
        0.88,
        validator=_aba_routing_ok,
    ),
    Detector(
        "bank_account_context",
        SensitivityLabel.PII,
        re.compile(
            r"\b(?:bank account|account number|acct(?:\.|ount)? no\.?)\b"
            r"[^A-Za-z0-9]{0,12}[A-Z0-9][A-Z0-9 -]{5,24}\b",
            re.I,
        ),
        0.78,
    ),
    # ── Additional financial identifiers ─────────────────────────────────────
    Detector(
        "us_itin",
        SensitivityLabel.PII,
        re.compile(
            r"\b(?:itin|individual taxpayer identification(?: number)?)\b"
            r"[^A-Za-z0-9]{0,12}9\d{2}-\d{2}-\d{4}\b",
            re.I,
        ),
        0.88,
    ),
    Detector(
        "credit_card_cvv_context",
        SensitivityLabel.PCI,
        re.compile(
            r"\b(?:cvv2?|cvc2?|security code|card verification)\b"
            r"[^A-Za-z0-9]{0,12}\d{3,4}\b",
            re.I,
        ),
        0.84,
    ),
    Detector(
        "credit_card_expiry_context",
        SensitivityLabel.PCI,
        re.compile(
            r"\b(?:exp(?:iry|iration)?(?:\s+date)?|"
            r"valid(?:\s+(?:thru|through|until))?)\b"
            r"[^A-Za-z0-9]{0,8}(?:0[1-9]|1[0-2])\s?[/\-]\s?(?:\d{2}|\d{4})\b",
            re.I,
        ),
        0.82,
    ),
    Detector(
        "iban",
        SensitivityLabel.PCI,
        re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]){11,30}\b"),
        0.90,
        validator=_iban_ok,
    ),
    Detector(
        "swift_bic_code",
        SensitivityLabel.PCI,
        re.compile(
            r"\b(?:swift|bic|swift[/\-]bic|bank identifier code)\b"
            r"[^A-Za-z0-9]{0,12}[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b",
            re.I,
        ),
        0.84,
    ),
    Detector(
        "medical_record_context",
        SensitivityLabel.PHI,
        re.compile(
            r"\b(?:mrn|medical record(?: number)?|patient id|health insurance id|"
            r"member id)\b[^A-Za-z0-9]{0,12}[A-Z0-9][A-Z0-9-]{4,24}\b",
            re.I,
        ),
        0.86,
    ),
    Detector(
        "us_medicare_mbi_context",
        SensitivityLabel.PHI,
        re.compile(
            r"\b(?:medicare(?: beneficiary)?(?: id| identifier| number)?|mbi)\b"
            r"[^A-Za-z0-9]{0,12}"
            r"[1-9][A-HJ-NP-Z][A-HJ-NP-Z0-9][0-9]-?"
            r"[A-HJ-NP-Z][A-HJ-NP-Z0-9][0-9]-?"
            r"[A-HJ-NP-Z]{2}[0-9]{2}\b",
            re.I,
        ),
        0.86,
    ),
    Detector(
        "npi_context",
        SensitivityLabel.PHI,
        re.compile(r"\b(?:npi|provider id)\b[^A-Za-z0-9]{0,12}\d{10}\b", re.I),
        0.80,
        validator=_npi_ok,
    ),
    Detector(
        "us_dea_number_context",
        SensitivityLabel.PHI,
        re.compile(
            r"\b(?:dea|drug enforcement)\s*(?:number|no\.?|#)?\b"
            r"[^A-Za-z0-9]{0,12}[A-Z]{2}\d{7}\b",
            re.I,
        ),
        0.86,
        validator=_us_dea_ok,
    ),
    Detector(
        "icd_code_context",
        SensitivityLabel.PHI,
        re.compile(
            r"\b(?:icd[-\s]?(?:9|10)|diagnosis code|dx(?:\s+code)?)\b"
            r"[^A-Za-z0-9]{0,12}[A-Z]\d{2}(?:\.\w{1,4})?\b",
            re.I,
        ),
        0.78,
    ),
    Detector(
        "metadata_identifier",
        SensitivityLabel.PII,
        re.compile(
            r"\b(?:customer|user|account|patient|member|employee|subscriber|contact"
            r"|site)"
            r"[_\s-]*(?:id|identifier|number|no)\b\s*[:=]\s*"
            r"[A-Za-z0-9][A-Za-z0-9._:-]{3,}\b",
            re.I,
        ),
        0.72,
    ),
    # ── Prefixed alphanumeric identifier (LETTERS-DIGITS): health-plan/member,
    # account, case, and record numbers are frequently written as a short
    # uppercase prefix + hyphen + digit run (``HP-678901``, ``HMO-234567``,
    # ``GRM-998877``, ``CLN-112233``) with no anchoring keyword.  Low confidence
    # because the shape also matches some benign codes; the NLP/context layers
    # and the document-level score threshold arbitrate borderline cases. ───────
    Detector(
        "prefixed_id",
        SensitivityLabel.PII,
        re.compile(r"\b#?[A-Z]{1,4}-\d{4,8}\b"),
        0.50,
    ),
    Detector(
        "credit_card",
        SensitivityLabel.PCI,
        re.compile(r"\b(?:\d[ -]?){13,19}\b"),
        0.97,
        validator=_card_number_ok,
    ),
    # ---- European national identifiers -----------------------------------
    #
    # All context-gated *and* check-digit validated. Either alone would be
    # thin: an eleven-digit number is not distinctive, and a modulo-11 check
    # accepts roughly one random string in eleven. Together they hold the same
    # precision bar as the identifiers already in this file.
    #
    # These matter disproportionately for GDPR. Most of them embed a date of
    # birth and several encode sex, so a single match is not one identifier
    # but three.
    Detector(
        "france_nir_context",
        SensitivityLabel.PII,
        re.compile(
            r"\b(?:NIR|INSEE|(?:num[e\u00e9]ro de )?s[e\u00e9]curit[e\u00e9] sociale"
            r"|social security)\b\W{0,15}"
            r"[12][\s.]?\d{2}[\s.]?\d{2}[\s.]?(?:\d{2}|2[AB])[\s.]?\d{3}[\s.]?\d{3}[\s.]?\d{2}",
            re.IGNORECASE,
        ),
        0.93,
        validator=france_nir_ok,
    ),
    Detector(
        "poland_pesel_context",
        SensitivityLabel.PII,
        re.compile(r"\bPESEL\b\W{0,15}\d{11}\b", re.IGNORECASE),
        0.95,
        validator=poland_pesel_ok,
    ),
    Detector(
        "germany_steuer_id_context",
        SensitivityLabel.PII,
        re.compile(
            r"\b(?:steuer[\s-]?id|steuerliche identifikationsnummer|idnr|tax id)\b"
            r"\W{0,15}\d{2}[\s/]?\d{3}[\s/]?\d{3}[\s/]?\d{3}\b",
            re.IGNORECASE,
        ),
        0.93,
        validator=germany_steuer_id_ok,
    ),
    Detector(
        "spain_dni_nie_context",
        SensitivityLabel.PII,
        re.compile(
            r"\b(?:DNI|NIE|documento nacional)\b\W{0,15}[XYZ]?\d{7,8}[\s-]?[A-Z]\b",
            re.IGNORECASE,
        ),
        0.94,
        validator=spain_dni_nie_ok,
    ),
    Detector(
        "sweden_personnummer_context",
        SensitivityLabel.PII,
        re.compile(
            r"\b(?:personnummer|person number|pnr)\b\W{0,15}"
            r"(?:\d{2})?\d{6}[-+]?\d{4}\b",
            re.IGNORECASE,
        ),
        0.93,
        validator=sweden_personnummer_ok,
    ),
    Detector(
        "norway_fodselsnummer_context",
        SensitivityLabel.PII,
        re.compile(
            r"\b(?:f[o\u00f8]dselsnummer|fnr|birth number)\b\W{0,15}\d{6}\s?\d{5}\b",
            re.IGNORECASE,
        ),
        0.93,
        validator=norway_fodselsnummer_ok,
    ),
    Detector(
        "finland_hetu_context",
        SensitivityLabel.PII,
        re.compile(
            r"\b(?:henkil[o\u00f6]tunnus|hetu|personal identity code)\b\W{0,15}"
            r"\d{6}[-+A-FUVWXY]\d{3}[0-9A-Y]\b",
            re.IGNORECASE,
        ),
        0.94,
        validator=finland_hetu_ok,
    ),
    Detector(
        "denmark_cpr_context",
        SensitivityLabel.PII,
        re.compile(
            r"\b(?:CPR(?:[\s-]?nummer)?|civil registration)\b\W{0,15}"
            r"\d{6}[\s-]?\d{4}\b",
            re.IGNORECASE,
        ),
        # Lower than its neighbours on purpose: CPR numbers issued since 2007
        # do not all satisfy the old modulo-11 check, so `denmark_cpr_ok`
        # validates the embedded date and nothing more. The gate is carrying
        # the precision here and the score says so.
        0.85,
        validator=denmark_cpr_ok,
    ),
    Detector(
        "belgium_rrn_context",
        SensitivityLabel.PII,
        re.compile(
            r"\b(?:rijksregisternummer|registre national|national register|RRN)\b"
            r"\W{0,15}\d{2}[.\s]?\d{2}[.\s]?\d{2}[-\s]?\d{3}[.\s-]?\d{2}\b",
            re.IGNORECASE,
        ),
        0.94,
        validator=belgium_rrn_ok,
    ),
    Detector(
        "ireland_ppsn_context",
        SensitivityLabel.PII,
        re.compile(
            r"\b(?:PPSN?|PPS number|personal public service)\b\W{0,15}"
            r"\d{7}[A-W][A-IW]?\b",
            re.IGNORECASE,
        ),
        0.94,
        validator=ireland_ppsn_ok,
    ),
    Detector(
        "portugal_nif_context",
        SensitivityLabel.PII,
        re.compile(
            r"\b(?:NIF|n[u\u00fa]mero de identifica[c\u00e7][a\u00e3]o fiscal"
            r"|contribuinte)\b\W{0,15}\d{3}[\s.]?\d{3}[\s.]?\d{3}\b",
            re.IGNORECASE,
        ),
        0.92,
        validator=portugal_nif_ok,
    ),
    Detector(
        "greece_amka_context",
        SensitivityLabel.PII,
        re.compile(r"\bAMKA\b\W{0,15}\d{11}\b", re.IGNORECASE),
        0.94,
        validator=greece_amka_ok,
    ),

    # ---- Clinical vocabularies -------------------------------------------
    #
    # Every one of these is context-gated, and deliberately so. A bare CPT code
    # is five digits, a LOINC code is digits-hyphen-digit, an RxCUI is up to
    # seven digits -- none of them are distinguishable from an order number
    # without the vocabulary being named. Gating costs recall on code tables
    # that omit their own header and buys precision everywhere else.
    #
    # These earn their place twice over: as identifiers, and as the strongest
    # available health-context signal, which is what drives the PII -> PHI
    # upgrade in `base.apply_phi_context`. The vocabulary names are added to
    # PHI_CONTEXT there for exactly that reason.
    Detector(
        "ndc_code_context",
        SensitivityLabel.PHI,
        # 4-4-2, 5-3-2, 5-4-1 and the 11-digit 5-4-2 presentations.
        re.compile(
            r"\bNDC\b\W{0,12}\d{4,5}-\d{3,4}-\d{1,2}\b",
            re.IGNORECASE,
        ),
        0.90,
    ),
    Detector(
        "cpt_hcpcs_code_context",
        SensitivityLabel.PHI,
        # CPT Category I is 5 digits; Category II/III end in F or T. HCPCS
        # Level II is a letter plus four digits.
        re.compile(
            r"\b(?:CPT|HCPCS|procedure\s+code)\b\W{0,12}"
            r"(?:\d{5}|\d{4}[FTU]|[A-V]\d{4})\b",
            re.IGNORECASE,
        ),
        0.88,
    ),
    Detector(
        "loinc_code_context",
        SensitivityLabel.PHI,
        re.compile(r"\bLOINC\b\W{0,12}\d{1,5}-\d\b", re.IGNORECASE),
        0.90,
    ),
    Detector(
        "snomed_code_context",
        SensitivityLabel.PHI,
        re.compile(
            r"\bSNOMED(?:\s*CT)?\b\W{0,12}\d{6,18}\b",
            re.IGNORECASE,
        ),
        0.90,
    ),
    Detector(
        "rxnorm_code_context",
        SensitivityLabel.PHI,
        re.compile(r"\b(?:RxNorm|RxCUI)\b\W{0,12}\d{1,7}\b", re.IGNORECASE),
        0.90,
    ),
    Detector(
        "drg_code_context",
        SensitivityLabel.PHI,
        re.compile(
            r"\b(?:MS-)?DRG\b\W{0,12}\d{1,3}\b",
            re.IGNORECASE,
        ),
        0.85,
    ),
    Detector(
        "clinical_trial_nct",
        SensitivityLabel.PHI,
        # ClinicalTrials.gov registry identifier. Safe Harbor (K).
        re.compile(r"\bNCT\d{8}\b"),
        0.95,
        gate="nct",
    ),
    Detector(
        "lab_accession_context",
        SensitivityLabel.PHI,
        # A routine pathology/radiology identifier and a known
        # re-identification vector. Safe Harbor (R).
        re.compile(
            r"\b(?:accession|specimen|spec\.?)\s*(?:no\.?|number|#|id)?\s*[:=#]\s*"
            r"[A-Z0-9][A-Z0-9-]{4,19}\b",
            re.IGNORECASE,
        ),
        0.85,
    ),

    # ---- GDPR Art. 9 special categories ----------------------------------
    #
    # Lexicon detectors, and so structurally less precise than the identifier
    # patterns above. They are written to fire on a *statement about a person*
    # rather than on a topic being mentioned: "member of the union" and not
    # "union", "identifies as" and not the identity word alone. A corpus that
    # discusses religion is not a corpus holding religious beliefs about
    # identified people, and Art. 9 is about the latter.
    Detector(
        "trade_union_membership",
        SensitivityLabel.SPECIAL_CATEGORY,
        re.compile(
            r"\b(?:union\s+(?:member(?:ship)?|dues|steward|rep(?:resentative)?)"
            r"|member\s+of\s+(?:the\s+)?[\w\s]{0,24}?union"
            r"|joined\s+(?:the\s+)?[\w\s]{0,24}?union)\b",
            re.IGNORECASE,
        ),
        0.80,
    ),
    Detector(
        "sexual_orientation",
        SensitivityLabel.SPECIAL_CATEGORY,
        re.compile(
            r"\b(?:sexual\s+orientation\s*[:=]\s*\w+"
            r"|(?:identifies\s+as|came\s+out\s+as|is\s+openly)\s+"
            r"(?:gay|lesbian|bisexual|bi|queer|asexual|pansexual|heterosexual|straight))\b",
            re.IGNORECASE,
        ),
        0.82,
    ),
    Detector(
        "political_opinion",
        SensitivityLabel.SPECIAL_CATEGORY,
        re.compile(
            r"\b(?:political\s+(?:opinion|affiliation|views?|party)\s*[:=]\s*\w+"
            r"|voted\s+(?:for|against)\s+\w+"
            r"|registered\s+(?:democrat|republican|green|labour|conservative|socialist)"
            r"|party\s+member(?:ship)?\s*[:=]\s*\w+)\b",
            re.IGNORECASE,
        ),
        0.78,
    ),
    Detector(
        "religious_belief",
        SensitivityLabel.SPECIAL_CATEGORY,
        re.compile(
            r"\b(?:religion\s*[:=]\s*\w+"
            r"|religious\s+(?:belief|affiliation)\s*[:=]\s*\w+"
            r"|(?:practis|practic)ing\s+(?:muslim|christian|jew|hindu|buddhist|sikh|catholic)"
            r"|identifies\s+as\s+(?:a\s+)?"
            r"(?:muslim|christian|jewish|hindu|buddhist|sikh|atheist|catholic|protestant))\b",
            re.IGNORECASE,
        ),
        0.78,
    ),
    Detector(
        "racial_ethnic_origin",
        SensitivityLabel.SPECIAL_CATEGORY,
        # Field-shaped only. Ethnicity in prose is left to the NER layer's NRP
        # recogniser, because a pattern for it cannot tell a person's origin
        # from a sentence about a country.
        re.compile(
            r"\b(?:ethnicity|ethnic\s+origin|ethnic\s+group|race)\s*[:=]\s*[\w\s-]{2,30}",
            re.IGNORECASE,
        ),
        0.80,
    ),

    # ---- Biometric and genetic data (Art. 9; Safe Harbor P; BIPA, CUBI) ---
    #
    # Raw biometric templates cannot be recognised in text and this does not
    # pretend to. What it recognises is *references* to them, which is what a
    # retrieval corpus actually contains: a support note saying a faceprint
    # was enrolled, a schema field called voiceprint, a filename. That is
    # enough to answer "does this store hold biometric data", which is the
    # question Art. 9 and BIPA ask.
    #
    # Note the deliberate absence of bare "fingerprint": this product uses the
    # word for finding fingerprints throughout its own corpus, and so does
    # every TLS and file-hash discussion in a runbook. Only the biometric
    # senses are matched.
    Detector(
        "biometric_reference",
        SensitivityLabel.SPECIAL_CATEGORY,
        re.compile(
            r"\b(?:faceprint|voiceprint|iris\s+(?:scan|template|recognition)"
            r"|retina(?:l)?\s+scan|palm\s+print|gait\s+(?:signature|analysis)"
            r"|fingerprint\s+(?:template|minutiae|enroll?ment|scan)"
            r"|facial\s+(?:recognition\s+)?(?:template|embedding)"
            r"|biometric\s+(?:template|identifier|data|enroll?ment))\b",
            re.IGNORECASE,
        ),
        0.88,
    ),
    Detector(
        "genetic_variant_hgvs",
        SensitivityLabel.SPECIAL_CATEGORY,
        # HGVS nomenclature, with or without its reference sequence.
        re.compile(
            r"\b(?:[NX][MRCGP]_\d+(?:\.\d+)?:)?[cgmnpr]\.\d+(?:_\d+)?"
            r"(?:[ACGT]>[ACGT]|del[A-Z]*|dup[A-Z]*|ins[A-Z]+)",
        ),
        0.92,
    ),
    Detector(
        "genetic_rsid",
        SensitivityLabel.SPECIAL_CATEGORY,
        # dbSNP reference SNP identifier. Three digits is the floor rather
        # than four because some of the most clinically significant SNPs are
        # short -- rs334 is the sickle-cell variant -- and excluding them to
        # dodge a hypothetical "rs123" ticket reference would miss exactly the
        # data the category exists to protect. Confidence is set accordingly.
        re.compile(r"\brs\d{3,}\b"),
        0.75,
        gate="rs",
    ),
    Detector(
        "genetic_sequence_run",
        SensitivityLabel.SPECIAL_CATEGORY,
        # Thirty or more consecutive nucleotide letters. Prose does not do
        # this; a FASTA or VCF fragment pasted into a note does.
        re.compile(r"\b[ACGTN]{30,}\b"),
        0.90,
    ),
    Detector(
        "genetic_testing_context",
        SensitivityLabel.SPECIAL_CATEGORY,
        re.compile(
            r"\b(?:genetic\s+(?:test(?:ing)?|screening|data|information|counsel+ing)"
            r"|genome\s+sequencing|whole[\s-]exome|karyotype"
            r"|BRCA[12]\b|carrier\s+status)\b",
            re.IGNORECASE,
        ),
        0.85,
    ),

    # ---- GDPR Art. 10 criminal convictions and offences -------------------
    Detector(
        "criminal_offence_context",
        SensitivityLabel.CRIMINAL_OFFENCE,
        re.compile(
            r"\b(?:convicted\s+of|conviction\s+for|criminal\s+(?:record|conviction|history)"
            r"|arrested\s+for|charged\s+with\s+(?:a\s+)?(?:crime|offence|offense|felony|misdemea?nou?r)"
            r"|indicted\s+for|sentenced\s+to|custodial\s+sentence|spent\s+conviction"
            r"|on\s+(?:probation|parole)|sex\s+offender\s+regist)\b",
            re.IGNORECASE,
        ),
        0.82,
    ),

    # ---- Children's data (a qualifier, not a label) -----------------------
    #
    # A child's email address is still an email address. What changes is the
    # regime that reaches it, so these ride as a qualifier on an ordinary PII
    # span rather than as a label of their own.
    Detector(
        "minor_age_context",
        SensitivityLabel.PII,
        re.compile(
            r"\b(?:aged?\s*[:=]?\s*)?\d{1,2}\s*(?:years?[\s-]*old|y/o|yrs?\s*old)\b",
            re.IGNORECASE,
        ),
        0.75,
        validator=_minor_age_ok,
        qualifier="minor",
    ),
    Detector(
        "minor_school_context",
        SensitivityLabel.PII,
        re.compile(
            r"\b(?:kindergarten|pre[\s-]?school|primary\s+school|middle\s+school"
            r"|elementary\s+school|year\s+[1-9]\s+pupil|grade\s+[1-9]\b"
            r"|schoolchild|legal\s+guardian|parental\s+consent|guardian\s+consent)\b",
            re.IGNORECASE,
        ),
        0.70,
        qualifier="minor",
    ),

    # ---- PCI DSS sensitive authentication data ---------------------------
    #
    # Requirement 3.3.1 prohibits retaining SAD after authorisation, so unlike
    # every other detector here these do not flag sensitive *content* -- they
    # flag a storage condition that is not permitted at all. That makes them
    # the highest-value patterns in the file and, because track formats are
    # rigid, among the most precise.
    Detector(
        "card_track1_data",
        SensitivityLabel.PCI,
        # %B<PAN>^<NAME>^<YYMM><service code><discretionary>?
        re.compile(r"%[Bb]\d{13,19}\^[^^?]{2,30}\^\d{7}[^?]{0,60}\?"),
        0.99,
        validator=_track_pan_ok,
        gate="%b",
    ),
    Detector(
        "card_track2_data",
        SensitivityLabel.PCI,
        # ;<PAN>=<YYMM><service code><discretionary>?
        re.compile(r";\d{13,19}=\d{7}[^?]{0,40}\?"),
        0.99,
        validator=_track_pan_ok,
        gate=";",
    ),
    Detector(
        "card_track2_equivalent",
        SensitivityLabel.PCI,
        # The same data without its sentinels, which is how it usually arrives
        # in a log line or a support paste. Luhn on the PAN is doing all the
        # precision work here, so it is required rather than optional.
        re.compile(r"\b\d{13,19}=\d{7,30}\b"),
        0.95,
        validator=_track_pan_ok,
        gate="=",
    ),
    Detector(
        "card_pin_block_context",
        SensitivityLabel.PCI,
        # An ISO 9564 PIN block is 16 hex characters, which on its own is
        # indistinguishable from half an MD5. Only flagged when it is named.
        re.compile(
            r"\b(?:pin\s*block|pinblock|encrypted\s*pin|iso\s*9564)\b[^0-9A-Fa-f]{0,20}"
            r"[0-9A-Fa-f]{16}\b",
            re.IGNORECASE,
        ),
        0.93,
    ),
    Detector(
        "card_pin_context",
        SensitivityLabel.PCI,
        # Storing a PIN is prohibited outright. Deliberately lower confidence:
        # "PIN" is also a door code, a voicemail code and a support-callback
        # code, and this cannot tell them apart.
        re.compile(
            r"\b(?:card\s*pin|pin\s*(?:number|code)|p\.i\.n\.)\s*[:=]?\s*\d{4,12}\b",
            re.IGNORECASE,
        ),
        0.72,
    ),
    Detector(
        "aws_access_key",
        SensitivityLabel.SECRET,
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        0.98,
    ),
    Detector(
        "github_token",
        SensitivityLabel.SECRET,
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b"),
        0.96,
    ),
    Detector(
        "slack_token",
        SensitivityLabel.SECRET,
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        0.94,
        gate="xox",
    ),
    Detector(
        "google_api_key",
        SensitivityLabel.SECRET,
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        0.94,
        gate="aiza",
    ),
    Detector(
        "openai_key",
        SensitivityLabel.SECRET,
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
        0.92,
        gate="sk-",
    ),
    Detector(
        "generic_secret_context",
        SensitivityLabel.SECRET,
        re.compile(
            r"\b(?:api[_ -]?key|access[_ -]?token|auth[_ -]?token|secret|password)\b"
            r"\s*[:=]\s*[\"']?[A-Za-z0-9._~+/=-]{12,}[\"']?",
            re.I,
        ),
        0.82,
    ),
    Detector(
        "bearer_token_context",
        SensitivityLabel.SECRET,
        re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b"),
        0.84,
        gate="bearer",
    ),
    Detector(
        "private_key_block",
        SensitivityLabel.SECRET,
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
        ),
        0.99,
        gate="private key",
    ),
    Detector(
        "pgp_private_key_block",
        SensitivityLabel.SECRET,
        re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
        0.99,
        gate="pgp private key",
    ),

    # ---- Cloud and platform credentials ----------------------------------
    #
    # Each of these is a literal-prefixed pattern, which is the cheapest shape
    # of detector this file supports: the `gate` pre-screen skips the regex
    # entirely unless the prefix is present, so the set can grow without
    # costing scan time.
    Detector(
        "azure_storage_connection_string",
        SensitivityLabel.SECRET,
        re.compile(
            r"DefaultEndpointsProtocol=https?;[^\s]{0,120}?AccountKey=[A-Za-z0-9+/=]{40,}",
            re.IGNORECASE,
        ),
        0.99,
        gate="accountkey=",
    ),
    Detector(
        "azure_sas_token",
        SensitivityLabel.SECRET,
        # A shared access signature is identified by its `sig=` parameter
        # alongside the signed-version and signed-permissions parameters.
        re.compile(
            r"\bsv=\d{4}-\d{2}-\d{2}[^\s]{0,200}?[?&]sig=[A-Za-z0-9%+/=]{20,}",
            re.IGNORECASE,
        ),
        0.96,
        gate="sig=",
    ),
    Detector(
        "gcp_service_account_key",
        SensitivityLabel.SECRET,
        re.compile(
            r"\"type\"\s*:\s*\"service_account\"",
            re.IGNORECASE,
        ),
        0.97,
        gate="service_account",
    ),
    Detector(
        "aws_secret_access_key_context",
        SensitivityLabel.SECRET,
        # The 40-character secret, as distinct from the AKIA access key id the
        # existing detector covers. Context-gated because forty base64
        # characters on their own are not distinctive.
        re.compile(
            r"\baws_secret_access_key\b\s*[:=]\s*[\"']?[A-Za-z0-9/+=]{40}\b",
            re.IGNORECASE,
        ),
        0.97,
    ),
    Detector(
        "vault_token",
        SensitivityLabel.SECRET,
        re.compile(r"\bhvs\.[A-Za-z0-9_-]{24,}"),
        0.97,
        gate="hvs.",
    ),
    Detector(
        "twilio_api_key",
        SensitivityLabel.SECRET,
        re.compile(r"\b(?:AC|SK)[0-9a-f]{32}\b"),
        0.95,
    ),
    Detector(
        "databricks_token",
        SensitivityLabel.SECRET,
        re.compile(r"\bdapi[0-9a-f]{32}\b"),
        0.97,
        gate="dapi",
    ),
    Detector(
        "shopify_access_token",
        SensitivityLabel.SECRET,
        re.compile(r"\bshp(?:at|ca|pa|ss)_[0-9a-fA-F]{32}\b"),
        0.98,
        gate="shp",
    ),
    Detector(
        "square_access_token",
        SensitivityLabel.SECRET,
        re.compile(r"\b(?:sq0atp|sq0csp|EAAA)[A-Za-z0-9_-]{22,}\b"),
        0.96,
    ),
    Detector(
        "atlassian_api_token",
        SensitivityLabel.SECRET,
        re.compile(r"\bATATT3[A-Za-z0-9_\-=]{20,}"),
        0.97,
        gate="atatt3",
    ),
    Detector(
        "notion_token",
        SensitivityLabel.SECRET,
        re.compile(r"\b(?:secret_[A-Za-z0-9]{43}|ntn_[A-Za-z0-9]{40,})\b"),
        0.96,
    ),
    Detector(
        "figma_token",
        SensitivityLabel.SECRET,
        re.compile(r"\bfigd_[A-Za-z0-9_-]{40,}\b"),
        0.97,
        gate="figd_",
    ),
    Detector(
        "linear_api_key",
        SensitivityLabel.SECRET,
        re.compile(r"\blin_api_[A-Za-z0-9]{40}\b"),
        0.98,
        gate="lin_api_",
    ),
    Detector(
        "mailgun_api_key",
        SensitivityLabel.SECRET,
        re.compile(r"\bkey-[0-9a-f]{32}\b"),
        0.94,
        gate="key-",
    ),
    Detector(
        "datadog_api_key_context",
        SensitivityLabel.SECRET,
        re.compile(
            r"\b(?:dd_api_key|datadog_api_key|DD_API_KEY)\b\s*[:=]\s*[\"']?[0-9a-f]{32}\b",
            re.IGNORECASE,
        ),
        0.96,
    ),
    Detector(
        "cloudflare_api_token_context",
        SensitivityLabel.SECRET,
        re.compile(
            r"\b(?:cloudflare|cf)_api_token\b\s*[:=]\s*[\"']?[A-Za-z0-9_-]{40}\b",
            re.IGNORECASE,
        ),
        0.95,
    ),
    Detector(
        "jwt",
        SensitivityLabel.SECRET,
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
        ),
        0.85,
        gate="eyj",
    ),
    # ── Platform API keys and service tokens ─────────────────────────────────
    Detector(
        "stripe_api_key",
        SensitivityLabel.SECRET,
        re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}\b"),
        0.97,
    ),
    Detector(
        "anthropic_api_key",
        SensitivityLabel.SECRET,
        re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{60,}\b"),
        0.97,
        gate="sk-ant-",
    ),
    Detector(
        "huggingface_token",
        SensitivityLabel.SECRET,
        re.compile(r"\bhf_[A-Za-z0-9]{34,}\b"),
        0.95,
        gate="hf_",
    ),
    Detector(
        "sendgrid_api_key",
        SensitivityLabel.SECRET,
        re.compile(r"\bSG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{43,}\b"),
        0.96,
    ),
    Detector(
        "npm_token",
        SensitivityLabel.SECRET,
        re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
        0.95,
    ),
    Detector(
        "database_url_credentials",
        SensitivityLabel.SECRET,
        re.compile(
            r"\b(?:postgresql|postgres|mysql|mongodb(?:\+srv)?|redis|mssql|oracle)"
            r"://[A-Za-z0-9._%+\-]+:[^@\s/]{4,}@[A-Za-z0-9.\-]",
            re.I,
        ),
        0.96,
    ),
    Detector(
        "basic_auth_header",
        SensitivityLabel.SECRET,
        re.compile(
            r"\bAuthorization:\s*Basic\s+[A-Za-z0-9+/]{12,}={0,2}",
            re.I,
        ),
        0.90,
    ),
    # ── Cryptocurrency wallet addresses (financial identifiers) ─────────────
    # Distinctive fixed formats; no checksum validation so synthetic and real
    # addresses both match. Ethereum: 0x + 40 hex. Bitcoin/Litecoin: base58
    # (excludes 0/O/I/l) starting 1/3/L/M, plus bech32 (bc1.../ltc1...).
    Detector(
        "ethereum_address",
        SensitivityLabel.PCI,
        re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
        0.90,
    ),
    Detector(
        "btc_ltc_address",
        SensitivityLabel.PCI,
        re.compile(
            r"\b(?:[13LM][1-9A-HJ-NP-Za-km-z]{25,38}"
            r"|(?:bc1|ltc1)[ac-hj-np-z02-9]{11,71})\b"
        ),
        0.80,
    ),
    # ── User-agent strings ───────────────────────────────────────────────────
    # "Mozilla/5.0 (...)" / "Opera/x.y (...)" are unique to UA headers.
    Detector(
        "user_agent_string",
        SensitivityLabel.PII,
        re.compile(
            r"(?:Mozilla|Opera)/\d+\.\d+\s*\([^)\n]{0,200}\)"
            r"(?:[^\n]{0,40}?"
            r"(?:AppleWebKit|Gecko|Presto|Trident|Chrome|Chromium|Safari|"
            r"Firefox|Version|Edge|Edg|OPR|Mobile|CriOS|FxiOS)/[\w.]+){0,6}"
        ),
        0.80,
    ),
    # ── GPS coordinates: bracketed lat,long decimal pair ──────────────────────
    Detector(
        "gps_coordinate",
        SensitivityLabel.PII,
        re.compile(r"\[-?\d{1,3}\.\d{2,7},\s?-?\d{1,3}\.\d{2,7}\]"),
        0.80,
    ),
    # ── IMEI: dd-dddddd-dddddd-d grouping, or 15 digits after an IMEI label ──
    Detector(
        "imei_number",
        SensitivityLabel.PII,
        re.compile(r"\b\d{2}-\d{6}-\d{6}-\d\b|\bimei\b\D{0,10}\d{15}\b", re.I),
        0.88,
        # An IMEI carries a Luhn check digit, which this detector was not
        # using. Confidence raised because the checksum now rejects the
        # arbitrary 15-digit runs the unlabelled branch used to accept.
        validator=imei_ok,
    ),
    # ── Secondary address unit (Apt/Suite/Unit N) ────────────────────────────
    Detector(
        "secondary_address",
        SensitivityLabel.PII,
        re.compile(
            r"\b(?:apt|apartment|suite|ste|unit|bldg|building)\.?\s*#?\s*\d{1,5}\b",
            re.I,
        ),
        0.70,
    ),
    # ── County name ("Franklin County" / "County Londonderry") ───────────────
    Detector(
        "county_name",
        SensitivityLabel.PII,
        re.compile(r"\b(?:[A-Z][a-z]+\s+County|County\s+[A-Z][a-z]+)\b"),
        0.70,
    ),
    # ── ZIP+4 postal code (bare 5-digit is too broad and intentionally left) ─
    Detector(
        "zip_plus4",
        SensitivityLabel.PII,
        re.compile(r"\b\d{5}-\d{4}\b"),
        0.62,
    ),
    # ── SSN with space/dot separators (dashed form handled by us_ssn) ─────────
    Detector(
        "us_ssn_spaced",
        SensitivityLabel.PII,
        re.compile(r"\b(?!000|666|9\d\d)\d{3}[ .](?!00)\d{2}[ .](?!0000)\d{4}\b"),
        0.85,
    ),
    # ── SSN behind an explicit label, restricted to the area numbers ``us_ssn``
    # deliberately rejects (``000``/``666``/``9xx`` — never issued for *real*
    # SSNs).  Valid-area SSNs are already covered by ``us_ssn``; this detector
    # only recovers the otherwise-invalid ones when an SSN keyword makes the
    # intent explicit, so it neither double-counts valid SSNs nor fires on a
    # bare 9xx-xx-xxxx string. ─────────────────────────────────────────────────
    Detector(
        "us_ssn_context",
        SensitivityLabel.PII,
        re.compile(
            r"\b(?:ssn|social security(?:\s+(?:number|no\.?|#))?|soc\.?\s*sec\.?)\b"
            r"[^A-Za-z0-9]{0,12}(?:000|666|9\d\d)-\d{2}-\d{4}\b",
            re.I,
        ),
        0.90,
    ),
    # ── Payment card issuer (conservative vocabulary; ambiguous single words
    # such as "visa"/"discover"/"amex" are excluded to protect precision) ─────
    Detector(
        "credit_card_issuer",
        SensitivityLabel.PCI,
        re.compile(
            r"\b(?:mastercard|american[ _]express|diners[ _]club|maestro|"
            r"unionpay|union[ _]pay|jcb)\b",
            re.I,
        ),
        0.62,
    ),
    # ── Card-format numbers that fail Luhn (synthetic PANs) ───────────────────
    # 16 contiguous digits or 4x4 grouped. Masked forms such as
    # 411111******1111 are deliberately not matched: first-six/last-four
    # truncation is what PCI DSS asks stored PAN to become, so labelling it
    # PCI reported the compliant pattern as a violation. The platform's
    # representation analysis recognises it as truncated instead.
    Detector(
        "card_like_number",
        SensitivityLabel.PCI,
        re.compile(
            r"\b\d{16}\b"
            r"|\b\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}\b"
        ),
        0.62,
    ),
    # ── Vehicle Identification Number (17 chars, no I/O/Q, mixed alnum) ───────
    Detector(
        "vehicle_vin",
        SensitivityLabel.PII,
        re.compile(
            r"\b(?=[A-HJ-NPR-Z0-9]{17}\b)"
            r"(?=[A-HJ-NPR-Z0-9]*\d)(?=[A-HJ-NPR-Z0-9]*[A-Z])"
            r"[A-HJ-NPR-Z0-9]{17}\b"
        ),
        # Raised from 0.60: the ISO 3779 check digit at position 9 now has to
        # agree, which is what a 17-character alphanumeric run needs before it
        # can be called a VIN rather than a build hash or an order reference.
        0.88,
        validator=vin_ok,
    ),
    # ── UK vehicle registration mark (AA00AAA) ───────────────────────────────
    Detector(
        "vehicle_vrm",
        SensitivityLabel.PII,
        re.compile(r"\b[A-Z]{2}\d{2}[A-Z]{3}\b"),
        0.60,
    ),
    # ── Street name without a leading building number (curated safe suffixes) ─
    Detector(
        "street_name_context",
        SensitivityLabel.PII,
        re.compile(
            r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\s+"
            r"(?:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Court|Ct|"
            r"Boulevard|Blvd|Terrace|Ter|Parkway|Pkwy|Highway|Hwy)\.?\b"
        ),
        0.55,
    ),
    # ── International phone (requires leading +country code for precision) ────
    Detector(
        "intl_phone",
        SensitivityLabel.PII,
        re.compile(r"(?<!\w)\+\d{1,3}[-.\s]\d{1,4}(?:[-.\s]\d{2,4}){1,4}\b"),
        0.65,
    ),
    # ── Age expressed as "N years old" / "N y/o" ─────────────────────────────
    Detector(
        "age_context",
        SensitivityLabel.PII,
        re.compile(
            r"\b\d{1,3}[\s-]?(?:years?[\s-]?old|yrs?[\s-]?old|y[/.]?o)\b",
            re.I,
        ),
        0.60,
    ),
    # ── Username handles (First_Last, First.Last, or Name+digits) ────────────
    Detector(
        "username_handle",
        SensitivityLabel.PII,
        re.compile(r"\b[A-Z][a-z]+[._][A-Z][a-z]+\b|\b[A-Z][a-z]{2,}\d{2,4}\b"),
        0.50,
    ),
]


class RegexClassifier(Classifier):
    name = "regex"

    def __init__(self, detectors: list[Detector] | None = None, fast: bool = False):
        self.detectors = detectors or DETECTORS
        # ``fast`` enables an early exit once the highest-priority label
        # (SECRET) has fired: the document-level verdict cannot get any
        # stronger, so remaining detectors are skipped.  This trades away
        # completeness of the ``spans``/``detectors`` lists, so it is OFF by
        # default — callers that need every span (redaction, chunk-boundary
        # straddle detection) must leave it disabled.
        self.fast = fast

    def classify(self, text: str | None) -> Classification:
        if not text:
            return Classification(SensitivityLabel.NONE, 0.0)

        fired: list[str] = []
        spans: list[dict] = []
        best_label = SensitivityLabel.NONE
        best_conf = 0.0
        lowered: str | None = None  # lazily computed for gate pre-screening

        for det in self.detectors:
            if det.gate is not None:
                if lowered is None:
                    lowered = text.lower()
                if isinstance(det.gate, str):
                    if det.gate not in lowered:
                        continue
                elif not any(anchor in lowered for anchor in det.gate):
                    continue
            for m in det.pattern.finditer(text):
                matched = m.group(0)
                if det.validator and not det.validator(matched):
                    continue
                fired.append(det.name)
                spans.append(
                    {
                        "detector": det.name,
                        "label": det.label.value,
                        "start": m.start(),
                        "end": m.end(),
                        # store only a redacted preview, never the raw secret
                        "preview": _redact(matched),
                        **({"qualifier": det.qualifier} if det.qualifier else {}),
                    }
                )
                if LABEL_PRIORITY[det.label] > LABEL_PRIORITY[best_label] or (
                    det.label == best_label and det.confidence > best_conf
                ):
                    best_label = det.label
                    best_conf = det.confidence
            if self.fast and LABEL_PRIORITY[best_label] >= _MAX_PRIORITY:
                break

        if not fired:
            return Classification(SensitivityLabel.NONE, 0.0)
        return Classification(
            label=best_label,
            confidence=best_conf,
            detectors=sorted(set(fired)),
            spans=spans,
        )


def _redact(s: str) -> str:
    if len(s) <= 4:
        return "*" * len(s)
    return s[:2] + "*" * (len(s) - 4) + s[-2:]


_default = RegexClassifier()


def classify_text(text: str | None) -> Classification:
    """Convenience wrapper using the default detector set."""
    return _default.classify(text)
