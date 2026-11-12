"""Check-digit algorithms for national identifiers.

Kept apart from the detector table for two reasons. The table is already long
enough that a dozen more inline functions would bury the patterns, and these
are pure arithmetic over a string: no regex, no imports from the classifier,
and therefore trivially testable on their own.

Every function takes the raw matched text, strips separators itself, and
returns False rather than raising on anything it does not understand. A
validator that throws would take down a scan of a corpus it merely failed to
recognise, which is the opposite of what a precision filter is for.

Where a national scheme has no usable check digit the function says so in its
docstring and validates only what can honestly be validated (format and, where
the number embeds one, a real calendar date). Those are marked so nobody later
mistakes a format check for a checksum.
"""

from __future__ import annotations

import re
from datetime import date


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def _valid_date(day: int, month: int, year: int) -> bool:
    try:
        date(year, month, day)
    except ValueError:
        return False
    return True


# --------------------------------------------------------------------------- #
# France            NIR / numéro de sécurité sociale                           #
# --------------------------------------------------------------------------- #
def france_nir_ok(value: str) -> bool:
    """13 digits plus a 2-digit key, where key = 97 - (body mod 97).

    Corsica is the wrinkle: départements 2A and 2B are letters inside an
    otherwise numeric field, and the standard substitutes them for 19 and 18
    before the arithmetic.
    """
    raw = re.sub(r"[\s.-]", "", value).upper()
    m = re.search(r"([12]\d{4}(?:\d{2}|2[AB])\d{6})(\d{2})$", raw)
    if not m:
        return False
    body, key = m.group(1), int(m.group(2))
    body = body.replace("2A", "19").replace("2B", "18")
    if not body.isdigit():
        return False
    return key == 97 - (int(body) % 97)


# --------------------------------------------------------------------------- #
# Poland            PESEL                                                      #
# --------------------------------------------------------------------------- #
def poland_pesel_ok(value: str) -> bool:
    """11 digits, weights 1-3-7-9 repeating, and an embedded birth date.

    The month field encodes the century by adding 20, 40, 60 or 80, which is
    why the month is taken modulo 20 before the date is checked.
    """
    d = _digits(value)
    if len(d) != 11:
        return False
    weights = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)
    total = sum(int(c) * w for c, w in zip(d[:10], weights))
    if (10 - total % 10) % 10 != int(d[10]):
        return False
    month_field = int(d[2:4])
    century = {0: 1900, 20: 2000, 40: 2100, 60: 2200, 80: 1800}.get(
        month_field - (month_field % 20)
    )
    if century is None:
        return False
    return _valid_date(int(d[4:6]), month_field % 20, century + int(d[:2]))


# --------------------------------------------------------------------------- #
# Germany           Steuerliche Identifikationsnummer                          #
# --------------------------------------------------------------------------- #
def germany_steuer_id_ok(value: str) -> bool:
    """11 digits, ISO 7064 MOD 11,10, and never leading with a zero."""
    d = _digits(value)
    if len(d) != 11 or d[0] == "0":
        return False
    product = 10
    for char in d[:10]:
        total = (int(char) + product) % 10 or 10
        product = (total * 2) % 11
    return (11 - product) % 10 == int(d[10])


# --------------------------------------------------------------------------- #
# Spain             DNI / NIE                                                  #
# --------------------------------------------------------------------------- #
_DNI_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"


def spain_dni_nie_ok(value: str) -> bool:
    """8 digits (DNI) or X/Y/Z plus 7 digits (NIE), then a letter from mod 23."""
    raw = re.sub(r"[\s-]", "", value).upper()
    m = re.search(r"([XYZ]?)(\d{7,8})([A-Z])$", raw)
    if not m:
        return False
    prefix, number, letter = m.groups()
    if prefix:
        if len(number) != 7:
            return False
        number = str("XYZ".index(prefix)) + number
    elif len(number) != 8:
        return False
    return _DNI_LETTERS[int(number) % 23] == letter


# --------------------------------------------------------------------------- #
# Sweden            personnummer                                               #
# --------------------------------------------------------------------------- #
def sweden_personnummer_ok(value: str) -> bool:
    """YYMMDD-NNNC with a Luhn check over the ten significant digits."""
    raw = _digits(value)
    if len(raw) == 12:  # written with century
        raw = raw[2:]
    if len(raw) != 10:
        return False
    if not _valid_date(int(raw[4:6]), int(raw[2:4]), 2000 + int(raw[:2])) and not (
        _valid_date(int(raw[4:6]), int(raw[2:4]), 1900 + int(raw[:2]))
    ):
        return False
    total = 0
    for i, char in enumerate(raw[:9]):
        n = int(char) * (2 if i % 2 == 0 else 1)
        total += n - 9 if n > 9 else n
    return (10 - total % 10) % 10 == int(raw[9])


# --------------------------------------------------------------------------- #
# Norway            fødselsnummer                                              #
# --------------------------------------------------------------------------- #
_NO_K1 = (3, 7, 6, 1, 8, 9, 4, 5, 2)
_NO_K2 = (5, 4, 3, 2, 7, 6, 5, 4, 3, 2)


def norway_fodselsnummer_ok(value: str) -> bool:
    """11 digits with two modulo-11 control digits."""
    d = _digits(value)
    if len(d) != 11:
        return False
    for weights, position in ((_NO_K1, 9), (_NO_K2, 10)):
        total = sum(int(c) * w for c, w in zip(d[:position], weights))
        control = 11 - total % 11
        control = 0 if control == 11 else control
        if control == 10 or control != int(d[position]):
            return False
    return True


# --------------------------------------------------------------------------- #
# Finland           henkilötunnus (HETU)                                       #
# --------------------------------------------------------------------------- #
_HETU_ALPHABET = "0123456789ABCDEFHJKLMNPRSTUVWXY"
_HETU_CENTURY = {"+": 1800, "-": 1900, "Y": 1900, "X": 1900, "W": 1900,
                 "V": 1900, "U": 1900, "A": 2000, "B": 2000, "C": 2000,
                 "D": 2000, "E": 2000, "F": 2000}


def finland_hetu_ok(value: str) -> bool:
    """DDMMYY, a century sign, a three-digit serial, then a base-31 check char."""
    raw = re.sub(r"\s", "", value).upper()
    m = re.search(r"(\d{6})([-+A-FUVWXY])(\d{3})([0-9A-Y])$", raw)
    if not m:
        return False
    born, sign, serial, check = m.groups()
    century = _HETU_CENTURY.get(sign)
    if century is None:
        return False
    if not _valid_date(int(born[:2]), int(born[2:4]), century + int(born[4:6])):
        return False
    return _HETU_ALPHABET[int(born + serial) % 31] == check


# --------------------------------------------------------------------------- #
# Denmark           CPR-nummer                                                 #
# --------------------------------------------------------------------------- #
def denmark_cpr_ok(value: str) -> bool:
    """FORMAT AND DATE ONLY -- this is deliberately not a checksum.

    CPR numbers carried a modulo-11 check until 2007, when the supply of
    compliant numbers ran out and the authority began issuing numbers that
    fail it. Validating the old checksum today would reject real, current
    identifiers, so only the embedded date is checked. Precision therefore
    rests on the detector's context gate rather than on this function, and the
    detector's confidence is set accordingly.
    """
    d = _digits(value)
    if len(d) != 10:
        return False
    day, month, year = int(d[:2]), int(d[2:4]), int(d[4:6])
    return _valid_date(day, month, 1900 + year) or _valid_date(day, month, 2000 + year)


# --------------------------------------------------------------------------- #
# Belgium           rijksregisternummer / numéro de registre national          #
# --------------------------------------------------------------------------- #
def belgium_rrn_ok(value: str) -> bool:
    """11 digits, modulo 97, with a 2000-or-later variant prefixed by a 2."""
    d = _digits(value)
    if len(d) != 11:
        return False
    body, check = d[:9], int(d[9:])
    return check == 97 - int(body) % 97 or check == 97 - int("2" + body) % 97


# --------------------------------------------------------------------------- #
# Ireland           PPS number                                                 #
# --------------------------------------------------------------------------- #
_PPSN_LETTERS = "WABCDEFGHIJKLMNOPQRSTUV"


def ireland_ppsn_ok(value: str) -> bool:
    """7 digits, a check letter from modulo 23, and an optional second letter."""
    raw = re.sub(r"[\s-]", "", value).upper()
    m = re.search(r"(\d{7})([A-W])([A-IW]?)$", raw)
    if not m:
        return False
    digits, check, second = m.groups()
    total = sum(int(c) * w for c, w in zip(digits, range(8, 1, -1)))
    # Numbers issued to a spouse or civil partner carry a second letter, whose
    # alphabetical position is weighted by 9 and added before the modulo. "W"
    # is the placeholder for "no second letter" and contributes nothing.
    if second and second != "W":
        total += (ord(second) - ord("A") + 1) * 9
    return _PPSN_LETTERS[total % 23] == check


# --------------------------------------------------------------------------- #
# Portugal          NIF                                                        #
# --------------------------------------------------------------------------- #
def portugal_nif_ok(value: str) -> bool:
    """9 digits, weights 9 down to 2, modulo 11."""
    d = _digits(value)
    if len(d) != 9 or d[0] == "0":
        return False
    total = sum(int(c) * w for c, w in zip(d[:8], range(9, 1, -1)))
    check = 11 - total % 11
    return (0 if check >= 10 else check) == int(d[8])


# --------------------------------------------------------------------------- #
# Greece            AMKA                                                       #
# --------------------------------------------------------------------------- #
def greece_amka_ok(value: str) -> bool:
    """11 digits, Luhn, with an embedded birth date in the first six."""
    d = _digits(value)
    if len(d) != 11:
        return False
    day, month, year = int(d[:2]), int(d[2:4]), int(d[4:6])
    if not (_valid_date(day, month, 1900 + year) or _valid_date(day, month, 2000 + year)):
        return False
    total = 0
    for i, char in enumerate(reversed(d)):
        n = int(char)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


# --------------------------------------------------------------------------- #
# Generic reusable checks for identifiers that already have detectors          #
# --------------------------------------------------------------------------- #
def imei_ok(value: str) -> bool:
    """IMEI carries a Luhn check digit; the existing detector did not use it."""
    d = _digits(value)
    if len(d) not in (15, 16):
        return False
    d = d[:15]
    total = 0
    for i, char in enumerate(reversed(d)):
        n = int(char)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


_VIN_TRANSLIT = {**{str(i): i for i in range(10)},
                 **{c: v for c, v in zip("ABCDEFGH", range(1, 9))},
                 **{c: v for c, v in zip("JKLMNP", [1, 2, 3, 4, 5, 7])},
                 "R": 9,
                 **{c: v for c, v in zip("STUVWXYZ", [2, 3, 4, 5, 6, 7, 8, 9])}}
_VIN_WEIGHTS = (8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2)


def vin_ok(value: str) -> bool:
    """ISO 3779 check digit at position 9. I, O and Q are never used in a VIN."""
    raw = re.sub(r"[\s-]", "", value).upper()
    if len(raw) != 17 or any(c in "IOQ" for c in raw):
        return False
    total = 0
    for char, weight in zip(raw, _VIN_WEIGHTS):
        if char not in _VIN_TRANSLIT:
            return False
        total += _VIN_TRANSLIT[char] * weight
    remainder = total % 11
    expected = "X" if remainder == 10 else str(remainder)
    return raw[8] == expected
