"""Find and mask credentials embedded in connection strings.

Store display names (``describe().name``/``endpoint``) are persisted on every
finding and shown to every console role, and stored connector config is
readable by viewers. Both are built from the same ``uri``/``url``/DSN values an
admin enters, and those values can carry a password. This module is the one
place that knows where a credential sits inside such a string:

* URL userinfo: ``scheme://user:PASSWORD@host`` — the *last* ``@`` ends the
  userinfo, so a password containing ``@``, ``/``, ``?`` or ``#`` is masked
  whole rather than half-parsed;
* password-like query parameters: ``?password=…``, ``?api_key=…``,
  ``?authMechanismProperties=…`` (MongoDB AWS session tokens) and similar;
* libpq keyword DSNs: ``host=db user=svc password=… sslpassword=…``, quoted or
  not.

A string without a credential comes back byte for byte, so finding
fingerprints keyed on a credential-free store name do not change. The helper
over-masks rather than under-masks: an ``@`` inside a URL path is read as
ending the userinfo.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import unquote

MASK = "***"

_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://")

#: Query-parameter / keyword names whose value is a credential.
_SECRET_PARAM_NAMES = frozenset({
    "password", "pass", "passwd", "pwd", "sslpassword", "secret", "token",
    "apikey", "api_key", "api-key", "x-api-key", "access_token", "auth_token",
    "access_key", "secret_key", "client_secret", "sig", "signature",
    "authmechanismproperties", "sas", "sastoken", "sas_token",
})
_SECRET_PARAM_PARTS = ("password", "secret", "token", "api_key", "apikey", "passwd")

# libpq keyword/value pair: key = 'quoted \' value' | bare-value
_KEYWORD_PAIR = re.compile(
    r"(?P<key>[A-Za-z_][A-Za-z0-9_\-]*)\s*=\s*"
    r"(?P<value>'(?:[^'\\]|\\.)*'|[^\s']*)")


def _is_secret_param(name: str) -> bool:
    lk = unquote(name).strip().lower()
    return lk in _SECRET_PARAM_NAMES or any(p in lk for p in _SECRET_PARAM_PARTS)


def _url_spans(value: str, start: int) -> list[tuple[int, int]]:
    """Credential spans in ``value[start:]`` (the part after ``scheme://``)."""
    spans: list[tuple[int, int]] = []
    rest = value[start:]
    host_from = start
    at = rest.rfind("@")
    if at >= 0:
        userinfo = rest[:at]
        colon = userinfo.find(":")
        if colon >= 0:
            spans.append((start + colon + 1, start + at))
        host_from = start + at + 1
    q = value.find("?", host_from)
    if q < 0:
        return spans
    end = value.find("#", q)
    end = len(value) if end < 0 else end
    pos = q + 1
    while pos <= end:
        nxt = end
        for sep in ("&", ";"):
            i = value.find(sep, pos, end)
            if 0 <= i < nxt:
                nxt = i
        pair = value[pos:nxt]
        eq = pair.find("=")
        if eq > 0 and _is_secret_param(pair[:eq]) and eq + 1 < len(pair):
            spans.append((pos + eq + 1, nxt))
        pos = nxt + 1
    return spans


def _keyword_spans(value: str) -> list[tuple[int, int]]:
    if "=" not in value:
        return []
    return [m.span("value") for m in _KEYWORD_PAIR.finditer(value)
            if _is_secret_param(m.group("key")) and m.group("value")]


def credential_spans(value: Any) -> list[tuple[int, int]]:
    """``(start, end)`` of each credential inside a connection string."""
    if not isinstance(value, str) or not value:
        return []
    m = _SCHEME.match(value)
    if m:
        return _url_spans(value, m.end())
    return _keyword_spans(value)


def embedded_credentials(value: Any) -> list[str]:
    """The credential values found inside ``value`` (``"***"`` when masked)."""
    return [value[a:b] for a, b in credential_spans(value)]


def redact_credentials(value: Any, mask: str = MASK) -> Any:
    """``value`` with every embedded credential replaced by ``mask``.

    Non-strings are returned unchanged, and so is a string with nothing to
    mask (byte for byte).
    """
    spans = credential_spans(value)
    if not spans:
        return value
    out, last = [], 0
    for a, b in sorted(spans):
        out.append(value[last:a])
        out.append(mask)
        last = b
    out.append(value[last:])
    return "".join(out)
