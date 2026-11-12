"""Terminal output shared by the ``vecshield`` and ``vecshield-platform`` CLIs.

One Rich theme, one severity palette, and the Windows encoding guard. On
Windows, redirected or piped output falls back to the ANSI code page (cp1252),
which cannot encode glyphs such as a check mark; printing one would raise
``UnicodeEncodeError`` part-way through a command. ``prepare_stdio`` makes such
a stream substitute instead of fail, and ``glyph`` picks an ASCII stand-in when
the stream cannot carry the symbol.
"""

from __future__ import annotations

import codecs
import sys
from typing import TextIO

from rich.console import Console
from rich.theme import Theme

from vecshield.models import Severity

THEME = Theme({
    "ok": "green",
    "warn": "yellow",
    "alert": "bold yellow",
    "bad": "red",
    "error": "bold red",
    "info": "cyan",
    "muted": "dim",
    "sev.critical": "bold white on red",
    "sev.high": "bold red",
    "sev.medium": "yellow",
    "sev.low": "cyan",
    "sev.info": "dim",
})

SEV_STYLE: dict[Severity, str] = {sev: f"sev.{sev.value}" for sev in Severity}

# name -> (symbol, ASCII stand-in)
_GLYPHS = {
    "ok": ("✓", "OK"),
    "fail": ("✗", "X"),
    "warn": ("⚠", "!"),
    "arrow": ("→", "->"),
    "approx": ("≈", "~"),
}


def _is_utf8(encoding: str | None) -> bool:
    try:
        return codecs.lookup(encoding or "").name == "utf-8"
    except LookupError:
        return False


def prepare_stdio() -> None:
    """Make stdout/stderr replace unencodable characters instead of raising.

    The encoding itself is kept, so a consumer reading the code page it expects
    sees no mojibake. Idempotent, and a no-op for UTF-8 or non-reconfigurable
    streams (such as test runners' capture buffers)."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None or _is_utf8(getattr(stream, "encoding", None)):
            continue
        try:
            reconfigure(errors="replace")
        except (ValueError, OSError):
            pass


def glyph(name: str, stream: TextIO | None = None) -> str:
    """The symbol ``name``, or its ASCII stand-in if ``stream`` cannot encode it."""
    symbol, fallback = _GLYPHS[name]
    encoding = getattr(stream or sys.stdout, "encoding", None) or "ascii"
    try:
        symbol.encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return fallback
    return symbol


def make_console(*, stderr: bool = False) -> Console:
    """A themed console that writes to whatever ``sys.stdout``/``sys.stderr`` is
    at print time, so test runners that swap the streams still capture it."""
    return Console(theme=THEME, stderr=stderr)
