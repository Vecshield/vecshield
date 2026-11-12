"""Shared CLI output: theme, glyph fallbacks and the Windows encoding guard."""

from __future__ import annotations

import io
import os
import subprocess
import sys

from vecshield.cli_output import SEV_STYLE, THEME, glyph, make_console, prepare_stdio
from vecshield.models import Severity


def _cp1252_stream() -> io.TextIOWrapper:
    # What Windows gives a redirected or piped stdout without UTF-8 mode.
    return io.TextIOWrapper(io.BytesIO(), encoding="cp1252")


def test_every_severity_has_a_theme_style():
    assert set(SEV_STYLE) == set(Severity)
    for style in SEV_STYLE.values():
        assert style in THEME.styles


def test_glyph_falls_back_to_ascii_when_the_stream_cannot_encode_it():
    stream = _cp1252_stream()
    assert glyph("ok", stream) == "OK"
    assert glyph("arrow", stream) == "->"
    assert glyph("ok", io.TextIOWrapper(io.BytesIO(), encoding="utf-8")) == "✓"


def test_prepare_stdio_turns_unencodable_output_into_replacements(monkeypatch):
    stdout, stderr = _cp1252_stream(), _cp1252_stream()
    monkeypatch.setattr(sys, "stdout", stdout)
    monkeypatch.setattr(sys, "stderr", stderr)
    prepare_stdio()
    prepare_stdio()  # idempotent
    console = make_console()
    console.print("[ok]✓ done[/] ⚠ ✗ → ≈ — …")
    make_console(stderr=True).print("✗ failed")
    stdout.flush()
    stderr.flush()
    assert b"done" in stdout.buffer.getvalue()
    assert b"failed" in stderr.buffer.getvalue()


def test_prepare_stdio_ignores_streams_it_cannot_reconfigure(monkeypatch):
    monkeypatch.setattr(sys, "stdout", io.StringIO())
    prepare_stdio()


def test_cli_survives_a_cp1252_pipe():
    env = {**os.environ, "PYTHONIOENCODING": "cp1252", "PYTHONUTF8": "0"}
    proc = subprocess.run(
        [sys.executable, "-c", "from vecshield.cli import cli; cli()",
         "detect", "the otter swam happily", "--no-nlp"],
        capture_output=True, env=env, timeout=120, check=False)
    assert proc.returncode == 0, proc.stderr.decode("cp1252", "replace")
    assert b"No PII detected" in proc.stdout
    assert b"Traceback" not in proc.stderr
