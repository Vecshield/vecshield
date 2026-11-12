"""Structured logging for the VecShield platform.

A single place to configure the ``vecshield`` / ``vecshield_platform`` logger
trees. Library modules should obtain a logger with ``logging.getLogger(__name__)``
(or the :func:`get_logger` helper) and never install their own handlers — the
application entry point (the CLI ``serve`` command) calls :func:`configure_logging`
once, so embedding hosts keep full control of the root logger.

Configuration precedence (highest first): explicit arguments, then the
environment (``VECSHIELD_LOG_LEVEL`` / ``LOG_LEVEL`` for level,
``VECSHIELD_LOG_FORMAT=json|text`` for format). :func:`configure_logging` is
idempotent: it only ever touches the handler it installed itself, so repeated
calls (e.g. from tests) do not stack duplicate handlers or clobber a host's.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from typing import Optional, TextIO

# Both the ``vecshield`` library and this package emit records; we
# attach the same handler to both roots so a single call captures everything.
_ROOTS = ("vecshield", "vecshield_platform")
_HANDLER_FLAG = "_vecshield_handler"

# LogRecord attributes we never want to duplicate into the JSON payload.
_RESERVED = frozenset(vars(logging.makeLogRecord({})).keys()) | {
    "message",
    "asctime",
    "taskName",
}


class JsonFormatter(logging.Formatter):
    """Compact single-line JSON formatter suitable for log shippers.

    Emits ``ts``, ``level``, ``logger`` and ``message`` always, the formatted
    traceback under ``exc`` when present, plus any structured fields passed via
    ``logger.info(..., extra={...})``.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = value
        return json.dumps(payload, default=str)


def configure_logging(
    level: Optional[str] = None,
    *,
    json_format: Optional[bool] = None,
    stream: Optional[TextIO] = None,
) -> logging.Logger:
    """Install VecShield's log handler on the package logger roots.

    Args:
        level: Log level name (e.g. ``"INFO"``). Falls back to
            ``VECSHIELD_LOG_LEVEL`` / ``LOG_LEVEL`` then ``INFO``.
        json_format: Force JSON (``True``) or plain text (``False``) output.
            ``None`` (default) consults ``VECSHIELD_LOG_FORMAT``.
        stream: Target stream; defaults to ``sys.stderr`` so structured logs
            never pollute stdout data.

    Returns:
        The ``vecshield_platform`` logger.
    """
    resolved_level = (
        level
        or os.getenv("VECSHIELD_LOG_LEVEL")
        or os.getenv("LOG_LEVEL")
        or "INFO"
    ).upper()
    numeric_level = getattr(logging, resolved_level, logging.INFO)

    if json_format is None:
        json_format = os.getenv("VECSHIELD_LOG_FORMAT", "text").strip().lower() == "json"

    handler = logging.StreamHandler(stream or sys.stderr)
    setattr(handler, _HANDLER_FLAG, True)
    if json_format:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)-7s %(name)s: %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S%z",
            )
        )

    for root in _ROOTS:
        logger = logging.getLogger(root)
        logger.setLevel(numeric_level)
        # Remove only a handler we installed on a previous call — never touch
        # handlers the embedding host may have added.
        for existing in [h for h in logger.handlers if getattr(h, _HANDLER_FLAG, False)]:
            logger.removeHandler(existing)
        logger.addHandler(handler)
        logger.propagate = False

    return logging.getLogger("vecshield_platform")


def get_logger(name: str) -> logging.Logger:
    """Return a logger under the VecShield tree.

    Convenience wrapper so callers do not have to remember the root prefix; a
    fully-qualified module name (``vecshield_platform.foo``) is returned as-is.
    """
    if not name or name in _ROOTS:
        return logging.getLogger(name or "vecshield_platform")
    if any(name == root or name.startswith(root + ".") for root in _ROOTS):
        return logging.getLogger(name)
    return logging.getLogger(f"vecshield_platform.{name}")
