"""JSON Lines reader. One record per line; configurable text field selector.

If `text_field` is given, that field is the record text and the rest becomes
metadata. Otherwise the reader concatenates all string-valued fields (common
fields like 'text'/'content'/'prompt'/'completion' first), which makes it work
on heterogeneous instruction-tuning datasets without configuration.
"""

from __future__ import annotations

import json
from collections.abc import Iterator

_PREFERRED = (
    "text",
    "content",
    "body",
    "prompt",
    "completion",
    "input",
    "output",
    "instruction",
    "response",
    "question",
    "answer",
)


def read_records(
    data: bytes, *, text_field: str | None = None
) -> Iterator[tuple[str, dict]]:
    for line in data.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            # not valid JSON — scan the raw line as text so nothing is missed
            yield (
                line.decode("utf-8", "replace") if isinstance(line, bytes) else line,
                {},
            )
            continue
        if not isinstance(obj, dict):
            yield str(obj), {}
            continue
        text = _extract_text(obj, text_field)
        meta = (
            {k: v for k, v in obj.items() if k != text_field}
            if text_field
            else dict(obj)
        )
        yield text, meta


def _extract_text(obj: dict, text_field: str | None) -> str:
    if text_field is not None:
        return str(obj.get(text_field, "") or "")
    parts: list[str] = []
    for key in _PREFERRED:
        if key in obj and isinstance(obj[key], str):
            parts.append(obj[key])
    if parts:
        return "\n".join(parts)
    # fall back to every string-valued field
    return "\n".join(str(v) for v in obj.values() if isinstance(v, str))
