"""Plain text / Markdown reader. Paragraph-chunked.

Splits on blank lines so each emitted record is one paragraph — small enough to
locate PII precisely, large enough to preserve context for NER. text_field is
ignored (no structure).
"""

from __future__ import annotations

import re
from typing import Iterator, Optional

_PARA_SPLIT = re.compile(r"\n\s*\n")


def read_records(
    data: bytes, *, text_field: Optional[str] = None
) -> Iterator[tuple[str, dict]]:
    text = data.decode("utf-8", "replace")
    paragraphs = [p.strip() for p in _PARA_SPLIT.split(text)]
    for i, para in enumerate(paragraphs):
        if para:
            yield para, {"paragraph": i}
