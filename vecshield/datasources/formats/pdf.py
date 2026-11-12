"""PDF text extraction via pdfminer.six. One record per page.

pdfminer imported lazily. Page-level granularity keeps findings locatable.
"""

from __future__ import annotations

import io
from collections.abc import Iterator


def read_records(
    data: bytes, *, text_field: str | None = None
) -> Iterator[tuple[str, dict]]:
    try:
        from pdfminer.high_level import extract_pages
        from pdfminer.layout import LTTextContainer
    except ImportError as e:  # pragma: no cover
        raise ImportError(
            "pdfminer.six not installed. pip install 'vecshield[datasources]'"
        ) from e

    for page_no, layout in enumerate(extract_pages(io.BytesIO(data))):
        parts = [el.get_text() for el in layout if isinstance(el, LTTextContainer)]
        page_text = "".join(parts).strip()
        if page_text:
            yield page_text, {"page": page_no}
