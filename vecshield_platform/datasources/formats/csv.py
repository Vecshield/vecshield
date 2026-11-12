"""CSV/TSV reader. Header auto-detect; configurable text column.

With `text_field` set, that column is the record text and remaining columns are
metadata. Without it, all columns are joined as `key: value` lines so contextual
detectors (e.g. `ssn: 123-45-6789`) still fire.
"""

from __future__ import annotations

import csv as _csv
import io
from typing import Iterator, Optional


def read_records(
    data: bytes, *, text_field: Optional[str] = None
) -> Iterator[tuple[str, dict]]:
    text = data.decode("utf-8", "replace")
    sample = text[:4096]
    delimiter = "\t" if sample.count("\t") > sample.count(",") else ","
    reader = _csv.DictReader(io.StringIO(text), delimiter=delimiter)
    for row in reader:
        row = {k: (v if v is not None else "") for k, v in row.items() if k is not None}
        if text_field is not None and text_field in row:
            yield str(row.get(text_field, "")), {k: v for k, v in row.items()
                                                 if k != text_field}
        else:
            joined = "\n".join(f"{k}: {v}" for k, v in row.items())
            yield joined, dict(row)
