"""Parquet reader via pyarrow. Reads row batches; row -> (text, metadata).

pyarrow imported lazily so the rest of VecShield works without it. Same
text-field / join-all semantics as the CSV reader.
"""

from __future__ import annotations

import io
from collections.abc import Iterator


def read_records(
    data: bytes, *, text_field: str | None = None
) -> Iterator[tuple[str, dict]]:
    try:
        import pyarrow.parquet as pq
    except ImportError as e:  # pragma: no cover
        raise ImportError(
            "pyarrow not installed. pip install 'vecshield[datasources_hf]'"
        ) from e

    table = pq.read_table(io.BytesIO(data))
    for batch in table.to_batches():
        rows = batch.to_pylist()
        for row in rows:
            if text_field is not None and text_field in row:
                text = str(row.get(text_field, "") or "")
                meta = {k: v for k, v in row.items() if k != text_field}
                yield text, meta
            else:
                parts = [f"{k}: {v}" for k, v in row.items() if v is not None]
                yield "\n".join(parts), dict(row)
