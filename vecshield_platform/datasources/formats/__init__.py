"""Format readers: turn raw bytes/streams into (text, metadata) records.

Every reader exposes `read_records(data: bytes, *, text_field=None) ->
Iterator[tuple[str, dict]]`. The data-source layer (local/s3/gcs/...) is
responsible for fetching bytes; readers are pure parsers with no I/O of their
own, which keeps them trivially testable.
"""

from __future__ import annotations

from typing import Iterator, Optional

from vecshield_platform.datasources.formats import csv as _csv
from vecshield_platform.datasources.formats import jsonl as _jsonl
from vecshield_platform.datasources.formats import parquet as _parquet
from vecshield_platform.datasources.formats import pdf as _pdf
from vecshield_platform.datasources.formats import text as _text

_READERS = {
    "jsonl": _jsonl.read_records,
    "csv": _csv.read_records,
    "parquet": _parquet.read_records,
    "text": _text.read_records,
    "pdf": _pdf.read_records,
    # A HuggingFace row is a JSON object, so its byte representation is JSONL.
    # HuggingFaceDataSource streams rows via the `datasets` library and does not
    # normally reach here, but registering the reader closes the latent trap
    # where a "huggingface"-formatted DatasetInfo would raise "no reader".
    "huggingface": _jsonl.read_records,
}


def read_records(
    fmt: str, data: bytes, *, text_field: Optional[str] = None
) -> Iterator[tuple[str, dict]]:
    """Dispatch to the reader for `fmt`. Raises ValueError on unknown format."""
    reader = _READERS.get(fmt)
    if reader is None:
        raise ValueError(f"no reader for format: {fmt!r}")
    return reader(data, text_field=text_field)


__all__ = ["read_records"]
