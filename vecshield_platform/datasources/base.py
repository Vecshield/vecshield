"""DataSource interface.

A DataSource is to raw training/fine-tuning data what a Connector is to a vector
store: it discovers datasets and streams their records as normalized `Chunk`
objects, so the entire existing classify -> score -> findings pipeline runs
unchanged over object storage.

Read-only by design. Sources never mutate the underlying data.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterator, Optional

from vecshield.models import Chunk, DataSourceStore, DatasetInfo

# Cap on how many bytes a single object/file may contain before it is skipped
# (with a warning) instead of being read whole into memory. Prevents OOM on
# pathologically large blobs. Streaming sources (e.g. HuggingFace) ignore it.
DEFAULT_MAX_OBJECT_BYTES = 256 * 1024 * 1024  # 256 MiB


class DataSource(ABC):
    """Base class for all raw-data sources (local dir, S3, GCS, Blob, HF)."""

    kind: str = "base"

    # File/object sources honor this cap; set to None to disable size limiting.
    max_object_bytes: Optional[int] = DEFAULT_MAX_OBJECT_BYTES

    @abstractmethod
    def describe(self) -> DataSourceStore:
        """Return source-level metadata and its datasets (without records)."""

    @abstractmethod
    def list_datasets(self) -> list[DatasetInfo]:
        """List datasets (files / tables / splits) under this source."""

    @abstractmethod
    def iter_records(self, dataset: str, batch_size: int = 256) -> Iterator[Chunk]:
        """Stream records from a dataset as Chunks (text + metadata, no vector)."""

    def close(self) -> None:  # optional cleanup hook
        pass

    def __enter__(self) -> "DataSource":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


# Extension -> format-name map, shared by every source that reads files.
EXT_FORMAT = {
    ".jsonl": "jsonl",
    ".ndjson": "jsonl",
    ".json": "jsonl",
    ".csv": "csv",
    ".tsv": "csv",
    ".parquet": "parquet",
    ".pq": "parquet",
    ".txt": "text",
    ".md": "text",
    ".markdown": "text",
    ".pdf": "pdf",
}


def format_for(name: str) -> str:
    """Pick a format reader by file extension. Returns 'unknown' if unmatched."""
    lower = name.lower()
    for ext, fmt in EXT_FORMAT.items():
        if lower.endswith(ext):
            return fmt
    return "unknown"
