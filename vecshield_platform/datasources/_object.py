"""Shared logic for blob-store data sources (S3, GCS, Azure Blob).

Subclass implements three thin I/O hooks — `_list_blobs()`, `_blob_size(key)`,
`_fetch(key)` — and gets list_datasets/iter_records/describe for free. Keeps the
classify pipeline identical across clouds.
"""

from __future__ import annotations

import logging
from typing import Iterator, Optional

from vecshield_platform.datasources.base import DataSource, format_for
from vecshield_platform.datasources.formats import read_records
from vecshield.models import Chunk, DataSourceStore, DatasetInfo

logger = logging.getLogger(__name__)


class ObjectStoreDataSource(DataSource):
    kind = "object"

    # subclasses set these in __init__
    _endpoint: str = ""
    _text_field: Optional[str] = None
    _format: Optional[str] = None
    # Lazily-built {key: size_bytes} index, reused across iter_records calls so
    # the size cap check never re-lists the bucket per dataset.
    _size_index: Optional[dict] = None

    # ---- I/O hooks subclasses must implement ----
    def _list_blobs(self) -> list[tuple[str, Optional[int]]]:
        """Return (key, size_bytes|None) for every blob in scope."""
        raise NotImplementedError

    def _fetch(self, key: str) -> bytes:
        raise NotImplementedError

    def _blob_size(self, key: str) -> Optional[int]:
        """Best-effort object size for the cap check (None = unknown).

        Reuses the listing that ``list_datasets()`` already performs, cached on
        first use so ``iter_records`` doesn't re-list once per dataset.
        """
        if self._size_index is None:
            self._size_index = {k: s for k, s in self._list_blobs()}
        return self._size_index.get(key)

    # ---- shared behavior ----
    def describe(self) -> DataSourceStore:
        return DataSourceStore(kind=self.kind, name=self._endpoint,
                               endpoint=self._endpoint,
                               datasets=self.list_datasets())

    def list_datasets(self) -> list[DatasetInfo]:
        out: list[DatasetInfo] = []
        for key, size in self._list_blobs():
            fmt = self._format or format_for(key)
            if fmt == "unknown":
                continue
            out.append(DatasetInfo(name=key, format=fmt, size_bytes=size))
        return out

    def iter_records(self, dataset: str, batch_size: int = 256) -> Iterator[Chunk]:
        fmt = self._format or format_for(dataset)
        cap = self.max_object_bytes
        if cap is not None:
            size = self._blob_size(dataset)
            if size is not None and size > cap:
                logger.warning(
                    "skipping oversized object %s (%d bytes > cap %d bytes)",
                    dataset, size, cap)
                return
        data = self._fetch(dataset)
        for i, (text, meta) in enumerate(
            read_records(fmt, data, text_field=self._text_field)
        ):
            meta = dict(meta)
            meta.setdefault("_source", self._endpoint)
            meta.setdefault("_dataset", dataset)
            yield Chunk(id=f"{dataset}#{i}", collection=dataset, text=text,
                        embedding=None, metadata=meta)
