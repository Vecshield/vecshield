"""Local directory data source.

Walks a directory tree, treats each readable file as a dataset, and picks the
format reader by extension. The `dataset` argument to iter_records is the file
path relative to the root (as reported by list_datasets).
"""

from __future__ import annotations

import logging
import os
from typing import Iterator, Optional

from vecshield_platform.datasources.base import DataSource, format_for
from vecshield_platform.datasources.formats import read_records
from vecshield.models import Chunk, DataSourceStore, DatasetInfo

logger = logging.getLogger(__name__)


class LocalDataSource(DataSource):
    kind = "local"

    def __init__(self, *, path: str, text_field: Optional[str] = None,
                 format: Optional[str] = None, **_ignored):
        if not path or not os.path.isdir(path):
            raise ValueError(f"local datasource requires an existing directory: {path!r}")
        self._root = os.path.abspath(path)
        self._text_field = text_field
        self._format = format               # force a format, else auto-detect
        self._endpoint = f"file://{self._root}"

    def describe(self) -> DataSourceStore:
        return DataSourceStore(kind=self.kind, name=self._endpoint,
                               endpoint=self._endpoint,
                               datasets=self.list_datasets())

    def list_datasets(self) -> list[DatasetInfo]:
        out: list[DatasetInfo] = []
        for dirpath, _dirs, files in os.walk(self._root):
            for fn in sorted(files):
                if fn.startswith("."):
                    continue
                full = os.path.join(dirpath, fn)
                fmt = self._format or format_for(fn)
                if fmt == "unknown":
                    continue
                rel = os.path.relpath(full, self._root)
                try:
                    size = os.path.getsize(full)
                except OSError:
                    size = None
                out.append(DatasetInfo(name=rel, format=fmt, size_bytes=size))
        return out

    def iter_records(self, dataset: str, batch_size: int = 256) -> Iterator[Chunk]:
        full = os.path.abspath(os.path.join(self._root, dataset))
        # Containment: never read outside the configured root, even if a caller
        # passes an absolute path or one with '..' segments.
        if os.path.commonpath([self._root, full]) != self._root:
            raise ValueError(f"dataset path escapes source root: {dataset!r}")
        cap = self.max_object_bytes
        if cap is not None:
            try:
                size = os.path.getsize(full)
            except OSError:
                size = None
            if size is not None and size > cap:
                logger.warning(
                    "skipping oversized file %s (%d bytes > cap %d bytes)",
                    dataset, size, cap)
                return
        fmt = self._format or format_for(dataset)
        with open(full, "rb") as f:
            data = f.read()
        for i, (text, meta) in enumerate(
            read_records(fmt, data, text_field=self._text_field)
        ):
            meta = dict(meta)
            meta.setdefault("_source", self._endpoint)
            meta.setdefault("_dataset", dataset)
            yield Chunk(id=f"{dataset}#{i}", collection=dataset, text=text,
                        embedding=None, metadata=meta)
