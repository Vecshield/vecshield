"""Local directory data source.

Walks a directory tree, treats each readable file as a dataset, and picks the
format reader by extension. The `dataset` argument to iter_records is the file
path relative to the root (as reported by list_datasets).
"""

from __future__ import annotations

import os
from collections.abc import Iterator

from vecshield.datasources.base import DataSource, format_for
from vecshield.datasources.formats import read_records
from vecshield.models import Chunk, DatasetInfo, DataSourceStore


class LocalDataSource(DataSource):
    kind = "local"

    def __init__(
        self,
        *,
        path: str,
        text_field: str | None = None,
        format: str | None = None,
        **_ignored,
    ):
        if not path or not os.path.isdir(path):
            raise ValueError(
                f"local datasource requires an existing directory: {path!r}"
            )
        self._root = os.path.abspath(path)
        self._text_field = text_field
        self._format = format  # force a format, else auto-detect
        self._endpoint = f"file://{self._root}"

    def describe(self) -> DataSourceStore:
        return DataSourceStore(
            kind=self.kind,
            name=self._endpoint,
            endpoint=self._endpoint,
            datasets=self.list_datasets(),
        )

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
        full = os.path.join(self._root, dataset)
        fmt = self._format or format_for(dataset)
        with open(full, "rb") as f:
            data = f.read()
        for i, (text, meta) in enumerate(
            read_records(fmt, data, text_field=self._text_field)
        ):
            meta = dict(meta)
            meta.setdefault("_source", self._endpoint)
            meta.setdefault("_dataset", dataset)
            yield Chunk(
                id=f"{dataset}#{i}",
                collection=dataset,
                text=text,
                embedding=None,
                metadata=meta,
            )
