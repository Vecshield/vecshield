"""HuggingFace Hub datasets source. Configurable split + text field.

`datasets` imported lazily. One DatasetInfo per loaded split; iter_records
streams rows. A single HF dataset name maps to a DataSourceStore whose datasets
are its splits (train/test/validation).
"""

from __future__ import annotations

import logging
from typing import Iterator, Optional

from vecshield_platform.datasources.base import DataSource
from vecshield.models import Chunk, DataSourceStore, DatasetInfo

logger = logging.getLogger(__name__)

_PREFERRED = ("text", "content", "prompt", "completion", "instruction",
              "input", "output", "question", "answer")


class HuggingFaceDataSource(DataSource):
    kind = "huggingface"

    def __init__(self, *, dataset: str, split: Optional[str] = None,
                 text_field: Optional[str] = None,
                 config: Optional[str] = None,
                 token: Optional[str] = None,
                 streaming: bool = True, **_ignored):
        try:
            import datasets  # noqa: F401
        except ImportError as e:  # pragma: no cover
            raise ImportError("datasets not installed. "
                              "pip install 'vecshield[datasources]'") from e
        if not dataset:
            raise ValueError("huggingface datasource requires a dataset name")
        self._name = dataset
        self._split = split
        self._text_field = text_field
        self._config = config
        self._token = token
        self._streaming = streaming
        self._endpoint = f"hf://{dataset}" + (f":{split}" if split else "")

    def describe(self) -> DataSourceStore:
        return DataSourceStore(kind=self.kind, name=self._endpoint,
                               endpoint=self._endpoint,
                               datasets=self.list_datasets())

    def list_datasets(self) -> list[DatasetInfo]:
        # A configured split is the single dataset; otherwise enumerate splits.
        if self._split:
            return [DatasetInfo(name=self._split, format="huggingface")]
        try:
            from datasets import get_dataset_split_names
            splits = get_dataset_split_names(self._name, self._config, token=self._token)
        except Exception as e:  # pragma: no cover
            logger.warning(
                "could not enumerate splits for %s (%s); falling back to ['train']",
                self._name, e)
            splits = ["train"]
        return [DatasetInfo(name=s, format="huggingface") for s in splits]

    def iter_records(self, dataset: str, batch_size: int = 256) -> Iterator[Chunk]:
        from datasets import load_dataset
        split = dataset or self._split or "train"
        ds = load_dataset(self._name, self._config, split=split,
                          streaming=self._streaming, token=self._token)
        for i, row in enumerate(ds):
            text = self._row_text(row)
            meta = {k: v for k, v in row.items()
                    if self._text_field is None or k != self._text_field}
            meta["_source"] = self._endpoint
            meta["_dataset"] = split
            yield Chunk(id=f"{split}#{i}", collection=split, text=text,
                        embedding=None, metadata=_scalars(meta))

    def _row_text(self, row: dict) -> str:
        if self._text_field is not None:
            return str(row.get(self._text_field, "") or "")
        for key in _PREFERRED:
            if key in row and isinstance(row[key], str):
                return row[key]
        return "\n".join(str(v) for v in row.values() if isinstance(v, str))


def _scalars(meta: dict) -> dict:
    out = {}
    for k, v in meta.items():
        if isinstance(v, (str, int, float, bool)) or v is None:
            out[k] = v
        else:
            out[k] = str(v)[:200]
    return out
