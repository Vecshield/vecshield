"""Local data-source registry.

The `vecshield` library reads raw training/fine-tuning data and pre-embedding
chunks from the local filesystem.
"""

from __future__ import annotations

from vecshield.datasources.base import DataSource, format_for

AVAILABLE = ("local",)


def get_datasource(kind: str) -> type[DataSource]:
    kind = kind.lower()
    if kind == "local":
        from vecshield.datasources.local import LocalDataSource

        return LocalDataSource
    raise ValueError(
        f"Unknown datasource kind: {kind!r}. This package supports: "
        f"{', '.join(AVAILABLE)}. Stage remote data locally before scanning."
    )


def build_datasource(kind: str, **opts) -> DataSource:
    cls = get_datasource(kind)
    keys = ("path", "text_field", "format")
    kwargs = {k: opts[k] for k in keys if opts.get(k) is not None}
    return cls(**kwargs)


__all__ = [
    "DataSource",
    "get_datasource",
    "build_datasource",
    "AVAILABLE",
    "format_for",
]
