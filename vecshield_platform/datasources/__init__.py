"""Data source registry.

Parallel to connectors/: resolves a DataSource class by kind and builds one with
only the kwargs it understands. Heavy SDKs (boto3, gcs, datasets) import lazily.
"""

from __future__ import annotations

from typing import Type

from vecshield_platform.datasources.base import DataSource, format_for

AVAILABLE = ("local", "s3", "gcs", "azure_blob", "huggingface")


def get_datasource(kind: str) -> Type[DataSource]:
    kind = kind.lower()
    if kind == "local":
        from vecshield_platform.datasources.local import LocalDataSource
        return LocalDataSource
    if kind == "s3":
        from vecshield_platform.datasources.s3 import S3DataSource
        return S3DataSource
    if kind == "gcs":
        from vecshield_platform.datasources.gcs import GCSDataSource
        return GCSDataSource
    if kind == "azure_blob":
        from vecshield_platform.datasources.azure_blob import AzureBlobDataSource
        return AzureBlobDataSource
    if kind == "huggingface":
        from vecshield_platform.datasources.huggingface import HuggingFaceDataSource
        return HuggingFaceDataSource
    raise ValueError(f"Unknown datasource kind: {kind!r}. "
                     f"Available: {', '.join(AVAILABLE)}")


def build_datasource(kind: str, **opts) -> DataSource:
    cls = get_datasource(kind)
    kind = kind.lower()
    if kind == "local":
        keys = ("path", "text_field", "format")
    elif kind == "s3":
        keys = ("bucket", "prefix", "region", "aws_access_key_id",
                "aws_secret_access_key", "text_field", "format")
    elif kind == "gcs":
        keys = ("bucket", "prefix", "project", "credentials_json",
                "text_field", "format")
    elif kind == "azure_blob":
        keys = ("container", "prefix", "connection_string", "account_url",
                "credential", "text_field", "format")
    elif kind == "huggingface":
        keys = ("dataset", "split", "text_field", "config", "token", "streaming")
    else:  # pragma: no cover
        keys = ()
    kwargs = {k: opts[k] for k in keys if opts.get(k) is not None}
    return cls(**kwargs)


__all__ = ["DataSource", "get_datasource", "build_datasource", "AVAILABLE",
           "format_for"]
