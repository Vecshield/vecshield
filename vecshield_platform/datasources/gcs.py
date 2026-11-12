"""Google Cloud Storage data source. Prefix-scoped.

google-cloud-storage imported lazily. credentials_json points at a service
account key file; omit to use Application Default Credentials.
"""

from __future__ import annotations

from typing import Optional

from vecshield_platform.datasources._object import ObjectStoreDataSource


class GCSDataSource(ObjectStoreDataSource):
    kind = "gcs"

    def __init__(self, *, bucket: str, prefix: str = "",
                 project: Optional[str] = None,
                 credentials_json: Optional[str] = None,
                 text_field: Optional[str] = None,
                 format: Optional[str] = None, **_ignored):
        try:
            from google.cloud import storage  # type: ignore
        except ImportError as e:  # pragma: no cover
            raise ImportError("google-cloud-storage not installed. "
                              "pip install 'vecshield[datasources]'") from e
        if not bucket:
            raise ValueError("gcs datasource requires a bucket")
        if credentials_json:
            self._client = storage.Client.from_service_account_json(
                credentials_json, project=project)
        else:
            self._client = storage.Client(project=project)
        self._bucket_name = bucket
        self._bucket = self._client.bucket(bucket)
        self._prefix = prefix
        self._text_field = text_field
        self._format = format
        self._endpoint = f"gs://{bucket}/{prefix}"

    def _list_blobs(self) -> list[tuple[str, Optional[int]]]:
        out: list[tuple[str, Optional[int]]] = []
        for blob in self._client.list_blobs(self._bucket_name, prefix=self._prefix):
            if blob.name.endswith("/"):
                continue
            out.append((blob.name, blob.size))
        return out

    def _fetch(self, key: str) -> bytes:
        return self._bucket.blob(key).download_as_bytes()
