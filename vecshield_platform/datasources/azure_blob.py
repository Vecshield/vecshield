"""Azure Blob Storage data source. Prefix-scoped.

azure-storage-blob imported lazily. Auth via connection string (preferred) or
account_url + credential.
"""

from __future__ import annotations

from typing import Optional

from vecshield_platform.datasources._object import ObjectStoreDataSource


class AzureBlobDataSource(ObjectStoreDataSource):
    kind = "azure_blob"

    def __init__(self, *, container: str, prefix: str = "",
                 connection_string: Optional[str] = None,
                 account_url: Optional[str] = None,
                 credential: Optional[str] = None,
                 text_field: Optional[str] = None,
                 format: Optional[str] = None, **_ignored):
        try:
            from azure.storage.blob import BlobServiceClient
        except ImportError as e:  # pragma: no cover
            raise ImportError("azure-storage-blob not installed. "
                              "pip install 'vecshield[datasources]'") from e
        if not container:
            raise ValueError("azure_blob datasource requires a container")
        if connection_string:
            svc = BlobServiceClient.from_connection_string(connection_string)
        elif account_url:
            svc = BlobServiceClient(account_url=account_url, credential=credential)
        else:
            raise ValueError("azure_blob requires connection_string or account_url")
        self._container = svc.get_container_client(container)
        self._prefix = prefix
        self._text_field = text_field
        self._format = format
        self._endpoint = f"azure://{container}/{prefix}"

    def _list_blobs(self) -> list[tuple[str, Optional[int]]]:
        out: list[tuple[str, Optional[int]]] = []
        for blob in self._container.list_blobs(name_starts_with=self._prefix or None):
            name = blob.name if hasattr(blob, "name") else blob["name"]
            if name.endswith("/"):
                continue
            size = getattr(blob, "size", None)
            out.append((name, size))
        return out

    def _fetch(self, key: str) -> bytes:
        downloader = self._container.download_blob(key)
        return downloader.readall()
