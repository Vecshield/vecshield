"""AWS S3 data source. Prefix-scoped; paginated list + streaming read.

boto3 imported lazily. Credentials come from the standard AWS chain unless
explicit keys are passed (server-side registry only — never from API clients).
"""

from __future__ import annotations

from typing import Optional

from vecshield_platform.datasources._object import ObjectStoreDataSource


class S3DataSource(ObjectStoreDataSource):
    kind = "s3"

    def __init__(self, *, bucket: str, prefix: str = "",
                 region: Optional[str] = None,
                 aws_access_key_id: Optional[str] = None,
                 aws_secret_access_key: Optional[str] = None,
                 text_field: Optional[str] = None,
                 format: Optional[str] = None, **_ignored):
        try:
            import boto3
        except ImportError as e:  # pragma: no cover
            raise ImportError("boto3 not installed. "
                              "pip install 'vecshield[datasources]'") from e
        if not bucket:
            raise ValueError("s3 datasource requires a bucket")
        kw = {}
        if region:
            kw["region_name"] = region
        if aws_access_key_id:
            kw.update(aws_access_key_id=aws_access_key_id,
                      aws_secret_access_key=aws_secret_access_key)
        self._s3 = boto3.client("s3", **kw)
        self._bucket = bucket
        self._prefix = prefix
        self._text_field = text_field
        self._format = format
        self._endpoint = f"s3://{bucket}/{prefix}"

    def _list_blobs(self) -> list[tuple[str, Optional[int]]]:
        out: list[tuple[str, Optional[int]]] = []
        token = None
        while True:
            kw = {"Bucket": self._bucket, "Prefix": self._prefix}
            if token:
                kw["ContinuationToken"] = token
            resp = self._s3.list_objects_v2(**kw)
            for obj in resp.get("Contents", []):
                key = obj["Key"]
                if key.endswith("/"):
                    continue
                out.append((key, obj.get("Size")))
            if not resp.get("IsTruncated"):
                break
            token = resp.get("NextContinuationToken")
        return out

    def _fetch(self, key: str) -> bytes:
        resp = self._s3.get_object(Bucket=self._bucket, Key=key)
        return resp["Body"].read()
