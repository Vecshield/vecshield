"""Amazon Bedrock Knowledge Bases connector (inventory mode).

Bedrock KBs embed chunks into an underlying vector store (OpenSearch Serverless,
Aurora pgvector, Neptune, S3 Vectors). The Bedrock API exposes KB/data-source
*inventory* but not per-chunk enumeration or raw vectors — so this connector
discovers KBs and their backing store, and recommends scanning that store
directly (e.g. the `opensearch` or `pgvector` connector) for content-level
findings. boto3 imported lazily.

Credentials come from explicit keys (with an optional session token), a named
profile, or boto3's default chain. With no ``region``, boto3 resolves one from
the profile or environment; the Region actually listed is recorded on the
store and on every knowledge base, since knowledge bases are regional.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Callable, Iterator, Optional, TypeVar

from vecshield_platform.connectors.base import (
    AtRestObservation,
    Connector,
    ConnectorAuthError,
    ConnectorError,
    ConnectorNotFound,
    ConnectorTimeout,
    ConnectorUnavailable,
    ErrorRegistry,
    error_class_for_status,
    mask_reference,
    retry_read,
    translate_error,
)
from vecshield.models import Chunk, Collection, VectorStore

logger = logging.getLogger(__name__)

_T = TypeVar("_T")

#: botocore exceptions raised before a response exists, by class name.
_ERRORS: ErrorRegistry = {
    "NoCredentialsError": ConnectorAuthError,
    "PartialCredentialsError": ConnectorAuthError,
    "TokenRetrievalError": ConnectorAuthError,
    "UnauthorizedSSOTokenError": ConnectorAuthError,
    "SSOTokenLoadError": ConnectorAuthError,
    "ConnectTimeoutError": ConnectorTimeout,
    "ReadTimeoutError": ConnectorTimeout,
    "EndpointConnectionError": ConnectorUnavailable,
    "ConnectionClosedError": ConnectorUnavailable,
}

#: ClientError ``response["Error"]["Code"]`` values. Anything else falls back
#: to ``response["ResponseMetadata"]["HTTPStatusCode"]``.
_AWS_CODES: dict[str, type[ConnectorError]] = {
    "AccessDeniedException": ConnectorAuthError,
    "AccessDenied": ConnectorAuthError,
    "UnrecognizedClientException": ConnectorAuthError,
    "InvalidSignatureException": ConnectorAuthError,
    "ExpiredTokenException": ConnectorAuthError,
    "ExpiredToken": ConnectorAuthError,
    "InvalidClientTokenId": ConnectorAuthError,
    "ResourceNotFoundException": ConnectorNotFound,
    "ThrottlingException": ConnectorUnavailable,
    "TooManyRequestsException": ConnectorUnavailable,
    "ServiceUnavailableException": ConnectorUnavailable,
    "InternalServerException": ConnectorUnavailable,
    "RequestTimeout": ConnectorTimeout,
    "RequestTimeoutException": ConnectorTimeout,
}


def _translate(exc: BaseException) -> BaseException:
    """A botocore error as a connector error; the AWS error code, never the message."""
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        code = str((response.get("Error") or {}).get("Code") or "")
        status = (response.get("ResponseMetadata") or {}).get("HTTPStatusCode")
        target = _AWS_CODES.get(code) or error_class_for_status(status)
        if target is not None:
            message = f"bedrock_kb: {code or type(exc).__name__}"
            if status is not None:
                message += f" (status {status})"
            return target(message)
    return translate_error(exc, kind="bedrock_kb", extra=_ERRORS)


def _mapped(fn: Callable[[], _T]) -> Callable[[], _T]:
    """``fn`` with botocore errors translated, for use inside retry_read."""
    def call() -> _T:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - translated or re-raised as is
            translated = _translate(exc)
            if translated is exc:
                raise
            raise translated from exc
    return call


def _read(fn: Callable[[], _T]) -> _T:
    """An idempotent read, error-mapped and retried on transient failure."""
    return retry_read(_mapped(fn))


class BedrockKBConnector(Connector):
    kind = "bedrock_kb"
    content_enumerable = False  # inventory only: no per-chunk enumeration API

    def __init__(self, *, region: Optional[str] = None,
                 aws_access_key_id: Optional[str] = None,
                 aws_secret_access_key: Optional[str] = None,
                 aws_session_token: Optional[str] = None,
                 profile_name: Optional[str] = None, **_ignored):
        try:
            import boto3
        except ImportError as e:  # pragma: no cover
            raise ImportError("boto3 not installed. pip install 'vecshield[bedrock]'") from e
        session_kw: dict[str, Any] = {}
        if profile_name:
            session_kw["profile_name"] = profile_name
        if aws_access_key_id:
            session_kw.update(aws_access_key_id=aws_access_key_id,
                              aws_secret_access_key=aws_secret_access_key)
            if aws_session_token:
                session_kw["aws_session_token"] = aws_session_token
        if region:
            session_kw["region_name"] = region
        session = boto3.Session(**session_kw)
        self._c = session.client("bedrock-agent")
        resolved = getattr(getattr(self._c, "meta", None), "region_name", None) or region
        self._region: Optional[str] = resolved
        self._endpoint = f"bedrock-kb://{resolved or 'unknown-region'}"

    def capabilities(self) -> set[str]:
        # Inventory only: no chunk/vector enumeration via API. Data-source
        # encryption configuration is readable, so at-rest state is.
        return {"at_rest_introspection"}

    def describe(self) -> VectorStore:
        region = getattr(self, "_region", None)
        return VectorStore(kind=self.kind, name=self._endpoint, endpoint=self._endpoint,
                           collections=self.list_collections(),
                           metadata={"managed": True, "enumeration": "inventory_only",
                                     "regions_listed": [region] if region else []})

    def _summaries(self) -> Iterator[dict]:
        """Knowledge-base summaries, one page at a time, each page retried."""
        token: Optional[str] = None
        while True:
            kw = {"nextToken": token} if token else {}
            page = _read(lambda: self._c.list_knowledge_bases(**kw)) or {}
            yield from page.get("knowledgeBaseSummaries", []) or []
            token = page.get("nextToken")
            if not token:
                return

    def list_collections(self) -> list[Collection]:
        out = []
        region = getattr(self, "_region", None)
        for kb in self._summaries():
            kb_id = kb.get("knowledgeBaseId")
            name = f"{kb.get('name')} ({kb_id})"
            metadata: dict[str, Any] = {
                "knowledge_base_id": kb_id, "status": kb.get("status"),
                "region": region,
                # Bedrock has no chunk or vector count for a knowledge base:
                # zero here is never a count.
                "count_known": False,
            }
            try:
                detail = (_read(lambda: self._c.get_knowledge_base(knowledgeBaseId=kb_id))
                          or {}).get("knowledgeBase", {}) or {}
            except Exception as exc:  # noqa: BLE001 - recorded, never read as clean
                error = type(exc).__name__
                logger.debug("could not read knowledge base %s (%s)", kb_id, error)
                metadata.update(backing_store=None, knowledge_base_type=None,
                                backing_store_error=error)
                self._record_read_error(name, operation="get_knowledge_base",
                                        error_type=error,
                                        reason="the knowledge base configuration could "
                                               "not be read, so its type and backing "
                                               "store are unknown")
            else:
                config = detail.get("knowledgeBaseConfiguration") or {}
                storage = detail.get("storageConfiguration") or {}
                metadata.update(knowledge_base_type=config.get("type"),
                                backing_store=storage.get("type"))
            out.append(Collection(name=name, count=0, dimension=None, metadata=metadata))
        return out

    def iter_chunks(self, collection: str, batch_size: int = 256) -> Iterator[Chunk]:
        # Not enumerable via the Bedrock API — scan the backing store directly.
        return iter(())

    def at_rest_encryption_state(self, collection: Optional[str] = None) -> AtRestObservation:
        """Encryption at rest of a knowledge base's own storage, where Bedrock reports it.

        - A *managed* knowledge base stores vectors itself and names its KMS
          key in ``knowledgeBaseConfiguration.managedKnowledgeBaseConfiguration``.
          Present means enabled with a customer-managed key; absent means
          AWS's default key, which is documented, not reported.
        - A *custom* knowledge base keeps vectors in a backing store Bedrock
          does not describe. Only that store's type and ARN are recorded.

        Data-source ``serverSideEncryptionConfiguration.kmsKeyArn`` covers
        only transient ingestion storage. It is counted in evidence under that
        label and never yields ``enabled``. Nothing here yields ``disabled``.
        """
        source = ("knowledgeBase.knowledgeBaseConfiguration.managedKnowledgeBaseConfiguration"
                  ".serverSideEncryptionConfiguration")
        if collection is None:
            return AtRestObservation(
                state="not_observable", scope="store", source=source, per_collection=True,
                reason="each knowledge base has its own storage and is reported "
                       "separately")
        match = re.search(r"\(([^()]+)\)\s*$", collection)
        kb_id = match.group(1) if match else collection
        try:
            kb = (self._c.get_knowledge_base(knowledgeBaseId=kb_id) or {}).get(
                "knowledgeBase", {}) or {}
        except Exception as exc:  # noqa: BLE001
            return AtRestObservation(
                state="error", scope="collection", collection=collection, source=source,
                reason=f"the knowledge base could not be read ({type(exc).__name__})")
        evidence: dict = {"ingestion (transient) storage": self._ingestion_keys(kb_id)}
        # botocore's KnowledgeBase shape nests the managed configuration inside
        # knowledgeBaseConfiguration; tests hold this to the service model.
        config = kb.get("knowledgeBaseConfiguration") or {}
        kb_type = (config.get("type") or "").upper()
        evidence["knowledge_base_type"] = kb_type or None

        if kb_type == "MANAGED":
            managed = config.get("managedKnowledgeBaseConfiguration") or {}
            key = (managed.get("serverSideEncryptionConfiguration") or {}).get("kmsKeyArn")
            if key:
                return AtRestObservation(
                    state="enabled", scope="collection", collection=collection,
                    source=source,
                    mechanism="customer-managed KMS key (managed KB storage)",
                    key_reference=mask_reference(key), evidence=evidence,
                    reason="this managed knowledge base stores its data with a "
                           "customer-managed KMS key")
            return AtRestObservation(
                state="not_observable", scope="collection", collection=collection,
                source=source, evidence=evidence,
                reason="This managed knowledge base names no customer-managed KMS "
                       "key. AWS documents encryption with an AWS default key; that "
                       "is documented, not reported.",
                documented_default={
                    "text": "By default, Amazon Bedrock encrypts this data using an "
                            "AWS-owned key.",
                    "source_url": _KB_ENCRYPTION_DOC})

        storage = kb.get("storageConfiguration") or {}
        store_type = (storage.get("type") or "").upper() or None
        evidence["backing_store_type"] = store_type
        arn = _backing_store_arn(storage)
        if arn:
            evidence["backing_store_arn"] = arn
        backing = _ALWAYS_ENCRYPTED_BACKING.get(store_type or "")
        return AtRestObservation(
            state="not_observable", scope="collection", collection=collection,
            source="knowledgeBase.storageConfiguration", evidence=evidence,
            reason="Bedrock does not report how the backing vector store encrypts "
                   "data. Data-source keys cover only ingestion storage. Scan the "
                   "vector store with its own connector.",
            evidence_to_supply=[f"The encryption configuration of the backing "
                                f"{store_type or 'vector store'}, or a scan of it with "
                                "its own connector"],
            documented_default=({"text": f"{backing[0]} always encrypts at rest, per AWS.",
                                 "source_url": backing[1]} if backing else None))

    def _ingestion_keys(self, kb_id: str) -> dict:
        """Counts of data sources with a customer key for *transient* ingestion storage."""
        try:
            summaries: list[dict] = []
            token = None
            while True:
                kw = {"knowledgeBaseId": kb_id}
                if token:
                    kw["nextToken"] = token
                page = self._c.list_data_sources(**kw)
                summaries.extend(page.get("dataSourceSummaries", []) or [])
                token = page.get("nextToken")
                if not token:
                    break
            with_key = 0
            for summary in summaries:
                ds = self._c.get_data_source(knowledgeBaseId=kb_id,
                                             dataSourceId=summary.get("dataSourceId"))
                sse = (ds.get("dataSource") or {}).get("serverSideEncryptionConfiguration") or {}
                with_key += bool(sse.get("kmsKeyArn"))
        except Exception as exc:  # noqa: BLE001
            return {"error": type(exc).__name__}
        return {"data_sources": len(summaries), "with_customer_key": with_key}


_KB_ENCRYPTION_DOC = "https://docs.aws.amazon.com/bedrock/latest/userguide/encryption-kb.html"

#: Backing stores AWS documents as always encrypted at rest, each with the page
#: that says so. Context only, never a state.
_ALWAYS_ENCRYPTED_BACKING: dict[str, tuple[str, str]] = {
    "OPENSEARCH_SERVERLESS": (
        "Amazon OpenSearch Serverless",
        "https://docs.aws.amazon.com/opensearch-service/latest/developerguide/"
        "serverless-encryption.html"),
    "S3_VECTORS": (
        "Amazon S3 Vectors",
        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-vectors-data-encryption.html"),
    "NEPTUNE_ANALYTICS": (
        "Amazon Neptune Analytics",
        "https://docs.aws.amazon.com/prescriptive-guidance/latest/"
        "neptune-analytics-well-architected-framework/security-pillar.html"),
}


def _backing_store_arn(storage: dict) -> Optional[str]:
    """The backing store's resource ARN from a storageConfiguration, if named.

    ``credentialsSecretArn`` names a Secrets Manager secret and is never read.
    """
    for value in storage.values():
        if isinstance(value, dict):
            for key in ("collectionArn", "domainArn", "resourceArn", "graphArn",
                        "indexArn", "vectorBucketArn"):
                if value.get(key):
                    return str(value[key])
    return None
