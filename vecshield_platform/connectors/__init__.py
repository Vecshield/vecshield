"""Connector registry."""

from __future__ import annotations

from typing import Type

from vecshield_platform.connectors.base import (
    AT_REST_STATES,
    AtRestObservation,
    Connector,
    ConnectorAuthError,
    ConnectorError,
    ConnectorNotFound,
    ConnectorTimeout,
    ConnectorUnavailable,
    RETRYABLE_ERRORS,
    UnsupportedCapability,
    retry_read,
)


AVAILABLE = ("chroma", "pgvector", "qdrant", "weaviate", "milvus", "pinecone",
             "redis", "opensearch", "mongodb", "openai", "azure_search",
             "bedrock_kb", "vertex_ai")


def get_connector(kind: str) -> Type[Connector]:
    """Resolve a connector class by kind. Imports lazily to avoid hard deps."""
    kind = kind.lower()
    if kind == "chroma":
        from vecshield_platform.connectors.chroma import ChromaConnector

        return ChromaConnector
    if kind == "pgvector":
        from vecshield_platform.connectors.pgvector import PgVectorConnector

        return PgVectorConnector
    if kind == "qdrant":
        from vecshield_platform.connectors.qdrant import QdrantConnector

        return QdrantConnector
    if kind == "weaviate":
        from vecshield_platform.connectors.weaviate import WeaviateConnector

        return WeaviateConnector
    if kind == "milvus":
        from vecshield_platform.connectors.milvus import MilvusConnector

        return MilvusConnector
    if kind == "pinecone":
        from vecshield_platform.connectors.pinecone import PineconeConnector

        return PineconeConnector
    if kind == "redis":
        from vecshield_platform.connectors.redis import RedisConnector

        return RedisConnector
    if kind == "opensearch":
        from vecshield_platform.connectors.opensearch import OpenSearchConnector

        return OpenSearchConnector
    if kind == "mongodb":
        from vecshield_platform.connectors.mongodb import MongoDBConnector

        return MongoDBConnector
    if kind == "openai":
        from vecshield_platform.connectors.openai_vs import OpenAIVectorStoreConnector

        return OpenAIVectorStoreConnector
    if kind == "azure_search":
        from vecshield_platform.connectors.azure_search import AzureSearchConnector

        return AzureSearchConnector
    if kind == "bedrock_kb":
        from vecshield_platform.connectors.bedrock_kb import BedrockKBConnector

        return BedrockKBConnector
    if kind == "vertex_ai":
        from vecshield_platform.connectors.vertex_ai import VertexAIConnector

        return VertexAIConnector
    raise ValueError(
        f"Unknown connector kind: {kind!r}. Available: {', '.join(AVAILABLE)}"
    )


def build_connector(kind: str, **opts) -> Connector:
    """Instantiate a connector, passing only the kwargs it understands."""
    cls = get_connector(kind)
    kind = kind.lower()
    keys: tuple[str, ...]
    if kind == "chroma":
        # Not "headers": header values are credentials, and the config store
        # masks only secret-named keys, so a headers dict would be shown and
        # stored in plaintext. ChromaConnector(headers=...) is for direct use.
        keys = ("host", "port", "path", "ssl", "tenant", "database")
    elif kind == "pgvector":
        keys = ("dsn", "host", "port", "dbname", "user", "password", "schema", "tables",
                "sslmode", "retrieval_role")
    elif kind == "qdrant":
        keys = ("url", "host", "port", "api_key")
    elif kind == "weaviate":
        keys = ("url", "host", "port", "grpc_port", "grpc_host", "api_key", "secure")
    elif kind == "milvus":
        keys = ("uri", "host", "port", "token", "db_name")
    elif kind == "pinecone":
        keys = ("api_key",)
    elif kind == "redis":
        keys = ("host", "port", "db", "password", "url")
    elif kind == "opensearch":
        keys = ("host", "port", "url", "user", "password", "use_ssl", "verify_certs")
    elif kind == "mongodb":
        keys = ("uri",)
    elif kind == "openai":
        keys = ("api_key",)
    elif kind == "azure_search":
        keys = ("endpoint", "api_key")
    elif kind == "bedrock_kb":
        keys = ("region", "aws_access_key_id", "aws_secret_access_key",
                "aws_session_token", "profile_name")
    elif kind == "vertex_ai":
        keys = ("project", "location", "endpoint_id", "credentials_json")
    else:  # pragma: no cover
        keys = ()
    kwargs = {k: opts[k] for k in keys if opts.get(k) is not None}
    # `tables` may arrive as a comma-separated string from the CLI; the pgvector
    # connector expects a list. Normalize without disturbing list inputs.
    if isinstance(kwargs.get("tables"), str):
        kwargs["tables"] = [t.strip() for t in kwargs["tables"].split(",") if t.strip()]
    connector = cls(**kwargs)
    # Not a connection setting: the model the owner says produced the vectors,
    # for stores that do not record it (see fill_declared_embedding_model).
    declared = opts.get("embedding_model")
    if isinstance(declared, str) and declared.strip():
        connector.declared_embedding_model = declared.strip()
    return connector


__all__ = [
    "AT_REST_STATES",
    "AtRestObservation",
    "Connector",
    "get_connector",
    "build_connector",
    "AVAILABLE",
    "ConnectorError",
    "ConnectorAuthError",
    "ConnectorTimeout",
    "ConnectorUnavailable",
    "ConnectorNotFound",
    "UnsupportedCapability",
    "RETRYABLE_ERRORS",
    "retry_read",
]
