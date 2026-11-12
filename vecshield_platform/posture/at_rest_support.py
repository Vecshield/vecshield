"""What each connector can and cannot tell us about encryption at rest.

One record per connector kind, and the only place this is written down. The
posture engine reads it to explain an ``unsupported`` result, the console
reads it to render the capability matrix, and a test holds it to the
connectors: a kind is ``supported`` exactly when its connector advertises
``at_rest_introspection`` and implements ``at_rest_encryption_state()``.

The research behind each entry (vendor documentation and SDK source, read
2026-09-24) is cited in ``sources``. Two rules shape the wording:

* ``documented_default`` is what a vendor *documents* — "always encrypted with
  provider-managed keys". It is context for a reviewer. It is never turned
  into a state: a document is not an observation of this store.
* ``not_supported_reason`` says why the connector cannot see the property, in
  plain words, so a reader knows the gap is the product's interface and not a
  failed scan. ``evidence_to_supply`` says what to attach instead.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

SUPPORTED = "supported"
NOT_SUPPORTED = "not_supported"


@dataclass(frozen=True)
class AtRestSupport:
    kind: str
    database: str
    support: str
    observable: str
    not_supported_reason: Optional[str] = None
    evidence_to_supply: tuple[str, ...] = ()
    documented_default: Optional[str] = None
    documented_default_source: Optional[str] = None
    sources: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.support not in (SUPPORTED, NOT_SUPPORTED):
            raise ValueError(f"unknown support value: {self.support}")
        if self.support == NOT_SUPPORTED and not self.not_supported_reason:
            raise ValueError(f"{self.kind}: a not-supported entry must say why")
        if self.documented_default and not self.documented_default_source:
            raise ValueError(f"{self.kind}: a documented default needs its source")

    def default_record(self) -> Optional[dict[str, str]]:
        """``{"text", "source_url"}`` for outcome details, or None."""
        if not self.documented_default:
            return None
        return {"text": self.documented_default,
                "source_url": self.documented_default_source or ""}

    def to_dict(self) -> dict:
        return {"kind": self.kind, "database": self.database, "support": self.support,
                "observable": self.observable,
                "not_supported_reason": self.not_supported_reason,
                "evidence_to_supply": list(self.evidence_to_supply),
                "documented_default": self.default_record(),
                "sources": list(self.sources)}


_ENTRIES = (
    AtRestSupport(
        kind="pgvector", database="PostgreSQL (pgvector)", support=SUPPORTED,
        observable="Percona pg_tde per table, including partitions, indexes and "
                   "TOAST; EDB transparent data encryption for the cluster. The "
                   "hosting provider is identified only to explain what to supply.",
        evidence_to_supply=(
            "Volume or disk encryption configuration of the database host",
            "The managed provider's storage-encryption setting and key identifier",
        ),
        sources=(
            "https://docs.percona.com/pg-tde/functions.html",
            "https://docs.percona.com/pg-tde/variables.html",
            "https://docs.percona.com/pg-tde/index/tde-limitations.html",
            "https://www.enterprisedb.com/docs/tde/latest/",
            "https://www.enterprisedb.com/docs/tde/latest/enabling/verifying_tde/",
            "https://learn.microsoft.com/azure/postgresql/security/security-data-encryption",
            "https://docs.cloud.google.com/sql/docs/postgres/cmek",
            "https://docs.cloud.google.com/alloydb/docs/cmek",
        )),
    AtRestSupport(
        kind="mongodb", database="MongoDB", support=SUPPORTED,
        observable="serverStatus.encryptionAtRest on the node VecShield is connected "
                   "to (Enterprise encrypted storage engine; field names documented "
                   "by Percona, medium confidence). Queryable Encryption and "
                   "server-side CSFLE schemas per collection.",
        evidence_to_supply=(
            "The server's security.enableEncryption and KMIP/keyfile configuration",
            "Volume or filesystem encryption configuration",
            "Atlas project Encryption at Rest settings, for customer-managed keys",
        ),
        sources=(
            "https://www.mongodb.com/docs/manual/core/security-encryption-at-rest/",
            "https://docs.percona.com/percona-server-for-mongodb/8.0/data-at-rest-encryption.html",
            "https://www.mongodb.com/docs/atlas/security-kms-encryption/",
        )),
    AtRestSupport(
        kind="azure_search", database="Azure AI Search", support=SUPPORTED,
        observable="SearchIndex.encryption_key: a customer-managed key in Azure "
                   "Key Vault, per index. Service-level customer-managed keys are in "
                   "preview (management API 2026-03-01-preview; data-plane "
                   "encryptionKey.isServiceLevelKey from 2026-05-01-preview) and are "
                   "not read yet.",
        evidence_to_supply=(
            "The search service's customer-managed key policy, if one is required",
        ),
        documented_default="Microsoft documents always-on AES-256 encryption with "
                           "Microsoft-managed keys for all Azure AI Search data.",
        documented_default_source="https://learn.microsoft.com/azure/search/search-security-built-in",
        sources=(
            "https://learn.microsoft.com/azure/search/search-security-built-in",
            "https://learn.microsoft.com/azure/search/search-security-manage-encryption-keys",
        )),
    AtRestSupport(
        kind="vertex_ai", database="Vertex AI Vector Search", support=SUPPORTED,
        observable="encryption_spec.kms_key_name on the index, and on the index "
                   "endpoint when one is configured.",
        evidence_to_supply=(
            "The Cloud KMS key and its IAM policy, if a customer-managed key is required",
        ),
        documented_default="Google documents that Vertex AI encrypts customer content "
                           "at rest by default (Google default encryption).",
        documented_default_source="https://docs.cloud.google.com/docs/security/encryption/"
                                  "default-encryption",
        sources=(
            "https://docs.cloud.google.com/docs/security/encryption/default-encryption",
            "https://docs.cloud.google.com/gemini-enterprise-agent-platform/"
            "machine-learning/general/cmek",
        )),
    AtRestSupport(
        kind="bedrock_kb", database="Amazon Bedrock Knowledge Bases", support=SUPPORTED,
        observable="Managed knowledge bases: the storage KMS key. Custom knowledge "
                   "bases: only the backing store's type and ARN; data-source keys "
                   "cover transient ingestion storage and are never counted.",
        evidence_to_supply=(
            "The backing vector store's encryption configuration, or a scan of it "
            "with its own connector",
            "The KMS key policy for the knowledge base",
        ),
        sources=(
            "https://docs.aws.amazon.com/bedrock/latest/userguide/encryption-kb.html",
            "https://docs.aws.amazon.com/opensearch-service/latest/developerguide/"
            "serverless-encryption.html",
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-vectors-data-encryption.html",
            "https://docs.aws.amazon.com/prescriptive-guidance/latest/"
            "neptune-analytics-well-architected-framework/security-pillar.html",
        )),
    AtRestSupport(
        kind="pinecone", database="Pinecone", support=SUPPORTED,
        observable="cmek_id on the index description (API 2026-07 or later). BYOC "
                   "deployments use the cloud provider's KMS instead of the console "
                   "CMEK flow, so a BYOC index likely shows no cmek_id.",
        evidence_to_supply=(
            "The Pinecone project's CMEK configuration and the key's policy",
            "For BYOC: the cloud provider's KMS configuration for the deployment",
            "Pinecone's SOC 2 Type 2 report",
        ),
        documented_default="Pinecone documents AES-256 encryption of stored data.",
        documented_default_source="https://docs.pinecone.io/guides/production/security-overview",
        sources=(
            "https://docs.pinecone.io/reference/api/2026-07/control-plane/describe_index",
            "https://docs.pinecone.io/guides/production/configure-cmek",
            "https://docs.pinecone.io/guides/production/security-overview",
        )),
    AtRestSupport(
        kind="milvus", database="Milvus", support=SUPPORTED,
        observable="Native encryption zones (Milvus 2.6.0 or later): cipher.ezID and "
                   "cipher.key on the database, cipher.ezID on collections. Only "
                   "'enabled' can be proven. Needs a live spike before leaving draft.",
        evidence_to_supply=(
            "Object storage (S3/MinIO) server-side encryption configuration",
            "Disk and message-queue encryption configuration",
        ),
        sources=(
            "https://github.com/milvus-io/milvus/blob/v2.6.0/internal/util/hookutil/cipher.go",
            "https://github.com/milvus-io/milvus/blob/v2.6.24/internal/util/hookutil/cipher.go",
            "https://github.com/milvus-io/milvus/blob/v2.6.24/pkg/common/common.go",
        )),
    AtRestSupport(
        kind="opensearch", database="OpenSearch", support=SUPPORTED,
        observable="index.store.type == cryptofs per index (storage-encryption "
                   "plugin), with its key provider / KMS type and KMS key ARN. The "
                   "plugin is pre-release: its README requires OpenSearch "
                   "3.6.0-SNAPSHOT and supports AWS KMS only.",
        evidence_to_supply=(
            "Domain or node disk encryption configuration (e.g. Amazon OpenSearch "
            "Service encryption at rest)",
        ),
        sources=("https://github.com/opensearch-project/opensearch-storage-encryption",)),
    AtRestSupport(
        kind="qdrant", database="Qdrant", support=NOT_SUPPORTED,
        observable="Nothing: Qdrant's API has no encryption-at-rest setting.",
        not_supported_reason="Qdrant has no encryption-at-rest setting in its API. "
                             "Encryption is applied to disks or by the cloud provider, "
                             "which an API key cannot inspect.",
        evidence_to_supply=(
            "Self-hosted: volume encryption (LUKS, EBS, or the Kubernetes StorageClass)",
            "Qdrant Cloud: the SOC 2 Type 2 report from the Trust Center (qdrant.tech/security)",
            "Customer-managed key ID and key policy, if one is used",
        ),
        documented_default="Qdrant Cloud documents that Qdrant Managed Cloud encrypts "
                           "all storage volumes at rest by default. Self-hosted "
                           "Qdrant has no such default.",
        documented_default_source="https://qdrant.tech/documentation/cloud/encryption/",
        sources=("https://qdrant.tech/documentation/cloud/encryption/",
                 "https://qdrant.tech/security/")),
    AtRestSupport(
        kind="weaviate", database="Weaviate", support=NOT_SUPPORTED,
        observable="Nothing: Weaviate's API does not expose encryption-at-rest state.",
        not_supported_reason="Weaviate does not expose encryption-at-rest state "
                             "through its API. It is handled by the storage layer or "
                             "Weaviate Cloud infrastructure, which an API key cannot "
                             "inspect.",
        evidence_to_supply=(
            "Self-hosted: volume or Kubernetes StorageClass encryption configuration",
            "Weaviate Cloud: the SOC 2 report, requested from trust.weaviate.io",
            "Any customer-managed key arrangement Weaviate confirms in writing",
        ),
        documented_default="Weaviate documents that Weaviate Cloud data is encrypted in "
                           "transit and at rest.",
        documented_default_source="https://weaviate.io/security",
        sources=("https://weaviate.io/security",
                 "https://forum.weaviate.io/t/how-does-encryption-work-on-weaviate/5832")),
    AtRestSupport(
        kind="chroma", database="Chroma", support=NOT_SUPPORTED,
        observable="Nothing through this connector. Chroma Cloud exposes per-"
                   "collection GCP CMEK via Schema.cmek, but this connector has no "
                   "CloudClient path yet.",
        not_supported_reason="Chroma documents no encryption-at-rest setting for local "
                             "or self-hosted storage. Protection depends on the host's "
                             "disk encryption, which Chroma's API does not report.",
        evidence_to_supply=(
            "Host disk encryption status (FileVault, BitLocker, LUKS or EBS)",
        ),
        sources=("https://github.com/chroma-core/chroma/blob/1.5.9/chromadb/api/types.py",)),
    AtRestSupport(
        kind="redis", database="Redis", support=NOT_SUPPORTED,
        observable="Nothing: Redis has no command that reports disk encryption.",
        not_supported_reason="Redis has no built-in encryption at rest and no command "
                             "that reports disk encryption. Provide your host's or "
                             "provider's disk and snapshot encryption settings.",
        evidence_to_supply=(
            "Host disk and RDB/AOF snapshot volume encryption",
            "Amazon ElastiCache: AtRestEncryptionEnabled and StorageEncryptionType",
            "Azure Cache for Redis: SKU and disk-encryption settings",
        ),
        sources=(
            "https://redis.io/faq/doc/2j6kk4yf86/does-redis-support-encryption-at-rest-and-in-transit",
            "https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/"
            "API_ReplicationGroup.html",
        )),
    AtRestSupport(
        kind="openai", database="OpenAI Vector Stores", support=NOT_SUPPORTED,
        observable="Nothing: the vector store API does not report encryption.",
        not_supported_reason="OpenAI's vector store API does not report encryption at "
                             "rest. OpenAI documents AES-256 encryption for API "
                             "platform data; EKM status needs an organization admin key.",
        evidence_to_supply=(
            "OpenAI's SOC 2 Type 2 report (trust.openai.com)",
            "The EKM project record, if Enterprise Key Management is claimed",
        ),
        documented_default="OpenAI documents AES-256 encryption at rest for API "
                           "platform data.",
        # Wording taken from the search index: the page returns 403 to fetchers.
        documented_default_source="https://openai.com/enterprise-privacy/",
        sources=("https://openai.com/enterprise-privacy/",
                 "https://help.openai.com/en/articles/20000953-ekm-external-keys-in-the-"
                 "management-api",
                 # Only where to request the SOC 2 report.
                 "https://trust.openai.com/")),
)

AT_REST_SUPPORT: dict[str, AtRestSupport] = {entry.kind: entry for entry in _ENTRIES}


def support_for(kind: str) -> AtRestSupport:
    """The entry for a connector kind; an unknown kind is honestly not supported."""
    entry = AT_REST_SUPPORT.get((kind or "").lower())
    if entry is not None:
        return entry
    return AtRestSupport(
        kind=kind or "unknown", database=kind or "Unknown store", support=NOT_SUPPORTED,
        observable="Nothing: this connector kind has no at-rest research entry.",
        not_supported_reason="This connector has no known way to read encryption at "
                             "rest from the store. Provide the store's encryption "
                             "configuration as evidence.",
        evidence_to_supply=("The store's encryption-at-rest configuration",))


def support_matrix() -> list[dict]:
    """Every entry, for the console and docs capability matrix."""
    return [entry.to_dict() for entry in _ENTRIES]
