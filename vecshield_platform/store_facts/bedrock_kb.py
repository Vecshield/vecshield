"""Store facts for the Bedrock Knowledge Bases connector (``kind = "bedrock_kb"``).

Uses the connector's existing ``bedrock-agent`` client, ``connector._c``.
Field names follow the botocore service model (bedrock-agent 2023-06-05) and:

* GetKnowledgeBase — ``knowledgeBaseConfiguration.{type,
  vectorKnowledgeBaseConfiguration, managedKnowledgeBaseConfiguration}
  .embeddingModelArn`` and ``storageConfiguration.type`` (OPENSEARCH_SERVERLESS,
  PINECONE, REDIS_ENTERPRISE_CLOUD, RDS, MONGO_DB_ATLAS, NEPTUNE_ANALYTICS,
  OPENSEARCH_MANAGED_CLUSTER, S3_VECTORS).
  https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_GetKnowledgeBase.html
* GetDataSource — ``vectorIngestionConfiguration.{parsingConfiguration,
  contextEnrichmentConfiguration, customTransformationConfiguration}``.
  https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_ParsingConfiguration.html
* Cross-Region inference profiles route a request to another Region in the
  profile's geography (or worldwide for ``global.``).
  https://docs.aws.amazon.com/bedrock/latest/userguide/cross-region-inference.html

Bedrock does not expose the backing store's similarity metric, so
``distance_metrics`` returns an empty mapping. Credentials secret ARNs and
connection secrets in ``storageConfiguration`` are never read.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from vecshield_platform.store_facts._managed_util import (
    failure_reason,
    get,
    host_of,
    integration,
    integrations_result,
    location,
    server,
)

#: Store facts this adapter answers (read by store_facts.supported()).
CAPABILITIES = frozenset({"server_info", "location_introspection", "egress_introspection"})

_PERMISSION = ("IAM permissions bedrock:ListKnowledgeBases, bedrock:GetKnowledgeBase, "
               "bedrock:ListDataSources and bedrock:GetDataSource")

#: Backing stores run by a third party outside the AWS account: chunk text and
#: vectors are written to that vendor, which is then a separate sub-processor.
_THIRD_PARTY_STORES = {
    "PINECONE": ("pinecone", "pineconeConfiguration", "connectionString"),
    "MONGO_DB_ATLAS": ("mongodb_atlas", "mongoDbAtlasConfiguration", "endpoint"),
    "REDIS_ENTERPRISE_CLOUD": ("redis_cloud", "redisEnterpriseCloudConfiguration",
                               "endpoint"),
}

#: Geography prefixes of system-defined cross-Region inference profiles.
_CRIS_PREFIXES = ("us-gov", "global", "apac", "us", "eu", "jp", "au", "ca")

_ARN = re.compile(r"^arn:(?P<partition>aws[a-z-]*):bedrock:(?P<region>[a-z0-9-]*):"
                  r"(?P<account>\d*):(?P<rtype>[a-z-]+)/(?P<rid>.+)$")


def _client(connector: Any) -> Any:
    client = getattr(connector, "_c", None)
    if client is None:
        raise AttributeError("the Bedrock KB connector has no client (_c)")
    return client


def _region(connector: Any) -> Optional[str]:
    """The Region the client lists, as boto3 resolved it (config, profile or env)."""
    return (get(getattr(connector, "_c", None), "meta", "region_name")
            or getattr(connector, "_region", None))


def _paged(call: Any, key: str, **kw: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    token = None
    while True:
        args = dict(kw)
        if token:
            args["nextToken"] = token
        page = call(**args) or {}
        out.extend(page.get(key) or [])
        token = page.get("nextToken")
        if not token:
            return out


def _knowledge_bases(connector: Any) -> list[dict[str, Any]]:
    return _paged(_client(connector).list_knowledge_bases, "knowledgeBaseSummaries")


def _collection_name(summary: dict[str, Any]) -> str:
    """The connector's collection name for a KB: ``"<name> (<id>)"``."""
    return f"{summary.get('name')} ({summary.get('knowledgeBaseId')})"


def parse_model_arn(value: Any) -> dict[str, Any]:
    """Model id, Region and cross-Region scope from a Bedrock model ARN.

    Handles foundation models, system-defined and application inference
    profiles, and custom/provisioned models. A bare model id (not an ARN) is
    returned as the model with no Region. The account id is not returned.
    """
    text = str(value or "").strip()
    match = _ARN.match(text)
    if not match:
        return {"model": text or None, "model_region": None, "arn_type": None}
    rtype, rid = match.group("rtype"), match.group("rid")
    out: dict[str, Any] = {"model": rid, "model_region": match.group("region") or None,
                           "arn_type": rtype}
    if rtype == "inference-profile":
        prefix = rid.split(".", 1)[0]
        if prefix in _CRIS_PREFIXES and "." in rid:
            out["cross_region_scope"] = prefix
            out["model"] = rid.split(".", 1)[1]
            out["inference_profile"] = rid
            out["note"] = ("cross-Region inference: requests may be processed in any "
                           + ("commercial AWS Region" if prefix == "global"
                              else f"Region of the '{prefix}' geography"))
    elif rtype == "application-inference-profile":
        out["model"] = None
        out["note"] = ("application inference profile: the model and Regions are "
                       "defined on the profile (bedrock:GetInferenceProfile)")
    return out


def _embedding_config(kb: dict[str, Any]) -> Optional[dict[str, Any]]:
    config = kb.get("knowledgeBaseConfiguration") or {}
    for key in ("vectorKnowledgeBaseConfiguration", "managedKnowledgeBaseConfiguration"):
        sub = config.get(key) or {}
        if sub.get("embeddingModelArn"):
            return sub
    return None


def _backing_store(kb: dict[str, Any]) -> dict[str, Any]:
    storage = kb.get("storageConfiguration") or {}
    store_type = (storage.get("type") or "").upper() or None
    out: dict[str, Any] = {"type": store_type, "third_party": False}
    third = _THIRD_PARTY_STORES.get(store_type or "")
    if third:
        vendor, block, host_key = third
        out.update(third_party=True, vendor=vendor,
                   host=host_of((storage.get(block) or {}).get(host_key)))
    return out


def _data_source_integrations(connector: Any, kb_id: Any, collection: str,
                              controls: dict[str, Any]) -> list[dict[str, Any]]:
    client = _client(connector)
    found = []
    for summary in _paged(client.list_data_sources, "dataSourceSummaries",
                          knowledgeBaseId=kb_id):
        ds_id = summary.get("dataSourceId")
        ds = (client.get_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_id)
              or {}).get("dataSource") or {}
        vic = ds.get("vectorIngestionConfiguration") or {}
        base_ev = {"data_source": ds.get("name") or summary.get("name"),
                   "data_source_id": ds_id}
        parsing = vic.get("parsingConfiguration") or {}
        strategy = parsing.get("parsingStrategy")
        if strategy == "BEDROCK_FOUNDATION_MODEL":
            arn = get(parsing, "bedrockFoundationModelConfiguration", "modelArn")
            parsed = parse_model_arn(arn)
            found.append(integration(
                collection=collection, stage="ingest", provider="aws_bedrock",
                model=parsed.pop("model"), auth="managed_identity",
                module="parsing:foundation_model",
                evidence={**base_ev, **parsed, "parsing_strategy": strategy,
                          "credential": "knowledge base service role"}))
        elif strategy == "BEDROCK_DATA_AUTOMATION":
            found.append(integration(
                collection=collection, stage="ingest", provider="aws_bedrock",
                model=None, auth="managed_identity", module="parsing:data_automation",
                evidence={**base_ev, "parsing_strategy": strategy,
                          "credential": "knowledge base service role"}))
        enrich = vic.get("contextEnrichmentConfiguration") or {}
        enrich_arn = get(enrich, "bedrockFoundationModelConfiguration", "modelArn")
        if enrich_arn:
            parsed = parse_model_arn(enrich_arn)
            found.append(integration(
                collection=collection, stage="ingest", provider="aws_bedrock",
                model=parsed.pop("model"), auth="managed_identity",
                module="context_enrichment",
                evidence={**base_ev, **parsed, "enrichment_type": enrich.get("type")}))
        transforms = get(vic, "customTransformationConfiguration", "transformations") or []
        if transforms:
            # Chunks go to the customer's own Lambda function: customer code,
            # not a model provider, so it is a control rather than an entry.
            controls.setdefault("custom_transformations", []).append(
                {"collection": collection, **base_ev, "lambda_functions": len(transforms)})
    return found


# ---- contract ---------------------------------------------------------------- #

def server_info(connector: Any) -> dict[str, Any]:
    client = getattr(connector, "_c", None)
    features: dict[str, Any] = {
        "api_version": get(client, "meta", "service_model", "api_version"),
        "region": _region(connector)}
    try:
        import botocore
        features["botocore_version"] = getattr(botocore, "__version__", None)
    except Exception:  # noqa: BLE001
        features["botocore_version"] = None
    return server(product="amazon_bedrock_knowledge_bases", source="bedrock-agent client",
                  features=features,
                  reason="Amazon Bedrock is a managed service and does not expose a "
                         "server version.")


def store_location(connector: Any) -> dict[str, Any]:
    region = _region(connector)
    evidence: dict[str, Any] = {}
    try:
        stores = {}
        for summary in _knowledge_bases(connector):
            kb = (_client(connector).get_knowledge_base(
                knowledgeBaseId=summary.get("knowledgeBaseId")) or {}).get(
                "knowledgeBase") or {}
            stores[_collection_name(summary)] = _backing_store(kb)
        evidence["backing_store"] = stores
        third = sorted({s["vendor"] for s in stores.values() if s.get("third_party")})
        if third:
            evidence["third_party_backing_stores"] = third
    except Exception as exc:  # noqa: BLE001
        evidence["backing_store_error"] = failure_reason(exc, "the knowledge bases",
                                                         _PERMISSION)
    if not region:
        return location(provider="aws", region=None, source="client_region",
                        observable=False, evidence=evidence,
                        reason="The bedrock-agent client has no Region configured.")
    reason = ("Knowledge bases are regional; the client lists those in this Region. "
              "Vectors live in each knowledge base's backing store (see evidence).")
    if evidence.get("third_party_backing_stores"):
        reason += (" Some backing stores are run by a third party outside AWS; their "
                   "location is set on that vendor's side.")
    return location(provider="aws", region=region, source="client_region",
                    observable=True, evidence=evidence, reason=reason)


def model_integrations(connector: Any) -> dict[str, Any]:
    source = "GetKnowledgeBase, ListDataSources, GetDataSource"
    try:
        summaries = _knowledge_bases(connector)
    except Exception as exc:  # noqa: BLE001
        return integrations_result(observable=False, source=source,
                                   reason=failure_reason(exc, "the knowledge bases",
                                                         _PERMISSION))
    found: list[dict[str, Any]] = []
    controls: dict[str, Any] = {
        "generation_model": "chosen per RetrieveAndGenerate request; not part of the "
                            "knowledge base configuration",
        "reranking_model": "chosen per Retrieve request; not part of the knowledge "
                           "base configuration",
        "backing_store": {}}
    unread: list[dict[str, str]] = []
    for summary in summaries:
        kb_id = summary.get("knowledgeBaseId")
        collection = _collection_name(summary)
        try:
            kb = (_client(connector).get_knowledge_base(knowledgeBaseId=kb_id)
                  or {}).get("knowledgeBase") or {}
        except Exception as exc:  # noqa: BLE001
            unread.append({"collection": collection,
                           "reason": failure_reason(exc, "the knowledge base",
                                                    _PERMISSION)})
            continue
        controls["backing_store"][collection] = _backing_store(kb)
        emb = _embedding_config(kb)
        if emb:
            parsed = parse_model_arn(emb.get("embeddingModelArn"))
            model = parsed.pop("model")
            bedrock_cfg = get(emb, "embeddingModelConfiguration",
                              "bedrockEmbeddingModelConfiguration") or {}
            evidence = {**parsed, "credential": "knowledge base service role",
                        "knowledge_base_type": get(kb, "knowledgeBaseConfiguration",
                                                   "type"),
                        "dimensions": bedrock_cfg.get("dimensions"),
                        "embedding_data_type": bedrock_cfg.get("embeddingDataType")}
            # The same model embeds documents at ingestion and the query text on
            # Retrieve / RetrieveAndGenerate.
            for stage in ("ingest", "query"):
                found.append(integration(collection=collection, stage=stage,
                                         provider="aws_bedrock", model=model,
                                         auth="managed_identity", module="embedding",
                                         evidence=evidence))
        try:
            found.extend(_data_source_integrations(connector, kb_id, collection,
                                                   controls))
        except Exception as exc:  # noqa: BLE001
            unread.append({"collection": collection,
                           "reason": failure_reason(exc, "the data sources",
                                                    _PERMISSION)})
    if unread:
        controls["unread"] = unread
    reason = (f"{len(found)} model integration(s) configured across "
              f"{len(summaries)} knowledge base(s)." if found
              else "No knowledge base names an embedding or parsing model.")
    if unread:
        reason += f" Partial: {len(unread)} item(s) could not be read."
    return integrations_result(observable=True, source=source, integrations=found,
                               controls=controls, reason=reason)


def distance_metrics(connector: Any) -> dict[str, Optional[str]]:
    """Bedrock does not report the backing store's metric: nothing is known."""
    return {}
