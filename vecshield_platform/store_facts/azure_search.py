"""Store facts for the Azure AI Search connector (``kind = "azure_search"``).

Uses the connector's existing clients and credential: ``connector._ix``
(``SearchIndexClient``), ``connector._endpoint`` and ``connector._cred``
(to open a ``SearchIndexerClient`` for skillsets and indexers). SDK models are
read through ``as_dict()``, which yields the REST field names, so the parsing
below follows the REST reference (verified against the 2025-09-01 and
2026-04-01 stable versions; azure-search-documents 12.0 sends 2026-04-01):

* Index: ``vectorSearch.{algorithms,profiles,vectorizers}``, ``semantic``,
  field ``vectorSearchProfile``.
  https://learn.microsoft.com/rest/api/searchservice/indexes/get?view=rest-searchservice-2025-09-01
* Vectorizer kinds ``azureOpenAI`` / ``customWebApi`` / ``aml`` /
  ``aiServicesVision``.
  https://learn.microsoft.com/azure/search/vector-search-vectorizer-azure-open-ai
* Skillsets ``GET /skillsets`` and indexers ``GET /indexers`` (to find the
  index a skillset writes to).
  https://learn.microsoft.com/rest/api/searchservice/skillsets/get?view=rest-searchservice-2026-04-01
* Aliases ``GET /aliases`` (stable since 2026-04-01).
  https://learn.microsoft.com/azure/search/search-how-to-alias

Secrets: since March 2024 GET responses do not return keys, and header
values come back as ``<redacted>``. An absent ``apiKey`` therefore does not
prove the system-assigned identity is in use; such entries report
``auth="unknown"``. Keys and header values are never copied out regardless.
"""

from __future__ import annotations

from typing import Any, Optional

from vecshield_platform.store_facts._managed_util import (
    as_plain,
    failure_reason,
    get,
    host_of,
    integration,
    integrations_result,
    is_denied,
    location,
    normalize_metric,
    server,
)

#: Store facts this adapter answers (read by store_facts.supported()).
CAPABILITIES = frozenset({"server_info", "location_introspection", "egress_introspection",
                          "aliases"})

_ADMIN = ("an admin API key, or the Search Service Contributor role for a "
          "Microsoft Entra credential (query keys cannot read definitions)")

_REGION_REASON = ("Region is reported by Azure Resource Manager, not the search "
                  "endpoint; supply subscription and resource group or declare "
                  "the region.")

#: Skills that run inside the search service and call no model.
_LOCAL_SKILLS = frozenset({
    "#Microsoft.Skills.Text.SplitSkill", "#Microsoft.Skills.Text.MergeSkill",
    "#Microsoft.Skills.Util.ShaperSkill", "#Microsoft.Skills.Util.ConditionalSkill",
    "#Microsoft.Skills.Util.DocumentExtractionSkill",
})
_CUSTOM_SKILLS = frozenset({
    "#Microsoft.Skills.Custom.WebApiSkill", "#Microsoft.Skills.Custom.AmlSkill",
    "#Microsoft.Skills.Custom.ChatCompletionSkill",
    "#Microsoft.Skills.Text.AzureOpenAIEmbeddingSkill",
})
_CREDENTIAL_HEADER_HINTS = ("auth", "key", "token", "secret", "signature")


# ---- client access ------------------------------------------------------- #

def _index_client(connector: Any) -> Any:
    client = getattr(connector, "_ix", None)
    if client is None:
        raise AttributeError("the Azure AI Search connector has no index client (_ix)")
    return client


def _indexer_client(connector: Any) -> Any:
    from azure.search.documents.indexes import SearchIndexerClient
    return SearchIndexerClient(getattr(connector, "_endpoint"), getattr(connector, "_cred"))


def _list(client: Any, *methods: str) -> list[dict[str, Any]]:
    """Call the first listing method the SDK has; REST-shaped dicts out."""
    for name in methods:
        fn = getattr(client, name, None)
        if callable(fn):
            return [as_plain(item) for item in fn()]
    raise AttributeError(f"the SDK client has none of {', '.join(methods)}")


def _indexes(connector: Any) -> list[dict[str, Any]]:
    # list_indexes: azure-search-documents 12.x; get_indexes: 11.x.
    return _list(_index_client(connector), "list_indexes", "get_indexes")


def _api_version(connector: Any) -> Optional[str]:
    version = get(getattr(connector, "_ix", None), "_config", "api_version")
    return str(version) if version else None


# ---- parsing ---------------------------------------------------------------- #

def _metric_of_index(index: dict[str, Any]) -> Optional[str]:
    """One metric for the index, or None when absent/mixed/hamming."""
    vs = index.get("vectorSearch") or {}
    algo_metric: dict[Any, Any] = {}
    for algo in vs.get("algorithms") or []:
        params = algo.get("hnswParameters") or algo.get("exhaustiveKnnParameters") or {}
        algo_metric[algo.get("name")] = params.get("metric")
    profile_algo: dict[Any, Any] = {p.get("name"): p.get("algorithm")
                                   for p in vs.get("profiles") or []}
    metrics = set()
    for field in index.get("fields") or []:
        profile = field.get("vectorSearchProfile")
        if profile:
            # A metric the definition omits is not guessed: it reads as None.
            metrics.add(normalize_metric(algo_metric.get(profile_algo.get(profile))))
    return metrics.pop() if len(metrics) == 1 else None


def _identity(auth_identity: Any) -> Optional[str]:
    if not isinstance(auth_identity, dict):
        return None
    kind = str(auth_identity.get("@odata.type") or "")
    if kind.endswith("DataUserAssignedIdentity"):
        return "user_assigned"
    if kind.endswith("DataNoneIdentity"):
        return "none"
    return kind or None


def _key_or_identity_auth(params: dict[str, Any], key_field: str,
                          evidence: dict[str, Any]) -> str:
    """Auth for Azure OpenAI / AI Services style parameters (key or identity)."""
    identity = _identity(params.get("authIdentity"))
    if params.get(key_field):
        evidence["credential"] = "api key set (value not read)"
        return "api_key"
    if identity == "user_assigned":
        evidence["credential"] = "user-assigned managed identity"
        return "managed_identity"
    evidence["credential"] = ("no key in the definition; GET responses omit keys, "
                              "so this is either a key or the system-assigned identity")
    return "unknown"


def _web_api_auth(params: dict[str, Any], evidence: dict[str, Any]) -> str:
    """Auth for customWebApi vectorizers and WebApiSkill."""
    headers = params.get("httpHeaders") or {}
    names = sorted(str(h) for h in headers) if isinstance(headers, dict) else []
    if names:
        evidence["header_names"] = names
    if params.get("authResourceId"):
        evidence["credential"] = "Microsoft Entra token for authResourceId"
        return "managed_identity"
    uri = str(params.get("uri") or "")
    if "code=" in uri or any(h in n.lower() for n in names for h in _CREDENTIAL_HEADER_HINTS):
        evidence["credential"] = "key in a header or ?code= (value redacted by the service)"
        return "api_key"
    if names:
        return "unknown"
    return "none"


def _aml_auth(params: dict[str, Any], evidence: dict[str, Any]) -> str:
    if params.get("region"):
        evidence["model_region"] = params.get("region")
    if params.get("key"):
        evidence["credential"] = "api key set (value not read)"
        return "api_key"
    if params.get("resourceId"):
        evidence["credential"] = "search service managed identity (token auth)"
        return "managed_identity"
    return "unknown"


def _provider_for_host(host: Optional[str]) -> str:
    host = (host or "").lower()
    if host.endswith(".openai.azure.com"):
        return "azure_openai"
    if host.endswith((".services.ai.azure.com", ".cognitiveservices.azure.com")):
        return "azure_ai_services"
    if host.endswith(".azure-api.net"):
        return "azure_api_management"
    if host.endswith(".inference.ml.azure.com") or ".models.ai.azure.com" in host:
        return "azure_ml"
    return "custom_web_api"


def _vectorizer(collection: Optional[str], vz: dict[str, Any],
                profiles: list[str]) -> Optional[dict[str, Any]]:
    kind = vz.get("kind")
    evidence: dict[str, Any] = {"vectorizer": vz.get("name"), "profiles": profiles}
    if kind == "azureOpenAI":
        p = vz.get("azureOpenAIParameters") or {}
        host = host_of(p.get("resourceUri"))
        evidence["deployment"] = p.get("deploymentId")
        auth = _key_or_identity_auth(p, "apiKey", evidence)
        return integration(collection=collection, stage="query",
                           provider=_provider_for_host(host) if host else "azure_openai",
                           model=p.get("modelName") or p.get("deploymentId"),
                           endpoint_host=host, auth=auth, module="vectorizer:azureOpenAI",
                           evidence=evidence)
    if kind == "customWebApi":
        p = vz.get("customWebApiParameters") or {}
        host = host_of(p.get("uri"))
        auth = _web_api_auth(p, evidence)
        return integration(collection=collection, stage="query",
                           provider=_provider_for_host(host), model=None,
                           endpoint_host=host, auth=auth,
                           module="vectorizer:customWebApi", evidence=evidence)
    if kind == "aml":
        p = vz.get("amlParameters") or {}
        host = host_of(p.get("uri"))
        auth = _aml_auth(p, evidence)
        return integration(collection=collection, stage="query", provider="azure_ml",
                           model=p.get("modelName"), endpoint_host=host, auth=auth,
                           module="vectorizer:aml", evidence=evidence)
    if kind == "aiServicesVision":
        p = vz.get("aiServicesVisionParameters") or vz.get("AIServicesVisionParameters") or {}
        host = host_of(p.get("resourceUri"))
        evidence["model_version"] = p.get("modelVersion")
        auth = _key_or_identity_auth(p, "apiKey", evidence)
        return integration(collection=collection, stage="query",
                           provider="azure_ai_services", model=None,
                           endpoint_host=host, auth=auth,
                           module="vectorizer:aiServicesVision", evidence=evidence)
    if kind:
        return integration(collection=collection, stage="query", provider="unknown",
                           module=f"vectorizer:{kind}",
                           evidence={**evidence, "note": "vectorizer kind not recognised"})
    return None


def _index_integrations(index: dict[str, Any]) -> list[dict[str, Any]]:
    name = index.get("name")
    vs = index.get("vectorSearch") or {}
    used_by: dict[str, list[str]] = {}
    for p in vs.get("profiles") or []:
        if p.get("vectorizer"):
            used_by.setdefault(p["vectorizer"], []).append(p.get("name"))
    out = []
    for vz in vs.get("vectorizers") or []:
        item = _vectorizer(name, vz, used_by.get(vz.get("name"), []))
        if item:
            out.append(item)
    semantic = index.get("semantic") or {}
    configs = [c.get("name") for c in semantic.get("configurations") or []]
    if configs:
        # Semantic ranker: Microsoft-hosted models re-rank results at query time.
        # https://learn.microsoft.com/azure/search/semantic-search-overview
        out.append(integration(
            collection=name, stage="rerank", provider="azure", model=None,
            endpoint_host=None, auth="none", module="semantic_ranker",
            evidence={"configurations": configs,
                      "default_configuration": semantic.get("defaultConfiguration"),
                      "note": "whether the ranker is enabled on the service is an "
                              "Azure Resource Manager setting"}))
    return out


def _skill_integration(skill: dict[str, Any], skillset: Optional[str],
                       targets: list[str]) -> Optional[dict[str, Any]]:
    kind = str(skill.get("@odata.type") or "")
    collection = targets[0] if len(targets) == 1 else None
    evidence: dict[str, Any] = {"skillset": skillset, "skill": skill.get("name"),
                                "skill_type": kind, "target_indexes": targets}
    if kind == "#Microsoft.Skills.Text.AzureOpenAIEmbeddingSkill":
        host = host_of(skill.get("resourceUri"))
        evidence["deployment"] = skill.get("deploymentId")
        auth = _key_or_identity_auth(skill, "apiKey", evidence)
        return integration(collection=collection, stage="ingest",
                           provider=_provider_for_host(host) if host else "azure_openai",
                           model=skill.get("modelName") or skill.get("deploymentId"),
                           endpoint_host=host, auth=auth,
                           module="skill:AzureOpenAIEmbedding", evidence=evidence)
    if kind == "#Microsoft.Skills.Custom.WebApiSkill":
        host = host_of(skill.get("uri"))
        auth = _web_api_auth(skill, evidence)
        return integration(collection=collection, stage="ingest",
                           provider=_provider_for_host(host), endpoint_host=host,
                           auth=auth, module="skill:WebApi", evidence=evidence)
    if kind == "#Microsoft.Skills.Custom.AmlSkill":
        host = host_of(skill.get("uri"))
        auth = _aml_auth(skill, evidence)
        return integration(collection=collection, stage="ingest", provider="azure_ml",
                           endpoint_host=host, auth=auth, module="skill:Aml",
                           evidence=evidence)
    if kind == "#Microsoft.Skills.Custom.ChatCompletionSkill":
        host = host_of(skill.get("uri"))
        auth = _key_or_identity_auth(skill, "apiKey", evidence)
        model = get(skill, "commonModelParameters", "model")
        return integration(collection=collection, stage="ingest",
                           provider=_provider_for_host(host), model=model,
                           endpoint_host=host, auth=auth, module="skill:ChatCompletion",
                           evidence=evidence)
    return None


def _builtin_ai_skills(skillset: dict[str, Any], targets: list[str]) -> Optional[dict]:
    """One entry per skillset for built-in skills billed to Azure AI services."""
    kinds = sorted({str(s.get("@odata.type")) for s in skillset.get("skills") or []
                    if str(s.get("@odata.type") or "").startswith("#Microsoft.Skills.")
                    and s.get("@odata.type") not in _LOCAL_SKILLS | _CUSTOM_SKILLS})
    if not kinds:
        return None
    account = skillset.get("cognitiveServices") or {}
    account_type = str(account.get("@odata.type") or "")
    host = host_of(account.get("subdomainUrl"))
    if account_type.endswith("AIServicesByIdentity"):
        auth = "managed_identity"
    elif account_type.endswith(("ByKey",)):
        auth = "api_key"
    elif account_type.endswith("DefaultCognitiveServices") or not account_type:
        auth = "none"
    else:
        auth = "unknown"
    return integration(
        collection=targets[0] if len(targets) == 1 else None, stage="ingest",
        provider="azure_ai_services", endpoint_host=host, auth=auth,
        module="skill:builtin_ai_enrichment",
        evidence={"skillset": skillset.get("name"), "skill_types": kinds,
                  "target_indexes": targets,
                  "ai_services_account": account_type.rsplit(".", 1)[-1] or None})


# ---- contract ---------------------------------------------------------------- #

def server_info(connector: Any) -> dict[str, Any]:
    features: dict[str, Any] = {"api_version": _api_version(connector),
                                "local_auth_disabled": None}
    try:
        import azure.search.documents as sdk
        features["sdk_version"] = getattr(sdk, "__version__", None)
    except Exception:  # noqa: BLE001
        features["sdk_version"] = None
    reason = ("Azure AI Search is a managed service and does not expose a server "
              "version. local_auth_disabled is an Azure Resource Manager property "
              "(disableLocalAuth) and is not readable from the search endpoint.")
    if getattr(connector, "_cred", None) is not None and \
            type(connector._cred).__name__ == "AzureKeyCredential":
        features["connection_auth"] = "api_key"
    try:
        indexes = _indexes(connector)
    except Exception as exc:  # noqa: BLE001
        features["semantic_search"] = None
        return server(product="azure_ai_search", source="GET /indexes",
                      features=features,
                      reason=reason + " " + failure_reason(exc, "the index definitions",
                                                          _ADMIN))
    features["semantic_search"] = {
        "configured_indexes": sorted(i.get("name") for i in indexes
                                     if (i.get("semantic") or {}).get("configurations"))}
    return server(product="azure_ai_search", source="GET /indexes", features=features,
                  reason=reason)


def store_location(connector: Any) -> dict[str, Any]:
    endpoint = str(getattr(connector, "_endpoint", "") or "")
    host = host_of(endpoint)
    evidence: dict[str, Any] = {}
    if host:
        evidence["endpoint_host"] = host
        if host.endswith(".search.azure.us"):
            evidence["cloud"] = "Azure Government"
        elif host.endswith(".search.azure.cn"):
            evidence["cloud"] = "Azure operated by 21Vianet (China)"
    return location(provider="azure", region=None, source="search endpoint",
                    observable=False, reason=_REGION_REASON, evidence=evidence)


def model_integrations(connector: Any) -> dict[str, Any]:
    source = "GET /indexes, GET /skillsets, GET /indexers, GET /knowledgebases"
    try:
        indexes = _indexes(connector)
    except Exception as exc:  # noqa: BLE001
        return integrations_result(observable=False, source=source,
                                   reason=failure_reason(exc, "the index definitions",
                                                         _ADMIN))
    found: list[dict[str, Any]] = []
    for index in indexes:
        found.extend(_index_integrations(index))

    unread: list[dict[str, str]] = []
    try:
        indexer_client = _indexer_client(connector)
        skillsets = _list(indexer_client, "get_skillsets", "list_skillsets")
    except Exception as exc:  # noqa: BLE001
        skillsets = []
        unread.append({"source": "GET /skillsets",
                       "reason": failure_reason(exc, "the skillsets", _ADMIN)})
        indexer_client = None
    targets: dict[Any, list[Any]] = {}
    if skillsets and indexer_client is not None:
        try:
            for ixr in _list(indexer_client, "get_indexers", "list_indexers"):
                if ixr.get("skillsetName"):
                    targets.setdefault(ixr["skillsetName"], []).append(
                        ixr.get("targetIndexName"))
        except Exception as exc:  # noqa: BLE001
            unread.append({"source": "GET /indexers",
                           "reason": failure_reason(exc, "the indexers", _ADMIN)
                           + " Skillset entries are reported without their index."})
    for skillset in skillsets:
        ss_targets = sorted(t for t in targets.get(skillset.get("name"), []) if t)
        for skill in skillset.get("skills") or []:
            item = _skill_integration(skill, skillset.get("name"), ss_targets)
            if item:
                found.append(item)
        builtin = _builtin_ai_skills(skillset, ss_targets)
        if builtin:
            found.append(builtin)

    # Knowledge bases (agentic retrieval) call an LLM for query planning and,
    # in answer-synthesis mode, with retrieved content. Stable in 2026-04-01.
    kb_fn = getattr(_index_client(connector), "list_knowledge_bases", None)
    if callable(kb_fn):
        try:
            for kb in (as_plain(k) for k in kb_fn()):
                for model in kb.get("models") or []:
                    p = model.get("azureOpenAIParameters") or {}
                    host = host_of(p.get("resourceUri"))
                    ev: dict[str, Any] = {"knowledge_base": kb.get("name"),
                                          "kind": model.get("kind"),
                                          "deployment": p.get("deploymentId")}
                    auth = _key_or_identity_auth(p, "apiKey", ev)
                    found.append(integration(
                        collection=None, stage="generate",
                        provider=_provider_for_host(host) if host else "azure_openai",
                        model=p.get("modelName") or p.get("deploymentId"),
                        endpoint_host=host, auth=auth, module="knowledge_base",
                        evidence=ev))
        except Exception as exc:  # noqa: BLE001
            unread.append({"source": "GET /knowledgebases",
                           "reason": failure_reason(exc, "the knowledge bases", _ADMIN)})

    controls: dict[str, Any] = {
        "outbound_restriction": "network security perimeter / shared private links "
                                "are Azure Resource Manager settings, not readable here"}
    if unread:
        controls["unread"] = unread
    reason = (f"{len(found)} model integration(s) configured across "
              f"{len(indexes)} index(es)." if found
              else "No vectorizer, semantic configuration, model-calling skill or "
                   "knowledge-base model is configured.")
    if unread:
        reason += " Partial: " + "; ".join(u["source"] for u in unread) + " unreadable."
    return integrations_result(observable=True, source=source, integrations=found,
                               controls=controls, reason=reason)


def list_aliases(connector: Any) -> dict[str, str]:
    """Alias → index. Aliases are stable from REST 2026-04-01 (SDK 12.x).

    An alias maps to a list with exactly one index today; the first is taken.
    A refused credential raises ConnectorAuthError naming the permission; an
    SDK without alias support raises UnsupportedCapability. Neither is
    reported as "no aliases".
    """
    from vecshield_platform.connectors.base import ConnectorAuthError, UnsupportedCapability
    client = _index_client(connector)
    if not any(callable(getattr(client, m, None)) for m in ("list_aliases", "get_aliases")):
        raise UnsupportedCapability("this azure-search-documents version cannot list "
                                    "aliases (REST 2026-04-01 / SDK 12.x needed)")
    try:
        aliases = _list(client, "list_aliases", "get_aliases")
    except Exception as exc:  # noqa: BLE001
        if is_denied(exc):
            raise ConnectorAuthError(failure_reason(exc, "the aliases", _ADMIN)) from exc
        raise
    out: dict[str, str] = {}
    for alias in aliases:
        indexes = alias.get("indexes") or []
        if alias.get("name") and indexes:
            out[str(alias["name"])] = str(indexes[0])
    return out


def distance_metrics(connector: Any) -> dict[str, Optional[str]]:
    """Index name → metric. Hamming, mixed metrics or no vector field → None."""
    try:
        indexes = _indexes(connector)
    except Exception:  # noqa: BLE001 - reported by model_integrations/server_info
        return {}
    return {str(i["name"]): _metric_of_index(i) for i in indexes if i.get("name")}
