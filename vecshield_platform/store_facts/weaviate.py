"""Store facts for :class:`~vecshield_platform.connectors.weaviate.WeaviateConnector`.

Connector attributes read: ``_client`` (weaviate v4 ``WeaviateClient``) and
``_endpoint`` (credential-redacted URL or ``http://host:port``).

* server_info — ``GET /v1/meta`` via ``client.get_meta()``: ``version`` and the
  enabled ``modules`` (names only).
* distance metrics — collection config via
  ``client.collections.list_all(simple=False)`` and ``CollectionConfig.to_dict()``,
  which rebuilds the REST schema shape (``vectorIndexConfig`` /
  ``vectorConfig.<name>.vectorIndexConfig``; the client serialises the metric
  as ``distanceMetric``, the REST schema as ``distance``). Weaviate metrics:
  cosine, dot, l2-squared, hamming, manhattan — hamming has no slot in the
  ``Collection.distance_metric`` vocabulary and is reported as None.
* model_integrations — enabled modules from ``/v1/meta`` (store-wide) and each
  collection's ``vectorizer``, named-vector vectorizers and ``moduleConfig``
  generative/reranker/qna modules. Module → provider names follow
  https://docs.weaviate.io/weaviate/model-providers. Only allow-listed config
  keys (model, base URL, region ...) are kept; keys and headers never are.
* list_aliases — ``client.alias.list_all()`` (REST ``/v1/aliases``), added in
  Weaviate v1.32 (https://docs.weaviate.io/weaviate/manage-collections/collection-aliases);
  version-gated on ``/v1/meta``.
* store_location — Weaviate Cloud hostnames. The docs say new cluster URLs
  "may have an extra subdomain such as ``.c0.region``"
  (https://docs.weaviate.io/cloud/manage-clusters/connect); live hostnames
  have the form ``<id>.c0.europe-west3.gcp.weaviate.cloud``. Only that exact
  shape yields a region.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from vecshield_platform.connectors.base import UnsupportedCapability
from vecshield_platform.store_facts import _selfhosted_util as u

CAPABILITIES = frozenset({"server_info", "location_introspection",
                          "egress_introspection", "aliases"})

ALIASES_SINCE = (1, 32)

_CLOUD_HOST = re.compile(
    r"^[a-z0-9-]+\.c\d+\.(?P<region>[a-z0-9-]+)\.(?P<cloud>gcp|aws|azure)\.weaviate\.cloud$")
_CLOUD_SUFFIXES = (".weaviate.cloud", ".weaviate.network")

#: Module family → the stage at which it sends data to a model.
_STAGES = {"text2vec": "ingest", "multi2vec": "ingest", "text2multivec": "ingest",
           "multi2multivec": "ingest", "img2vec": "ingest", "generative": "generate",
           "reranker": "rerank", "qna": "query", "ner": "query", "sum": "query"}

#: Module suffix → provider (https://docs.weaviate.io/weaviate/model-providers).
_PROVIDERS = {
    "openai": "openai", "azure-openai": "azure_openai", "cohere": "cohere",
    "google": "google", "palm": "google", "huggingface": "huggingface",
    "jinaai": "jinaai", "voyageai": "voyageai", "mistral": "mistral",
    "nvidia": "nvidia", "anthropic": "anthropic", "anyscale": "anyscale",
    "databricks": "databricks", "friendliai": "friendliai", "octoai": "octoai",
    "weaviate": "weaviate_embeddings", "xai": "xai", "deepseek": "deepseek",
    "contextualai": "contextualai", "twelvelabs": "twelvelabs", "morph": "morph",
    "digitalocean": "digitalocean", "aws": "aws",
}
#: Locally hosted inference containers: no third-party egress by design.
_LOCAL = {"transformers", "ollama", "gpt4all", "model2vec", "clip", "bind",
          "imagebind", "kubeai", "contextionary", "neural"}

_CONFIG_KEYS = ("model", "modelId", "modelName", "model_id", "baseURL", "baseUrl",
                "apiEndpoint", "endpoint", "endpointUrl", "url", "resourceName",
                "deploymentId", "region", "service", "projectId", "location",
                "dimensions", "vectorizeClassName")
_ENDPOINT_KEYS = ("baseURL", "baseUrl", "apiEndpoint", "endpoint", "endpointUrl", "url")


def _client(conn: Any) -> Any:
    return getattr(conn, "_client", None)


def _host(conn: Any) -> Optional[str]:
    return u.host_of(getattr(conn, "_endpoint", None))


def _is_cloud(host: Optional[str]) -> bool:
    return host is not None and any(host.endswith(s) for s in _CLOUD_SUFFIXES)


def _meta(conn: Any) -> dict[str, Any]:
    meta = _client(conn).get_meta()
    return meta if isinstance(meta, dict) else {}


def _module_names(meta: dict[str, Any]) -> list[str]:
    modules = meta.get("modules") or {}
    return sorted(str(k) for k in modules) if isinstance(modules, dict) else []


def server_info(conn: Any) -> dict[str, Any]:
    managed = _is_cloud(_host(conn))
    edition = "weaviate_cloud" if managed else None
    try:
        meta = _meta(conn)
    except Exception as exc:  # noqa: BLE001
        return u.server(product="weaviate", source="GET /v1/meta", edition=edition,
                        managed=managed,
                        reason=u.failed_reason(exc, "/v1/meta", "read access to /v1/meta"))
    version = meta.get("version")
    return u.server(product="weaviate", source="GET /v1/meta",
                    version=str(version) if version else None, edition=edition,
                    managed=managed, reason="" if version else "/v1/meta returned no version",
                    features={"modules": _module_names(meta)})


# ------------------------------------------------------------------ schema #

def _schemas(conn: Any) -> dict[str, dict[str, Any]]:
    """Collection name → REST-shaped schema dict."""
    configs = _client(conn).collections.list_all(simple=False)
    out: dict[str, dict[str, Any]] = {}
    for name, cfg in (configs or {}).items():
        if isinstance(cfg, dict):
            out[str(name)] = cfg
            continue
        to_dict = getattr(cfg, "to_dict", None)
        try:
            out[str(name)] = to_dict() if callable(to_dict) else {}
        except Exception:  # noqa: BLE001 - one malformed config must not hide the rest
            out[str(name)] = {}
    return out


def _distance(index_config: Any) -> Any:
    if not isinstance(index_config, dict):
        return None
    return index_config.get("distance") or index_config.get("distanceMetric")


def distance_metric_details(conn: Any) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for name, schema in _schemas(conn).items():
        per: dict[str, Any] = {}
        named = schema.get("vectorConfig")
        if isinstance(named, dict) and named:
            for vname, vcfg in named.items():
                per[str(vname)] = _distance((vcfg or {}).get("vectorIndexConfig"))
        if not per or schema.get("vectorIndexConfig"):
            top = _distance(schema.get("vectorIndexConfig"))
            if top is not None or not per:
                per.setdefault("default", top)
        out[name] = u.combine(per, "vectorIndexConfig.distance")
    return out


# ------------------------------------------------------------ integrations #

def _classify(module: str) -> tuple[Optional[str], Optional[str], bool]:
    """(stage, provider, local) for a module name; stage None = not a model module."""
    family, _, suffix = module.partition("-")
    stage = _STAGES.get(family)
    if stage is None:
        return None, None, False
    if suffix in _LOCAL:
        return stage, "self_hosted", True
    return stage, _PROVIDERS.get(suffix, suffix or module), False


def _entry(module: str, collection: Optional[str], config: Any,
           extra: Optional[dict[str, Any]] = None) -> Optional[dict[str, Any]]:
    stage, provider, local = _classify(module)
    if stage is None or provider is None:
        return None
    settings = u.pick(config, _CONFIG_KEYS)
    endpoint = next((u.host_of(settings[k]) for k in _ENDPOINT_KEYS if settings.get(k)), None)
    if module.endswith("-aws"):
        service = str(settings.get("service", "")).lower()
        provider = {"bedrock": "aws_bedrock", "sagemaker": "aws_sagemaker"}.get(service, "aws")
    if local and endpoint and not u.is_private_host(endpoint):
        # A "local" module pointed at a public endpoint is still egress.
        provider = u.provider_for_host(endpoint) or "external"
    model = (settings.get("model") or settings.get("modelId") or settings.get("modelName")
             or settings.get("model_id"))
    auth = "none" if local else ("unknown" if provider in ("aws", "aws_bedrock",
                                                           "aws_sagemaker", "google")
                                 else "api_key")
    evidence = {k: v for k, v in settings.items() if k not in ("model", "modelId",
                                                               "modelName", "model_id")}
    evidence.update(extra or {})
    return u.integration(collection=collection, stage=stage, provider=provider,
                         model=str(model) if model else None, endpoint_host=endpoint,
                         auth=auth, module=module, evidence=evidence)


def _collection_entries(name: str, schema: dict[str, Any]) -> list[dict[str, Any]]:
    entries: list[Optional[dict[str, Any]]] = []
    module_config = schema.get("moduleConfig") or {}
    vectorizer = schema.get("vectorizer")
    if isinstance(vectorizer, str) and vectorizer and vectorizer != "none":
        entries.append(_entry(vectorizer, name, module_config.get(vectorizer),
                              {"vector": "default", "also_applies_at": "query"}))
    for vname, vcfg in (schema.get("vectorConfig") or {}).items():
        vec = (vcfg or {}).get("vectorizer")
        if isinstance(vec, dict):
            for module, cfg in vec.items():
                if module != "none":
                    entries.append(_entry(str(module), name, cfg,
                                          {"vector": str(vname), "also_applies_at": "query"}))
        elif isinstance(vec, str) and vec and vec != "none":
            entries.append(_entry(vec, name, None,
                                  {"vector": str(vname), "also_applies_at": "query"}))
    for module, cfg in module_config.items():
        stage, _, _ = _classify(str(module))
        if stage in ("generate", "rerank", "query"):
            entries.append(_entry(str(module), name, cfg))
    return [e for e in entries if e is not None]


def model_integrations(conn: Any) -> dict[str, Any]:
    integrations: list[dict[str, Any]] = []
    problems: list[str] = []
    sources = []
    try:
        meta = _meta(conn)
        sources.append("GET /v1/meta")
        for module in _module_names(meta):
            entry = _entry(module, None, None, {"enabled_module": True})
            if entry is not None:
                integrations.append(entry)
    except Exception as exc:  # noqa: BLE001
        problems.append(u.failed_reason(exc, "the enabled modules (/v1/meta)",
                                        "read access to /v1/meta"))
    try:
        for name, schema in _schemas(conn).items():
            integrations.extend(_collection_entries(name, schema))
        sources.append("GET /v1/schema")
    except Exception as exc:  # noqa: BLE001
        problems.append(u.failed_reason(
            exc, "the collection schema", "the read_collections permission "
            "(Weaviate RBAC) on every collection"))
    reason = " ".join(problems) if problems else (
        "Enabled modules are store-wide capabilities; collection entries are "
        "configured vectorizers and generative/reranker modules. Configured is not "
        "the same as used.")
    return u.integrations_result(observable=not problems, reason=reason,
                                 source=", ".join(sources) or "GET /v1/meta, GET /v1/schema",
                                 integrations=integrations)


# ------------------------------------------------------------------ aliases #

def list_aliases(conn: Any) -> dict[str, str]:
    meta = _meta(conn)
    version = u.version_tuple(meta.get("version"))
    if version is not None and version[:2] < ALIASES_SINCE:
        raise UnsupportedCapability(
            f"Weaviate {meta.get('version')} predates collection aliases (added in v1.32)")
    alias_api = getattr(_client(conn), "alias", None)
    if alias_api is None or not callable(getattr(alias_api, "list_all", None)):
        raise UnsupportedCapability("the installed weaviate-client has no alias API; "
                                    "aliases need weaviate-client 4.16 or later")
    out: dict[str, str] = {}
    for key, alias in (alias_api.list_all() or {}).items():
        name = u.get(alias, "alias") or key
        target = u.get(alias, "collection")
        if name and target:
            out[str(name)] = str(target)
    return out


# ----------------------------------------------------------------- location #

def store_location(conn: Any) -> dict[str, Any]:
    source = "endpoint hostname"
    host = _host(conn)
    if not host:
        return u.unknown_host(source, None)
    m = _CLOUD_HOST.match(host)
    if m:
        return u.location(
            provider="weaviate_cloud", region=m.group("region"), source=source,
            observable=True,
            reason="Weaviate Cloud encodes the cluster's region and cloud in its hostname.",
            evidence={"host": host, "cloud": m.group("cloud"),
                      "pattern_source": "https://docs.weaviate.io/cloud/manage-clusters/connect"})
    if _is_cloud(host):
        return u.location(provider="weaviate_cloud", region=None, source=source,
                          observable=False, evidence={"host": host},
                          reason="This Weaviate Cloud hostname does not carry a region "
                                 "subdomain; declare the cluster's region.")
    if u.is_private_host(host):
        return u.self_hosted(source, host)
    return u.unknown_host(source, host)
