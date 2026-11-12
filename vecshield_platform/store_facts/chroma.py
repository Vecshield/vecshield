"""Store facts for :class:`~vecshield_platform.connectors.chroma.ChromaConnector`.

Connector attributes read: ``_client`` (``chromadb.HttpClient`` or
``PersistentClient``) and ``_endpoint`` (``http://host:port`` or ``file://path``).

Verified against the chromadb 1.5.x source (``chromadb/api/client.py``,
``api/fastapi.py``, ``api/collection_configuration.py``,
``utils/embedding_functions/__init__.py``):

* server_info — ``client.get_version()``; over HTTP it is ``GET /version``
  (the server's version), embedded it is the local library's version. A 0.x
  server is reported as ``features.server_implementation = "python"`` (the
  Rust frontend arrived in 1.0); from 1.0 the implementation is not reported.
* distance metrics — ``Collection.configuration_json``: ``hnsw.space`` or
  ``spann.space`` (``l2`` / ``cosine`` / ``ip``), else the legacy
  ``hnsw:space`` metadata key. New collections have the space written into
  their configuration at creation (``populate_create_hnsw_defaults``: the
  embedding function's default space, or ``l2`` without one), so a collection
  with neither is an older one whose effective default depended on the
  client that created it — reported as None rather than guessed.
* model_integrations — ``configuration_json.embedding_function``
  (``{"type": "known", "name": ..., "config": {...}}``). Chroma runs
  embedding functions in the *client* that reads the collection, not in the
  server: the persisted config tells every client (including VecShield's own
  writes without vectors) which provider to call. Only allow-listed config
  keys are kept — never ``api_key_env_var`` or ``default_headers``.
* store_location — self-hosted or embedded; Chroma Cloud's hostname
  (``api.trychroma.com``) carries no region.
"""

from __future__ import annotations

from typing import Any, Optional

from vecshield_platform.store_facts import _selfhosted_util as u

CAPABILITIES = frozenset({"server_info", "location_introspection", "egress_introspection"})

_CLOUD_HOSTS = ("trychroma.com",)

#: Chroma known-embedding-function names → provider ("local" = in-process model).
_PROVIDERS = {
    "openai": "openai", "cohere": "cohere", "huggingface": "huggingface",
    "huggingface_server": "self_hosted", "sentence_transformer": "local",
    "google_palm": "google", "google_generative_ai": "google", "google_gemini": "google",
    "google_genai": "google", "google_vertex": "google_vertex", "ollama": "self_hosted",
    "instructor": "local", "jina": "jinaai", "mistral": "mistral", "morph": "morph",
    "nomic": "nomic", "voyageai": "voyageai", "onnx_mini_lm_l6_v2": "local",
    "open_clip": "local", "roboflow": "roboflow", "text2vec": "local",
    "amazon_bedrock": "aws_bedrock", "baseten": "baseten",
    "default": "local", "cloudflare_workers_ai": "cloudflare",
    "together_ai": "together_ai", "chroma-cloud-qwen": "chroma_cloud",
    "perplexity": "perplexity", "huggingface_sparse": "local",
    "fastembed_sparse": "local", "bm25": "local", "chroma_bm25": "local",
    "chroma-cloud-splade": "chroma_cloud",
}
_CONFIG_KEYS = ("model_name", "model", "api_base", "api_url", "url", "region",
                "api_type", "api_version", "deployment_id", "task", "dimensions")
_ENDPOINT_KEYS = ("api_base", "api_url", "url")


def _client(conn: Any) -> Any:
    return getattr(conn, "_client", None)


def _endpoint(conn: Any) -> str:
    return str(getattr(conn, "_endpoint", "") or "")


def _embedded(conn: Any) -> bool:
    return _endpoint(conn).startswith("file://")


def _host(conn: Any) -> Optional[str]:
    return None if _embedded(conn) else u.host_of(_endpoint(conn))


def _is_cloud(host: Optional[str]) -> bool:
    return host is not None and any(host == h or host.endswith("." + h) for h in _CLOUD_HOSTS)


def server_info(conn: Any) -> dict[str, Any]:
    embedded = _embedded(conn)
    managed = _is_cloud(_host(conn))
    source = "chromadb library version (embedded)" if embedded else "GET /api/v2/version"
    edition = "embedded" if embedded else ("chroma_cloud" if managed else None)
    try:
        version = _client(conn).get_version()
    except Exception as exc:  # noqa: BLE001
        return u.server(product="chroma", source=source, edition=edition, managed=managed,
                        reason=u.failed_reason(exc, "the server version",
                                               "access to the version endpoint"))
    features: dict[str, Any] = {}
    parsed = u.version_tuple(version) if version else None
    if not embedded and not managed and parsed and parsed[0] == 0:
        # Every 0.x server is the Python FastAPI server; the Rust frontend
        # shipped with 1.0. From 1.0 either can serve the same API, so the
        # implementation is not reported rather than guessed.
        features["server_implementation"] = "python"
    return u.server(product="chroma", source=source,
                    version=str(version) if version else None, edition=edition,
                    managed=managed, features=features,
                    reason="" if version else "no version was returned")


def _collections(conn: Any) -> list[Any]:
    return list(_client(conn).list_collections() or [])


def _name(col: Any) -> str:
    return col if isinstance(col, str) else str(getattr(col, "name", ""))


def _config(col: Any) -> dict[str, Any]:
    cfg = getattr(col, "configuration_json", None)
    if cfg is None:
        cfg = getattr(getattr(col, "_model", None), "configuration_json", None)
    return cfg if isinstance(cfg, dict) else {}


def distance_metric_details(conn: Any) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for col in _collections(conn):
        name = _name(col)
        cfg = _config(col)
        space = None
        source = None
        for index in ("hnsw", "spann"):
            section = cfg.get(index)
            if isinstance(section, dict) and section.get("space"):
                space, source = section["space"], f"configuration.{index}.space"
                break
        if space is None:
            meta = getattr(col, "metadata", None) or {}
            if isinstance(meta, dict) and meta.get("hnsw:space"):
                space, source = meta["hnsw:space"], "metadata.hnsw:space"
        detail = u.combine({"default": space} if space is not None else {},
                           source or "configuration_json")
        if space is None:
            detail["note"] = ("no space is recorded in this collection's configuration "
                              "or metadata")
        out[name] = detail
    return out


def _ef_entry(collection: str, ef: dict[str, Any]) -> Optional[dict[str, Any]]:
    kind = str(ef.get("type") or "")
    if kind == "legacy":
        return u.integration(collection=collection, stage="ingest", provider="unknown",
                             module="embedding_function (legacy)", auth="unknown",
                             evidence={"execution": "client",
                                       "note": "a legacy embedding function records no "
                                               "provider"})
    name = str(ef.get("name") or "")
    if not name:
        return None
    settings = u.pick(ef.get("config"), _CONFIG_KEYS)
    endpoint = next((u.host_of(settings[k]) for k in _ENDPOINT_KEYS if settings.get(k)), None)
    provider = _PROVIDERS.get(name, name)
    if name == "openai" and str(settings.get("api_type", "")).lower() == "azure":
        provider = "azure_openai"
    if endpoint and provider in ("openai", "self_hosted", "local"):
        by_host = u.provider_for_host(endpoint)
        if by_host:
            provider = by_host
        elif not u.is_private_host(endpoint):
            provider = "external"
    auth = ("none" if provider in ("local", "self_hosted")
            else "api_key" if "api_key_env_var" in (ef.get("config") or {}) else "unknown")
    model = settings.get("model_name") or settings.get("model")
    evidence = {k: v for k, v in settings.items()
                if k not in ("model_name", "model", "api_base", "api_url", "url")}
    evidence.update({"embedding_function": name, "execution": "client",
                     "also_applies_at": "query"})
    return u.integration(collection=collection, stage="ingest", provider=provider,
                         model=model, endpoint_host=endpoint, auth=auth,
                         module="embedding_function", evidence=evidence)


def model_integrations(conn: Any) -> dict[str, Any]:
    source = "collection configuration_json.embedding_function"
    try:
        cols = _collections(conn)
    except Exception as exc:  # noqa: BLE001
        return u.integrations_result(observable=False, source=source,
                                     reason=u.failed_reason(exc, "the collection list",
                                                            "read access to the database"))
    integrations = []
    for col in cols:
        ef = _config(col).get("embedding_function")
        if isinstance(ef, dict):
            entry = _ef_entry(_name(col), ef)
            if entry is not None:
                integrations.append(entry)
    return u.integrations_result(
        observable=True, source=source, integrations=integrations,
        reason="Chroma runs embedding functions in the client that reads the collection, "
               "not in the server; the persisted configuration tells every client which "
               "provider to send text to.")


def store_location(conn: Any) -> dict[str, Any]:
    source = "endpoint"
    if _embedded(conn):
        return u.self_hosted(source, None, local=True)
    host = _host(conn)
    if not host:
        return u.unknown_host(source, None)
    if _is_cloud(host):
        return u.location(provider="chroma_cloud", region=None, source=source,
                          observable=False, evidence={"host": host},
                          reason="Chroma Cloud's endpoint does not carry a region; "
                                 "declare the database's region.")
    if u.is_private_host(host):
        return u.self_hosted(source, host)
    return u.unknown_host(source, host)
