"""Store facts for :class:`~vecshield_platform.connectors.milvus.MilvusConnector`.

Connector attributes read: ``_client`` (pymilvus ``MilvusClient``), ``_uri``
(the raw URI, used only for its hostname) and ``_endpoint`` (redacted URI).

* server_info — ``MilvusClient.get_server_version()``. Zilliz Cloud answers
  with its own product string; the Milvus version is parsed from it when it
  carries one.
* distance metrics — ``list_indexes()`` + ``describe_index()`` → ``metric_type``
  (COSINE / IP / L2; HAMMING, JACCARD, BM25 ... have no slot → None).
* model_integrations — ``describe_collection()["functions"]`` with type
  ``TEXTEMBEDDING`` (Milvus 2.6+). FunctionSchema dict keys ``name``, ``type``,
  ``params``, ``input_field_names``, ``output_field_names`` are pymilvus's
  (pymilvus/client/abstract.py); params ``provider``, ``model_name``,
  ``credential`` (a label for a credential in milvus.yaml, not the secret),
  ``endpoint`` / ``url`` follow https://milvus.io/docs/embedding-function-overview.md
  and https://milvus.io/docs/hugging-face-tei.md. Rerank functions are passed
  with each search request and are not stored, so they are not observable.
* list_aliases — ``describe_collection()["aliases"]`` (pymilvus
  CollectionSchema dict), falling back to ``list_aliases(collection_name)``.
* store_location — Zilliz Cloud endpoints
  ``https://{cluster-id}.serverless.{region}.vectordb.zillizcloud.com`` and
  ``https://{cluster-id}.{region}.vectordb.zillizcloud.com:19530``
  (https://docs.zilliz.com/docs/connect-to-serving-cluster). Milvus Lite (a
  local file URI) is self-hosted.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from vecshield_platform.store_facts import _selfhosted_util as u

CAPABILITIES = frozenset({"server_info", "location_introspection",
                          "egress_introspection", "aliases"})

_ZILLIZ_HOST = re.compile(
    r"^[a-z0-9-]+(?:\.serverless)?\.(?P<region>[a-z0-9-]+)\.vectordb\.zillizcloud\.com$")
_ZILLIZ_SUFFIXES = (".zillizcloud.com", ".zilliz.com")

#: Milvus TEXTEMBEDDING provider values → provider names.
_PROVIDERS = {"openai": "openai", "azure-openai": "azure_openai", "azure_openai": "azure_openai",
              "dashscope": "alibaba_dashscope", "bedrock": "aws_bedrock",
              "vertexai": "google_vertex", "voyageai": "voyageai", "voyage": "voyageai",
              "cohere": "cohere", "siliconflow": "siliconflow", "tei": "self_hosted",
              "huggingface": "huggingface", "gemini": "google", "yandex": "yandex"}
_PARAM_KEYS = ("provider", "model_name", "endpoint", "url", "region", "dim",
               "hf_provider", "truncate", "normalize")


def _client(conn: Any) -> Any:
    return getattr(conn, "_client", None)


def _uri(conn: Any) -> str:
    return str(getattr(conn, "_uri", None) or getattr(conn, "_endpoint", None) or "")


def _is_local_file(uri: str) -> bool:
    return "://" not in uri or uri.startswith("file://")


def _host(conn: Any) -> Optional[str]:
    uri = _uri(conn)
    return None if _is_local_file(uri) else u.host_of(uri)


def _is_zilliz(host: Optional[str]) -> bool:
    return host is not None and any(host.endswith(s) for s in _ZILLIZ_SUFFIXES)


def server_info(conn: Any) -> dict[str, Any]:
    host = _host(conn)
    managed = _is_zilliz(host)
    lite = _is_local_file(_uri(conn))
    try:
        text = str(_client(conn).get_server_version())
    except Exception as exc:  # noqa: BLE001
        return u.server(product="milvus", source="GetVersion (get_server_version)",
                        edition="zilliz_cloud" if managed else ("lite" if lite else None),
                        managed=managed,
                        reason=u.failed_reason(exc, "the server version",
                                               "a user allowed to call GetVersion"))
    zilliz = managed or "zilliz" in text.lower()
    parsed = u.version_tuple(text)
    version = ".".join(str(p) for p in parsed) if parsed else None
    features: dict[str, Any] = {}
    if zilliz or not version:
        features["reported"] = u.clean_text(text)
    return u.server(product="milvus", source="GetVersion (get_server_version)",
                    version=version,
                    edition="zilliz_cloud" if zilliz else ("lite" if lite else None),
                    managed=zilliz, features=features,
                    reason="" if version else "the server's version string has no version number")


def _collections(conn: Any) -> list[str]:
    return [str(c) for c in (_client(conn).list_collections() or [])]


def _describe(conn: Any, name: str) -> dict[str, Any]:
    desc = _client(conn).describe_collection(name)
    return desc if isinstance(desc, dict) else {}


def distance_metric_details(conn: Any) -> dict[str, dict[str, Any]]:
    client = _client(conn)
    out: dict[str, dict[str, Any]] = {}
    for name in _collections(conn):
        per: dict[str, Any] = {}
        try:
            for index in client.list_indexes(collection_name=name) or []:
                info = client.describe_index(collection_name=name, index_name=index) or {}
                metric = info.get("metric_type") if isinstance(info, dict) else None
                if metric is not None:
                    field = info.get("field_name") or index
                    per[str(field)] = metric
        except Exception as exc:  # noqa: BLE001
            out[name] = {"metric": None, "vector_metrics": {}, "source": "describe_index",
                         "error": u.describe_error(exc)}
            continue
        detail = u.combine(per, "describe_index.metric_type")
        if not per:
            detail["note"] = "no index, so no metric is recorded"
        out[name] = detail
    return out


def _function_type(fn: dict[str, Any]) -> str:
    raw = fn.get("type")
    name = getattr(raw, "name", None)
    if name:
        return str(name).upper()
    if isinstance(raw, int):
        return {1: "BM25", 2: "TEXTEMBEDDING", 3: "RERANK", 4: "MINHASH"}.get(raw, str(raw))
    return str(raw or "").rsplit(".", 1)[-1].upper()


def _function_entry(collection: str, fn: dict[str, Any]) -> dict[str, Any]:
    raw_params = fn.get("params")
    params: dict[str, Any] = raw_params if isinstance(raw_params, dict) else {}
    settings = u.pick(params, _PARAM_KEYS)
    provider_raw = str(settings.get("provider") or "").lower()
    endpoint = u.host_of(settings.get("endpoint") or settings.get("url"))
    provider = _PROVIDERS.get(provider_raw, provider_raw or "unknown")
    if provider == "self_hosted" and endpoint and not u.is_private_host(endpoint):
        provider = u.provider_for_host(endpoint) or "external"
    has_credential = bool(params.get("credential"))
    auth = "api_key" if has_credential else ("none" if provider == "self_hosted" else "unknown")
    evidence = {"function": u.clean_text(fn.get("name")),
                "input_fields": [str(f) for f in fn.get("input_field_names") or []],
                "output_fields": [str(f) for f in fn.get("output_field_names") or []],
                "provider_param": settings.get("provider"),
                "also_applies_at": "query"}
    evidence.update({k: v for k, v in settings.items()
                     if k not in ("provider", "model_name", "endpoint", "url")})
    return u.integration(collection=collection, stage="ingest", provider=provider,
                         model=settings.get("model_name"), endpoint_host=endpoint,
                         auth=auth, module="TEXTEMBEDDING function", evidence=evidence)


def model_integrations(conn: Any) -> dict[str, Any]:
    source = "describe_collection().functions"
    integrations: list[dict[str, Any]] = []
    try:
        names = _collections(conn)
    except Exception as exc:  # noqa: BLE001
        return u.integrations_result(
            observable=False, source=source,
            reason=u.failed_reason(exc, "the collection list",
                                   "the ShowCollections privilege"))
    failures: list[str] = []
    for name in names:
        try:
            desc = _describe(conn, name)
        except Exception as exc:  # noqa: BLE001
            failures.append(f"{name}: {u.describe_error(exc)}")
            if u.is_denied(exc):
                return u.integrations_result(
                    observable=False, source=source, integrations=integrations,
                    reason=u.denied_reason(f"collection '{name}'",
                                           "the DescribeCollection privilege on every "
                                           "collection"))
            continue
        for fn in desc.get("functions") or []:
            if isinstance(fn, dict) and _function_type(fn) == "TEXTEMBEDDING":
                integrations.append(_function_entry(name, fn))
    reason = ("TEXTEMBEDDING functions call their provider at insert and at search. "
              "Rerank functions are supplied per search request and are not stored, so "
              "they are not visible here.")
    if failures:
        reason = f"Some collections could not be described ({'; '.join(failures[:5])}). " + reason
    return u.integrations_result(observable=not failures, source=source, reason=reason,
                                 integrations=integrations)


def list_aliases(conn: Any) -> dict[str, str]:
    client = _client(conn)
    out: dict[str, str] = {}
    for name in _collections(conn):
        aliases = _describe(conn, name).get("aliases")
        if aliases is None and callable(getattr(client, "list_aliases", None)):
            resp = client.list_aliases(collection_name=name) or {}
            aliases = resp.get("aliases") if isinstance(resp, dict) else resp
        for alias in aliases or []:
            out[str(alias)] = name
    return out


def store_location(conn: Any) -> dict[str, Any]:
    source = "endpoint hostname"
    if _is_local_file(_uri(conn)):
        return u.self_hosted(source, None, local=True)
    host = _host(conn)
    if not host:
        return u.unknown_host(source, None)
    m = _ZILLIZ_HOST.match(host)
    if m:
        return u.location(
            provider="zilliz", region=m.group("region"), source=source, observable=True,
            reason="Zilliz Cloud encodes the cluster's cloud region in its endpoint.",
            evidence={"host": host,
                      "pattern_source": "https://docs.zilliz.com/docs/connect-to-serving-cluster"})
    if _is_zilliz(host):
        return u.location(provider="zilliz", region=None, source=source, observable=False,
                          evidence={"host": host},
                          reason="This Zilliz Cloud endpoint does not match the documented "
                                 "region pattern; declare the cluster's region.")
    if u.is_private_host(host):
        return u.self_hosted(source, host)
    return u.unknown_host(source, host)
