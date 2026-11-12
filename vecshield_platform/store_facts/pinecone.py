"""Store facts for the Pinecone connector (``kind = "pinecone"``).

Reads only the control plane (``list_indexes`` / ``describe_index``) through
the connector's existing client, ``connector._pc``. Two response shapes are
handled, because the connector supports both:

* API versions up to 2025-10: top-level ``metric``, ``deletion_protection``,
  ``spec.serverless.{cloud,region}`` / ``spec.pod.environment`` /
  ``spec.byoc.environment`` and, for integrated embedding, ``embed.{model,
  metric, field_map}``.
  https://docs.pinecone.io/reference/api/2025-10/control-plane/describe_index
* API version 2026-07: ``deployment.{deployment_type, cloud, region,
  environment}`` and ``schema.fields`` (``dense_vector`` with ``metric``;
  ``semantic_text`` with ``model`` for integrated embedding).
  https://docs.pinecone.io/reference/api/latest/control-plane/describe_index

Location decision: ``provider`` is ``"pinecone"``, not the hosting cloud.
Pinecone is the party that holds the data (the processor the customer
contracts with); AWS, GCP or Azure is Pinecone's sub-processor. The hosting
cloud is kept in ``evidence["cloud"]`` so a residency check can still read it.
"""

from __future__ import annotations

from typing import Any, Optional

from vecshield_platform.store_facts._managed_util import (
    failure_reason,
    get,
    integration,
    integrations_result,
    location,
    normalize_metric,
    server,
)

#: Store facts this adapter answers (read by store_facts.supported()).
CAPABILITIES = frozenset({"server_info", "location_introspection", "egress_introspection"})

_PERMISSION = ("an API key with control-plane read access to the project "
               "(the ControlPlaneViewer role or higher)")

_POD_ENV_DOC = ("https://docs.pinecone.io/guides/indexes/pods/"
                "understanding-pod-based-indexes")

#: Pod-based environments → (cloud, provider region id), from Pinecone's
#: documented environment table (_POD_ENV_DOC). Pinecone labels the GCP
#: Belgium and Netherlands environments "eu-west1"/"eu-west4"; GCP's own
#: region identifiers for those locations are europe-west1 and europe-west4.
#: An environment not in this table is reported as-is with region None.
_POD_ENVIRONMENTS: dict[str, tuple[str, str]] = {
    "us-west1-gcp": ("gcp", "us-west1"),
    "us-central1-gcp": ("gcp", "us-central1"),
    "us-west4-gcp": ("gcp", "us-west4"),
    "us-east4-gcp": ("gcp", "us-east4"),
    "northamerica-northeast1-gcp": ("gcp", "northamerica-northeast1"),
    "asia-northeast1-gcp": ("gcp", "asia-northeast1"),
    "asia-southeast1-gcp": ("gcp", "asia-southeast1"),
    "us-east1-gcp": ("gcp", "us-east1"),
    "eu-west1-gcp": ("gcp", "europe-west1"),
    "eu-west4-gcp": ("gcp", "europe-west4"),
    "us-east-1-aws": ("aws", "us-east-1"),
    "eastus-azure": ("azure", "eastus"),
}


def _client(connector: Any) -> Any:
    client = getattr(connector, "_pc", None)
    if client is None:
        raise AttributeError("the Pinecone connector has no client (_pc)")
    return client


def _indexes(connector: Any) -> list[Any]:
    listed = _client(connector).list_indexes()
    inner = get(listed, "indexes")
    if inner is not None and not isinstance(listed, list):
        listed = inner
    return list(listed or [])


def _name(desc: Any) -> Optional[str]:
    name = get(desc, "name")
    return str(name) if name else None


def _deployment(desc: Any) -> dict[str, Any]:
    """Deployment type, cloud, region and environment of one index."""
    spec = get(desc, "spec")
    if spec is not None:
        serverless = get(spec, "serverless")
        if serverless is not None:
            return {"index_type": "serverless", "cloud": get(serverless, "cloud"),
                    "region": get(serverless, "region"), "environment": None}
        pod = get(spec, "pod")
        if pod is not None:
            return {"index_type": "pod", "environment": get(pod, "environment"),
                    "cloud": None, "region": None}
        byoc = get(spec, "byoc")
        if byoc is not None:
            return {"index_type": "byoc", "environment": get(byoc, "environment"),
                    "cloud": None, "region": None}
    dep = get(desc, "deployment")
    if dep is not None:
        kind = get(dep, "deployment_type")
        if kind is None:  # SDK v10 tagged struct: the tag is not an attribute
            config = getattr(type(dep), "__struct_config__", None)
            kind = getattr(config, "tag", None) or type(dep).__name__
        kind = str(kind).lower()
        if "pod" in kind or get(dep, "pod_type") is not None:
            index_type = "pod"
        elif "byoc" in kind:
            index_type = "byoc"
        elif "managed" in kind or "serverless" in kind or get(dep, "cloud"):
            index_type = "serverless"
        else:
            index_type = None
        return {"index_type": index_type, "cloud": get(dep, "cloud"),
                "region": get(dep, "region"), "environment": get(dep, "environment")}
    return {"index_type": None, "cloud": None, "region": None, "environment": None}


def _fields(desc: Any) -> list[tuple[str, Any]]:
    fields = get(desc, "schema", "fields")
    if isinstance(fields, dict):
        return list(fields.items())
    items = getattr(fields, "items", None)
    if callable(items):
        try:
            return list(items())
        except Exception:  # noqa: BLE001
            return []
    return []


def _field_type(field: Any) -> Optional[str]:
    kind = get(field, "type")
    if kind is None:
        config = getattr(type(field), "__struct_config__", None)
        kind = getattr(config, "tag", None)
    if kind is None:
        cls = type(field).__name__
        kind = {"DenseVectorField": "dense_vector",
                "SemanticTextField": "semantic_text"}.get(cls)
    return str(kind) if kind else None


def _metric(desc: Any) -> Optional[str]:
    """The index's similarity metric; None when several fields disagree."""
    top = get(desc, "metric")
    if top is not None:
        return normalize_metric(top)
    embed_metric = get(desc, "embed", "metric")
    if embed_metric is not None:
        return normalize_metric(embed_metric)
    seen = set()
    for _fname, field in _fields(desc):
        if _field_type(field) in ("dense_vector", "semantic_text"):
            raw = get(field, "metric")
            if raw is not None:
                seen.add(normalize_metric(raw))
    return seen.pop() if len(seen) == 1 else None


def _embedders(desc: Any) -> list[dict[str, Any]]:
    """Integrated-embedding configurations on one index."""
    out = []
    embed = get(desc, "embed")
    if embed is not None and get(embed, "model"):
        field_map = get(embed, "field_map")
        out.append({"model": str(get(embed, "model")), "field": None,
                    "field_map": dict(field_map) if isinstance(field_map, dict) else None,
                    "source": "index.embed"})
    for fname, field in _fields(desc):
        if _field_type(field) == "semantic_text" and get(field, "model"):
            out.append({"model": str(get(field, "model")), "field": str(fname),
                        "field_map": None, "source": "index.schema.fields"})
    return out


def _api_version() -> Optional[str]:
    """The control-plane API version the installed SDK sends, if it says."""
    for module in ("pinecone.core.openapi.db_control", "pinecone.openapi_support",
                   "pinecone.core.openapi.shared"):
        try:
            mod = __import__(module, fromlist=["API_VERSION"])
        except Exception:  # noqa: BLE001
            continue
        version = getattr(mod, "API_VERSION", None)
        if version:
            return str(version)
    return None


def _sdk_version() -> Optional[str]:
    try:
        import pinecone  # type: ignore[import-not-found,unused-ignore]
    except Exception:  # noqa: BLE001
        return None
    return getattr(pinecone, "__version__", None)


def _deletion_protection(desc: Any) -> Optional[str]:
    value = get(desc, "deletion_protection")
    return None if value is None else str(getattr(value, "value", value))


def server_info(connector: Any) -> dict[str, Any]:
    features: dict[str, Any] = {"api_version": _api_version(),
                                "sdk_version": _sdk_version()}
    try:
        indexes = _indexes(connector)
    except Exception as exc:  # noqa: BLE001
        return server(product="pinecone", source="list_indexes", features=features,
                      reason="Pinecone does not expose a server version. "
                             + failure_reason(exc, "the index list", _PERMISSION))
    features["indexes"] = {
        _name(d): {"index_type": _deployment(d)["index_type"],
                   "deletion_protection": _deletion_protection(d)}
        for d in indexes if _name(d)}
    return server(product="pinecone", source="list_indexes", features=features,
                  reason="Pinecone is a managed service and does not expose a "
                         "server version.")


def store_location(connector: Any) -> dict[str, Any]:
    source = "list_indexes: spec/deployment"
    try:
        indexes = _indexes(connector)
    except Exception as exc:  # noqa: BLE001
        return location(provider="pinecone", region=None, source=source,
                        observable=False,
                        reason=failure_reason(exc, "the index list", _PERMISSION))
    if not indexes:
        return location(provider="pinecone", region=None, source=source,
                        observable=False,
                        reason="The project has no indexes. Pinecone sets the "
                               "location per index.")
    per_index: dict[str, dict[str, Any]] = {}
    for desc in indexes:
        dep = _deployment(desc)
        entry = {"index_type": dep["index_type"], "cloud": dep["cloud"],
                 "region": dep["region"]}
        env = dep["environment"]
        if env:
            entry["environment"] = env
            mapped = _POD_ENVIRONMENTS.get(str(env)) if dep["index_type"] == "pod" else None
            if mapped:
                entry["cloud"], entry["region"] = mapped
                entry["region_basis"] = _POD_ENV_DOC
        per_index[_name(desc) or "?"] = entry
    places = {(e["cloud"], e["region"]) for e in per_index.values()}
    evidence: dict[str, Any] = {"indexes": per_index}
    if len(places) == 1:
        cloud, region = next(iter(places))
        evidence["cloud"] = cloud
        if region:
            return location(provider="pinecone", region=str(region), source=source,
                            observable=True, evidence=evidence,
                            reason="every index reports the same cloud and region")
        return location(provider="pinecone", region=None, source=source,
                        observable=False, evidence=evidence,
                        reason="The indexes do not report a region Pinecone "
                               "documents (BYOC or an undocumented pod "
                               "environment). See evidence for what each reports.")
    evidence["regions"] = sorted(f"{c or '?'}:{r or '?'}" for c, r in places)
    return location(provider="pinecone", region=None, source=source, observable=True,
                    evidence=evidence,
                    reason="The indexes are in more than one cloud or region; each "
                           "is listed in evidence. No single region applies.")


def model_integrations(connector: Any) -> dict[str, Any]:
    source = "list_indexes: embed / schema.fields[semantic_text]"
    try:
        indexes = _indexes(connector)
    except Exception as exc:  # noqa: BLE001
        return integrations_result(observable=False, source=source,
                                   reason=failure_reason(exc, "the index list",
                                                         _PERMISSION))
    found = []
    for desc in indexes:
        iname = _name(desc)
        for emb in _embedders(desc):
            evidence = {"configured_in": emb["source"], "hosting": "Pinecone Inference"}
            if emb["field"]:
                evidence["field"] = emb["field"]
            if emb["field_map"]:
                evidence["field_map"] = emb["field_map"]
            # Integrated embedding runs on upsert (records are embedded) and on
            # text search (the query is embedded), so both stages apply.
            # https://docs.pinecone.io/guides/index-data/indexing-overview
            for stage in ("ingest", "query"):
                found.append(integration(
                    collection=iname, stage=stage, provider="pinecone",
                    model=emb["model"], endpoint_host=None, auth="none",
                    module="integrated_embedding", evidence=evidence))
    return integrations_result(
        observable=True, source=source, integrations=found,
        reason=("Integrated embedding is configured on "
                f"{len({i['collection'] for i in found})} index(es)." if found
                else "No index has integrated embedding configured."),
        controls={"rerank": "chosen per search request, not stored on the index",
                  "credential": "none: Pinecone calls its own hosted inference"})


def distance_metrics(connector: Any) -> dict[str, Optional[str]]:
    """Collection name → metric, keyed as the connector names collections:
    the index name and "index/namespace" for each non-default namespace
    (namespaces share their index's metric). An unreadable index list yields
    an empty mapping (nothing known)."""
    try:
        indexes = _indexes(connector)
    except Exception:  # noqa: BLE001 - reported by store_location/server_info
        return {}
    out: dict[str, Optional[str]] = {}
    for desc in indexes:
        name = _name(desc)
        if not name:
            continue
        metric = out[name] = _metric(desc)
        for ns in _namespaces(connector, name):
            out[f"{name}/{ns}"] = metric
    return out


def _namespaces(connector: Any, index: str) -> list[str]:
    """Non-default namespaces of an index, named as the connector names them.

    Best effort: a failed stats call leaves only the index-level key.
    """
    try:
        opener = getattr(connector, "_index", None)
        handle = opener(index) if callable(opener) else _client(connector).Index(index)
        stats = handle.describe_index_stats()
    except Exception:  # noqa: BLE001
        return []
    namespaces = get(stats, "namespaces") or {}
    keys = namespaces.keys() if hasattr(namespaces, "keys") else []
    return sorted(str(ns) for ns in keys if ns not in ("", None))
