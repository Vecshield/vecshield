"""Store facts for the Vertex AI Vector Search connector (``kind = "vertex_ai"``).

Uses the connector's existing SDK handle and settings: ``connector._ai``
(the ``google.cloud.aiplatform`` module), ``_project``, ``_location`` and
``_endpoint_id``. The SDK is never ``init``-ed: every list call passes the
connector's project, location and credentials (``connector._sdk_kw()``), so
two Vertex stores in one process never read each other's project. Index facts
come from the Index resource:

* ``metadata.config.distanceMeasureType`` — SQUARED_L2_DISTANCE,
  L1_DISTANCE, DOT_PRODUCT_DISTANCE, COSINE_DISTANCE.
  https://docs.cloud.google.com/vertex-ai/docs/vector-search/configuring-indexes
* the resource name ``projects/{project}/locations/{location}/indexes/{id}``,
  whose location segment is the index's Region.
  https://cloud.google.com/vertex-ai/docs/reference/rest/v1/projects.locations.indexes

An Index stores vectors the caller computes; its configuration has no
embedding-model field, so model_integrations reports none configured.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from vecshield_platform.store_facts._managed_util import (
    as_plain,
    failure_reason,
    get,
    integrations_result,
    location,
    normalize_metric,
    server,
)

#: Store facts this adapter answers (read by store_facts.supported()).
CAPABILITIES = frozenset({"server_info", "location_introspection", "egress_introspection"})

_PERMISSION = ("the aiplatform.indexes.list and aiplatform.indexes.get permissions "
               "(for example roles/aiplatform.viewer)")

_LOCATION = re.compile(r"(?:^|/)projects/[^/]+/locations/(?P<loc>[^/]+)/")


def _indexes(connector: Any) -> list[Any]:
    sdk = getattr(connector, "_ai", None)
    if sdk is None:
        raise AttributeError("the Vertex AI connector has no SDK handle (_ai)")
    sdk_kw = getattr(connector, "_sdk_kw", None)
    kw = sdk_kw() if callable(sdk_kw) else {}
    return list(sdk.MatchingEngineIndex.list(**kw))


def _index_id(idx: Any) -> Optional[str]:
    name = getattr(idx, "name", None)
    return str(name) if name else None


def _resource_name(idx: Any) -> Optional[str]:
    name = getattr(idx, "resource_name", None) or get(as_plain(idx), "name")
    return str(name) if name else None


def _config(idx: Any) -> Any:
    """``metadata.config`` from the SDK resource, its dict form or raw proto."""
    plain = as_plain(idx)
    config = get(plain, "metadata", "config") if isinstance(plain, dict) else None
    if config is None:
        config = get(idx, "metadata", "config")
    if config is None:
        config = get(getattr(idx, "_gca_resource", None), "metadata", "config")
    return config


def _metric(idx: Any) -> Optional[str]:
    config = _config(idx)
    raw = get(config, "distanceMeasureType")
    if raw is None:
        raw = get(config, "distance_measure_type")
    return normalize_metric(raw)


def _region_of(resource_name: Optional[str]) -> Optional[str]:
    match = _LOCATION.search(resource_name or "")
    return match.group("loc") if match else None


def server_info(connector: Any) -> dict[str, Any]:
    features: dict[str, Any] = {
        "project": getattr(connector, "_project", None),
        "location": getattr(connector, "_location", None),
        "query_endpoint_configured": bool(getattr(connector, "_endpoint_id", None)),
        "sdk_version": getattr(getattr(connector, "_ai", None), "__version__", None)}
    reason = "Vertex AI is a managed service and does not expose a server version."
    try:
        indexes = _indexes(connector)
    except Exception as exc:  # noqa: BLE001
        return server(product="vertex_ai_vector_search", source="indexes.list",
                      features=features,
                      reason=reason + " " + failure_reason(exc, "the index list",
                                                          _PERMISSION))
    details = {}
    for idx in indexes:
        plain = as_plain(idx)
        plain = plain if isinstance(plain, dict) else {}
        details[_index_id(idx) or "?"] = {
            "index_update_method": plain.get("indexUpdateMethod")
            or get(idx, "index_update_method"),
            "deployed_index_count": len(plain.get("deployedIndexes") or []),
            "feature_norm_type": get(_config(idx), "featureNormType")}
    features["indexes"] = details
    return server(product="vertex_ai_vector_search", source="indexes.list",
                  features=features, reason=reason)


def store_location(connector: Any) -> dict[str, Any]:
    try:
        indexes = _indexes(connector)
    except Exception as exc:  # noqa: BLE001
        configured = getattr(connector, "_location", None)
        return location(provider="gcp", region=None, source="resource_name",
                        observable=False,
                        evidence={"configured_location": configured},
                        reason=failure_reason(exc, "the index list", _PERMISSION))
    regions = {}
    for idx in indexes:
        region = _region_of(_resource_name(idx))
        if region:
            regions[_index_id(idx) or "?"] = region
    distinct = sorted(set(regions.values()))
    if len(distinct) == 1:
        return location(provider="gcp", region=distinct[0], source="resource_name",
                        observable=True, evidence={"indexes": regions},
                        reason="the index resource names carry their Region")
    if len(distinct) > 1:  # not expected: a list call is regional
        return location(provider="gcp", region=None, source="resource_name",
                        observable=True, evidence={"indexes": regions,
                                                   "regions": distinct},
                        reason="The indexes are in more than one Region; each is "
                               "listed in evidence.")
    configured = getattr(connector, "_location", None)
    if configured:
        # No index to read, but the SDK lists from the regional endpoint of the
        # location the connector passes, which is where indexes would live.
        return location(provider="gcp", region=str(configured), source="client_location",
                        observable=True, evidence={"indexes": {}},
                        reason="No index exists yet; the Region is the location the "
                               "client is configured for.")
    return location(provider="gcp", region=None, source="resource_name",
                    observable=False, reason="No index and no configured location.")


def model_integrations(connector: Any) -> dict[str, Any]:
    return integrations_result(
        observable=True, source="Index resource schema",
        reason="Vector Search indexes store vectors the caller computes; the index "
               "configuration has no embedding or reranking model. Other Vertex AI "
               "products that embed on the customer's behalf (for example RAG Engine "
               "corpora) are not read by this connector.",
        integrations=[], controls={})


def distance_metrics(connector: Any) -> dict[str, Optional[str]]:
    """Index id (the connector's collection name) → metric."""
    try:
        indexes = _indexes(connector)
    except Exception:  # noqa: BLE001 - reported by store_location/server_info
        return {}
    return {iid: _metric(idx) for idx in indexes if (iid := _index_id(idx))}
