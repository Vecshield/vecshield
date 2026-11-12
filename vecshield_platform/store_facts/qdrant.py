"""Store facts for :class:`~vecshield_platform.connectors.qdrant.QdrantConnector`.

Connector attributes read: ``_client`` (qdrant_client.QdrantClient) and
``_endpoint`` (the credential-redacted URL).

* server_info — ``GET /`` via ``client.info()`` (title, version, commit).
* distance metrics — ``GET /collections/{name}``: ``config.params.vectors``
  (one ``VectorParams`` or a dict of named vectors; ``Distance`` is Cosine,
  Euclid, Dot or Manhattan). Sparse vectors have no distance and are skipped.
* store_location — Qdrant Cloud hostnames encode region and cloud:
  ``https://xyz-example.eu-central.aws.cloud.qdrant.io``
  (https://qdrant.tech/documentation/cloud-quickstart/). The region label is
  Qdrant's, taken from the hostname as written.
* model_integrations — Qdrant Cloud Inference and external providers (OpenAI,
  Cohere, Jina, OpenRouter) are chosen per request and API keys are sent with
  each request; nothing is stored in collection configuration
  (https://qdrant.tech/documentation/inference/external-inference-providers/),
  so this is reported as not observable.
* list_aliases — ``GET /aliases`` via ``client.get_aliases()``.
"""

from __future__ import annotations

import re
from typing import Any

from vecshield_platform.store_facts import _selfhosted_util as u

CAPABILITIES = frozenset({"server_info", "location_introspection",
                          "egress_introspection", "aliases"})

#: https://qdrant.tech/documentation/cloud-quickstart/
_CLOUD_HOST = re.compile(
    r"^[a-z0-9-]+\.(?P<region>[a-z0-9-]+)\.(?P<cloud>aws|gcp|azure)\.cloud\.qdrant\.io$")


def _client(conn: Any) -> Any:
    return getattr(conn, "_client", None)


def _host(conn: Any) -> Any:
    return u.host_of(getattr(conn, "_endpoint", None))


def _is_cloud(host: Any) -> bool:
    return bool(host) and (host == "cloud.qdrant.io" or host.endswith(".cloud.qdrant.io"))


def server_info(conn: Any) -> dict[str, Any]:
    client = _client(conn)
    managed = _is_cloud(_host(conn))
    edition = "qdrant_cloud" if managed else None
    info = None
    try:
        fn = getattr(client, "info", None)
        if callable(fn):
            info = fn()
        else:  # older qdrant-client: the generated REST root call
            info = client.http.service_api.root()
    except Exception as exc:  # noqa: BLE001
        return u.server(product="qdrant", source="GET /", edition=edition, managed=managed,
                        reason=u.failed_reason(exc, "the server version", "read access to GET /"))
    version = u.get(info, "version") or u.get(info, "result", "version")
    commit = u.get(info, "commit") or u.get(info, "result", "commit")
    return u.server(product="qdrant", source="GET /", version=str(version) if version else None,
                    edition=edition, managed=managed,
                    reason="" if version else "GET / returned no version",
                    features={"commit": str(commit)} if commit else {})


def distance_metric_details(conn: Any) -> dict[str, dict[str, Any]]:
    client = _client(conn)
    out: dict[str, dict[str, Any]] = {}
    for col in u.get(client.get_collections(), "collections", default=[]):
        name = u.get(col, "name")
        if not name:
            continue
        try:
            info = client.get_collection(name)
        except Exception as exc:  # noqa: BLE001
            out[name] = {"metric": None, "vector_metrics": {},
                         "source": "GET /collections/{name}", "error": u.describe_error(exc)}
            continue
        vectors = u.get(info, "config", "params", "vectors")
        if vectors is None:
            per: dict[str, Any] = {}
        elif isinstance(vectors, dict):
            per = {str(k): u.get(v, "distance") for k, v in vectors.items()}
        else:
            per = {"": u.get(vectors, "distance")}
        out[name] = u.combine(per, "config.params.vectors.distance")
    return out


def store_location(conn: Any) -> dict[str, Any]:
    source = "endpoint hostname"
    host = _host(conn)
    if not host:
        return u.unknown_host(source, None)
    m = _CLOUD_HOST.match(host)
    if m:
        return u.location(
            provider="qdrant_cloud", region=m.group("region"), source=source,
            observable=True,
            reason="Qdrant Cloud encodes the cluster's region and cloud in its hostname.",
            evidence={"host": host, "cloud": m.group("cloud"),
                      "region_note": "Qdrant's region label as written in the hostname",
                      "pattern_source": "https://qdrant.tech/documentation/cloud-quickstart/"})
    if _is_cloud(host):
        return u.location(provider="qdrant_cloud", region=None, source=source,
                          observable=False, evidence={"host": host},
                          reason="This Qdrant Cloud hostname does not match the documented "
                                 "region pattern; declare the cluster's region.")
    if u.is_private_host(host):
        return u.self_hosted(source, host)
    return u.unknown_host(source, host)


def model_integrations(conn: Any) -> dict[str, Any]:
    cloud = _is_cloud(_host(conn))
    reason = ("Qdrant chooses an inference model per request: Cloud Inference and external "
              "providers (OpenAI, Cohere, Jina, OpenRouter) are named in each upsert or "
              "query, with the provider key sent per request. Collection configuration "
              "does not record them, so whether text leaves the store cannot be read "
              "here; review the applications' Qdrant requests.")
    if not cloud:
        reason += " Qdrant Cloud documents these features for managed clusters."
    return u.integrations_result(observable=False, reason=reason,
                                 source="collection configuration")


def list_aliases(conn: Any) -> dict[str, str]:
    resp = _client(conn).get_aliases()
    out: dict[str, str] = {}
    for alias in u.get(resp, "aliases", default=[]):
        name = u.get(alias, "alias_name")
        target = u.get(alias, "collection_name")
        if name and target:
            out[str(name)] = str(target)
    return out
