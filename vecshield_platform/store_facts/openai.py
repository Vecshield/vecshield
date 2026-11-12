"""Store facts for the OpenAI Vector Stores connector (``kind = "openai"``).

Uses the connector's existing client, ``connector._c`` (``openai.OpenAI``),
and only its ``base_url``; no request is sent.

* Data residency is configured per project when the project is created, and
  requests to such a project use a regional domain prefix
  (``eu.api.openai.com``, ``us.``, ``au.``, ``ca.``, ``jp.``, ``in.``, ``sg.``,
  ``kr.``, ``gb.``, ``ae.``). A prefixed domain can also be used with a
  Global project's key to select regional *processing* per request, so the
  domain alone does not establish where a project *stores* vector stores.
  https://developers.openai.com/api/docs/guides/your-data
* Files added to a vector store are chunked and embedded by OpenAI, and
  search / file_search embeds the query, so both stages send text to an
  OpenAI-hosted embedding model. The API does not report which model.

OpenAI does not expose embeddings or a similarity metric: distance_metrics
returns an empty mapping.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from vecshield_platform.store_facts._managed_util import (
    host_of,
    integration,
    integrations_result,
    location,
    server,
)

#: Store facts this adapter answers (read by store_facts.supported()).
CAPABILITIES = frozenset({"server_info", "location_introspection", "egress_introspection"})

_RESIDENCY_DOC = "https://developers.openai.com/api/docs/guides/your-data"
_REGIONAL_HOST = re.compile(r"^(?P<prefix>us|eu|au|ca|jp|in|sg|kr|gb|ae)\.api\.openai\.com$")


def _api_host(connector: Any) -> Optional[str]:
    return host_of(getattr(getattr(connector, "_c", None), "base_url", None))


def server_info(connector: Any) -> dict[str, Any]:
    features: dict[str, Any] = {"api_host": _api_host(connector)}
    try:
        import openai as sdk  # the installed SDK, not this module
        features["sdk_version"] = getattr(sdk, "__version__", None)
    except Exception:  # noqa: BLE001
        features["sdk_version"] = None
    return server(product="openai_vector_stores", source="client configuration",
                  features=features,
                  reason="OpenAI's API is a managed service and does not expose a "
                         "server version.")


def store_location(connector: Any) -> dict[str, Any]:
    host = _api_host(connector)
    evidence: dict[str, Any] = {"api_host": host, "source_url": _RESIDENCY_DOC}
    match = _REGIONAL_HOST.match(host or "")
    if match:
        evidence["request_region_prefix"] = match.group("prefix")
        reason = (f"The client uses OpenAI's '{match.group('prefix')}' regional domain. "
                  "That selects regional processing for requests; where the project "
                  "stores vector stores is set on the project in the OpenAI dashboard "
                  "and is not reported by the API. OpenAI documents File Search "
                  "processing in the United States and Europe only.")
    elif host == "api.openai.com":
        reason = ("OpenAI sets data residency per project in the dashboard and the "
                  "API does not report it; this client uses the global "
                  "api.openai.com domain.")
    else:
        reason = (f"The client's base URL ({host or 'unset'}) is not an OpenAI API "
                  "domain, so OpenAI's residency settings cannot be inferred from it.")
    return location(provider="openai", region=None, source="base_url",
                    observable=False, reason=reason, evidence=evidence)


def model_integrations(connector: Any) -> dict[str, Any]:
    host = _api_host(connector)
    evidence = {"hosting": "OpenAI-hosted embedding model",
                "model_reported": False,
                "note": "the API does not report which embedding model is used"}
    found = [integration(collection=None, stage=stage, provider="openai", model=None,
                         endpoint_host=host, auth="none", module="vector_store_embedding",
                         evidence=evidence)
             for stage in ("ingest", "query")]
    return integrations_result(
        observable=True, source="OpenAI vector store behaviour (documented)",
        integrations=found,
        reason="OpenAI embeds every file added to a vector store and every search "
               "query; this is how the service works, not a per-store setting.",
        controls={"ranker": "chosen per search / file_search request "
                            "(ranking_options), not stored on the vector store",
                  "chunking": "chunking_strategy is set per file when it is added"})


def distance_metrics(connector: Any) -> dict[str, Optional[str]]:
    """OpenAI does not report a similarity metric: nothing is known."""
    return {}
