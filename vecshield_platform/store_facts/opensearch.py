"""Store facts for :class:`~vecshield_platform.connectors.opensearch.OpenSearchConnector`.

Connector attributes read: ``_c`` (opensearch-py ``OpenSearch``) and
``_endpoint`` (credential-redacted URL or ``http(s)://host:port``).

* server_info — ``GET /`` (``version.number``, ``version.distribution``) and
  ``GET _cat/plugins?format=json`` (component → version) when permitted.
* distance metrics — ``GET <index>/_mapping``: ``knn_vector`` fields'
  ``space_type`` at the field level or under ``method`` (both are documented:
  documentation-website ``_mappings/supported-field-types/knn-spaces.md``).
  Spaces l2, l1, linf, cosinesimil, innerproduct, hamming, hammingbit;
  linf and the hamming spaces have no slot → None. The docs state no default,
  so an unset space_type is None.
* model_integrations — ML Commons: ``POST /_plugins/_ml/connectors/_search``
  (``protocol``, ``parameters``, ``actions[].url``; response shape in
  https://docs.opensearch.org/latest/ml-commons-plugin/api/connector-apis/search-connector/),
  ``POST /_plugins/_ml/models/_search`` (model → connector),
  ``GET _ingest/pipeline`` and ``GET _search/pipeline`` processors that name a
  model, index ``default_pipeline`` / ``search.default_pipeline`` settings for
  collection attribution, and the cluster setting
  ``plugins.ml_commons.trusted_connector_endpoints_regex`` as a control.
  Connector ``credential`` and action ``headers`` are never read into the
  result; only the *names* of credential fields decide ``auth``.
* list_aliases — ``GET _alias``. An alias over several indices maps to their
  comma-joined, sorted names.
* store_location — Amazon OpenSearch Service domain endpoints
  ``search-<domain>-<id>.<region>.es.amazonaws.com``
  (https://docs.aws.amazon.com/opensearch-service/latest/developerguide/createupdatedomains.html)
  and their ``vpc-`` form
  (https://docs.aws.amazon.com/opensearch-service/latest/developerguide/vpc.html);
  OpenSearch Serverless ``<collection-id>.<region>.aoss.amazonaws.com`` and
  ``<id>.aoss.<region>.on.aws``
  (https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-collection-endpoints.html).
"""

from __future__ import annotations

import re
from typing import Any, Optional

from vecshield_platform.store_facts import _selfhosted_util as u

CAPABILITIES = frozenset({"server_info", "location_introspection",
                          "egress_introspection", "aliases"})

_REGION = r"(?P<region>[a-z]{2}(?:-[a-z]+)+-\d)"
_DOMAIN_HOST = re.compile(r"^(?:search|vpc)-[a-z][a-z0-9-]*\." + _REGION
                          + r"\.es\.amazonaws\.com(?:\.cn)?$")
_AOSS_CLASSIC = re.compile(r"^[a-z0-9]+\." + _REGION + r"\.aoss\.amazonaws\.com$")
_AOSS_NEXTGEN = re.compile(r"^[a-z0-9]+\.aoss\." + _REGION + r"\.on\.aws$")

_TRUSTED = "plugins.ml_commons.trusted_connector_endpoints_regex"

#: Search-pipeline processor → stage; any other model-calling one is "query".
_RESPONSE_STAGES = {"retrieval_augmented_generation": "generate", "rerank": "rerank",
                    "ml_inference": "query"}


def _c(conn: Any) -> Any:
    return getattr(conn, "_c", None)


def _host(conn: Any) -> Optional[str]:
    return u.host_of(getattr(conn, "_endpoint", None))


def _aws_edition(host: Optional[str]) -> Optional[str]:
    if not host:
        return None
    if _DOMAIN_HOST.match(host) or host.endswith(".es.amazonaws.com"):
        return "aws_opensearch_service"
    if (_AOSS_CLASSIC.match(host) or _AOSS_NEXTGEN.match(host)
            or host.endswith(".aoss.amazonaws.com")):
        return "aws_opensearch_serverless"
    return None


def _request(conn: Any, method: str, path: str, body: Any = None) -> Any:
    transport = u.get(_c(conn), "transport")
    if body is None:
        return transport.perform_request(method, path)
    return transport.perform_request(method, path, body=body)


# -------------------------------------------------------------- server info #

def server_info(conn: Any) -> dict[str, Any]:
    edition = _aws_edition(_host(conn))
    managed = edition is not None
    try:
        info = _c(conn).info() or {}
    except Exception as exc:  # noqa: BLE001
        return u.server(product="opensearch", source="GET /", edition=edition,
                        managed=managed,
                        reason=u.failed_reason(exc, "GET /", "cluster:monitor/main"))
    version = u.get(info, "version", "number")
    distribution = u.get(info, "version", "distribution")
    tagline = str(info.get("tagline", "")).lower()
    product = ("opensearch" if distribution == "opensearch" or "opensearch" in tagline
               else "elasticsearch" if not distribution else str(distribution))
    features: dict[str, Any] = {}
    reason = ""
    if not distribution:
        reason = ("GET / reported no distribution: this is Elasticsearch, or OpenSearch in "
                  "compatibility mode reporting 7.10.")
    try:
        rows = _c(conn).cat.plugins(format="json") or []
        plugins = {str(r.get("component")): str(r.get("version") or "")
                   for r in rows if isinstance(r, dict) and r.get("component")}
        features["plugins"] = dict(sorted(plugins.items()))
    except Exception as exc:  # noqa: BLE001
        reason = (reason + " " if reason else "") + u.failed_reason(
            exc, "_cat/plugins", "cluster:monitor/nodes/info")
    return u.server(product=product, source="GET /; GET _cat/plugins",
                    version=str(version) if version else None, edition=edition,
                    managed=managed, features=features, reason=reason)


# ------------------------------------------------------------------ metrics #

def knn_fields(props: Any, prefix: str = "") -> dict[str, dict[str, Any]]:
    """Every ``knn_vector`` field in a mapping's ``properties``, by dotted path.

    Recurses into object and ``nested`` properties, so a vector inside a
    nested document (``chunks.embedding``) is found as well as a top-level
    one. Shared with the connector, which reads vectors at these paths.
    """
    out: dict[str, dict[str, Any]] = {}
    for name, spec in (props or {}).items():
        if not isinstance(spec, dict):
            continue
        path = f"{prefix}.{name}" if prefix else str(name)
        if spec.get("type") == "knn_vector":
            out[path] = spec
        if isinstance(spec.get("properties"), dict):
            out.update(knn_fields(spec["properties"], path))
    return out


def distance_metric_details(conn: Any) -> dict[str, dict[str, Any]]:
    mappings = _c(conn).indices.get_mapping(index="*") or {}
    out: dict[str, dict[str, Any]] = {}
    for index, body in mappings.items():
        if str(index).startswith("."):
            continue
        props = u.get(body, "mappings", "properties", default={})
        fields = knn_fields(props)
        if not fields:
            continue  # not a vector index: not a collection
        per: dict[str, Any] = {}
        unset: list[str] = []
        for path, spec in fields.items():
            space = spec.get("space_type") or u.get(spec, "method", "space_type")
            per[path] = space
            if space is None:
                unset.append(path)
        detail = u.combine(per, "mapping knn_vector space_type")
        if unset:
            detail["note"] = ("space_type is not set on " + ", ".join(unset)
                              + " (a trained model or the engine default decides it)")
        out[str(index)] = detail
    return out


# ------------------------------------------------------------- integrations #

def _hits(resp: Any) -> list[dict[str, Any]]:
    return [h for h in u.get(resp, "hits", "hits", default=[]) if isinstance(h, dict)]


def _substitute(url: str, params: dict[str, Any]) -> str:
    def repl(m: re.Match) -> str:
        value = params.get(m.group(1))
        return str(value) if isinstance(value, (str, int, float)) else m.group(0)
    return re.sub(r"\$\{parameters\.([A-Za-z0-9_]+)\}", repl, url)


def _connector_facts(source: dict[str, Any]) -> dict[str, Any]:
    """Provider, endpoint, model and auth of one ML connector — no credentials."""
    raw_params = source.get("parameters")
    params: dict[str, Any] = raw_params if isinstance(raw_params, dict) else {}
    hosts: list[str] = []
    for action in source.get("actions") or []:
        url = action.get("url") if isinstance(action, dict) else None
        if isinstance(url, str):
            host = u.host_of(_substitute(url, params))
            if host and host not in hosts:
                hosts.append(host)
    if not hosts and isinstance(params.get("endpoint"), str):
        host = u.host_of(params["endpoint"])
        if host:
            hosts.append(host)
    provider = next((p for p in (u.provider_for_host(h) for h in hosts) if p), None)
    if provider is None:
        provider = "external" if hosts else "unknown"
    credential_names = {str(k).lower() for k in (source.get("credential") or {})} \
        if isinstance(source.get("credential"), dict) else set()
    if "rolearn" in credential_names:
        auth = "managed_identity"
    elif credential_names:
        auth = "api_key"
    else:
        auth = "unknown"
    model = params.get("model") or params.get("model_name") or params.get("model_id")
    return {"provider": provider, "endpoint_host": hosts[0] if hosts else None,
            "all_hosts": hosts, "model": model, "auth": auth,
            "protocol": source.get("protocol"), "name": source.get("name"),
            "region": params.get("region") if isinstance(params.get("region"), str) else None}


def _pipeline_models(pipeline: dict[str, Any], keys: tuple[str, ...]) -> list[tuple[str, str]]:
    """(processor, model_id) for model-calling processors under ``keys``."""
    found: list[tuple[str, str]] = []
    for key in keys:
        for proc in pipeline.get(key) or []:
            if not isinstance(proc, dict):
                continue
            for pname, cfg in proc.items():
                if not isinstance(cfg, dict):
                    continue
                model_id = (cfg.get("model_id") or cfg.get("default_model_id")
                            or u.get(cfg, "ml_opensearch", "model_id"))
                if model_id:
                    found.append((str(pname), str(model_id)))
    return found


def model_integrations(conn: Any) -> dict[str, Any]:
    c = _c(conn)
    problems: list[str] = []
    sources: list[str] = []
    controls: dict[str, Any] = {}

    # Connectors
    connectors: dict[str, dict[str, Any]] = {}
    ml_missing = False
    try:
        resp = _request(conn, "POST", "/_plugins/_ml/connectors/_search",
                        {"query": {"match_all": {}}, "size": 1000})
        for hit in _hits(resp):
            connectors[str(hit.get("_id"))] = _connector_facts(hit.get("_source") or {})
        sources.append("POST /_plugins/_ml/connectors/_search")
    except Exception as exc:  # noqa: BLE001
        if u.is_denied(exc):
            problems.append(u.denied_reason("ML Commons connectors",
                                            "cluster:admin/opensearch/ml/connectors/search"))
        elif u.is_missing(exc):
            ml_missing = True
        else:
            problems.append(u.failed_reason(exc, "ML Commons connectors", ""))

    # Models → connector (remote) or local
    models: dict[str, dict[str, Any]] = {}
    if not ml_missing:
        try:
            resp = _request(conn, "POST", "/_plugins/_ml/models/_search", {
                "query": {"bool": {"must_not": {"exists": {"field": "chunk_number"}}}},
                "size": 1000})
            for hit in _hits(resp):
                src = hit.get("_source") or {}
                inline = src.get("connector")
                models[str(hit.get("_id"))] = {
                    "name": src.get("name"), "algorithm": src.get("algorithm"),
                    "connector_id": src.get("connector_id"),
                    "inline": _connector_facts(inline) if isinstance(inline, dict) else None}
            sources.append("POST /_plugins/_ml/models/_search")
        except Exception as exc:  # noqa: BLE001
            if u.is_denied(exc):
                problems.append(u.denied_reason("ML Commons models",
                                                "cluster:admin/opensearch/ml/models/search"))
            elif not u.is_missing(exc):
                problems.append(u.failed_reason(exc, "ML Commons models", ""))

    def resolve(model_id: str) -> dict[str, Any]:
        model = models.get(model_id)
        if model is None:
            return {"provider": "unknown", "model": None, "endpoint_host": None,
                    "auth": "unknown", "model_id": model_id,
                    "note": "model not found or not readable"}
        facts = model.get("inline") or connectors.get(str(model.get("connector_id")))
        if facts:
            return {**facts, "model": facts.get("model") or model.get("name"),
                    "model_id": model_id, "connector_id": model.get("connector_id")}
        remote = str(model.get("algorithm") or "").upper() == "REMOTE"
        return {"provider": "unknown" if remote else "local", "model": model.get("name"),
                "endpoint_host": None, "auth": "unknown" if remote else "none",
                "model_id": model_id}

    # Index → pipelines
    index_pipelines: dict[str, set[str]] = {}
    try:
        settings = c.indices.get_settings(index="*", flat_settings=True) or {}
        for index, body in settings.items():
            if str(index).startswith("."):
                continue
            flat = (body or {}).get("settings") or {}
            for key in ("index.default_pipeline", "index.final_pipeline",
                        "index.search.default_pipeline"):
                name = flat.get(key)
                if name and name != "_none":
                    index_pipelines.setdefault(str(name), set()).add(str(index))
    except Exception as exc:  # noqa: BLE001
        problems.append(u.failed_reason(exc, "index settings (pipeline attribution)",
                                        "indices:monitor/settings/get on the vector indices"))

    integrations: list[dict[str, Any]] = []
    used_connectors: set[str] = set()

    def add(stage: str, facts: dict[str, Any], collection: Optional[str],
            pipeline: str, processor: str) -> None:
        if facts.get("connector_id"):
            used_connectors.add(str(facts["connector_id"]))
        evidence = {"pipeline": pipeline, "processor": processor,
                    "model_id": facts.get("model_id"),
                    "connector_id": facts.get("connector_id"),
                    "protocol": facts.get("protocol"), "region": facts.get("region")}
        if facts.get("note"):
            evidence["note"] = facts["note"]
        integrations.append(u.integration(
            collection=collection, stage=stage, provider=str(facts.get("provider")),
            model=facts.get("model"), endpoint_host=facts.get("endpoint_host"),
            auth=facts.get("auth") or "unknown", module=f"ml-commons {processor}",
            evidence={k: v for k, v in evidence.items() if v is not None}))

    for label, path, keys, stage_for in (
            ("ingest", "/_ingest/pipeline", ("processors",), lambda p: "ingest"),
            ("search", "/_search/pipeline", ("request_processors", "response_processors",
                                             "phase_results_processors"),
             lambda p: _RESPONSE_STAGES.get(p, "query"))):
        try:
            pipelines = _request(conn, "GET", path) or {}
            sources.append(f"GET {path.lstrip('/')}")
        except Exception as exc:  # noqa: BLE001
            if u.is_missing(exc) and not u.is_denied(exc):
                continue  # no pipelines of this kind
            problems.append(u.failed_reason(exc, f"{label} pipelines",
                                            "cluster:admin/ingest/pipeline/get" if label
                                            == "ingest" else
                                            "cluster:admin/search/pipeline/get"))
            continue
        for pname, pipeline in (pipelines or {}).items():
            if not isinstance(pipeline, dict):
                continue
            for processor, model_id in _pipeline_models(pipeline, keys):
                facts = resolve(model_id)
                targets: list[Optional[str]] = [
                    *sorted(index_pipelines.get(str(pname), set()))] or [None]
                for index in targets:
                    add(stage_for(processor), facts, index, str(pname), processor)

    # Configured connectors no pipeline references (direct _predict / agents).
    for cid, facts in connectors.items():
        if cid in used_connectors:
            continue
        integrations.append(u.integration(
            collection=None, stage="query", provider=str(facts["provider"]),
            model=facts.get("model"), endpoint_host=facts.get("endpoint_host"),
            auth=facts.get("auth") or "unknown", module="ml-commons connector",
            evidence={k: v for k, v in {
                "connector_id": cid, "protocol": facts.get("protocol"),
                "region": facts.get("region"),
                "note": "configured; no pipeline references it (direct predict or agent "
                        "use)"}.items() if v is not None}))

    # Trusted endpoint allow-list
    try:
        cs = c.cluster.get_settings(include_defaults=True, flat_settings=True) or {}
        for layer in ("transient", "persistent", "defaults"):
            value = (cs.get(layer) or {}).get(_TRUSTED)
            if value is not None:
                controls["trusted_endpoints"] = list(value) if isinstance(value, list) \
                    else [value]
                controls["trusted_endpoints_source"] = layer
                break
        sources.append("GET _cluster/settings?include_defaults=true")
    except Exception as exc:  # noqa: BLE001
        problems.append(u.failed_reason(exc, "cluster settings",
                                        "cluster:monitor/settings (cluster:admin/settings/get)"))

    if ml_missing:
        controls["ml_commons"] = "not_installed"
    reason = " ".join(problems) if problems else (
        "ML Commons connectors, the models that use them, and the ingest/search pipelines "
        "that call those models." if not ml_missing else
        "The ML Commons plugin is not installed, so the cluster makes no model calls of "
        "its own.")
    return u.integrations_result(observable=not problems, reason=reason,
                                 source="; ".join(sources) or "ML Commons",
                                 integrations=integrations, controls=controls)


# ------------------------------------------------------------------ aliases #

def list_aliases(conn: Any) -> dict[str, str]:
    raw = _c(conn).indices.get_alias() or {}
    targets: dict[str, list[str]] = {}
    for index, body in raw.items():
        for alias in ((body or {}).get("aliases") or {}):
            targets.setdefault(str(alias), []).append(str(index))
    return {alias: ",".join(sorted(indices)) for alias, indices in sorted(targets.items())
            if not all(i.startswith(".") for i in indices)}


# ----------------------------------------------------------------- location #

def store_location(conn: Any) -> dict[str, Any]:
    source = "endpoint hostname"
    host = _host(conn)
    if not host:
        return u.unknown_host(source, None)
    for pattern, service, doc in (
            (_DOMAIN_HOST, "opensearch_service",
             "https://docs.aws.amazon.com/opensearch-service/latest/developerguide/"
             "createupdatedomains.html"),
            (_AOSS_CLASSIC, "opensearch_serverless",
             "https://docs.aws.amazon.com/opensearch-service/latest/developerguide/"
             "serverless-collection-endpoints.html"),
            (_AOSS_NEXTGEN, "opensearch_serverless",
             "https://docs.aws.amazon.com/opensearch-service/latest/developerguide/"
             "serverless-collection-endpoints.html")):
        m = pattern.match(host)
        if m:
            return u.location(provider="aws", region=m.group("region"), source=source,
                              observable=True,
                              reason="The AWS endpoint hostname encodes the region.",
                              evidence={"host": host, "service": service,
                                        "pattern_source": doc})
    if _aws_edition(host):
        return u.location(provider="aws", region=None, source=source, observable=False,
                          evidence={"host": host},
                          reason="This AWS endpoint does not match a documented pattern; "
                                 "declare the domain's region.")
    if u.is_private_host(host):
        return u.self_hosted(source, host)
    return u.unknown_host(source, host)
