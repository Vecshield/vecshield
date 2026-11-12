"""Store facts for :class:`~vecshield_platform.connectors.mongodb.MongoDBConnector`.

Connector attributes read: ``_c`` (pymongo ``MongoClient``) and ``_endpoint``
(the host list only — the connector strips userinfo from the URI).

* server_info — ``buildInfo`` (``version``, ``modules`` such as
  ``["enterprise"]``; Percona Server adds ``psmdbVersion``). Atlas is
  identified by its ``*.mongodb.net`` hostname. ``features.network_compressors``
  comes from ``getCmdLineOpts`` (``parsed.net.compression.compressors``, else
  the documented default) only when the user may run it.
* distance metrics — ``$listSearchIndexes`` (``list_search_indexes()``):
  ``vectorSearch`` index fields of type ``vector`` carry ``similarity``
  (cosine / dotProduct / euclidean).
* model_integrations — Automated Embedding: vector search index fields of type
  ``autoEmbed`` with ``model`` (Voyage AI models;
  https://www.mongodb.com/docs/vector-search/crud-embeddings/automated-embedding/).
  On Atlas the embedding calls are managed by Atlas; self-managed mongot uses
  Voyage AI API keys supplied in its configuration.
* store_location — Atlas nodes carry pre-defined replica set tags
  ``provider`` and ``region`` (e.g. ``{"region": "US_EAST_2"}``;
  https://www.mongodb.com/docs/atlas/reference/replica-set-tags/), which the
  connected node reports in ``hello.tags`` and every member in
  ``replSetGetConfig``. Hostnames are not used for the region.
"""

from __future__ import annotations

from typing import Any, Iterator, Optional

from vecshield_platform.store_facts import _selfhosted_util as u

CAPABILITIES = frozenset({"server_info", "location_introspection", "egress_introspection"})

_SKIP_DBS = {"admin", "local", "config"}


def _c(conn: Any) -> Any:
    return getattr(conn, "_c", None)


def _hosts(conn: Any) -> list[str]:
    endpoint = str(getattr(conn, "_endpoint", "") or "")
    return [h for h in (u.host_of(part) for part in endpoint.split(",")) if h]


def _is_atlas(conn: Any) -> bool:
    return any(h.endswith(".mongodb.net") for h in _hosts(conn))


#: mongod's documented default for ``net.compression.compressors`` since 4.2
#: (https://www.mongodb.com/docs/manual/reference/configuration-options/#mongodb-setting-net.compression.compressors).
_DEFAULT_COMPRESSORS = ["snappy", "zstd", "zlib"]


def _network_compressors(conn: Any) -> Optional[list[str]]:
    """Enabled wire compressors, from ``getCmdLineOpts`` when the user may run it.

    Only ``parsed.net.compression.compressors`` is read; nothing else from the
    command's output (which can include file paths and bind settings) is kept.
    A successful read with no explicit setting means the documented default.
    ``getCmdLineOpts`` needs the ``getCmdLineOpts`` privilege (clusterMonitor);
    a refusal leaves the feature unreported rather than failing server_info.
    """
    try:
        opts = _c(conn).admin.command("getCmdLineOpts") or {}
    except Exception:  # noqa: BLE001 - optional detail, commonly refused
        return None
    value = u.get(opts, "parsed", "net", "compression", "compressors")
    if value is None:
        return list(_DEFAULT_COMPRESSORS)
    if isinstance(value, (list, tuple)):
        names = [str(v) for v in value]
    else:
        names = [part for part in str(value).split(",")]
    cleaned = [n.strip().lower() for n in names if n.strip()]
    return [] if cleaned == ["disabled"] else cleaned


def server_info(conn: Any) -> dict[str, Any]:
    atlas = _is_atlas(conn)
    try:
        info = _c(conn).admin.command("buildInfo") or {}
    except Exception as exc:  # noqa: BLE001
        return u.server(product="mongodb", source="buildInfo",
                        edition="atlas" if atlas else None, managed=atlas,
                        reason=u.failed_reason(exc, "buildInfo", "an authenticated user"))
    modules = [str(m) for m in info.get("modules") or []]
    if atlas:
        edition: Optional[str] = "atlas"
    elif info.get("psmdbVersion"):
        edition = "percona"
    elif "enterprise" in modules:
        edition = "enterprise"
    else:
        edition = "community"
    features: dict[str, Any] = {"modules": modules}
    if info.get("psmdbVersion"):
        features["psmdb_version"] = str(info["psmdbVersion"])
    compressors = _network_compressors(conn)
    if compressors is not None:
        features["network_compressors"] = compressors
    version = info.get("version")
    return u.server(product="mongodb", source="buildInfo",
                    version=str(version) if version else None, edition=edition,
                    managed=atlas, features=features,
                    reason="" if version else "buildInfo returned no version")


# ------------------------------------------------------------ search indexes #

def _search_indexes(conn: Any) -> Iterator[tuple[str, dict[str, Any]]]:
    """(``db.collection``, search index) for every user collection."""
    client = _c(conn)
    for db in client.list_database_names():
        if db in _SKIP_DBS:
            continue
        for coll in client[db].list_collection_names():
            if coll.startswith("system."):
                continue
            for idx in client[db][coll].list_search_indexes():
                if isinstance(idx, dict):
                    yield f"{db}.{coll}", idx


def _fields(idx: dict[str, Any]) -> list[dict[str, Any]]:
    definition = idx.get("latestDefinition") or idx.get("definition") or {}
    return [f for f in (definition.get("fields") or []) if isinstance(f, dict)]


def distance_metric_details(conn: Any) -> dict[str, dict[str, Any]]:
    per_collection: dict[str, dict[str, Any]] = {}
    for name, idx in _search_indexes(conn):
        for field in _fields(idx):
            if field.get("type") == "vector":
                key = f"{field.get('path')} ({idx.get('name')})"
                per_collection.setdefault(name, {})[key] = field.get("similarity")
    return {name: u.combine(per, "$listSearchIndexes fields.similarity")
            for name, per in per_collection.items()}


def _search_unavailable(exc: BaseException) -> bool:
    text = str(exc).lower()
    return ("only allowed on mongodb atlas" in text or "only supported" in text
            or "search index commands" in text or "mongot" in text
            or getattr(exc, "code", None) in (115, 31082, 40324))


def model_integrations(conn: Any) -> dict[str, Any]:
    source = "$listSearchIndexes (autoEmbed fields)"
    atlas = _is_atlas(conn)
    integrations = []
    try:
        for name, idx in _search_indexes(conn):
            for field in _fields(idx):
                if field.get("type") != "autoEmbed":
                    continue
                integrations.append(u.integration(
                    collection=name, stage="ingest", provider="voyageai",
                    model=field.get("model"), endpoint_host=None,
                    auth="unknown" if atlas else "api_key",
                    module="MongoDB Vector Search Automated Embedding",
                    evidence={"index": idx.get("name"), "path": field.get("path"),
                              "modality": field.get("modality"),
                              "also_applies_at": "query",
                              "execution": "Atlas-managed" if atlas else "mongot"}))
    except Exception as exc:  # noqa: BLE001
        if u.is_denied(exc):
            return u.integrations_result(
                observable=False, source=source, integrations=integrations,
                reason=u.denied_reason("search index definitions",
                                       "the listSearchIndexes action on every database "
                                       "(e.g. readAnyDatabase)"))
        if _search_unavailable(exc):
            return u.integrations_result(
                observable=True, source=source,
                reason="This deployment has no search/vector index service (mongot), so "
                       "it cannot embed text on its own.")
        return u.integrations_result(observable=False, source=source,
                                     integrations=integrations,
                                     reason=u.failed_reason(exc, "search indexes", ""))
    return u.integrations_result(
        observable=True, source=source, integrations=integrations,
        reason="Automated Embedding indexes send the indexed text field to Voyage AI at "
               "index time and query text at search time.")


# ----------------------------------------------------------------- location #

def _tags(doc: Any) -> dict[str, Any]:
    tags = (doc or {}).get("tags") if isinstance(doc, dict) else None
    return tags if isinstance(tags, dict) else {}


def store_location(conn: Any) -> dict[str, Any]:
    hosts = _hosts(conn)
    atlas = _is_atlas(conn)
    if not atlas:
        if hosts and all(u.is_private_host(h) for h in hosts):
            return u.self_hosted("connection hosts", ",".join(hosts))
        return u.unknown_host("connection hosts", ",".join(hosts) or None)
    source = "hello.tags (Atlas replica set tags)"
    try:
        hello = _c(conn).admin.command("hello")
    except Exception:  # noqa: BLE001 - servers before 4.4.2 only know isMaster
        try:
            hello = _c(conn).admin.command("isMaster")
        except Exception as exc:  # noqa: BLE001
            return u.location(provider="mongodb_atlas", region=None, source=source,
                              observable=False,
                              reason=u.failed_reason(exc, "hello", "an authenticated user"))
    tags = _tags(hello)
    region = tags.get("region")
    if not region:
        return u.location(provider="mongodb_atlas", region=None, source=source,
                          observable=False, evidence={"tags_reported": bool(tags)},
                          reason="The connected Atlas node reports no region tag; declare "
                                 "the cluster's region.")
    evidence: dict[str, Any] = {"cloud": tags.get("provider"),
                                "node_type": tags.get("nodeType"),
                                "tag_source": "https://www.mongodb.com/docs/atlas/reference/"
                                              "replica-set-tags/"}
    replicas: set[str] = set()
    try:
        config = _c(conn).admin.command("replSetGetConfig") or {}
        for member in u.get(config, "config", "members", default=[]):
            member_region = _tags(member).get("region")
            if member_region:
                replicas.add(str(member_region))
        replicas.discard(str(region))
        evidence["replica_regions_source"] = "replSetGetConfig members[].tags.region"
    except Exception as exc:  # noqa: BLE001
        evidence["replica_regions"] = ("not readable: " + (
            "needs the replSetGetConfig action (clusterMonitor)" if u.is_denied(exc)
            else u.describe_error(exc)))
    return u.location(provider="mongodb_atlas", region=str(region), source=source,
                      observable=True, replica_regions=replicas, evidence=evidence,
                      reason="Atlas reports the node's region in its replica set tags.")
