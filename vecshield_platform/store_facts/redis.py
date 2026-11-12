"""Store facts for :class:`~vecshield_platform.connectors.redis.RedisConnector`.

Connector attributes read: ``_r`` (redis-py client) and ``_endpoint``.

* server_info — ``INFO server`` (``redis_version``; Valkey reports
  ``server_name: valkey`` and ``valkey_version``) and ``MODULE LIST`` for the
  search module's version; ``features.replica_read_only`` ("yes"/"no") from
  ``INFO replication`` on a replica, else ``CONFIG GET replica-read-only``
  when the ACL allows it.
* distance metrics — ``FT.INFO`` vector attributes carry ``distance_metric``
  (L2, IP or COSINE; https://redis.io/docs/latest/develop/ai/search-and-query/vectors/).
* list_aliases — ``FT.ALIASLIST index`` (Redis Open Source 8.10+; not
  supported on Redis Software or Redis Cloud:
  https://redis.io/docs/latest/commands/ft.aliaslist/). Older servers raise
  UnsupportedCapability — there is no other command that lists aliases.
* store_location — Redis Cloud hostnames (``redis-<port>.c<n>.<zone>.ec2.
  cloud.redislabs.com`` / ``...redns.redis-cloud.com``) carry a zone label such
  as ``us-east-1-1`` that is not documented as the cloud region, so no region
  is taken from them.
* model_integrations — not implemented: absence of a store-side model feature
  could not be confirmed from Redis documentation.
"""

from __future__ import annotations

from typing import Any, Optional

from vecshield_platform.connectors.base import UnsupportedCapability
from vecshield_platform.store_facts import _selfhosted_util as u

CAPABILITIES = frozenset({"server_info", "location_introspection", "aliases"})

_CLOUD_SUFFIXES = (".cloud.redislabs.com", ".redns.redis-cloud.com", ".redis-cloud.com")


def _r(conn: Any) -> Any:
    return getattr(conn, "_r", None)


def _host(conn: Any) -> Optional[str]:
    kwargs = u.get(_r(conn), "connection_pool", "connection_kwargs", default={})
    if isinstance(kwargs, dict):
        if kwargs.get("path"):
            return "/" + str(kwargs["path"]).lstrip("/")  # Unix socket
        if kwargs.get("host"):
            return str(kwargs["host"]).lower()
    return u.host_of(getattr(conn, "_endpoint", None))


def _is_cloud(host: Optional[str]) -> bool:
    return host is not None and any(host.endswith(s) for s in _CLOUD_SUFFIXES)


def _modules(conn: Any) -> dict[str, str]:
    raw = _r(conn).execute_command("MODULE", "LIST") or []
    out: dict[str, str] = {}
    for entry in raw:
        if isinstance(entry, dict):
            fields = {u.dec(k): u.dec(v) for k, v in entry.items()}
        elif isinstance(entry, (list, tuple)):
            items = [u.dec(x) for x in entry]
            fields = dict(zip(items[0::2], items[1::2]))
        else:
            continue
        name = fields.get("name")
        if name:
            out[str(name)] = str(fields.get("ver", ""))
    return out


def _yes_no(value: Any) -> Optional[str]:
    text = str(u.dec(value)).strip().lower()
    if text in ("1", "yes", "true"):
        return "yes"
    if text in ("0", "no", "false"):
        return "no"
    return None


def _replica_read_only(conn: Any) -> Optional[str]:
    """``"yes"``/``"no"`` for the replica-read-only setting, or None if unreadable.

    A replica reports it in ``INFO replication`` (``slave_read_only``, and
    ``replica_read_only`` on newer servers). A primary does not; there the
    configured value (which applies once it is made a replica) is read with
    ``CONFIG GET``, which needs ``+config|get``; a refusal leaves it unreported.
    """
    try:
        repl = _r(conn).info("replication") or {}
        repl = {u.dec(k): v for k, v in repl.items()}
    except Exception:  # noqa: BLE001 - optional detail
        repl = {}
    for key in ("replica_read_only", "slave_read_only"):
        if key in repl:
            value = _yes_no(repl[key])
            if value is not None:
                return value
    try:
        config = _r(conn).config_get("replica-read-only") or {}
    except Exception:  # noqa: BLE001 - CONFIG may be refused by ACL; never fatal
        return None
    if isinstance(config, dict):
        for key, value in config.items():
            if str(u.dec(key)).lower() in ("replica-read-only", "slave-read-only"):
                return _yes_no(value)
    return None


def server_info(conn: Any) -> dict[str, Any]:
    source = "INFO server; MODULE LIST"
    host = _host(conn)
    managed = _is_cloud(host)
    try:
        info = _r(conn).info("server") or {}
    except Exception as exc:  # noqa: BLE001
        return u.server(product="redis", source=source, managed=managed,
                        edition="redis_cloud" if managed else None,
                        reason=u.failed_reason(exc, "INFO server",
                                               "the +info command (ACL @dangerous)"))
    info = {u.dec(k): u.dec(v) for k, v in info.items()}
    valkey = str(info.get("server_name", "")).lower() == "valkey" or "valkey_version" in info
    product = "valkey" if valkey else "redis"
    version = info.get("valkey_version") if valkey else info.get("redis_version")
    features: dict[str, Any] = {}
    reason = ""
    try:
        modules = _modules(conn)
        if modules:
            features["modules"] = modules
    except Exception as exc:  # noqa: BLE001
        reason = u.failed_reason(exc, "MODULE LIST", "the +module|list command")
    if info.get("redis_mode"):
        features["mode"] = str(info["redis_mode"])
    read_only = _replica_read_only(conn)
    if read_only is not None:
        features["replica_read_only"] = read_only
    return u.server(product=product, source=source,
                    version=str(version) if version else None,
                    edition="redis_cloud" if managed else None, managed=managed,
                    features=features, reason=reason)


def _pairs(tokens: Any) -> list[tuple[str, Any]]:
    """Every (key, value) pair in a nested FT.INFO attribute, keys lower-cased."""
    out: list[tuple[str, Any]] = []
    if isinstance(tokens, dict):
        for k, v in tokens.items():
            out.append((str(u.dec(k)).lower(), u.dec(v)))
            out.extend(_pairs(v))
        return out
    if isinstance(tokens, (list, tuple)):
        items = list(tokens)
        for i, item in enumerate(items):
            if isinstance(item, (list, tuple, dict)):
                out.extend(_pairs(item))
            elif i + 1 < len(items) and isinstance(u.dec(item), str):
                out.append((str(u.dec(item)).lower(), u.dec(items[i + 1])))
    return out


def distance_metric_details(conn: Any) -> dict[str, dict[str, Any]]:
    r = _r(conn)
    out: dict[str, dict[str, Any]] = {}
    for index in [u.dec(x) for x in r.execute_command("FT._LIST") or []]:
        try:
            info = r.ft(index).info()
        except Exception as exc:  # noqa: BLE001
            out[index] = {"metric": None, "vector_metrics": {}, "source": "FT.INFO",
                          "error": u.describe_error(exc)}
            continue
        per: dict[str, Any] = {}
        for attr in (info or {}).get("attributes", []) or []:
            pairs = _pairs(attr)
            fields: dict[str, Any] = {}
            for k, v in pairs:
                fields.setdefault(k, v)
            if str(fields.get("type", "")).upper() != "VECTOR":
                continue
            name = str(fields.get("identifier") or fields.get("attribute") or "vector")
            per[name] = fields.get("distance_metric")
        out[index] = u.combine(per, "FT.INFO attributes.distance_metric")
    return out


def list_aliases(conn: Any) -> dict[str, str]:
    r = _r(conn)
    out: dict[str, str] = {}
    for index in [u.dec(x) for x in r.execute_command("FT._LIST") or []]:
        try:
            aliases = r.execute_command("FT.ALIASLIST", index) or []
        except Exception as exc:  # noqa: BLE001
            if "unknown command" in str(exc).lower():
                raise UnsupportedCapability(
                    "this server has no FT.ALIASLIST (Redis Open Source 8.10+ only), and "
                    "Redis has no other command that lists aliases") from exc
            raise
        for alias in aliases:
            out[str(u.dec(alias))] = index
    return out


def store_location(conn: Any) -> dict[str, Any]:
    source = "connection host"
    host = _host(conn)
    if not host:
        return u.unknown_host(source, None)
    if host.startswith("/"):
        return u.self_hosted(source, None, local=True)
    if _is_cloud(host):
        return u.location(
            provider="redis_cloud", region=None, source=source, observable=False,
            evidence={"host": host},
            reason="Redis Cloud hostnames carry a zone label that is not documented as the "
                   "cloud region; declare the database's region from the Redis Cloud "
                   "console.")
    if u.is_private_host(host):
        return u.self_hosted(source, host)
    return u.unknown_host(source, host)
