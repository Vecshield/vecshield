"""Read-only facts about a vector store itself, outside its connector class.

The connector contract in ``connectors/base.py`` defines four optional store
facts — ``server_info()``, ``store_location()``, ``model_integrations()`` and
``list_aliases()`` — plus ``Collection.distance_metric``. This package answers
them for a live connector without editing the connector modules:

* if the connector's own class overrides the base method, that method is called;
* otherwise the call is dispatched on ``connector.kind`` to an adapter module in
  this package (``store_facts/<kind>.py``), which reads the connector's existing
  client/session attributes and never modifies them.

Adapters are imported lazily by name, so a kind without an adapter (or an
adapter without a given function) raises :class:`UnsupportedCapability`, the
same answer the base connector gives. Return shapes are exactly the ones the
base-class docstrings define. Values are configuration, never secrets.

Each adapter module may define:

``CAPABILITIES``
    frozenset of capability names it implements (``server_info``,
    ``location_introspection``, ``egress_introspection``, ``aliases``).
``server_info(conn)``, ``store_location(conn)``, ``model_integrations(conn)``,
``list_aliases(conn)``
    the store facts, with the base-class return shapes.
``distance_metric_details(conn)``
    ``{collection: {"metric": str|None, "vector_metrics": {...}, "source": str,
    ...}}`` — the per-vector detail behind :func:`distance_metrics`.
``distance_metrics(conn)``
    ``{collection: metric|None}``, if the adapter has no details function.
"""

from __future__ import annotations

import importlib
import re
from types import ModuleType
from typing import Any, Optional

from vecshield_platform.connectors.base import Connector, UnsupportedCapability

#: Capability name → the method/adapter function that backs it.
CAPABILITY_FUNCTIONS: dict[str, str] = {
    "server_info": "server_info",
    "location_introspection": "store_location",
    "egress_introspection": "model_integrations",
    "aliases": "list_aliases",
}

_KIND = re.compile(r"[a-z][a-z0-9_]*")

__all__ = [
    "FACT_NAMES",
    "GatheredFacts",
    "fill_distance_metrics",
    "gather",
    "summarize",
    "CAPABILITY_FUNCTIONS",
    "distance_metric_details",
    "distance_metrics",
    "list_aliases",
    "model_integrations",
    "server_info",
    "store_location",
    "supported",
]


def _adapter(connector: Any) -> Optional[ModuleType]:
    """The adapter module for ``connector.kind``, or None when there is none.

    A kind is only ever used as a module name after it matches a plain
    identifier, so a connector cannot steer the import elsewhere.
    """
    kind = str(getattr(connector, "kind", "") or "")
    if not _KIND.fullmatch(kind):
        return None
    name = f"{__name__}.{kind}"
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError as exc:
        if exc.name == name:
            return None
        raise  # the adapter exists but one of its own imports is broken


def _overrides(connector: Any, method: str) -> bool:
    """Whether the connector's class implements ``method`` itself."""
    own = getattr(type(connector), method, None)
    return own is not None and own is not getattr(Connector, method, None)


def _dispatch(connector: Any, method: str) -> Any:
    if _overrides(connector, method):
        return getattr(connector, method)()
    module = _adapter(connector)
    fn = getattr(module, method, None) if module is not None else None
    if not callable(fn):
        raise UnsupportedCapability(
            f"{getattr(connector, 'kind', type(connector).__name__)} does not support "
            f"{method}()")
    return fn(connector)


def supported(connector: Any) -> set[str]:
    """Store-fact capability names this connector can answer, by either route."""
    out: set[str] = set()
    for cap, method in CAPABILITY_FUNCTIONS.items():
        if _overrides(connector, method):
            out.add(cap)
    module = _adapter(connector)
    if module is not None:
        declared = getattr(module, "CAPABILITIES", None)
        if declared is None:  # no declaration: whatever functions exist
            declared = {cap for cap, fn in CAPABILITY_FUNCTIONS.items()
                        if callable(getattr(module, fn, None))}
        out |= {cap for cap in declared
                if callable(getattr(module, CAPABILITY_FUNCTIONS.get(cap, ""), None))}
    return out


def server_info(connector: Any) -> dict[str, Any]:
    """See :meth:`Connector.server_info`."""
    return _dispatch(connector, "server_info")


def store_location(connector: Any) -> dict[str, Any]:
    """See :meth:`Connector.store_location`."""
    return _dispatch(connector, "store_location")


def model_integrations(connector: Any) -> dict[str, Any]:
    """See :meth:`Connector.model_integrations`."""
    return _dispatch(connector, "model_integrations")


def list_aliases(connector: Any) -> dict[str, str]:
    """See :meth:`Connector.list_aliases`."""
    return _dispatch(connector, "list_aliases")


def distance_metric_details(connector: Any) -> dict[str, dict[str, Any]]:
    """Per-collection metric detail: ``{"metric", "vector_metrics", "source", ...}``.

    Raises UnsupportedCapability when the kind has no adapter that can read it.
    """
    module = _adapter(connector)
    fn = getattr(module, "distance_metric_details", None) if module is not None else None
    if callable(fn):
        return fn(connector)
    simple = getattr(module, "distance_metrics", None) if module is not None else None
    if callable(simple):
        return {name: {"metric": metric, "vector_metrics": {}, "source": "adapter"}
                for name, metric in simple(connector).items()}
    raise UnsupportedCapability(
        f"{getattr(connector, 'kind', type(connector).__name__)} has no distance-metric "
        "adapter")


def distance_metrics(connector: Any) -> dict[str, Optional[str]]:
    """``{collection: "cosine"|"dot"|"euclidean"|"manhattan"|None}``.

    Uses the kind's adapter; without one, falls back to whatever
    ``Collection.distance_metric`` the connector itself fills in.
    None means the store did not report a metric this vocabulary can hold.
    """
    try:
        details = distance_metric_details(connector)
    except UnsupportedCapability:
        return {c.name: getattr(c, "distance_metric", None)
                for c in connector.list_collections()}
    return {name: (d or {}).get("metric") for name, d in details.items()}


# --------------------------------------------------------------------------- #
# Gathering once per assessment                                                #
# --------------------------------------------------------------------------- #

#: The store facts an assessment gathers, in the order it gathers them.
FACT_NAMES: tuple[str, ...] = ("server_info", "store_location", "list_aliases",
                               "model_integrations")

_READERS = {"server_info": server_info, "store_location": store_location,
            "list_aliases": list_aliases, "model_integrations": model_integrations}


class GatheredFacts:
    """Store facts read once, with how each read went.

    ``values`` holds what each fact function returned, or None when it could
    not be read. ``status`` says why, per fact: ``observed``, ``unsupported``
    (the connector and its kind's adapter cannot answer), ``denied`` (the
    credential was refused) or ``error``. Reasons carry the exception *type*
    only: exception text can hold a credential-bearing URL.

    The exceptions themselves are kept (never serialised) so a check that
    consumes a fact through :meth:`reader` sees the same failure it would have
    seen calling the connector, and classifies it the same way.
    """

    def __init__(self) -> None:
        self.values: dict[str, Any] = {}
        self.status: dict[str, dict[str, Any]] = {}
        self._errors: dict[str, BaseException] = {}

    def get(self, name: str) -> Any:
        return self.values.get(name)

    def gathered(self, name: str) -> bool:
        return name in self.status

    def reader(self, name: str):
        """A zero-argument callable returning the fact, or raising its failure."""
        def read() -> Any:
            if name in self._errors:
                raise self._errors[name]
            return self.values.get(name)
        return read

    def record(self, name: str, value: Any = None,
               error: Optional[BaseException] = None) -> None:
        if error is None:
            self.values[name] = value
            self.status[name] = {"state": "observed"}
            return
        from vecshield_platform.connectors.base import ConnectorAuthError

        self.values[name] = None
        self._errors[name] = error
        if isinstance(error, UnsupportedCapability):
            state, reason = "unsupported", (
                f"This connector cannot report {name.replace('_', ' ')}.")
        elif isinstance(error, ConnectorAuthError) or _denied(error):
            state, reason = "denied", (
                f"The credential was refused when reading {name.replace('_', ' ')}.")
        else:
            state, reason = "error", (
                f"{name.replace('_', ' ')} could not be read ({type(error).__name__}).")
        self.status[name] = {"state": state, "reason": reason,
                             "error_type": type(error).__name__}


def _denied(exc: BaseException) -> bool:
    try:
        from vecshield_platform.store_facts._selfhosted_util import is_denied
    except Exception:  # noqa: BLE001 - classification is best effort
        return False
    try:
        return bool(is_denied(exc))
    except Exception:  # noqa: BLE001
        return False


def gather(connector: Any, names: tuple[str, ...] = FACT_NAMES) -> GatheredFacts:
    """Read each store fact once. Never raises: a failure is recorded per fact."""
    facts = GatheredFacts()
    for name in names:
        try:
            facts.record(name, _READERS[name](connector))
        except Exception as exc:  # noqa: BLE001 - one unreadable fact never stops an audit
            facts.record(name, error=exc)
    return facts


def fill_distance_metrics(connector: Any, collections: list[Any]) -> dict[str, Any]:
    """Set ``Collection.distance_metric`` where the collection left it None.

    Only a metric in the ``Collection.distance_metric`` vocabulary is written,
    and a value the connector already reported is never replaced. Returns a
    secret-free record of what happened.
    """
    from vecshield_platform.store_facts._selfhosted_util import normalize_metric

    missing = [c for c in collections if getattr(c, "distance_metric", None) is None]
    record: dict[str, Any] = {"state": "not_needed" if not missing else "observed",
                              "filled": [], "unreported": []}
    if not missing:
        return record
    try:
        details = distance_metric_details(connector)
    except UnsupportedCapability:
        record["state"] = "unsupported"
        record["unreported"] = sorted(c.name for c in missing)
        return record
    except Exception as exc:  # noqa: BLE001
        record.update(state="error", error_type=type(exc).__name__,
                      unreported=sorted(c.name for c in missing))
        return record
    for col in missing:
        metric = normalize_metric(((details or {}).get(col.name) or {}).get("metric"))
        if metric is None:
            record["unreported"].append(col.name)
            continue
        col.distance_metric = metric
        record["filled"].append(col.name)
    record["filled"].sort()
    record["unreported"].sort()
    return record


def _text(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    from vecshield_platform.connectors.redact import redact_credentials

    return redact_credentials(str(value))[:256]


def summarize(facts: Optional[GatheredFacts]) -> dict[str, Any]:
    """A secret-free summary for the audit scope: states, versions, counts.

    Never copies integration evidence, alias targets, feature values or
    reasons returned by the store; only allow-listed scalars and counts.
    """
    if facts is None:
        return {"gathered": False}
    out: dict[str, Any] = {"gathered": True,
                           "facts": {name: dict(status) for name, status in facts.status.items()}}
    server = facts.get("server_info")
    if isinstance(server, dict):
        features = server.get("features") if isinstance(server.get("features"), dict) else {}
        out["server"] = {"product": _text(server.get("product")),
                         "version": _text(server.get("version")),
                         "edition": _text(server.get("edition")),
                         "managed": bool(server.get("managed")),
                         "source": _text(server.get("source")),
                         "feature_keys": sorted(str(k) for k in features)[:50]}
    location = facts.get("store_location")
    if isinstance(location, dict):
        out["location"] = {"provider": _text(location.get("provider")),
                           "region": _text(location.get("region")),
                           "replica_regions": sorted(_text(r) for r in
                                                     location.get("replica_regions") or [])[:20],
                           "observable": location.get("observable") is True,
                           "source": _text(location.get("source"))}
    aliases = facts.get("list_aliases")
    if isinstance(aliases, dict):
        out["aliases"] = {"count": len(aliases)}
    report = facts.get("model_integrations")
    if isinstance(report, dict):
        integrations = [i for i in report.get("integrations") or [] if isinstance(i, dict)]
        out["model_integrations"] = {
            "observable": report.get("observable") is True,
            "count": len(integrations),
            "providers": sorted({str(_text(i.get("provider"))) for i in integrations
                                 if i.get("provider")})[:50],
            "source": _text(report.get("source"))}
    return out
