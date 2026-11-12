"""Server-side store registry.

Security boundary: the API never accepts a connection string or credentials
from a client. Stores are registered out-of-band (config/env/admin), and API
requests reference a store by its opaque `store_id`. This eliminates the SSRF /
credential-injection surface that "scan this DSN" endpoints create.

A registered store is a connector *factory* (called per request) plus optional
non-secret config such as the tenant field used for isolation probes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from vecshield_platform.connectors import build_connector
from vecshield_platform.connectors.base import Connector


@dataclass
class StoreConfig:
    store_id: str
    kind: str
    factory: Callable[[], Connector]
    tenant_field: Optional[str] = None
    description: str = ""
    #: Why the store cannot be opened (e.g. an unresolvable secret reference);
    #: None when it can. Its factory raises with the same reason.
    unavailable: Optional[str] = None

    def public_dict(self) -> dict:
        out = {"store_id": self.store_id, "kind": self.kind,
               "tenant_field": self.tenant_field, "description": self.description}
        if self.unavailable:
            out["unavailable"] = self.unavailable
        return out


class StoreRegistry:
    def __init__(self) -> None:
        self._stores: dict[str, StoreConfig] = {}

    def register(
        self,
        store_id: str,
        kind: str,
        *,
        tenant_field: Optional[str] = None,
        description: str = "",
        factory: Optional[Callable[[], Connector]] = None,
        unavailable: Optional[str] = None,
        **conn_kwargs,
    ) -> StoreConfig:
        """Register a store. Either pass a `factory`, or connector kwargs that
        are bound now and used to build a fresh connector per request."""
        if store_id in self._stores:
            raise ValueError(f"store_id already registered: {store_id!r}")
        if factory is None:
            def factory() -> Connector:  # bind kwargs at registration time
                return build_connector(kind, **conn_kwargs)
        cfg = StoreConfig(store_id=store_id, kind=kind, factory=factory,
                          tenant_field=tenant_field, description=description,
                          unavailable=unavailable)
        self._stores[store_id] = cfg
        return cfg

    def get(self, store_id: str) -> StoreConfig:
        if store_id not in self._stores:
            raise KeyError(store_id)
        return self._stores[store_id]

    def open(self, store_id: str) -> Connector:
        return self.get(store_id).factory()

    def list(self) -> list[StoreConfig]:
        return list(self._stores.values())
