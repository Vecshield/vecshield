"""VecShield REST API."""

from __future__ import annotations

from vecshield_platform.api.app import create_app
from vecshield_platform.api.registry import StoreConfig, StoreRegistry

__all__ = ["create_app", "StoreRegistry", "StoreConfig"]
