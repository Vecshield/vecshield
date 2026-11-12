"""Gated live connector validation.

Set VECSHIELD_LIVE_CONFIG to a VecShield admin config JSON containing real
stores. This test is skipped by default and is intended for nightly or
credentialed CI.
"""

from __future__ import annotations

import os

import pytest


pytestmark = pytest.mark.skipif(
    not os.environ.get("VECSHIELD_LIVE_CONFIG"),
    reason="set VECSHIELD_LIVE_CONFIG to run live connector validation",
)


def test_live_registered_stores_validate():
    from vecshield_platform.api.config_store import ConfigStore
    from vecshield_platform.validation import validate_connector

    cfg = ConfigStore(path=os.environ["VECSHIELD_LIVE_CONFIG"])
    reg = cfg.build_registry()
    stores = reg.list()
    assert stores, "live config has no stores"
    failures = []
    for store in stores:
        conn = reg.open(store.store_id)
        try:
            result = validate_connector(conn, sample_chunks=2, max_collections=2)
        finally:
            conn.close()
        if not result.ok:
            failures.append(result.to_dict())
    assert not failures
