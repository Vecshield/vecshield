"""Network discovery tests."""

from __future__ import annotations

import os

import pytest

from vecshield_platform.discovery import discover, expand_targets


def test_expand_cidr():
    ips = expand_targets("10.0.0.0/30")
    assert ips == ["10.0.0.1", "10.0.0.2"]  # usable hosts


def test_expand_range_full_and_short():
    assert expand_targets("192.168.0.1-192.168.0.3") == \
        ["192.168.0.1", "192.168.0.2", "192.168.0.3"]
    assert expand_targets("192.168.0.5-7") == \
        ["192.168.0.5", "192.168.0.6", "192.168.0.7"]


def test_expand_mixed_and_host():
    out = expand_targets("localhost, 10.0.0.0/31")
    assert "localhost" in out


def test_closed_port_finds_nothing():
    # very short timeout, a port nothing listens on
    assert discover("127.0.0.1", ports=[59999], timeout=0.2) == []


WEAVIATE_PORT = int(os.environ.get("VECSHIELD_WEAVIATE_PORT", "8090"))


def _weaviate_up() -> bool:
    import urllib.request
    try:
        urllib.request.urlopen(
            f"http://127.0.0.1:{WEAVIATE_PORT}/v1/.well-known/ready", timeout=2)
        return True
    except Exception:
        return False


@pytest.mark.skipif(not _weaviate_up(), reason="Weaviate not reachable")
def test_discovers_live_weaviate_on_custom_port():
    found = discover("127.0.0.1", ports=[WEAVIATE_PORT], timeout=1.0)
    kinds = {(f.kind) for f in found}
    assert "weaviate" in kinds
    w = next(f for f in found if f.kind == "weaviate")
    assert w.port == WEAVIATE_PORT and w.endpoint.endswith(str(WEAVIATE_PORT))
