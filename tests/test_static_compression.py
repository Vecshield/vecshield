"""The console's static assets are gzip-compressed; nothing else is.

dashboard.js and dashboard.css are most of a first load, and they compress by
about three quarters. The compression is scoped to the `/static` mount: the
JSON API stays uncompressed, Range requests are served as-is, and assets that
are already compressed (fonts, PNGs) are not compressed again.
"""

from __future__ import annotations

import gzip
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from vecshield_platform.api import create_app  # noqa: E402
from vecshield_platform.api.config_store import ConfigStore  # noqa: E402

ASSETS = (Path(__file__).resolve().parents[1]
          / "vecshield_platform" / "api" / "dashboard" / "dist" / "assets")


@pytest.fixture()
def client(tmp_path):
    app = create_app(config_store=ConfigStore(path=str(tmp_path / "config.json")),
                     serve_ui=True)
    try:
        yield TestClient(app)
    finally:
        app.state.jobs.shutdown(wait=False)


def _raw(client: TestClient, url: str, **headers: str):
    """GET without letting the client decode the body, so encoding is visible."""
    with client.stream("GET", url, headers=headers) as response:
        body = b"".join(response.iter_raw())
    return response, body


@pytest.mark.parametrize("name", ["dashboard.js", "dashboard.css"])
def test_console_assets_are_gzipped_and_decode_to_the_file(client, name):
    response, body = _raw(client, f"/static/assets/{name}", **{"Accept-Encoding": "gzip"})

    assert response.status_code == 200
    assert response.headers["content-encoding"] == "gzip"
    assert "accept-encoding" in response.headers["vary"].lower()
    on_disk = (ASSETS / name).read_bytes()
    assert gzip.decompress(body) == on_disk
    assert len(body) < len(on_disk) // 2


def test_compression_keeps_the_revalidation_policy(client):
    first, _ = _raw(client, "/static/assets/dashboard.js", **{"Accept-Encoding": "gzip"})
    assert first.headers["cache-control"] == "no-cache"
    etag = first.headers["etag"]

    revalidated = client.get("/static/assets/dashboard.js",
                             headers={"Accept-Encoding": "gzip", "If-None-Match": etag})
    assert revalidated.status_code == 304


def test_assets_are_plain_for_a_client_that_does_not_ask_for_gzip(client):
    response, body = _raw(client, "/static/assets/dashboard.js",
                          **{"Accept-Encoding": "identity"})

    assert "content-encoding" not in response.headers
    assert body == (ASSETS / "dashboard.js").read_bytes()


def test_range_requests_are_served_uncompressed(client):
    response, body = _raw(client, "/static/assets/dashboard.js",
                          **{"Accept-Encoding": "gzip", "Range": "bytes=0-99"})

    assert response.status_code == 206
    assert "content-encoding" not in response.headers
    assert body == (ASSETS / "dashboard.js").read_bytes()[:100]


@pytest.mark.parametrize("path", ["fonts/inter-latin-var.woff2", "vecshield-logo.png"])
def test_already_compressed_assets_are_not_recompressed(client, path):
    response, body = _raw(client, f"/static/assets/{path}", **{"Accept-Encoding": "gzip"})

    assert response.status_code == 200
    assert "content-encoding" not in response.headers
    assert body == (ASSETS / path).read_bytes()


def test_the_api_is_not_compressed(client):
    response, _ = _raw(client, "/healthz", **{"Accept-Encoding": "gzip"})

    assert response.status_code == 200
    assert "content-encoding" not in response.headers
