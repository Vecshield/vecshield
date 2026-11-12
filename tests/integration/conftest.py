"""Shared fixtures and guards for the container-backed integration suite.

Anything that needs Docker depends on the ``docker_available`` fixture (or the
module-level ``importorskip``), so the suite degrades to *skipped* — never
*errored* — on machines without a Docker daemon.
"""

from __future__ import annotations

import shutil
import socket

import pytest

# Skip the entire package at collection time if testcontainers isn't installed
# (it lives in the optional ``integration`` extra).
pytest.importorskip("testcontainers")


def _docker_reachable() -> bool:
    """Best-effort check that a Docker daemon is present and reachable."""
    if shutil.which("docker") is None:
        return False
    try:
        # The default Unix socket; on CI runners this is the usual location.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            s.connect("/var/run/docker.sock")
        return True
    except OSError:
        # Fall back to trusting the CLI if the socket path differs (e.g. rootless
        # or Docker Desktop); the container fixtures will surface a clear error
        # if the daemon is genuinely unavailable.
        return True


@pytest.fixture(scope="session")
def docker_available() -> None:
    if not _docker_reachable():
        pytest.skip("Docker is not available; skipping integration tests.")
