"""VecShield platform — self-hosted vector/RAG security posture management.

Wraps the `vecshield` detection library with an operational control plane:
dashboards, a REST API, scheduled audits, vector-DB security posture, managed
connectors, runtime query monitoring, access-control auditing, RAG integrity,
and compliance workflows (DPIA/DSAR/erasure).

Architecture: ``vecshield_platform`` imports ``vecshield``; ``vecshield`` never
imports ``vecshield_platform``. Both packages ship from this repository and
from one distribution.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version as _dist_version

try:
    #: Read from the installed distribution so pyproject.toml stays the single
    #: source of truth. An uninstalled checkout has no metadata to read.
    __version__ = _dist_version("vecshield")
except PackageNotFoundError:  # pragma: no cover - source checkout only
    __version__ = "0.0.0+unknown"

# The detection engine this build wraps. Kept explicit so deployments can
# assert the detection engine version they are governing against.
from vecshield import __version__ as detection_version  # noqa: E402

__all__ = ["__version__", "detection_version"]
