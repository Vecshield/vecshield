"""Verified regulatory references shipped as data, not code.

Each file carries its own ``verified_on`` date, a ``source_url`` per entry and
the exact citation, so a reviewer can check a reference without reading
Python. They are suggestions for people to pick from; nothing in the product
applies one automatically.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

_DIR = Path(__file__).resolve().parent

#: The reference sets that exist. Anything else is a caller error.
REFERENCE_SETS = ("retention", "biometric", "inventory")


@lru_cache(maxsize=None)
def _load(name: str) -> dict[str, Any]:
    with (_DIR / f"{name}_references.json").open(encoding="utf-8") as handle:
        return json.load(handle)


def load_references(name: str) -> dict[str, Any]:
    """The named reference set as a fresh dict (callers may mutate it)."""
    if name not in REFERENCE_SETS:
        raise ValueError(f"unknown reference set: {name}")
    return json.loads(json.dumps(_load(name)))


def reference_ids(name: str) -> frozenset[str]:
    return frozenset(ref["id"] for ref in _load(name)["references"])
