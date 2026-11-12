"""Deterministic finding fingerprints.

Findings are assigned a random ``find-{uuid}`` id on every scan, so the same
underlying issue gets a different id each run. That makes it impossible to
allow-list, suppress, deduplicate, or track a finding across scans.

A *fingerprint* is a stable, deterministic identity for a finding derived only
from its meaningful dimensions — the ones that stay the same when the same
problem is re-detected: its ``category``, the ``store`` and ``collection`` it
lives in, a *rule* token (which detector fired), and any per-item key the
detector carries in its evidence (``cve_id``, ``key_id``, ``principal`` ...).
Volatile fields (the random id, timestamps, counts, example lists) are
deliberately excluded so re-scanning a stable environment yields a stable
fingerprint.

This is the prerequisite for false-positive management (allow-lists /
suppressions), drift detection, and a de-duplicated SIEM feed.
"""

from __future__ import annotations

import hashlib
import re
from typing import Iterable

from vecshield.models import Finding

#: Evidence keys that carry a *stable per-item identity* for a given category.
#: When present they pin the fingerprint to a specific item (this CVE, this key,
#: this grant) rather than to the whole collection. Order matters — it is part
#: of the hashed material.
_ITEM_KEYS: dict[str, tuple[str, ...]] = {
    "cve": ("package", "vuln_id"),
    "access_control": ("key_id", "principal", "namespace", "action"),
    "network_exposure": ("endpoint",),
    "transport_encryption": ("endpoint",),
    # Crypto posture: the same endpoint identity as transport_encryption, so a
    # store re-registered under a new name keeps its findings' history.
    "transport_tls_enforcement": ("endpoint",),
    "tls_certificate_verification": ("endpoint",),
    "isolation": ("tenant_field",),
    "coverage": ("kind",),
}

_FIELD_SEP = "\x1f"  # unit separator: unambiguous join of fingerprint parts


def _rule_token(title: str) -> str:
    """Reduce a finding title to a stable "which detector fired" token.

    Strips the volatile parts of a title — quoted collection/key names, digits
    (counts, versions), and punctuation — leaving the fixed descriptive words
    that identify the *kind* of finding (e.g. "prompt injection content in",
    "anomalous embeddings in"). Deterministic for a given title.
    """
    t = title.lower()
    t = re.sub(r"'[^']*'", " ", t)       # drop 'quoted' names (collections, keys)
    t = re.sub(r'"[^"]*"', " ", t)       # drop "quoted" names
    t = re.sub(r"\d+", " ", t)            # drop counts / versions
    t = re.sub(r"[^a-z_ ]+", " ", t)      # keep letters / underscore / space
    return " ".join(t.split()[:8])


def fingerprint_finding(finding: Finding) -> str:
    """Return a stable ``fp-<hex>`` fingerprint for ``finding``.

    Pure and deterministic: the same logical finding always hashes to the same
    value, independent of its random id, timestamp, or example payload.
    """
    parts: list[str] = [
        finding.category or "",
        finding.store or "",
        finding.collection or "",
        _rule_token(finding.title or ""),
    ]
    evidence = finding.evidence or {}
    for key in _ITEM_KEYS.get(finding.category or "", ()):
        val = evidence.get(key)
        if val is not None:
            parts.append(f"{key}={val}")
    digest = hashlib.sha256(_FIELD_SEP.join(parts).encode("utf-8")).hexdigest()
    return f"fp-{digest[:16]}"


def apply_fingerprints(findings: Iterable[Finding]) -> None:
    """Stamp ``evidence['fingerprint']`` on each finding in place (idempotent)."""
    for f in findings:
        if f.evidence is None:
            f.evidence = {}
        f.evidence["fingerprint"] = fingerprint_finding(f)
