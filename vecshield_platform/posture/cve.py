"""CVE / patch-status scanner.

Maps each connector kind to its PyPI client package, reads the *installed*
version via importlib.metadata, and queries the OSV.dev database for known
vulnerabilities affecting that version. OSV aggregates GHSA, PYSEC and CVE
records and is free + unauthenticated.

Design notes:
  * stdlib only (urllib) — no new runtime dependency.
  * Offline-tolerant: a network failure yields a single INFO finding ("could
    not reach OSV"), never an exception that breaks an audit.
  * Version-aware: OSV is queried *with* the installed version so it only
    returns vulns that actually affect what's running.
  * Fix version is extracted from the affected-ranges so the remediation tells
    the operator exactly what to upgrade to.

Server-side DB binary versions (e.g. a self-hosted Qdrant server) are out of
scope here — this scans the client libraries VecShield itself talks through,
which is what determines the exploitability of the integration.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Optional

from vecshield.models import Finding, Severity
from vecshield_platform.posture.cvss import v3_base_score

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

# connector kind -> PyPI distribution name (must match pyproject extras).
KIND_TO_PYPI = {
    "chroma": "chromadb",
    "pgvector": "psycopg",
    "qdrant": "qdrant-client",
    "weaviate": "weaviate-client",
    "milvus": "pymilvus",
    "pinecone": "pinecone",
    "redis": "redis",
    "opensearch": "opensearch-py",
    "mongodb": "pymongo",
    "openai": "openai",
    "azure_search": "azure-search-documents",
    "bedrock_kb": "boto3",
    "vertex_ai": "google-cloud-aiplatform",
}

# CVSS v3 base-score band -> VecShield severity.
def _cvss_to_severity(score: Optional[float]) -> Severity:
    if score is None:
        return Severity.MEDIUM           # unknown but present => treat as medium
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


@dataclass
class CveMatch:
    package: str
    installed_version: str
    vuln_id: str            # GHSA / PYSEC / CVE id
    summary: str
    severity: Severity
    fixed_version: Optional[str] = None
    aliases: list[str] = field(default_factory=list)
    reference: str = ""

    def to_dict(self) -> dict:
        return {
            "package": self.package,
            "installed_version": self.installed_version,
            "vuln_id": self.vuln_id,
            "summary": self.summary,
            "severity": self.severity.value,
            "fixed_version": self.fixed_version,
            "aliases": self.aliases,
            "reference": self.reference,
        }


def _installed_version(pypi_name: str) -> Optional[str]:
    try:
        from importlib.metadata import version

        return version(pypi_name)
    except Exception:
        return None


def _query_osv(pypi_name: str, version: str, *, timeout: float) -> list[dict]:
    """POST one version-scoped query to OSV. Returns raw vuln dicts (may raise)."""
    body = json.dumps({
        "package": {"name": pypi_name, "ecosystem": "PyPI"},
        "version": version,
    }).encode()
    req = urllib.request.Request(
        OSV_QUERY_URL, data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode())
    return data.get("vulns", []) or []


def _cvss_score(vuln: dict) -> Optional[float]:
    """Pull a numeric CVSS base score from an OSV vuln record, if present."""
    best: Optional[float] = None
    for sev in vuln.get("severity", []) or []:
        val = sev.get("score")
        # OSV gives a CVSS vector string (CVSS_V3 / CVSS_V4) far more often
        # than a number. v3 vectors are scored here; a v4 vector has no base
        # score we compute, so it falls through to the advisory's label below.
        try:
            score: Optional[float] = float(val)
        except (TypeError, ValueError):
            score = v3_base_score(val) if isinstance(val, str) else None
        if score is not None:
            best = max(best or 0.0, score)
    # Some records stash a numeric score under database_specific.
    ds = vuln.get("database_specific", {}) or {}
    sev_label = str(ds.get("severity", "")).upper()
    if best is None and sev_label:
        return {"CRITICAL": 9.5, "HIGH": 8.0, "MODERATE": 5.0,
                "MEDIUM": 5.0, "LOW": 2.0}.get(sev_label)
    return best


def _fixed_version(vuln: dict, pypi_name: str) -> Optional[str]:
    """First 'fixed' event in the PyPI affected-ranges for this package."""
    for aff in vuln.get("affected", []) or []:
        pkg = aff.get("package", {}) or {}
        if pkg.get("ecosystem") != "PyPI":
            continue
        if pkg.get("name", "").lower() != pypi_name.lower():
            continue
        for rng in aff.get("ranges", []) or []:
            for event in rng.get("events", []) or []:
                if "fixed" in event:
                    return event["fixed"]
    return None


def scan_cves(
    *,
    kinds: Optional[list[str]] = None,
    packages: Optional[dict[str, str]] = None,
    timeout: float = 10.0,
    offline: bool = False,
    store_label: str = "dependencies",
) -> list[Finding]:
    """Scan installed connector client libraries for known CVEs.

    Provide either `kinds` (connector kinds, versions read from the
    environment) or `packages` ({pypi_name: version}) directly. With neither,
    every kind in KIND_TO_PYPI that is actually installed is scanned.
    """
    # Resolve the {pypi_name: version} map to scan.
    # `packages is not None` means "use exactly these" (an empty dict => scan
    # nothing); `None` means "discover installed connector libraries".
    targets: dict[str, str] = {}
    if packages is not None:
        targets = dict(packages)
    else:
        scan_kinds = kinds or list(KIND_TO_PYPI)
        for kind in scan_kinds:
            pypi = KIND_TO_PYPI.get(kind.lower())
            if not pypi:
                continue
            v = _installed_version(pypi)
            if v:
                targets[pypi] = v

    findings: list[Finding] = []

    if not targets:
        findings.append(Finding(
            id=f"find-{uuid.uuid4().hex[:10]}",
            title="No connector client libraries detected for CVE scan",
            severity=Severity.INFO,
            category="cve",
            store=store_label,
            description="None of the known connector packages are installed in "
                        "this environment, so there was nothing to scan.",
            remediation="Install the connector extras you use (e.g. "
                        "vecshield[chroma]) and re-run the CVE scan.",
        ))
        return findings

    if offline:
        findings.append(Finding(
            id=f"find-{uuid.uuid4().hex[:10]}",
            title="CVE scan skipped (offline mode)",
            severity=Severity.INFO,
            category="cve",
            store=store_label,
            description=f"Offline mode: {len(targets)} package(s) would be checked "
                        "against OSV.dev when online.",
            evidence={"packages": targets},
            remediation="Re-run without --offline to query OSV.dev.",
        ))
        return findings

    for pypi_name, version in sorted(targets.items()):
        try:
            vulns = _query_osv(pypi_name, version, timeout=timeout)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            findings.append(Finding(
                id=f"find-{uuid.uuid4().hex[:10]}",
                title=f"Could not reach OSV.dev to scan {pypi_name}",
                severity=Severity.INFO,
                category="cve",
                store=store_label,
                description=f"Network error querying OSV for {pypi_name}=={version}: {e}",
                evidence={"package": pypi_name, "installed_version": version,
                          "osv_unreachable": True},
                remediation="Check network egress to api.osv.dev, or run an "
                            "offline CVE feed mirror.",
            ))
            continue

        for vuln in vulns:
            score = _cvss_score(vuln)
            severity = _cvss_to_severity(score)
            fixed = _fixed_version(vuln, pypi_name)
            match = CveMatch(
                package=pypi_name,
                installed_version=version,
                vuln_id=vuln.get("id", "UNKNOWN"),
                summary=(vuln.get("summary") or vuln.get("details", ""))[:300],
                severity=severity,
                fixed_version=fixed,
                aliases=vuln.get("aliases", []) or [],
                reference=f"https://osv.dev/vulnerability/{vuln.get('id', '')}",
            )
            fix_txt = (f"Upgrade {pypi_name} to {fixed} or later."
                       if fixed else
                       f"No fixed version is published yet; track {match.vuln_id} "
                       "and apply mitigations.")
            findings.append(Finding(
                id=f"find-{uuid.uuid4().hex[:10]}",
                title=f"{pypi_name}=={version} affected by {match.vuln_id}",
                severity=severity,
                category="cve",
                store=store_label,
                description=(f"{match.summary or 'Known vulnerability'} "
                             f"(CVSS {score if score is not None else 'n/a'}). "
                             f"Aliases: {', '.join(match.aliases) or 'none'}."),
                evidence=match.to_dict(),
                remediation=fix_txt,
            ))

    return findings
