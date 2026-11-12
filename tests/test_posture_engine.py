"""Posture engine: network exposure, transport encryption, CVE scan, redact, PIA."""

from __future__ import annotations

import pytest

from vecshield.models import Severity, VectorStore
from vecshield_platform.posture.network import classify_endpoint, check_network_exposure
from vecshield_platform.posture.encryption import transport_status, check_transport_encryption
from vecshield_platform.posture import cve as cve_mod
from vecshield_platform.posture.cve import scan_cves


# ---------------- network exposure ----------------

@pytest.mark.parametrize("endpoint,kind,expected", [
    ("http://localhost:8000", "chroma", "private"),
    ("http://10.0.0.5:6333", "qdrant", "private"),
    ("http://192.168.1.4:6379", "redis", "private"),
    ("https://8.8.8.8:9200", "opensearch", "public"),
    ("file:///data/chroma", "chroma", "local"),
    ("pinecone://abc123", "pinecone", "managed_public"),
    ("redis://x.privatelink.cache.amazonaws.com:6379", "redis", "private"),
    ("https://svc.internal.corp:9200", "opensearch", "private"),
    # libpq keyword DSNs (redacted as the pgvector connector names them)
    ("host=10.0.0.7 port=5432 dbname=app user=app password=***", "pgvector", "private"),
    ("host='8.8.8.8' dbname=app", "pgvector", "public"),
    ("hostaddr=127.0.0.1 dbname=app", "pgvector", "private"),
    ("host=10.0.0.8,10.0.0.9 dbname=app", "pgvector", "private"),
    ("host=/var/run/postgresql dbname=app", "pgvector", "unknown"),
    ("dbname=app user=app", "pgvector", "unknown"),
])
def test_classify_endpoint(endpoint, kind, expected):
    v = classify_endpoint(endpoint, kind=kind, resolve=False)
    assert v.exposure == expected


def test_public_endpoint_flags_high():
    store = VectorStore(kind="qdrant", name="prod", endpoint="https://8.8.8.8:6333")
    findings = check_network_exposure(store, resolve=False)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].category == "network_exposure"


def test_private_endpoint_clean():
    store = VectorStore(kind="qdrant", name="dev", endpoint="http://10.1.2.3:6333")
    assert check_network_exposure(store, resolve=False) == []


def test_managed_saas_clean_unless_strict():
    store = VectorStore(kind="pinecone", name="pc", endpoint="pinecone://k")
    assert check_network_exposure(store, resolve=False) == []
    strict = check_network_exposure(store, resolve=False, flag_managed=True)
    assert len(strict) == 1
    assert strict[0].severity == Severity.LOW


# ---------------- transport encryption ----------------

@pytest.mark.parametrize("endpoint,kind,meta,encrypted", [
    ("http://localhost:8000", "chroma", {}, False),
    ("https://h:9200", "opensearch", {}, True),
    ("redis://h:6379", "redis", {}, False),
    ("rediss://h:6379", "redis", {}, True),
    ("postgresql://h:5432/db?sslmode=disable", "pgvector", {}, False),
    ("postgresql://h:5432/db?sslmode=require", "pgvector", {}, True),
    ("mongodb+srv://h/db", "mongodb", {}, True),
    ("http://h:9200", "opensearch", {"use_ssl": True}, True),
    ("pinecone://k", "pinecone", {}, True),
])
def test_transport_status(endpoint, kind, meta, encrypted):
    assert transport_status(endpoint, kind=kind, metadata=meta)["encrypted"] is encrypted


def test_plaintext_flags_high():
    store = VectorStore(kind="chroma", name="c", endpoint="http://host:8000")
    findings = check_transport_encryption(store)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].category == "transport_encryption"


def test_unverified_tls_flags_medium():
    # postgres with no sslmode => undetermined => MEDIUM
    store = VectorStore(kind="pgvector", name="pg",
                        endpoint="postgresql://host:5432/db")
    findings = check_transport_encryption(store)
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


def test_tls_endpoint_clean():
    store = VectorStore(kind="opensearch", name="os", endpoint="https://host:9200")
    assert check_transport_encryption(store) == []


# ---------------- CVE scan ----------------

def test_cve_offline_returns_info():
    findings = scan_cves(packages={"chromadb": "1.5.0"}, offline=True)
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "offline" in findings[0].title.lower()


def test_cve_no_packages_returns_info():
    findings = scan_cves(packages={}, offline=False)
    assert len(findings) == 1
    assert findings[0].category == "cve"
    assert findings[0].severity == Severity.INFO


def test_cve_parses_osv_response(monkeypatch):
    fake_vuln = {
        "id": "GHSA-test-0001",
        "summary": "Remote code execution in fake-db",
        "aliases": ["CVE-2099-0001"],
        "severity": [{"type": "CVSS_V3", "score": "9.8"}],
        "affected": [{
            "package": {"ecosystem": "PyPI", "name": "chromadb"},
            "ranges": [{"type": "ECOSYSTEM",
                        "events": [{"introduced": "1.0.0"}, {"fixed": "1.6.0"}]}],
        }],
    }
    monkeypatch.setattr(cve_mod, "_query_osv",
                        lambda name, version, *, timeout: [fake_vuln])
    findings = scan_cves(packages={"chromadb": "1.5.0"})
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.CRITICAL
    assert "GHSA-test-0001" in f.title
    assert f.evidence["fixed_version"] == "1.6.0"
    assert "1.6.0" in f.remediation


@pytest.mark.parametrize("entry,expected", [
    # OSV publishes vectors, not numbers: a 9.8 vector must not fall to MEDIUM.
    ({"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
     Severity.CRITICAL),
    ({"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
     Severity.HIGH),
])
def test_cve_scores_cvss_vectors(monkeypatch, entry, expected):
    vuln = {"id": "GHSA-vec-0001", "severity": [entry], "affected": []}
    monkeypatch.setattr(cve_mod, "_query_osv", lambda name, version, *, timeout: [vuln])
    [finding] = scan_cves(packages={"chromadb": "1.5.0"})
    assert finding.severity == expected


def test_cve_v4_vector_falls_back_to_advisory_label(monkeypatch):
    vuln = {"id": "GHSA-vec-0002", "affected": [],
            "severity": [{"type": "CVSS_V4",
                          "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}],
            "database_specific": {"severity": "HIGH"}}
    monkeypatch.setattr(cve_mod, "_query_osv", lambda name, version, *, timeout: [vuln])
    [finding] = scan_cves(packages={"chromadb": "1.5.0"})
    assert finding.severity == Severity.HIGH


def test_cve_network_error_is_info(monkeypatch):
    import urllib.error

    def boom(name, version, *, timeout):
        raise urllib.error.URLError("no route to host")

    monkeypatch.setattr(cve_mod, "_query_osv", boom)
    findings = scan_cves(packages={"chromadb": "1.5.0"})
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "OSV" in findings[0].title


def test_cve_cvss_severity_bands():
    assert cve_mod._cvss_to_severity(9.5) == Severity.CRITICAL
    assert cve_mod._cvss_to_severity(7.5) == Severity.HIGH
    assert cve_mod._cvss_to_severity(5.0) == Severity.MEDIUM
    assert cve_mod._cvss_to_severity(2.0) == Severity.LOW
    assert cve_mod._cvss_to_severity(None) == Severity.MEDIUM
