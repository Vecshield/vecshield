"""Unit tests for the API key auditor."""

from __future__ import annotations

from datetime import datetime, timezone

from vecshield_platform.access import audit_api_keys
from vecshield.models import ApiKey, Severity

NOW = datetime(2026, 6, 30, tzinfo=timezone.utc)


def _days_ago(n: int) -> datetime:
    from datetime import timedelta

    return NOW - timedelta(days=n)


def test_wildcard_write_key_is_high():
    keys = [ApiKey(id="k1", name="ci", actions=["read", "write"], namespaces=["*"],
                   last_used=_days_ago(1))]
    findings = audit_api_keys(keys, now=NOW)
    assert any(f.severity == Severity.HIGH for f in findings)


def test_wildcard_read_only_is_medium():
    keys = [ApiKey(id="k2", name="ro", actions=["read"], namespaces=["*"],
                   last_used=_days_ago(1))]
    findings = audit_api_keys(keys, now=NOW)
    sev = {f.severity for f in findings}
    assert Severity.MEDIUM in sev and Severity.HIGH not in sev


def test_scoped_recent_readonly_key_is_clean():
    # Named for its holder rather than "svc": a generic service name is now
    # itself a finding (PCI DSS Req 8.2.1), and this test is about scope,
    # recency and read-only access, not about naming.
    keys = [ApiKey(id="k3", name="ingest-worker-a", actions=["read"],
                   namespaces=["public-kb"], last_used=_days_ago(2))]
    assert audit_api_keys(keys, now=NOW) == []


def test_stale_key_flagged():
    keys = [ApiKey(id="k4", name="old", actions=["read"], namespaces=["public-kb"],
                   last_used=_days_ago(200))]
    findings = audit_api_keys(keys, now=NOW, stale_days=90)
    assert any("Stale" in f.title for f in findings)


def test_mutating_access_to_sensitive_namespace():
    keys = [ApiKey(id="k5", name="writer", actions=["read", "write"],
                   namespaces=["pii-docs"], last_used=_days_ago(1))]
    findings = audit_api_keys(keys, now=NOW, sensitive_namespaces={"pii-docs"})
    assert any("sensitive namespace" in f.title for f in findings)


def test_admin_key_is_high():
    keys = [ApiKey(id="k6", name="root", actions=["admin"], namespaces=["public"],
                   last_used=_days_ago(1))]
    findings = audit_api_keys(keys, now=NOW)
    assert any(f.severity == Severity.HIGH for f in findings)


def test_api_keys_from_dicts_parses_provider_export():
    from vecshield_platform.access import api_keys_from_dicts

    keys = api_keys_from_dicts([{
        "key_id": "k1",
        "name": "svc",
        "actions": ["read"],
        "namespaces": ["docs"],
        "last_used": "2026-06-01T00:00:00Z",
        "created_at": "2026-01-01T00:00:00+00:00",
        "metadata": {"provider": "pinecone"},
    }])
    assert keys[0].id == "k1"
    assert keys[0].last_used.tzinfo is not None
    assert keys[0].metadata["provider"] == "pinecone"
