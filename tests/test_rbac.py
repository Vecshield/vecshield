"""Unit tests for the RBAC diff."""

from __future__ import annotations

from vecshield_platform.access import diff_access
from vecshield.models import AccessGrant, Severity


def test_identical_policies_no_findings():
    g = [AccessGrant("svc", "kb", "read")]
    assert diff_access(g, g) == []


def test_over_grant_mutating_is_high():
    intended = [AccessGrant("svc", "kb", "read")]
    actual = [AccessGrant("svc", "kb", "read"), AccessGrant("svc", "kb", "delete")]
    findings = diff_access(intended, actual)
    assert any(f.severity == Severity.HIGH and "delete" in f.title for f in findings)


def test_over_grant_read_is_medium():
    intended = []
    actual = [AccessGrant("guest", "kb", "read")]
    findings = diff_access(intended, actual)
    assert len(findings) == 1 and findings[0].severity == Severity.MEDIUM


def test_missing_grant_is_low():
    intended = [AccessGrant("svc", "kb", "write")]
    actual = []
    findings = diff_access(intended, actual)
    assert len(findings) == 1 and findings[0].severity == Severity.LOW
    assert "Missing grant" in findings[0].title


def test_grants_from_dicts_builds_grants():
    from vecshield_platform.access import grants_from_dicts

    grants = grants_from_dicts([
        {"principal": "svc", "namespace": "kb", "action": "read"},
        {"principal": "svc", "action": "delete"},  # namespace defaults to '*'
    ])
    assert grants[0].as_tuple() == ("svc", "kb", "read")
    assert grants[1].as_tuple() == ("svc", "*", "delete")


def test_rbac_diff_cli(tmp_path):
    import json

    from click.testing import CliRunner

    from vecshield_platform.cli import cli

    intended = tmp_path / "intended.json"
    actual = tmp_path / "actual.json"
    intended.write_text(json.dumps(
        [{"principal": "svc", "namespace": "kb", "action": "read"}]))
    actual.write_text(json.dumps([
        {"principal": "svc", "namespace": "kb", "action": "read"},
        {"principal": "svc", "namespace": "kb", "action": "delete"},
    ]))

    result = CliRunner().invoke(cli, [
        "rbac-diff", "--intended", str(intended),
        "--actual", str(actual), "--store-name", "kb",
    ])
    # A mutating over-grant is HIGH severity -> exit code 2.
    assert result.exit_code == 2
    assert "Unintended grant" in result.output
