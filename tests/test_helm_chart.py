"""Helm chart hardening (plan §0.3, §2.4 item 4, §3.3).

``helm`` is not a test dependency, so the chart is checked statically here,
and rendered for real only when a ``helm`` binary is on PATH.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

CHART = Path(__file__).resolve().parents[1] / "helm"
VALUES = yaml.safe_load((CHART / "values.yaml").read_text())
DEPLOYMENT = (CHART / "templates" / "deployment.yaml").read_text()
HELPERS = (CHART / "templates" / "_helpers.tpl").read_text()


def test_initial_admin_password_is_required_while_local_login_is_on():
    assert VALUES["auth"]["localLogin"] is True
    assert VALUES["auth"]["initialAdminPasswordSecret"] == ""
    assert "and .Values.auth.localLogin (not .Values.auth.initialAdminPasswordSecret)" in DEPLOYMENT
    assert "VECSHIELD_INITIAL_ADMIN_PASSWORD" in DEPLOYMENT
    assert 'name: VECSHIELD_LOGIN\n              value: "off"' in DEPLOYMENT


def test_read_and_admin_tokens_are_separate():
    assert "adminToken" in VALUES["auth"]
    assert "VECSHIELD_ADMIN_TOKEN" in DEPLOYMENT


def test_pod_hardening_defaults():
    pod = VALUES["podSecurityContext"]
    assert pod["runAsNonRoot"] is True and pod["seccompProfile"]["type"] == "RuntimeDefault"
    c = VALUES["securityContext"]
    assert c["readOnlyRootFilesystem"] is True
    assert c["allowPrivilegeEscalation"] is False
    assert c["capabilities"]["drop"] == ["ALL"]
    assert DEPLOYMENT.count("automountServiceAccountToken: false") == 2  # server + CronJob
    assert "mountPath: /tmp" in HELPERS and "mountPath: /data" in HELPERS


def test_probes_and_resources():
    startup = VALUES["probes"]["startup"]
    assert startup["periodSeconds"] * startup["failureThreshold"] >= 60
    for probe, path in (("startupProbe", "/healthz"), ("livenessProbe", "/healthz"),
                        ("readinessProbe", "/readyz")):
        block = DEPLOYMENT.split(probe + ":", 1)[1][:120]
        assert f"path: {path}" in block
    assert VALUES["resources"] == {"requests": {"cpu": "2", "memory": "3Gi"},
                                   "limits": {"memory": "4Gi"}}


def test_nlp_values_render_env():
    assert VALUES["nlp"]["mode"] in ("auto", "required", "disabled")
    assert "VECSHIELD_NLP_MODE" in HELPERS and "VECSHIELD_NLP_MODEL" in HELPERS


def test_network_policy_is_default_deny_with_an_egress_allowlist():
    policy = (CHART / "templates" / "networkpolicy.yaml").read_text()
    assert VALUES["networkPolicy"]["enabled"] is False
    assert 'policyTypes: ["Ingress", "Egress"]' in policy
    assert ".Values.networkPolicy.egress" in policy


def test_secure_app_defaults():
    assert VALUES["storeSecrets"]["rejectPlaintext"] is True
    assert VALUES["metrics"]["public"] is False
    assert VALUES["hardening"]["maxBodyBytes"] > 0


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")
def test_helm_template_renders_and_refuses():
    ok = subprocess.run(
        ["helm", "template", "vs", str(CHART), "--set", "auth.token=t",
         "--set", "auth.adminToken=a", "--set", "auth.initialAdminPasswordSecret=init"],
        capture_output=True, text=True)
    assert ok.returncode == 0, ok.stderr
    docs = [d for d in yaml.safe_load_all(ok.stdout) if d]
    dep = next(d for d in docs if d["kind"] == "Deployment")
    assert dep["spec"]["template"]["spec"]["automountServiceAccountToken"] is False
    refused = subprocess.run(["helm", "template", "vs", str(CHART), "--set", "auth.token=t"],
                             capture_output=True, text=True)
    assert refused.returncode != 0
    assert "initialAdminPasswordSecret" in refused.stderr
