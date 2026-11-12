"""Declarative policies for Phase-9 posture findings.

These plug into the same evaluate_policies() engine as default_policies(); the
orchestrator appends them whenever a posture audit runs.
"""

from __future__ import annotations

from vecshield_platform.compliance.policy import Policy
from vecshield.models import Severity


def posture_policies() -> list[Policy]:
    return [
        Policy(
            id="store-private-network-only",
            description="Vector store must not be reachable from the public internet",
            when={"category": "network_exposure", "min_severity": "high"},
            action="move_to_private_network",
            severity=Severity.HIGH,
        ),
        Policy(
            id="require-store-authentication",
            description="A vector store must not serve data to unauthenticated callers",
            when={"category": "authentication", "min_severity": "high"},
            action="require_authentication",
            severity=Severity.CRITICAL,
        ),
        Policy(
            id="encrypt-in-transit",
            description="All store connections must use TLS",
            when={"category": "transport_encryption", "min_severity": "high"},
            action="enforce_tls",
            severity=Severity.HIGH,
        ),
        Policy(
            id="verify-tls-certificates",
            description="A vector store connection must verify the server's TLS "
                        "certificate",
            when={"category": "tls_certificate_verification", "min_severity": "medium"},
            action="enforce_certificate_verification",
            severity=Severity.MEDIUM,
        ),
        Policy(
            id="tls-enforced",
            description="A vector store must refuse clients that connect without TLS",
            when={"category": "transport_tls_enforcement", "min_severity": "high"},
            action="enforce_tls",
            severity=Severity.HIGH,
        ),
        Policy(
            # Fires only on an observed "disabled". A store whose encryption at
            # rest cannot be observed produces no finding, so it cannot trip this.
            id="at-rest-encryption-not-disabled",
            description="Database-native encryption at rest must not be disabled",
            when={"category": "at_rest_encryption", "min_severity": "high"},
            action="enable_encryption_at_rest",
            severity=Severity.HIGH,
        ),
        Policy(
            id="no-critical-cves",
            description="No connector library may run with a critical known CVE",
            when={"category": "cve", "min_severity": "critical"},
            action="patch_dependency",
            severity=Severity.CRITICAL,
        ),
        Policy(
            id="no-high-cves",
            description="No connector library may run with a high-severity known CVE",
            when={"category": "cve", "min_severity": "high"},
            action="patch_dependency",
            severity=Severity.HIGH,
        ),
        # ---- the database server itself (posture/server_vulns.py) ----------
        Policy(
            id="no-critical-server-vulnerabilities",
            description="The vector database server must not run a version with a "
                        "critical known vulnerability",
            when={"category": "server_vulnerability", "min_severity": "critical"},
            action="patch_server",
            severity=Severity.CRITICAL,
        ),
        Policy(
            # Listed in CISA's Known Exploited Vulnerabilities catalog: exploited
            # in the wild, whatever its CVSS score. BOD 22-01 binds US federal
            # agencies only; for everyone else it is a prioritisation signal.
            # ``known_exploited`` is a bool, which compares as 0/1 here and in
            # the console's rule preview alike.
            id="no-known-exploited-server-vulnerabilities",
            description="The vector database server must not run a version with a "
                        "vulnerability CISA lists as known exploited",
            when={"category": "server_vulnerability",
                  "evidence_gte": {"known_exploited": 1}},
            action="patch_server",
            severity=Severity.CRITICAL,
        ),
        Policy(
            # Only an end-of-life release line is HIGH; one nearing its end
            # date is LOW and does not trip this.
            id="server-release-supported",
            description="The vector database server must run a release line that "
                        "still receives security fixes",
            when={"category": "server_support_status", "min_severity": "high"},
            action="upgrade_supported_release",
            severity=Severity.HIGH,
        ),
        # ---- who can read the vector tables (access/grants.py) -------------
        Policy(
            # CRITICAL is a retrieval role that is a superuser, or bypasses row
            # security on a table that relies on it. An assumed retrieval role
            # (none declared) is capped at MEDIUM and cannot trip this.
            id="no-rls-bypass-on-retrieval",
            description="The role a RAG application retrieves as must not bypass "
                        "row-level security",
            when={"category": "access_grants", "min_severity": "critical"},
            action="restrict_retrieval_role",
            severity=Severity.CRITICAL,
        ),
        Policy(
            id="retrieval-credential-least-privilege",
            description="The retrieval role must only read the vector tables: no "
                        "writes, role administration, or unrestricted PUBLIC reads",
            when={"category": "access_grants", "min_severity": "high"},
            action="restrict_retrieval_role",
            severity=Severity.HIGH,
        ),
        Policy(
            # HIGH and above: trust for non-local clients, or TLS off on a
            # server listening beyond loopback.
            id="database-server-hardened",
            description="The database server must authenticate remote clients and "
                        "offer TLS on every non-local listener",
            when={"category": "server_hardening", "min_severity": "high"},
            action="harden_server_configuration",
            severity=Severity.HIGH,
        ),
        # ---- where the data goes (posture/egress.py, posture/residency.py) --
        Policy(
            # HIGH is PHI without a declared BAA, cardholder data, special-
            # category or criminal-offence data, or secrets reaching an outside
            # model provider through the store's own model module.
            id="model-egress-declared",
            description="The store must not send high-risk data to a model provider "
                        "that is not a declared processor",
            when={"category": "model_egress", "min_severity": "high"},
            action="declare_processor_or_disable_module",
            severity=Severity.HIGH,
        ),
        Policy(
            # HIGH is a location outside the declared residency policy in a
            # country with no adequacy finding for a declared regime.
            id="data-within-residency-policy",
            description="Store data and model calls must stay inside the declared "
                        "residency policy, or the transfer must be documented",
            when={"category": "data_residency", "min_severity": "high"},
            action="restrict_region_or_document_transfer",
            severity=Severity.HIGH,
        ),
    ]
