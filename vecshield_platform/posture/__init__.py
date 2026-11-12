"""Security posture / configuration audit.

Where the scan engines inspect *data* (what is inside the store), posture
inspects *configuration* (how the store is exposed and operated):

  * network exposure   — is the endpoint reachable from the public internet?
  * authentication     — does the store serve data without a credential?
  * transport security — is the connection TLS-encrypted, and does the store
                          refuse plaintext clients (opt-in probe)?
  * encryption at rest — what the data plane reports about native and field
                          encryption; unobservable is never a failure
  * CVE / patch status  — is the client (and, where queryable, the server)
                          running a version with known vulnerabilities?
  * store controls      — (``store_controls=True``) model egress to outside
                          AI providers, data residency against the declared
                          policy, and server advisories / end-of-life status,
                          all read through ``store_facts``

All of them are pure functions over a VectorStore description (or a small
inventory), so they are testable without a live store and compose into a single
ScanJob via run_posture_audit().
"""

from __future__ import annotations

from vecshield_platform.posture.authentication import (
    authentication_status,
    check_authentication,
    probe_anonymous_access,
)
from vecshield_platform.posture.at_rest import (
    at_rest_check,
    field_encryption_checks,
    observe_at_rest,
)
from vecshield_platform.posture.cve import CveMatch, scan_cves
from vecshield_platform.posture.encryption import (
    check_tls_certificate_verification,
    check_transport_encryption,
    transport_status,
)
from vecshield_platform.posture.engine import STORE_CONTROL_CHECKS, run_posture_audit
from vecshield_platform.posture.network import NetworkExposure, check_network_exposure
from vecshield_platform.posture.policy import posture_policies
from vecshield_platform.posture.tls_probe import probe_tls_enforcement

__all__ = [
    "check_authentication",
    "authentication_status",
    "probe_anonymous_access",
    "check_network_exposure",
    "NetworkExposure",
    "check_transport_encryption",
    "check_tls_certificate_verification",
    "transport_status",
    "probe_tls_enforcement",
    "observe_at_rest",
    "at_rest_check",
    "field_encryption_checks",
    "scan_cves",
    "CveMatch",
    "run_posture_audit",
    "STORE_CONTROL_CHECKS",
    "posture_policies",
]
