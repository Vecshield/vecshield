"""Network exposure checker.

Given a store's endpoint, decide whether the database is reachable from the
public internet. The check is deliberately layered so it works whether or not
DNS resolution is available:

  1. Parse a host out of the endpoint string (URL, host:port, or DSN).
  2. If the host is already an IP literal, classify it directly (RFC 1918 /
     loopback / link-local => private).
  3. Otherwise look for private-DNS markers (privatelink, .internal, .vpc,
     .local, *.svc) before falling back to a DNS lookup.
  4. If a lookup is possible and resolves to a public IP => PUBLIC.

Managed SaaS stores (Pinecone, OpenAI, Azure AI Search, Bedrock, Vertex) are
public *by design* and TLS-only; for those, a public endpoint is expected, so
we emit an INFO note rather than a finding unless `flag_managed=True`.

No finding is raised on "unknown" — we never cry wolf when we genuinely can't
tell; we say so in the evidence instead.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import uuid
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

from vecshield.models import Finding, Severity, VectorStore

# Stores that are SaaS-managed: always TLS, public endpoint is expected.
MANAGED_SAAS_KINDS = frozenset(
    {"pinecone", "openai", "azure_search", "bedrock_kb", "vertex_ai"}
)

# Substrings in a hostname that signal a private/peered endpoint.
_PRIVATE_DNS_MARKERS = (
    "privatelink", ".internal", ".vpc", ".local", ".svc", "internal.",
    ".intranet", ".corp", ".lan",
)

_HOST_PORT_RE = re.compile(r"^(?P<host>[A-Za-z0-9._-]+)(?::\d+)?$")
#: ``keyword=value`` pairs of a libpq DSN, values optionally single-quoted.
_LIBPQ_KEYWORD_RE = re.compile(r"(\w+)\s*=\s*('(?:[^']*)'|\S+)")


@dataclass
class NetworkExposure:
    """The verdict for one store's endpoint."""

    endpoint: str
    host: Optional[str]
    exposure: str          # "private" | "public" | "managed_public" | "local" | "unknown"
    resolved_ip: Optional[str] = None
    reason: str = ""

    @property
    def is_public(self) -> bool:
        return self.exposure in ("public", "managed_public")

    def to_dict(self) -> dict:
        return {
            "endpoint": self.endpoint,
            "host": self.host,
            "exposure": self.exposure,
            "resolved_ip": self.resolved_ip,
            "reason": self.reason,
        }


def _extract_host(endpoint: str) -> Optional[str]:
    """Pull a hostname out of a URL, host:port, or DSN-ish endpoint string."""
    if not endpoint:
        return None
    ep = endpoint.strip()

    # file:// or a bare filesystem path => no network host.
    if ep.startswith("file://") or ep.startswith("/"):
        return None

    # libpq keyword DSN ("host=db port=5432 dbname=app"). No host keyword
    # means a Unix socket or libpq's default, so there is no host to classify.
    if "://" not in ep and _LIBPQ_KEYWORD_RE.search(ep):
        kv = {k.lower(): v.strip("'") for k, v in _LIBPQ_KEYWORD_RE.findall(ep)}
        host = (kv.get("host") or kv.get("hostaddr") or "").split(",")[0]
        return host if host and not host.startswith("/") else None

    # Provider pseudo-schemes we can't resolve (e.g. "pinecone://ab12…").
    parsed = urlparse(ep if "://" in ep else f"//{ep}", scheme="")
    host = parsed.hostname
    if host:
        return host

    # Fallback: bare "host:port".
    m = _HOST_PORT_RE.match(ep)
    if m:
        return m.group("host")
    return None


def _classify_ip(ip_str: str) -> Optional[str]:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved:
        return "private"
    return "public"


def classify_endpoint(
    endpoint: str,
    *,
    kind: str = "",
    resolve: bool = True,
) -> NetworkExposure:
    """Classify a single endpoint string. DNS resolution is best-effort."""
    host = _extract_host(endpoint)
    kind = (kind or "").lower()

    if host is None:
        # filesystem-backed store (e.g. local Chroma) — no network surface.
        if endpoint.startswith("file://") or endpoint.startswith("/"):
            return NetworkExposure(endpoint, None, "local",
                                   reason="filesystem-backed store, no network endpoint")
        return NetworkExposure(endpoint, None, "unknown",
                               reason="could not extract a host from the endpoint")

    # 1. IP literal?
    direct = _classify_ip(host)
    if direct == "private":
        return NetworkExposure(endpoint, host, "private", resolved_ip=host,
                               reason=f"{host} is a private/loopback IP")
    if direct == "public":
        exposure = "managed_public" if kind in MANAGED_SAAS_KINDS else "public"
        return NetworkExposure(endpoint, host, exposure, resolved_ip=host,
                               reason=f"{host} is a public IP literal")

    # 2. Localhost name.
    if host in ("localhost", "localhost.localdomain"):
        return NetworkExposure(endpoint, host, "private",
                               reason="localhost — not network-exposed")

    # 3. Private-DNS markers (cloud private endpoints, VPC peering, k8s svc).
    low = host.lower()
    if any(marker in low for marker in _PRIVATE_DNS_MARKERS):
        return NetworkExposure(endpoint, host, "private",
                               reason=f"hostname '{host}' matches a private-endpoint pattern")

    # 4. Managed SaaS — public by design (DNS would resolve public anyway).
    if kind in MANAGED_SAAS_KINDS:
        return NetworkExposure(endpoint, host, "managed_public",
                               reason=f"{kind} is a managed SaaS store (TLS-only, public by design)")

    # 5. Resolve and classify.
    if resolve:
        try:
            ip = socket.gethostbyname(host)
        except (OSError, UnicodeError):
            return NetworkExposure(endpoint, host, "unknown",
                                   reason=f"could not resolve '{host}' (offline or private DNS)")
        kind_of = _classify_ip(ip)
        if kind_of == "private":
            return NetworkExposure(endpoint, host, "private", resolved_ip=ip,
                                   reason=f"'{host}' resolves to private IP {ip}")
        return NetworkExposure(endpoint, host, "public", resolved_ip=ip,
                               reason=f"'{host}' resolves to public IP {ip}")

    return NetworkExposure(endpoint, host, "unknown",
                           reason="resolution disabled; host is not an obvious private endpoint")


def check_network_exposure(
    store: VectorStore,
    *,
    resolve: bool = True,
    flag_managed: bool = False,
) -> list[Finding]:
    """Emit a finding when a store is reachable from the public internet.

    `flag_managed=True` also raises a (low) finding for managed SaaS stores so a
    "private-network-only" policy can be enforced strictly.
    """
    verdict = classify_endpoint(store.endpoint, kind=store.kind, resolve=resolve)
    findings: list[Finding] = []

    def mk(severity: Severity, title: str, desc: str, remediation: str) -> Finding:
        return Finding(
            id=f"find-{uuid.uuid4().hex[:10]}",
            title=title,
            severity=severity,
            category="network_exposure",
            store=store.name,
            description=desc,
            evidence=verdict.to_dict(),
            remediation=remediation,
        )

    if verdict.exposure == "public":
        findings.append(mk(
            Severity.HIGH,
            f"Vector store '{store.name}' is reachable from the public internet",
            f"{verdict.reason}. A self-hosted vector store on a public address is "
            "exposed to credential-stuffing, scraping, and CVE exploitation.",
            "Move the store onto a private subnet/VPC and front it with an "
            "authenticated gateway. Restrict the security group to known CIDRs; "
            "never bind a vector DB directly to 0.0.0.0 on a public host.",
        ))
    elif verdict.exposure == "managed_public" and flag_managed:
        findings.append(mk(
            Severity.LOW,
            f"Managed store '{store.name}' uses a public SaaS endpoint",
            f"{verdict.reason}. Acceptable for most deployments, but violates a "
            "strict 'private-network-only' policy.",
            "If policy requires private networking, enable the provider's "
            "PrivateLink / Private Service Connect / VPC endpoint feature.",
        ))

    return findings
