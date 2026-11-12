"""Authentication posture checker.

`network.py` says whether a store can be reached and `encryption.py` says
whether the connection is encrypted. Neither asks the question that produced
this category's most cited incidents: **is a credential required at all?**
Chroma ships with no authentication by default, and public surveys have found
large numbers of reachable instances serving data to anonymous callers.

Two signals, deliberately separate:

- **Configuration** — what the connection string implies. A URI carrying
  ``user:password@`` is evidence a credential is in play; a managed SaaS store
  cannot be reached without one; a filesystem-backed store has no transport to
  authenticate.
- **Probe** — an unauthenticated request to *the store's own configured
  endpoint*, and nothing else. This is the only signal that establishes what a
  stranger actually gets, and it is the one that catches the case where a
  client is configured with an API key the server never enforces.

The probe never touches a host the caller names, never sweeps a range, and
never authenticates. It asks the registered store one question without
credentials and reads the status code.

An undetermined answer is reported as undetermined. Silence is not a pass.
"""

from __future__ import annotations

import uuid
from typing import Callable, Optional
from urllib.parse import urlparse

from vecshield.models import Finding, Severity, VectorStore
from vecshield_platform.posture.network import MANAGED_SAAS_KINDS

#: Paths probed per store kind, in order, each tagged with what a 2xx proves.
#: "data" means the response would enumerate collections or documents — an
#: anonymous read of the customer's own inventory. "liveness" means the service
#: answered but told us nothing about data access, which many deployments
#: expose on purpose.
_PROBE_PATHS: dict[str, tuple[tuple[str, str], ...]] = {
    "qdrant": (("/collections", "data"), ("/", "liveness")),
    "chroma": (("/api/v1/collections", "data"),
               ("/api/v2/tenants", "data"),
               ("/api/v1/heartbeat", "liveness"),
               ("/api/v2/heartbeat", "liveness")),
    "weaviate": (("/v1/schema", "data"), ("/v1/meta", "liveness")),
    "opensearch": (("/_cat/indices", "data"), ("/", "liveness")),
    "milvus": (("/v2/vectordb/collections/list", "data"), ("/healthz", "liveness")),
}

#: Schemes whose URI can carry a credential inline.
_CREDENTIAL_SCHEMES = ("postgresql", "postgres", "mongodb", "mongodb+srv", "redis",
                       "rediss", "http", "https")


def authentication_status(endpoint: str, *, kind: str = "",
                          metadata: dict | None = None,
                          session_auth: dict | None = None) -> dict:
    """Return {'authenticated': bool|None, 'mode': str, 'reason': str}.

    This reads what the connection implies: its configuration, and, when the
    connector can report it (``session_auth``, from session_auth_info()), how
    the server authenticated VecShield's own session. Neither establishes
    what an anonymous caller would get; that is what the probe is for.
    ``authenticated=None`` means undetermined, never 'fine'.
    """
    kind = (kind or "").lower()
    metadata = metadata or {}
    ep = (endpoint or "").strip()

    if session_auth and session_auth.get("observed"):
        if session_auth.get("authenticated") is False:
            return {"authenticated": False, "mode": "server_admitted_unauthenticated",
                    "auth_method": None, "source": session_auth.get("source"),
                    "reason": session_auth.get("reason") or
                    "the server admitted this session without authenticating it"}
        if session_auth.get("authenticated"):
            return {"authenticated": True, "mode": "server_authenticated",
                    "auth_method": session_auth.get("auth_method"),
                    "source": session_auth.get("source"),
                    "reason": session_auth.get("reason") or
                    "the server authenticated this session"}

    if ep.startswith("file://") or ep.startswith("/"):
        return {"authenticated": None, "mode": "not_applicable",
                "reason": "filesystem-backed store: access is governed by file "
                          "permissions, not by a service credential"}

    if kind in MANAGED_SAAS_KINDS:
        return {"authenticated": True, "mode": "provider_credential",
                "reason": f"{kind} is a managed service that cannot be reached "
                          "without a provider credential"}

    parsed = urlparse(ep if "://" in ep else f"//{ep}", scheme="")
    scheme = (parsed.scheme or "").lower()
    # Redis is routinely password-only ("redis://:secret@host"), so a username
    # alone is not the test — either half means a credential is in play.
    if (parsed.username or parsed.password) and scheme in _CREDENTIAL_SCHEMES:
        return {"authenticated": True, "mode": "connection_credential",
                "reason": "the connection string carries a credential"}

    if metadata.get("api_key_configured"):
        return {"authenticated": True, "mode": "connection_credential",
                "reason": "the connector was configured with an API key"}

    if metadata.get("credential_configured"):
        sources = ", ".join(metadata.get("credential_sources") or []) or "its settings"
        return {"authenticated": True, "mode": "connection_credential",
                "reason": f"the connector was given a credential ({sources})"}

    return {"authenticated": None, "mode": "undetermined",
            "reason": "no credential is visible in the connection, and "
                      "configuration alone cannot say whether the server "
                      "requires one"}


def probe_anonymous_access(endpoint: str, *, kind: str = "",
                           timeout: float = 3.0) -> dict:
    """Ask the store's own endpoint one unauthenticated question.

    Returns {'probed': bool, 'anonymous': bool|None, 'reach': str,
             'path': str|None, 'status': int|None, 'reason': str}.

    ``anonymous=True`` means an unauthenticated request succeeded.
    ``reach='data'`` means what succeeded would enumerate the customer's own
    collections, which is materially worse than a liveness endpoint answering.
    """
    import urllib.error
    import urllib.request

    kind = (kind or "").lower()
    paths = _PROBE_PATHS.get(kind)
    if not paths:
        return {"probed": False, "anonymous": None, "reach": "none", "path": None,
                "status": None,
                "reason": f"no unauthenticated HTTP probe is defined for {kind or 'this kind'}"}

    base = endpoint.rstrip("/")
    if "://" not in base:
        base = f"http://{base}"

    denied = False
    liveness_only = False
    for path, reach in paths:
        url = f"{base}{path}"
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                status = int(getattr(resp, "status", 0) or 0)
        except urllib.error.HTTPError as e:
            status = int(e.code)
            if status in (401, 403):
                denied = True
                continue
            continue
        except Exception:
            # Unreachable, TLS failure, timeout: says nothing about auth.
            continue

        if 200 <= status < 300:
            if reach == "data":
                return {"probed": True, "anonymous": True, "reach": "data",
                        "path": path, "status": status,
                        "reason": f"an unauthenticated GET {path} returned {status}"}
            liveness_only = True

    if denied:
        return {"probed": True, "anonymous": False, "reach": "denied", "path": None,
                "status": None,
                "reason": "the store refused an unauthenticated request"}
    if liveness_only:
        return {"probed": True, "anonymous": None, "reach": "liveness", "path": None,
                "status": None,
                "reason": "a liveness endpoint answered anonymously, which does not "
                          "establish whether data is readable without a credential"}
    return {"probed": True, "anonymous": None, "reach": "none", "path": None,
            "status": None,
            "reason": "the store did not answer the unauthenticated probe"}


def check_authentication(
    store: VectorStore,
    *,
    probe: bool = True,
    timeout: float = 3.0,
    exposure: Optional[str] = None,
    prober: Optional[Callable[..., dict]] = None,
    session_auth: Optional[dict] = None,
) -> list[Finding]:
    """Emit a finding when a store may serve data without a credential.

    ``exposure`` is the verdict from :func:`classify_endpoint`, passed in so the
    check does not resolve DNS a second time. A store that is both publicly
    reachable and anonymously readable is the worst case and is reported as
    such.
    """
    status = authentication_status(store.endpoint, kind=store.kind,
                                   metadata=store.metadata, session_auth=session_auth)
    result = {"probed": False, "anonymous": None, "reach": "none", "path": None,
              "status": None, "reason": "the probe was not run"}
    if probe and status["mode"] != "not_applicable":
        run = prober or probe_anonymous_access
        result = run(store.endpoint, kind=store.kind, timeout=timeout)

    evidence = {"endpoint": store.endpoint, **status,
                "probe": {k: v for k, v in result.items() if k != "reason"},
                "probe_reason": result["reason"]}
    findings: list[Finding] = []

    def mk(severity, title, desc, remediation) -> Finding:
        return Finding(
            id=f"find-{uuid.uuid4().hex[:10]}",
            title=title,
            severity=severity,
            category="authentication",
            store=store.name,
            description=desc,
            evidence=evidence,
            remediation=remediation,
        )

    if status["mode"] == "not_applicable":
        return findings

    if status["authenticated"] is False:
        public = exposure in ("public", "managed_public")
        findings.append(mk(
            Severity.CRITICAL if public else Severity.HIGH,
            f"Vector store '{store.name}' admitted VecShield without authentication",
            f"{status['reason']}. "
            + ("The endpoint is also reachable from the public internet. "
               if public else "")
            + "Any client that reaches the server along the same path (host, database "
              "and user matching the same pg_hba.conf rule) is admitted the same way, "
              "with this role's access to the vector tables. A connection pooler in "
              "front of the server authenticates clients separately; this describes "
              "the server's own rule.",
            "Replace trust with scram-sha-256 (or certificate authentication) in the "
            "pg_hba.conf rule this connection matched, reload the configuration, and "
            "repeat this check.",
        ))
        return findings

    if result["anonymous"] is True:
        public = exposure in ("public", "managed_public")
        findings.append(mk(
            Severity.CRITICAL if public else Severity.HIGH,
            f"Vector store '{store.name}' serves data without authentication",
            f"{result['reason']}. "
            + ("The endpoint is also reachable from the public internet, so anyone "
               "who finds it can read every collection in this store. "
               if public else
               "Anyone who can reach this endpoint can read every collection in "
               "this store, including from inside the network perimeter. ")
            + ("A credential is configured on this connector, which means the "
               "server is not enforcing the one it was given."
               if status["authenticated"] else
               "No credential is configured on this connector either."),
            "Require authentication at the store itself — an API key, JWT, or the "
            "provider's access control — and confirm it is enforced by repeating "
            "this check. Network controls in front of an open store limit who can "
            "reach it, but they do not authenticate anyone.",
        ))
        return findings

    if status["authenticated"] is None and result["anonymous"] is not False:
        findings.append(mk(
            Severity.MEDIUM,
            f"Vector store '{store.name}' authentication is unverified",
            f"{status['reason']}. {result['reason']}. This is not evidence the "
            "store is open; it is evidence the check could not establish that it "
            "is closed.",
            "Confirm the store requires a credential, and record how that was "
            "established. If this store kind has no unauthenticated probe, attach "
            "the server's access-control configuration as evidence instead.",
        ))

    return findings
