"""Transport-encryption (TLS) checker.

Decides whether a store's *connection* is encrypted in transit, from three
sources in increasing strength:

  1. the endpoint string (every connector has one);
  2. TLS facts the connector recorded in ``VectorStore.metadata["transport"]``
     — a flag or DSN setting the endpoint string does not carry (MongoDB's
     endpoint is stripped because its URI can hold credentials; pgvector's
     host/port path never carried ``sslmode``);
  3. the live session, where the connector can report it
     (``Connector.transport_session_info()``, e.g. Postgres ``pg_stat_ssl``).

Endpoint strings are never rewritten to carry these facts: finding
fingerprints are keyed on them.

This says whether VecShield's own connection is encrypted. Whether the store
*refuses* plaintext clients is a different property, checked by
``transport_tls_enforcement``. Encryption at rest is checked separately too.

Scheme map:
  http://    -> plaintext  (Chroma, Qdrant, OpenSearch, Weaviate, Milvus)
  https://   -> TLS
  redis://   -> plaintext  ; rediss:// -> TLS
  postgresql://...sslmode=disable/allow -> plaintext ; require/verify-* -> TLS
  postgresql:// with no sslmode, or prefer -> unverified (opportunistic)
  mongodb://...tls=false           -> plaintext ; tls=true / +srv -> TLS

Managed SaaS stores are TLS-only and reported as encrypted.
"""

from __future__ import annotations

import re
import uuid
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

from vecshield.models import Finding, Severity, VectorStore
from vecshield_platform.posture.network import MANAGED_SAAS_KINDS

# Schemes that are encrypted on their own.
_TLS_SCHEMES = {"https", "rediss", "grpcs"}
# Schemes that are plaintext unless an explicit TLS flag overrides.
_PLAINTEXT_SCHEMES = {"http", "redis", "grpc", "ws"}


def transport_status(endpoint: str, *, kind: str = "", metadata: dict | None = None,
                     session: Optional[dict[str, Any]] = None) -> dict:
    """Return {'encrypted': bool|None, 'scheme': str, 'reason': str, 'source': str}.

    `encrypted=None` means undetermined (e.g. filesystem store or opaque
    provider pseudo-scheme). ``source`` names what decided it: ``session``,
    ``connector_flag``, ``dsn``, ``environment``, ``endpoint``,
    ``managed_service`` or ``filesystem``. A session observation, when given,
    outranks configuration: it is what the connection actually negotiated.

    ``certificate_verification`` is present when it is known: ``False`` means
    the client encrypts but accepts any server certificate. Every ``reason``
    is a complete sentence.
    """
    status = _configured_status(endpoint, kind=kind, metadata=metadata or {})
    if session and session.get("tls") is not None and status["source"] != "filesystem":
        encrypted = bool(session["tls"])
        via = session.get("source") or "the driver"
        status = {**status, "encrypted": encrypted, "source": "session",
                  "protocol": session.get("version"), "cipher": session.get("cipher"),
                  "reason": (f"The session VecShield opened negotiated "
                             f"{session.get('version') or 'TLS'} ({via})." if encrypted else
                             f"The session VecShield opened is not encrypted ({via}).")}
        if "certificate_verification" in session:
            status["certificate_verification"] = session["certificate_verification"]
    return status


def _configured_status(endpoint: str, *, kind: str, metadata: dict) -> dict:
    kind = (kind or "").lower()
    ep = (endpoint or "").strip()

    # Legacy explicit connector signal (e.g. OpenSearch's use_ssl flag).
    if "use_ssl" in metadata:
        enc = bool(metadata["use_ssl"])
        return {"encrypted": enc, "scheme": "opensearch",
                "reason": f"The connector sets use_ssl={enc}.", "source": "connector_flag"}

    parsed = urlparse(ep if "://" in ep else f"//{ep}", scheme="")
    scheme = (parsed.scheme or "").lower()

    transport = metadata.get("transport")
    if isinstance(transport, dict):
        decided = _from_transport(transport, scheme or kind)
        if decided is not None:
            return decided

    if ep.startswith("file://") or ep.startswith("/"):
        return {"encrypted": None, "scheme": "file",
                "reason": "This is a filesystem-backed store, with no transport to "
                          "encrypt.",
                "source": "filesystem"}

    if kind in MANAGED_SAAS_KINDS:
        return {"encrypted": True, "scheme": "https",
                "reason": f"The {kind} store is a managed SaaS service served over TLS "
                          "only.",
                "source": "managed_service"}

    if scheme in _TLS_SCHEMES:
        return {"encrypted": True, "scheme": scheme,
                "reason": f"The {scheme}:// scheme is TLS.", "source": "endpoint"}

    # Postgres: sslmode query/keyword.
    if scheme in ("postgresql", "postgres"):
        return _pg_status(ep, parsed)

    # Mongo: tls / ssl query param, or +srv (Atlas, always TLS).
    if scheme.startswith("mongodb"):
        return _mongo_status(scheme, parsed)

    if scheme in _PLAINTEXT_SCHEMES:
        return {"encrypted": False, "scheme": scheme,
                "reason": f"The {scheme}:// scheme is plaintext (no TLS).",
                "source": "endpoint"}

    return {"encrypted": None, "scheme": scheme or "unknown",
            "reason": "Transport encryption could not be determined from the endpoint.",
            "source": "endpoint"}


def _with_source(reason: str, source: str) -> str:
    """Append "(source)" inside a sentence's closing full stop."""
    return f"{reason[:-1] if reason.endswith('.') else reason} ({source})."


def _sentence(text: str) -> str:
    """A reason from any producer, as one capitalised sentence."""
    text = (text or "").strip()
    if not text:
        return text
    text = text[:1].upper() + text[1:]
    return text if text.endswith((".", "!", "?")) else text + "."


def _from_transport(transport: dict, fallback_scheme: str) -> Optional[dict]:
    """A verdict from connector-recorded TLS facts, or None to keep looking."""
    source = transport.get("source") or "connector_flag"
    if transport.get("sslmode"):
        status = _sslmode_status(str(transport["sslmode"]).lower())
        status["reason"] = _with_source(status["reason"], source)
        return {**status, "source": source}
    if transport.get("tls") is None:
        return None
    encrypted = bool(transport["tls"])
    scheme = transport.get("scheme") or fallback_scheme or "unknown"
    status = {"encrypted": encrypted, "scheme": scheme, "source": source,
              "reason": _sentence(transport.get("reason") or "") or
              (f"The connector is configured {'with' if encrypted else 'without'} "
               f"TLS ({source}).")}
    if "certificate_verification" in transport:
        status["certificate_verification"] = bool(transport["certificate_verification"])
    return status


def _sslmode_status(sslmode: str) -> dict:
    """libpq sslmode semantics. ``prefer`` is the libpq default and falls back
    to plaintext silently, so it is unverified, exactly like no sslmode.

    ``require`` encrypts without checking the server certificate; only
    ``verify-ca`` (chain) and ``verify-full`` (chain and host name) verify it.
    """
    if sslmode in ("disable", "allow"):
        return {"encrypted": False, "scheme": "postgresql", "sslmode": sslmode,
                "reason": f"The connection uses sslmode={sslmode}, so it is not "
                          "encrypted."}
    if sslmode == "require":
        return {"encrypted": True, "scheme": "postgresql", "sslmode": sslmode,
                "certificate_verification": False,
                "reason": "The connection uses sslmode=require."}
    if sslmode in ("verify-ca", "verify-full"):
        return {"encrypted": True, "scheme": "postgresql", "sslmode": sslmode,
                "certificate_verification": True,
                "reason": f"The connection uses sslmode={sslmode}."}
    if sslmode == "prefer":
        return {"encrypted": None, "scheme": "postgresql", "sslmode": sslmode,
                "certificate_verification": False,
                "reason": "With sslmode=prefer, TLS is opportunistic and falls back to "
                          "plaintext without error."}
    return {"encrypted": None, "scheme": "postgresql", "sslmode": sslmode or None,
            "reason": "No sslmode is set; libpq's default 'prefer' does not enforce TLS."}


def _pg_status(ep: str, parsed) -> dict:
    q = parse_qs(parsed.query)
    sslmode = (q.get("sslmode", [None])[0] or "").lower()
    if not sslmode:
        m = re.search(r"sslmode\s*=\s*([a-z-]+)", ep, re.I)
        sslmode = (m.group(1).lower() if m else "")
    return {**_sslmode_status(sslmode), "source": "endpoint"}


def _mongo_status(scheme: str, parsed) -> dict:
    q = {k.lower(): v for k, v in parse_qs(parsed.query).items()}
    tls = (q.get("tls", q.get("ssl", [None]))[0] or "").lower()
    insecure = any((q.get(k, [""])[0] or "").lower() in ("true", "1")
                   for k in ("tlsinsecure", "tlsallowinvalidcertificates"))
    if tls in ("true", "1"):
        status = {"encrypted": True, "scheme": scheme,
                  "reason": "The connection string sets tls=true.", "source": "endpoint"}
    elif tls in ("false", "0"):
        return {"encrypted": False, "scheme": scheme,
                "reason": "The connection string sets tls=false.", "source": "endpoint"}
    elif scheme == "mongodb+srv":
        status = {"encrypted": True, "scheme": scheme,
                  "reason": "The mongodb+srv scheme implies TLS (Atlas).",
                  "source": "endpoint"}
    else:
        return {"encrypted": None, "scheme": scheme,
                "reason": "No tls flag is set; the driver default does not enforce TLS.",
                "source": "endpoint"}
    if insecure:
        status["certificate_verification"] = False
    return status


def check_transport_encryption(
    store: VectorStore,
    *,
    require_tls: bool = True,
    session: Optional[dict[str, Any]] = None,
) -> list[Finding]:
    """Emit a finding when a store's connection is (or may be) plaintext.

    Titles and the ``endpoint`` evidence key are what fingerprints hash, so
    they stay fixed whichever source decided the verdict.
    """
    status = transport_status(store.endpoint, kind=store.kind,
                              metadata=store.metadata, session=session)
    findings: list[Finding] = []

    def mk(severity, title, desc, remediation) -> Finding:
        return Finding(
            id=f"find-{uuid.uuid4().hex[:10]}",
            title=title,
            severity=severity,
            category="transport_encryption",
            store=store.name,
            description=desc,
            evidence={"endpoint": store.endpoint, **status},
            remediation=remediation,
        )

    if not require_tls:
        return findings

    if status["encrypted"] is False:
        findings.append(mk(
            Severity.HIGH,
            f"Vector store '{store.name}' connection is not TLS-encrypted",
            f"{_sentence(status['reason'])} Embeddings and the raw text they encode "
            "travel in plaintext and can be intercepted on the network path.",
            "Enable TLS on the store and connect over https:// / rediss:// / "
            "sslmode=require. Terminate TLS at the store or a sidecar, not only "
            "at an external load balancer.",
        ))
    elif status["encrypted"] is None and status["scheme"] not in ("file",):
        findings.append(mk(
            Severity.MEDIUM,
            f"Vector store '{store.name}' transport encryption is unverified",
            f"{_sentence(status['reason'])} TLS is not explicitly enforced, so the "
            "connection may silently fall back to plaintext.",
            "Set the transport explicitly: sslmode=require (Postgres), tls=true "
            "(Mongo), or rediss:// (Redis). Do not rely on opportunistic TLS.",
        ))

    return findings


#: How each client turns certificate verification back on.
_VERIFY_REMEDIATION = {
    "opensearch": "Set verify_certs=True on the OpenSearch connection and give the "
                  "client the CA that signed the cluster's certificate.",
    "pgvector": "Connect with sslmode=verify-full and point sslrootcert at the CA "
                "that signed the server's certificate.",
    "mongodb": "Remove tlsInsecure and tlsAllowInvalidCertificates from the "
               "connection string, and set tlsCAFile if the server uses a private CA.",
    "redis": "Set ssl_cert_reqs='required' and ssl_ca_certs to the CA that signed "
             "the server's certificate.",
}


def check_tls_certificate_verification(
    store: VectorStore,
    *,
    session: Optional[dict[str, Any]] = None,
    status: Optional[dict] = None,
) -> list[Finding]:
    """Emit a finding when the connection is encrypted but the server certificate is not checked.

    Only an explicit ``certificate_verification: False`` on an encrypted
    connection counts; an unknown verification setting raises nothing. The
    category is separate from ``transport_encryption`` because that
    category's fingerprint is keyed on the endpoint alone, and a second
    finding there would collide with the first.
    """
    status = status or transport_status(store.endpoint, kind=store.kind,
                                        metadata=store.metadata, session=session)
    if status.get("encrypted") is not True or status.get("certificate_verification") is not False:
        return []
    kind = (store.kind or "").lower()
    return [Finding(
        id=f"find-{uuid.uuid4().hex[:10]}",
        title=f"Vector store '{store.name}' connection uses TLS without verifying the "
              "server certificate",
        severity=Severity.MEDIUM,
        category="tls_certificate_verification",
        store=store.name,
        description=(f"{_sentence(status.get('reason', ''))} The connection is "
                     "encrypted, but the client accepts any certificate the server "
                     "presents. Anyone who can intercept the network path and present "
                     "a certificate of their own can read and alter the traffic, "
                     "including credentials, queries and returned text."),
        evidence={"endpoint": store.endpoint, "scheme": status.get("scheme"),
                  "source": status.get("source"), "sslmode": status.get("sslmode"),
                  "certificate_verification": False},
        remediation=_VERIFY_REMEDIATION.get(
            kind, "Enable server certificate verification in the client and trust "
                  "only the CA that issued the store's certificate."),
    )]
