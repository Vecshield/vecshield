"""Opt-in active probe: does the store accept a plaintext client? (VCR-02)

``transport_encryption`` says whether *VecShield's* connection is encrypted.
This asks the different question regulators care about for data in transit:
would the store let a careless client in without TLS?

Safety is the design constraint, and it is structural rather than a promise:

* The probe is given the endpoint string only. It never sees the connector,
  its password, API key or token, so it has nothing to leak.
* User info in the endpoint (``user:pass@``) is discarded before any socket
  is opened. Only host and port are used.
* Postgres: the probe speaks the startup message itself, over a raw socket,
  with a throwaway role name and the configured database name. It never sends
  a password message and closes as soon as the server answers. libpq is not
  used, because libpq would read ``PGPASSWORD``, ``~/.pgpass`` and service
  files and could send a real password over the plaintext connection.
* HTTP(S): only when the configured endpoint is ``https://``. One ``GET /`` to
  the ``http://`` equivalent with no auth header and no cookies, redirects not
  followed, a short timeout, and at most a few hundred bytes read.

Anything the probe cannot interpret is ``plaintext_accepted=None``, reported
as not verified. A probe that cannot run says so; it never reads as a pass.
"""

from __future__ import annotations

import re
import secrets
import socket
import struct
from typing import Any, Callable, Optional
from urllib.parse import urlsplit

#: The only header the HTTP probe sends besides Host. No Authorization,
#: api-key, Cookie or anything derived from the connector's configuration.
PROBE_HEADERS = {"User-Agent": "VecShield-TLS-enforcement-probe", "Connection": "close"}

_DEFAULT_PG_PORT = 5432
_MAX_READ = 512


def _result(accepted: Optional[bool], method: Optional[str], reason: str,
            **evidence: Any) -> dict[str, Any]:
    return {"plaintext_accepted": accepted, "method": method, "reason": reason,
            "evidence": evidence}


def probe_tls_enforcement(
    endpoint: str,
    *,
    kind: str = "",
    timeout: float = 3.0,
    http_get: Optional[Callable[..., tuple[int, dict, bytes]]] = None,
    open_socket: Optional[Callable[..., Any]] = None,
) -> dict[str, Any]:
    """Try the store's plaintext equivalent without credentials; classify the answer.

    Returns ``{"plaintext_accepted": bool|None, "method": "active_probe"|None,
    "reason": str, "evidence": {...}}``. ``http_get(host, port, timeout)``
    and ``open_socket(host, port, timeout)`` are injectable so tests never
    touch the network; neither receives anything but a host, port and timeout.
    """
    ep = (endpoint or "").strip()
    parts = urlsplit(ep if "://" in ep else f"//{ep}")
    scheme = (parts.scheme or "").lower()
    kind = (kind or "").lower()

    if scheme in ("postgresql", "postgres") or kind == "pgvector":
        target = _pg_target(ep)
        if target is None:
            return _result(None, None, "the Postgres host could not be read from the "
                                       "endpoint, so no probe was sent")
        host, port, dbname = target
        return probe_postgres_plaintext(host, port, dbname, timeout=timeout,
                                        open_socket=open_socket)

    if scheme == "https":
        https_host = parts.hostname
        if not https_host:
            return _result(None, None, "the endpoint has no host to probe")
        try:
            port = parts.port or 80
        except ValueError:
            return _result(None, None, "the endpoint port could not be read")
        return probe_http_plaintext(https_host, port, timeout=timeout, http_get=http_get)

    if scheme == "http":
        return _result(None, None, "the configured endpoint is already plaintext; "
                                   "there is no TLS to test enforcement of")
    return _result(None, None, f"no safe plaintext probe is defined for "
                               f"{scheme or kind or 'this endpoint'}")


# ---- HTTP -----------------------------------------------------------------

_TLS_REQUIRED_MARKERS = (
    "plain http request was sent to https port",
    "http request to an https server",
    "plain http to an ssl-enabled server",
    "requires tls",
    "tls required",
    "ssl required",
)

def _default_http_get(host: str, port: int, timeout: float) -> tuple[int, dict, bytes]:
    import http.client

    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", "/", headers=dict(PROBE_HEADERS))
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        return int(resp.status), headers, resp.read(_MAX_READ)
    finally:
        conn.close()


def probe_http_plaintext(host: str, port: int, *, timeout: float = 3.0,
                         http_get: Optional[Callable[..., tuple[int, dict, bytes]]] = None
                         ) -> dict[str, Any]:
    """GET / over plain HTTP, no credentials, redirects not followed."""
    import http.client

    get = http_get or _default_http_get
    target = f"http://{host}:{port}/"
    try:
        status, headers, body = get(host, port, timeout)
    except (ConnectionRefusedError, ConnectionResetError, http.client.BadStatusLine,
            http.client.RemoteDisconnected, BrokenPipeError) as exc:
        return _result(False, "active_probe",
                       f"the plaintext request to {target} was refused "
                       f"({type(exc).__name__})", target=target)
    except (socket.timeout, TimeoutError) as exc:
        return _result(None, "active_probe",
                       f"the plaintext request to {target} timed out; a silent drop "
                       f"is not proof of refusal ({type(exc).__name__})", target=target)
    except Exception as exc:  # noqa: BLE001 - DNS, routing: says nothing about TLS
        return _result(None, "active_probe",
                       f"the plaintext request to {target} could not be made "
                       f"({type(exc).__name__})", target=target)

    headers = {str(k).lower(): v for k, v in (headers or {}).items()}
    text = (body or b"")[:_MAX_READ].decode("latin-1", "replace").lower()
    location = str(headers.get("location", ""))
    # TLS listeners that parse the stray plaintext request answer 400 in their
    # own words: nginx ("plain HTTP request was sent to HTTPS port"), Go
    # net/http ("client sent an HTTP request to an HTTPS server"), Apache
    # ("speaking plain HTTP to an SSL-enabled server port"). None served data.
    if status == 400 and any(marker in text for marker in _TLS_REQUIRED_MARKERS):
        return _result(False, "active_probe",
                       f"{target} answered that TLS is required (HTTP 400)",
                       target=target, status=status)
    if 300 <= status < 400 and location.lower().startswith("https://"):
        # Nothing is served over plaintext, but a client that sent a credential
        # on this request has already sent it in clear. Neither pass nor fail.
        return _result(None, "active_probe",
                       f"{target} redirects to HTTPS (HTTP {status}); the request "
                       "itself still crossed the network unencrypted",
                       target=target, status=status, redirect="https")
    return _result(True, "active_probe",
                   f"{target} answered a plaintext request with HTTP {status}",
                   target=target, status=status)


# ---- Postgres -------------------------------------------------------------

def _pg_target(endpoint: str) -> Optional[tuple[str, int, str]]:
    """(host, port, dbname) from a URI or keyword DSN. Credentials are ignored."""
    if "://" in endpoint:
        parts = urlsplit(endpoint)
        netloc = parts.netloc.rsplit("@", 1)[-1]  # drop user:password
        first = netloc.split(",")[0]               # multi-host: the first one
        if first.startswith("["):                  # [v6]:port
            host, _, port_text = first[1:].partition("]")
            port_text = port_text.lstrip(":")
        elif ":" in first:
            host, port_text = first.rsplit(":", 1)
        else:
            host, port_text = first, ""
        dbname = parts.path.lstrip("/") or "postgres"
    else:
        kv = dict(re.findall(r"(\w+)\s*=\s*('(?:[^']*)'|\S+)", endpoint))
        host = kv.get("host", "").strip("'").split(",")[0]
        port_text = kv.get("port", "").strip("'").split(",")[0]
        dbname = kv.get("dbname", "postgres").strip("'")
    if not host or host.startswith("/"):
        return None  # Unix socket: no network path
    try:
        port = int(port_text) if port_text else _DEFAULT_PG_PORT
    except ValueError:
        return None
    return host, port, dbname


def throwaway_role() -> str:
    """A role name no real account uses, so no pg_hba user rule or .pgpass line matches."""
    return f"vecshield_tls_probe_{secrets.token_hex(4)}"


def _startup_message(user: str, database: str) -> bytes:
    body = struct.pack("!I", 196608)  # protocol 3.0
    for key, value in (("user", user), ("database", database),
                       ("application_name", "vecshield-tls-probe")):
        body += key.encode() + b"\x00" + value.encode() + b"\x00"
    body += b"\x00"
    return struct.pack("!I", len(body) + 4) + body


def _read_message(sock: Any) -> Optional[tuple[bytes, bytes]]:
    header = _recv_exact(sock, 5)
    if header is None or len(header) < 5:
        return None
    kind = header[:1]
    length = struct.unpack("!I", header[1:5])[0]
    payload = _recv_exact(sock, min(max(length - 4, 0), 8192)) or b""
    return kind, payload


def _recv_exact(sock: Any, n: int) -> Optional[bytes]:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None if not data else data
        data += chunk
    return data


def _error_fields(payload: bytes) -> dict[str, str]:
    fields: dict[str, str] = {}
    for part in payload.split(b"\x00"):
        if part:
            fields[chr(part[0])] = part[1:].decode("utf-8", "replace")
    return fields


def probe_postgres_plaintext(host: str, port: int, dbname: str, *, timeout: float = 3.0,
                             open_socket: Optional[Callable[..., Any]] = None,
                             role: Optional[str] = None) -> dict[str, Any]:
    """Open a non-TLS startup with a throwaway role and read the server's first answer.

    - an authentication request (or AuthenticationOk) means pg_hba matched a
      plaintext rule: plaintext accepted. The probe then hangs up; no password
      message is ever sent.
    - "no pg_hba.conf entry … no encryption" (or "SSL off") means no rule
      admits a non-TLS client for this database from this address.
    - anything else is not interpretable and is reported as not verified.

    A rejection is only as broad as the throwaway role: pg_hba can admit a
    specific role without TLS, and that rule is never exercised. So a refusal
    is reported as not verified — refused for a test user, per-user rules
    unchecked — and never as proof that plaintext is refused.
    """
    connect = open_socket or (lambda h, p, t: socket.create_connection((h, p), timeout=t))
    user = role or throwaway_role()
    target = f"{host}:{port}/{dbname}"
    try:
        sock = connect(host, port, timeout)
    except Exception as exc:  # noqa: BLE001
        return _result(None, "active_probe",
                       f"no TCP connection to {host}:{port} ({type(exc).__name__}); "
                       "that says nothing about TLS", target=target)
    try:
        sock.sendall(_startup_message(user, dbname))
        message = None
        for _ in range(4):  # skip NegotiateProtocolVersion / notices
            message = _read_message(sock)
            if message is None or message[0] not in (b"v", b"N"):
                break
    except Exception as exc:  # noqa: BLE001
        return _result(None, "active_probe",
                       f"the plaintext startup to {target} failed "
                       f"({type(exc).__name__})", target=target)
    finally:
        try:
            sock.close()
        except Exception:  # pragma: no cover
            pass

    if message is None:
        return _result(None, "active_probe",
                       f"{target} closed the plaintext connection without an answer",
                       target=target)
    kind, payload = message
    if kind == b"R":
        return _result(True, "active_probe",
                       f"{target} asked a plaintext client to authenticate: pg_hba "
                       "admits connections without TLS", target=target)
    if kind != b"E":
        return _result(None, "active_probe",
                       f"{target} answered with an unexpected message", target=target)
    fields = _error_fields(payload)
    code, text = fields.get("C", ""), fields.get("M", "").lower()
    evidence = {"target": target, "sqlstate": code}
    if ("no pg_hba.conf entry" in text or "pg_hba.conf rejects" in text) and \
            ("no encryption" in text or "ssl off" in text):
        return _result(None, "active_probe",
                       f"Plaintext was refused for a test user on {target}, but "
                       "per-user rules could not be checked: pg_hba may still admit "
                       "a specific role without TLS", refused_for_test_role=True,
                       **evidence)
    if 'role "' in text and "does not exist" in text:
        return _result(True, "active_probe",
                       f"{target} matched a pg_hba rule for a plaintext client and "
                       "only then rejected the unknown role", **evidence)
    if "authentication failed" in text:
        return _result(True, "active_probe",
                       f"{target} attempted authentication over plaintext", **evidence)
    return _result(None, "active_probe",
                   f"{target} rejected the plaintext client for a reason the probe "
                   f"cannot interpret (SQLSTATE {code or 'unknown'})", **evidence)
