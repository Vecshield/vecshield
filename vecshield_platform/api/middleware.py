"""ASGI middleware for API surface hardening (improvement plan 1.9, F8).

Three small, dependency-free middlewares:

  * :class:`SecurityHeadersMiddleware` — always installed. Adds
    ``X-Content-Type-Options``, ``Referrer-Policy``, ``X-Frame-Options`` and a
    Content-Security-Policy to every response (the route's own CSP wins; HTML
    without one gets a no-script policy suited to the downloadable reports),
    plus HSTS when the request arrived over https or ``VECSHIELD_HSTS=1``.
  * :class:`MaxBodySizeMiddleware` — rejects oversized request bodies with 413,
    both from a declared ``Content-Length`` and by counting the bytes actually
    received, so a chunked upload without a length cannot bypass it.
  * :class:`RateLimitMiddleware` — fixed-window per-caller rate limiting,
    returning 429 with a ``Retry-After`` header. A request is keyed on a hash
    of its bearer credential only when that credential validates; anything
    else (no credential, a junk or expired one, and every ``/auth/login``) is
    keyed on the client IP, so rotating made-up ``Authorization`` headers
    cannot mint a fresh bucket per request.

The body and rate limits are opt-in: ``create_app`` only installs them when a
limit is configured. Rate-limit state is in-process, so limits are per-worker —
run a single worker, or front the API with a shared limiter, when a global
limit is required.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from typing import Awaitable, Callable, Iterable, Optional, Tuple

_Send = Callable[[dict], Awaitable[None]]
_Receive = Callable[[], Awaitable[dict]]


async def _send_json(send: _Send, status: int, payload: dict,
                     extra_headers: Optional[Iterable[Tuple[bytes, bytes]]] = None) -> None:
    body = json.dumps(payload).encode("utf-8")
    headers = [(b"content-type", b"application/json"),
               (b"content-length", str(len(body)).encode("ascii"))]
    if extra_headers:
        headers.extend(extra_headers)
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


#: CSP for HTML responses that set none of their own: the downloadable audit
#: and DPIA reports. They carry inline ``<style>`` and no script, so script is
#: refused outright and nothing may frame them.
REPORT_CSP = ("default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
              "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
#: CSP for every other response (JSON, text, static assets): nothing loads and
#: nothing frames. Harmless for data, and it neuters a response that a browser
#: is tricked into rendering as a document.
DEFAULT_CSP = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'"
HSTS_VALUE = "max-age=31536000; includeSubDomains"


class SecurityHeadersMiddleware:
    """Set baseline security headers on every HTTP response (F8).

    Headers a route already set are left alone, so the console page keeps its
    own CSP. ``csp_exempt_paths`` (the interactive API docs, which load their
    own scripts) receive every header except the CSP. HSTS is sent when the
    request came in over https, or on every response when ``hsts=True``
    (TLS terminated by a proxy in front of the server).
    """

    def __init__(self, app, *, hsts: bool = False,
                 csp_exempt_paths: Iterable[str] = ()):
        self.app = app
        self.hsts = hsts
        self.csp_exempt = tuple(csp_exempt_paths)

    async def __call__(self, scope, receive: _Receive, send: _Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path") or ""
        exempt = any(path == p or path.startswith(p + "/") for p in self.csp_exempt)
        https = scope.get("scheme") == "https"

        async def send_with_headers(message: dict) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers") or [])
                present = {name.lower() for name, _ in headers}
                ctype = next((v for n, v in headers if n.lower() == b"content-type"), b"")

                def add(name: bytes, value: str) -> None:
                    if name not in present:
                        headers.append((name, value.encode("latin-1")))

                add(b"x-content-type-options", "nosniff")
                add(b"referrer-policy", "no-referrer")
                add(b"x-frame-options", "DENY")
                if not exempt:
                    add(b"content-security-policy",
                        REPORT_CSP if ctype.lower().startswith(b"text/html") else DEFAULT_CSP)
                if self.hsts or https:
                    add(b"strict-transport-security", HSTS_VALUE)
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)


class _BodyTooLarge(Exception):
    """Raised into the app when a streamed body passes the limit."""


class MaxBodySizeMiddleware:
    """Reject request bodies larger than ``max_bytes`` with 413.

    A declared ``Content-Length`` over the limit is refused before the app
    runs. The bytes actually received are also counted, so a body sent with
    ``Transfer-Encoding: chunked`` (no length) or a length that understates it
    is cut off at the limit: the 413 is sent at that point, the app's read
    fails, and anything the app tries to send afterwards is discarded.
    """

    def __init__(self, app, *, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    def _too_large(self) -> dict:
        return {"detail": f"request body too large (> {self.max_bytes} bytes)"}

    async def __call__(self, scope, receive: _Receive, send: _Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        for name, value in scope.get("headers") or []:
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    break
                if declared > self.max_bytes:
                    await _send_json(send, 413, self._too_large())
                    return
                break

        received = 0
        state = {"started": False, "rejected": False}

        async def counting_receive() -> dict:
            nonlocal received
            message = await receive()
            if message.get("type") == "http.request":
                received += len(message.get("body") or b"")
                if received > self.max_bytes:
                    if not state["started"] and not state["rejected"]:
                        state["rejected"] = True
                        await _send_json(send, 413, self._too_large())
                    raise _BodyTooLarge()
            return message

        async def guarded_send(message: dict) -> None:
            if state["rejected"]:
                return  # the 413 already went out
            if message.get("type") == "http.response.start":
                state["started"] = True
            await send(message)

        try:
            await self.app(scope, counting_receive, guarded_send)
        except _BodyTooLarge:
            if not state["started"] and not state["rejected"]:
                state["rejected"] = True
                await _send_json(send, 413, self._too_large())
        except Exception:
            if state["rejected"]:
                return  # the app's own error from the refused read
            raise


class RateLimiter:
    """Thread-safe fixed-window counter, keyed by an opaque caller id."""

    def __init__(self, limit: int, window_s: float, *,
                 clock: Callable[[], float] = time.monotonic):
        if limit <= 0:
            raise ValueError("rate limit must be positive")
        self.limit = limit
        self.window_s = float(window_s)
        self._clock = clock
        self._buckets: dict[str, Tuple[float, int]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> Tuple[bool, float]:
        """Register a hit for ``key``; return (allowed, seconds_until_reset)."""
        now = self._clock()
        with self._lock:
            start, count = self._buckets.get(key, (now, 0))
            if now - start >= self.window_s:
                start, count = now, 0
            count += 1
            self._buckets[key] = (start, count)
            if len(self._buckets) > 10_000:
                self._prune(now)
            retry_after = max(0.0, self.window_s - (now - start))
            return count <= self.limit, retry_after

    def _prune(self, now: float) -> None:
        stale = [k for k, (start, _) in self._buckets.items()
                 if now - start >= self.window_s]
        for k in stale:
            self._buckets.pop(k, None)


class RateLimitMiddleware:
    """Per-caller fixed-window rate limiting. Exempts probe paths and OPTIONS.

    ``credential_validator`` receives the raw ``Authorization`` header value
    and returns whether it identifies a real caller. Only then does the caller
    get a bucket of its own; otherwise the request counts against its client
    IP. Without a validator every request is keyed by IP. ``ip_only_paths``
    (sign-in by default) are always keyed by IP, since they are where guessing
    happens and carry no credential worth trusting.
    """

    def __init__(self, app, *, limit: int, window_s: float = 60.0,
                 exempt_paths: Iterable[str] = (),
                 credential_validator: Optional[Callable[[str], bool]] = None,
                 ip_only_paths: Iterable[str] = ("/auth/login",)):
        self.app = app
        self.limiter = RateLimiter(limit, window_s)
        self.exempt_paths = frozenset(exempt_paths)
        self.credential_validator = credential_validator
        self.ip_only_paths = frozenset(ip_only_paths)

    @staticmethod
    def _ip_key(scope) -> str:
        client = scope.get("client")
        return "ip:" + (client[0] if client else "unknown")

    def _caller_key(self, scope) -> str:
        if scope.get("path") in self.ip_only_paths or self.credential_validator is None:
            return self._ip_key(scope)
        for name, value in scope.get("headers") or []:
            if name == b"authorization":
                try:
                    valid = bool(self.credential_validator(value.decode("latin-1")))
                except Exception:  # noqa: BLE001 - an unusable credential is not a caller
                    valid = False
                if valid:
                    # Never key on the raw secret — a stable hash is enough.
                    return "tok:" + hashlib.sha256(value).hexdigest()[:32]
                break
        return self._ip_key(scope)

    async def __call__(self, scope, receive: _Receive, send: _Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        if scope.get("method") == "OPTIONS" or scope.get("path") in self.exempt_paths:
            await self.app(scope, receive, send)
            return
        allowed, retry_after = self.limiter.check(self._caller_key(scope))
        if not allowed:
            await _send_json(
                send, 429, {"detail": "rate limit exceeded"},
                extra_headers=[(b"retry-after", str(int(retry_after) + 1).encode("ascii"))],
            )
            return
        await self.app(scope, receive, send)
