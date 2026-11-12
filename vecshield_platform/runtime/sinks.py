"""Alert sinks: where confirmed alerts go.

A sink must never raise into the monitored query path — the engine calls sinks
inside a fail-open guard, but sinks defend themselves too (especially the
network one). Outbound delivery failures are logged, never propagated.
"""

from __future__ import annotations

import json
import logging
import sys
import threading
from abc import ABC, abstractmethod
from typing import Any, Callable, Optional

from vecshield.models import Severity
from vecshield_platform.runtime.events import Alert

logger = logging.getLogger(__name__)


class AlertSink(ABC):
    @abstractmethod
    def emit(self, alert: Alert) -> None:
        ...


class InMemorySink(AlertSink):
    """Collects alerts in a list. Used by tests and for forensic replay."""

    def __init__(self) -> None:
        self.alerts: list[Alert] = []

    def emit(self, alert: Alert) -> None:
        self.alerts.append(alert)

    def __len__(self) -> int:
        return len(self.alerts)


class ConsoleSink(AlertSink):
    """Human-readable line to stderr (so it doesn't pollute stdout data)."""

    def emit(self, alert: Alert) -> None:
        print(
            f"[VECSHIELD ALERT] {alert.severity.value.upper()} {alert.rule} "
            f"principal={alert.principal} :: {alert.message}",
            file=sys.stderr,
        )


class PersistentAlertSink(AlertSink):
    """Persist confirmed alerts to an ``AlertStore`` (SQLite).

    This is the sink that turns the runtime monitor from replay-only into a live
    feature: the engine dispatches here, and the alert becomes queryable through
    the REST API / dashboard. Like every sink, it never raises into the monitored
    query path — a storage failure is counted and logged, not propagated.
    """

    def __init__(self, store: Any) -> None:
        self.store = store
        self.persisted = 0
        self.failed = 0

    def emit(self, alert: Alert) -> None:
        try:
            self.store.save(alert)
            self.persisted += 1
        except Exception as e:  # noqa: BLE001 — persistence must never raise
            self.failed += 1
            logger.warning("alert persistence failed: %s", e)


def _slack_payload(alert: Alert) -> dict:
    return {"text": f":rotating_light: *VecShield {alert.severity.value.upper()}* "
                    f"`{alert.rule}` — {alert.message}",
            "alert": alert.to_dict()}


def _generic_payload(alert: Alert) -> dict:
    """Raw alert JSON — for a generic HTTP receiver."""
    return alert.to_dict()


# PagerDuty Events v2 severity vocabulary: critical | error | warning | info.
_PAGERDUTY_SEVERITY = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "info",
    Severity.INFO: "info",
}


def _pagerduty_payload(routing_key: Optional[str] = None) -> Callable[[Alert], dict]:
    """Build a PagerDuty Events v2 ``trigger`` payload formatter.

    Posting the returned payload to ``https://events.pagerduty.com/v2/enqueue``
    opens/updates an incident keyed on ``dedup_key``.
    """
    def _fmt(alert: Alert) -> dict:
        return {
            "routing_key": routing_key or "",
            "event_action": "trigger",
            "dedup_key": alert.dedup_key,
            "payload": {
                "summary": f"VecShield {alert.severity.value.upper()} "
                           f"{alert.rule}: {alert.message}",
                "severity": _PAGERDUTY_SEVERITY.get(alert.severity, "error"),
                "source": alert.collection or "vecshield",
                "custom_details": alert.to_dict(),
            },
        }
    return _fmt


class WebhookDeliveryError(Exception):
    """A webhook delivery that was refused or did not finish in time."""


class WebhookURLError(ValueError):
    """A webhook URL this deployment refuses to deliver to (F2).

    Raised when an alerting config is saved and again before each delivery,
    because a name that resolved to a public address when it was saved can
    resolve to an internal one later (DNS rebinding).
    """


#: Opt in to cleartext ``http://`` webhooks (e.g. a receiver on a trusted
#: network). Off by default: an alert and a webhook's path credential would
#: otherwise cross the network in the clear.
ALLOW_HTTP_ENV = "VECSHIELD_ALLOW_HTTP_WEBHOOKS"
#: Comma-separated hosts (exact, or ``.suffix``) and IP networks (CIDR) that a
#: webhook may use even though they resolve to a non-public address.
HOST_ALLOW_ENV = "VECSHIELD_WEBHOOK_HOST_ALLOW"
#: Opt in to delivering through the ``HTTPS_PROXY``/``HTTP_PROXY`` environment
#: proxy. The target host is still resolved and checked before each request,
#: but the connection goes to the operator's proxy, which is not re-checked.
USE_ENV_PROXY_ENV = "VECSHIELD_WEBHOOK_USE_ENV_PROXY"

#: Well-known cloud instance-metadata addresses, named in refusals. All of them
#: are also non-global, so the general rule already refuses them.
METADATA_ADDRESSES = frozenset({
    "169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254",
})


def _truthy(name: str) -> bool:
    import os
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _host_allowlist() -> tuple[set[str], list]:
    import ipaddress
    import os

    names: set[str] = set()
    nets: list = []
    for part in os.environ.get(HOST_ALLOW_ENV, "").split(","):
        part = part.strip().lower()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            names.add(part.rstrip("."))
    return names, nets


def _host_allowed(host: str, names: set[str]) -> bool:
    host = host.lower().rstrip(".")
    return host in names or any(n.startswith(".") and host.endswith(n) for n in names)


def _address_refusal(ip_text: str, nets: list) -> "str | None":
    """Why ``ip_text`` may not receive a webhook, or None if it may."""
    import ipaddress

    try:
        ip = ipaddress.ip_address(ip_text.split("%", 1)[0])
    except ValueError:
        return f"{ip_text} is not an IP address"
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    if any(ip in net for net in nets):
        return None
    if str(ip) in METADATA_ADDRESSES:
        return f"{ip} is a cloud instance-metadata address"
    if ip.is_loopback:
        return f"{ip} is a loopback address"
    if ip.is_link_local:
        return f"{ip} is a link-local address"
    if ip.is_private:
        return f"{ip} is a private-network address"
    if not ip.is_global or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return f"{ip} is not a public address"
    return None


def _refusal_hint() -> str:
    return (f"allow the host explicitly with {HOST_ALLOW_ENV} if this receiver "
            "is meant to be internal")


def _resolve(host: str, port: int) -> list[str]:
    import socket

    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(info[4][0] for info in infos))


def validate_webhook_url(url: str, *, resolve: bool = True,
                         require_resolution: bool = False) -> None:
    """Refuse a webhook URL that could leak alerts or reach internal services.

    * The scheme is ``https`` (``http`` only with ``VECSHIELD_ALLOW_HTTP_WEBHOOKS=1``).
    * The host must not be, or resolve to, a loopback, link-local, private
      (RFC 1918 / ULA), metadata or otherwise non-public address, unless it
      is allowlisted in ``VECSHIELD_WEBHOOK_HOST_ALLOW``.

    ``resolve=False`` checks only what the URL itself says (scheme and a
    literal IP host). With ``resolve=True`` a name is resolved; when it does
    not resolve the URL is accepted unless ``require_resolution`` is set (the
    save path, where the receiver may be unreachable from here today; every
    delivery checks again). Raises :class:`WebhookURLError` naming the rule.
    """
    import ipaddress
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise WebhookURLError(f"webhook URL is not valid ({exc})") from None
    scheme = (parts.scheme or "").lower()
    if scheme == "http":
        if not _truthy(ALLOW_HTTP_ENV):
            raise WebhookURLError(
                "webhook URLs must use https; cleartext http is refused unless "
                f"{ALLOW_HTTP_ENV}=1")
    elif scheme != "https":
        raise WebhookURLError(
            f"webhook URLs must use https (got {scheme or 'no'} scheme)")
    host = parts.hostname
    if not host:
        raise WebhookURLError("webhook URL has no host")
    names, nets = _host_allowlist()
    if _host_allowed(host, names):
        return
    try:
        literal = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        literal = None
    if literal is not None:
        addresses = [host]
    elif host.lower().rstrip(".") in {"localhost", "localhost.localdomain"} \
            or host.lower().endswith(".localhost"):
        raise WebhookURLError(
            f"webhook host {host} is a loopback name; {_refusal_hint()}")
    elif not resolve:
        return
    else:
        try:
            addresses = _resolve(host, port or (443 if scheme == "https" else 80))
        except OSError:
            if require_resolution:
                raise WebhookURLError(f"webhook host {host} does not resolve") from None
            return
    for address in addresses:
        why = _address_refusal(address, nets)
        if why:
            raise WebhookURLError(
                f"webhook host {host} refused: {why}; {_refusal_hint()}")


def _guarded_create_connection(address, timeout=None, source_address=None, **kwargs):
    """``socket.create_connection`` that connects only to checked addresses.

    The name is resolved once, every address is checked, and the socket is
    opened to one of those same addresses, so a rebinding resolver cannot
    swap in an internal address between the check and the connect.
    """
    import socket

    host, port = address
    names, nets = _host_allowlist()
    allowed_by_name = _host_allowed(str(host), names)
    addresses = _resolve(host, port)
    if not allowed_by_name:
        for ip in addresses:
            why = _address_refusal(ip, nets)
            if why:
                raise WebhookURLError(
                    f"webhook host {host} refused at delivery: {why}; {_refusal_hint()}")
    last: Exception = OSError(f"no address for {host}")
    for ip in addresses:
        try:
            return socket.create_connection((ip, port), timeout, source_address)
        except OSError as exc:
            last = exc
    raise last


def _no_redirect_opener():
    """An opener with only HTTP(S) handlers, checked sockets and no redirects.

    Built by hand rather than with ``build_opener``, so ``file:``, ``ftp:``
    and ``data:`` handlers are never installed, and the environment proxy is
    used only when ``VECSHIELD_WEBHOOK_USE_ENV_PROXY=1``.
    """
    import http.client
    import ssl
    import urllib.error
    import urllib.request

    class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            # A redirect could send the alert (and a webhook's credentials in
            # its payload) to a host the operator never configured.
            raise urllib.error.HTTPError(
                req.full_url, code,
                f"refused to follow a {code} redirect: webhooks are delivered "
                "only to the configured URL", headers, fp)

    via_proxy = _truthy(USE_ENV_PROXY_ENV)

    class _GuardedHTTPConnection(http.client.HTTPConnection):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            if not via_proxy:
                self._create_connection = _guarded_create_connection

    class _GuardedHTTPSConnection(http.client.HTTPSConnection):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            if not via_proxy:
                self._create_connection = _guarded_create_connection

    class _HTTP(urllib.request.HTTPHandler):
        def http_open(self, req):
            return self.do_open(_GuardedHTTPConnection, req)

    class _HTTPS(urllib.request.HTTPSHandler):
        def https_open(self, req):
            return self.do_open(_GuardedHTTPSConnection, req,
                                context=ssl.create_default_context())

    opener = urllib.request.OpenerDirector()
    handlers: list = [_HTTP(), _HTTPS(), _RefuseRedirects(),
                      urllib.request.HTTPDefaultErrorHandler(),
                      urllib.request.HTTPErrorProcessor(),
                      # Any other scheme fails loudly instead of returning None.
                      urllib.request.UnknownHandler()]
    if via_proxy:
        handlers.insert(0, urllib.request.ProxyHandler())
    for handler in handlers:
        opener.add_handler(handler)
    return opener


class WebhookSink(AlertSink):
    """POST alerts as JSON to a webhook (Slack / PagerDuty / generic).

    Uses stdlib urllib (no extra deps) and swallows every error so a flaky or
    unreachable endpoint can never break query handling. ``timeout`` is an
    overall deadline for ``emit`` (connect, send and the response head), not
    only a per-socket-read timeout, so a receiver that trickles its response
    cannot stall the caller. The request runs on a short-lived delivery thread
    that ``emit`` waits on for at most the deadline; at most
    ``max_in_flight`` deliveries may still be running (e.g. against a stalled
    receiver) before further alerts to this sink are dropped and counted as
    failed rather than queued without bound. Redirects are never followed.
    """

    def __init__(self, url: str, *, timeout: float = 3.0,
                 formatter: Optional[Callable[[Alert], dict]] = None,
                 on_error: Optional[Callable[[Exception], None]] = None,
                 max_in_flight: int = 2):
        self.url = url
        self.timeout = timeout
        self.formatter = formatter or _slack_payload
        self.on_error = on_error
        self.delivered = 0
        self.failed = 0
        self._in_flight = threading.BoundedSemaphore(max(1, max_in_flight))
        self._opener = _no_redirect_opener()

    def _post(self, data: bytes) -> None:
        import urllib.request

        # Re-checked at every delivery: the saved URL was checked when it was
        # saved, but its host can resolve somewhere else now.
        validate_webhook_url(self.url, resolve=True, require_resolution=True)
        req = urllib.request.Request(
            self.url, data=data,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with self._opener.open(req, timeout=self.timeout):  # noqa: S310
            pass

    def emit(self, alert: Alert) -> None:
        try:
            data = json.dumps(self.formatter(alert)).encode("utf-8")
            if not self._in_flight.acquire(blocking=False):
                raise WebhookDeliveryError(
                    "earlier deliveries to this webhook are still in flight; "
                    "alert dropped rather than queued")
            done = threading.Event()
            outcome: dict[str, Any] = {}

            def _deliver() -> None:
                try:
                    self._post(data)
                except Exception as exc:  # noqa: BLE001 — reported by emit
                    outcome["error"] = exc
                finally:
                    self._in_flight.release()
                    done.set()

            threading.Thread(target=_deliver, name="vs-webhook",
                             daemon=True).start()
            if not done.wait(self.timeout):
                raise WebhookDeliveryError(
                    f"webhook did not respond within the {self.timeout:g}s deadline")
            if "error" in outcome:
                raise outcome["error"]
            self.delivered += 1
        except Exception as e:  # noqa: BLE001 — delivery must never raise
            self.failed += 1
            if self.on_error:
                self.on_error(e)
            else:
                logger.warning("webhook delivery failed: %s", e)


def build_sinks(config) -> list[AlertSink]:
    """Build production alert sinks from an ``AlertingConfig``.

    Returns a ``WebhookSink`` per configured webhook (formatted for its style)
    plus an optional ``ConsoleSink``. Never returns an ``InMemorySink`` — that
    is a test/forensic sink only. An empty list means "no delivery configured".
    """
    sinks: list[AlertSink] = []
    for wh in getattr(config, "webhooks", []) or []:
        url = wh.get("url") if isinstance(wh, dict) else wh
        if not url:
            continue
        style = (wh.get("style") if isinstance(wh, dict) else "slack") or "slack"
        if style == "pagerduty":
            formatter = _pagerduty_payload(
                wh.get("routing_key") if isinstance(wh, dict) else None)
        elif style == "generic":
            formatter = _generic_payload
        else:
            formatter = _slack_payload
        sinks.append(WebhookSink(url, formatter=formatter))
    if getattr(config, "console", False):
        sinks.append(ConsoleSink())
    return sinks
