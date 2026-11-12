"""Sink tests: in-memory capture and resilient webhook delivery."""

from __future__ import annotations

from vecshield.models import Severity
from vecshield_platform.runtime.events import Alert
from vecshield_platform.runtime.sinks import InMemorySink, WebhookSink, _slack_payload


def _alert():
    return Alert(rule="bulk_volume", severity=Severity.HIGH, principal="svc",
                 timestamp=1.0, message="600 queries in 600s", dedup_key="svc:bulk")


def test_in_memory_sink_collects():
    s = InMemorySink()
    s.emit(_alert())
    assert len(s) == 1 and s.alerts[0].rule == "bulk_volume"


def test_slack_payload_shape():
    p = _slack_payload(_alert())
    assert "text" in p and "VecShield" in p["text"]
    assert p["alert"]["rule"] == "bulk_volume"


def test_webhook_failure_is_swallowed():
    # Unroutable port -> connection refused fast. Must NOT raise.
    errors = []
    sink = WebhookSink("http://127.0.0.1:1/hook", timeout=1.0,
                       on_error=errors.append)
    sink.emit(_alert())
    assert sink.failed == 1 and sink.delivered == 0
    assert errors  # the error was captured, not propagated


# --------------------------------------------------------------------------- #
# A slow receiver must not stall the monitored path                           #
# --------------------------------------------------------------------------- #

import http.server  # noqa: E402
import socketserver  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402


class _SlowDripHandler(http.server.BaseHTTPRequestHandler):
    """Accepts the POST, then drips the status line and headers one byte at a
    time, so every individual socket read finishes inside a per-read timeout
    and only an overall deadline can bound the delivery."""

    drip_s = 0.25

    def do_POST(self):  # noqa: N802
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        head = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Pad: slowslowslow\r\n\r\n"
        for i in range(len(head)):
            try:
                self.wfile.write(head[i:i + 1])
                self.wfile.flush()
            except OSError:
                return
            time.sleep(self.drip_s)
        self.close_connection = True

    def log_message(self, *args):
        pass


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def _serve(handler):
    server = _Server(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_slow_receiver_cannot_stall_emit_beyond_the_deadline(monkeypatch):
    monkeypatch.setenv("VECSHIELD_ALLOW_HTTP_WEBHOOKS", "1")
    monkeypatch.setenv("VECSHIELD_WEBHOOK_HOST_ALLOW", "127.0.0.1")
    server = _serve(_SlowDripHandler)
    try:
        sink = WebhookSink(f"http://127.0.0.1:{server.server_port}/hook",
                           timeout=1.0, on_error=lambda e: None)
        started = time.monotonic()
        sink.emit(_alert())
        elapsed = time.monotonic() - started
        # ~60 bytes x 0.25 s = 15 s if only the per-read timeout applied.
        assert elapsed < 2.5, elapsed
    finally:
        server.shutdown()


class _Target(http.server.BaseHTTPRequestHandler):
    hits: list = []

    def do_GET(self):  # noqa: N802
        _Target.hits.append(self.path)
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_POST = do_GET

    def log_message(self, *args):
        pass


def test_webhook_does_not_follow_redirects(monkeypatch):
    # The receivers are local: allow them explicitly (F2 refuses loopback and
    # cleartext http by default).
    monkeypatch.setenv("VECSHIELD_ALLOW_HTTP_WEBHOOKS", "1")
    monkeypatch.setenv("VECSHIELD_WEBHOOK_HOST_ALLOW", "127.0.0.1")
    target = _serve(_Target)

    class _RedirectHandler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self.send_response(302)
            self.send_header("Location",
                             f"http://127.0.0.1:{target.server_port}/elsewhere")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = _serve(_RedirectHandler)
    errors = []
    _Target.hits.clear()
    try:
        sink = WebhookSink(f"http://127.0.0.1:{server.server_port}/hook",
                           timeout=1.0, on_error=errors.append)
        sink.emit(_alert())
        assert _Target.hits == []
        assert sink.delivered == 0 and sink.failed == 1
        assert errors and "redirect" in str(errors[0]).lower()
    finally:
        server.shutdown()
        target.shutdown()
