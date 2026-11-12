"""Network discovery for vector-store instances.

Given a host, CIDR, or range, TCP-scan known vector-DB ports then HTTP-fingerprint
the open ones to identify kind + version. Read-only probing — no auth, no writes.

Intended for asset discovery on networks you are authorized to scan. Cloud
stores (Pinecone) are not network-discoverable and are excluded.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass
class DiscoveredInstance:
    host: str
    port: int
    kind: str
    version: Optional[str] = None
    endpoint: str = ""
    detail: str = ""

    def to_dict(self) -> dict:
        return {"host": self.host, "port": self.port, "kind": self.kind,
                "version": self.version, "endpoint": self.endpoint, "detail": self.detail}


@dataclass
class Probe:
    kind: str
    port: int
    path: str
    match: Callable[[int, str], Optional[str]]  # (status, body) -> version|"" if match else None


def _json(body):
    try:
        d = json.loads(body)
        return d if isinstance(d, dict) else None
    except Exception:
        return None


def _chroma(status, body):
    # heartbeat returns {"nanosecond heartbeat": <int>}
    if status == 200 and "nanosecond heartbeat" in body:
        return ""
    return None


def _qdrant(status, body):
    d = _json(body) if status == 200 else None
    if d and "qdrant" in str(d.get("title", "")).lower():
        return d.get("version", "")
    return None


def _weaviate(status, body):
    d = _json(body) if status == 200 else None
    if d and "version" in d and ("modules" in d or "hostname" in d):
        return d.get("version", "")
    return None


def _milvus(status, body):
    if status == 200 and body.strip() in ("OK", "healthy") or "healthy" in body.lower():
        return ""
    return None


PROBES: list[Probe] = [
    Probe("chroma", 8000, "/api/v2/heartbeat", _chroma),
    Probe("chroma", 8000, "/api/v1/heartbeat", _chroma),
    Probe("qdrant", 6333, "/", _qdrant),
    Probe("weaviate", 8080, "/v1/meta", _weaviate),
    Probe("milvus", 9091, "/healthz", _milvus),
]


def expand_targets(targets) -> list[str]:
    """Accept str (comma-sep) or list. Each item: host, IP, CIDR, or a-b range."""
    if isinstance(targets, str):
        items = [t.strip() for t in targets.split(",") if t.strip()]
    else:
        items = list(targets)
    out: list[str] = []
    for item in items:
        if "/" in item:  # CIDR
            try:
                net = ipaddress.ip_network(item, strict=False)
                out.extend(str(ip) for ip in (net.hosts() if net.num_addresses > 2 else net))
                continue
            except ValueError:
                pass
        if "-" in item and item.count(".") >= 3:  # a.b.c.d-e.f.g.h or a.b.c.d-N
            lo, hi = item.split("-", 1)
            try:
                start = int(ipaddress.ip_address(lo))
                end = int(ipaddress.ip_address(hi)) if "." in hi else \
                    int(ipaddress.ip_address(".".join(lo.split(".")[:3] + [hi])))
                out.extend(str(ipaddress.ip_address(i)) for i in range(start, end + 1))
                continue
            except ValueError:
                pass
        out.append(item)  # plain host/IP
    return out


def _tcp_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _http(host: str, port: int, path: str, timeout: float) -> tuple[int, str]:
    url = f"http://{host}:{port}{path}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:  # noqa: S310
            return r.status, r.read(4096).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return 0, ""


def discover(targets, *, ports: Optional[list[int]] = None,
             timeout: float = 0.6, workers: int = 64) -> list[DiscoveredInstance]:
    ips = expand_targets(targets)
    probe_ports = sorted({p.port for p in PROBES} | set(ports or []))

    # phase 1: TCP scan unique (ip, port)
    pairs = [(ip, port) for ip in ips for port in probe_ports]
    with ThreadPoolExecutor(max_workers=workers) as ex:
        open_flags = ex.map(lambda p: _tcp_open(p[0], p[1], timeout), pairs)
    open_pairs = {pair for pair, ok in zip(pairs, open_flags) if ok}

    # phase 2: HTTP fingerprint open ports
    found: dict[tuple, DiscoveredInstance] = {}

    def fingerprint(ip: str, port: int):
        # Try probes whose default port matches first, then the rest — so a
        # service on a non-default port still gets identified.
        ordered = sorted(PROBES, key=lambda pr: pr.port != port)
        for pr in ordered:
            status, body = _http(ip, port, pr.path, timeout)
            ver = pr.match(status, body)
            if ver is not None:
                return DiscoveredInstance(host=ip, port=port, kind=pr.kind,
                                          version=ver or None,
                                          endpoint=f"http://{ip}:{port}",
                                          detail=pr.path)
        return None

    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = ex.map(lambda p: fingerprint(p[0], p[1]), open_pairs)
    for r in results:
        if r:
            found[(r.host, r.port)] = r
    return sorted(found.values(), key=lambda d: (d.host, d.port))
