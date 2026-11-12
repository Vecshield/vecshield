"""Shared helpers for the managed-service store-facts adapters.

Used by ``store_facts/{pinecone,azure_search,bedrock_kb,vertex_ai,openai}.py``.
Everything here is pure: reading SDK objects (dicts, attribute objects, proto
wrappers), normalising metric names, classifying errors and scrubbing
secret-bearing keys out of evidence before it leaves the adapter.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional
from urllib.parse import urlparse

_MISSING = object()

#: Store metric spellings → the vocabulary of ``Collection.distance_metric``.
#: Hamming (Azure AI Search, binary vectors) has no slot in that vocabulary
#: and is deliberately left unmapped (None), not coerced.
_METRICS = {
    "cosine": "cosine", "cosine_distance": "cosine", "cosinesimilarity": "cosine",
    "dot": "dot", "dotproduct": "dot", "dot_product": "dot", "ip": "dot",
    "inner_product": "dot", "innerproduct": "dot", "dot_product_distance": "dot",
    "euclidean": "euclidean", "l2": "euclidean", "squared_l2_distance": "euclidean",
    "squared_l2": "euclidean", "euclidean_distance": "euclidean",
    "manhattan": "manhattan", "l1": "manhattan", "l1_distance": "manhattan",
}

#: Key names whose values are credentials. Compared case-insensitively with
#: ``-`` and ``_`` removed. Evidence never needs them; see scrub().
_SECRET_KEYS = frozenset({
    "apikey", "key", "password", "secret", "token", "authorization",
    "httpheaders", "headers", "credentials", "accesscredentials",
    "connectionstring", "credentialssecretarn", "authenticationkey",
    "applicationsecret", "clientsecret", "sastoken", "accesskey", "secretkey",
})


def get(obj: Any, *path: str, default: Any = None) -> Any:
    """Walk ``path`` through dicts, mappings and attribute objects.

    Tries ``obj[name]`` then ``getattr(obj, name)`` at each step so the same
    code reads a REST dict, an SDK model and a proto-plus wrapper. A property
    that raises (SDK v10 Pinecone's deprecated ``dimension``) reads as missing.
    """
    cur = obj
    for name in path:
        if cur is None:
            return default
        nxt = _MISSING
        if isinstance(cur, dict):
            nxt = cur.get(name, _MISSING)
        else:
            getter = getattr(cur, "get", None)
            if callable(getter) and not isinstance(cur, type):
                try:
                    nxt = getter(name, _MISSING)
                except Exception:  # noqa: BLE001 - not a mapping after all
                    nxt = _MISSING
            if nxt is _MISSING:
                try:
                    nxt = getattr(cur, name, _MISSING)
                except Exception:  # noqa: BLE001 - raising property
                    nxt = _MISSING
        if nxt is _MISSING:
            return default
        cur = nxt
    return default if cur is None else cur


def as_plain(obj: Any) -> Any:
    """A JSON-shaped copy of an SDK model where the SDK offers one, else obj.

    ``as_dict()`` (Azure typespec models, keyed by REST names), ``to_dict()``
    (Pinecone OpenAPI models, Vertex SDK resources) and plain mappings are
    tried in that order.
    """
    if obj is None or isinstance(obj, (dict, list, str, int, float, bool)):
        return obj
    for meth in ("as_dict", "to_dict"):
        fn = getattr(obj, meth, None)
        if callable(fn):
            try:
                out = fn()
            except Exception:  # noqa: BLE001
                continue
            if isinstance(out, dict):
                return out
    try:
        return dict(obj)
    except Exception:  # noqa: BLE001
        return obj


def normalize_metric(raw: Any) -> Optional[str]:
    """The store's metric name in ``Collection.distance_metric`` vocabulary."""
    if raw is None:
        return None
    text = str(getattr(raw, "value", raw)).strip()
    if "." in text:  # an enum repr such as "Metric.COSINE"
        text = text.rsplit(".", 1)[-1]
    return _METRICS.get(text.lower().replace("-", "_"))


def host_of(uri: Any) -> Optional[str]:
    """The hostname of an endpoint URI, without userinfo, port or path."""
    if not uri:
        return None
    text = str(uri).strip()
    if "://" not in text:
        text = "//" + text
    try:
        host = urlparse(text).hostname
    except ValueError:
        return None
    return host or None


def _norm_key(key: Any) -> str:
    return str(key).lower().replace("-", "").replace("_", "")


def scrub(value: Any) -> Any:
    """Drop credential-bearing keys from a nested evidence structure."""
    if isinstance(value, dict):
        return {k: scrub(v) for k, v in value.items() if _norm_key(k) not in _SECRET_KEYS}
    if isinstance(value, list):
        return [scrub(v) for v in value]
    return value


def error_status(exc: BaseException) -> Optional[int]:
    """The HTTP status an SDK exception carries, where it carries one."""
    for attr in ("status_code", "status", "code", "http_status"):
        val = getattr(exc, attr, None)
        if callable(val):  # grpc-style code()
            try:
                val = val()
            except Exception:  # noqa: BLE001
                val = None
        if isinstance(val, int) and 100 <= val < 600:
            return val
    response = getattr(exc, "response", None)
    if isinstance(response, dict):  # botocore ClientError
        meta = response.get("ResponseMetadata") or {}
        status = meta.get("HTTPStatusCode")
        if isinstance(status, int):
            return status
        code = (response.get("Error") or {}).get("Code", "")
        if code in ("AccessDeniedException", "AccessDenied", "UnauthorizedOperation"):
            return 403
    status = getattr(response, "status_code", None)
    return status if isinstance(status, int) else None


def is_denied(exc: BaseException) -> bool:
    """Whether an exception means the credential was refused (401/403)."""
    if error_status(exc) in (401, 403):
        return True
    name = type(exc).__name__
    return any(s in name for s in ("Forbidden", "PermissionDenied", "AccessDenied",
                                   "Unauthorized", "ClientAuthentication"))


def failure_reason(exc: BaseException, what: str, permission: str) -> str:
    """A reason string for a failed read that names the permission needed."""
    if is_denied(exc):
        return f"The credential was refused when reading {what}. It needs {permission}."
    status = error_status(exc)
    suffix = f", HTTP {status}" if status else ""
    return f"{what} could not be read ({type(exc).__name__}{suffix})."


def location(*, provider: Optional[str], region: Optional[str], source: str,
             observable: bool, reason: str = "",
             evidence: Optional[dict[str, Any]] = None,
             replica_regions: Iterable[str] = ()) -> dict[str, Any]:
    return {"provider": provider, "region": region,
            "replica_regions": list(replica_regions), "source": source,
            "observable": observable, "reason": reason,
            "evidence": scrub(dict(evidence or {}))}


def integration(*, collection: Optional[str], stage: str, provider: str,
                model: Optional[str] = None, endpoint_host: Optional[str] = None,
                auth: str = "unknown", module: Optional[str] = None,
                evidence: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    if stage not in ("ingest", "query", "generate", "rerank"):
        raise ValueError(f"unknown integration stage: {stage}")
    if auth not in ("managed_identity", "api_key", "none", "unknown"):
        raise ValueError(f"unknown integration auth: {auth}")
    return {"collection": collection, "stage": stage, "provider": provider,
            "model": model, "endpoint_host": endpoint_host, "auth": auth,
            "module": module, "evidence": scrub(dict(evidence or {}))}


def integrations_result(*, observable: bool, reason: str, source: str,
                        integrations: Optional[list[dict[str, Any]]] = None,
                        controls: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    return {"observable": observable, "reason": reason, "source": source,
            "integrations": list(integrations or []),
            "controls": scrub(dict(controls or {}))}


def server(*, product: str, source: str, reason: str = "",
           version: Optional[str] = None, edition: Optional[str] = None,
           features: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    return {"product": product, "version": version, "edition": edition,
            "managed": True, "source": source, "reason": reason,
            "features": scrub(dict(features or {}))}
