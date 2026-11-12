"""Shared helpers for the self-hosted store-facts adapters.

Used by ``store_facts/{qdrant,weaviate,milvus,chroma,pgvector,redis,opensearch,
mongodb}.py``. Pure functions only: result builders with the base-class
shapes, host classification, metric normalisation, error classification and
evidence scrubbing.

Evidence is built from allow-listed keys wherever a store returns free-form
configuration, and every remaining string passes through
:func:`redact_credentials`. :func:`scrub` is the second line of defence: it
drops any key whose name suggests a credential, header or signature.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Iterable, Optional
from urllib.parse import urlparse

from vecshield_platform.connectors.redact import redact_credentials

UNPLACEABLE = ("The store runs on infrastructure VecShield cannot place; declare its "
               "location.")
UNKNOWN_HOST = ("The endpoint's hostname does not identify a hosting provider or "
                "region; declare the store's location.")

STAGES = ("ingest", "query", "generate", "rerank")
AUTHS = ("managed_identity", "api_key", "none", "unknown")

#: Key-name fragments that mark a credential-bearing value.
_SECRET_PARTS = ("key", "secret", "token", "password", "passwd", "credential",
                 "header", "cookie", "signature", "auth", "session", "bearer")

_MAX_TEXT = 256


# ------------------------------------------------------------------ results #

def server(*, product: str, source: str, version: Optional[str] = None,
           edition: Optional[str] = None, managed: bool = False, reason: str = "",
           features: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    return {"product": product, "version": version, "edition": edition,
            "managed": bool(managed), "source": source, "reason": reason,
            "features": scrub(dict(features or {}))}


def location(*, provider: Optional[str], region: Optional[str], source: str,
             observable: bool, reason: str = "",
             evidence: Optional[dict[str, Any]] = None,
             replica_regions: Iterable[str] = ()) -> dict[str, Any]:
    return {"provider": provider, "region": region,
            "replica_regions": sorted({str(r) for r in replica_regions if r}),
            "source": source, "observable": bool(observable), "reason": reason,
            "evidence": scrub(dict(evidence or {}))}


def integration(*, collection: Optional[str], stage: str, provider: str,
                model: Optional[str] = None, endpoint_host: Optional[str] = None,
                auth: str = "unknown", module: Optional[str] = None,
                evidence: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    if stage not in STAGES:
        raise ValueError(f"unknown integration stage: {stage}")
    if auth not in AUTHS:
        raise ValueError(f"unknown integration auth: {auth}")
    return {"collection": collection, "stage": stage, "provider": provider,
            "model": clean_text(model), "endpoint_host": endpoint_host, "auth": auth,
            "module": module, "evidence": scrub(dict(evidence or {}))}


def integrations_result(*, observable: bool, reason: str, source: str,
                        integrations: Optional[list[dict[str, Any]]] = None,
                        controls: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    return {"observable": bool(observable), "reason": reason, "source": source,
            "integrations": list(integrations or []),
            "controls": scrub(dict(controls or {}))}


# ---------------------------------------------------------------- scrubbing #

def is_secret_key(key: Any) -> bool:
    k = str(key).lower()
    return any(part in k for part in _SECRET_PARTS)


def clean_text(value: Any) -> Any:
    """Strings redacted of embedded credentials and bounded in length."""
    if not isinstance(value, str):
        return value
    text = redact_credentials(value)
    return text if len(text) <= _MAX_TEXT else text[:_MAX_TEXT] + "…"


def scrub(value: Any) -> Any:
    """Drop credential-looking keys and redact credential-bearing strings."""
    if isinstance(value, dict):
        return {str(k): scrub(v) for k, v in value.items() if not is_secret_key(k)}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [scrub(v) for v in value]
    return clean_text(value)


def pick(mapping: Any, keys: Iterable[str]) -> dict[str, Any]:
    """Allow-listed scalar entries of ``mapping`` (never nested structures)."""
    if not isinstance(mapping, dict):
        return {}
    out: dict[str, Any] = {}
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, (str, int, float, bool)) and not is_secret_key(key):
            out[key] = clean_text(value)
    return out


# -------------------------------------------------------------------- hosts #

_PRIVATE_SUFFIXES = (".local", ".localdomain", ".internal", ".lan", ".home.arpa",
                     ".svc", ".cluster.local", ".localhost")


def host_of(endpoint: Any) -> Optional[str]:
    """Lower-case hostname of a URL or ``host[:port]``, never userinfo or path."""
    if not endpoint:
        return None
    text = str(endpoint).strip()
    if "${" in text:
        return None  # an unresolved template placeholder is not a host
    if "://" not in text:
        text = "//" + text
    try:
        host = urlparse(text).hostname
    except ValueError:
        return None
    return host.lower().rstrip(".") if host else None


def is_private_host(host: Optional[str]) -> bool:
    """Loopback, RFC 1918/4193, link-local, or a name only local DNS resolves.

    A single-label name (``qdrant``, ``milvus-standalone``) is a container or
    cluster service name. Nothing here resolves DNS or looks up an address.
    """
    if not host:
        return False
    h = host.strip("[]").lower()
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return (h == "localhost" or "." not in h
                or any(h.endswith(s) for s in _PRIVATE_SUFFIXES))
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified


def self_hosted(source: str, host: Optional[str], *, local: bool = False) -> dict[str, Any]:
    evidence: dict[str, Any] = {"host_class": "local_file" if local else "private_or_loopback"}
    if host and not local:
        evidence["host"] = host
    return location(provider="self_hosted", region=None, source=source,
                    observable=False, reason=UNPLACEABLE, evidence=evidence)


def unknown_host(source: str, host: Optional[str]) -> dict[str, Any]:
    return location(provider=None, region=None, source=source, observable=False,
                    reason=UNKNOWN_HOST if host else
                    "The connection has no hostname to read; declare the store's location.",
                    evidence={"host": host} if host else {})


# ------------------------------------------------------------------ metrics #

_METRICS = {
    "cosine": "cosine", "cosinesimil": "cosine", "cos": "cosine",
    "dot": "dot", "dotproduct": "dot", "ip": "dot", "innerproduct": "dot",
    "inner_product": "dot", "dot_product": "dot",
    "euclidean": "euclidean", "euclid": "euclidean", "l2": "euclidean",
    "l2squared": "euclidean", "l2-squared": "euclidean", "l2_squared": "euclidean",
    "manhattan": "manhattan", "l1": "manhattan",
}


def normalize_metric(raw: Any) -> Optional[str]:
    """A store's metric spelling in ``Collection.distance_metric`` vocabulary.

    Anything outside it (hamming, jaccard, linf, BM25, ...) is None, not
    coerced; callers keep the raw name in their evidence.
    """
    if raw is None:
        return None
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    text = str(getattr(raw, "value", raw)).strip()
    if "." in text:  # an enum repr such as "Distance.COSINE"
        text = text.rsplit(".", 1)[-1]
    return _METRICS.get(text.lower())


def raw_metric(raw: Any) -> Optional[str]:
    if raw is None:
        return None
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    return str(getattr(raw, "value", raw))


def combine(per_vector: dict[str, Any], source: str, **extra: Any) -> dict[str, Any]:
    """One collection's detail: a metric only when every vector agrees."""
    normalised = {name: normalize_metric(m) for name, m in per_vector.items()}
    values = set(normalised.values())
    metric = values.pop() if len(values) == 1 else None
    detail: dict[str, Any] = {"metric": metric, "source": source,
                              "vector_metrics": {n: raw_metric(m) for n, m in per_vector.items()}}
    if len(normalised) > 1 and len(set(normalised.values())) > 1:
        detail["note"] = "vectors use different metrics"
    detail.update({k: v for k, v in extra.items() if v is not None})
    return detail


# ------------------------------------------------------------------- errors #

_DENIED_TEXT = ("permission denied", "permission deny", "not authorized", "unauthorized",
                "forbidden", "access denied", "insufficient privilege", "privilege",
                "noperm", "not allowed", "requires authentication")


def error_status(exc: BaseException) -> Optional[int]:
    for attr in ("status_code", "status", "http_status"):
        val = getattr(exc, attr, None)
        if isinstance(val, int) and 100 <= val < 600:
            return val
    response = getattr(exc, "response", None)
    val = getattr(response, "status_code", None)
    return val if isinstance(val, int) else None


def is_denied(exc: BaseException) -> bool:
    """Whether an exception means the credential was refused."""
    if error_status(exc) in (401, 403):
        return True
    if getattr(exc, "code", None) in (13, 18) and hasattr(exc, "details"):
        return True  # pymongo OperationFailure: Unauthorized / AuthenticationFailed
    if getattr(exc, "sqlstate", None) == "42501" or getattr(exc, "pgcode", None) == "42501":
        return True
    name = type(exc).__name__
    if any(s in name for s in ("Forbidden", "PermissionDenied", "AccessDenied",
                               "Unauthorized", "AuthorizationException",
                               "AuthenticationException", "NoPermission")):
        return True
    text = str(exc).lower()
    return any(s in text for s in _DENIED_TEXT)


def is_missing(exc: BaseException) -> bool:
    """Whether the endpoint/command does not exist on this server version."""
    if error_status(exc) in (400, 404, 405, 501):
        return True
    text = str(exc).lower()
    return any(s in text for s in ("unknown command", "no handler found", "not found",
                                   "not supported", "unrecognized", "no such",
                                   "does not exist", "unsupported"))


def describe_error(exc: BaseException) -> str:
    """A short, credential-free description of a failure."""
    status = error_status(exc)
    return f"{type(exc).__name__}" + (f", HTTP {status}" if status else "")


def denied_reason(what: str, privilege: str) -> str:
    return f"The credential was refused when reading {what}. It needs {privilege}."


def failed_reason(exc: BaseException, what: str, privilege: str) -> str:
    if is_denied(exc):
        return denied_reason(what, privilege)
    return f"{what} could not be read ({describe_error(exc)})."


# ---------------------------------------------------------------- providers #

#: Hostname suffix → provider, for model endpoints a store calls.
_HOST_PROVIDERS: tuple[tuple[str, str], ...] = (
    ("api.openai.com", "openai"),
    (".openai.azure.com", "azure_openai"),
    (".cognitiveservices.azure.com", "azure_ai"),
    (".services.ai.azure.com", "azure_ai"),
    ("api.cohere.ai", "cohere"),
    ("api.cohere.com", "cohere"),
    ("api.anthropic.com", "anthropic"),
    ("api.voyageai.com", "voyageai"),
    ("api.jina.ai", "jinaai"),
    ("api.mistral.ai", "mistral"),
    ("api.deepseek.com", "deepseek"),
    ("generativelanguage.googleapis.com", "google"),
    ("aiplatform.googleapis.com", "google_vertex"),
    ("api-inference.huggingface.co", "huggingface"),
    ("router.huggingface.co", "huggingface"),
    ("api.together.xyz", "together_ai"),
    ("api.fireworks.ai", "fireworks"),
    ("openrouter.ai", "openrouter"),
)
_AWS_SERVICE = re.compile(
    r"^(?P<svc>bedrock-runtime|bedrock|runtime\.sagemaker|comprehend|textract)"
    r"\.(?P<region>[a-z0-9-]+)\.amazonaws\.com$")
_AWS_PROVIDERS = {"bedrock-runtime": "aws_bedrock", "bedrock": "aws_bedrock",
                  "runtime.sagemaker": "aws_sagemaker", "comprehend": "aws_comprehend",
                  "textract": "aws_textract"}


def provider_for_host(host: Optional[str]) -> Optional[str]:
    """The model provider a hostname belongs to; ``self_hosted`` for private hosts."""
    if not host:
        return None
    m = _AWS_SERVICE.match(host)
    if m:
        return _AWS_PROVIDERS[m.group("svc")]
    for suffix, provider in _HOST_PROVIDERS:
        bare = suffix.lstrip(".")
        if host == bare or host.endswith("." + bare):
            return provider
    if is_private_host(host):
        return "self_hosted"
    return None


def version_tuple(text: Any) -> Optional[tuple[int, ...]]:
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", str(text or ""))
    if not m:
        return None
    return tuple(int(g) for g in m.groups() if g is not None)


def get(obj: Any, *path: Any, default: Any = None) -> Any:
    """Walk ``path`` through dicts and attribute objects; missing → default."""
    cur = obj
    for name in path:
        if cur is None:
            return default
        if isinstance(cur, dict):
            cur = cur.get(name)
        elif isinstance(cur, (list, tuple)) and isinstance(name, int):
            cur = cur[name] if -len(cur) <= name < len(cur) else None
        else:
            try:
                cur = getattr(cur, name, None)
            except Exception:  # noqa: BLE001 - a raising property reads as missing
                cur = None
    return default if cur is None else cur


def dec(value: Any) -> Any:
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else value
