"""Live connector validation.

This module is deliberately connector-agnostic. It exercises the same contract
VecShield relies on in production: inventory, bounded chunk enumeration,
metadata/text classification, optional query, and optional key introspection.
Cloud-specific live tests can call this with real credentials while ordinary
unit tests use small fake connectors.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from vecshield_platform.access import audit_api_keys
from vecshield.classify import RegexClassifier
from vecshield_platform.connectors.base import (
    Connector,
    ConnectorAuthError,
    ConnectorNotFound,
    ConnectorTimeout,
    ConnectorUnavailable,
    UnsupportedCapability,
)
from vecshield.models import Finding, Severity
from vecshield_platform.scan import scan_store


def classify_connector_error(exc: BaseException) -> str:
    """Map an exception to a stable category for distinct reporting/metrics.

    Returns one of: ``auth`` | ``timeout`` | ``unavailable`` | ``not_found`` |
    ``unsupported`` | ``error``. Typed connector errors are mapped precisely;
    untyped exceptions fall back to the generic ``error`` bucket.
    """
    if isinstance(exc, ConnectorAuthError):
        return "auth"
    if isinstance(exc, ConnectorTimeout):
        return "timeout"
    if isinstance(exc, ConnectorUnavailable):
        return "unavailable"
    if isinstance(exc, ConnectorNotFound):
        return "not_found"
    if isinstance(exc, UnsupportedCapability):
        return "unsupported"
    return "error"


def _failure(category: str, exc: BaseException) -> str:
    """A check's failure detail: category and exception type, never its text.

    Validation results are served to read-only API callers, and an SDK's
    message can echo a DSN, URL or key.
    """
    return f"{category}: {type(exc).__name__}"


def _record_connector_error(category: str) -> None:
    """Best-effort metric increment; never let telemetry break validation."""
    try:
        from vecshield_platform import metrics

        metrics.CONNECTOR_ERRORS_TOTAL.inc()
    except Exception:  # pragma: no cover - metrics are non-critical
        pass


@dataclass
class ValidationCheck:
    name: str
    ok: bool
    detail: str = ""
    skipped: bool = False
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "ok": self.ok,
            "skipped": self.skipped,
            "detail": self.detail,
            "data": self.data,
        }


@dataclass
class StoreValidation:
    store: str
    kind: str
    endpoint: str
    checks: list[ValidationCheck] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(c.ok or c.skipped for c in self.checks)

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def add(self, check: ValidationCheck) -> None:
        self.checks.append(check)

    def to_dict(self) -> dict[str, Any]:
        return {
            "store": self.store,
            "kind": self.kind,
            "endpoint": self.endpoint,
            "ok": self.ok,
            "max_severity": self.max_severity.value,
            "checks": [c.to_dict() for c in self.checks],
            "findings": [f.to_dict() for f in self.findings],
        }


def validate_connector(
    connector: Connector,
    *,
    max_collections: int = 5,
    sample_chunks: int = 5,
    run_scan: bool = True,
    run_query: bool = True,
    run_key_audit: bool = True,
) -> StoreValidation:
    """Run a bounded validation pass over a connector.

    The pass is read-only. `run_query` issues one similarity query only when the
    connector advertises `query` and a sampled chunk exposes an embedding.
    """
    store = connector.describe()
    result = StoreValidation(store=store.name, kind=store.kind, endpoint=store.endpoint)
    result.add(ValidationCheck(
        "describe",
        ok=True,
        detail=f"{len(store.collections)} collection(s)",
        data={"collections": len(store.collections), "metadata": store.metadata},
    ))

    collections = store.collections[:max_collections]
    if not collections:
        result.add(ValidationCheck("sample_chunks", ok=True, skipped=True,
                                   detail="no collections to sample"))
        return result

    sampled: dict[str, dict[str, int]] = {}
    first_query_probe: Optional[tuple[str, list[float]]] = None
    for col in collections:
        stats = {"chunks": 0, "with_text": 0, "with_metadata": 0, "with_vectors": 0}
        try:
            for chunk in connector.iter_chunks(col.name, batch_size=max(1, sample_chunks)):
                if stats["chunks"] >= sample_chunks:
                    break
                stats["chunks"] += 1
                if chunk.text:
                    stats["with_text"] += 1
                if chunk.metadata:
                    stats["with_metadata"] += 1
                if chunk.embedding:
                    stats["with_vectors"] += 1
                    if first_query_probe is None:
                        first_query_probe = (col.name, chunk.embedding)
        except Exception as e:  # noqa: BLE001
            category = classify_connector_error(e)
            _record_connector_error(category)
            result.add(ValidationCheck(
                "sample_chunks",
                ok=False,
                detail=f"{col.name}: {_failure(category, e)}",
                data={"collection": col.name, "error_category": category},
            ))
            continue
        sampled[col.name] = stats

    if sampled:
        result.add(ValidationCheck(
            "sample_chunks",
            ok=True,
            detail=f"sampled {sum(s['chunks'] for s in sampled.values())} chunk(s)",
            data={"collections": sampled},
        ))

    if run_scan:
        try:
            job = scan_store(
                connector,
                classifier=RegexClassifier(),
                max_chunks_per_collection=sample_chunks,
            )
            result.findings.extend(job.findings)
            result.add(ValidationCheck(
                "classification_scan",
                ok=True,
                detail=f"{len(job.findings)} finding(s)",
                data={"stats": job.stats, "max_severity": job.max_severity.value},
            ))
        except Exception as e:  # noqa: BLE001
            category = classify_connector_error(e)
            _record_connector_error(category)
            result.add(ValidationCheck(
                "classification_scan", ok=False, detail=_failure(category, e),
                data={"error_category": category}))

    if run_query:
        if "query" not in connector.capabilities():
            result.add(ValidationCheck("query", ok=True, skipped=True,
                                       detail="connector does not advertise query"))
        elif first_query_probe is None:
            result.add(ValidationCheck("query", ok=True, skipped=True,
                                       detail="no sampled embedding available"))
        else:
            collection, vector = first_query_probe
            try:
                hits = connector.query(collection, vector, top_k=1)
                result.add(ValidationCheck(
                    "query",
                    ok=True,
                    detail=f"{len(hits)} hit(s)",
                    data={"collection": collection, "hits": len(hits)},
                ))
            except Exception as e:  # noqa: BLE001
                category = classify_connector_error(e)
                _record_connector_error(category)
                result.add(ValidationCheck(
                    "query",
                    ok=False,
                    detail=f"{collection}: {_failure(category, e)}",
                    data={"collection": collection, "error_category": category},
                ))

    if run_key_audit:
        if "api_keys" not in connector.capabilities():
            result.add(ValidationCheck("api_keys", ok=True, skipped=True,
                                       detail="connector does not advertise api_keys"))
        else:
            try:
                keys = connector.list_api_keys()
                result.findings.extend(audit_api_keys(keys, store_name=store.name))
                result.add(ValidationCheck(
                    "api_keys",
                    ok=True,
                    detail=f"{len(keys)} key(s)",
                    data={"keys": len(keys)},
                ))
            except UnsupportedCapability:
                result.add(ValidationCheck("api_keys", ok=True, skipped=True,
                                           detail="api key listing unsupported"))
            except Exception as e:  # noqa: BLE001
                category = classify_connector_error(e)
                _record_connector_error(category)
                result.add(ValidationCheck(
                    "api_keys", ok=False, detail=_failure(category, e),
                    data={"error_category": category}))

    return result
