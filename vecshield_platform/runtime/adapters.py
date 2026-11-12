"""Runtime monitoring adapters for RAG frameworks.

The transparent connector proxy is ideal when VecShield owns the vector-store
connector. Many production apps query through LangChain, LlamaIndex, or custom
retrievers instead. These helpers let those apps emit the same QueryEvent shape
without taking a dependency on any one framework.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any, Callable, Optional

from vecshield_platform.runtime.engine import MonitorEngine
from vecshield_platform.runtime.events import QueryEvent


def emit_retrieval_event(
    engine: MonitorEngine,
    *,
    principal: str,
    collection: str,
    results: Optional[list[Any]] = None,
    result_ids: Optional[list[str]] = None,
    query_vector: Optional[list[float]] = None,
    timestamp: Optional[float] = None,
    metadata: Optional[dict[str, Any]] = None,
):
    """Emit a QueryEvent from framework retriever results.

    `results` may be LangChain Documents, LlamaIndex nodes, raw dicts, strings,
    or connector-specific objects. Stable IDs are extracted from common fields;
    if no ID exists, a short content hash is used so sweep detection can still
    reason over repeated result sets.
    """
    ids = result_ids if result_ids is not None else [_result_id(r) for r in (results or [])]
    event = QueryEvent(
        principal=principal,
        collection=collection,
        timestamp=timestamp if timestamp is not None else time.time(),
        query_vector=query_vector,
        result_ids=[i for i in ids if i],
        result_count=len(results or ids),
        metadata=metadata or {},
    )
    return engine.process(event)


def wrap_retriever(
    retrieve: Callable[..., list[Any]],
    engine: MonitorEngine,
    *,
    principal: str | Callable[[], str],
    collection: str,
    vector_arg: str = "query_vector",
) -> Callable[..., list[Any]]:
    """Wrap a retriever callable and observe its returned documents/nodes.

    The wrapper is intentionally framework-neutral. If the application passes a
    query embedding as `query_vector=...` (or another configured kwarg), the
    enumeration detector can use it; otherwise volume and sweep detectors still
    work from result IDs.
    """

    def observed(*args, **kwargs):
        ts = time.time()
        vector = kwargs.get(vector_arg)
        results = retrieve(*args, **kwargs)
        p = principal() if callable(principal) else principal
        emit_retrieval_event(
            engine,
            principal=p,
            collection=collection,
            results=list(results or []),
            query_vector=vector,
            timestamp=ts,
            metadata={"adapter": "retriever_wrapper"},
        )
        return results

    return observed


class LangChainRetrieverCallback:
    """Duck-typed LangChain callback handler for retriever end events.

    LangChain does not guarantee vectors are available in callbacks, so this
    adapter primarily powers volume/sweep monitoring from returned document IDs.
    """

    def __init__(self, engine: MonitorEngine, *, principal: str, collection: str):
        self.engine = engine
        self.principal = principal
        self.collection = collection

    def on_retriever_end(self, documents, **kwargs):  # LangChain callback name
        return emit_retrieval_event(
            self.engine,
            principal=self.principal,
            collection=kwargs.get("collection", self.collection),
            results=list(documents or []),
            metadata={"adapter": "langchain_callback"},
        )


def _result_id(result: Any) -> str:
    if result is None:
        return ""
    if isinstance(result, str):
        return _hash_id(result)
    if isinstance(result, dict):
        for key in ("id", "_id", "doc_id", "document_id", "node_id"):
            if result.get(key):
                return str(result[key])
        meta = result.get("metadata") or {}
        if isinstance(meta, dict):
            for key in ("id", "_id", "source", "source_id", "doc_id", "document_id"):
                if meta.get(key):
                    return str(meta[key])
        return _hash_id(str(result))

    for attr in ("id", "id_", "doc_id", "document_id", "node_id", "ref_doc_id"):
        value = getattr(result, attr, None)
        if value:
            return str(value)
    meta = getattr(result, "metadata", None) or {}
    if isinstance(meta, dict):
        for key in ("id", "_id", "source", "source_id", "doc_id", "document_id"):
            if meta.get(key):
                return str(meta[key])
    content = getattr(result, "page_content", None) or getattr(result, "text", None)
    return _hash_id(str(content or result))


def _hash_id(value: str) -> str:
    return "hash:" + hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]
