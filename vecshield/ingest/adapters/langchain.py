"""LangChain adapter.

VecShieldCallbackHandler wraps an IngestGate and filters a list of LangChain
`Document` objects: documents whose text classifies at the gate's block level are
removed and recorded. No hard dependency on langchain — Documents are duck-typed
(`page_content` + `metadata`), so this works with any compatible object.
"""

from __future__ import annotations

from typing import Any

from vecshield.ingest.gate import IngestGate
from vecshield.models import Chunk, IngestGateReport


class VecShieldCallbackHandler:
    """Filter LangChain Documents through an IngestGate before embedding."""

    def __init__(self, gate: IngestGate):
        self.gate = gate
        self.last_report: IngestGateReport | None = None

    def filter_documents(self, documents: list[Any]) -> list[Any]:
        """Return only documents that pass the gate; stash the report."""
        chunks, by_id = [], {}
        for i, doc in enumerate(documents):
            cid = str(_meta(doc).get("id", i))
            by_id[cid] = doc
            chunks.append(
                Chunk(
                    id=cid,
                    collection=_meta(doc).get("collection", "ingest"),
                    text=_text(doc),
                    metadata=dict(_meta(doc)),
                )
            )
        report = self.gate.inspect(chunks)
        self.last_report = report
        blocked_ids = {c.id for c in report.blocked_chunks}
        return (
            [by_id[c.id] for c in report.allowed_chunks if c.id in by_id]
            if blocked_ids
            else documents
        )

    # LangChain callback hook name (best-effort; safe no-op shape)
    def on_retriever_end(self, documents: list[Any], **_: Any) -> list[Any]:
        return self.filter_documents(documents)


def _text(doc: Any) -> str:
    return getattr(doc, "page_content", None) or (
        doc.get("page_content", "") if isinstance(doc, dict) else ""
    )


def _meta(doc: Any) -> dict:
    m = getattr(doc, "metadata", None)
    if m is None and isinstance(doc, dict):
        m = doc.get("metadata")
    return m or {}
