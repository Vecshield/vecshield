"""LlamaIndex adapter.

VecShieldNodeFilter is a NodeParser post-processor: it gates a list of
LlamaIndex nodes and drops the ones carrying blocked PII. Nodes are duck-typed
(`get_content()`/`text` + `metadata`), so no hard llama-index dependency.
"""

from __future__ import annotations

from typing import Any

from vecshield.ingest.gate import IngestGate
from vecshield.models import Chunk, IngestGateReport


class VecShieldNodeFilter:
    """Drop LlamaIndex nodes that fail an IngestGate."""

    def __init__(self, gate: IngestGate):
        self.gate = gate
        self.last_report: IngestGateReport | None = None

    def __call__(self, nodes: list[Any], **_: Any) -> list[Any]:
        return self.postprocess_nodes(nodes)

    def postprocess_nodes(self, nodes: list[Any], **_: Any) -> list[Any]:
        chunks, by_id = [], {}
        for i, node in enumerate(nodes):
            cid = str(_node_id(node, i))
            by_id[cid] = node
            chunks.append(
                Chunk(
                    id=cid,
                    collection="ingest",
                    text=_node_text(node),
                    metadata=_node_meta(node),
                )
            )
        report = self.gate.inspect(chunks)
        self.last_report = report
        blocked = {c.id for c in report.blocked_chunks}
        if not blocked:
            return nodes
        return [by_id[c.id] for c in report.allowed_chunks if c.id in by_id]


def _node_text(node: Any) -> str:
    if hasattr(node, "get_content"):
        try:
            return node.get_content() or ""
        except Exception:  # pragma: no cover
            pass
    return getattr(node, "text", "") or ""


def _node_id(node: Any, fallback: int) -> Any:
    return getattr(node, "node_id", None) or getattr(node, "id_", None) or fallback


def _node_meta(node: Any) -> dict:
    return getattr(node, "metadata", None) or {}
