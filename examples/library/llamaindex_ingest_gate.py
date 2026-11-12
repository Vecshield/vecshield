"""LlamaIndex ingestion with a VecShield PII gate before indexing.

VecShield gates the parsed nodes: PII-carrying nodes are dropped (or redacted)
before they reach `VectorStoreIndex`.

    pip install vecshield llama-index
"""

from __future__ import annotations

from vecshield import check_chunks, redact_text


def gate_nodes(nodes, *, redact: bool = False):
    """Filter (or redact) LlamaIndex nodes before indexing.

    Each node exposes `.get_content()` / `.text`. We gate on the text and either
    drop PII nodes (default) or redact their content in place.
    """
    texts = [getattr(n, "text", None) or n.get_content() for n in nodes]
    report = check_chunks(texts, mode="soft")
    blocked_idx = {int(c.id) for c in report.blocked_chunks}

    if not redact:
        return [n for i, n in enumerate(nodes) if i not in blocked_idx]

    for i in blocked_idx:
        nodes[i].text = redact_text(texts[i])
    return nodes


if __name__ == "__main__":
    # --- Real pipeline shape -------------------------------------------------
    # from llama_index.core import VectorStoreIndex, SimpleDirectoryReader
    # from llama_index.core.node_parser import SentenceSplitter
    #
    # docs = SimpleDirectoryReader("kb/").load_data()
    # nodes = SentenceSplitter().get_nodes_from_documents(docs)
    # clean = gate_nodes(nodes)               # <-- VecShield gate
    # index = VectorStoreIndex(clean)
    # -------------------------------------------------------------------------

    class _Node:
        def __init__(self, text):
            self.text = text

        def get_content(self):
            return self.text

    demo = [_Node("clean note"), _Node("email leak jane@acme.com")]
    print("kept:", [n.text for n in gate_nodes(demo)])
    print("redacted:", [n.text for n in gate_nodes(demo, redact=True)])
