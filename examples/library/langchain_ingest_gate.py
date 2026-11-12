"""LangChain ingestion with a VecShield PII gate before embedding.

VecShield sits between the text splitter and the vector store: only PII-clean
chunks are embedded and upserted.

    pip install vecshield langchain langchain-community

This example is intentionally dependency-light: the LangChain objects are only
referenced in comments so the file runs as pseudo-code you can lift into a real
pipeline.
"""

from __future__ import annotations

from vecshield import check_chunks
from vecshield.ingest import IngestGate
from vecshield.ingest.adapters.langchain import VecShieldCallbackHandler


def gate_documents(docs):
    """Return only the documents whose text is PII-clean.

    `docs` is a list of LangChain Documents (each has `.page_content`).
    """
    handler = VecShieldCallbackHandler(IngestGate())
    return handler.filter_documents(docs)


def gate_texts(texts: list[str]) -> list[str]:
    """Lower-level: gate raw chunk strings before embedding."""
    report = check_chunks(texts, mode="soft")
    blocked_ids = {c.id for c in report.blocked_chunks}
    return [t for i, t in enumerate(texts) if str(i) not in blocked_ids]


if __name__ == "__main__":
    # --- Real pipeline shape -------------------------------------------------
    # from langchain_community.document_loaders import TextLoader
    # from langchain.text_splitter import RecursiveCharacterTextSplitter
    # from langchain_community.vectorstores import Chroma
    #
    # docs = TextLoader("kb.txt").load()
    # chunks = RecursiveCharacterTextSplitter().split_documents(docs)
    # clean = gate_documents(chunks)          # <-- VecShield gate
    # Chroma.from_documents(clean, embedding=...)
    # -------------------------------------------------------------------------

    sample = ["The quick brown fox.", "Patient SSN is 123-45-6789."]
    print("clean chunks:", gate_texts(sample))
