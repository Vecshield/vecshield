"""run_full_audit chains the datasource scan, boundary check and store audit."""

from __future__ import annotations

import json

import pytest

from vecshield.classify import RegexClassifier
from vecshield_platform.datasources import build_datasource
from vecshield_platform.orchestrator import run_full_audit


@pytest.fixture
def chroma_conn(tmp_path):
    import chromadb
    from vecshield_platform.connectors.chroma import ChromaConnector
    path = str(tmp_path / "chroma")
    client = chromadb.PersistentClient(path=path)
    col = client.create_collection("knowledge")
    col.add(ids=["1"], documents=["benign product doc"],
            embeddings=[[0.1, 0.2]], metadatas=[{"source": "catalog"}])
    return ChromaConnector(path=path)


def test_audit_with_datasource_chains_training_scan(tmp_path, chroma_conn):
    # seed a training dataset with a secret
    d = tmp_path / "data"
    d.mkdir()
    with open(d / "train.jsonl", "w") as f:
        f.write(json.dumps({"text": "key AKIAIOSFODNN7EXAMPLE"}) + "\n")
        f.write(json.dumps({"text": "clean record"}) + "\n")
    source = build_datasource("local", path=str(d))

    result = run_full_audit(chroma_conn, classifier=RegexClassifier(),
                            datasource=source)

    # a training_data_classification job is present and flags the secret
    cats = {f.category for f in result.all_findings()}
    assert "training_data_classification" in cats
    # training_policies were applied -> a purge_and_retrain violation exists
    assert any(v.policy_id == "training-no-secrets" for v in result.violations)


def test_audit_without_datasource_unchanged(chroma_conn):
    result = run_full_audit(chroma_conn, classifier=RegexClassifier())
    cats = {f.category for f in result.all_findings()}
    assert "training_data_classification" not in cats
