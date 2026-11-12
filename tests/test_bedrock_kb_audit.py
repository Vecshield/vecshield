"""Bedrock Knowledge Bases connector fixes from the scan audit (boto3 1.43).

* session tokens and named profiles reach the boto3 Session;
* with no region, boto3 resolves it and the Region listed is recorded;
* the knowledge-base type and any backing-store lookup error are recorded;
* a knowledge base never reports a known count (Bedrock has none);
* botocore ClientError codes and HTTP statuses map onto the taxonomy.
"""

from __future__ import annotations

import pytest

pytest.importorskip("boto3")

import boto3  # noqa: E402
from botocore.exceptions import ClientError  # noqa: E402

from vecshield_platform.connectors import build_connector  # noqa: E402
from vecshield_platform.connectors.base import (  # noqa: E402
    ConnectorAuthError,
    ConnectorUnavailable,
)
from vecshield_platform.coverage import count_known  # noqa: E402


def _client_error(code, status):
    return ClientError({"Error": {"Code": code, "Message": "arn:aws:iam::1:user/x denied"},
                        "ResponseMetadata": {"HTTPStatusCode": status}}, "ListKnowledgeBases")


class _Bedrock:
    def __init__(self, region="eu-west-1", kbs=None, details=None, pages=None):
        self.meta = type("Meta", (), {"region_name": region})()
        self.kbs = kbs or []
        self.details = details or {}
        self.pages = pages
        self.list_calls: list[dict] = []

    def list_knowledge_bases(self, **kw):
        self.list_calls.append(kw)
        if self.pages is not None:
            page = self.pages.pop(0)
            if isinstance(page, Exception):
                raise page
            return page
        return {"knowledgeBaseSummaries": self.kbs}

    def get_knowledge_base(self, knowledgeBaseId=None):
        detail = self.details[knowledgeBaseId]
        if isinstance(detail, Exception):
            raise detail
        return {"knowledgeBase": detail}


@pytest.fixture
def sessions(monkeypatch):
    made: list[dict] = []
    clients: list[_Bedrock] = []

    class Session:
        def __init__(self, **kw):
            made.append(kw)
            self.kw = kw

        def client(self, service, **kw):
            assert service == "bedrock-agent" and kw == {}
            client = clients.pop(0) if clients else _Bedrock(
                region=self.kw.get("region_name") or "us-west-2")
            return client

    monkeypatch.setattr(boto3, "Session", Session)
    monkeypatch.setattr("vecshield_platform.connectors.base.time.sleep", lambda _s: None)
    return made, clients


def test_session_token_and_profile_reach_the_session(sessions):
    made, _ = sessions
    build_connector("bedrock_kb", region="eu-central-1", aws_access_key_id="AKIAX",
                    aws_secret_access_key="s3cr3t", aws_session_token="tok",
                    profile_name="audit")
    assert made[-1] == {"profile_name": "audit", "aws_access_key_id": "AKIAX",
                        "aws_secret_access_key": "s3cr3t", "aws_session_token": "tok",
                        "region_name": "eu-central-1"}


def test_region_defaults_to_boto3_resolution_and_is_recorded(sessions):
    made, clients = sessions
    clients.append(_Bedrock(region="ap-southeast-2", kbs=[
        {"knowledgeBaseId": "kb-1", "name": "support", "status": "ACTIVE"}],
        details={"kb-1": {"knowledgeBaseConfiguration": {"type": "VECTOR"},
                          "storageConfiguration": {"type": "RDS"}}}))
    conn = build_connector("bedrock_kb", profile_name="audit")
    assert "region_name" not in made[-1]  # boto3 resolves it from the profile/env
    store = conn.describe()
    assert store.endpoint == "bedrock-kb://ap-southeast-2"
    assert store.metadata["regions_listed"] == ["ap-southeast-2"]
    col = store.collections[0]
    assert col.metadata["region"] == "ap-southeast-2"
    assert col.metadata["knowledge_base_type"] == "VECTOR"
    assert col.metadata["backing_store"] == "RDS"
    assert not count_known(col)
    assert conn.read_errors() == []


def test_backing_store_lookup_error_is_recorded(sessions):
    _, clients = sessions
    clients.append(_Bedrock(kbs=[
        {"knowledgeBaseId": "kb-1", "name": "support"},
        {"knowledgeBaseId": "kb-2", "name": "managed"}],
        details={"kb-1": _client_error("AccessDeniedException", 403),
                 "kb-2": {"knowledgeBaseConfiguration": {"type": "MANAGED"}}}))
    conn = build_connector("bedrock_kb", region="eu-west-1")
    cols = {c.metadata["knowledge_base_id"]: c for c in conn.list_collections()}
    assert cols["kb-1"].metadata["backing_store_error"] == "ConnectorAuthError"
    assert cols["kb-1"].metadata["knowledge_base_type"] is None
    assert cols["kb-2"].metadata["knowledge_base_type"] == "MANAGED"
    errors = conn.read_errors()
    assert [e["collection"] for e in errors] == ["support (kb-1)"]
    assert errors[0]["operation"] == "get_knowledge_base"
    assert "arn:aws" not in repr(errors)
    assert conn.content_enumerable is False


def test_pages_follow_next_token_and_retry_throttling(sessions):
    _, clients = sessions
    bedrock = _Bedrock(pages=[
        {"knowledgeBaseSummaries": [{"knowledgeBaseId": "a", "name": "A"}],
         "nextToken": "t2"},
        _client_error("ThrottlingException", 400),
        {"knowledgeBaseSummaries": [{"knowledgeBaseId": "b", "name": "B"}]}],
        details={"a": {}, "b": {}})
    clients.append(bedrock)
    conn = build_connector("bedrock_kb", region="eu-west-1")
    assert [c.metadata["knowledge_base_id"] for c in conn.list_collections()] == ["a", "b"]
    assert bedrock.list_calls == [{}, {"nextToken": "t2"}, {"nextToken": "t2"}]


@pytest.mark.parametrize("code,status,expected", [
    ("AccessDeniedException", 403, ConnectorAuthError),
    ("ExpiredTokenException", 400, ConnectorAuthError),
    ("ThrottlingException", 400, ConnectorUnavailable),
    ("SomethingNew", 503, ConnectorUnavailable),
])
def test_client_errors_map_by_code_then_status(sessions, code, status, expected):
    _, clients = sessions
    clients.append(_Bedrock(pages=[_client_error(code, status)] * 3))
    conn = build_connector("bedrock_kb", region="eu-west-1")
    with pytest.raises(expected) as info:
        conn.list_collections()
    assert "arn:aws" not in str(info.value)
