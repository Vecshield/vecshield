"""Store-facts adapters for the managed connectors (no network, no live creds).

Connectors are built with ``object.__new__`` and given fake clients on the
attributes the adapters read, so no SDK constructor or network runs. Where
the SDK is installed (azure-search-documents, botocore) the fakes return the
SDK's own models or are validated by botocore's Stubber, which holds the
field names to the published service model.
"""

from __future__ import annotations

import importlib.util
import json
from types import SimpleNamespace

import pytest

from vecshield_platform.store_facts import _managed_util as util
from vecshield_platform.store_facts import azure_search as sf_azure
from vecshield_platform.store_facts import bedrock_kb as sf_bedrock
from vecshield_platform.store_facts import openai as sf_openai
from vecshield_platform.store_facts import pinecone as sf_pinecone
from vecshield_platform.store_facts import vertex_ai as sf_vertex


class _Denied(Exception):
    status_code = 403


def _dump(value) -> str:
    return json.dumps(value, default=str)


def _assert_shapes(loc=None, integ=None, info=None):
    if loc is not None:
        assert set(loc) == {"provider", "region", "replica_regions", "source",
                            "observable", "reason", "evidence"}
    if integ is not None:
        assert set(integ) == {"observable", "reason", "source", "integrations", "controls"}
        for item in integ["integrations"]:
            assert set(item) == {"collection", "stage", "provider", "model",
                                 "endpoint_host", "auth", "module", "evidence"}
            assert item["stage"] in ("ingest", "query", "generate", "rerank")
            assert item["auth"] in ("managed_identity", "api_key", "none", "unknown")
    if info is not None:
        assert set(info) == {"product", "version", "edition", "managed", "source",
                             "reason", "features"}
        assert info["managed"] is True


# --------------------------------------------------------------------------- #
# shared helpers                                                               #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("raw,expected", [
    ("cosine", "cosine"), ("COSINE_DISTANCE", "cosine"),
    ("dotproduct", "dot"), ("dotProduct", "dot"), ("DOT_PRODUCT_DISTANCE", "dot"),
    ("euclidean", "euclidean"), ("SQUARED_L2_DISTANCE", "euclidean"),
    ("L1_DISTANCE", "manhattan"), ("hamming", None), (None, None), ("bogus", None),
])
def test_normalize_metric(raw, expected):
    assert util.normalize_metric(raw) == expected


def test_scrub_drops_secret_keys_recursively():
    out = util.scrub({"apiKey": "s1", "nested": {"api-key": "s2", "keep": 1},
                      "items": [{"password": "s3", "host": "h"}],
                      "httpHeaders": {"x": "s4"}, "connectionString": "s5"})
    assert "s1" not in _dump(out) and "s2" not in _dump(out)
    assert "s3" not in _dump(out) and "s4" not in _dump(out) and "s5" not in _dump(out)
    assert out["nested"]["keep"] == 1 and out["items"][0]["host"] == "h"


def test_host_of_strips_userinfo_port_and_path():
    assert util.host_of("https://user:pw@x.openai.azure.com:443/a?code=1") == \
        "x.openai.azure.com"
    assert util.host_of(None) is None


# --------------------------------------------------------------------------- #
# Pinecone                                                                     #
# --------------------------------------------------------------------------- #

def _pinecone(indexes=None, error=None, namespaces=None):
    from vecshield_platform.connectors.pinecone import PineconeConnector

    class _Index:
        def __init__(self, name):
            self.name = name

        def describe_index_stats(self):
            return {"namespaces": (namespaces or {}).get(self.name, {})}

    class _PC:
        api_key = "pcsk-SECRET-123"

        def list_indexes(self):
            if error:
                raise error
            return indexes

        def Index(self, name):  # noqa: N802 - Pinecone API
            return _Index(name)

    conn = object.__new__(PineconeConnector)
    conn._pc = _PC()
    conn._idx_cache = {}
    conn._endpoint = "pinecone://pcsk-S…"
    return conn


_PC_LEGACY = {
    "name": "docs", "metric": "dotproduct", "dimension": 1024,
    "deletion_protection": "enabled",
    "host": "docs-abc.svc.aped-4627-b74a.pinecone.io",
    "spec": {"serverless": {"cloud": "aws", "region": "us-east-1"}},
    "embed": {"model": "llama-text-embed-v2", "metric": "dotproduct",
              "field_map": {"text": "chunk_text"}},
}
_PC_2026 = {
    "name": "kb", "deletion_protection": "disabled",
    "deployment": {"deployment_type": "managed", "cloud": "aws", "region": "us-east-1"},
    "schema": {"fields": {
        "body": {"type": "semantic_text", "model": "multilingual-e5-large",
                 "metric": "cosine"},
        "tag": {"type": "string"}}},
}


def test_pinecone_happy_path_legacy_and_2026_shapes():
    conn = _pinecone([_PC_LEGACY, _PC_2026], namespaces={"docs": {"": {}, "t1": {}}})
    assert sf_pinecone.distance_metrics(conn) == {"docs": "dot", "docs/t1": "dot",
                                                  "kb": "cosine"}

    loc = sf_pinecone.store_location(conn)
    _assert_shapes(loc=loc)
    assert loc["provider"] == "pinecone" and loc["region"] == "us-east-1"
    assert loc["observable"] is True and loc["evidence"]["cloud"] == "aws"

    integ = sf_pinecone.model_integrations(conn)
    _assert_shapes(integ=integ)
    got = {(i["collection"], i["stage"], i["model"]) for i in integ["integrations"]}
    assert got == {("docs", "ingest", "llama-text-embed-v2"),
                   ("docs", "query", "llama-text-embed-v2"),
                   ("kb", "ingest", "multilingual-e5-large"),
                   ("kb", "query", "multilingual-e5-large")}
    assert all(i["provider"] == "pinecone" for i in integ["integrations"])

    info = sf_pinecone.server_info(conn)
    _assert_shapes(info=info)
    assert info["product"] == "pinecone" and info["version"] is None
    assert info["features"]["indexes"]["docs"] == {"index_type": "serverless",
                                                   "deletion_protection": "enabled"}
    assert info["features"]["indexes"]["kb"]["index_type"] == "serverless"
    for result in (loc, integ, info):
        assert "SECRET" not in _dump(result)


def test_pinecone_pod_environment_uses_documented_table():
    conn = _pinecone([{"name": "p", "metric": "euclidean",
                       "spec": {"pod": {"environment": "eu-west1-gcp",
                                        "pod_type": "p1.x1"}}}])
    loc = sf_pinecone.store_location(conn)
    assert loc["region"] == "europe-west1" and loc["evidence"]["cloud"] == "gcp"
    assert loc["evidence"]["indexes"]["p"]["environment"] == "eu-west1-gcp"
    assert sf_pinecone.distance_metrics(conn) == {"p": "euclidean"}


def test_pinecone_unknown_environment_and_mixed_regions_are_not_guessed():
    conn = _pinecone([{"name": "x", "spec": {"pod": {"environment": "gcp-starter"}}}])
    loc = sf_pinecone.store_location(conn)
    assert loc["region"] is None and loc["observable"] is False

    conn = _pinecone([_PC_LEGACY, {"name": "eu", "spec": {"serverless": {
        "cloud": "aws", "region": "eu-west-1"}}}])
    loc = sf_pinecone.store_location(conn)
    assert loc["region"] is None and loc["observable"] is True
    assert loc["evidence"]["regions"] == ["aws:eu-west-1", "aws:us-east-1"]


def test_pinecone_missing_permission_is_reported_not_raised():
    conn = _pinecone(error=_Denied("forbidden"))
    loc = sf_pinecone.store_location(conn)
    integ = sf_pinecone.model_integrations(conn)
    info = sf_pinecone.server_info(conn)
    assert loc["observable"] is False and "ControlPlaneViewer" in loc["reason"]
    assert integ["observable"] is False and "ControlPlaneViewer" in integ["reason"]
    assert "ControlPlaneViewer" in info["reason"]
    assert sf_pinecone.distance_metrics(conn) == {}


# --------------------------------------------------------------------------- #
# Azure AI Search                                                              #
# --------------------------------------------------------------------------- #

def _has(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except ModuleNotFoundError:
        return False


needs_azure = pytest.mark.skipif(not _has("azure.search.documents"),
                                 reason="azure-search-documents not installed")


def _azure_index():
    from azure.search.documents.indexes import models as m
    return m.SearchIndex(
        name="docs",
        fields=[m.SearchField(name="id", type="Edm.String", key=True),
                m.SearchField(name="v", type="Collection(Edm.Single)",
                              vector_search_dimensions=3,
                              vector_search_profile_name="p-aoai")],
        vector_search=m.VectorSearch(
            profiles=[m.VectorSearchProfile(name="p-aoai", algorithm_configuration_name="h",
                                            vectorizer_name="aoai"),
                      m.VectorSearchProfile(name="p-web", algorithm_configuration_name="h",
                                            vectorizer_name="web")],
            algorithms=[m.HnswAlgorithmConfiguration(
                name="h", parameters=m.HnswParameters(metric="dotProduct"))],
            vectorizers=[
                m.AzureOpenAIVectorizer(
                    vectorizer_name="aoai",
                    parameters=m.AzureOpenAIVectorizerParameters(
                        resource_url="https://contoso.openai.azure.com",
                        deployment_name="emb", api_key="AOAI-SECRET-KEY",
                        model_name="text-embedding-3-small")),
                m.WebApiVectorizer(
                    vectorizer_name="web",
                    web_api_parameters=m.WebApiVectorizerParameters(
                        url="https://embed.example.com/v1?code=FUNC-SECRET",
                        http_headers={"x-api-key": "HEADER-SECRET"})),
                m.AzureMachineLearningVectorizer(
                    vectorizer_name="aml",
                    aml_parameters=m.AzureMachineLearningParameters(
                        scoring_uri="https://ep.eastus.inference.ml.azure.com/score",
                        resource_id="/subscriptions/x/onlineendpoints/ep",
                        region="eastus"))]),
        semantic_search=m.SemanticSearch(configurations=[m.SemanticConfiguration(
            name="sem", prioritized_fields=m.SemanticPrioritizedFields(
                content_fields=[m.SemanticField(field_name="id")]))]))


def _azure_second_index(metric="hamming"):
    from azure.search.documents.indexes import models as m
    return m.SearchIndex(
        name="bin",
        fields=[m.SearchField(name="b", type="Collection(Edm.Byte)",
                              vector_search_dimensions=8, vector_search_profile_name="pb")],
        vector_search=m.VectorSearch(
            profiles=[m.VectorSearchProfile(name="pb", algorithm_configuration_name="e")],
            algorithms=[m.ExhaustiveKnnAlgorithmConfiguration(
                name="e", parameters=m.ExhaustiveKnnParameters(metric=metric))]))


def _azure(indexes=None, index_error=None, skillsets=None, skill_error=None,
           aliases=None, alias_error=None, monkeypatch=None):
    from azure.core.credentials import AzureKeyCredential
    from azure.search.documents.indexes import models as m

    from vecshield_platform.connectors.azure_search import AzureSearchConnector

    class _IX:
        _config = SimpleNamespace(api_version="2026-04-01")

        def list_indexes(self):
            if index_error:
                raise index_error
            return indexes if indexes is not None else [_azure_index(),
                                                         _azure_second_index()]

        def list_aliases(self):
            if alias_error:
                raise alias_error
            return aliases or []

        def list_knowledge_bases(self):
            return [m.KnowledgeBase(name="kb", knowledge_sources=[], models=[
                m.KnowledgeBaseAzureOpenAIModel(
                    azure_open_ai_parameters=m.AzureOpenAIVectorizerParameters(
                        resource_url="https://contoso.openai.azure.com",
                        deployment_name="gpt", model_name="gpt-4o",
                        auth_identity=m.SearchIndexerDataUserAssignedIdentity(
                            resource_id="/subscriptions/x/identity")))])]

    class _Indexer:
        def get_skillsets(self):
            if skill_error:
                raise skill_error
            return skillsets if skillsets is not None else [_azure_skillset()]

        def get_indexers(self):
            return [m.SearchIndexer(name="ixr", data_source_name="ds",
                                    target_index_name="docs", skillset_name="ss")]

    conn = object.__new__(AzureSearchConnector)
    conn._endpoint = "https://contoso-search.search.windows.net"
    conn._cred = AzureKeyCredential("ADMIN-SECRET-KEY")
    conn._ix = _IX()
    monkeypatch.setattr(sf_azure, "_indexer_client", lambda _c: _Indexer())
    return conn


def _azure_skillset():
    from azure.search.documents.indexes import models as m
    ss = m.SearchIndexerSkillset(
        name="ss",
        skills=[
            m.AzureOpenAIEmbeddingSkill(
                inputs=[], outputs=[], resource_url="https://contoso.openai.azure.com",
                deployment_name="emb", api_key="SKILL-SECRET-KEY",
                model_name="text-embedding-3-small"),
            m.WebApiSkill(inputs=[], outputs=[], uri="https://fn.azurewebsites.net/api/x",
                          auth_resource_id="api://contoso-skill"),
            m.EntityRecognitionSkillV3(inputs=[], outputs=[]),
            m.SplitSkill(inputs=[], outputs=[]),
        ],
        cognitive_services_account=m.AIServicesAccountKey(
            key="AISVC-SECRET-KEY", subdomain_url="https://ai.cognitiveservices.azure.com"))
    raw = ss.as_dict()
    # An AML skill as the REST API returns it (not modelled by SDK 12.0).
    raw["skills"].append({"@odata.type": "#Microsoft.Skills.Custom.AmlSkill",
                          "name": "aml", "uri": "https://aml.example.com/score",
                          "key": "AML-SECRET-KEY"})
    return raw


@needs_azure
def test_azure_happy_path(monkeypatch):
    conn = _azure(monkeypatch=monkeypatch)
    assert sf_azure.distance_metrics(conn) == {"docs": "dot", "bin": None}

    integ = sf_azure.model_integrations(conn)
    _assert_shapes(integ=integ)
    assert integ["observable"] is True and "unread" not in integ["controls"]
    by_module = {i["module"]: i for i in integ["integrations"]}

    aoai = by_module["vectorizer:azureOpenAI"]
    assert (aoai["collection"], aoai["stage"], aoai["provider"], aoai["model"],
            aoai["endpoint_host"], aoai["auth"]) == (
        "docs", "query", "azure_openai", "text-embedding-3-small",
        "contoso.openai.azure.com", "api_key")
    web = by_module["vectorizer:customWebApi"]
    assert web["endpoint_host"] == "embed.example.com" and web["auth"] == "api_key"
    assert web["evidence"]["header_names"] == ["x-api-key"]
    aml = by_module["vectorizer:aml"]
    assert aml["auth"] == "managed_identity" and aml["evidence"]["model_region"] == "eastus"
    assert by_module["semantic_ranker"]["stage"] == "rerank"
    assert by_module["semantic_ranker"]["provider"] == "azure"

    emb_skill = by_module["skill:AzureOpenAIEmbedding"]
    assert (emb_skill["stage"], emb_skill["collection"], emb_skill["auth"]) == (
        "ingest", "docs", "api_key")
    assert by_module["skill:WebApi"]["auth"] == "managed_identity"
    assert by_module["skill:WebApi"]["endpoint_host"] == "fn.azurewebsites.net"
    assert by_module["skill:Aml"]["auth"] == "api_key"
    builtin = by_module["skill:builtin_ai_enrichment"]
    assert builtin["auth"] == "api_key"
    assert builtin["endpoint_host"] == "ai.cognitiveservices.azure.com"
    assert builtin["evidence"]["skill_types"] == [
        "#Microsoft.Skills.Text.V3.EntityRecognitionSkill"]
    kb = by_module["knowledge_base"]
    assert (kb["stage"], kb["model"], kb["auth"]) == ("generate", "gpt-4o",
                                                      "managed_identity")

    info = sf_azure.server_info(conn)
    _assert_shapes(info=info)
    assert info["product"] == "azure_ai_search"
    assert info["features"]["api_version"] == "2026-04-01"
    assert info["features"]["semantic_search"] == {"configured_indexes": ["docs"]}
    assert info["features"]["local_auth_disabled"] is None

    loc = sf_azure.store_location(conn)
    _assert_shapes(loc=loc)
    assert loc["observable"] is False and loc["region"] is None
    assert loc["reason"].startswith("Region is reported by Azure Resource Manager")

    for result in (integ, info, loc):
        text = _dump(result)
        for secret in ("AOAI-SECRET", "FUNC-SECRET", "HEADER-SECRET", "SKILL-SECRET",
                       "AISVC-SECRET", "AML-SECRET", "ADMIN-SECRET"):
            assert secret not in text


@needs_azure
def test_azure_absent_key_is_unknown_not_managed_identity(monkeypatch):
    """GET responses omit keys, so a blank apiKey cannot prove identity auth."""
    from azure.search.documents.indexes import models as m
    index = m.SearchIndex(name="i", fields=[], vector_search=m.VectorSearch(
        vectorizers=[m.AzureOpenAIVectorizer(
            vectorizer_name="a", parameters=m.AzureOpenAIVectorizerParameters(
                resource_url="https://c.openai.azure.com", deployment_name="d"))]))
    conn = _azure(indexes=[index], skillsets=[], monkeypatch=monkeypatch)
    (item,) = [i for i in sf_azure.model_integrations(conn)["integrations"]
               if i["module"] == "vectorizer:azureOpenAI"]
    assert item["auth"] == "unknown" and item["model"] == "d"


@needs_azure
def test_azure_mixed_metrics_are_none(monkeypatch):
    from azure.search.documents.indexes import models as m
    index = m.SearchIndex(
        name="mix",
        fields=[m.SearchField(name="a", type="Collection(Edm.Single)",
                              vector_search_dimensions=3, vector_search_profile_name="pa"),
                m.SearchField(name="b", type="Collection(Edm.Single)",
                              vector_search_dimensions=3, vector_search_profile_name="pb")],
        vector_search=m.VectorSearch(
            profiles=[m.VectorSearchProfile(name="pa", algorithm_configuration_name="x"),
                      m.VectorSearchProfile(name="pb", algorithm_configuration_name="y")],
            algorithms=[m.HnswAlgorithmConfiguration(
                name="x", parameters=m.HnswParameters(metric="cosine")),
                m.ExhaustiveKnnAlgorithmConfiguration(
                name="y", parameters=m.ExhaustiveKnnParameters(metric="euclidean"))]))
    conn = _azure(indexes=[index, _azure_second_index("euclidean")],
                  monkeypatch=monkeypatch)
    assert sf_azure.distance_metrics(conn) == {"mix": None, "bin": "euclidean"}


@needs_azure
def test_azure_missing_permission(monkeypatch):
    from azure.core.exceptions import HttpResponseError

    err = HttpResponseError(message="Forbidden")
    err.status_code = 403
    conn = _azure(index_error=err, monkeypatch=monkeypatch)
    integ = sf_azure.model_integrations(conn)
    assert integ["observable"] is False and "admin API key" in integ["reason"]
    info = sf_azure.server_info(conn)
    assert "admin API key" in info["reason"] and info["features"]["semantic_search"] is None
    assert sf_azure.distance_metrics(conn) == {}

    # Indexes readable but skillsets refused: partial, and visibly so.
    conn = _azure(skill_error=err, monkeypatch=monkeypatch)
    integ = sf_azure.model_integrations(conn)
    assert integ["observable"] is True
    assert integ["controls"]["unread"][0]["source"] == "GET /skillsets"
    assert "Partial" in integ["reason"]


@needs_azure
def test_azure_aliases(monkeypatch):
    from azure.core.exceptions import HttpResponseError
    from azure.search.documents.indexes import models as m

    from vecshield_platform.connectors.base import ConnectorAuthError

    conn = _azure(aliases=[m.SearchAlias(name="prod", indexes=["docs-v2"])],
                  monkeypatch=monkeypatch)
    assert sf_azure.list_aliases(conn) == {"prod": "docs-v2"}

    err = HttpResponseError(message="Forbidden")
    err.status_code = 403
    conn = _azure(alias_error=err, monkeypatch=monkeypatch)
    with pytest.raises(ConnectorAuthError, match="admin API key"):
        sf_azure.list_aliases(conn)


# --------------------------------------------------------------------------- #
# Bedrock Knowledge Bases (botocore Stubber: responses checked against the     #
# published bedrock-agent service model)                                       #
# --------------------------------------------------------------------------- #

def _bedrock(stub_setup):
    boto3 = pytest.importorskip("boto3")
    from botocore.stub import Stubber

    from vecshield_platform.connectors.bedrock_kb import BedrockKBConnector

    client = boto3.client("bedrock-agent", region_name="eu-west-1",
                          aws_access_key_id="AKIAEXAMPLE", aws_secret_access_key="SECRET")
    stubber = Stubber(client)
    stub_setup(stubber)
    stubber.activate()
    conn = object.__new__(BedrockKBConnector)
    conn._c = client
    conn._endpoint = "bedrock-kb://eu-west-1"
    return conn, stubber


_KB_SUMMARY = {"knowledgeBaseId": "KB12345678", "name": "hr", "status": "ACTIVE",
               "updatedAt": "2026-01-01T00:00:00Z"}
_KB = {
    "knowledgeBaseId": "KB12345678", "name": "hr",
    "knowledgeBaseArn": "arn:aws:bedrock:eu-west-1:111122223333:knowledge-base/KB12345678",
    "roleArn": "arn:aws:iam::111122223333:role/kb", "status": "ACTIVE",
    "createdAt": "2026-01-01T00:00:00Z", "updatedAt": "2026-01-01T00:00:00Z",
    "knowledgeBaseConfiguration": {
        "type": "VECTOR",
        "vectorKnowledgeBaseConfiguration": {
            "embeddingModelArn": "arn:aws:bedrock:eu-west-1:111122223333:"
                                 "inference-profile/eu.cohere.embed-v4:0",
            "embeddingModelConfiguration": {"bedrockEmbeddingModelConfiguration": {
                "dimensions": 1024, "embeddingDataType": "FLOAT32"}}}},
    "storageConfiguration": {
        "type": "PINECONE",
        "pineconeConfiguration": {
            "connectionString": "https://hr-abc.svc.aped-1.pinecone.io",
            "credentialsSecretArn": "arn:aws:secretsmanager:eu-west-1:111122223333:"
                                    "secret:PINECONE-SECRET-ARN",
            "fieldMapping": {"textField": "t", "metadataField": "m"}}},
}
_DS = {
    "knowledgeBaseId": "KB12345678", "dataSourceId": "DS12345678", "name": "s3",
    "status": "AVAILABLE", "createdAt": "2026-01-01T00:00:00Z",
    "updatedAt": "2026-01-01T00:00:00Z",
    "dataSourceConfiguration": {"type": "S3", "s3Configuration": {
        "bucketArn": "arn:aws:s3:::docs"}},
    "vectorIngestionConfiguration": {
        "parsingConfiguration": {
            "parsingStrategy": "BEDROCK_FOUNDATION_MODEL",
            "bedrockFoundationModelConfiguration": {
                "modelArn": "arn:aws:bedrock:eu-west-1::foundation-model/"
                            "anthropic.claude-3-haiku-20240307-v1:0"}}},
}


def _stub_bedrock_happy(stubber, times=1):
    for _ in range(times):
        stubber.add_response("list_knowledge_bases",
                             {"knowledgeBaseSummaries": [_KB_SUMMARY]}, {})
        stubber.add_response("get_knowledge_base", {"knowledgeBase": _KB},
                             {"knowledgeBaseId": "KB12345678"})


def test_bedrock_model_integrations_and_backing_store():
    def setup(stubber):
        _stub_bedrock_happy(stubber)
        stubber.add_response("list_data_sources", {"dataSourceSummaries": [{
            "knowledgeBaseId": "KB12345678", "dataSourceId": "DS12345678", "name": "s3",
            "status": "AVAILABLE", "updatedAt": "2026-01-01T00:00:00Z"}]},
            {"knowledgeBaseId": "KB12345678"})
        stubber.add_response("get_data_source", {"dataSource": _DS},
                             {"knowledgeBaseId": "KB12345678",
                              "dataSourceId": "DS12345678"})

    conn, stubber = _bedrock(setup)
    integ = sf_bedrock.model_integrations(conn)
    stubber.assert_no_pending_responses()
    _assert_shapes(integ=integ)
    assert integ["observable"] is True
    emb = [i for i in integ["integrations"] if i["module"] == "embedding"]
    assert {i["stage"] for i in emb} == {"ingest", "query"}
    assert emb[0]["model"] == "cohere.embed-v4:0" and emb[0]["provider"] == "aws_bedrock"
    assert emb[0]["evidence"]["cross_region_scope"] == "eu"
    assert emb[0]["evidence"]["model_region"] == "eu-west-1"
    assert emb[0]["collection"] == "hr (KB12345678)"
    (parse,) = [i for i in integ["integrations"] if i["module"] == "parsing:foundation_model"]
    assert parse["stage"] == "ingest"
    assert parse["model"] == "anthropic.claude-3-haiku-20240307-v1:0"
    store = integ["controls"]["backing_store"]["hr (KB12345678)"]
    assert store == {"type": "PINECONE", "third_party": True, "vendor": "pinecone",
                     "host": "hr-abc.svc.aped-1.pinecone.io"}
    assert "RetrieveAndGenerate" in integ["controls"]["generation_model"]
    text = _dump(integ)
    assert "PINECONE-SECRET-ARN" not in text and "111122223333" not in text
    assert sf_bedrock.distance_metrics(conn) == {}


def test_bedrock_location_and_server_info():
    conn, stubber = _bedrock(_stub_bedrock_happy)
    loc = sf_bedrock.store_location(conn)
    _assert_shapes(loc=loc)
    assert (loc["provider"], loc["region"], loc["source"], loc["observable"]) == (
        "aws", "eu-west-1", "client_region", True)
    assert loc["evidence"]["third_party_backing_stores"] == ["pinecone"]
    info = sf_bedrock.server_info(conn)
    _assert_shapes(info=info)
    assert info["features"]["api_version"] == "2023-06-05"
    assert "SECRET" not in _dump(loc) + _dump(info)


def test_bedrock_access_denied():
    def setup(stubber):
        for _ in range(2):
            stubber.add_client_error("list_knowledge_bases",
                                     service_error_code="AccessDeniedException",
                                     http_status_code=403)

    conn, _ = _bedrock(setup)
    integ = sf_bedrock.model_integrations(conn)
    assert integ["observable"] is False
    assert "bedrock:ListKnowledgeBases" in integ["reason"]
    loc = sf_bedrock.store_location(conn)  # region still comes from the client
    assert loc["region"] == "eu-west-1"
    assert "bedrock:ListKnowledgeBases" in loc["evidence"]["backing_store_error"]


@pytest.mark.parametrize("arn,model,scope", [
    ("arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-embed-text-v2:0",
     "amazon.titan-embed-text-v2:0", None),
    ("arn:aws:bedrock:us-east-1:1:inference-profile/global.cohere.embed-v4:0",
     "cohere.embed-v4:0", "global"),
    ("arn:aws:bedrock:us-east-1:1:application-inference-profile/abc", None, None),
    ("amazon.titan-embed-text-v1", "amazon.titan-embed-text-v1", None),
])
def test_bedrock_parse_model_arn(arn, model, scope):
    parsed = sf_bedrock.parse_model_arn(arn)
    assert parsed["model"] == model
    assert parsed.get("cross_region_scope") == scope


# --------------------------------------------------------------------------- #
# Vertex AI Vector Search                                                      #
# --------------------------------------------------------------------------- #

def _vertex(indexes=None, error=None):
    from vecshield_platform.connectors.vertex_ai import VertexAIConnector

    class _Idx:
        def __init__(self, iid, metric, location="europe-west4"):
            self.name = iid
            self.resource_name = f"projects/123/locations/{location}/indexes/{iid}"
            self._metric = metric

        def to_dict(self):
            return {"name": self.resource_name, "indexUpdateMethod": "STREAM_UPDATE",
                    "metadata": {"config": {"dimensions": 768,
                                            "distanceMeasureType": self._metric,
                                            "featureNormType": "UNIT_L2_NORM"}}}

    class _MEI:
        @staticmethod
        def list(**_kw):  # the connector passes project/location/credentials
            if error:
                raise error
            return [_Idx(*spec) for spec in indexes]

    conn = object.__new__(VertexAIConnector)
    conn._ai = SimpleNamespace(MatchingEngineIndex=_MEI, __version__="1.99.0")
    conn._project = "proj"
    conn._location = "europe-west4"
    conn._endpoint_id = None
    return conn


def test_vertex_metrics_location_and_integrations():
    conn = _vertex([("i1", "DOT_PRODUCT_DISTANCE"), ("i2", "SQUARED_L2_DISTANCE"),
                    ("i3", "L1_DISTANCE"), ("i4", "COSINE_DISTANCE")])
    assert sf_vertex.distance_metrics(conn) == {"i1": "dot", "i2": "euclidean",
                                                "i3": "manhattan", "i4": "cosine"}
    loc = sf_vertex.store_location(conn)
    _assert_shapes(loc=loc)
    assert (loc["provider"], loc["region"], loc["source"]) == (
        "gcp", "europe-west4", "resource_name")
    integ = sf_vertex.model_integrations(conn)
    _assert_shapes(integ=integ)
    assert integ["observable"] is True and integ["integrations"] == []
    info = sf_vertex.server_info(conn)
    _assert_shapes(info=info)
    assert info["features"]["indexes"]["i1"]["index_update_method"] == "STREAM_UPDATE"


def test_vertex_missing_permission():
    class PermissionDenied(Exception):
        code = 403

    conn = _vertex(error=PermissionDenied("denied"))
    loc = sf_vertex.store_location(conn)
    assert loc["observable"] is False and "aiplatform.indexes.list" in loc["reason"]
    assert sf_vertex.distance_metrics(conn) == {}
    assert "aiplatform.indexes.list" in sf_vertex.server_info(conn)["reason"]


# --------------------------------------------------------------------------- #
# OpenAI vector stores                                                         #
# --------------------------------------------------------------------------- #

def _openai(base_url=None):
    openai = pytest.importorskip("openai")

    from vecshield_platform.connectors.openai_vs import OpenAIVectorStoreConnector

    conn = object.__new__(OpenAIVectorStoreConnector)
    kw = {"api_key": "sk-OPENAI-SECRET"}
    if base_url:
        kw["base_url"] = base_url
    conn._c = openai.OpenAI(**kw)
    return conn


def test_openai_location_is_not_claimed_from_the_domain(monkeypatch):
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    loc = sf_openai.store_location(_openai())
    _assert_shapes(loc=loc)
    assert loc["observable"] is False and "dashboard" in loc["reason"]

    loc = sf_openai.store_location(_openai("https://eu.api.openai.com/v1"))
    assert loc["observable"] is False and loc["region"] is None
    assert loc["evidence"]["request_region_prefix"] == "eu"

    loc = sf_openai.store_location(_openai("https://proxy.internal.example/v1"))
    assert "not an OpenAI API domain" in loc["reason"]


def test_openai_integrations_and_secrets(monkeypatch):
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    conn = _openai()
    integ = sf_openai.model_integrations(conn)
    _assert_shapes(integ=integ)
    assert {(i["stage"], i["provider"], i["model"]) for i in integ["integrations"]} == {
        ("ingest", "openai", None), ("query", "openai", None)}
    info = sf_openai.server_info(conn)
    _assert_shapes(info=info)
    assert info["product"] == "openai_vector_stores"
    assert sf_openai.distance_metrics(conn) == {}
    assert "OPENAI-SECRET" not in _dump(integ) + _dump(info)
