"""Model egress: the store sending chunk text to an outside AI provider.

The rules under test: severity follows what the collection holds; a declared
processor with the right agreements turns a gap into an INFO record; a store
that cannot report its integrations is never failed; evidence never carries a
secret.
"""

from __future__ import annotations

import json
import types

import pytest

from vecshield.models import Severity
from vecshield_platform.connectors.base import ConnectorAuthError, UnsupportedCapability
from vecshield_platform.posture import egress
from vecshield_platform.posture.egress import (
    CATEGORY,
    CHECK,
    assess_model_egress,
    evaluate_trusted_endpoints,
    flow_severity,
    provider_registry,
    resolve_provider,
    scrub,
)

SECRET = "sk-proj-THISISNOTAREALKEY0123456789abcdef"


class FakeConnector:
    def __init__(self, kind="weaviate", report=None, caps=("egress_introspection",), raises=None):
        self.kind = kind
        self._report = report
        self._caps = set(caps)
        self._raises = raises

    def capabilities(self):
        return self._caps

    def model_integrations(self):
        if self._raises:
            raise self._raises
        return self._report


def store(name="kb", kind="weaviate", endpoint="https://weaviate.internal.example:8080"):
    return types.SimpleNamespace(name=name, kind=kind, endpoint=endpoint)


def integ(collection, provider, *, stage="ingest", model=None, host=None, auth="unknown",
          module=None, evidence=None):
    return {"collection": collection, "stage": stage, "provider": provider, "model": model,
            "endpoint_host": host, "auth": auth, "module": module, "evidence": evidence or {}}


def report(*integrations, controls=None, observable=True, reason=""):
    return {"observable": observable, "reason": reason, "source": "GET /v1/schema",
            "integrations": list(integrations), "controls": controls or {}}


def run(integrations=(), labels=None, declared=None, kind="weaviate", controls=None,
        endpoint="https://weaviate.internal.example:8080"):
    conn = FakeConnector(kind=kind, report=report(*integrations, controls=controls))
    return assess_model_egress(conn, store(kind=kind, endpoint=endpoint),
                               sensitive_labels_by_collection=labels or {},
                               declared_processors=declared)


def only(findings, severity=None, title_part=None):
    out = [f for f in findings if (severity is None or f.severity == severity)
           and (title_part is None or title_part in f.title)]
    assert len(out) == 1, [(f.severity, f.title) for f in findings]
    return out[0]


# ---- registry ----------------------------------------------------------------

def test_registry_has_required_providers_and_sources_for_every_statement():
    reg = provider_registry()["providers"]
    for pid in ("openai", "azure_openai", "cohere", "voyageai", "jina", "google_vertex",
                "google_gemini_api", "aws_bedrock", "anthropic", "huggingface", "mistral",
                "nvidia", "pinecone", "mongodb_autoembed", "local", "self_hosted", "unknown"):
        assert pid in reg, pid
    for pid, entry in reg.items():
        assert entry["class"] in egress.CLASSES, pid
        for key in ("training_use", "retention", "baa", "eu_residency"):
            stmt = entry.get(key)
            if stmt is not None:
                assert stmt["source"].startswith("https://"), (pid, key)


def test_same_cloud_tenant_service_is_not_the_public_api():
    assert provider_registry()["providers"]["azure_openai"]["class"] == "customer_cloud_service"
    assert provider_registry()["providers"]["openai"]["class"] == "third_party_processor"
    assert provider_registry()["providers"]["google_vertex"]["class"] == "customer_cloud_service"
    assert provider_registry()["providers"]["google_gemini_api"]["class"] == "third_party_processor"


def test_provider_resolution_by_alias_and_host():
    assert resolve_provider("text2vec-transformers")[0] == "transformers"
    assert resolve_provider("unknown", "api.openai.com")[0] == "openai"
    assert resolve_provider(None, "myres.openai.azure.com")[0] == "azure_openai"
    assert resolve_provider("bedrock")[0] == "aws_bedrock"
    # "google" alone is ambiguous: resolved by host, never assumed to be Vertex.
    assert resolve_provider("google", "generativelanguage.googleapis.com")[0] == "google_gemini_api"
    assert resolve_provider("google", "us-central1-aiplatform.googleapis.com")[0] == "google_vertex"
    pid, entry = resolve_provider("google")
    assert pid == "google_unresolved" and entry["class"] == "third_party_processor"


# ---- severity paths -------------------------------------------------------------

@pytest.mark.parametrize("labels,expected", [
    ({"phi": 3}, Severity.HIGH),
    ({"pci": 1}, Severity.HIGH),
    ({"secret": 1}, Severity.HIGH),
    ({"special_category": 2}, Severity.HIGH),
    ({"criminal_offence": 1}, Severity.HIGH),
    ({"pii": 9}, Severity.MEDIUM),
])
def test_undeclared_third_party_flow_severity(labels, expected):
    findings, outcome = run([integ("docs", "openai", host="api.openai.com")],
                            labels={"docs": labels})
    f = only(findings, expected)
    assert f.category == CATEGORY and f.collection == "docs"
    assert outcome["check"] == CHECK and outcome["collection"] is None
    if expected == Severity.HIGH:
        assert outcome["outcome"] == "failed"
    else:
        assert outcome["outcome"] == "inconclusive"
    asks = f.evidence["evidence_to_supply"]
    assert "sub_processor_register" in asks and "data_processing_agreement" in asks
    assert ("business_associate_agreement" in asks) == ("phi" in labels)
    flow = outcome["coverage"]["flows"][0]
    assert flow["provider"] == "openai" and flow["declared"] is False
    assert flow["labels"] == list(labels)


def test_flow_severity_rules_directly():
    assert flow_severity(["phi"], klass="third_party_processor", baa_declared=True)[0] == Severity.MEDIUM
    assert flow_severity(["pii"], klass="customer_cloud_service", baa_declared=False)[0] == Severity.INFO
    assert flow_severity(["secret"], klass="store_operator", baa_declared=False)[0] == Severity.MEDIUM


def test_customer_cloud_service_with_phi_is_not_a_gap():
    findings, outcome = run([integ("notes", "azure_openai", host="kb.openai.azure.com",
                                   auth="managed_identity")],
                            labels={"notes": {"phi": 10}}, kind="azure_search")
    assert findings == []
    assert outcome["outcome"] == "passed"
    assert outcome["coverage"]["flows"][0]["status"] == "within_customer_control"


def test_local_model_is_not_egress():
    findings, outcome = run([integ("notes", "text2vec-transformers",
                                   host="t2v-transformers:8080")],
                            labels={"notes": {"phi": 10}})
    assert findings == [] and outcome["outcome"] == "passed"


def test_unknown_provider_on_private_host_is_local():
    findings, outcome = run([integ("notes", None, host="10.0.4.12")],
                            labels={"notes": {"pii": 1}})
    assert outcome["coverage"]["flows"][0]["class"] == "local"
    assert outcome["outcome"] == "passed"


def test_store_operator_flow_is_capped_at_medium():
    findings, outcome = run([integ("idx", "pinecone", stage="ingest")],
                            labels={"idx": {"phi": 4}}, kind="pinecone",
                            endpoint="https://idx-abc.svc.aped-4627-b74a.pinecone.io")
    f = only(findings, Severity.MEDIUM)
    assert f.evidence["class"] == "store_operator"
    assert outcome["outcome"] == "inconclusive"


def test_voyage_from_atlas_is_store_operator_but_third_party_elsewhere():
    _, atlas = run([integ("c", "voyageai")], labels={"c": {"pii": 1}}, kind="mongodb",
                   endpoint="mongodb+srv://cluster0.abcde.mongodb.net")
    _, other = run([integ("c", "voyageai")], labels={"c": {"pii": 1}}, kind="weaviate")
    assert atlas["coverage"]["flows"][0]["class"] == "store_operator"
    assert other["coverage"]["flows"][0]["class"] == "third_party_processor"


def test_non_sensitive_collection_passes():
    findings, outcome = run([integ("public", "cohere")], labels={"public": {"none": 50}})
    assert findings == [] and outcome["outcome"] == "passed"


def test_unscanned_collection_is_labels_unknown_never_failed():
    findings, outcome = run([integ("never_scanned", "openai")], labels={})
    assert findings == []
    assert outcome["outcome"] == "inconclusive"
    assert outcome["coverage"]["flows"][0]["label_status"] == "unknown"
    assert "sub_processor_register" in outcome["coverage"]["evidence_to_supply"]


# ---- declared processors ----------------------------------------------------

def test_declared_processor_with_dpa_turns_gap_into_info_record():
    findings, outcome = run([integ("docs", "openai")], labels={"docs": {"pii": 3}},
                            declared=[{"provider": "openai", "dpa": True, "baa": False,
                                       "regions": ["eu"]}])
    f = only(findings)
    assert f.severity == Severity.INFO
    assert outcome["outcome"] == "passed"
    assert outcome["coverage"]["flows"][0]["declared"] is True


def test_phi_needs_a_declared_baa_as_well_as_a_dpa():
    declared = [{"provider": "OpenAI", "dpa": True, "baa": False}]
    findings, outcome = run([integ("notes", "openai")], labels={"notes": {"phi": 1}},
                            declared=declared)
    f = only(findings, Severity.HIGH)
    assert "no BAA is declared" in f.description
    assert outcome["outcome"] == "failed"

    declared[0]["baa"] = True
    findings, outcome = run([integ("notes", "openai")], labels={"notes": {"phi": 1}},
                            declared=declared)
    assert only(findings).severity == Severity.INFO and outcome["outcome"] == "passed"


def test_declared_alias_matches_registry_id():
    findings, _ = run([integ("docs", "voyageai")],
                      labels={"docs": {"pii": 1}},
                      declared=[{"provider": "voyage", "dpa": True}])
    assert only(findings).severity == Severity.INFO


# ---- store-wide modules, auth, controls -------------------------------------

def test_configured_but_unused_modules_are_one_low_finding():
    findings, outcome = run([integ(None, "openai", module="text2vec-openai"),
                             integ(None, "cohere", module="text2vec-cohere"),
                             integ(None, "text2vec-transformers", module="text2vec-transformers")])
    f = only(findings, Severity.LOW, "not observed in use")
    assert set(f.evidence["providers"]) == {"openai", "cohere"}
    assert "ENABLE_MODULES" in f.remediation
    assert outcome["outcome"] == "passed"


def test_store_wide_module_used_by_a_collection_is_not_unused():
    findings, _ = run([integ(None, "openai", module="text2vec-openai"),
                       integ("docs", "openai", module="text2vec-openai")],
                      labels={"docs": {"none": 1}})
    assert not [f for f in findings if "not observed in use" in f.title]


def test_api_key_auth_is_low_and_key_never_recorded():
    findings, _ = run([integ("docs", "azure_openai", host="res.openai.azure.com", auth="api_key",
                             evidence={"resourceUri": "https://res.openai.azure.com",
                                       "apiKey": SECRET, "note": f"key={SECRET}"})],
                      labels={"docs": {"none": 1}}, kind="azure_search")
    f = only(findings, Severity.LOW, "API keys")
    assert "managed identity" in f.remediation.lower() or "authIdentity" in f.remediation
    assert SECRET not in json.dumps([x.to_dict() for x in findings])


def test_trusted_endpoint_regex_over_broad_and_plaintext():
    result = evaluate_trusted_endpoints([
        r"^https://api\.openai\.com/.*$",
        r".*",
        r"^https?://api\.cohere\.ai/.*$",
        r"^(unbalanced",
    ])
    assert result["over_broad"] == [".*"]
    assert set(result["plaintext"]) == {".*", r"^https?://api\.cohere\.ai/.*$"}
    assert result["not_evaluated"] == [r"^(unbalanced"]
    assert r"^https://api\.openai\.com/.*$" not in result["over_broad"] + result["plaintext"]


def test_trusted_endpoint_finding_is_medium_and_names_the_setting():
    findings, _ = run(kind="opensearch", controls={"trusted_endpoints": [".*"]})
    f = only(findings, Severity.MEDIUM)
    assert "plugins.ml_commons.trusted_connector_endpoints_regex" in f.remediation


def test_tight_trusted_endpoints_raise_nothing():
    findings, outcome = run(kind="opensearch", controls={
        "trusted_endpoints": [r"^https://bedrock-runtime\..*[a-z0-9-]\.amazonaws\.com/.*$"]})
    assert findings == []
    assert outcome["coverage"]["controls"]["trusted_endpoints"]["evaluated"]


# ---- not observable: never failed ---------------------------------------------

@pytest.fixture
def no_store_facts(monkeypatch):
    """Neither the connector nor its kind's store_facts adapter can answer."""
    from vecshield_platform import store_facts

    monkeypatch.setattr(store_facts, "supported", lambda connector: set())


def test_no_capability_on_store_without_model_features_is_capability_limit(no_store_facts):
    conn = FakeConnector(kind="redis", caps=())
    findings, outcome = assess_model_egress(conn, store(kind="redis"),
                                            sensitive_labels_by_collection={})
    assert findings == []
    assert outcome["outcome"] == "unsupported"
    assert outcome["coverage"]["capability_limit"] is True


def test_no_capability_on_store_with_model_features_is_inconclusive(no_store_facts):
    for kind in ("weaviate", "vertex_ai", "chroma"):
        conn = FakeConnector(kind=kind, caps=())
        findings, outcome = assess_model_egress(conn, store(kind=kind),
                                                sensitive_labels_by_collection={})
        assert findings == [] and outcome["outcome"] == "inconclusive", kind
        assert "capability_limit" not in outcome["coverage"]
        assert "sub_processor_register" in outcome["coverage"]["evidence_to_supply"]


def test_capability_comes_from_store_facts_not_the_connector_flag():
    """A connector that implements model_integrations() is read even when its
    capabilities() does not advertise egress_introspection (store_facts decides)."""
    conn = FakeConnector(caps=(), report=report(integ("docs", "openai")))
    findings, outcome = assess_model_egress(conn, store(),
                                            sensitive_labels_by_collection={"docs": {"phi": 2}})
    assert outcome["outcome"] == "failed"
    assert [f["provider"] for f in outcome["coverage"]["flows"]] == ["openai"]


def test_redis_adapter_has_no_egress_capability():
    """Redis has an adapter but no model_integrations: a capability limit."""
    class RedisOnly:
        kind = "redis"

    findings, outcome = assess_model_egress(RedisOnly(), store(kind="redis"),
                                            sensitive_labels_by_collection={})
    assert findings == [] and outcome["outcome"] == "unsupported"
    assert outcome["coverage"]["capability_limit"] is True


def test_integrations_reader_replays_a_gathered_report_without_calling_the_store():
    class Unreachable(FakeConnector):
        def model_integrations(self):
            raise AssertionError("the store must not be asked twice")

    gathered = report(integ("docs", "openai"))
    findings, outcome = assess_model_egress(
        Unreachable(), store(), sensitive_labels_by_collection={"docs": {"pii": 1}},
        integrations_reader=lambda: gathered)
    assert [f["provider"] for f in outcome["coverage"]["flows"]] == ["openai"]


@pytest.mark.parametrize("exc,expected", [
    (ConnectorAuthError("403"), "inconclusive"),
    (UnsupportedCapability("no"), "inconclusive"),
    (RuntimeError("boom"), "error"),
])
def test_read_failures_are_never_failed(exc, expected):
    conn = FakeConnector(raises=exc)
    findings, outcome = assess_model_egress(conn, store(), sensitive_labels_by_collection={})
    assert findings == [] and outcome["outcome"] == expected


def test_not_observable_report_is_inconclusive_with_reason():
    conn = FakeConnector(report=report(observable=False,
                                       reason="the key lacks schema read permission"))
    findings, outcome = assess_model_egress(conn, store(), sensitive_labels_by_collection={})
    assert findings == [] and outcome["outcome"] == "inconclusive"
    assert "schema read permission" in outcome["reason"]


# ---- secret-free evidence ------------------------------------------------------

def test_scrub_drops_secret_keys_and_values_but_keeps_config():
    cleaned = scrub({"apiKey": SECRET, "X-OpenAI-Api-Key": "abc", "headers": {"a": "b"},
                     "auth": "api_key", "model": "text-embedding-3-small",
                     "resource": "projects/p-1/locations/us-central1/models/m",
                     "nested": [{"token": "t"}, f"Bearer {SECRET}"]})
    text = json.dumps(cleaned)
    assert SECRET not in text and "abc" not in text and "headers" not in text
    assert cleaned["auth"] == "api_key" and cleaned["model"] == "text-embedding-3-small"
    assert cleaned["resource"].startswith("projects/")


def test_findings_never_carry_endpoint_credentials():
    findings, outcome = run([integ("docs", "openai",
                                   host=f"https://user:{SECRET}@api.openai.com/v1?key={SECRET}",
                                   evidence={"Authorization": f"Bearer {SECRET}"})],
                            labels={"docs": {"pii": 1}})
    dumped = json.dumps([f.to_dict() for f in findings]) + json.dumps(outcome)
    assert SECRET not in dumped
    assert outcome["coverage"]["flows"][0]["endpoint_host"] == "api.openai.com"


def test_every_connector_kind_has_an_egress_support_entry():
    from vecshield_platform.posture.egress import egress_support
    kinds = {"azure_search", "bedrock_kb", "chroma", "milvus", "mongodb", "openai", "opensearch",
             "pgvector", "pinecone", "qdrant", "redis", "vertex_ai", "weaviate"}
    stores = egress_support()["stores"]
    assert kinds <= set(stores)
    for kind, entry in stores.items():
        assert entry["store_side_models"] in (True, False, "unknown"), kind
        if entry["store_side_models"] is False:
            assert entry.get("not_supported_reason"), kind
        if entry["store_side_models"] is True:
            assert entry["sources"] and all(s.startswith("https://") for s in entry["sources"]), kind
