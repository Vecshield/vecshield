"""Data residency: region catalogue, adequacy, policy, model egress, DOJ thresholds.

The rules under test: a location is only ever what the provider reported,
mapped through the official region catalogue; an unobservable location is
never a failure; the US is never plainly adequate; 28 CFR Part 202 thresholds
are "more than", and the finding is informational.
"""

from __future__ import annotations

import pytest

from vecshield.models import Severity
from vecshield_platform.posture.residency import (
    CATEGORY,
    CHECK,
    assess_residency,
    bulk_status,
    country_of_concern,
    doj_categories_for,
    doj_subject_counts,
    jurisdictions_for,
    locate_integration,
    region_catalogue,
    resolve_region,
    transfer_status,
)


def loc(region, provider="aws", replicas=(), observable=True, **extra):
    return {"provider": provider, "region": region, "replica_regions": list(replicas),
            "source": "DescribeDomain", "observable": observable, "reason": "", "evidence": {},
            **extra}


EU_ONLY = {"allowed_jurisdictions": ["EU"], "data_subject_regimes": ["GDPR"]}


# ---- region catalogue ------------------------------------------------------------

@pytest.mark.parametrize("cloud,region,country", [
    ("aws", "us-east-1", "US"), ("aws", "eu-central-1", "DE"), ("aws", "eu-west-2", "GB"),
    ("aws", "ap-east-1", "HK"), ("aws", "eu-central-2", "CH"), ("aws", "me-central-1", "AE"),
    ("aws", "ap-southeast-6", "NZ"), ("aws", "mx-central-1", "MX"), ("aws", "sa-east-1", "BR"),
    ("gcp", "europe-west4", "NL"), ("gcp", "europe-west1", "BE"), ("gcp", "europe-west2", "GB"),
    ("gcp", "asia-east1", "TW"), ("gcp", "asia-east2", "HK"), ("gcp", "me-central2", "SA"),
    ("gcp", "northamerica-northeast1", "CA"), ("gcp", "us-central1", "US"),
    ("gcp", "southamerica-west1", "CL"), ("gcp", "europe-north2", "SE"),
    ("azure", "westeurope", "NL"), ("azure", "northeurope", "IE"), ("azure", "eastasia", "HK"),
    ("azure", "southeastasia", "SG"), ("azure", "uksouth", "GB"), ("azure", "swedencentral", "SE"),
    ("azure", "switzerlandnorth", "CH"), ("azure", "australiaeast", "AU"),
    ("azure", "West Europe", "NL"),  # display name normalises to the programmatic name
])
def test_region_country_mapping(cloud, region, country):
    assert resolve_region(cloud, region)["country"] == country


def test_region_counts_and_sovereign_partitions():
    clouds = region_catalogue()["clouds"]
    assert len(clouds["aws"]) == 39 and len(clouds["gcp"]) == 43 and len(clouds["azure"]) == 68
    assert resolve_region("aws", "cn-north-1")["sovereign"] == "china"
    assert resolve_region("aws", "us-gov-west-1")["sovereign"] == "us_government"
    eusc = resolve_region("aws", "eusc-de-east-1")
    assert eusc["sovereign"] == "eu_sovereign" and eusc["country"] == "DE"
    assert resolve_region("azure", "chinanorth3")["country"] == "CN"
    assert resolve_region("azure", "usgovvirginia")["sovereign"] == "us_government"


def test_every_catalogue_country_has_a_name_and_sources_are_cited():
    cat = region_catalogue()
    for cloud, regions in cat["clouds"].items():
        assert cat["_sources"][cloud], cloud
        for rid, rec in regions.items():
            assert len(rec["country"]) == 2 and rec["country"] in cat["countries"], rid


def test_unknown_region_is_not_guessed():
    assert resolve_region("aws", "xx-nowhere-9") is None
    assert resolve_region("zilliz", "us-east-1") is None  # no mapping, no cloud hint
    assert resolve_region("zilliz", "us-east-1", cloud="aws")["country"] == "US"
    assert resolve_region("pinecone", "eastus2")["cloud"] == "azure"
    assert resolve_region("pinecone", "europe-west4")["country"] == "NL"


def test_jurisdiction_tags():
    assert jurisdictions_for("DE") == ["DE", "EU", "EEA"]
    assert jurisdictions_for("NO") == ["NO", "EEA"]
    assert jurisdictions_for("GB") == ["GB", "UK"]
    assert jurisdictions_for("US") == ["US"]


# ---- adequacy ----------------------------------------------------------------------

def test_adequacy_logic():
    assert transfer_status("GDPR", "FR")["status"] == "within_area"
    assert transfer_status("GDPR", "NO")["status"] == "within_area"
    assert transfer_status("GDPR", "CH")["status"] == "adequate"
    assert transfer_status("GDPR", "GB")["status"] == "adequate"
    assert transfer_status("GDPR", "JP")["status"] == "adequate"
    assert transfer_status("GDPR", "CA")["status"] == "partial"
    assert transfer_status("GDPR", "IN")["status"] == "none"
    assert transfer_status("UK_GDPR", "GB")["status"] == "within_area"
    assert transfer_status("UK_GDPR", "DE")["status"] == "adequate"
    assert transfer_status("UK_GDPR", "JP")["status"] == "partial"
    assert transfer_status("UK_GDPR", "SG")["status"] == "none"
    assert transfer_status("PIPL", "US")["status"] == "not_evaluated"


def test_us_is_never_plainly_adequate():
    for regime in ("GDPR", "UK_GDPR"):
        st = transfer_status(regime, "US")
        assert st["status"] == "conditional_dpf"
        assert "certif" in st["scope"].lower()


# ---- the check -------------------------------------------------------------------

def test_inside_policy_passes():
    findings, outcome = assess_residency(loc("eu-central-1", replicas=["eu-west-1"]),
                                         policy=EU_ONLY, store="kb")
    assert findings == []
    assert outcome["check"] == CHECK and outcome["outcome"] == "passed"
    assert outcome["coverage"]["complete"] is True


def test_outside_policy_without_adequacy_is_high_and_asks_for_transfer_mechanism():
    findings, outcome = assess_residency(loc("ap-south-1"), policy=EU_ONLY, store="kb")
    assert outcome["outcome"] == "failed"
    f = findings[0]
    assert f.severity == Severity.HIGH and f.category == CATEGORY
    assert "transfer_mechanism" in f.evidence["evidence_to_supply"]
    assert f.evidence["country"] == "IN"


def test_outside_policy_to_us_is_medium_conditional():
    findings, outcome = assess_residency(loc("us-east-1"), policy=EU_ONLY, store="kb")
    assert outcome["outcome"] == "failed"
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].evidence["transfer_status"][0]["status"] == "conditional_dpf"
    assert "transfer_mechanism" in findings[0].evidence["evidence_to_supply"]


def test_outside_policy_to_adequate_country_is_medium_without_mechanism_ask():
    findings, _ = assess_residency(loc("eu-central-2"), policy=EU_ONLY, store="kb")  # Zurich
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].evidence["evidence_to_supply"] == []


def test_outside_policy_without_regimes_is_medium():
    findings, outcome = assess_residency(loc("ap-south-1"),
                                         policy={"allowed_countries": ["DE"]}, store="kb")
    assert outcome["outcome"] == "failed" and findings[0].severity == Severity.MEDIUM


def test_replica_outside_policy_fails():
    findings, outcome = assess_residency(
        loc("europe-west4", provider="gcp", replicas=["us-central1"]),
        policy={"allowed_jurisdictions": ["EEA"], "data_subject_regimes": ["GDPR"]}, store="kb")
    assert outcome["outcome"] == "failed"
    assert [f.evidence["role"] for f in findings] == ["replica"]


def test_allowed_regions_and_uk_alias():
    _, ok = assess_residency(loc("eu-west-2"), policy={"allowed_countries": ["UK"]}, store="kb")
    assert ok["outcome"] == "passed"
    _, ok = assess_residency(loc("westeurope", provider="azure"),
                             policy={"allowed_regions": ["azure:westeurope"]}, store="kb")
    assert ok["outcome"] == "passed"


def test_no_policy_is_inconclusive_but_reports_location():
    findings, outcome = assess_residency(loc("eu-central-1"), policy=None, store="kb")
    assert findings == []
    assert outcome["outcome"] == "inconclusive"
    assert "No residency policy declared" in outcome["reason"]
    assert outcome["coverage"]["locations"][0]["resolved"]["country"] == "DE"
    # The location was fully observed; the missing policy is an input, so the
    # run is not partial because of it.
    assert outcome["coverage"]["complete"] is True
    assert outcome["coverage"]["policy_missing"] is True


def test_region_not_in_catalogue_is_inconclusive():
    _, outcome = assess_residency(loc("xx-nowhere-9"), policy=EU_ONLY, store="kb")
    assert outcome["outcome"] == "inconclusive"


# ---- not observable: never failed, never guessed -------------------------------

def test_self_hosted_is_capability_limit():
    findings, outcome = assess_residency(
        {"provider": "self_hosted", "region": None, "replica_regions": [], "observable": False,
         "reason": "Self-hosted Qdrant does not report its location.", "source": "", "evidence": {}},
        policy=EU_ONLY, store="kb")
    assert findings == [] and outcome["outcome"] == "unsupported"
    assert outcome["coverage"]["capability_limit"] is True
    assert outcome["coverage"]["evidence_to_supply"] == ["data_residency_statement"]


def test_no_location_capability_is_unsupported():
    _, outcome = assess_residency(None, policy=EU_ONLY, store="kb")
    assert outcome["outcome"] == "unsupported"


def test_azure_without_arm_is_inconclusive_not_failed():
    findings, outcome = assess_residency(
        {"provider": "azure", "region": None, "replica_regions": [], "observable": False,
         "reason": "The data-plane key cannot read the service's ARM location.", "source": "",
         "evidence": {}}, policy=EU_ONLY, store="kb")
    assert findings == [] and outcome["outcome"] == "inconclusive"
    assert "IP" in outcome["reason"]
    assert outcome["coverage"]["evidence_to_supply"] == ["data_residency_statement"]


# ---- model egress destinations -------------------------------------------------

def test_egress_destination_location_rules():
    eu = locate_integration({"provider": "openai", "endpoint_host": "eu.api.openai.com"})
    assert eu["basis"] == "regional_endpoint" and eu["jurisdiction"] == "EU"
    default = locate_integration({"provider": "openai", "endpoint_host": "api.openai.com"})
    assert default["basis"] == "not_observable" and default["countries"] == []
    az = locate_integration({"provider": "azure_openai", "endpoint_host": "r.openai.azure.com",
                             "evidence": {"region": "swedencentral"}})
    assert az["basis"] == "reported_region" and az["country"] == "SE"
    az_global = locate_integration({"provider": "azure_openai", "evidence": {
        "region": "swedencentral", "deployment_type": "GlobalStandard"}})
    assert az_global["basis"] == "not_observable"
    az_zone = locate_integration({"provider": "azure_openai", "evidence": {
        "region": "swedencentral", "deployment_type": "DataZoneStandard"}})
    assert az_zone["basis"] == "data_zone" and az_zone["jurisdiction"] == "EU"
    br = locate_integration({"provider": "aws_bedrock", "model": "amazon.titan-embed-text-v2:0",
                             "endpoint_host": "bedrock-runtime.eu-west-3.amazonaws.com"})
    assert br["country"] == "FR"
    profile = locate_integration({"provider": "aws_bedrock",
                                  "model": "eu.anthropic.claude-sonnet-4-v1:0",
                                  "endpoint_host": "bedrock-runtime.eu-west-3.amazonaws.com"})
    assert profile["basis"] == "not_observable"
    vertex_regional = locate_integration({"provider": "google",
                                          "endpoint_host": "europe-west4-aiplatform.googleapis.com"})
    assert vertex_regional["basis"] == "not_observable"  # regional endpoints don't guarantee residency
    vertex_eu = locate_integration({"provider": "google",
                                    "endpoint_host": "aiplatform.eu.rep.googleapis.com"})
    assert vertex_eu["jurisdiction"] == "EU"


def test_egress_outside_policy_fails_and_unknown_egress_never_fails():
    integrations = [{"collection": "docs", "stage": "ingest", "provider": "openai",
                     "endpoint_host": "us.api.openai.com"}]
    findings, outcome = assess_residency(loc("eu-central-1"), policy=EU_ONLY,
                                         integrations=integrations, store="kb")
    assert outcome["outcome"] == "failed"
    assert findings[0].evidence["role"] == "model_egress"
    assert findings[0].severity == Severity.MEDIUM  # US: conditional DPF

    unknown = [{"collection": "docs", "stage": "ingest", "provider": "cohere"}]
    findings, outcome = assess_residency(loc("eu-central-1"), policy=EU_ONLY,
                                         integrations=unknown, store="kb")
    assert findings == [] and outcome["outcome"] == "inconclusive"
    assert outcome["coverage"]["not_observable_egress"] == 1


def test_eu_egress_against_country_only_policy_is_undetermined():
    integrations = [{"collection": "d", "provider": "openai", "endpoint_host": "eu.api.openai.com"}]
    findings, outcome = assess_residency(loc("eu-central-1"), policy={"allowed_countries": ["DE"]},
                                         integrations=integrations, store="kb")
    assert findings == [] and outcome["outcome"] == "inconclusive"


def test_eu_egress_inside_eu_policy_passes():
    integrations = [{"collection": "d", "provider": "openai", "endpoint_host": "eu.api.openai.com"}]
    _, outcome = assess_residency(loc("eu-central-1"), policy=EU_ONLY,
                                  integrations=integrations, store="kb")
    assert outcome["outcome"] == "passed"


# ---- DOJ Data Security Program ---------------------------------------------------

def test_doj_thresholds_are_strictly_more_than():
    bulk = bulk_status({"human_genomic": 100, "personal_health_data": 10001,
                        "covered_personal_identifiers": 100000})
    assert bulk["human_genomic"]["reached"] is False
    assert bulk["personal_health_data"]["reached"] is True
    assert bulk["covered_personal_identifiers"]["reached"] is False
    assert bulk["biometric_identifiers"]["evaluated"] is False
    assert bulk["human_omic_other"]["reached"] is None
    expected = {"human_genomic": 100, "human_omic_other": 1000, "biometric_identifiers": 1000,
                "precise_geolocation": 1000, "personal_health_data": 10000,
                "personal_financial_data": 10000, "covered_personal_identifiers": 100000}
    assert {k: v["more_than"] for k, v in bulk.items()} == expected


def test_doj_detector_mapping_is_conservative():
    assert doj_categories_for(["genetic_rsid"]) == {"human_genomic"}
    assert doj_categories_for(["icd_code_context"]) == {"personal_health_data"}
    assert doj_categories_for(["npi_context"]) == set()  # a provider id, not health data
    assert doj_categories_for(["biometric_reference"]) == set()
    # Demographic/contact linked only to demographic/contact is excluded (202.212(b)(1)).
    assert doj_categories_for(["email", "us_phone"]) == set()
    # Government id + contact data is a covered personal identifier.
    assert doj_categories_for(["us_ssn", "email"]) == {"covered_personal_identifiers"}
    # A lone listed identifier is not (202.212(c)(1)).
    assert doj_categories_for(["us_ssn"]) == set()
    # Network id linked only to authentication data is excluded (202.212(b)(2)).
    assert doj_categories_for(["ipv4_address", "username_handle"]) == set()
    # A listed identifier linked to health data is covered too.
    assert doj_categories_for(["email", "icd_code_context"]) == {
        "personal_health_data", "covered_personal_identifiers"}


def test_doj_subject_counts_are_distinct():
    rows = [("s1", ["icd_code_context"]), ("s1", ["icd_code_context"]),
            ("s2", ["icd_code_context", "email"]), ("", ["icd_code_context"])]
    assert doj_subject_counts(rows) == {"personal_health_data": 2,
                                        "covered_personal_identifiers": 1}


def test_countries_of_concern_include_hong_kong_and_macau():
    for code in ("CN", "HK", "MO", "CU", "IR", "KP", "RU", "VE"):
        assert country_of_concern(code)
    assert country_of_concern("TW") is None and country_of_concern("SG") is None


def test_doj_finding_low_by_default_medium_in_country_of_concern():
    counts = {"personal_health_data": 20000}
    findings, outcome = assess_residency(loc("eu-central-1"), policy=EU_ONLY,
                                         subject_counts=counts, store="kb")
    f = [x for x in findings if "28 CFR Part 202" in x.title][0]
    assert f.severity == Severity.LOW
    assert "cannot see who has access" in f.description
    assert outcome["outcome"] == "passed"  # informational: not a residency failure

    findings, _ = assess_residency(loc("ap-east-1"), policy={"allowed_countries": ["HK"]},
                                   subject_counts=counts, store="kb")
    f = [x for x in findings if "28 CFR Part 202" in x.title][0]
    assert f.severity == Severity.MEDIUM
    assert f.evidence["countries_of_concern"][0]["country"] == "HK"


def test_no_subject_counts_means_doj_not_evaluated():
    findings, outcome = assess_residency(loc("eu-central-1"), policy=EU_ONLY, store="kb")
    assert outcome["coverage"]["doj_bulk"] is None and findings == []
