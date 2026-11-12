"""Vector-store inventory and inventory change tracking.

The inventory is evidence for NYDFS 500.13, CCPA 7123(c)(4) and Minnesota
325M.16, so it must not leak credentials, must not invent facts it did not
observe, must hash stably, and its CSV must be safe to open in a spreadsheet.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timedelta, timezone

import pytest

from vecshield.models import Collection, VectorStore
from vecshield_platform.drift import (
    diff_inventories,
    inventory_of,
    latest_inventory_pair,
    looks_like_copy,
)
from vecshield_platform.inventory import (
    CSV_COLUMNS,
    asset_inventory_outcome,
    build_inventory,
    inventory_hash,
    inventory_to_csv,
    inventory_to_json,
)
from vecshield_platform.scan.retention import observe_retention

NOW = datetime(2026, 9, 29, tzinfo=timezone.utc)


def store(*collections, endpoint="https://q.example.com:6333", name="prod-qdrant"):
    return VectorStore(kind="qdrant", name=name, endpoint=endpoint,
                       collections=list(collections))


def customers(count=100, dimension=384, model="all-minilm-l6-v2", metric="cosine"):
    return Collection("customers", count=count, dimension=dimension,
                      embedding_model=model, distance_metric=metric)


def inventory(*collections, **kwargs):
    kwargs.setdefault("store_id", "s1")
    kwargs.setdefault("now", NOW)
    return build_inventory(store(*collections), **kwargs)


# ----------------------------------------------------------------- building
def test_inventory_records_observed_facts_and_strips_credentials():
    retention = observe_retention([{"created_at": "2024-01-01"}, {"created_at": "2026-01-01"}],
                                  now=NOW)
    inv = build_inventory(
        store(customers(), endpoint="https://admin:hunter2@q.example.com?api_key=abc",
              name="postgresql://svc:pw@db/prod"),
        store_id="s1",
        server_info={"product": "qdrant", "version": "1.12.1", "managed": False,
                     "source": "GET /"},
        location={"provider": "aws", "region": "eu-west-1", "replica_regions": [],
                  "observable": True, "source": "cloud API"},
        aliases={"live": "customers"},
        classification_by_collection={"customers": {
            "label_counts": {"pii": 12, "pci": 2, "none": 80},
            "detector_counts": {"email": 12}, "chunks_scanned": 100}},
        subject_counts={"customers": 9},
        retention_by_collection={"customers": retention},
        biometric_by_collection={"customers": {"status": "none"}},
        egress={"integrations": [
            {"collection": None, "provider": "openai", "stage": "ingest"},
            {"collection": "customers", "provider": "cohere", "stage": "rerank"}]},
        now=NOW)
    text = json.dumps(inv)
    assert "hunter2" not in text and "abc" not in text and ":pw@" not in text
    s = inv["store"]
    assert (s["product"], s["version"], s["region"]) == ("qdrant", "1.12.1", "eu-west-1")
    assert s["aliases"] == {"live": "customers"}
    [c] = inv["collections"]
    assert c["sensitive_categories"] == {"pci": 2, "pii": 12}
    assert c["distance_metric"] == "cosine"
    assert c["distinct_subjects"] == 9
    assert c["retention"]["oldest"].startswith("2024-01-01")
    assert c["egress_providers"] == ["cohere", "openai"]
    assert c["aliased_by"] == ["live"]
    assert inv["totals"]["sensitive_collections"] == 1


def test_unobserved_facts_are_recorded_as_unobserved_not_empty():
    inv = inventory(customers())
    s = inv["store"]
    assert s["server_observed"] is False and s["version"] is None
    assert s["location_observed"] is False and s["region"] is None
    assert s["aliases_observed"] is False and s["aliases"] is None
    assert s["egress_observed"] is False
    c = inv["collections"][0]
    assert c["classified"] is False and c["distinct_subjects"] is None
    assert c["retention"]["observed"] is False


def test_manual_fields_are_present_and_marked_undeclared():
    inv = inventory(customers(), declarations={
        "store": {"owner": "Data Platform", "recovery_time_objective": "4h"},
        "collections": {"customers": {"business_purpose": "Support search"}}})
    declared = inv["store"]["declared"]
    assert declared["owner"] == {"value": "Data Platform", "declared": True}
    assert declared["support_expiration_date"] == {"value": None, "declared": False}
    assert set(declared) == {"owner", "business_purpose", "recovery_time_objective",
                             "support_contact", "support_expiration_date"}
    col = inv["collections"][0]["declared"]
    assert col["business_purpose"]["declared"] is True
    assert col["owner"]["declared"] is False
    ids = {r["id"] for r in inv["requirements"]}
    assert {"nydfs_23_nycrr_500_13_a", "ccpa_regs_7123_c_4",
            "minnesota_325m_16_subd_2_c"} == ids


def test_hash_is_stable_across_time_and_collection_order():
    a = build_inventory(store(customers(), Collection("zeta", count=1)),
                        store_id="s1", now=NOW)
    b = build_inventory(store(Collection("zeta", count=1), customers()),
                        store_id="s1", now=NOW + timedelta(days=30))
    assert a["inventory_hash"] == b["inventory_hash"]
    assert a["inventory_hash"] == inventory_hash(a)


def test_hash_ignores_ages_but_not_record_timestamps():
    old = observe_retention([{"created_at": "2024-01-01"}], now=NOW)
    later = observe_retention([{"created_at": "2024-01-01"}], now=NOW + timedelta(days=9))
    a = inventory(customers(), retention_by_collection={"customers": old})
    b = inventory(customers(), retention_by_collection={"customers": later})
    assert a["collections"][0]["retention"]["oldest_age_days"] != \
        b["collections"][0]["retention"]["oldest_age_days"]
    assert a["inventory_hash"] == b["inventory_hash"]
    moved = observe_retention([{"created_at": "2023-01-01"}], now=NOW)
    assert inventory(customers(), retention_by_collection={"customers": moved})[
        "inventory_hash"] != a["inventory_hash"]


def test_hash_changes_when_the_store_changes():
    assert inventory(customers())["inventory_hash"] != \
        inventory(customers(count=101))["inventory_hash"]


# ------------------------------------------------------------------ exports
def test_csv_has_one_row_per_collection_and_neutralises_formulas():
    evil = Collection("=HYPERLINK(\"http://x\",\"click\")", count=1)
    inv = inventory(customers(), evil, declarations={"store": {"owner": "@ops"}})
    rows = list(csv.reader(io.StringIO(inventory_to_csv([inv]))))
    assert tuple(rows[0]) == CSV_COLUMNS
    body = rows[1:]
    assert len(body) == 2
    by_name = {r[CSV_COLUMNS.index("collection")]: r for r in body}
    assert "'=HYPERLINK(\"http://x\",\"click\")" in by_name
    assert by_name["customers"][CSV_COLUMNS.index("store_owner")] == "'@ops"
    assert by_name["customers"][CSV_COLUMNS.index("count")] == "100"


def test_csv_keeps_a_row_for_a_store_with_no_collections():
    rows = list(csv.reader(io.StringIO(inventory_to_csv([inventory()]))))
    assert len(rows) == 2 and rows[1][CSV_COLUMNS.index("collection")] == ""


def test_json_export_carries_version_time_and_hash():
    inv = inventory(customers())
    doc = json.loads(inventory_to_json([inv], now=NOW))
    assert doc["generated_at"].startswith("2026-09-29")
    assert doc["vecshield_version"]
    assert doc["inventories"][0]["inventory_hash"] == inv["inventory_hash"]


def test_asset_inventory_outcome():
    passed = asset_inventory_outcome("prod", inventory(customers()))
    assert passed["check"] == "asset_inventory" and passed["outcome"] == "passed"
    assert passed["coverage"]["complete"] is True
    assert passed["coverage"]["collections"] == 1
    failed = asset_inventory_outcome("prod", None, reason="describe() timed out")
    assert failed["outcome"] == "error" and failed["coverage"]["complete"] is False


# -------------------------------------------------------------- change diff
@pytest.mark.parametrize("name,copy", [
    ("customers_backup", True), ("customers-copy", True), ("customers_v2", True),
    ("tmp_customers", True), ("customers_20250101", True), ("customers.old", True),
    ("customers_test", True), ("customers", False), ("contest_entries", False),
    ("templates", False), ("devices", False), ("latest_news", False),
    ("gold_members", False),
])
def test_copy_like_names(name, copy):
    assert looks_like_copy(name) is copy


def test_first_inventory_reports_a_sensitive_shadow_copy():
    backup = Collection("customers_backup", count=100, dimension=384)
    inv = inventory(customers(), backup, classification_by_collection={
        "customers_backup": {"label_counts": {"pii": 40}}})
    diff = diff_inventories(None, inv)
    assert diff["baseline"] is True
    [shadow] = diff["possible_shadow_copies"]
    assert shadow["possible_copy_of"] == "customers"
    assert shadow["severity"] == "high"
    assert diff["events"][0]["kind"] == "possible_shadow_copy"


def test_diff_reports_each_kind_of_change():
    before = inventory(
        customers(count=100),
        Collection("orders", count=10),
        aliases={"live": "customers"},
        classification_by_collection={"customers": {"label_counts": {"pii": 1}}},
        server_info={"product": "qdrant", "version": "1.11.0"},
        location={"provider": "aws", "region": "us-east-1", "observable": True})
    after = inventory(
        customers(count=5000, dimension=768, model="bge-base-en-v1.5"),
        Collection("orders_tmp", count=10),
        aliases={"live": "orders_tmp"},
        classification_by_collection={"customers": {"label_counts": {"pii": 1, "phi": 3}}},
        server_info={"product": "qdrant", "version": "1.12.1"},
        location={"provider": "aws", "region": "eu-west-1", "observable": True})
    diff = diff_inventories(before, after)
    assert diff["collections"] == {"added": ["orders_tmp"], "removed": ["orders"]}
    assert diff["possible_shadow_copies"][0]["possible_copy_of"] == "orders"
    assert diff["count_jumps"] == [{"collection": "customers", "before": 100,
                                    "after": 5000, "delta": 4900}]
    changes = diff["re_embedding"][0]["changes"]
    assert set(changes) == {"dimension", "embedding_model"}
    assert diff["aliases"]["repointed"] == [
        {"alias": "live", "before": "customers", "after": "orders_tmp"}]
    assert diff["new_sensitive_categories"] == [{"collection": "customers",
                                                 "categories": ["phi"]}]
    assert diff["server"]["version"] == {"before": "1.11.0", "after": "1.12.1"}
    assert diff["location"]["region"] == {"before": "us-east-1", "after": "eu-west-1"}
    assert diff["integrity_relevant"] is True
    severities = [e["severity"] for e in diff["events"]]
    assert severities == sorted(severities, key=lambda s: -{"high": 3, "medium": 2,
                                                            "low": 1, "info": 0}[s])


def test_small_count_changes_are_not_jumps_and_thresholds_are_configurable():
    before, after = inventory(customers(count=100)), inventory(customers(count=900))
    assert diff_inventories(before, after)["count_jumps"] == []
    assert diff_inventories(before, after, count_jump_min=500)["count_jumps"]
    big_b, big_a = inventory(customers(count=100_000)), inventory(customers(count=140_000))
    assert diff_inventories(big_b, big_a)["count_jumps"] == [], "40% is under 50%"


def test_unobserved_facts_are_not_changes():
    before = inventory(customers(), aliases={"live": "customers"},
                       location={"provider": "aws", "region": "us-east-1", "observable": True})
    after = inventory(customers())
    diff = diff_inventories(before, after)
    assert diff["aliases"]["repointed"] == [] and diff["location"] is None
    assert diff["server"] is None


def test_unclassified_before_does_not_report_new_categories():
    before = inventory(customers())
    after = inventory(customers(), classification_by_collection={
        "customers": {"label_counts": {"pii": 3}}})
    assert diff_inventories(before, after)["new_sensitive_categories"] == []


def test_identical_inventories_are_unchanged():
    diff = diff_inventories(inventory(customers()), inventory(customers()))
    assert diff["unchanged"] is True and diff["events"] == []


def test_inventories_of_different_stores_are_refused():
    with pytest.raises(ValueError):
        diff_inventories(inventory(customers(), store_id="a"),
                         inventory(customers(), store_id="b"))


class FakeHistory:
    def __init__(self, snapshots):
        self.snapshots = snapshots  # newest first

    def list_audits(self, *, store_id=None, limit=50):
        return [{"id": s["id"]} for s in self.snapshots
                if s["store_id"] == store_id][:limit]

    def get_audit(self, audit_id):
        return next(s for s in self.snapshots if s["id"] == audit_id)


def test_latest_inventory_pair_reads_scope_and_skips_audits_without_one():
    first, second = inventory(customers(count=1)), inventory(customers(count=2))
    history = FakeHistory([
        {"id": "a3", "store_id": "s1", "scope": {"inventory": second}},
        {"id": "a2", "store_id": "s1", "scope": {}},
        {"id": "a1", "store_id": "s1", "scope": {"inventory": first}},
    ])
    assert latest_inventory_pair(history, "s1") == (first, second)
    assert latest_inventory_pair(FakeHistory(history.snapshots[:2]), "s1") == (None, second)
    assert latest_inventory_pair(history, "other") == (None, None)
    assert inventory_of({"scope": {"inventory": "junk"}}) is None
