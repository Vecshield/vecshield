"""End to end: run_full_audit wires store facts, the declared store controls,
integrity inputs and the asset inventory together.

A fake connector answers every store fact itself (the connector-override route
of ``store_facts``), holds old personal data, a face-template collection and
chunks from a source the manifest marks deleted. Nothing touches a network:
the CVE lookup is offline and the endpoint has no network scheme.
"""

from __future__ import annotations

import json

import pytest

from vecshield.classify import RegexClassifier
from vecshield.models import Chunk, Collection, VectorStore
from vecshield_platform import store_facts as sf
from vecshield_platform.connectors.base import Connector
from vecshield_platform.history import ScanHistory
from vecshield_platform.orchestrator import AuditResult, run_full_audit
from vecshield_platform.remediation import catalogue, finding_kind
from vecshield_platform.scan.retention_schedule import ScheduleError, validate_schedule

SECRET = "sk-live-NEVER-IN-A-REPORT-0123456789abcdef"

SCHEDULE = validate_schedule({
    "rules": [{"category": "pii", "max_age_days": 365,
               "basis": "Records policy RP-7, section 4"}],
    "default_max_age_days": 3650, "default_basis": "Records policy RP-7"})
EU_ONLY = {"allowed_jurisdictions": ["EU"], "data_subject_regimes": ["GDPR"]}
REGISTER = [{"provider": "cohere", "dpa": True, "baa": False, "regions": ["eu"]}]
MANIFEST = [{"source": "legacy-crm", "deleted": True},
            {"source": "ehr", "version": "1"}]

NEW_CHECKS = {"retention_schedule", "biometric_templates", "model_egress",
              "data_residency", "server_vulnerability", "server_support_status",
              "asset_inventory", "corpus_duplication", "retrieval_hubness",
              "ingestion_burst", "chunk_versions"}


def _patients() -> list[Chunk]:
    chunks = []
    for i in range(12):
        source = "legacy-crm" if i < 3 else "ehr"
        chunks.append(Chunk(
            id=f"p{i}", collection="patients",
            text=(f"Patient record {i}: SSN 123-45-67{i:02d}, email person{i}@example.com"
                  if i % 2 == 0 else f"Visit summary {i} with routine follow-up notes."),
            metadata={"source": source, "ingested_at": f"2019-0{1 + i % 9}-15T10:00:00Z",
                      "doc_id": f"d{i}", "chunk_index": 0},
            embedding=[0.1 + i * 0.01, 0.2, 0.3 - i * 0.005, 0.05]))
    return chunks


def _faces() -> list[Chunk]:
    return [Chunk(id=f"f{i}", collection="faces", text="",
                  metadata={"face_id": f"person-{i % 4}", "image_path": f"img/{i}.jpg",
                            "bbox": [1, 2, 30, 40], "source": "camera",
                            "ingested_at": "2026-09-01T00:00:00Z"},
                  embedding=[0.5, 0.1 * (i % 3), 0.2, 0.3])
            for i in range(8)]


class ControlsConnector(Connector):
    kind = "fakestore"

    def __init__(self):
        self.data = {"patients": _patients(), "faces": _faces()}
        self.fact_calls: list[str] = []

    def describe(self):
        return VectorStore(kind=self.kind, name="fake-prod", endpoint="memory://fake",
                           collections=self.list_collections())

    def list_collections(self):
        return [Collection(name="patients", count=12, dimension=4),
                Collection(name="faces", count=8, dimension=512,
                           embedding_model="arcface_r100")]

    def iter_chunks(self, collection, batch_size=256):
        yield from self.data[collection]

    # --- store facts, answered by the connector itself -----------------
    def server_info(self):
        self.fact_calls.append("server_info")
        return {"product": "milvus", "version": "2.5.12", "edition": None,
                "managed": False, "source": "GetVersion", "reason": "",
                "features": {"metrics_port_reachable": True, "api_key": SECRET}}

    def store_location(self):
        self.fact_calls.append("store_location")
        return {"provider": "aws", "region": "us-east-1", "replica_regions": [],
                "source": "DescribeCluster", "observable": True, "reason": "",
                "evidence": {"token": SECRET}}

    def list_aliases(self):
        self.fact_calls.append("list_aliases")
        return {"live": "patients"}

    def model_integrations(self):
        self.fact_calls.append("model_integrations")
        return {"observable": True, "reason": "", "source": "schema", "controls": {},
                "integrations": [{"collection": "patients", "stage": "ingest",
                                  "provider": "openai", "model": "text-embedding-3-small",
                                  "endpoint_host": "api.openai.com", "auth": "api_key",
                                  "module": "embedding function",
                                  "evidence": {"authorization": f"Bearer {SECRET}",
                                               "api_key": SECRET}}]}


@pytest.fixture
def metrics(monkeypatch):
    """The fake kind has no store_facts adapter; supply its metric details."""
    monkeypatch.setattr(sf, "distance_metric_details",
                        lambda conn: {"patients": {"metric": "cosine"}})


def _audit(**overrides):
    conn = ControlsConnector()
    kwargs = dict(classifier=RegexClassifier(), cve_offline=True,
                  retention_schedule=SCHEDULE, residency_policy=EU_ONLY,
                  processor_register=REGISTER, source_manifest=MANIFEST,
                  store_id="store-1")
    kwargs.update(overrides)
    return conn, run_full_audit(conn, **kwargs)


def _by_check(result) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for outcome in result.all_check_outcomes():
        out.setdefault(outcome["check"], []).append(outcome)
    return out


def test_every_store_control_check_is_emitted_with_grounded_outcomes(metrics):
    conn, result = _audit()
    checks = _by_check(result)
    assert NEW_CHECKS <= set(checks), NEW_CHECKS - set(checks)

    # Facts are read once, before the posture checks consume them.
    assert sorted(conn.fact_calls) == sorted(sf.FACT_NAMES)

    retention = {o["collection"]: o for o in checks["retention_schedule"]}
    assert retention["patients"]["outcome"] == "failed"
    assert retention["patients"]["coverage"]["over_max"] > 0
    biometric = {o["collection"]: o for o in checks["biometric_templates"]}
    assert biometric["faces"]["coverage"]["biometric_status"] == "biometric_templates"
    assert biometric["patients"]["coverage"]["biometric_status"] == "none"

    assert checks["data_residency"][0]["outcome"] == "failed"      # us-east-1 vs EU only
    assert checks["server_vulnerability"][0]["outcome"] == "failed"  # milvus 2.5.12
    assert checks["server_support_status"][0]["outcome"] in (
        "passed", "failed", "inconclusive", "unsupported")
    egress = checks["model_egress"][0]
    flows = egress["coverage"]["flows"]
    assert [(f["collection"], f["provider"]) for f in flows] == [("patients", "openai")]
    assert "pii" in flows[0]["labels"]           # labels came from classification
    assert checks["asset_inventory"][0]["outcome"] == "passed"
    assert {o["outcome"] for o in checks["chunk_versions"]} & {"failed", "passed",
                                                               "inconclusive"}

    categories = {f.category for f in result.all_findings()}
    assert {"retention_schedule", "biometric_templates", "model_egress",
            "data_residency", "server_vulnerability"} <= categories
    deleted = [f for f in result.all_findings() if f.category == "chunk_versions"
               and "deleted sources" in f.title]
    assert deleted and deleted[0].collection == "patients"
    # One finding per advisory: finding ids are random, the advisory is not.
    advisories = [(f.evidence.get("advisory_id"), f.evidence.get("component"))
                  for f in result.all_findings() if f.evidence.get("advisory_id")]
    assert len(advisories) == len(set(advisories))


def test_scope_records_what_was_supplied_and_the_inventory(metrics):
    _, result = _audit()
    scope = result.scope
    controls = scope["store_controls"]
    assert controls["retention_schedule"] == {"supplied": True, "rules": 1,
                                              "default_max_age_days": True}
    assert controls["residency_policy"]["supplied"] is True
    assert controls["residency_policy"]["allowed_jurisdictions"] == 1
    assert controls["processor_register"] == {"supplied": True, "entries": 1}
    assert controls["source_manifest"] == {"supplied": True, "entries": 2}
    assert controls["vuln_feed"]["source"] in ("seed", "state")
    assert controls["vuln_feed"]["updated_at"]

    facts = scope["store_facts"]
    assert facts["gathered"] is True
    assert facts["server"]["product"] == "milvus"
    assert facts["location"]["region"] == "us-east-1"
    assert facts["aliases"] == {"count": 1}
    assert facts["distance_metrics"]["filled"] == ["patients"]

    inventory = scope["inventory"]
    assert inventory["store"]["id"] == "store-1"
    assert inventory["store"]["version"] == "2.5.12"
    assert inventory["store"]["aliases"] == {"live": "patients"}
    cols = {c["name"]: c for c in inventory["collections"]}
    assert cols["patients"]["distance_metric"] == "cosine"
    assert "pii" in cols["patients"]["sensitive_categories"]
    assert cols["patients"]["egress_providers"] == ["openai"]
    assert cols["faces"]["biometric"]["status"] == "biometric_templates"
    assert cols["patients"]["retention"]["observed"] is True

    classification = next(j for j in result.jobs
                          if j.stats.get("check") == "data_classification")
    # Ids were for the integrity pass; the saved record keeps counts only.
    assert "sensitive_chunk_ids" not in classification.stats
    assert "inventory_inputs" not in classification.stats
    assert classification.stats["sensitive_chunk_ids_recorded"]["patients"] > 0


def test_no_secret_reaches_the_serialised_result_or_history(metrics, tmp_path):
    _, result = _audit()
    data = result.to_dict()
    assert SECRET not in json.dumps(data, default=str)

    restored = AuditResult.from_dict(data)
    assert restored.scope["inventory"] == result.scope["inventory"]
    assert len(restored.all_check_outcomes()) == len(result.all_check_outcomes())

    history = ScanHistory(tmp_path / "h.db")
    history.save_audit(result, store_id="store-1")
    rows = history.list_audits(store_id="store-1")
    assert rows and "scope" not in rows[0]
    saved = history.get_audit(result.id)
    assert saved["scope"]["inventory"]["inventory_hash"] == \
        result.scope["inventory"]["inventory_hash"]
    assert SECRET not in json.dumps(saved, default=str)


def test_new_findings_have_catalogued_remediations(metrics):
    _, result = _audit()
    kinds = {}
    for finding in result.all_findings():
        record = finding.to_dict()
        kind = finding_kind(record)
        if finding.category in NEW_CHECKS:
            assert kind == finding.category, (finding.category, kind)
            kinds[kind] = catalogue(record, store_id="store-1", store_kind="milvus")
    assert {"retention_schedule", "biometric_templates", "model_egress",
            "data_residency", "server_vulnerability"} <= set(kinds)
    for kind, cat in kinds.items():
        assert cat.guided, kind
        assert all(g.check for g in cat.guided), kind
    upgrade = kinds["server_vulnerability"].guided[0]
    assert "2.5" in upgrade.title                   # the advisory's own fix version
    retention = kinds["retention_schedule"]
    assert [s.action for s in retention.suggestions][:1] == ["quarantine_chunks"]
    assert retention.suggestions[0].chunk_ids


def test_without_a_schedule_the_check_is_an_opt_in_skip(metrics):
    _, result = _audit(retention_schedule=None)
    rows = _by_check(result)["retention_schedule"]
    assert [(r["outcome"], r["coverage"].get("opt_in")) for r in rows] == [("skipped", True)]
    assert result.scope["store_controls"]["retention_schedule"]["supplied"] is False


def test_invalid_schedule_fails_before_the_store_is_read():
    conn = ControlsConnector()
    with pytest.raises(ScheduleError):
        run_full_audit(conn, classifier=RegexClassifier(), cve_offline=True,
                       retention_schedule={"rules": [{"category": "nope",
                                                      "max_age_days": 0}]})
    assert conn.fact_calls == []


def test_store_facts_can_be_excluded(metrics):
    conn, result = _audit(include_store_facts=False)
    checks = _by_check(result)
    for check in ("model_egress", "data_residency", "server_vulnerability",
                  "server_support_status"):
        assert [o["outcome"] for o in checks[check]] == ["skipped"], check
    assert conn.fact_calls == []
    assert result.scope["store_facts"] == {"gathered": False}
    inventory = result.scope["inventory"]
    assert inventory["store"]["server_observed"] is False
    assert inventory["store"]["location_observed"] is False


def test_parallel_integrity_shares_one_registry(metrics):
    _, result = _audit(max_workers=2)
    integrity = [o for o in result.all_check_outcomes() if o["check"] == "corpus_duplication"]
    assert {o["collection"] for o in integrity} == {"patients", "faces"}
