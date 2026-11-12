"""Unified audit orchestration.

Runs every applicable VecShield scan against a store in one call and evaluates
policies over the combined findings:

  store facts          (once, first: server version, location, aliases, model
                        integrations and distance metrics, via store_facts;
                        a fact that cannot be read is recorded, never fatal)
  data classification  (always; also the declared retention schedule and
                        biometric-template verdicts, on the same read)
  RAG integrity        (per collection, with the classification's sensitive
                        chunk ids and one cross-collection registry)
  tenant isolation     (per collection, when a tenant field is given and the
                        connector supports query())
  configuration posture (incl. model egress, data residency and server
                        advisories, fed by the store facts and classification)
  asset inventory      (last, assembled from everything above)

Returns an AuditResult that aggregates the per-scan ScanJobs plus policy
violations — the single object the API, CLI, and report generator consume.
"""

from __future__ import annotations

import threading
import uuid
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from vecshield_platform.access import probe_isolation
from vecshield_platform.access.isolation import IsolationLimits
from vecshield.classify import Classifier
from vecshield_platform.compliance.fingerprint import apply_fingerprints
from vecshield_platform.compliance.policy import Policy, PolicyViolation, default_policies, evaluate_policies
from vecshield_platform.compliance.training_policy import training_policies
from vecshield_platform.connectors.base import (
    Connector,
    UnsupportedCapability,
    fill_declared_embedding_model,
)
from vecshield_platform.coverage import (
    check_outcome, job_outcomes, set_job_coverage, summarize_coverage,
)
from vecshield_platform.integrity import scan_integrity
from vecshield_platform.detection import build_classifier
from vecshield.models import Finding, ScanJob, Severity
from vecshield_platform.progress import (
    CLASSIFYING,
    CONFIGURATION,
    INTEGRITY,
    ISOLATION,
    READING_STORE,
    RETRIEVAL,
    audit_phases,
    bind as bind_progress,
    current as current_progress,
    finish_phase,
    publish_plan_if_empty,
    reset as reset_progress,
    start_closing_if_planned,
    start_phase,
    tick,
)
from vecshield_platform.scan import scan_store


@dataclass
class AuditResult:
    id: str
    store: str
    jobs: list[ScanJob] = field(default_factory=list)
    violations: list[PolicyViolation] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""
    alerts_dispatched: int = 0
    scope: dict = field(default_factory=dict)
    schema_version: int = 1
    check_outcomes: list[dict] = field(default_factory=list)

    def all_check_outcomes(self) -> list[dict]:
        return [*deepcopy(self.check_outcomes),
                *(outcome for job in self.jobs for outcome in job_outcomes(job))]

    @property
    def coverage(self) -> dict:
        return summarize_coverage(self.all_check_outcomes())

    @property
    def status(self) -> str:
        if not self.finished_at:
            return "running"
        return "completed" if self.coverage["complete"] else "partial"

    def all_findings(self) -> list[Finding]:
        out: list[Finding] = []
        for j in self.jobs:
            out.extend(j.findings)
        return out

    @property
    def max_severity(self) -> Severity:
        findings = self.all_findings()
        if not findings:
            return Severity.INFO
        return max((f.severity for f in findings), key=lambda s: s.rank)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "store": self.store,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "max_severity": self.max_severity.value,
            "summary": self.severity_summary(),
            "suppressed": self.suppressed_count(),
            "jobs": [j.to_dict() for j in self.jobs],
            "violations": [v.to_dict() for v in self.violations],
            "alerts_dispatched": self.alerts_dispatched,
            "schema_version": self.schema_version,
            "scope": deepcopy(self.scope),
            "status": self.status,
            "coverage": self.coverage,
            "check_outcomes": self.all_check_outcomes(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AuditResult":
        """Hydrate a saved snapshot without connecting to or scanning a store."""
        jobs = []
        for raw in data.get("jobs", []):
            job = ScanJob(id=raw["id"], store=raw["store"],
                          stats=deepcopy(raw.get("stats", {})))
            if raw.get("started_at"):
                job.started_at = datetime.fromisoformat(raw["started_at"])
            if raw.get("finished_at"):
                job.finished_at = datetime.fromisoformat(raw["finished_at"])
            for value in raw.get("findings", []):
                finding = Finding(
                    id=value["id"], title=value["title"], severity=Severity(value["severity"]),
                    category=value["category"], store=value["store"],
                    collection=value.get("collection"), description=value.get("description", ""),
                    evidence=deepcopy(value.get("evidence", {})),
                    remediation=value.get("remediation", ""))
                if value.get("created_at"):
                    finding.created_at = datetime.fromisoformat(value["created_at"])
                job.add(finding)
            jobs.append(job)
        violations = [PolicyViolation(**{**value, "severity": Severity(value["severity"])})
                      for value in data.get("violations", [])]
        # Serialized outcomes include job outcomes; retain only the audit-level
        # records here so a round trip cannot double-count checks.
        extras = deepcopy(data.get("check_outcomes", []))
        for job in jobs:
            for outcome in job_outcomes(job):
                if outcome in extras:
                    extras.remove(outcome)
        return cls(id=data["id"], store=data["store"], jobs=jobs, violations=violations,
                   started_at=data.get("started_at", ""),
                   finished_at=data.get("finished_at", ""),
                   alerts_dispatched=data.get("alerts_dispatched", 0),
                   scope=deepcopy(data.get("scope", {})),
                   schema_version=data.get("schema_version", 0), check_outcomes=extras)

    def severity_summary(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.all_findings():
            counts[f.severity.value] += 1
        return counts

    def suppressed_count(self) -> int:
        """Number of findings tagged as allow-listed / suppressed."""
        return sum(1 for f in self.all_findings()
                   if (f.evidence or {}).get("suppressed"))


def run_full_audit(
    connector: Connector,
    *,
    classifier: Optional[Classifier] = None,
    policies: Optional[list[Policy]] = None,
    tenant_field: Optional[str] = None,
    include_integrity: bool = True,
    max_chunks_per_collection: Optional[int] = None,
    datasource=None,
    include_posture: bool = True,
    cve_offline: bool = False,
    include_crypto: bool = True,
    tls_probe: bool = False,
    retrieval_probe: bool = False,
    isolation_query_budget: Optional[int] = None,
    sinks: Optional[list] = None,
    alert_min_severity: Severity = Severity.HIGH,
    max_workers: int = 1,
    suppressor: Optional[Callable[[list[Finding]], list[Finding]]] = None,
    retention_schedule: Any = None,
    residency_policy: Optional[dict] = None,
    processor_register: Optional[list[dict]] = None,
    vuln_feed_dir: Optional[str] = None,
    source_manifest: Optional[list[dict]] = None,
    include_store_facts: bool = True,
    store_id: Optional[str] = None,
    inventory_declarations: Optional[dict] = None,
) -> AuditResult:
    """Run every applicable check against ``connector`` and evaluate policies.

    Store controls (all optional; each is recorded in ``scope`` only as
    supplied-or-not and counts, never its contents):

    ``retention_schedule``
        The declared schedule for this store (``RetentionSchedule`` or its
        mapping form). An invalid one raises ``ScheduleError`` before the
        store is read: a schedule that is silently not evaluated is worse
        than a run that does not start.
    ``residency_policy``
        This store's resolved policy: ``{allowed_regions, allowed_countries,
        allowed_jurisdictions, data_subject_regimes}``.
    ``processor_register``
        The declared sub-processors: ``[{provider, dpa, baa, regions, notes}]``.
    ``vuln_feed_dir``
        State directory holding ``vulnfeed/``; None uses the bundled seed.
    ``source_manifest``
        ``[{source, version|hash|updated_at, deleted}]`` for chunk_versions.
    ``include_store_facts``
        Read the store's own facts (server, location, aliases, model
        integrations, distance metrics). False skips them and the checks that
        rest on them (model_egress, data_residency, server_vulnerability,
        server_support_status, server_hardening), recorded as skipped.
    ``store_id`` / ``inventory_declarations``
        The registered store id and the owner/purpose/RTO facts a person
        declared, both carried into the asset inventory.
    """
    from vecshield_platform import store_facts as facts_api
    from vecshield_platform.scan.retention_schedule import validate_schedule

    schedule = validate_schedule(retention_schedule)
    classifier = classifier or build_classifier()
    store = connector.describe()
    fill_declared_embedding_model(connector, store.collections)
    result = AuditResult(
        id=f"audit-{uuid.uuid4().hex[:12]}",
        store=store.name,
        started_at=datetime.now(timezone.utc).isoformat(),
        scope={"collections": [c.name for c in store.collections],
               "tenant_field": tenant_field, "include_integrity": include_integrity,
               "include_posture": include_posture, "cve_offline": cve_offline,
               "include_crypto": include_crypto, "tls_probe": tls_probe,
               "retrieval_probe": retrieval_probe,
               "max_chunks_per_collection": max_chunks_per_collection},
    )
    # The isolation sweep's budget is configuration (env, overridable per run);
    # the scope records the value this run used.
    isolation_limits = IsolationLimits.from_env()
    if isolation_query_budget is not None:
        isolation_limits = IsolationLimits(query_budget=max(0, int(isolation_query_budget)),
                                           sweep_margin=isolation_limits.sweep_margin)
    result.scope["isolation_query_budget"] = isolation_limits.query_budget
    if hasattr(classifier, "detection_metadata"):
        result.scope["detection"] = classifier.detection_metadata()
    extra_policies: list[Policy] = []
    publish_plan_if_empty(audit_phases(
        include_integrity=include_integrity, tenant_field=tenant_field,
        include_posture=include_posture, retrieval_probe=retrieval_probe,
        include_crypto=include_crypto))
    start_phase(READING_STORE)

    # Store facts, read once. Every fact is wrapped by store_facts.gather: an
    # unsupported, refused or failing read is recorded and the audit goes on.
    # The facts stay in this local object; the scope carries a summary only.
    facts: Optional[facts_api.GatheredFacts] = None
    result.scope["include_store_facts"] = include_store_facts
    if include_store_facts:
        facts = facts_api.gather(connector)
        # Integrity and isolation read Collection.distance_metric; fill it
        # where the connector's own describe() left it None.
        metrics = facts_api.fill_distance_metrics(connector, store.collections)
        result.scope["store_facts"] = {**facts_api.summarize(facts),
                                       "distance_metrics": metrics}
    else:
        result.scope["store_facts"] = facts_api.summarize(None)
    vuln_feed = None
    if include_posture and include_store_facts:
        vuln_feed = _load_vuln_feed(vuln_feed_dir)
    result.scope["store_controls"] = _store_controls_scope(
        schedule=schedule, residency_policy=residency_policy,
        processor_register=processor_register, source_manifest=source_manifest,
        vuln_feed=vuln_feed)

    # 0. (optional) upstream training-data scan + chunk-boundary check
    if datasource is not None:
        from vecshield.datascan import scan_datasource

        ds_job = _run_check(result.store, "training_data_classification", None,
                           lambda: scan_datasource(
                               datasource, classifier=classifier,
                               max_records_per_dataset=max_chunks_per_collection))
        result.jobs.append(ds_job)
        extra_policies = training_policies()

        # boundary check over each dataset's records, as an ingest pre-flight
        boundary_job = _run_check(result.store, "chunk_boundary", None,
                                 lambda: _boundary_job(datasource, classifier,
                                                       max_chunks_per_collection))
        result.jobs.append(boundary_job)

    finish_phase(READING_STORE)

    # 1. data classification (walks all collections internally). Cryptographic
    # representation analysis rides the same pass as an observer, so the store
    # is read once; its outcomes become their own job.
    representation = None
    if include_crypto:
        from vecshield_platform.crypto.representation import RepresentationObserver

        representation = RepresentationObserver(collections=store.collections)
    start_phase(CLASSIFYING)
    classification_job = _run_check(
        result.store, "data_classification", None,
        lambda: scan_store(connector, classifier=classifier,
                           max_chunks_per_collection=max_chunks_per_collection,
                           observer=representation, retention_schedule=schedule))
    result.jobs.append(classification_job)
    finish_phase(CLASSIFYING)
    if representation is not None:
        result.jobs.append(_run_check(
            result.store, "data_representation", None,
            lambda: representation.job(result.store,
                                       classification=classification_job)))
        extra_policies = extra_policies + _representation_policies()
    else:
        for check in ("data_representation", "pan_representation",
                      "direct_identifier_exposure"):
            result.check_outcomes.append(check_outcome(
                check, result.store, outcome="skipped", crypto_state="not_verified",
                reason="Cryptographic posture was excluded by the run configuration."))

    collections = [c.name for c in store.collections]
    collection_meta = {c.name: c for c in store.collections}
    sensitive_ids = classification_job.stats.get("sensitive_chunk_ids") or {}

    # 2. RAG integrity, per collection. One registry is shared so a sensitive
    # chunk copied into another collection is found; it is lock-protected, so
    # a parallel run is safe, though which copy is reported as "the other"
    # then follows completion order rather than collection order.
    if include_integrity:
        from vecshield_platform.integrity.duplication import SensitiveFingerprintRegistry

        registry = SensitiveFingerprintRegistry()

        def _integrity(col: str) -> ScanJob:
            return _run_check(result.store, "rag_integrity", col,
                              lambda: scan_integrity(
                                  connector, col,
                                  max_chunks=max_chunks_per_collection
                                  if max_chunks_per_collection is not None else 50000,
                                  collection_meta=collection_meta.get(col),
                                  sensitive_ids=sensitive_ids.get(col) or (),
                                  sensitive_registry=registry,
                                  source_manifest=source_manifest))
        start_phase(INTEGRITY)
        result.jobs.extend(_map_collections(_integrity, collections, max_workers))
        finish_phase(INTEGRITY)
    else:
        result.check_outcomes.append(check_outcome(
            "rag_integrity", result.store, outcome="skipped",
            reason="Integrity scanning was excluded by the run configuration."))

    # 3. tenant isolation, per collection (only if we can query + have a field)
    if tenant_field:
        def _isolation(col: str) -> ScanJob:
            # The engine records its own structured outcome. The fallback only
            # covers a replacement that returns a job without one; it never
            # reads an absence of findings as a pass.
            job = _run_check(result.store, "tenant_isolation", col,
                             lambda: probe_isolation(
                                 connector, col, tenant_field=tenant_field,
                                 max_chunks=max_chunks_per_collection,
                                 limits=isolation_limits))
            if "check_outcomes" not in job.stats:
                detected = any(f.category == "isolation" and f.severity.rank >= Severity.HIGH.rank
                               for f in job.findings)
                set_job_coverage(job, [check_outcome(
                    "tenant_isolation", result.store, col,
                    outcome="failed" if detected else "inconclusive",
                    reason="The isolation check returned no structured outcome.",
                    chunks_scanned=job.stats.get("chunks_examined", 0))])
            return job
        start_phase(ISOLATION)
        result.jobs.extend(_map_collections(_isolation, collections, max_workers))
        finish_phase(ISOLATION)
    else:
        result.check_outcomes.append(check_outcome(
            "tenant_isolation", result.store, outcome="skipped",
            reason="No tenant field was configured."))

    # The ids were for the integrity pass; the saved record keeps counts only.
    _drop_sensitive_ids(classification_job)
    inventory_inputs = classification_job.stats.pop("inventory_inputs", None) or {}

    # 4. configuration posture: network exposure, TLS, at-rest encryption, CVEs,
    # and the store controls that rest on the facts gathered above.
    posture_job: Optional[ScanJob] = None
    if include_posture:
        from vecshield_platform.posture import posture_policies, run_posture_audit

        labels = _sensitive_labels(classification_job, inventory_inputs)
        start_phase(CONFIGURATION)
        posture_job = _run_check(result.store, "configuration_posture", None,
                                 lambda: run_posture_audit(
                                     connector, cve_offline=cve_offline, tls_probe=tls_probe,
                                     store_controls=include_store_facts, facts=facts,
                                     sensitive_labels_by_collection=labels,
                                     residency_policy=residency_policy,
                                     processor_register=processor_register,
                                     vuln_feed=vuln_feed))
        finish_phase(CONFIGURATION)
        result.jobs.append(posture_job)
        extra_policies = extra_policies + posture_policies()
        if not include_store_facts:
            _skip_store_controls(result, "Store facts were excluded by the run "
                                         "configuration.")
    else:
        result.check_outcomes.append(check_outcome(
            "configuration_posture", result.store, outcome="skipped",
            reason="Posture scanning was excluded by the run configuration."))
        _skip_store_controls(result, "Posture scanning was excluded by the run "
                                     "configuration.")

    # 5. retrieval exposure: an active probe, so opt-in (docs/crypto_posture.md)
    if retrieval_probe and include_crypto:
        from vecshield_platform.crypto.retrieval import probe_retrieval_exposure

        def _retrieval(col: str) -> ScanJob:
            return _run_check(result.store, "retrieval_exposure", col,
                              lambda: probe_retrieval_exposure(
                                  connector, col, classifier=classifier,
                                  **({"max_chunks": max_chunks_per_collection}
                                     if max_chunks_per_collection is not None else {})))
        start_phase(RETRIEVAL)
        result.jobs.extend(_map_collections(_retrieval, collections, max_workers))
        finish_phase(RETRIEVAL)
    else:
        result.check_outcomes.append(check_outcome(
            "retrieval_exposure", result.store, outcome="skipped",
            reason="The retrieval probe is an active check and was not requested.",
            crypto_state="not_verified", opt_in=True))

    # 6. asset inventory, from what the run observed. Never fatal.
    _record_inventory(result, store, facts=facts, inputs=inventory_inputs,
                      posture_job=posture_job, store_id=store_id,
                      declarations=inventory_declarations)

    # Stamp a stable fingerprint on every finding (posture/isolation jobs are
    # produced outside scan_store/scan_integrity, which already stamp their own).
    start_closing_if_planned()
    apply_fingerprints(result.all_findings())

    # False-positive management (improvement plan 1.12): tag allow-listed /
    # suppressed findings in place, then evaluate policies over only the active
    # ones so suppressed findings never produce violations or alerts — while
    # remaining fully present (and tagged) in result.jobs for the record.
    findings = result.all_findings()
    active = suppressor(findings) if suppressor is not None else findings

    effective_policies = (policies if policies is not None else default_policies()) + extra_policies
    result.scope["policies"] = [
        {"id": policy.id, "description": policy.description,
         "when": deepcopy(policy.when), "action": policy.action,
         "severity": policy.severity.value} for policy in effective_policies]
    result.violations = evaluate_policies(effective_policies, active)
    result.finished_at = datetime.now(timezone.utc).isoformat()
    if sinks:
        result.alerts_dispatched = dispatch_alerts(
            result, sinks, min_severity=alert_min_severity)
    return result


def _load_vuln_feed(state_dir: Optional[str]):
    """The advisory feed; a feed that cannot load is the empty feed, not a crash."""
    from vecshield_platform.posture.vulnfeed import Feed, load_feed

    try:
        return load_feed(state_dir)
    except Exception as exc:  # noqa: BLE001
        return Feed({}, origin="none",
                    error=f"the advisory feed could not be loaded ({type(exc).__name__})")


def _store_controls_scope(*, schedule: Any, residency_policy: Optional[dict],
                          processor_register: Optional[list[dict]],
                          source_manifest: Optional[list[dict]],
                          vuln_feed: Any) -> dict:
    """What the run was given: flags and counts only, never contents."""
    policy = residency_policy if isinstance(residency_policy, dict) else {}

    def count(key: str) -> int:
        value = policy.get(key)
        return len(value) if isinstance(value, (list, tuple, set)) else 0

    scope: dict[str, Any] = {
        "retention_schedule": {
            "supplied": schedule is not None,
            "rules": len(schedule.rules) if schedule is not None else 0,
            "default_max_age_days": (schedule.default_max_age_days is not None
                                     if schedule is not None else False)},
        "residency_policy": {
            "supplied": bool(policy),
            **{key: count(key) for key in ("allowed_regions", "allowed_countries",
                                           "allowed_jurisdictions",
                                           "data_subject_regimes")}},
        "processor_register": {"supplied": processor_register is not None,
                               "entries": len(processor_register or [])},
        "source_manifest": {"supplied": source_manifest is not None,
                            "entries": len(source_manifest or [])},
        "vuln_feed": None,
    }
    if vuln_feed is not None:
        try:
            age = vuln_feed.age_days()
        except Exception:  # noqa: BLE001
            age = None
        scope["vuln_feed"] = {"source": vuln_feed.origin,
                              "updated_at": (vuln_feed.raw or {}).get("updated_at"),
                              "age_days": round(age, 2) if isinstance(age, float) else age,
                              "error": vuln_feed.error or None}
    return scope


def _skip_store_controls(result: "AuditResult", reason: str) -> None:
    from vecshield_platform.posture import STORE_CONTROL_CHECKS

    for check in STORE_CONTROL_CHECKS:
        result.check_outcomes.append(check_outcome(check, result.store, outcome="skipped",
                                                   reason=reason))


def _drop_sensitive_ids(job: ScanJob) -> None:
    ids = job.stats.pop("sensitive_chunk_ids", None)
    if isinstance(ids, dict):
        job.stats["sensitive_chunk_ids_recorded"] = {col: len(v) for col, v in ids.items()}


def _sensitive_labels(classification_job: ScanJob,
                      inventory_inputs: dict) -> dict[str, dict[str, int]]:
    """``{collection: {label: chunks}}`` for every collection the scan settled.

    A collection read completely with nothing found maps to ``{}`` (clean).
    One read only in part maps to what was found, or is left out when nothing
    was, so model egress reports its labels as unknown rather than clean.
    """
    labels: dict[str, dict[str, int]] = {}
    for name, entry in (inventory_inputs.get("classification") or {}).items():
        counts = {str(k): int(v) for k, v in (entry.get("label_counts") or {}).items()
                  if str(k) != "none" and int(v or 0) > 0}
        if counts or entry.get("complete"):
            labels[name] = counts
    for finding in classification_job.findings:
        if finding.category == "data_classification" and finding.collection:
            found = (finding.evidence or {}).get("label_counts") or {}
            merged = labels.setdefault(finding.collection, {})
            for label, n in found.items():
                merged[str(label)] = max(int(n or 0), merged.get(str(label), 0))
    return labels


def _egress_for_inventory(posture_job: Optional[ScanJob], facts: Any) -> Optional[list[dict]]:
    """Provider flows per collection, or None when egress was not observed."""
    if posture_job is not None:
        for outcome in posture_job.stats.get("check_outcomes") or []:
            if outcome.get("check") == "model_egress":
                flows = (outcome.get("coverage") or {}).get("flows")
                if outcome.get("outcome") in ("passed", "failed") and isinstance(flows, list):
                    return [{"provider": f.get("provider"), "collection": f.get("collection")}
                            for f in flows if isinstance(f, dict)]
    report = facts.get("model_integrations") if facts is not None else None
    if isinstance(report, dict) and report.get("observable") is True:
        return [{"provider": i.get("provider"), "collection": i.get("collection")}
                for i in report.get("integrations") or [] if isinstance(i, dict)]
    return None


def _record_inventory(result: "AuditResult", store: Any, *, facts: Any, inputs: dict,
                      posture_job: Optional[ScanJob], store_id: Optional[str],
                      declarations: Optional[dict]) -> None:
    from vecshield_platform.inventory import asset_inventory_outcome, build_inventory

    def fact(name: str) -> Any:
        value = facts.get(name) if facts is not None else None
        return value if isinstance(value, dict) else None

    try:
        inventory = build_inventory(
            store, store_id=store_id, server_info=fact("server_info"),
            location=fact("store_location"), aliases=fact("list_aliases"),
            classification_by_collection=inputs.get("classification") or {},
            subject_counts=None,
            retention_by_collection=inputs.get("retention") or {},
            biometric_by_collection=inputs.get("biometric") or {},
            egress=_egress_for_inventory(posture_job, facts),
            declarations=declarations)
    except Exception as exc:  # noqa: BLE001 - the inventory never costs the audit
        result.check_outcomes.append(asset_inventory_outcome(
            result.store, None,
            reason=f"The inventory could not be assembled ({type(exc).__name__})."))
        return
    result.scope["inventory"] = inventory
    result.check_outcomes.append(asset_inventory_outcome(result.store, inventory))


def _representation_policies() -> list[Policy]:
    from vecshield_platform.crypto.representation import representation_policies

    return representation_policies()


def _run_check(store: str, check: str, collection: str | None, fn) -> ScanJob:
    """Turn a failed check into evidence while preserving sibling scan results."""
    try:
        job = fn()
        job.stats.setdefault("check", check)
        return job
    except Exception as exc:
        outcome = "unsupported" if isinstance(exc, UnsupportedCapability) else "error"
        # Exception strings may contain credential-bearing URLs or source text.
        reason = f"The check could not complete ({type(exc).__name__})."
        job = ScanJob(id=f"check-{uuid.uuid4().hex[:12]}", store=store)
        job.stats = {"check": check, "collection": collection}
        set_job_coverage(job, [check_outcome(
            check, store, collection, outcome=outcome, reason=reason)])
        job.add(Finding(
            id=f"find-{uuid.uuid4().hex[:10]}", title=f"{check} could not complete",
            severity=Severity.MEDIUM, category="coverage", store=store,
            collection=collection, description=reason,
            remediation="Resolve the check failure and run a new assessment.",
            evidence={"check": check, "outcome": outcome,
                      "error_type": type(exc).__name__}))
        job.finished_at = datetime.now(timezone.utc)
        return job


def _map_collections(fn, collections: list[str], max_workers: int) -> list:
    """Apply ``fn`` to each collection, optionally with a bounded thread pool.

    With ``max_workers <= 1`` (the default) this is a plain serial map, so
    behavior and ordering are unchanged. With ``max_workers > 1`` the per-
    collection scans run concurrently on a bounded pool and results are returned
    in the original collection order.

    Note: concurrent scanning shares one connector across threads. Only enable
    ``max_workers > 1`` with a thread-safe connector; the safe default is serial.
    Progress context is copied into each worker so chunk ticks still land on
    the job that started this audit.
    """
    if not collections:
        return []
    reporter = current_progress()
    total = len(collections)

    def _call(col: str, *, index: int | None = None,
              in_flight: list[str] | None = None):
        token = bind_progress(reporter)
        try:
            if in_flight is not None:
                tick(collections_in_flight=in_flight, collection_count=total)
            elif index is not None:
                tick(collection=col, collection_index=index, collection_count=total)
            return fn(col)
        finally:
            reset_progress(token)

    if max_workers <= 1 or total == 1:
        return [_call(col, index=i) for i, col in enumerate(collections, start=1)]

    from concurrent.futures import ThreadPoolExecutor

    in_flight: set[str] = set()
    lock = threading.Lock()

    def _parallel(col: str):
        with lock:
            in_flight.add(col)
            names = list(in_flight)
        try:
            return _call(col, in_flight=names)
        finally:
            with lock:
                in_flight.discard(col)

    workers = min(max_workers, total)
    with ThreadPoolExecutor(max_workers=workers,
                            thread_name_prefix="vs-audit") as pool:
        return list(pool.map(_parallel, collections))



def dispatch_alerts(result: AuditResult, sinks: list, *,
                    min_severity: Severity = Severity.HIGH) -> int:
    """Emit one alert per policy violation at/above ``min_severity`` to each sink.

    Returns the number of alerts dispatched. Delivery is fail-open — sinks
    swallow their own errors — so this never raises into the audit path. Alerts
    dedup per (store, policy, collection) so re-audits update rather than
    duplicate incidents on stateful sinks (e.g. PagerDuty).
    """
    if not sinks:
        return 0
    from vecshield_platform.runtime.events import Alert

    try:
        ts = datetime.fromisoformat(result.finished_at).timestamp()
    except (ValueError, TypeError):
        ts = datetime.now(timezone.utc).timestamp()

    dispatched = 0
    for v in result.violations:
        if v.severity.rank < min_severity.rank:
            continue
        scope = f"{v.store}/{v.collection}" if v.collection else v.store
        alert = Alert(
            rule=f"policy:{v.policy_id}",
            severity=v.severity,
            principal="audit",
            timestamp=ts,
            message=f"{v.description} in '{scope}' (action: {v.action})",
            dedup_key=f"audit:{v.store}:{v.policy_id}:{v.collection or '*'}",
            collection=v.collection,
            evidence=v.to_dict(),
        )
        for sink in sinks:
            sink.emit(alert)
        dispatched += 1
    return dispatched


def _boundary_job(datasource, classifier, max_records) -> ScanJob:
    """Run the chunk-boundary analyzer over a datasource's records."""
    from vecshield.ingest import ChunkBoundaryAnalyzer

    analyzer = ChunkBoundaryAnalyzer(classifier=classifier,
                                     store=datasource.describe().name)
    job = ScanJob(id=f"bound-{uuid.uuid4().hex[:12]}",
                  store=datasource.describe().name)
    for ds in datasource.describe().datasets:
        records = []
        for i, chunk in enumerate(datasource.iter_records(ds.name)):
            if max_records and i >= max_records:
                break
            records.append(chunk)
        for f in analyzer.analyze(records):
            job.add(f)
    job.finished_at = datetime.now(timezone.utc)
    job.stats = {"datasets": len(datasource.describe().datasets),
                 "boundary_findings": len(job.findings)}
    return job
