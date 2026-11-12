"""Namespace / tenant isolation verification.

The common multi-tenant RAG pattern packs many tenants into one collection and
separates them with a metadata filter (e.g. WHERE tenant_id = 'acme'). Isolation
then depends on two things: the store honouring that filter, and the
application remembering to add it to every query.

This engine checks the first exhaustively, where the store allows it, and
reports the second as a structural fact:

  1. enumerate the collection (the whole of it unless the caller caps it) and
     map every chunk id to its tenant, counting chunks with no tenant value
  2. canary: one query filtered to a tenant value that cannot exist. Any hit
     means the store ignores the filter (CRITICAL)
  3. full view, per tenant: one query filtered to that tenant, asking for as
     many results as the collection holds (up to the store's result cap). Any
     chunk of another tenant, or with no tenant value, means the filter leaks
     (CRITICAL). It also shows whether the tenant's own view is whole
  4. cross-tenant sweep: every stored chunk's own vector is queried under every
     OTHER tenant's filter (untagged chunks under every tenant's). Any returned
     chunk that is not that tenant's is a bleed (CRITICAL)
  5. one unfiltered query, recording what a query without the filter returns.
     When two or more tenants share the collection, isolation is convention-only
     by construction (HIGH)

Why the sweep proves filter enforcement for the stored corpus
--------------------------------------------------------------
A chunk ``c`` queried with its own vector is at distance zero from itself, so
among the chunks a filter admits, ``c`` ranks first, tied only with chunks whose
vectors are byte-identical to it. Enumeration counts those duplicates, and each
sweep query asks for ``duplicates(c) + margin`` results. So under exact search,
if tenant T's filter admits ``c`` at all, the T-filtered query for ``c``'s
vector returns ``c``. Running that query for every pair (chunk, tenant other
than its owner) therefore shows, chunk by chunk, that no other tenant's filter
admits it. This does not depend on the store's result cap or on a tenant's
size, which a single large filtered query cannot escape. Under approximate
search the argument rests on the index finding an exact self-match, which is
the most recoverable result an ANN index has; the full-view query (3) cross
checks it, and a full view that comes back short marks the index lossy and the
result partial rather than verified.

Short views on an approximate index
-----------------------------------
pgvector applies a filter to the rows its HNSW or IVFFlat index returns, so a
filtered query can come back short when other tenants' chunks fill the scan
(``hnsw.ef_search`` is 40 by default). Where the connector can say so
(``ann_iterative_scan``), a short full view is asked again once with the
iterative index scan on for that statement only. A view that is then whole
was a loss of recall, not an isolation result, and is judged on the retried
rows; any foreign chunk in the retry is a leak like any other. A tenant-
filtered collection on such an index with iterative scans off is reported
LOW: searches can return fewer results than asked for, and nothing leaks.

What it does not establish
--------------------------
It verifies the store's enforcement of the tenant filter, for the chunks stored
at the time of the check, through this connector's query path. It does not
test the application's own retrieval path (a query built without the filter,
an application-side post-filter, a cache), other credentials or API surfaces,
or chunks written after enumeration. Nor does it judge whether each chunk's
tenant value is correct: a chunk tagged with the wrong tenant is invisible to a
filter check.

Cost and budget
---------------
The sweep issues ``chunks x (tenants - 1)`` queries (plus one per untagged chunk
per tenant). ``IsolationLimits.query_budget`` bounds it per collection and is
configuration (``VECSHIELD_ISOLATION_QUERY_BUDGET``). Over budget, a
deterministic subset of chunk-tenant pairs is queried instead, the result is
labelled ``sampled``, and the check cannot read complete: an absence of
observed bleed over part of the collection does not verify isolation.

It reuses ScanJob so isolation findings serialize and render like scan findings.
"""

from __future__ import annotations

import hashlib
import logging
import math
import os
import uuid
from array import array
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Iterator, Mapping, Optional

from vecshield.models import Finding, ScanJob, Severity
from vecshield_platform.connectors.base import Connector, UnsupportedCapability
from vecshield_platform.coverage import (
    COUNT_UNKNOWN_REASON,
    check_outcome,
    count_known,
    read_errors_for,
    set_job_coverage,
)

logger = logging.getLogger(__name__)

CHECK = "tenant_isolation"

#: Result cap used when a connector declares none (``Connector.max_top_k``).
DEFAULT_TOP_K_CAP = 10000

#: Tenant names and per-tenant rows kept in evidence and coverage details.
MAX_LISTED_TENANTS = 200

_EXAMPLES = 10

#: A query hit whose tenant cannot be told: not enumerated, no metadata returned.
_UNKNOWN: Any = object()

QUERY_BUDGET_ENV = "VECSHIELD_ISOLATION_QUERY_BUDGET"
SWEEP_MARGIN_ENV = "VECSHIELD_ISOLATION_SWEEP_MARGIN"

#: Metadata keys that commonly carry a tenant. Used only when no chunk carries
#: the configured tenant field, to tell a collection with no tenant partition
#: (not applicable) from one that partitions on a field the run was not given.
TENANT_FIELD_HINTS = (
    "tenant", "tenant_id", "tenantid", "tenant_key", "org", "org_id", "orgid",
    "organization", "organization_id", "organisation", "organisation_id",
    "account_id", "workspace", "workspace_id", "namespace", "customer_id",
    "client_id", "company_id",
)

_HINT_VALUES = 50  # distinct values remembered per hinted field

#: Every integer below 2**53 has a float64 of its own. From 2**53 up,
#: neighbouring integers round to the same float (2**53 + 1 rounds to 2**53),
#: so a floating-point id at or beyond it stops naming one tenant.
_EXACT_FLOAT_LIMIT = 2 ** 53

#: The range stores hold integer metadata in (int64): a canary outside it is
#: a type or overflow error in Chroma, Milvus and Postgres.
_INT64_MIN, _INT64_MAX = -(2 ** 63), 2 ** 63 - 1


@dataclass(frozen=True)
class IsolationLimits:
    """The isolation check's configurable limits, per collection.

    ``query_budget``: the most cross-tenant sweep queries one collection's
    check may issue. Over it, the sweep queries a deterministic subset and the
    result is partial. ``sweep_margin``: results each sweep query asks for
    beyond the chunk's own byte-identical duplicates; any non-tenant chunk in
    them counts, so a margin also surfaces near neighbours the filter admitted.
    """

    query_budget: int = 10_000
    sweep_margin: int = 4

    @classmethod
    def from_env(cls, environ: Optional[Mapping[str, str]] = None) -> "IsolationLimits":
        env = os.environ if environ is None else environ
        default = cls()
        return cls(query_budget=_env_int(env, QUERY_BUDGET_ENV, default.query_budget),
                   sweep_margin=_env_int(env, SWEEP_MARGIN_ENV, default.sweep_margin))


def _env_int(env: Mapping[str, str], name: str, default: int) -> int:
    raw = (env.get(name) or "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        value = -1
    if value < 0:
        logger.warning("Ignoring %s=%r: expected a non-negative integer; using %d",
                       name, raw, default)
        return default
    return value


@dataclass
class _Census:
    """What enumeration learned about one collection."""

    id_to_tenant: dict[str, Optional[str]] = field(default_factory=dict)
    tenant_ids: dict[str, set[str]] = field(default_factory=dict)
    tenant_value: dict[str, Any] = field(default_factory=dict)
    tenant_vector: dict[str, list[float]] = field(default_factory=dict)
    #: Chunks with a stored vector, by owning tenant (None: untagged).
    vectors_by_owner: dict[Optional[str], int] = field(default_factory=dict)
    #: Byte-identical vectors: digest -> how many chunks carry it.
    vector_counts: dict[bytes, int] = field(default_factory=dict)
    hint_values: dict[str, set[str]] = field(default_factory=dict)
    #: Stored text of a tenant value -> the value types that carry it, so a
    #: string "1" and an integer 1 are two tenants however they are ordered.
    text_types: dict[str, set[str]] = field(default_factory=dict)
    any_vector: Optional[list[float]] = None

    def key_for(self, raw: Any) -> str:
        """The tenant key for a stored value, as enumeration assigned it."""
        return _tenant_key(raw, self.text_types)
    untagged: int = 0
    no_vector: int = 0
    scanned: int = 0
    capped: bool = False


def probe_isolation(
    connector: Connector,
    collection: str,
    tenant_field: str,
    *,
    max_chunks: Optional[int] = None,
    top_k_cap: Optional[int] = None,
    top_k: Optional[int] = None,
    query_budget: Optional[int] = None,
    limits: Optional[IsolationLimits] = None,
) -> ScanJob:
    """Verify tenant isolation on ``tenant_field`` in one collection.

    ``max_chunks`` caps enumeration (None reads the whole collection); a run
    that hits it is partial. ``top_k_cap`` overrides the connector's declared
    result cap. ``limits`` defaults to ``IsolationLimits.from_env()``, and
    ``query_budget`` overrides its sweep budget. ``top_k`` is accepted for
    compatibility with older callers and ignored: query sizes follow the
    collection and the store's cap, because a fixed small top_k cannot show that
    a filter returns exactly one tenant.
    """
    del top_k  # compatibility only; see docstring
    limits = limits or IsolationLimits.from_env()
    if query_budget is not None:
        limits = replace(limits, query_budget=max(0, int(query_budget)))
    store = connector.describe()
    job = ScanJob(id=f"iso-{uuid.uuid4().hex[:12]}", store=store.name)

    skip_reason = _skip_reason(connector)
    if skip_reason:
        return _skipped(job, store, collection, tenant_field, skip_reason)

    cap = _cap(connector, top_k_cap)

    # ---- 1. enumerate ---------------------------------------------------- #
    reset_read_errors = getattr(connector, "reset_read_errors", None)
    if callable(reset_read_errors):
        reset_read_errors()
    census = _enumerate(connector, collection, tenant_field, max_chunks)
    scanned, capped, untagged = census.scanned, census.capped, census.untagged
    # A read that stopped short of the inventory without reaching the run's
    # limit: the unread part may hold other tenants, so neither "empty" nor
    # "one tenant" can be concluded from what was read.
    short_read = _short_read(connector, store, collection, scanned) if not capped else ""
    tenant_ids, tenant_value = census.tenant_ids, census.tenant_value

    tenants = sorted(tenant_ids)
    total = scanned if not capped else _declared_count(store, collection, scanned)
    size = min(total, cap) if total else cap
    job.stats = {
        "check": CHECK,
        "collection": collection,
        "tenant_field": tenant_field,
        "tenants": tenants[:MAX_LISTED_TENANTS],
        "tenant_count": len(tenants),
        "chunks_examined": scanned,
        "total_chunks": total,
        "untagged": untagged,
        "top_k_cap": cap,
        "enumeration_capped": capped,
    }
    base = {"tenants": tenants[:MAX_LISTED_TENANTS], "tenant_count": len(tenants),
            "chunks_examined": scanned, "chunks_scanned": scanned,
            "total_chunks": total, "untagged": untagged, "top_k_cap": cap,
            "enumeration_capped": capped, "tenant_field": tenant_field,
            "query_budget": limits.query_budget}
    # Recorded when the connector reports it. Informational only: the sweep's
    # self-rank check, not a declared metric, decides whether its proof holds.
    metric = next((getattr(c, "distance_metric", None) for c in store.collections or []
                   if c.name == collection), None)
    if metric:
        base["distance_metric"] = metric
    cap_clause = (f"only the first {_n(scanned, 'chunk')} were read (the run's limit)"
                  if capped else "")

    if short_read:
        base["short_read"] = short_read
    # ---- nothing to isolate, or nothing to isolate on --------------------- #
    if short_read and (scanned == 0 or (len(tenants) <= 1 and not untagged)):
        return _finish(job, store, collection, outcome="inconclusive", complete=False,
                       reason=(f"{short_read} Whether other tenants' data is in the "
                               "unread part is not established; isolation was not "
                               "assessed."),
                       details={**base, "per_tenant": [], "filter_enforcement": "not_verified",
                                "canary": "not_run", "method": "not_run",
                                "structure": "unknown"})
    if scanned == 0 and not capped:
        return _finish(job, store, collection, outcome="passed", complete=True,
                       reason=("The collection holds no chunks, so there is no tenant "
                               "data to isolate; isolation is not applicable."),
                       details={**base, "per_tenant": [], "filter_enforcement": "not_applicable",
                                "canary": "not_run", "structure": "single_tenant",
                                "method": "not_applicable", "applicability": "not_applicable"})
    if not tenants:
        return _no_tenant_values(job, store, collection, tenant_field, census, base,
                                 cap_clause)
    imprecise = [t for t in tenants if _imprecise_float(tenant_value[t])]
    if len(tenants) == 1 and not untagged and not capped and imprecise:
        # One stored value, but a float this large stands for every integer
        # id that rounds to it: several tenants written through a float path
        # (JSON, JavaScript) land on it together, and nothing can tell them
        # apart. "Only one tenant" cannot be established.
        job.add(_imprecise_float_finding(store, collection, tenant_field, imprecise,
                                         tenant_value))
        return _finish(job, store, collection, outcome="inconclusive", complete=False,
                       reason=(f"Every chunk carries the same '{tenant_field}' value, "
                               f"'{tenants[0]}', but it is a floating-point number at or "
                               "beyond 2^53, which stands for every integer id that rounds "
                               "to it, so whether it is one tenant cannot be established; "
                               "isolation was not assessed."),
                       details={**base, "per_tenant": [],
                                "filter_enforcement": "not_verified", "canary": "not_run",
                                "structure": "single_tenant", "method": "not_run",
                                "imprecise_tenants": imprecise[:MAX_LISTED_TENANTS]})
    if len(tenants) == 1 and not untagged and not capped:
        job.add(Finding(
            id=f"find-{uuid.uuid4().hex[:10]}",
            title=f"No multi-tenant isolation risk in '{collection}'",
            severity=Severity.INFO, category="isolation", store=store.name,
            collection=collection,
            description=(f"Every one of the {_n(scanned, 'chunk')} carries the same "
                         f"'{tenant_field}' value, so no other tenant's data is in this "
                         "collection to reach."),
            evidence={"tenants": tenants, "chunks": scanned}))
        return _finish(job, store, collection, outcome="passed", complete=True,
                       reason=(f"Only one tenant's data is in this collection (all "
                               f"{_n(scanned, 'chunk')} read), so there is no other "
                               "tenant's data to reach; isolation is not applicable."),
                       details={**base, "per_tenant": [],
                                "filter_enforcement": "not_applicable", "canary": "not_run",
                                "structure": "single_tenant", "method": "not_applicable",
                                "applicability": "not_applicable"})
    if census.any_vector is None:
        job.add(_skip_finding(store, collection, tenant_field,
                              "no chunk in the collection has a stored vector to query with"))
        return _finish(job, store, collection, outcome="inconclusive", complete=False,
                       reason="No chunk has a stored vector, so the tenant filter could not be queried.",
                       details={**base, "per_tenant": [], "filter_enforcement": "not_verified",
                                "canary": "not_run", "method": "not_run",
                                "structure": "shared" if len(tenants) > 1 else "single_tenant"})

    queries = 0

    def tenant_of(hit) -> Optional[str]:
        """The hit's tenant: None if untagged, _UNKNOWN if it cannot be told."""
        if hit.id in census.id_to_tenant:
            return census.id_to_tenant[hit.id]
        metadata = hit.metadata or {}
        if tenant_field not in metadata:
            return _UNKNOWN  # not enumerated (capped run) and no metadata returned
        raw = metadata[tenant_field]
        return None if _is_blank(raw) else census.key_for(raw)

    # ---- 2. canary ------------------------------------------------------- #
    canary_value = _canary_value(tenant_value.values())
    try:
        canary_hits = connector.query(collection, census.any_vector, top_k=size,
                                      where={tenant_field: canary_value})
    except UnsupportedCapability as exc:
        return _skipped(job, store, collection, tenant_field,
                        f"{connector.kind} does not support a filtered query ({exc})")
    queries += 1
    # A hit genuinely carrying the canary value (possible only for an integer
    # canary in a capped run, beyond what was enumerated) is not a violation.
    canary_ids = sorted({hit.id for hit in canary_hits
                         if tenant_of(hit) != census.key_for(canary_value)})
    canary = "failed" if canary_ids else "passed"

    # ---- 3. full view per tenant ------------------------------------------ #
    queryable = [t for t in tenants if _is_scalar(tenant_value[t])]
    unqueried = [t for t in tenants if t not in queryable]
    full_view: dict[str, dict] = {}
    leaked: dict[str, set[str]] = {}  # probe tenant -> leaked chunk ids
    # (probe tenant, owning tenant or None) -> leaked chunk ids, so a bleed can
    # be traced to the pair of stored values the store matched.
    leak_pairs: dict[tuple[str, Optional[str]], set[str]] = {}
    examples: list[dict] = []

    def record_leak(tenant: str, owner, hit_id: str, query: str) -> None:
        ids = leaked.setdefault(tenant, set())
        if hit_id in ids:
            return
        ids.add(hit_id)
        leak_pairs.setdefault((tenant, owner), set()).add(hit_id)
        if len(examples) < _EXAMPLES:
            examples.append({"probe_tenant": tenant, "leaked_tenant": owner,
                             "leaked_id": hit_id, "query": query})

    # A query that fails part-way must not lose what earlier queries found:
    # the failure is recorded, the run becomes partial, and any leak or canary
    # failure already seen still decides the outcome.
    query_errors: list[dict] = []

    def absorb(tenant: str, hits, view: dict, query: str) -> None:
        for hit in hits:
            if hit.id in view["returned"]:
                continue
            view["returned"].add(hit.id)
            owner = tenant_of(hit)
            if owner is _UNKNOWN:
                view["unattributed"] += 1
            elif owner != tenant:
                view["foreign"] += 1
                record_leak(tenant, owner, hit.id, query)

    for tenant in queryable:
        vector = census.tenant_vector.get(tenant, census.any_vector)
        try:
            hits = connector.query(collection, vector, top_k=size,
                                   where={tenant_field: tenant_value[tenant]})
        except UnsupportedCapability:
            raise
        except Exception as exc:  # noqa: BLE001 - recorded, never read as a pass
            query_errors.append({"stage": "full_view", "tenant": tenant,
                                 "error_type": type(exc).__name__})
            break
        queries += 1
        full_view[tenant] = {"returned": set(), "foreign": 0, "unattributed": 0}
        absorb(tenant, hits, full_view[tenant], "full_view")

    # ---- 3b. a short view on an approximate index: recall or isolation? --- #
    ann = _ann_index(connector, collection)
    ann_retry: dict[str, dict] = {}
    if ann.get("index_type"):
        for tenant in queryable:
            view = full_view.get(tenant)
            if view is None or view["foreign"] or _whole(view["returned"],
                                                         tenant_ids[tenant], size):
                continue
            before = len(view["returned"])
            try:
                hits = connector.query_iterative(
                    collection, census.tenant_vector.get(tenant, census.any_vector),
                    top_k=size, where={tenant_field: tenant_value[tenant]})
            except UnsupportedCapability as exc:
                ann["retry_unavailable"] = str(exc)
                break
            except Exception as exc:  # noqa: BLE001 - the view stays short, as it was
                ann["retry_error"] = type(exc).__name__
                break
            queries += 1
            foreign_before = view["foreign"]
            absorb(tenant, hits, view, "full_view_iterative")
            ann_retry[tenant] = {
                "returned_before": before, "returned_after": len(view["returned"]),
                "result": ("leak" if view["foreign"] > foreign_before
                           else "recall_loss" if _whole(view["returned"],
                                                        tenant_ids[tenant], size)
                           else "still_short")}

    # ---- 4. cross-tenant sweep -------------------------------------------- #
    sweep = _sweep(connector, collection, tenant_field, census, queryable, limits, cap,
                   max_chunks, tenant_of, record_leak)
    queries += sweep["queries"]

    # ---- 5. structure: what a query without the filter returns ------------ #
    probe_tenant = next((t for t in tenants if t in census.tenant_vector), tenants[0])
    try:
        unfiltered = connector.query(
            collection, census.tenant_vector.get(probe_tenant, census.any_vector),
            top_k=size)
        queries += 1
    except Exception as exc:  # noqa: BLE001 - recorded, never read as a pass
        unfiltered = []
        query_errors.append({"stage": "unfiltered", "error_type": type(exc).__name__})
    seen_tenants = sorted({t for t in (tenant_of(h) for h in unfiltered)
                           if t is not None and t is not _UNKNOWN})
    cross = [{"probe_tenant": probe_tenant, "leaked_tenant": tenant_of(h), "leaked_id": h.id,
              "score": round(h.score, 4)}
             for h in unfiltered
             if tenant_of(h) not in (probe_tenant, None, _UNKNOWN)][:_EXAMPLES]
    # A capped run may meet tenants in query results that enumeration never
    # reached; they still share the collection.
    sharing = sorted(set(tenants) | set(seen_tenants))
    shared = len(sharing) > 1

    # ---- per-tenant verdicts ------------------------------------------------ #
    exhaustive = (sweep["method"] == "exhaustive" and not sweep["error"]
                  and not sweep["self_rank_unverified"])
    vectors_total = sum(census.vectors_by_owner.values())
    per_tenant: list[dict] = []
    short: list[str] = []
    for tenant in tenants:
        own = tenant_ids[tenant]
        if tenant not in full_view:
            per_tenant.append({"tenant": tenant, "chunks": len(own), "returned": 0,
                               "foreign": 0, "unattributed": 0, "cross_tenant_queries": 0,
                               "bleeds": 0, "verified": False})
            continue
        view = full_view[tenant]
        returned = view["returned"]
        whole = _whole(returned, own, size)
        expected = vectors_total - census.vectors_by_owner.get(tenant, 0)
        swept = sweep["per_tenant"].get(tenant, 0)
        bleeds = len(leaked.get(tenant, ()))
        verified = (not bleeds and not view["unattributed"] and whole
                    and exhaustive and swept == expected and tenant not in imprecise)
        if not bleeds and not whole:
            short.append(tenant)
        row = {"tenant": tenant, "chunks": len(own), "returned": len(returned),
               "foreign": view["foreign"], "unattributed": view["unattributed"],
               "cross_tenant_queries": swept, "bleeds": bleeds, "verified": verified}
        if tenant in ann_retry:
            row["ann_retry"] = ann_retry[tenant]
        per_tenant.append(row)

    # ---- findings --------------------------------------------------------- #
    leaking = [row["tenant"] for row in per_tenant if row["bleeds"]]
    verified = [row["tenant"] for row in per_tenant if row["verified"]]
    # Numeric tenant values the store matched although they differ as stored.
    # A bleed between the same number written with two types (1042, 1042.0)
    # may be one tenant, so a run whose every bleed is of that kind is not
    # reported as a cross-tenant leak.
    numeric = _numeric_diagnosis(leak_pairs, tenant_value)
    same_value = {(r["probe_tenant"], r["leaked_tenant"]) for r in numeric["same_value"]}
    ambiguous = (canary != "failed" and bool(leaking)
                 and all(pair in same_value for pair in leak_pairs))
    violated = canary == "failed" or bool(leaking)
    enforcement = ("ambiguous" if ambiguous
                   else "violated" if violated
                   else "verified" if len(verified) == len(tenants)
                   else "partially_verified")
    changed = sweep["appeared"] or sweep["vanished"]

    if ambiguous:
        job.add(_same_value_finding(store, collection, tenant_field, leaking, leaked,
                                    examples, sweep, numeric["same_value"]))
    elif violated:
        job.add(_not_enforced_finding(store, collection, tenant_field, canary_ids,
                                      leaking, leaked, examples, sweep, numeric,
                                      tenant_value))
    # A float id at or beyond 2**53 may be several tenants under one value. A
    # collision the sweep observed already names the cause in the CRITICAL
    # finding; otherwise say it here, because no bleed can show it.
    collided = {name for row in numeric["collision"]
                for name in (row["probe_tenant"], row["leaked_tenant"])}
    unexplained = [t for t in imprecise if t not in collided]
    if unexplained:
        job.add(_imprecise_float_finding(store, collection, tenant_field, unexplained,
                                         tenant_value))
    if shared:
        job.add(_convention_only_finding(store, collection, sharing, enforcement,
                                         verified, seen_tenants, cross))
    if untagged:
        job.add(_untagged_finding(store, collection, tenant_field, untagged))
    if shared and ann.get("index_type") and \
            str(ann.get("iterative_scan") or "").strip().lower() == "off":
        job.add(_ann_post_filter_finding(store, collection, tenant_field, ann, ann_retry))

    complete = (not capped and not short_read and not query_errors
                and enforcement == "verified" and canary == "passed"
                and not census.no_vector and not changed)
    failed = any(f.severity.rank >= Severity.HIGH.rank for f in job.findings)
    outcome = "failed" if failed else "passed" if complete else "inconclusive"
    reason = _reason(
        tenants=tenants, scanned=scanned, canary=canary, canary_ids=canary_ids,
        leaking=leaking, leaked=leaked, verified=verified, unqueried=unqueried,
        short=short, per_tenant=per_tenant, shared=len(sharing) if shared else 0,
        untagged=untagged, field_name=tenant_field, cap_clause=cap_clause, cap=cap,
        capped=capped, sweep=sweep, no_vector=census.no_vector, complete=complete,
        budget=limits.query_budget, ambiguous=ambiguous,
        collision=bool(numeric["collision"]), imprecise=unexplained)
    if query_errors:
        stages = ", ".join(sorted({e["stage"].replace("_", " ") for e in query_errors}))
        reason = (f"A {stages} query failed ({query_errors[0]['error_type']}), so the "
                  f"check did not finish. {reason}")
    if short_read:
        reason = f"{short_read} {reason}"
    details = {**base,
               "per_tenant": per_tenant[:MAX_LISTED_TENANTS],
               "filter_enforcement": enforcement, "canary": canary,
               "structure": "shared" if shared else "single_tenant",
               "unfiltered_tenants_returned": len(seen_tenants),
               "queries": queries,
               "method": sweep["method"],
               "sampled": sweep["method"] == "sampled",
               "cross_tenant_pairs": sweep["pairs_total"],
               "cross_tenant_queries": sweep["queries"],
               "bleeds": sum(len(ids) for ids in leaked.values()),
               "chunks_without_vector": census.no_vector,
               "sweep_top_k_margin": limits.sweep_margin,
               "self_rank_queries": sweep["self_rank_queries"],
               "self_rank_widened": sweep["self_rank_widened"],
               "self_rank_unverified": sweep["self_rank_unverified"]}
    if imprecise:
        details["imprecise_tenants"] = imprecise[:MAX_LISTED_TENANTS]
    if ann.get("index_type") or ann.get("error"):
        details["ann_index"] = _ann_details(ann, ann_retry)
    if sweep["error"]:
        details["sweep_error"] = sweep["error"]
    if query_errors:
        details["query_errors"] = query_errors
    if changed:
        details["changed_during_check"] = {"appeared": sweep["appeared"],
                                           "vanished": sweep["vanished"]}
    job.stats.update({"filter_enforcement": enforcement, "canary": canary,
                      "structure": details["structure"], "queries": queries,
                      "method": sweep["method"], "cross_tenant_queries": sweep["queries"],
                      "bleeds": details["bleeds"]})
    return _finish(job, store, collection, outcome=outcome, complete=complete,
                   reason=reason, details=details)


# --------------------------------------------------------------------------- #
# enumeration and the sweep                                                   #
# --------------------------------------------------------------------------- #

def _enumerate(connector: Connector, collection: str, tenant_field: str,
               max_chunks: Optional[int]) -> _Census:
    census = _Census()
    # Tenants are keyed by (value type, stored text) while reading, and given
    # their display keys only once every value has been seen: keying by text
    # alone merges the string "1" with the integer 1, and which of the two
    # then served as the filter value depended on enumeration order.
    owners: dict[str, Optional[tuple[str, str]]] = {}
    tenant_ids: dict[tuple[str, str], set[str]] = {}
    tenant_value: dict[tuple[str, str], Any] = {}
    tenant_vector: dict[tuple[str, str], list[float]] = {}
    vectors_by_owner: dict[Optional[tuple[str, str]], int] = {}
    for chunk in connector.iter_chunks(collection):
        if max_chunks is not None and census.scanned >= max_chunks:
            census.capped = True
            break
        census.scanned += 1
        metadata = chunk.metadata or {}
        raw = metadata.get(tenant_field)
        owner: Optional[tuple[str, str]]
        if _is_blank(raw):
            census.untagged += 1
            owner = None
        else:
            owner = (_value_type(raw), str(raw))
            census.text_types.setdefault(owner[1], set()).add(owner[0])
            tenant_ids.setdefault(owner, set()).add(chunk.id)
            tenant_value.setdefault(owner, raw)
            if chunk.embedding and owner not in tenant_vector:
                tenant_vector[owner] = chunk.embedding
        owners[chunk.id] = owner
        if chunk.embedding:
            if census.any_vector is None:
                census.any_vector = chunk.embedding
            vectors_by_owner[owner] = vectors_by_owner.get(owner, 0) + 1
            digest = _vector_key(chunk.embedding)
            census.vector_counts[digest] = census.vector_counts.get(digest, 0) + 1
        else:
            census.no_vector += 1
        for key, value in metadata.items():
            if key == tenant_field or not _looks_like_tenant_field(key):
                continue
            if _is_blank(value) or not _is_scalar(value):
                continue
            seen = census.hint_values.setdefault(key, set())
            if len(seen) < _HINT_VALUES:
                seen.add(str(value))

    def display(typed: Optional[tuple[str, str]]) -> Optional[str]:
        return None if typed is None else _display_key(typed, census.text_types)

    census.id_to_tenant = {cid: display(o) for cid, o in owners.items()}
    census.tenant_ids = {display(k): v for k, v in tenant_ids.items()}  # type: ignore[misc]
    census.tenant_value = {display(k): v for k, v in tenant_value.items()}  # type: ignore[misc]
    census.tenant_vector = {display(k): v for k, v in tenant_vector.items()}  # type: ignore[misc]
    census.vectors_by_owner = {display(k): v for k, v in vectors_by_owner.items()}
    return census


def _value_type(raw: Any) -> str:
    if isinstance(raw, bool):
        return "boolean"
    if isinstance(raw, str):
        return "string"
    if isinstance(raw, int):
        return "integer"
    if isinstance(raw, float):
        return "float"
    return type(raw).__name__


def _display_key(typed: tuple[str, str], text_types: Mapping[str, set[str]]) -> str:
    """The stored text, qualified by its type only where two types share it."""
    kind, text = typed
    return f"{text} ({kind})" if len(text_types.get(text, ())) > 1 else text


def _tenant_key(raw: Any, text_types: Mapping[str, set[str]]) -> str:
    kind, text = _value_type(raw), str(raw)
    known = text_types.get(text, set())
    if len(known | {kind}) > 1:
        return f"{text} ({kind})"
    return text


def _imprecise_float(value: Any) -> bool:
    """A float at or beyond 2**53: it stands for more than one integer id."""
    return (isinstance(value, float) and math.isfinite(value)
            and abs(value) >= _EXACT_FLOAT_LIMIT)


#: Chunks the sweep reads ahead so a batching connector can answer their
#: queries together, and the most queries one such window plans. Both bound
#: the query results held at once.
_SWEEP_WINDOW_CHUNKS = 128
_SWEEP_WINDOW_QUERIES = 1024


def _batches_queries(connector: Connector) -> bool:
    """Whether the connector answers several vectors in one request."""
    return type(connector).query_many is not Connector.query_many


def _self_rank_in(hits, chunk_id: str) -> Optional[int]:
    """The chunk's rank among distinct hit ids, or None when it is absent."""
    seen_ids: set[str] = set()
    for hit in hits:
        seen_ids.add(hit.id)
        if hit.id == chunk_id:
            return len(seen_ids)
    return None


def _sweep(connector: Connector, collection: str, tenant_field: str, census: _Census,
           queryable: list[str], limits: IsolationLimits, cap: int,
           max_chunks: Optional[int], tenant_of, record_leak) -> dict:
    """Query every stored chunk's vector under every other tenant's filter.

    Streams the collection a second time rather than holding every vector from
    enumeration, so memory stays proportional to the number of chunk ids.

    Through a connector that batches (``query_many``), the sweep reads a window
    of chunks ahead, plans the queries the loop below will issue for them, and
    answers those in a few batched requests. The loop then runs unchanged and
    takes each answer from that prefetch; a query the prefetch did not answer
    (its batch failed, say) is issued on its own as before, so budget, counts,
    examples and the point an error stops the sweep are the same either way.
    """
    queryable_set = set(queryable)
    pairs_total = sum(count * (len(queryable) - (1 if owner in queryable_set else 0))
                      for owner, count in census.vectors_by_owner.items())
    budget = limits.query_budget
    method = "exhaustive" if pairs_total <= budget else "sampled"
    # Over budget, a pair is kept when its hash falls under budget/total: a
    # deterministic, evenly spread subset of about ``budget`` pairs.
    fraction = 1.0 if method == "exhaustive" else budget / pairs_total
    result: dict[str, Any] = {"method": method, "pairs_total": pairs_total, "queries": 0,
              "per_tenant": {}, "error": "", "appeared": 0, "vanished": 0,
              "self_rank_queries": 0, "self_rank_widened": 0, "self_rank_unverified": 0}
    if not pairs_total or not budget:
        return result

    def where_for(tenant: Optional[str]) -> Optional[dict]:
        return None if tenant is None else {tenant_field: census.tenant_value[tenant]}

    #: Prefetched hits by (read sequence, tenant or None for self-rank, top_k),
    #: and the window's plans by read sequence, so each vector is hashed once.
    prefetched: dict[tuple[int, Optional[str], int], list] = {}
    plans: dict[int, tuple[int, list[str]]] = {}

    def fetch(seq: int, chunk, tenant: Optional[str], k: int) -> list:
        hits = prefetched.pop((seq, tenant, k), None)
        if hits is not None:
            return hits
        if tenant is None:
            return connector.query(collection, chunk.embedding, top_k=k)
        return connector.query(collection, chunk.embedding, top_k=k, where=where_for(tenant))

    def self_rank(seq: int, chunk, k: int) -> Optional[int]:
        """The chunk's rank for its own vector over the whole collection.

        Unfiltered on purpose: every tenant filter admits a subset of the
        collection, so a chunk ranked r overall ranks at most r under any
        filter that admits it. Under L2 or cosine r is 1 (ties with its
        duplicates); under inner product a higher-norm neighbour can outrank
        it, and a sweep query sized for rank 1 would miss it.
        """
        hits = fetch(seq, chunk, None, k)
        result["self_rank_queries"] += 1
        return _self_rank_in(hits, chunk.id)

    def plan(chunk) -> tuple[int, list[str]]:
        """The chunk's first query size and the tenants it is queried under."""
        owner = census.id_to_tenant[chunk.id]
        duplicates = census.vector_counts.get(_vector_key(chunk.embedding), 1)
        top_k = max(1, min(cap, duplicates + limits.sweep_margin))
        targets = [t for t in queryable if t != owner
                   and (fraction >= 1.0 or _pair_selected(chunk.id, t, fraction))]
        return top_k, targets

    def prefetch(planned: list[tuple[int, Any, int, list[str]]]) -> None:
        """Answer the planned queries in batches: self-rank, widened, filtered."""
        def run(groups: dict[tuple[Optional[str], int], list[tuple[int, Any]]]) -> None:
            for (tenant, k), items in groups.items():
                try:
                    answers = connector.query_many(
                        collection, [chunk.embedding for _, chunk in items],
                        top_k=k, where=where_for(tenant))
                except Exception:  # noqa: BLE001 - re-issued singly, where it is recorded
                    continue
                if len(answers) != len(items):
                    continue
                for (seq, _), hits in zip(items, answers):
                    prefetched[(seq, tenant, k)] = hits

        groups: dict[tuple[Optional[str], int], list[tuple[int, Any]]] = {}
        for seq, chunk, k, _ in planned:
            groups.setdefault((None, k), []).append((seq, chunk))
        run(groups)
        groups = {}
        for seq, chunk, k, _ in planned:
            hits = prefetched.get((seq, None, k))
            if hits is not None and k < cap and _self_rank_in(hits, chunk.id) is None:
                groups.setdefault((None, cap), []).append((seq, chunk))
        run(groups)
        groups = {}
        for seq, chunk, k, targets in planned:
            hits = prefetched.get((seq, None, k))
            if hits is None:
                continue
            rank = _self_rank_in(hits, chunk.id)
            if rank is None and k < cap:
                wide = prefetched.get((seq, None, cap))
                if wide is None:
                    continue
                rank = _self_rank_in(wide, chunk.id)
            final_k = cap if rank is None else max(k, min(cap, rank + limits.sweep_margin))
            for tenant in targets:
                groups.setdefault((tenant, final_k), []).append((seq, chunk))
        run(groups)

    per_tenant: dict[str, int] = {}
    seen: set[str] = set()
    read = 0
    stop = False

    def chunks() -> Iterator[tuple[int, Any]]:
        """``(sequence, chunk)`` in store order, prefetching each window."""
        source = iter(connector.iter_chunks(collection))
        if not _batches_queries(connector):
            yield from enumerate(source)
            return
        seq = 0
        while True:
            # Mirror the loop below on the window, without its side effects,
            # to find the queries it will issue. A read error is raised only
            # where the loop would have reached it.
            window: list[tuple[int, Any]] = []
            planned: list[tuple[int, Any, int, list[str]]] = []
            failure: Optional[BaseException] = None
            exhausted = False
            queries, reads, planned_queries = result["queries"], read, 0
            window_seen: set[str] = set()
            window_plans: dict[int, tuple[int, list[str]]] = {}
            while len(window) < _SWEEP_WINDOW_CHUNKS and planned_queries < _SWEEP_WINDOW_QUERIES:
                try:
                    chunk = next(source)
                except StopIteration:
                    exhausted = True
                    break
                except Exception as exc:  # noqa: BLE001 - re-raised in order below
                    failure = exc
                    break
                window.append((seq, chunk))
                seq += 1
                if max_chunks is not None and reads >= max_chunks:
                    break
                reads += 1
                if (chunk.id not in census.id_to_tenant or chunk.id in seen
                        or chunk.id in window_seen):
                    continue
                window_seen.add(chunk.id)
                if not chunk.embedding:
                    continue
                top_k, targets = window_plans[window[-1][0]] = plan(chunk)
                if not targets:
                    continue
                if queries >= budget:
                    break
                take = min(len(targets), budget - queries)
                queries += take
                planned_queries += take + 1
                planned.append((window[-1][0], chunk, top_k, targets[:take]))
            prefetched.clear()
            plans.clear()
            plans.update(window_plans)
            if planned:
                prefetch(planned)
            yield from window
            if failure is not None:
                raise failure
            if exhausted:
                return

    for seq, chunk in chunks():
        if stop or (max_chunks is not None and read >= max_chunks):
            break
        read += 1
        if chunk.id not in census.id_to_tenant:
            result["appeared"] += 1  # written after enumeration
            continue
        if chunk.id in seen:
            continue
        seen.add(chunk.id)
        if not chunk.embedding:
            continue  # counted in the census; the reason names it
        top_k, targets = plans.pop(seq) if seq in plans else plan(chunk)
        if not targets:
            continue
        if result["queries"] >= budget:
            stop = True
            break
        # The sweep's proof rests on the chunk ranking within top_k for its own
        # vector. Check that before relying on it; where it does not hold,
        # size the queries to the rank observed, up to the store's cap.
        try:
            rank = self_rank(seq, chunk, top_k)
            if rank is None and top_k < cap:
                result["self_rank_widened"] += 1
                rank = self_rank(seq, chunk, cap)
        except Exception as exc:  # noqa: BLE001 - recorded, never read as a pass
            result["error"] = f"self-rank query, {type(exc).__name__}: {exc}"[:300]
            stop = True
            break
        if rank is None:
            # Not found even at the cap: a filter admitting this chunk could
            # rank it out of any query this store allows. Still queried, so an
            # observed bleed is still reported, but it cannot be verified.
            result["self_rank_unverified"] += 1
            top_k = cap
        else:
            top_k = max(top_k, min(cap, rank + limits.sweep_margin))
        for tenant in targets:
            if result["queries"] >= budget:
                stop = True
                break
            try:
                hits = fetch(seq, chunk, tenant, top_k)
            except Exception as exc:  # noqa: BLE001 - recorded, never read as a pass
                result["error"] = f"{type(exc).__name__}: {exc}"[:300]
                stop = True
                break
            result["queries"] += 1
            per_tenant[tenant] = per_tenant.get(tenant, 0) + 1
            for hit in hits:
                who = tenant_of(hit)
                if who is not _UNKNOWN and who != tenant:
                    record_leak(tenant, who, hit.id, "cross_tenant")
    prefetched.clear()
    plans.clear()
    if not stop:
        result["vanished"] = sum(1 for cid in census.id_to_tenant if cid not in seen)
    result["per_tenant"] = per_tenant
    return result


# --------------------------------------------------------------------------- #
# helpers                                                                     #
# --------------------------------------------------------------------------- #

def _whole(returned, own, size: int) -> bool:
    """A tenant's filtered view holds all its chunks, or as many as a query may."""
    return len(returned) == len(own) or (len(own) > size and len(returned) >= size)


def _ann_index(connector: Connector, collection: str) -> dict:
    """The connector's ``ann_index_info()``, or ``{}`` when it has none."""
    try:
        caps = set(connector.capabilities())
    except Exception:  # noqa: BLE001
        return {}
    if "ann_iterative_scan" not in caps:
        return {}
    try:
        info = connector.ann_index_info(collection)
    except Exception as exc:  # noqa: BLE001 - the probe runs as it did without it
        return {"index_type": None, "error": type(exc).__name__}
    return dict(info) if isinstance(info, dict) else {}


def _ann_details(ann: dict, retry: dict[str, dict]) -> dict:
    keep = ("index_type", "index", "metric", "operator", "partial", "settings",
            "retrieval_role_settings", "iterative_scan", "pgvector_version",
            "iterative_scan_supported", "retry_unavailable", "retry_error", "error")
    out = {k: ann[k] for k in keep if k in ann}
    by_result: dict[str, list[str]] = {}
    for tenant, entry in retry.items():
        by_result.setdefault(entry["result"], []).append(tenant)
    out["short_views_retried"] = len(retry)
    for result in ("recall_loss", "still_short", "leak"):
        if by_result.get(result):
            out[result] = sorted(by_result[result])[:MAX_LISTED_TENANTS]
    return out


def _skip_reason(connector: Connector) -> Optional[str]:
    if "query" not in connector.capabilities():
        return _no_query_reason(connector)
    if not getattr(connector, "content_enumerable", True):
        return ("this store exposes inventory only (no per-chunk enumeration API), "
                "so tenant membership cannot be read here")
    return None


def _cap(connector: Connector, override: Optional[int]) -> int:
    for value in (override, getattr(connector, "max_top_k", None)):
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            return value
    return DEFAULT_TOP_K_CAP


def _short_read(connector: Connector, store, collection: str, scanned: int) -> str:
    """Why an uncapped read cannot be taken as the whole collection, or "".

    The store reporting more chunks than were read, a count the store could
    not produce, or items the connector could not read all leave part of the
    collection unseen.
    """
    col = next((c for c in store.collections or [] if c.name == collection), None)
    if col is not None and isinstance(col.count, int) and col.count > scanned:
        return (f"Enumeration returned {_n(scanned, 'chunk')} of the {col.count} "
                "the inventory reports.")
    if col is not None and not count_known(col):
        return COUNT_UNKNOWN_REASON
    try:
        errors = read_errors_for(connector.read_errors(), collection)
    except Exception as exc:  # noqa: BLE001
        return f"The connector's read errors could not be read ({type(exc).__name__})."
    if errors:
        return f"The connector could not read {_n(len(errors), 'item')} in this collection."
    return ""


def _declared_count(store, collection: str, scanned: int) -> Optional[int]:
    """The store's own count for a collection enumeration stopped early in.

    None when the store does not report one larger than what was read, so an
    unknown total is never shown as the number read.
    """
    for col in store.collections or []:
        if col.name == collection and isinstance(col.count, int) and col.count > scanned:
            return col.count
    return None


def _is_blank(value: Any) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


def _is_scalar(value: Any) -> bool:
    # Only plain values go into a filter: a dict or list taken from stored
    # metadata could read as a filter operator in some stores. A UUID is what
    # pgvector returns for a ``uuid`` column, the usual type of a tenant id.
    return isinstance(value, (str, int, float, bool, uuid.UUID))


def _looks_like_tenant_field(key: str) -> bool:
    lowered = str(key).lower()
    return lowered in TENANT_FIELD_HINTS or "tenant" in lowered


def _vector_key(embedding) -> bytes:
    """A digest of the vector's exact float values, to count exact duplicates."""
    return hashlib.blake2b(array("d", (float(x) for x in embedding)).tobytes(),
                           digest_size=16).digest()


def _pair_selected(chunk_id: str, tenant: str, fraction: float) -> bool:
    digest = hashlib.blake2b(f"{chunk_id}\x00{tenant}".encode(), digest_size=8).digest()
    return int.from_bytes(digest, "big") < fraction * 2 ** 64


def _canary_value(values) -> Any:
    """A tenant value that no chunk carries, typed like the real ones.

    A string canary against an integer column is a type error in several stores
    (Postgres, Milvus), so an all-integer field gets an integer no chunk holds.
    Likewise a Postgres ``uuid`` column rejects any string that is not a UUID,
    so an all-UUID field gets a fresh UUID.
    """
    values = list(values)
    if values and all(isinstance(v, uuid.UUID) for v in values):
        taken_ids = set(values)
        canary = uuid.uuid4()
        while canary in taken_ids:
            canary = uuid.uuid4()
        return canary
    if values and all(isinstance(v, int) and not isinstance(v, bool) for v in values):
        # Just past the largest id, unless that leaves int64 -- where the
        # store would reject the query rather than answer it.
        if max(values) < _INT64_MAX:
            return max(values) + 1
        if min(values) > _INT64_MIN:
            return min(values) - 1
        taken = set(values)
        return next(n for n in range(len(taken) + 1) if n not in taken)
    return f"__vecshield_isolation_canary_{uuid.uuid4().hex}"


def _all(count: int) -> str:
    return "both tenants" if count == 2 else f"all {count:,} tenants"


def _n(count: int, noun: str, plural: Optional[str] = None) -> str:
    return f"{count:,} {noun if count == 1 else (plural or noun + 's')}"


def _queries(count: int) -> str:
    return _n(count, "cross-tenant query", "cross-tenant queries")


def _reason(*, tenants, scanned, canary, canary_ids, leaking, leaked, verified, unqueried,
            short, per_tenant, shared, untagged, field_name, cap_clause, cap, capped,
            sweep, no_vector, complete, budget, ambiguous=False,
            collision=False, imprecise=()) -> str:
    total = len(tenants)
    bleeds = sum(len(ids) for ids in leaked.values())
    cap_tail = cap_clause
    if canary == "failed":
        main = (f"The store ignored the tenant filter: a query for a '{field_name}' value "
                f"no chunk carries returned {_n(len(canary_ids), 'chunk')}")
    elif ambiguous:
        main = (f"Filtered queries for {len(leaking)} of {_n(total, 'tenant')} returned "
                "chunks tagged with the same number stored as another type "
                f"({_n(bleeds, 'chunk')}; {_queries(sweep['queries'])} in the cross-tenant "
                "sweep); these may be one tenant written with two types, so no "
                "cross-tenant leak is asserted")
    elif leaking:
        main = (f"Filtered queries for {len(leaking)} of {_n(total, 'tenant')} returned "
                f"another tenant's data ({_n(bleeds, 'bleed')}; "
                f"{_queries(sweep['queries'])} in the cross-tenant sweep)")
        if collision:
            main += ("; the store compares tenant values as numbers, and distinct "
                     "tenant ids become the same number as floating point")
    elif complete:
        main = (f"Isolation verified exhaustively: {_n(scanned, 'chunk')} across "
                f"{_n(total, 'tenant')}, {_queries(sweep['queries'])}, 0 bleeds")
    else:
        gaps = []
        if sweep["method"] == "sampled":
            gaps.append(f"the cross-tenant sweep needs {sweep['pairs_total']:,} queries and "
                        f"the configured budget ({QUERY_BUDGET_ENV}) is {budget:,}, so "
                        f"{sweep['queries']:,} of {sweep['pairs_total']:,} chunk-tenant "
                        "pairs were queried")
        if sweep["error"]:
            gaps.append(f"a cross-tenant query failed after {sweep['queries']:,} of "
                        f"{sweep['pairs_total']:,} ({sweep['error']}), so the sweep stopped")
        if sweep.get("self_rank_unverified"):
            gaps.append(f"for {_n(sweep['self_rank_unverified'], 'chunk')} the store did not "
                        "return the chunk for its own vector within its result limit "
                        f"({cap:,}), as inner-product or approximate search can, so a "
                        "filter that admitted it could rank it out of every query")
        if short and not capped:  # a capped read already says why views are short
            over = [r for r in per_tenant if r["tenant"] in short and r["chunks"] > cap]
            if capped:
                why = "enumeration stopped early, so a tenant's full set of chunks is unknown"
            elif over and len(over) == len(short):
                why = "a tenant holds more chunks than the store's result limit"
            else:
                why = "approximate search returned fewer results than the tenant holds"
            gaps.append(f"filtered queries for {len(short)} of {_n(total, 'tenant')} did not "
                        f"return exactly that tenant's chunks ({why})")
        if unqueried:
            gaps.append(f"{len(unqueried)} of {_n(total, 'tenant')} could not be queried "
                        "(a non-scalar tenant value)")
        if imprecise:
            gaps.append(f"{len(imprecise)} of {_n(total, 'tenant')} "
                        f"{'is' if len(imprecise) == 1 else 'are'} stored as a "
                        "floating-point number at or beyond 2^53, which stands for more "
                        "than one integer id, so no filter can tell those tenants apart")
        if no_vector:
            gaps.append(f"{_n(no_vector, 'chunk')} {'has' if no_vector == 1 else 'have'} "
                        "no stored vector to query with")
        if sweep["appeared"] or sweep["vanished"]:
            gaps.append("the collection changed while it was being checked")
        if capped:
            gaps.append(cap_clause)
            cap_tail = ""
        if not gaps:
            gaps.append("not every tenant's filter could be verified")
        main = ("No bleed was observed, but isolation was not verified exhaustively: "
                + "; ".join(gaps))
        if verified and len(verified) < total:
            main += f" (enforcement verified for {len(verified)} of {_n(total, 'tenant')})"
    tail = []
    if shared and canary != "failed" and not leaking:
        # Why a verified filter still reads as failed: sharing one collection
        # makes isolation depend on every query carrying the filter.
        tail.append(f"{_n(shared, 'tenant')} share this collection, so isolation "
                    "depends on every query carrying the filter")
    if untagged:
        tail.append(f"{_n(untagged, 'chunk')} carry no '{field_name}' value"
                    if untagged != 1 else f"1 chunk carries no '{field_name}' value")
    if cap_tail:
        tail.append(cap_tail)
    return main + ("; " + "; ".join(tail) if tail else "") + "."


def _no_tenant_values(job: ScanJob, store, collection: str, tenant_field: str,
                      census: _Census, base: dict, cap_clause: str) -> ScanJob:
    """No chunk read carries the tenant field.

    Such a collection is not partitioned by that field, so there is no tenant
    filter to verify. Two cases are told apart: another tenant-like field varies
    across chunks (the run may have been given the wrong field, or the
    collection mixes tenants without the configured one), which is
    inconclusive; or nothing marks a tenant at all, which is a single-tenant
    collection and not applicable. A capped run cannot say either.
    """
    scanned = census.scanned
    mixed = {key: sorted(values) for key, values in sorted(census.hint_values.items())
             if len(values) > 1}
    details = {**base, "per_tenant": [], "canary": "not_run",
               "structure": "single_tenant", "method": "not_run"}
    if mixed:
        [(other, values)] = list(mixed.items())[:1]
        job.add(Finding(
            id=f"find-{uuid.uuid4().hex[:10]}",
            title=f"Tenants mixed in '{collection}' without the tenant field",
            severity=Severity.MEDIUM, category="isolation", store=store.name,
            collection=collection,
            description=(f"No chunk carries '{tenant_field}', but '{other}' takes "
                         f"{_n(len(values), 'distinct value')} across the "
                         f"{_n(scanned, 'chunk')} read, so this collection appears to hold "
                         "several tenants' data under a field the check was not given. "
                         "Isolation was not assessed."),
            remediation=(f"Run the check with '{other}' as the tenant field if it identifies "
                         f"the tenant, or give every chunk a '{tenant_field}' value."),
            evidence={"tenant_field": tenant_field, "candidate_fields": {
                key: len(vals) for key, vals in mixed.items()},
                "chunks_examined": scanned}))
        reason = (f"No chunk carries the tenant field '{tenant_field}', but '{other}' "
                  f"varies across chunks ({_n(len(values), 'value')}), so this collection "
                  "may mix tenants under another field; isolation was not assessed.")
        if cap_clause:
            reason = reason[:-1] + f"; {cap_clause}."
        return _finish(job, store, collection, outcome="inconclusive", complete=False,
                       reason=reason,
                       details={**details, "filter_enforcement": "not_verified",
                                "candidate_tenant_fields": sorted(mixed)})
    if census.capped:
        job.add(_no_tenant_field_finding(store, collection, tenant_field, scanned))
        return _finish(job, store, collection, outcome="inconclusive", complete=False,
                       reason=(f"No chunk read carries the tenant field '{tenant_field}' "
                               f"({cap_clause}); whether the rest does is unknown, so "
                               "isolation was not assessed."),
                       details={**details, "filter_enforcement": "not_verified"})
    job.add(Finding(
        id=f"find-{uuid.uuid4().hex[:10]}",
        title=f"No tenant partition in '{collection}'",
        severity=Severity.INFO, category="isolation", store=store.name,
        collection=collection,
        description=(f"None of the {_n(scanned, 'chunk')} carries a '{tenant_field}' value "
                     "and no other tenant-like field varies, so this collection is not "
                     "partitioned by tenant and there is no tenant filter to verify. If it "
                     "is meant to serve several tenants, anyone who can query it can read "
                     "all of it."),
        evidence={"tenant_field": tenant_field, "chunks_examined": scanned}))
    return _finish(job, store, collection, outcome="passed", complete=True,
                   reason=(f"No chunk carries the tenant field '{tenant_field}' and no other "
                           f"tenant-like field varies across the {_n(scanned, 'chunk')}, so "
                           "this collection is single-tenant; isolation is not applicable."),
                   details={**details, "filter_enforcement": "not_applicable",
                            "method": "not_applicable", "applicability": "not_applicable"})


def _finish(job: ScanJob, store, collection: str, *, outcome: str, complete: bool,
            reason: str, details: dict) -> ScanJob:
    set_job_coverage(job, [check_outcome(CHECK, store.name, collection, outcome=outcome,
                                         reason=reason, complete=complete, **details)])
    job.finished_at = datetime.now(timezone.utc)
    return job


def _skipped(job: ScanJob, store, collection: str, tenant_field: str,
             reason: str) -> ScanJob:
    # The engine needs BOTH query() and per-chunk enumeration. Missing either is
    # a coverage gap, not evidence of isolation.
    job.stats = {"check": CHECK, "collection": collection, "tenant_field": tenant_field,
                 "tenants": [], "tenant_count": 0, "chunks_examined": 0, "skipped": True}
    job.add(_skip_finding(store, collection, tenant_field, reason))
    return _finish(job, store, collection, outcome="unsupported", complete=False,
                   reason=f"Tenant isolation could not be checked: {reason}.",
                   details={"tenant_field": tenant_field, "chunks_examined": 0,
                            "skip_reason": reason, "method": "not_run"})


# --------------------------------------------------------------------------- #
# numeric tenant values                                                       #
# --------------------------------------------------------------------------- #

def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _numeric_relation(probe: Any, owner: Any) -> Optional[str]:
    """How two stored tenant values a filter matched relate as numbers.

    Stores such as Chroma compare an integer with a float by value. Two values
    that are distinct as stored (so the check keys them as distinct tenants) but
    equal once converted to float64 are either ``"same_value"``: the same
    integer written with two types (1042 and 1042.0), which may be one tenant;
    or ``"collision"``: distinct identifiers, or a float beyond 2**53, which
    stands for every integer that rounds to it and so cannot name one tenant.
    None when the values are not both numbers or differ as numbers.
    """
    if not (_is_number(probe) and _is_number(owner)):
        return None
    try:
        if float(probe) != float(owner):
            return None
    except OverflowError:
        return None
    # Python compares int and float exactly, not by rounding the int.
    if probe == owner and abs(probe) < _EXACT_FLOAT_LIMIT:
        return "same_value"
    return "collision"


def _numeric_diagnosis(pairs: Mapping[tuple[str, Optional[str]], set[str]],
                       values: Mapping[str, Any]) -> dict[str, list[dict]]:
    """Classify each (probing tenant, leaked owner) pair by ``_numeric_relation``."""
    out: dict[str, list[dict]] = {"collision": [], "same_value": []}
    for (probe, owner), ids in sorted(pairs.items(), key=lambda kv: (kv[0][0], kv[0][1] or "")):
        if owner is None or probe not in values or owner not in values:
            continue
        kind = _numeric_relation(values[probe], values[owner])
        if kind is None:
            continue
        out[kind].append({"probe_tenant": probe, "probe_type": _type_name(values[probe]),
                          "leaked_tenant": owner, "leaked_type": _type_name(values[owner]),
                          "chunks": len(ids)})
    return out


def _type_name(value: Any) -> str:
    return "float" if isinstance(value, float) else "integer"


def _stored_as(value: Any) -> str:
    return "a floating-point number" if isinstance(value, float) else "an integer"


def _quoted(names) -> str:
    names = [f"'{n}'" for n in names]
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]


def _collision_text(rows: list[dict], values: Mapping[str, Any]) -> str:
    """Name the stored values that collide and why, from the observed pairs."""
    returned_to: dict[str, set[str]] = {}  # float value -> tenants whose filter returned it
    equal_to: dict[str, set[str]] = {}     # float value -> every value it met
    plain: set[tuple[str, str]] = set()    # collisions with no float side
    for row in rows:
        probe, owner = row["probe_tenant"], row["leaked_tenant"]
        if row["leaked_type"] == "float" and row["probe_type"] != "float":
            returned_to.setdefault(owner, set()).add(probe)
            equal_to.setdefault(owner, set()).add(probe)
        elif row["probe_type"] == "float" and row["leaked_type"] != "float":
            equal_to.setdefault(probe, set()).add(owner)
        else:
            plain.add((min(probe, owner), max(probe, owner)))
    parts = []
    for value, others in sorted(equal_to.items()):
        reached = sorted(returned_to.get(value, ()))
        if len(reached) > 1:
            parts.append(f"Chunks tagged '{value}' (stored as a floating-point number) are "
                         f"returned to queries filtered to {_quoted(reached)}, distinct "
                         "tenants that both equal it as the store compares them: whichever "
                         "tenant those chunks belong to, the other receives them.")
        else:
            parts.append(f"'{value}' (stored as a floating-point number) equals "
                         f"{_quoted(sorted(others))} as the store compares them.")
    for left, right in sorted(plain):
        parts.append(f"'{left}' ({_stored_as(values[left])}) and '{right}' "
                     f"({_stored_as(values[right])}) are distinct identifiers that are "
                     "equal once converted to floating point.")
    magnitude = max((abs(values[name]) for row in rows
                     for name in (row["probe_tenant"], row["leaked_tenant"])), default=0)
    if magnitude >= _EXACT_FLOAT_LIMIT:
        spacing = int(math.ulp(float(magnitude)))
        parts.append(f"The store compares tenant values as numbers, and identifiers above "
                     f"2^53 ({_EXACT_FLOAT_LIMIT:,}) lose precision as floating point: near "
                     f"{float(magnitude):.1e} representable values are {spacing:,} apart, so "
                     "distinct tenants' ids collapse onto the same number.")
    else:
        parts.append("The store compares tenant values as numbers, so values that differ "
                     "as stored can still select each other's chunks.")
    return " ".join(parts)


def _imprecise_float_finding(store, collection: str, field_name: str, names: list[str],
                            values: Mapping[str, Any]) -> Finding:
    magnitude = max(abs(values[name]) for name in names)
    spacing = int(math.ulp(float(magnitude)))
    subject = (f"{_quoted(names[:_EXAMPLES])} "
               + ("is" if len(names) == 1 else "are"))
    return Finding(
        id=f"find-{uuid.uuid4().hex[:10]}",
        title=f"Tenant ids stored as imprecise floating point in '{collection}'",
        severity=Severity.MEDIUM, category="isolation", store=store.name,
        collection=collection,
        description=(
            f"{subject} stored in '{field_name}' as floating point at or beyond 2^53 "
            f"({_EXACT_FLOAT_LIMIT:,}). Near {float(magnitude):.1e} representable values "
            f"are {spacing:,} apart, so each such value stands for every integer id that "
            "rounds to it: distinct tenants whose ids were written through a "
            "floating-point path (JSON, JavaScript) carry the same stored value, and "
            "neither the store's filter nor this check can tell their chunks apart. "
            "Isolation for these values cannot be verified."),
        evidence={"cause": "imprecise_float_tenant",
                  "tenants": names[:MAX_LISTED_TENANTS],
                  "exact_float_limit": _EXACT_FLOAT_LIMIT, "spacing": spacing},
        remediation=(
            f"Store '{field_name}' as a string (or as an exact integer in every ingestion "
            "path, never as floating point), re-tag the affected chunks with their "
            "owner's exact identifier from the source system, and reject floating-point "
            "tenant values at ingestion."),
    )


def _same_value_text(rows: list[dict]) -> str:
    pairs = sorted({tuple(sorted((r["probe_tenant"], r["leaked_tenant"]))) for r in rows})
    named = "; ".join(f"'{a}' and '{b}'" for a, b in pairs[:_EXAMPLES])
    return f"the same number stored as an integer and as a float ({named})"


def _same_value_finding(store, collection, field_name, leaking, leaked, examples, sweep,
                        rows) -> Finding:
    count = sum(len(leaked.get(t, ())) for t in leaking)
    return Finding(
        id=f"find-{uuid.uuid4().hex[:10]}",
        title=f"Tenant values stored with two numeric types in '{collection}'",
        severity=Severity.MEDIUM, category="isolation", store=store.name,
        collection=collection,
        description=(
            f"Queries filtered to {_quoted(leaking[:_EXAMPLES])} returned "
            f"{_n(count, 'chunk')} tagged with {_same_value_text(rows)}. The store "
            f"compares '{field_name}' values as numbers, so its filter treats each such "
            "pair as one tenant. This is most likely one tenant written with two types by "
            "different ingestion paths rather than a cross-tenant leak, but the check "
            "tells tenants apart by their stored value and cannot confirm it; if they "
            "are different tenants, each can retrieve the other's data."),
        evidence={"cause": "numeric_type_mismatch", "same_value_pairs": rows[:_EXAMPLES],
                  "leaking_tenants": leaking[:MAX_LISTED_TENANTS],
                  "examples": examples[:_EXAMPLES],
                  "bleeds": sum(len(ids) for ids in leaked.values()),
                  "method": sweep["method"], "cross_tenant_queries": sweep["queries"]},
        remediation=(
            f"Confirm these values identify the same tenant, then write '{field_name}' "
            "with one type in every ingestion path (a string, or an exact integer) and "
            "re-tag the chunks written with the other type."),
    )


def _not_enforced_finding(store, collection, field_name, canary_ids, leaking, leaked,
                          examples, sweep, numeric=None, values=None) -> Finding:
    if canary_ids:
        what = (f"A query filtered to a '{field_name}' value that no chunk carries returned "
                f"{_n(len(canary_ids), 'chunk')}: the store does not apply the filter.")
    else:
        what = ""
    if leaking:
        named = ", ".join(f"'{t}'" for t in leaking[:_EXAMPLES])
        more = f" and {len(leaking) - _EXAMPLES:,} more" if len(leaking) > _EXAMPLES else ""
        count = sum(len(leaked.get(t, ())) for t in leaking)
        what = (what + " " if what else "") + (
            f"Queries filtered to {named}{more} returned {_n(count, 'chunk')} belonging "
            "to other tenants or carrying no tenant value.")
    # Chunk ids and tenant names only: never the leaked chunk's content.
    evidence = {"canary_hits": canary_ids[:_EXAMPLES], "leaking_tenants":
                leaking[:MAX_LISTED_TENANTS], "examples": examples[:_EXAMPLES],
                "bleeds": sum(len(ids) for ids in leaked.values()),
                "method": sweep["method"],
                "cross_tenant_queries": sweep["queries"]}
    remediation = (
        "Do not rely on metadata filters for tenant isolation in this store. Use "
        "physically separate collections/namespaces (or databases) per tenant, and "
        "verify the filter pushdown.")
    numeric = numeric or {}
    if numeric.get("collision"):
        what += " " + _collision_text(numeric["collision"], values or {})
        evidence["cause"] = "numeric_tenant_collision"
        evidence["colliding_values"] = numeric["collision"][:_EXAMPLES]
        remediation = (
            f"Store '{field_name}' as a string (or as an exact integer in every ingestion "
            "path, never as floating point), re-tag the affected chunks with their owner's "
            "exact identifier from the source system, and reject floating-point tenant "
            "values at ingestion. Until then the filter cannot separate these tenants; "
            "separate collections or namespaces per tenant do not depend on it.")
    if numeric.get("same_value"):
        what += (f" Some of these chunks are tagged with {_same_value_text(numeric['same_value'])}, "
                 "which may be one tenant written with two types.")
        evidence["same_value_pairs"] = numeric["same_value"][:_EXAMPLES]
    return Finding(
        id=f"find-{uuid.uuid4().hex[:10]}",
        title=f"Tenant filter NOT enforced in '{collection}'",
        severity=Severity.CRITICAL, category="isolation", store=store.name,
        collection=collection,
        description=what + " Cross-tenant data is directly retrievable.",
        evidence=evidence,
        remediation=remediation,
    )


def _convention_only_finding(store, collection, tenants, enforcement, verified,
                             seen_tenants, cross) -> Finding:
    count = len(tenants)
    if enforcement == "verified" and len(verified) == count:
        filt = (f"The store enforces the filter for {_all(len(verified))}, verified "
                "chunk by chunk, but isolation still depends on every query carrying it.")
    elif enforcement == "violated":
        filt = "The store does not reliably enforce the filter either (see the CRITICAL finding)."
    elif enforcement == "ambiguous":
        filt = ("Some tenant values are the same number stored with two types, so whether "
                "they are one tenant could not be confirmed (see the MEDIUM finding), and "
                "isolation still depends on every query carrying the filter.")
    else:
        filt = (f"The store's filter was verified for {len(verified):,} of {count:,} "
                "tenants, and isolation still depends on every query carrying it.")
    return Finding(
        id=f"find-{uuid.uuid4().hex[:10]}",
        title=f"Tenant isolation is convention-only in '{collection}'",
        severity=Severity.HIGH, category="isolation", store=store.name,
        collection=collection,
        description=(
            f"{count:,} tenants share one collection, so any query that omits the tenant "
            "filter can return other tenants' chunks (a query without it returned "
            f"chunks from {_n(len(seen_tenants), 'tenant')}). {filt}"),
        evidence={"tenants": tenants[:MAX_LISTED_TENANTS], "tenant_count": count,
                  "filter_enforcement": enforcement,
                  "unfiltered_tenants_returned": seen_tenants[:MAX_LISTED_TENANTS],
                  "examples": cross},
        remediation=(
            "Enforce the tenant filter server-side (per-tenant API keys or namespaces), "
            "or move each tenant to its own collection so isolation is structural rather "
            "than convention-based."),
    )


def _ann_post_filter_finding(store, collection, field_name, ann: dict,
                             retry: dict[str, dict]) -> Finding:
    """LOW: filtered searches on an approximate index can come back short."""
    from vecshield_platform.posture.pg_hardening import pg_rules

    rule = pg_rules("tenant_isolation")["ann_filter_without_iterative_scan"]
    index_type = ann.get("index_type")
    setting = f"{index_type}.iterative_scan"
    mode = "strict_order" if index_type == "hnsw" else "relaxed_order"
    recovered = [t for t, e in retry.items() if e["result"] == "recall_loss"]
    observed = ""
    if retry:
        observed = (f" In this check {_n(len(retry), 'tenant view')} came back short with "
                    f"{setting} off; with it on, {len(recovered)} of them were whole.")
    upgrade = ("" if ann.get("iterative_scan_supported") else
               " Iterative scans need pgvector 0.8.0 or later; this server runs "
               f"{ann.get('pgvector_version') or 'an unknown version'}.")
    return Finding(
        id=f"find-{uuid.uuid4().hex[:10]}",
        title=f"Filtered searches on the approximate index can come back short in "
              f"'{collection}'",
        severity=Severity(rule["severity"]), category="isolation", store=store.name,
        collection=collection,
        description=(f"'{collection}' is searched through {index_type} index "
                     f"'{ann.get('index')}' with {setting} off. pgvector applies the "
                     f"'{field_name}' filter to the rows the index returns, so a tenant's "
                     "search can return fewer results than asked for, or none, when other "
                     "tenants' chunks fill the scan. This is lost recall, not a leak: other "
                     "tenants' rows are filtered out, never returned." + observed + upgrade),
        evidence={"rule": rule["id"], "source_url": rule["source_url"],
                  "quote": rule["quote"], "index_type": index_type,
                  "index": ann.get("index"), "metric": ann.get("metric"),
                  "iterative_scan": ann.get("iterative_scan"),
                  "settings": ann.get("settings") or {},
                  "short_views_retried": len(retry), "recall_loss": sorted(recovered),
                  "leaks_data": False},
        remediation=(f"Turn on iterative index scans for the role the application "
                     f"searches as: ALTER ROLE <app role> SET {setting} = {mode} "
                     "(or SET LOCAL per transaction). Alternatively, give large tenants "
                     "a partial index or a partition of their own." + upgrade),
    )


def _untagged_finding(store, collection, field_name, untagged) -> Finding:
    subject = (f"{untagged:,} chunks carry" if untagged != 1 else "1 chunk carries")
    return Finding(
        id=f"find-{uuid.uuid4().hex[:10]}",
        title=f"Chunks without a tenant value in '{collection}'",
        severity=Severity.MEDIUM, category="isolation", store=store.name,
        collection=collection,
        description=(f"{subject} no '{field_name}' value: every unfiltered query can return "
                     f"{'it' if untagged == 1 else 'them'}, and no tenant's filtered view "
                     f"includes {'it' if untagged == 1 else 'them'}."),
        evidence={"untagged": untagged, "tenant_field": field_name},
        remediation=(
            f"Assign each of these chunks the '{field_name}' of the tenant that owns it, or "
            "move shared content to a collection of its own, and make the ingest "
            "pipeline reject chunks without a tenant value."),
    )


def _no_tenant_field_finding(store, collection, field_name, scanned) -> Finding:
    return Finding(
        id=f"find-{uuid.uuid4().hex[:10]}",
        title=f"Tenant isolation NOT verified in '{collection}'",
        severity=Severity.MEDIUM, category="coverage", store=store.name,
        collection=collection,
        description=(f"None of the {_n(scanned, 'chunk')} read carries a '{field_name}' value, "
                     "so tenant membership is unknown and isolation cannot be assessed on "
                     "this field. The configured tenant field may be wrong for this "
                     "collection."),
        remediation=("Confirm which metadata field identifies the tenant in this "
                     "collection and run the check with that field."),
        evidence={"tenant_field": field_name, "chunks_examined": scanned},
    )


def _no_query_reason(connector: Connector) -> str:
    base = f"{connector.kind} does not support vector query()"
    if connector.kind == "vertex_ai":
        return base + " until an index endpoint is configured (set endpoint_id)"
    return base


def _skip_finding(store, collection: str, tenant_field: str, reason: str) -> Finding:
    """Coverage finding for when isolation cannot be checked.

    Mirrors the scan engine's treatment of inventory-only stores: never let an
    inability to check look like a clean result.
    """
    return Finding(
        id=f"find-{uuid.uuid4().hex[:10]}",
        title=f"Tenant isolation NOT verified in '{collection}'",
        severity=Severity.MEDIUM,
        category="coverage",
        store=store.name,
        collection=collection,
        description=(
            f"The isolation check could not run: {reason}. A missing result is "
            f"NOT evidence of isolation — cross-tenant bleed on '{tenant_field}' "
            f"remains unverified for this store."
        ),
        remediation=(
            "Run the check with a query- and content-capable connector pointed "
            "at this data (e.g. the backing pgvector/OpenSearch store), or "
            "configure this connector's query endpoint."
        ),
        evidence={"kind": store.kind, "reason": reason},
    )
