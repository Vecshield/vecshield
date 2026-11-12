"""Tenant isolation verification.

The engine enumerates a collection, runs one canary query, one full-view
filtered query per tenant, a cross-tenant sweep (every chunk's own vector under
every other tenant's filter) and one unfiltered query, and records a structured
outcome. Fakes cover each result the store can give; a persistent Chroma
collection shows the engine reaching exhaustive verification on a real store.
"""

from __future__ import annotations

import pytest

from vecshield.models import Chunk, Collection, QueryHit, Severity, VectorStore
from vecshield_platform.access import probe_isolation
from vecshield_platform.access.isolation import IsolationLimits
from vecshield_platform.connectors.base import Connector
from vecshield_platform.connectors.chroma import ChromaConnector


def _emb(seed: int, dim: int = 8) -> list[float]:
    return [((seed * (i + 7)) % 97) / 97.0 for i in range(dim)]


def outcome_of(job) -> dict:
    [item] = [o for o in job.stats["check_outcomes"] if o["check"] == "tenant_isolation"]
    return item


def sev(job, severity):
    return [f for f in job.findings if f.severity == severity]


# --------------------------------------------------------------------------- #
# fakes                                                                       #
# --------------------------------------------------------------------------- #

def _numeric_match(stored, wanted) -> bool:
    """Chroma's metadata equality, as observed in chromadb 1.5."""
    def number(v):
        return isinstance(v, (int, float)) and not isinstance(v, bool)
    if number(stored) and number(wanted):
        if isinstance(stored, int) and isinstance(wanted, int):
            return stored == wanted
        return float(stored) == float(wanted)
    return type(stored) is type(wanted) and stored == wanted


class FakeStore(Connector):
    """In-memory store whose filter behaviour is chosen per test.

    ``filter_mode``: "enforced" applies ``where`` exactly; "ignored" drops it;
    "numeric" compares like Chroma: integer with integer exactly, an integer
    with a float by value as float64, strings only with strings.
    ``leak``: tenant -> ids of other chunks a query filtered to it also returns.
    ``recall``: the most results a filtered query returns (simulated ANN loss).
    """

    kind = "fake"

    def __init__(self, chunks, *, filter_mode="enforced", leak=None, recall=None,
                 max_top_k=None, can_query=True, name="shared", fail_on_call=None,
                 second_read=None):
        self.chunks = list(chunks)
        self.fail_on_call = fail_on_call
        self.second_read = second_read
        self.reads = 0
        self.filter_mode = filter_mode
        self.leak = leak or {}
        self.recall = recall
        self.max_top_k = max_top_k
        self.can_query = can_query
        self.name = name
        self.calls: list[dict] = []

    def capabilities(self):
        return {"query"} if self.can_query else set()

    def describe(self):
        return VectorStore(kind=self.kind, name="fake://store", endpoint="fake://store",
                           collections=self.list_collections())

    def list_collections(self):
        return [Collection(name=self.name, count=len(self.chunks))]

    def iter_chunks(self, collection, batch_size=256):
        self.reads += 1
        if self.reads > 1 and self.second_read is not None:
            yield from self.second_read
            return
        yield from self.chunks

    def query(self, collection, vector, top_k=10, where=None):
        if self.max_top_k is not None:
            assert top_k <= self.max_top_k, "engine exceeded the connector's cap"
        if self.fail_on_call is not None and len(self.calls) == self.fail_on_call:
            self.fail_on_call = None  # one transient failure
            raise ConnectionError("store went away")
        self.calls.append({"top_k": top_k, "where": dict(where) if where else None,
                           "vector": list(vector)})
        pool = self.chunks
        if where and self.filter_mode == "enforced":
            [(field, value)] = where.items()
            pool = [c for c in pool if c.metadata.get(field) == value]
        elif where and self.filter_mode == "numeric":
            [(field, value)] = where.items()
            pool = [c for c in pool if _numeric_match(c.metadata.get(field), value)]
        if where and self.filter_mode in ("enforced", "numeric"):
            extra = set(self.leak.get(value, ()))
            pool = pool + [c for c in self.chunks if c.id in extra]
            if self.recall is not None:
                pool = pool[: self.recall]

        def score(c):
            # Negative Euclidean distance: a chunk's own vector ranks it first,
            # as in any exact nearest-neighbour search.
            return -sum((a - b) ** 2 for a, b in zip(vector, c.embedding or [])) ** 0.5

        ranked = sorted(pool, key=lambda c: (-score(c), c.id))[:top_k]
        return [QueryHit(id=c.id, score=score(c), metadata=dict(c.metadata)) for c in ranked]


def tenant_chunks(counts: dict, field="tenant_id", start=0) -> list[Chunk]:
    out, seed = [], start
    for tenant, n in counts.items():
        for i in range(n):
            seed += 1
            out.append(Chunk(id=f"{tenant}-{i}", collection="shared", text="t",
                             embedding=_emb(seed), metadata={field: tenant}))
    return out


def untagged_chunks(n: int) -> list[Chunk]:
    return [Chunk(id=f"u-{i}", collection="shared", text="t", embedding=_emb(500 + i),
                  metadata={"source": "wiki"}) for i in range(n)]


THREE = {"acme": 4, "globex": 3, "initech": 5}


# --------------------------------------------------------------------------- #
# verified enforcement, shared collection                                    #
# --------------------------------------------------------------------------- #

def test_enforced_shared_collection_is_failed_but_completely_verified():
    conn = FakeStore(tenant_chunks(THREE))
    job = probe_isolation(conn, "shared", tenant_field="tenant_id")
    out = outcome_of(job)

    assert out["outcome"] == "failed"  # HIGH: convention-only by construction
    assert out["coverage"]["complete"] is True
    cov = out["coverage"]
    assert cov["filter_enforcement"] == "verified"
    assert cov["canary"] == "passed"
    assert cov["structure"] == "shared"
    assert cov["tenant_count"] == 3 and cov["tenants"] == ["acme", "globex", "initech"]
    assert cov["chunks_examined"] == cov["total_chunks"] == 12
    assert cov["untagged"] == 0 and cov["enumeration_capped"] is False
    assert cov["top_k_cap"] == 10000
    assert [row["verified"] for row in cov["per_tenant"]] == [True, True, True]
    assert {row["tenant"]: row["returned"] for row in cov["per_tenant"]} == THREE
    # Every chunk under every other tenant's filter: 4*2 + 3*2 + 5*2.
    assert cov["method"] == "exhaustive" and cov["sampled"] is False
    assert cov["cross_tenant_pairs"] == cov["cross_tenant_queries"] == 24
    assert {r["tenant"]: r["cross_tenant_queries"] for r in cov["per_tenant"]} == {
        "acme": 8, "globex": 9, "initech": 7}
    assert cov["bleeds"] == 0
    assert out["reason"] == ("Isolation verified exhaustively: 12 chunks across 3 tenants, "
                             "24 cross-tenant queries, 0 bleeds; 3 tenants share this "
                             "collection, so isolation depends on every query carrying "
                             "the filter.")

    [high] = sev(job, Severity.HIGH)
    assert high.category == "isolation" and "convention-only" in high.title
    assert "enforces the filter for all 3 tenants, verified chunk by chunk" in high.description
    assert "still depends on every query carrying it" in high.description
    assert high.evidence["examples"]
    assert not sev(job, Severity.CRITICAL)
    assert job.stats["coverage"]["complete"] is True


def test_query_plan_is_bounded_and_sized_to_the_collection():
    chunks = tenant_chunks(THREE)
    conn = FakeStore(chunks)
    probe_isolation(conn, "shared", tenant_field="tenant_id")
    # canary, 3 full views, 24 cross-tenant queries, one unfiltered self-rank
    # check per chunk (12), and the unfiltered structure query.
    assert len(conn.calls) == 1 + 3 + 24 + 12 + 1
    canary, *rest, unfiltered = conn.calls
    full_view = rest[:3]
    sweep = [c for c in rest[3:] if c["where"] is not None]
    self_rank = [c for c in rest[3:] if c["where"] is None]
    assert len(self_rank) == 12
    assert {c["top_k"] for c in self_rank} == {1 + IsolationLimits().sweep_margin}
    assert canary["where"]["tenant_id"].startswith("__vecshield_isolation_canary_")
    assert [c["where"]["tenant_id"] for c in full_view] == ["acme", "globex", "initech"]
    assert unfiltered["where"] is None
    assert {c["top_k"] for c in (canary, *full_view, unfiltered)} == {12}
    # Sweep: one byte-identical copy of each vector plus the default margin.
    assert {c["top_k"] for c in sweep} == {1 + IsolationLimits().sweep_margin}
    # Every chunk's own vector, under exactly the tenants that do not own it.
    owner = {tuple(c.embedding): c.metadata["tenant_id"] for c in chunks}
    pairs = {(tuple(c["vector"]), c["where"]["tenant_id"]) for c in sweep}
    assert len(pairs) == 24
    assert all(owner[vec] != tenant for vec, tenant in pairs)
    assert {vec for vec, _ in pairs} == set(owner)


def test_duplicate_vectors_widen_the_sweep_query():
    chunks = tenant_chunks({"acme": 2, "globex": 2})
    same = chunks[0].embedding
    chunks[2] = Chunk(id="globex-0", collection="shared", embedding=list(same),
                      metadata={"tenant_id": "globex"})
    conn = FakeStore(chunks)
    job = probe_isolation(conn, "shared", tenant_field="tenant_id",
                          limits=IsolationLimits(sweep_margin=0))
    sweep = conn.calls[3:-1]
    widths = {tuple(c["vector"]) == tuple(same): c["top_k"] for c in sweep}
    assert widths == {True: 2, False: 1}
    assert outcome_of(job)["coverage"]["complete"] is True


# --------------------------------------------------------------------------- #
# violations                                                                  #
# --------------------------------------------------------------------------- #

def test_ignored_filter_fails_the_canary_and_is_critical():
    conn = FakeStore(tenant_chunks(THREE), filter_mode="ignored")
    job = probe_isolation(conn, "shared", tenant_field="tenant_id")
    out = outcome_of(job)
    [crit] = sev(job, Severity.CRITICAL)
    assert "NOT enforced" in crit.title
    assert "no chunk carries" in crit.description
    assert crit.evidence["canary_hits"]
    assert out["outcome"] == "failed"
    assert out["coverage"]["canary"] == "failed"
    assert out["coverage"]["filter_enforcement"] == "violated"
    assert out["coverage"]["complete"] is False
    assert out["reason"].startswith("The store ignored the tenant filter")


def test_filter_leaking_for_one_tenant_names_that_tenant():
    conn = FakeStore(tenant_chunks(THREE), leak={"globex": ["acme-0"]})
    job = probe_isolation(conn, "shared", tenant_field="tenant_id")
    out = outcome_of(job)
    [crit] = sev(job, Severity.CRITICAL)
    assert "'globex'" in crit.description and "'acme'" not in crit.description
    assert crit.evidence["leaking_tenants"] == ["globex"]
    assert crit.evidence["examples"][0] == {"probe_tenant": "globex",
                                            "leaked_tenant": "acme", "leaked_id": "acme-0",
                                            "query": "full_view"}
    rows = {r["tenant"]: r for r in out["coverage"]["per_tenant"]}
    assert rows["globex"]["foreign"] == 1 and rows["globex"]["verified"] is False
    assert rows["globex"]["bleeds"] == 1
    assert rows["acme"]["verified"] is True
    assert out["coverage"]["canary"] == "passed"
    assert out["coverage"]["filter_enforcement"] == "violated"
    assert out["coverage"]["bleeds"] == 1
    assert out["outcome"] == "failed"
    assert out["reason"] == ("Filtered queries for 1 of 3 tenants returned another tenant's "
                             "data (1 bleed; 24 cross-tenant queries in the cross-tenant "
                             "sweep).")


def test_filtered_result_containing_an_untagged_chunk_is_a_leak():
    chunks = tenant_chunks({"acme": 2, "globex": 2}) + untagged_chunks(1)
    conn = FakeStore(chunks, leak={"acme": ["u-0"]})
    job = probe_isolation(conn, "shared", tenant_field="tenant_id")
    [crit] = sev(job, Severity.CRITICAL)
    assert "'acme'" in crit.description
    assert crit.evidence["examples"][0]["leaked_tenant"] is None


# --------------------------------------------------------------------------- #
# numeric tenant values: collisions and mixed types                           #
# --------------------------------------------------------------------------- #

#: Snowflake-style merchant ids above 2**53: float(KESTREL) rounds to exactly
#: HARBOURLINE, so a float-typed Kestrel id is Harbourline's id as stored.
HARBOURLINE = 1541815603606036480
KESTREL = 1541815603606036521
BRIGHTMOOR = 1541815603606049307


def numeric_chunks(values: list) -> list[Chunk]:
    return [Chunk(id=f"c{i}", collection="shared", text="t", embedding=_emb(i + 1),
                  metadata={"tenant_id": value}) for i, value in enumerate(values)]


def test_numeric_relation_classifies_what_the_store_would_match():
    from vecshield_platform.access.isolation import _numeric_relation

    assert float(KESTREL) == HARBOURLINE  # the premise of the collision
    assert _numeric_relation(HARBOURLINE, float(KESTREL)) == "collision"
    assert _numeric_relation(KESTREL, float(KESTREL)) == "collision"
    assert _numeric_relation(1042, 1042.0) == "same_value"
    assert _numeric_relation(1042, 1043) is None
    assert _numeric_relation("1042", 1042) is None
    assert _numeric_relation(True, 1) is None


def test_ids_beyond_2_53_stored_as_float_collide_and_are_critical_with_cause():
    values = ([HARBOURLINE] * 2 + [float(KESTREL)] * 2 + [KESTREL] + [BRIGHTMOOR] * 2)
    job = probe_isolation(FakeStore(numeric_chunks(values), filter_mode="numeric"),
                          "shared", tenant_field="tenant_id")
    out = outcome_of(job)
    [crit] = sev(job, Severity.CRITICAL)
    assert crit.title == "Tenant filter NOT enforced in 'shared'"
    assert crit.evidence["cause"] == "numeric_tenant_collision"
    pairs = {(r["probe_tenant"], r["probe_type"], r["leaked_tenant"], r["leaked_type"])
             for r in crit.evidence["colliding_values"]}
    as_float = str(float(KESTREL))
    assert (str(HARBOURLINE), "integer", as_float, "float") in pairs
    assert (str(KESTREL), "integer", as_float, "float") in pairs
    # The float-tagged chunks reach two distinct integer tenants.
    assert (f"Chunks tagged '{as_float}' (stored as a floating-point number) are returned "
            f"to queries filtered to '{HARBOURLINE}' and '{KESTREL}'") in crit.description
    assert "2^53 (9,007,199,254,740,992)" in crit.description
    assert "256 apart" in crit.description
    assert crit.description.endswith("Cross-tenant data is directly retrievable.")
    assert "as a string" in crit.remediation and "re-tag" in crit.remediation
    cov = out["coverage"]
    assert out["outcome"] == "failed" and cov["complete"] is False
    assert cov["filter_enforcement"] == "violated" and cov["bleeds"] > 0
    rows = {r["tenant"]: r for r in cov["per_tenant"]}
    assert rows[str(BRIGHTMOOR)]["verified"] is True  # its id collides with nothing
    assert out["reason"].startswith("Filtered queries for 3 of 4 tenants returned another "
                                    "tenant's data")
    assert "floating point" in out["reason"] and out["reason"].endswith(".")


def test_same_integer_written_as_int_and_float_is_not_asserted_as_a_leak():
    values = [1042, 1042, 1042.0, 1042.0, 2077, 2077]
    job = probe_isolation(FakeStore(numeric_chunks(values), filter_mode="numeric"),
                          "shared", tenant_field="tenant_id")
    out = outcome_of(job)
    assert not sev(job, Severity.CRITICAL)
    [medium] = [f for f in sev(job, Severity.MEDIUM) if f.category == "isolation"]
    assert medium.title == "Tenant values stored with two numeric types in 'shared'"
    assert medium.evidence["cause"] == "numeric_type_mismatch"
    assert {(r["probe_tenant"], r["leaked_tenant"])
            for r in medium.evidence["same_value_pairs"]} == {("1042", "1042.0"),
                                                              ("1042.0", "1042")}
    assert "'1042' and '1042.0'" in medium.description
    assert "most likely one tenant written with two types" in medium.description
    assert "cross-tenant data is directly retrievable" not in medium.description.lower()
    [high] = sev(job, Severity.HIGH)
    assert "see the MEDIUM finding" in high.description
    cov = out["coverage"]
    assert cov["filter_enforcement"] == "ambiguous"
    assert cov["complete"] is False and cov["bleeds"] == 4
    assert out["outcome"] == "failed"  # the HIGH convention-only finding still stands
    assert "may be one tenant written with two types" in out["reason"]
    assert "no cross-tenant leak is asserted" in out["reason"]
    assert out["reason"].endswith(".") and "(s)" not in out["reason"]


def test_same_value_pair_beside_a_real_leak_stays_critical():
    values = [1042, 1042.0, 2077, 2077]
    job = probe_isolation(FakeStore(numeric_chunks(values), filter_mode="numeric",
                                    leak={2077: ["c0"]}),
                          "shared", tenant_field="tenant_id")
    [crit] = sev(job, Severity.CRITICAL)
    assert "cause" not in crit.evidence  # the 2077 leak is not a numeric artefact
    assert crit.evidence["same_value_pairs"]
    assert "may be one tenant written with two types" in crit.description
    assert outcome_of(job)["coverage"]["filter_enforcement"] == "violated"


def test_string_tenants_are_unchanged_by_the_numeric_diagnosis():
    job = probe_isolation(FakeStore(tenant_chunks(THREE), leak={"globex": ["acme-0"]}),
                          "shared", tenant_field="tenant_id")
    [crit] = sev(job, Severity.CRITICAL)
    assert "cause" not in crit.evidence and "colliding_values" not in crit.evidence
    assert "same_value_pairs" not in crit.evidence
    assert crit.remediation.startswith("Do not rely on metadata filters")
    assert crit.description == ("Queries filtered to 'globex' returned 1 chunk belonging "
                                "to other tenants or carrying no tenant value. "
                                "Cross-tenant data is directly retrievable.")
    # Numeric-looking strings are strings: the store keeps them apart.
    job = probe_isolation(FakeStore(numeric_chunks(["1042", "1042", "1042.0", "1042.0"]),
                                    filter_mode="numeric"),
                          "shared", tenant_field="tenant_id")
    assert outcome_of(job)["coverage"]["filter_enforcement"] == "verified"
    assert not [f for f in job.findings if (f.evidence or {}).get("cause")]


# --------------------------------------------------------------------------- #
# partial verification                                                        #
# --------------------------------------------------------------------------- #

def test_ann_returning_fewer_is_partially_verified_not_complete():
    conn = FakeStore(tenant_chunks(THREE), recall=4)  # initech holds 5
    job = probe_isolation(conn, "shared", tenant_field="tenant_id")
    out = outcome_of(job)
    cov = out["coverage"]
    assert cov["filter_enforcement"] == "partially_verified"
    assert cov["complete"] is False and cov["status"] == "partial"
    assert not sev(job, Severity.CRITICAL)
    assert out["outcome"] == "failed"  # still shared: HIGH
    rows = {r["tenant"]: r for r in cov["per_tenant"]}
    assert rows["initech"] == {"tenant": "initech", "chunks": 5, "returned": 4,
                               "foreign": 0, "unattributed": 0,
                               "cross_tenant_queries": 7, "bleeds": 0, "verified": False}
    assert out["reason"].startswith("No bleed was observed, but isolation was not "
                                    "verified exhaustively")
    assert "approximate search" in out["reason"]
    assert "verified for 2 of 3 tenants" in out["reason"]
    [high] = sev(job, Severity.HIGH)
    assert "verified for 2 of 3 tenants" in high.description


def test_tenant_larger_than_the_store_cap_is_still_verified_by_the_sweep():
    # A full view cannot return all 7 of globex's chunks under a cap of 5, but
    # the sweep does not need it to: each of acme's chunks is asked for under
    # globex's filter individually.
    conn = FakeStore(tenant_chunks({"acme": 3, "globex": 7}), max_top_k=5)
    job = probe_isolation(conn, "shared", tenant_field="tenant_id")
    out = outcome_of(job)
    assert out["coverage"]["top_k_cap"] == 5
    assert max(c["top_k"] for c in conn.calls) == 5
    assert out["coverage"]["filter_enforcement"] == "verified"
    assert out["coverage"]["complete"] is True


def test_leak_hidden_from_a_capped_full_view_is_caught_by_the_sweep():
    # globex's filter admits acme-0, but globex holds more chunks than the cap,
    # so its full view fills up with its own chunks before acme-0 appears.
    chunks = [Chunk(id=f"globex-{i}", collection="shared", embedding=[1.0, i / 100, 0.0],
                    metadata={"tenant_id": "globex"}) for i in range(7)]
    chunks += [Chunk(id=f"acme-{i}", collection="shared", embedding=[0.0, i / 100, 9.0],
                     metadata={"tenant_id": "acme"}) for i in range(3)]
    conn = FakeStore(chunks, max_top_k=5, leak={"globex": ["acme-0"]})
    job = probe_isolation(conn, "shared", tenant_field="tenant_id")
    out = outcome_of(job)
    [crit] = sev(job, Severity.CRITICAL)
    assert crit.evidence["examples"] == [{"probe_tenant": "globex", "leaked_tenant": "acme",
                                          "leaked_id": "acme-0", "query": "cross_tenant"}]
    assert out["outcome"] == "failed"
    assert out["coverage"]["filter_enforcement"] == "violated"
    rows = {r["tenant"]: r for r in out["coverage"]["per_tenant"]}
    assert rows["globex"]["foreign"] == 0 and rows["globex"]["bleeds"] == 1


def test_enumeration_cap_makes_the_result_partial():
    conn = FakeStore(tenant_chunks(THREE))
    job = probe_isolation(conn, "shared", tenant_field="tenant_id", max_chunks=6)
    out = outcome_of(job)
    cov = out["coverage"]
    assert cov["enumeration_capped"] is True
    assert cov["chunks_examined"] == 6
    assert cov["total_chunks"] == 12  # the store's own count
    assert cov["complete"] is False
    assert "only the first 6 chunks were read" in out["reason"]
    assert not sev(job, Severity.CRITICAL)


def test_capped_run_still_sees_tenants_it_did_not_enumerate():
    conn = FakeStore(tenant_chunks({"acme": 3, "globex": 4}))
    job = probe_isolation(conn, "shared", tenant_field="tenant_id", max_chunks=3)
    out = outcome_of(job)
    assert out["coverage"]["tenants"] == ["acme"]
    assert out["coverage"]["structure"] == "shared"
    [high] = sev(job, Severity.HIGH)
    assert high.evidence["tenants"] == ["acme", "globex"]
    assert out["outcome"] == "failed" and out["coverage"]["complete"] is False
    assert out["reason"] == ("No bleed was observed, but isolation was not verified "
                             "exhaustively: only the first 3 chunks were read (the run's "
                             "limit); 2 tenants share this collection, so isolation depends "
                             "on every query carrying the filter.")


def test_cap_with_a_violation_is_partial_but_still_failed():
    conn = FakeStore(tenant_chunks(THREE), filter_mode="ignored")
    job = probe_isolation(conn, "shared", tenant_field="tenant_id", max_chunks=6)
    out = outcome_of(job)
    assert out["outcome"] == "failed" and out["coverage"]["complete"] is False
    assert sev(job, Severity.CRITICAL)


# --------------------------------------------------------------------------- #
# nothing to isolate / nothing to isolate on                                  #
# --------------------------------------------------------------------------- #

def test_single_tenant_is_passed_and_complete():
    conn = FakeStore(tenant_chunks({"onlyco": 5}))
    job = probe_isolation(conn, "shared", tenant_field="tenant_id")
    out = outcome_of(job)
    assert out["outcome"] == "passed" and out["coverage"]["complete"] is True
    assert out["reason"] == ("Only one tenant's data is in this collection (all 5 chunks "
                             "read), so there is no other tenant's data to reach; "
                             "isolation is not applicable.")
    assert out["coverage"]["structure"] == "single_tenant"
    assert out["coverage"]["applicability"] == "not_applicable"
    assert job.max_severity == Severity.INFO
    assert conn.calls == []


def test_untagged_chunks_in_a_shared_collection_are_medium():
    chunks = tenant_chunks({"acme": 2, "globex": 2}) + untagged_chunks(3)
    job = probe_isolation(FakeStore(chunks), "shared", tenant_field="tenant_id")
    out = outcome_of(job)
    [medium] = [f for f in sev(job, Severity.MEDIUM) if f.category == "isolation"]
    assert medium.description == (
        "3 chunks carry no 'tenant_id' value: every unfiltered query can return them, "
        "and no tenant's filtered view includes them.")
    assert medium.remediation
    assert out["coverage"]["untagged"] == 3
    assert out["coverage"]["filter_enforcement"] == "verified"
    assert "3 chunks carry no 'tenant_id' value" in out["reason"]


def test_single_tenant_with_untagged_chunks_is_checked_not_waved_through():
    chunks = tenant_chunks({"acme": 3}) + untagged_chunks(1)
    conn = FakeStore(chunks)
    job = probe_isolation(conn, "shared", tenant_field="tenant_id")
    out = outcome_of(job)
    # canary, acme's full view, the untagged chunk's self-rank check, the
    # untagged chunk under acme's filter, unfiltered
    assert len(conn.calls) == 5
    assert conn.calls[2]["where"] is None
    assert conn.calls[3]["where"] == {"tenant_id": "acme"}
    assert out["outcome"] == "passed"  # MEDIUM does not fail the check
    assert out["reason"] == ("Isolation verified exhaustively: 4 chunks across 1 tenant, "
                             "1 cross-tenant query, 0 bleeds; 1 chunk carries no "
                             "'tenant_id' value.")
    assert any("1 chunk carries no" in f.description for f in sev(job, Severity.MEDIUM))
    assert out["coverage"]["complete"] is True


def test_no_tenant_field_anywhere_is_not_applicable():
    conn = FakeStore(untagged_chunks(4))
    job = probe_isolation(conn, "shared", tenant_field="tenant_id")
    out = outcome_of(job)
    assert out["outcome"] == "passed" and out["coverage"]["complete"] is True
    assert out["coverage"]["applicability"] == "not_applicable"
    assert out["reason"] == ("No chunk carries the tenant field 'tenant_id' and no other "
                             "tenant-like field varies across the 4 chunks, so this "
                             "collection is single-tenant; isolation is not applicable.")
    assert job.max_severity == Severity.INFO
    assert conn.calls == []


def test_tenants_mixed_under_another_field_are_inconclusive():
    chunks = [Chunk(id=f"c{i}", collection="shared", embedding=_emb(i),
                    metadata={"org_id": "north" if i % 2 else "south"}) for i in range(6)]
    job = probe_isolation(FakeStore(chunks), "shared", tenant_field="tenant_id")
    out = outcome_of(job)
    assert out["outcome"] == "inconclusive" and out["coverage"]["complete"] is False
    assert out["coverage"]["candidate_tenant_fields"] == ["org_id"]
    assert "'org_id' varies across chunks" in out["reason"]
    [medium] = sev(job, Severity.MEDIUM)
    assert medium.category == "isolation" and "mixed" in medium.title
    assert "'org_id'" in medium.remediation


def test_no_tenant_field_in_a_capped_read_is_inconclusive():
    job = probe_isolation(FakeStore(untagged_chunks(4)), "shared", tenant_field="tenant_id",
                          max_chunks=2)
    out = outcome_of(job)
    assert out["outcome"] == "inconclusive" and out["coverage"]["complete"] is False
    [cov] = [f for f in job.findings if f.category == "coverage"]
    assert cov.severity == Severity.MEDIUM and "may be wrong" in cov.description


def test_integer_tenant_values_get_an_integer_canary():
    chunks = [Chunk(id=f"c{i}", collection="shared", embedding=_emb(i),
                    metadata={"org": 7 if i < 3 else 9}) for i in range(6)]
    conn = FakeStore(chunks)
    job = probe_isolation(conn, "shared", tenant_field="org")
    canary = conn.calls[0]["where"]["org"]
    assert isinstance(canary, int) and canary not in (7, 9)
    assert [c["where"]["org"] for c in conn.calls[1:3]] == [7, 9]
    assert outcome_of(job)["coverage"]["filter_enforcement"] == "verified"


def test_uuid_tenant_values_get_a_uuid_canary():
    """pgvector returns a ``uuid`` column as UUID objects, and Postgres rejects
    any string that is not a UUID: a string canary failed the whole check."""
    import uuid

    acme, globex = uuid.uuid4(), uuid.uuid4()
    chunks = [Chunk(id=f"c{i}", collection="shared", embedding=_emb(i),
                    metadata={"org": acme if i < 3 else globex}) for i in range(6)]
    conn = FakeStore(chunks)
    job = probe_isolation(conn, "shared", tenant_field="org")
    canary = conn.calls[0]["where"]["org"]
    assert isinstance(canary, uuid.UUID) and canary not in (acme, globex)
    assert {c["where"]["org"] for c in conn.calls[1:3]} == {acme, globex}
    assert outcome_of(job)["coverage"]["filter_enforcement"] == "verified"


def test_reasons_are_plain_sentences():
    scenarios = [
        FakeStore(tenant_chunks(THREE)),
        FakeStore(tenant_chunks(THREE), filter_mode="ignored"),
        FakeStore(tenant_chunks(THREE), leak={"acme": ["globex-0"]}),
        FakeStore(tenant_chunks(THREE), recall=2),
        FakeStore(tenant_chunks({"a": 1})),
        FakeStore(untagged_chunks(2)),
        FakeStore(tenant_chunks({"a": 1, "b": 1}) + untagged_chunks(1)),
        FakeStore([], name="shared"),
        FakeStore([], can_query=False),
    ]
    for conn in scenarios:
        job = probe_isolation(conn, "shared", tenant_field="tenant_id")
        reason = outcome_of(job)["reason"]
        text = reason + " ".join(f.description for f in job.findings)
        assert "(s)" not in text and "sampl" not in text.lower(), reason
        assert reason.endswith(".") and reason[0].isupper()


# --------------------------------------------------------------------------- #
# skip / coverage paths                                                       #
# --------------------------------------------------------------------------- #

class _NoQueryConn(Connector):
    kind = "chroma"

    def capabilities(self):
        return {"delete"}

    def describe(self):
        return VectorStore(kind=self.kind, name="x://store", endpoint="x://store",
                           collections=[])

    def list_collections(self):
        return []

    def iter_chunks(self, collection, batch_size=256):
        return iter(())


class _InventoryOnlyConn(_NoQueryConn):
    kind = "vertex_ai"
    content_enumerable = False

    def capabilities(self):
        return {"query", "delete"}  # can query, but can't enumerate chunks

    def query(self, collection, vector, top_k=10, where=None):
        return []


def test_probe_skips_when_query_unsupported():
    job = probe_isolation(_NoQueryConn(), "c", tenant_field="tenant_id")
    assert job.stats["skipped"] is True
    cov = [f for f in job.findings if f.category == "coverage"]
    assert cov and cov[0].severity == Severity.MEDIUM
    assert "NOT verified" in cov[0].title
    out = outcome_of(job)
    assert out["outcome"] == "unsupported" and out["coverage"]["complete"] is False
    assert "does not support vector query()" in out["reason"]


def test_probe_skips_for_inventory_only_store():
    job = probe_isolation(_InventoryOnlyConn(), "c", tenant_field="tenant_id")
    assert job.stats["skipped"] is True
    cov = [f for f in job.findings if f.category == "coverage"]
    assert cov and "inventory only" in cov[0].description
    assert outcome_of(job)["outcome"] == "unsupported"


def test_vertex_without_endpoint_hints_endpoint_id():
    class _VertexNoEndpoint(_NoQueryConn):
        kind = "vertex_ai"

    job = probe_isolation(_VertexNoEndpoint(), "c", tenant_field="tenant_id")
    cov = [f for f in job.findings if f.category == "coverage"]
    assert cov and "endpoint_id" in cov[0].description


def test_legacy_top_k_argument_is_accepted_and_does_not_shrink_queries():
    conn = FakeStore(tenant_chunks(THREE))
    job = probe_isolation(conn, "shared", "tenant_id", top_k=2)
    assert conn.calls[-1]["where"] is None and conn.calls[-1]["top_k"] == 12
    assert min(c["top_k"] for c in conn.calls) == 1 + IsolationLimits().sweep_margin
    assert outcome_of(job)["coverage"]["complete"] is True


# --------------------------------------------------------------------------- #
# orchestrator                                                                #
# --------------------------------------------------------------------------- #

def test_full_audit_uses_the_engine_outcome_and_passes_the_chunk_cap():
    from vecshield.classify import RegexClassifier
    from vecshield_platform.orchestrator import run_full_audit

    def audit(**kw):
        conn = FakeStore(tenant_chunks(THREE))
        result = run_full_audit(conn, classifier=RegexClassifier(), tenant_field="tenant_id",
                                include_integrity=False, include_posture=False,
                                include_crypto=False, **kw)
        [iso] = [o for o in result.to_dict()["check_outcomes"]
                 if o["check"] == "tenant_isolation"]
        return iso

    full = audit()
    assert full["outcome"] == "failed" and full["coverage"]["complete"] is True
    assert full["coverage"]["filter_enforcement"] == "verified"
    assert "sampl" not in full["reason"].lower()

    capped = audit(max_chunks_per_collection=5)
    assert capped["coverage"]["enumeration_capped"] is True
    assert capped["coverage"]["complete"] is False


# --------------------------------------------------------------------------- #
# filter values reach stores as literals                                      #
# --------------------------------------------------------------------------- #

def test_redis_tag_values_are_escaped():
    from vecshield_platform.connectors.redis import _field_name, _tag_value

    assert _tag_value("acme} | @tenant:{globex") == r"acme\}\ \|\ \@tenant\:\{globex"
    assert _tag_value("__vecshield_isolation_canary_ab12") == "__vecshield_isolation_canary_ab12"
    with pytest.raises(ValueError):
        _field_name("tenant} | @x:{y")


def test_azure_odata_literals_are_escaped():
    from vecshield_platform.connectors.azure_search import _odata_field, _odata_literal

    assert _odata_literal("x' or tenant_id ne 'y") == "'x'' or tenant_id ne ''y'"
    assert _odata_literal(True) == "true" and _odata_literal(3) == "3"
    with pytest.raises(ValueError):
        _odata_field("tenant_id eq 'a' or true")


def test_milvus_string_literals_are_escaped():
    from vecshield_platform.connectors.milvus import _filter

    assert _filter({"tenant": 'a" or tenant != "b'}) == 'tenant == "a\\" or tenant != \\"b"'


# --------------------------------------------------------------------------- #
# a real store                                                                #
# --------------------------------------------------------------------------- #

@pytest.fixture
def multitenant_chroma(tmp_path):
    """One collection shared by two tenants, plus a single-tenant control."""
    import chromadb

    client = chromadb.PersistentClient(path=str(tmp_path / "chroma"))

    shared = client.create_collection("shared-rag")
    ids, embs, metas, docs = [], [], [], []
    for i in range(6):
        ids.append(f"acme-{i}")
        embs.append(_emb(i + 1))
        metas.append({"tenant_id": "acme"})
        docs.append(f"acme document {i}")
    for i in range(6):
        ids.append(f"globex-{i}")
        embs.append(_emb(i + 50))
        metas.append({"tenant_id": "globex"})
        docs.append(f"globex document {i}")
    shared.add(ids=ids, embeddings=embs, metadatas=metas, documents=docs)

    single = client.create_collection("single-tenant")
    single.add(
        ids=[f"s-{i}" for i in range(5)],
        embeddings=[_emb(i + 100) for i in range(5)],
        metadatas=[{"tenant_id": "onlyco"} for _ in range(5)],
        documents=[f"doc {i}" for i in range(5)],
    )

    return str(tmp_path / "chroma")


def test_chroma_shared_collection_is_completely_verified(multitenant_chroma):
    with ChromaConnector(path=multitenant_chroma) as conn:
        job = probe_isolation(conn, "shared-rag", tenant_field="tenant_id")

    assert set(job.stats["tenants"]) == {"acme", "globex"}
    out = outcome_of(job)
    cov = out["coverage"]
    assert out["outcome"] == "failed"
    assert cov["complete"] is True
    assert cov["filter_enforcement"] == "verified"
    assert cov["canary"] == "passed"
    assert cov["chunks_examined"] == 12
    assert [(r["tenant"], r["returned"], r["verified"]) for r in cov["per_tenant"]] == [
        ("acme", 6, True), ("globex", 6, True)]
    # Chroma honours the filter: convention-only (HIGH), never CRITICAL.
    [high] = sev(job, Severity.HIGH)
    assert "convention-only" in high.title and high.evidence["examples"]
    assert job.max_severity != Severity.CRITICAL


def test_chroma_numeric_tenant_collision_is_a_real_leak(tmp_path):
    """Chroma compares an int filter with a float value numerically, so a
    64-bit merchant id written as a float is returned to another merchant."""
    import chromadb

    path = str(tmp_path / "chroma")
    values = ([HARBOURLINE] * 3 + [KESTREL] * 2 + [float(KESTREL)] * 2 + [BRIGHTMOOR] * 2)
    chromadb.PersistentClient(path=path).create_collection("merchant-disputes").add(
        ids=[f"d{i}" for i in range(len(values))],
        embeddings=[_emb(i + 1) for i in range(len(values))],
        metadatas=[{"tenant_id": v} for v in values],
        documents=[f"dispute {i}" for i in range(len(values))])
    with ChromaConnector(path=path) as conn:
        job = probe_isolation(conn, "merchant-disputes", tenant_field="tenant_id")
    [crit] = sev(job, Severity.CRITICAL)
    assert crit.evidence["cause"] == "numeric_tenant_collision"
    # Harbourline's own filter returns the float-tagged Kestrel chunks.
    assert {e["leaked_id"] for e in crit.evidence["examples"]
            if e["probe_tenant"] == str(HARBOURLINE)} == {"d5", "d6"}
    cov = outcome_of(job)["coverage"]
    assert cov["tenant_count"] == 4 and cov["method"] == "exhaustive"
    assert cov["cross_tenant_queries"] == 9 * 3 and cov["bleeds"] > 0


def test_chroma_single_tenant_collection_is_info(multitenant_chroma):
    with ChromaConnector(path=multitenant_chroma) as conn:
        job = probe_isolation(conn, "single-tenant", tenant_field="tenant_id")
    assert job.max_severity == Severity.INFO
    assert job.stats["tenant_count"] == 1
    assert outcome_of(job)["outcome"] == "passed"


# --------------------------------------------------------------------------- #
# budget, configuration and failure paths of the cross-tenant sweep           #
# --------------------------------------------------------------------------- #

def test_budget_truncated_sweep_is_sampled_and_inconclusive():
    conn = FakeStore(tenant_chunks({"acme": 3, "globex": 3}))  # 6 chunks: 6 sweep pairs
    job = probe_isolation(conn, "shared", tenant_field="tenant_id", query_budget=3)
    out = outcome_of(job)
    cov = out["coverage"]
    assert cov["method"] == "sampled" and cov["sampled"] is True
    assert cov["cross_tenant_pairs"] == 6 and cov["query_budget"] == 3
    assert 0 < cov["cross_tenant_queries"] <= 3
    assert cov["complete"] is False and cov["filter_enforcement"] == "partially_verified"
    assert not sev(job, Severity.CRITICAL)
    # Still shared, so still failed (HIGH); the reason says the sweep was partial.
    assert out["outcome"] == "failed"
    assert out["reason"].startswith("No bleed was observed, but isolation was not verified "
                                    "exhaustively: the cross-tenant sweep needs 6 queries and "
                                    "the configured budget (VECSHIELD_ISOLATION_QUERY_BUDGET) "
                                    "is 3")


def test_budget_truncation_without_a_structural_finding_is_inconclusive_not_passed():
    chunks = tenant_chunks({"acme": 3}) + untagged_chunks(4)  # 4 pairs, one tenant
    job = probe_isolation(FakeStore(chunks), "shared", tenant_field="tenant_id",
                          query_budget=2)
    out = outcome_of(job)
    assert out["outcome"] == "inconclusive" and out["coverage"]["complete"] is False
    assert out["coverage"]["cross_tenant_queries"] <= 2


def test_sampled_selection_is_deterministic():
    def planned():
        conn = FakeStore(tenant_chunks(THREE))
        probe_isolation(conn, "shared", tenant_field="tenant_id", query_budget=10)
        return [(tuple(c["vector"]), c["where"]["tenant_id"]) for c in conn.calls[4:-1]
                if c["where"] is not None]

    assert planned() == planned()


def test_zero_budget_runs_no_sweep_and_is_partial():
    conn = FakeStore(tenant_chunks(THREE))
    job = probe_isolation(conn, "shared", tenant_field="tenant_id", query_budget=0)
    cov = outcome_of(job)["coverage"]
    assert cov["cross_tenant_queries"] == 0 and cov["complete"] is False
    assert len(conn.calls) == 1 + 3 + 1


def test_violation_in_a_budget_truncated_run_still_fails():
    conn = FakeStore(tenant_chunks(THREE), filter_mode="ignored")
    job = probe_isolation(conn, "shared", tenant_field="tenant_id", query_budget=2)
    out = outcome_of(job)
    assert out["outcome"] == "failed" and out["coverage"]["complete"] is False
    assert sev(job, Severity.CRITICAL)


def test_budget_and_margin_come_from_configuration():
    env = {"VECSHIELD_ISOLATION_QUERY_BUDGET": "7", "VECSHIELD_ISOLATION_SWEEP_MARGIN": "0"}
    assert IsolationLimits.from_env(env) == IsolationLimits(query_budget=7, sweep_margin=0)
    assert IsolationLimits.from_env({}) == IsolationLimits()
    assert IsolationLimits.from_env({"VECSHIELD_ISOLATION_QUERY_BUDGET": "lots"}) == \
        IsolationLimits()
    assert IsolationLimits.from_env({"VECSHIELD_ISOLATION_QUERY_BUDGET": "-1"}) == \
        IsolationLimits()


def test_environment_budget_reaches_the_check(monkeypatch):
    monkeypatch.setenv("VECSHIELD_ISOLATION_QUERY_BUDGET", "1")
    job = probe_isolation(FakeStore(tenant_chunks(THREE)), "shared", tenant_field="tenant_id")
    cov = outcome_of(job)["coverage"]
    assert cov["query_budget"] == 1 and cov["method"] == "sampled"


def test_failed_sweep_query_stops_the_sweep_and_is_recorded():
    # canary + 3 views + the first chunk's self-rank check + 2 sweeps
    conn = FakeStore(tenant_chunks(THREE), fail_on_call=7)
    job = probe_isolation(conn, "shared", tenant_field="tenant_id")
    out = outcome_of(job)
    cov = out["coverage"]
    assert cov["complete"] is False and cov["cross_tenant_queries"] == 2
    assert "ConnectionError" in cov["sweep_error"]
    assert "a cross-tenant query failed after 2 of 24" in out["reason"]


def test_collection_changing_between_reads_is_partial():
    chunks = tenant_chunks({"acme": 2, "globex": 2})
    later = chunks[:3] + tenant_chunks({"initech": 1})  # one gone, one new
    job = probe_isolation(FakeStore(chunks, second_read=later), "shared",
                          tenant_field="tenant_id")
    out = outcome_of(job)
    assert out["coverage"]["changed_during_check"] == {"appeared": 1, "vanished": 1}
    assert out["coverage"]["complete"] is False
    assert "changed while it was being checked" in out["reason"]


def test_leak_evidence_names_ids_and_tenants_never_content():
    chunks = [Chunk(id=c.id, collection="shared", text=f"secret text of {c.id}",
                    embedding=c.embedding, metadata=c.metadata)
              for c in tenant_chunks({"acme": 2, "globex": 2})]
    job = probe_isolation(FakeStore(chunks, leak={"acme": ["globex-1"]}), "shared",
                          tenant_field="tenant_id")
    [crit] = sev(job, Severity.CRITICAL)
    assert "secret text" not in repr(crit.evidence) + crit.description
    assert crit.evidence["bleeds"] == 1
    assert {e["leaked_id"] for e in crit.evidence["examples"]} == {"globex-1"}


def test_unsupported_filtered_query_is_unsupported():
    from vecshield_platform.connectors.base import UnsupportedCapability

    class NoFilter(FakeStore):
        def query(self, collection, vector, top_k=10, where=None):
            if where:
                raise UnsupportedCapability("metadata filters are not supported")
            return super().query(collection, vector, top_k=top_k)

    job = probe_isolation(NoFilter(tenant_chunks(THREE)), "shared", tenant_field="tenant_id")
    out = outcome_of(job)
    assert out["outcome"] == "unsupported" and out["coverage"]["complete"] is False
    assert "filtered query" in out["reason"]


def test_full_audit_records_and_applies_the_isolation_budget():
    from vecshield.classify import RegexClassifier
    from vecshield_platform.orchestrator import run_full_audit

    result = run_full_audit(FakeStore(tenant_chunks(THREE)), classifier=RegexClassifier(),
                            tenant_field="tenant_id", include_integrity=False,
                            include_posture=False, include_crypto=False,
                            isolation_query_budget=4)
    assert result.scope["isolation_query_budget"] == 4
    [iso] = [o for o in result.to_dict()["check_outcomes"]
             if o["check"] == "tenant_isolation"]
    assert iso["coverage"]["method"] == "sampled"
    assert iso["coverage"]["cross_tenant_queries"] <= 4


# --------------------------------------------------------------------------- #
# exhaustive verification on a real store                                     #
# --------------------------------------------------------------------------- #

def test_chroma_exhaustive_sweep_covers_every_chunk_tenant_pair(multitenant_chroma):
    with ChromaConnector(path=multitenant_chroma) as conn:
        job = probe_isolation(conn, "shared-rag", tenant_field="tenant_id")
    cov = outcome_of(job)["coverage"]
    assert cov["method"] == "exhaustive"
    assert cov["cross_tenant_pairs"] == cov["cross_tenant_queries"] == 12
    assert cov["bleeds"] == 0 and cov["complete"] is True
    assert outcome_of(job)["reason"].startswith(
        "Isolation verified exhaustively: 12 chunks across 2 tenants, "
        "12 cross-tenant queries, 0 bleeds")


def test_chroma_untagged_chunks_are_swept_under_every_tenant(multitenant_chroma):
    import chromadb

    client = chromadb.PersistentClient(path=multitenant_chroma)
    client.get_collection("shared-rag").add(
        ids=["neutral-0", "neutral-1"], embeddings=[_emb(200), _emb(201)],
        metadatas=[{"source": "wiki"}, {"tenant_id": ""}], documents=["a", "b"])
    with ChromaConnector(path=multitenant_chroma) as conn:
        job = probe_isolation(conn, "shared-rag", tenant_field="tenant_id")
    out = outcome_of(job)
    cov = out["coverage"]
    assert cov["untagged"] == 2
    assert cov["cross_tenant_queries"] == 12 + 2 * 2
    assert cov["complete"] is True and cov["bleeds"] == 0
    assert any("2 chunks carry no 'tenant_id'" in f.description
               for f in sev(job, Severity.MEDIUM))


def test_chroma_budget_truncation_is_partial(multitenant_chroma):
    with ChromaConnector(path=multitenant_chroma) as conn:
        job = probe_isolation(conn, "shared-rag", tenant_field="tenant_id", query_budget=5)
    cov = outcome_of(job)["coverage"]
    assert cov["method"] == "sampled" and cov["complete"] is False
    assert cov["cross_tenant_queries"] <= 5


def test_chroma_collection_without_tenant_field_is_not_applicable(tmp_path):
    import chromadb

    client = chromadb.PersistentClient(path=str(tmp_path / "c"))
    client.create_collection("plain-docs").add(
        ids=["a", "b", "c"], embeddings=[_emb(1), _emb(2), _emb(3)],
        metadatas=[{"source": "x"}] * 3, documents=["a", "b", "c"])
    with ChromaConnector(path=str(tmp_path / "c")) as conn:
        job = probe_isolation(conn, "plain-docs", tenant_field="tenant_id")
    out = outcome_of(job)
    assert out["outcome"] == "passed" and out["coverage"]["complete"] is True
    assert out["coverage"]["applicability"] == "not_applicable"


# --------------------------------------------------------------------------- #
# inner-product ranking: a chunk's own vector need not rank it first          #
# --------------------------------------------------------------------------- #

class InnerProductStore(FakeStore):
    """Ranks by inner product (Milvus IP, Pinecone dotproduct, Qdrant Dot,
    Chroma space=ip): a high-norm neighbour outranks a chunk's own vector."""

    def query(self, collection, vector, top_k=10, where=None):
        if self.max_top_k is not None:
            assert top_k <= self.max_top_k, "engine exceeded the connector's cap"
        self.calls.append({"top_k": top_k, "where": dict(where) if where else None,
                           "vector": list(vector)})
        pool = self.chunks
        if where:
            [(field, value)] = where.items()
            pool = [c for c in pool if c.metadata.get(field) == value]
            extra = set(self.leak.get(value, ()))
            pool = pool + [c for c in self.chunks if c.id in extra]

        def score(c):
            return sum(a * b for a, b in zip(vector, c.embedding or []))

        ranked = sorted(pool, key=lambda c: (-score(c), c.id))[:top_k]
        return [QueryHit(id=c.id, score=score(c), metadata=dict(c.metadata)) for c in ranked]


def _ip_chunks():
    # 'big' has high-norm vectors; 'small-0' is a low-norm chunk whose own
    # vector ranks it seventh in the collection, behind all six of big's.
    chunks = [Chunk(id=f"big-{i}", collection="shared", embedding=[10.0, i / 1000, 0.0],
                    metadata={"tenant_id": "big"}) for i in range(6)]
    chunks += [Chunk(id="small-0", collection="shared", embedding=[1.0, 0.0, 0.0],
                     metadata={"tenant_id": "small"}),
               Chunk(id="small-1", collection="shared", embedding=[0.0, 0.0, 1.0],
                     metadata={"tenant_id": "small"})]
    return chunks


def test_inner_product_leak_the_sweep_cannot_reach_is_not_reported_verified():
    # big's filter also admits small-0 (a real partial leak), and the store's
    # result cap (5) is below small-0's rank for its own vector (7).
    conn = InnerProductStore(_ip_chunks(), max_top_k=5, leak={"big": ["small-0"]})
    job = probe_isolation(conn, "shared", tenant_field="tenant_id")
    out = outcome_of(job)
    cov = out["coverage"]
    assert not (cov["filter_enforcement"] == "verified" and cov["complete"] is True)
    assert cov["complete"] is False
    assert cov["self_rank_unverified"] >= 1
    assert "own vector" in out["reason"]
    high = [f for f in sev(job, Severity.HIGH) if "convention-only" in f.title]
    assert high and "verified chunk by chunk" not in high[0].description


def test_inner_product_sweep_widens_to_the_chunks_own_rank_and_finds_the_leak():
    conn = InnerProductStore(_ip_chunks(), max_top_k=50, leak={"big": ["small-0"]})
    job = probe_isolation(conn, "shared", tenant_field="tenant_id")
    out = outcome_of(job)
    assert sev(job, Severity.CRITICAL), out["reason"]
    assert out["coverage"]["filter_enforcement"] == "violated"
    assert out["coverage"]["self_rank_unverified"] == 0


def test_inner_product_store_that_enforces_its_filter_is_still_verified():
    conn = InnerProductStore(_ip_chunks(), max_top_k=50)
    job = probe_isolation(conn, "shared", tenant_field="tenant_id")
    cov = outcome_of(job)["coverage"]
    assert cov["filter_enforcement"] == "verified" and cov["complete"] is True
    assert not sev(job, Severity.CRITICAL)


# --------------------------------------------------------------------------- #
# tenant values a check cannot tell apart                                     #
# --------------------------------------------------------------------------- #

def test_float_tenant_beyond_2_53_is_not_single_tenant_not_applicable():
    # Two tenants' ids written through a float path land on the same float:
    # the collection looks single-tenant, but that float names 2**60+1 and
    # 2**60+100 alike.
    a, b = float(2 ** 60 + 1), float(2 ** 60 + 100)
    assert a == b
    job = probe_isolation(FakeStore(numeric_chunks([a] * 3 + [b] * 3), filter_mode="numeric"),
                          "shared", tenant_field="tenant_id")
    out = outcome_of(job)
    assert out["outcome"] == "inconclusive" and out["coverage"]["complete"] is False
    assert out["coverage"].get("applicability") != "not_applicable"
    [finding] = [f for f in job.findings
                 if (f.evidence or {}).get("cause") == "imprecise_float_tenant"]
    assert finding.severity == Severity.MEDIUM
    assert str(a) in finding.description and "2^53" in finding.description
    assert "2^53" in out["reason"]


def test_float_tenant_beyond_2_53_is_never_verified_in_a_shared_collection():
    values = [5, 5, float(2 ** 60), float(2 ** 60)]
    job = probe_isolation(FakeStore(numeric_chunks(values), filter_mode="numeric"),
                          "shared", tenant_field="tenant_id")
    cov = outcome_of(job)["coverage"]
    assert not sev(job, Severity.CRITICAL)
    assert cov["filter_enforcement"] != "verified" and cov["complete"] is False
    rows = {r["tenant"]: r for r in cov["per_tenant"]}
    assert rows[str(float(2 ** 60))]["verified"] is False
    assert rows["5"]["verified"] is True
    assert [f for f in job.findings
            if (f.evidence or {}).get("cause") == "imprecise_float_tenant"]


def test_2_53_itself_is_already_imprecise():
    from vecshield_platform.access.isolation import _numeric_relation

    # float(2**53) is what both 2**53 and 2**53 + 1 round to.
    assert float(2 ** 53 + 1) == float(2 ** 53)
    assert _numeric_relation(2 ** 53, float(2 ** 53)) == "collision"
    assert _numeric_relation(2 ** 53 - 1, float(2 ** 53 - 1)) == "same_value"


@pytest.mark.parametrize("values", [["1", "1", 1, 1, 1.0, 1.0], [1, 1, "1", "1", 1.0, 1.0],
                                    [1.0, 1.0, 1, 1, "1", "1"]])
def test_string_and_integer_tenants_with_the_same_text_are_kept_apart(values):
    job = probe_isolation(FakeStore(numeric_chunks(values), filter_mode="numeric"),
                          "shared", tenant_field="tenant_id")
    cov = outcome_of(job)["coverage"]
    # Three stored values: the string "1", the integer 1 and the float 1.0.
    # The string is its own tenant; the int and float are the same number.
    assert cov["tenant_count"] == 3
    assert sorted(cov["tenants"]) == ["1 (integer)", "1 (string)", "1.0"]
    assert cov["filter_enforcement"] == "ambiguous"
    assert not sev(job, Severity.CRITICAL)


def test_integer_canary_stays_inside_int64():
    from vecshield_platform.access.isolation import _canary_value

    top = 2 ** 63 - 1
    for values in ([top, 5], [top, -(2 ** 63)], [top]):
        canary = _canary_value(values)
        assert isinstance(canary, int) and -(2 ** 63) <= canary <= top
        assert canary not in values
    assert _canary_value([3, 9]) == 10


def test_chroma_int64_max_tenant_does_not_crash_the_probe(tmp_path):
    import chromadb

    path = str(tmp_path / "chroma")
    values = [2 ** 63 - 1] * 2 + [5] * 2
    chromadb.PersistentClient(path=path).create_collection("tenants").add(
        ids=[f"d{i}" for i in range(len(values))],
        embeddings=[_emb(i + 1) for i in range(len(values))],
        metadatas=[{"tenant_id": v} for v in values],
        documents=[f"doc {i}" for i in range(len(values))])
    with ChromaConnector(path=path) as conn:
        job = probe_isolation(conn, "tenants", tenant_field="tenant_id")
    cov = outcome_of(job)["coverage"]
    assert cov["canary"] == "passed" and cov["filter_enforcement"] == "verified"


# --------------------------------------------------------------------------- #
# reads that stop short, and queries that fail part-way                       #
# --------------------------------------------------------------------------- #

class _ShortStore(FakeStore):
    """A store whose inventory reports more than enumeration returns."""

    def __init__(self, chunks, *, reported=None, count_known=True, **kw):
        super().__init__(chunks, **kw)
        self.reported = reported
        self.count_known = count_known

    def list_collections(self):
        meta = {} if self.count_known else {"count_known": False}
        count = self.reported if self.reported is not None else len(self.chunks)
        return [Collection(name=self.name, count=count, metadata=meta)]


def test_single_tenant_read_short_of_the_inventory_is_inconclusive():
    conn = _ShortStore(tenant_chunks({"acme": 3}), reported=10)
    job = probe_isolation(conn, "shared", tenant_field="tenant_id")
    out = outcome_of(job)
    assert out["outcome"] == "inconclusive" and out["coverage"]["complete"] is False
    assert "3 chunks of the 10" in out["coverage"]["short_read"]
    assert "unread part" in out["reason"]
    assert not [f for f in job.findings if "No multi-tenant" in f.title]


def test_empty_read_with_unknown_count_is_not_a_pass():
    conn = _ShortStore([], count_known=False)
    out = outcome_of(probe_isolation(conn, "shared", tenant_field="tenant_id"))
    assert out["outcome"] == "inconclusive" and out["coverage"]["complete"] is False
    assert "count could not be read" in out["reason"]


def test_empty_read_with_known_zero_count_is_still_not_applicable():
    out = outcome_of(probe_isolation(_ShortStore([]), "shared", tenant_field="tenant_id"))
    assert out["outcome"] == "passed"
    assert out["coverage"]["applicability"] == "not_applicable"


def test_shared_collection_read_short_is_never_complete():
    conn = _ShortStore(tenant_chunks(THREE), reported=40)
    out = outcome_of(probe_isolation(conn, "shared", tenant_field="tenant_id"))
    assert out["coverage"]["complete"] is False
    assert out["outcome"] != "passed"
    assert out["reason"].startswith("Enumeration returned 12 chunks of the 40")


def test_connector_read_errors_for_the_collection_make_the_read_short():
    class Unreadable(FakeStore):
        def iter_chunks(self, collection, batch_size=256):
            self._record_read_error(collection, item_id="f-1", error_type="Timeout")
            yield from super().iter_chunks(collection, batch_size)

    out = outcome_of(probe_isolation(Unreadable(tenant_chunks({"acme": 3})), "shared",
                                     tenant_field="tenant_id"))
    assert out["outcome"] == "inconclusive"
    assert "could not read 1 item" in out["reason"]


def test_full_view_query_failing_after_a_leak_keeps_the_leak():
    # canary (0), acme's view (1) finds globex-0, globex's view (2) fails.
    conn = FakeStore(tenant_chunks(THREE), leak={"acme": ["globex-0"]}, fail_on_call=2)
    job = probe_isolation(conn, "shared", tenant_field="tenant_id")
    out = outcome_of(job)
    assert out["outcome"] == "failed"
    assert sev(job, Severity.CRITICAL)
    assert out["coverage"]["complete"] is False
    assert out["coverage"]["query_errors"] == [
        {"stage": "full_view", "tenant": "globex", "error_type": "ConnectionError"}]
    assert "full view query failed (ConnectionError)" in out["reason"]


def test_unfiltered_query_failing_is_recorded_not_raised():
    class NoUnfiltered(FakeStore):
        def query(self, collection, vector, top_k=10, where=None):
            if where is None and len(self.calls) > 3:  # after the views
                raise TimeoutError("slow")
            return super().query(collection, vector, top_k=top_k, where=where)

    out = outcome_of(probe_isolation(NoUnfiltered(tenant_chunks(THREE)), "shared",
                                     tenant_field="tenant_id"))
    assert out["coverage"]["complete"] is False
    assert {"stage": "unfiltered", "error_type": "TimeoutError"} in out["coverage"]["query_errors"]
    assert out["outcome"] in ("failed", "inconclusive")


# --------------------------------------------------------------------------- #
# batched sweep: a connector with query_many gets the same result             #
# --------------------------------------------------------------------------- #

class _FailingQueries(FakeStore):
    """Fails one (chunk vector, tenant) query, however it is requested, and
    optionally the chunk read after ``read_fails_after`` chunks."""

    def __init__(self, chunks, *, fail_pair=None, read_fails_after=None, **kw):
        super().__init__(chunks, **kw)
        self.fail_pair = fail_pair
        self.read_fails_after = read_fails_after

    def _check(self, vector, where):
        if self.fail_pair is not None and where:
            chunk_id, tenant = self.fail_pair
            owner = next(c for c in self.chunks if c.id == chunk_id)
            if list(vector) == owner.embedding and where.get("tenant_id") == tenant:
                raise ConnectionError("store went away")

    def query(self, collection, vector, top_k=10, where=None):
        self._check(vector, where)
        return super().query(collection, vector, top_k=top_k, where=where)

    def iter_chunks(self, collection, batch_size=256):
        for i, chunk in enumerate(super().iter_chunks(collection, batch_size)):
            if self.read_fails_after is not None and self.reads > 1 \
                    and i == self.read_fails_after:
                raise OSError("read failed")
            yield chunk


class _Batching(_FailingQueries):
    """The same store, answering several vectors per request."""

    def __init__(self, chunks, **kw):
        super().__init__(chunks, **kw)
        self.batches: list[int] = []

    def query_many(self, collection, vectors, top_k=10, where=None):
        for vector in vectors:
            self._check(vector, where)
        self.batches.append(len(vectors))
        # The ranking of the store class after _FailingQueries in the MRO.
        answer = super(_FailingQueries, self).query
        return [answer(collection, v, top_k=top_k, where=where) for v in vectors]


class _BatchingIP(_Batching, InnerProductStore):
    pass


class _SingleIP(_FailingQueries, InnerProductStore):
    pass


def _comparable(job) -> dict:
    return {"stats": job.stats,
            "findings": [(f.severity, f.title, f.description, f.evidence)
                         for f in job.findings]}


_MANY = {"acme": 70, "globex": 90, "initech": 60}

_SWEEP_CASES = {
    "enforced": (FakeStore, _Batching, lambda: tenant_chunks(_MANY), {}, {}),
    "leaks": (FakeStore, _Batching, lambda: tenant_chunks(_MANY) + untagged_chunks(5),
              {"leak": {"acme": ["globex-3", "initech-40"], "globex": ["acme-69"]}}, {}),
    "budget_cut": (FakeStore, _Batching, lambda: tenant_chunks(_MANY),
                   {"leak": {"initech": ["acme-1"]}}, {"query_budget": 301}),
    "enumeration_cap": (FakeStore, _Batching, lambda: tenant_chunks(_MANY), {},
                        {"max_chunks": 150}),
    "changed": (FakeStore, _Batching, lambda: tenant_chunks(_MANY),
                {"second_read": tenant_chunks({"acme": 70, "globex": 80, "umbrella": 3})}, {}),
    "query_fails": (_FailingQueries, _Batching, lambda: tenant_chunks(_MANY),
                    {"fail_pair": ("globex-50", "initech")}, {}),
    "read_fails": (_FailingQueries, _Batching, lambda: tenant_chunks(_MANY),
                   {"read_fails_after": 140}, {}),
    "inner_product": (_SingleIP, _BatchingIP, _ip_chunks,
                      {"max_top_k": 50, "leak": {"big": ["small-0"]}}, {}),
}


@pytest.mark.parametrize("case", sorted(_SWEEP_CASES))
def test_batched_sweep_matches_the_query_by_query_sweep(case):
    single_cls, batch_cls, make, store_kw, probe_kw = _SWEEP_CASES[case]

    def run(cls):
        conn = cls(make(), **store_kw)
        try:
            return conn, _comparable(probe_isolation(conn, "shared", tenant_field="tenant_id",
                                                     **probe_kw))
        except OSError as exc:
            return conn, repr(exc)

    _, expected = run(single_cls)
    batching, actual = run(batch_cls)
    assert actual == expected
    if case != "read_fails":
        assert batching.batches and max(batching.batches) > 1  # it did batch


def test_batched_sweep_reissues_a_failed_batch_one_query_at_a_time():
    # The batch holding the failing pair is dropped; the loop re-asks each of
    # its queries singly, so the error stops the sweep where it always did.
    single = probe_isolation(_FailingQueries(tenant_chunks(_MANY),
                                             fail_pair=("acme-10", "globex")),
                             "shared", tenant_field="tenant_id")
    conn = _Batching(tenant_chunks(_MANY), fail_pair=("acme-10", "globex"))
    batched = probe_isolation(conn, "shared", tenant_field="tenant_id")
    assert _comparable(batched) == _comparable(single)
    cov = outcome_of(batched)["coverage"]
    assert cov["complete"] is False and "ConnectionError" in cov["sweep_error"]


def test_default_query_many_is_one_query_per_vector():
    conn = FakeStore(tenant_chunks(THREE))
    vectors = [c.embedding for c in conn.chunks[:3]]
    where = {"tenant_id": "acme"}
    assert Connector.query_many(conn, "shared", vectors, top_k=2, where=where) == [
        FakeStore(tenant_chunks(THREE)).query("shared", v, top_k=2, where=where)
        for v in vectors]
    assert len(conn.calls) == 3


def test_chroma_query_many_matches_single_queries(multitenant_chroma):
    conn = ChromaConnector(path=multitenant_chroma)
    chunks = list(conn.iter_chunks("shared-rag"))[:6]
    vectors = [c.embedding for c in chunks]
    for where in (None, {"tenant_id": chunks[0].metadata["tenant_id"]}):
        assert conn.query_many("shared-rag", vectors, top_k=3, where=where) == [
            conn.query("shared-rag", v, top_k=3, where=where) for v in vectors]
    assert conn.query_many("shared-rag", [], top_k=3) == []


# --------------------------------------------------------------------------- #
# short views on an approximate index (pgvector HNSW / IVFFlat)               #
# --------------------------------------------------------------------------- #

class AnnStore(FakeStore):
    """A store whose filtered queries lose recall unless the iterative scan is on.

    ``iterative``: the effective ``hnsw.iterative_scan``; ``iterative_recall``
    and ``iterative_leak`` shape what ``query_iterative`` returns.
    """

    def __init__(self, chunks, *, iterative="off", iterative_recall=None,
                 iterative_leak=None, iterative_error=None, **kw):
        super().__init__(chunks, **kw)
        self.iterative = iterative
        self.iterative_recall = iterative_recall
        self.iterative_leak = iterative_leak or {}
        self.iterative_error = iterative_error
        self.iterative_calls = 0

    def capabilities(self):
        return super().capabilities() | {"ann_iterative_scan"}

    def ann_index_info(self, collection):
        return {"index_type": "hnsw", "index": "shared_embedding_idx", "metric": "cosine",
                "operator": "<=>", "partial": False,
                "settings": {"hnsw.iterative_scan": self.iterative, "hnsw.ef_search": "40"},
                "retrieval_role_settings": {}, "iterative_scan": self.iterative,
                "pgvector_version": "0.8.7", "iterative_scan_supported": True}

    def query_iterative(self, collection, vector, top_k=10, where=None):
        self.iterative_calls += 1
        if self.iterative_error is not None:
            raise self.iterative_error
        saved = (self.recall, self.leak)
        self.recall, self.leak = self.iterative_recall, self.iterative_leak
        try:
            return FakeStore.query(self, collection, vector, top_k=top_k, where=where)
        finally:
            self.recall, self.leak = saved


def test_a_short_view_recovered_by_the_iterative_scan_is_recall_loss():
    conn = AnnStore(tenant_chunks(THREE), recall=4)  # initech holds 5
    job = probe_isolation(conn, "shared", tenant_field="tenant_id")
    cov = outcome_of(job)["coverage"]
    rows = {r["tenant"]: r for r in cov["per_tenant"]}
    assert rows["initech"]["returned"] == 5 and rows["initech"]["verified"] is True
    assert rows["initech"]["ann_retry"] == {"returned_before": 4, "returned_after": 5,
                                            "result": "recall_loss"}
    assert cov["filter_enforcement"] == "verified"
    assert cov["ann_index"]["recall_loss"] == ["initech"]
    assert cov["ann_index"]["index_type"] == "hnsw"
    assert conn.iterative_calls == 1  # only the short view is asked again
    [low] = [f for f in sev(job, Severity.LOW) if "approximate index" in f.title]
    assert "never returned" in low.description and low.evidence["leaks_data"] is False
    assert low.evidence["recall_loss"] == ["initech"]
    assert "hnsw.iterative_scan = strict_order" in low.remediation
    assert low.evidence["source_url"].startswith("https://github.com/pgvector/pgvector")


def test_a_view_still_short_with_the_iterative_scan_stays_partial():
    conn = AnnStore(tenant_chunks(THREE), recall=4, iterative_recall=4)
    cov = outcome_of(probe_isolation(conn, "shared", tenant_field="tenant_id"))["coverage"]
    rows = {r["tenant"]: r for r in cov["per_tenant"]}
    assert rows["initech"]["ann_retry"]["result"] == "still_short"
    assert rows["initech"]["verified"] is False
    assert cov["filter_enforcement"] == "partially_verified"
    assert cov["complete"] is False


def test_a_foreign_chunk_in_the_retry_is_a_leak():
    chunks = tenant_chunks(THREE)
    acme_id = next(c.id for c in chunks if c.metadata["tenant_id"] == "acme")
    conn = AnnStore(chunks, recall=4, iterative_leak={"initech": [acme_id]})
    job = probe_isolation(conn, "shared", tenant_field="tenant_id")
    cov = outcome_of(job)["coverage"]
    rows = {r["tenant"]: r for r in cov["per_tenant"]}
    assert rows["initech"]["ann_retry"]["result"] == "leak"
    assert cov["filter_enforcement"] == "violated"
    assert sev(job, Severity.CRITICAL)


def test_iterative_scan_on_raises_no_availability_finding():
    conn = AnnStore(tenant_chunks(THREE), iterative="strict_order")
    job = probe_isolation(conn, "shared", tenant_field="tenant_id")
    assert not [f for f in job.findings if "approximate index" in f.title]
    assert conn.iterative_calls == 0  # nothing came back short
    assert outcome_of(job)["coverage"]["ann_index"]["iterative_scan"] == "strict_order"


def test_a_retry_the_store_cannot_make_leaves_the_view_as_it_was():
    from vecshield_platform.connectors.base import UnsupportedCapability

    conn = AnnStore(tenant_chunks(THREE), recall=4,
                    iterative_error=UnsupportedCapability("needs pgvector 0.8.0"))
    cov = outcome_of(probe_isolation(conn, "shared", tenant_field="tenant_id"))["coverage"]
    assert cov["filter_enforcement"] == "partially_verified"
    assert "0.8.0" in cov["ann_index"]["retry_unavailable"]
    assert "ann_retry" not in {r["tenant"]: r for r in cov["per_tenant"]}["initech"]


def test_a_single_tenant_collection_gets_no_availability_finding():
    conn = AnnStore(tenant_chunks({"acme": 4}))
    job = probe_isolation(conn, "shared", tenant_field="tenant_id")
    assert not [f for f in job.findings if "approximate index" in f.title]
