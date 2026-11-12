# ADR 0001: Exhaustive tenant-isolation verification

Status: accepted (2026-09-25)

## Context

The tenant isolation check (`vecshield_platform/access/isolation.py`) used to
take three vectors per tenant as probes and look at their top ten results,
filtered and unfiltered. The orchestrator recorded every run as
`inconclusive` with the reason "Isolation uses sampled probes; absence of
observed bleed does not verify full isolation." That was honest, but it meant
that no store holding a tenant field could ever read coverage `complete`, even
when the store was small enough to check in full.

A later revision enumerated every chunk and ran one filtered query per tenant,
sized to the whole collection. That verifies a filter under exact search, but
has two gaps. A tenant with more chunks than the store's result cap (Pinecone,
OpenSearch, Weaviate and MongoDB cap at 10,000) cannot have its view returned
in full, so another tenant's chunk can hide behind the cap. And under
approximate (ANN) search, a filtered query can miss a result the filter
admitted, including a leaked one.

## Decision

The check runs, per collection:

1. Enumeration: every chunk's id, its tenant value, and a digest of its vector,
   used to count byte-identical duplicates.
2. Canary: one query filtered to a tenant value no chunk carries. Any hit means
   the store ignores the filter.
3. Full view: one query per tenant, filtered to that tenant, asking for as many
   results as the collection holds (up to the store's cap). It shows whether
   the tenant's own view is whole, and flags any foreign chunk it returns.
4. Cross-tenant sweep: for every chunk `c`, and every tenant `T` that does not
   own it (every tenant, for an untagged chunk), query with `c`'s own vector
   filtered to `T`, with `top_k = duplicates(c) + margin`. Any result not owned
   by `T` is a bleed.
5. Unfiltered: one query without the filter, recording which tenants a query
   that omits the filter reaches.

Why step 4 is exhaustive. `c` is at distance zero from its own vector. Among
the chunks `T`'s filter admits, it can only tie with byte-identical copies,
which enumeration counted. So under exact search, if `T`'s filter admits `c`,
the query returns `c`. Querying every (chunk, other tenant) pair therefore
shows, chunk by chunk, that no other tenant's filter admits it, whatever the
tenant sizes and the result cap. Under ANN search the argument rests on the
index finding an exact self-match, which is the most recoverable result an ANN
index has. The full view cross-checks it: a full view that comes back short of
the tenant's enumerated chunks (for a reason other than the cap) marks the
index as lossy, and the result is partial, not verified.

Outcomes:

| Situation | Outcome | Coverage |
| --- | --- | --- |
| Every chunk enumerated, every pair queried, canary passed, full views whole, no bleed | `passed` (or `failed` for the structural HIGH below) | complete, `method: exhaustive` |
| Any bleed, or the canary returned a chunk | `failed`, CRITICAL finding | complete only if the run was also whole |
| Sweep larger than the budget | `inconclusive` (or `failed` if something failed) | partial, `method: sampled` |
| Enumeration capped, collection changed between reads, sweep query error, chunks without vectors, non-scalar tenant values, ANN shortfall | `inconclusive` (or `failed`) | partial, with the reason stated |
| One tenant only, or no tenant field and no other tenant-like field varies | `passed` | complete, `applicability: not_applicable` |
| No tenant field, but another tenant-like field (`org_id`, `workspace_id`, ...) varies | `inconclusive`, MEDIUM finding | partial |
| Connector cannot enumerate, cannot query, or cannot filter | `unsupported` | partial |

Two or more tenants sharing a collection still produce the HIGH
"convention-only" finding, and so a `failed` outcome, even when the sweep
verified the filter. That is unchanged: the store enforcing a filter does not
show that every application query carries it. Untagged chunks in a
tenant-scoped collection are a MEDIUM finding.

The sweep costs `chunks x (tenants - 1)` queries, plus `untagged x tenants`.
It is bounded by `IsolationLimits.query_budget`, configured per deployment with
`VECSHIELD_ISOLATION_QUERY_BUDGET` (default 10,000 per collection) and per run
with `run_full_audit(isolation_query_budget=...)`; the audit scope records the
value used. `VECSHIELD_ISOLATION_SWEEP_MARGIN` (default 4) sets how many
results each sweep query asks for beyond the chunk's own duplicates. Over
budget, the sweep keeps a deterministic, evenly spread subset of pairs (by a
hash of chunk id and tenant), and the reason says how many of how many pairs
were queried. The collection is read twice, streaming, so memory grows with
the number of chunk ids, not with vector size.

Evidence carries chunk ids, tenant names and counts, never chunk content.

## What this does not establish

The check verifies the store's enforcement of the tenant filter, for the
chunks stored when it ran, through the query path this connector uses. It
does not:

- observe the application's retrieval path: a query built without the filter,
  an application-side post-filter, a cache, a reranker, or a prompt that
  mixes contexts;
- cover other credentials, API surfaces, or replicas than the one the
  connector reaches;
- cover chunks written after enumeration (a change between the two reads is
  detected and makes the result partial, but writes after the check are not);
- judge whether a chunk's tenant value is correct. A chunk tagged with the
  wrong tenant is invisible to any filter-based check.

## Alternatives considered

- **Keep sampled probes.** Cheap, but it can never read complete, which is
  the problem this ADR addresses.
- **One large filtered query per tenant only.** Verifies exact-search stores
  within the result cap, but misses leaks behind the cap and leaks an ANN
  index skips. Kept as step 3 for the whole-view and recall signal.
- **Query every tenant with every vector (all pairs, including a tenant's
  own chunks).** Adds `chunks` queries that cannot surface a bleed, since
  `T`'s own chunks are allowed in `T`'s view.
- **Batch queries.** Would cut round trips for stores that accept several
  query vectors, but the `Connector.query` contract is single-vector.
  A later optimisation, not a change in method.

## Consequences

- Multi-tenant collections within budget read complete for isolation. In the
  demo estate, all thirteen collections now do; the capped `customer-360` run
  stays partial because it read four chunks per collection.
- Isolation checks issue more queries: one per (chunk, other tenant) pair.
  Deployments with large shared collections should set the budget to what
  their store can serve, and will read `sampled`/partial above it.
- A collection with no tenant field and nothing tenant-like now reads
  `not_applicable` instead of `inconclusive`. A collection whose tenant sits in
  a differently named field is flagged by the hint list
  (`TENANT_FIELD_HINTS`), which is heuristic: a field outside it is not seen.

## Migration and reproduction impact

Stored audits are immutable and keep the outcomes they recorded. New audits
record `method`, `cross_tenant_pairs`, `cross_tenant_queries`, `bleeds`,
`query_budget`, `sampled`, and `applicability` in the check's coverage, and
`isolation_query_budget` in the audit scope. Tests are in
`tests/test_isolation.py`; the demo seeder (`demo/seed.py`)
checks every seeded collection's isolation outcome against counts derived from
`scenarios.py`.
