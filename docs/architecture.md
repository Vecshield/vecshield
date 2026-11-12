# Architecture

VecShield is one project shipping two packages: `vecshield`, the detection
library, and `vecshield_platform`, the self-hosted server that governs vector
stores with it. Both come from the same distribution and the same commit.

## Layers

```
┌────────────────────────────────────────────────────────────────┐
│  vecshield_platform  — server, console, assessment engines     │
│                                                                │
│  api/          FastAPI service + console + store registry      │
│  orchestrator  full audit flow                                 │
│  connectors/   vector-DB connectors                            │
│  posture/      network / TLS / CVE posture                     │
│  runtime/      query monitoring + ingest monitor               │
│  access/       RBAC diff, key auditor, isolation prober        │
│  integrity/    prompt injection, provenance, anomaly           │
│  compliance/   DPIA, DSAR, erasure, audit log, policy, reports │
│  scan/         vector-store classification scan                │
│  discovery / history / validation                              │
└───────────────────────────┬────────────────────────────────────┘
                            │ imports (one-way)
                            ▼
┌────────────────────────────────────────────────────────────────┐
│  vecshield  — detection library                                │
│                                                                │
│  models        shared data model (Chunk, Finding, Severity…)   │
│  classify/     PII/PHI/PCI/secret detection engine             │
│  ingest/       ingest PII gate + boundary analyzer             │
│  datascan/     training-dataset scan                           │
│  datasources/  local file/dataset readers                      │
│  score/        sensitivity / inversion scoring                 │
└────────────────────────────────────────────────────────────────┘
```

## Dependency rule

The layering is one-way and enforced, so the library stays usable on its own:

- `vecshield_platform` imports `vecshield.*`. `vecshield` never imports
  `vecshield_platform.*`.
- Shared types live in the library (`vecshield.models`).
- Every server-side module is rooted under `vecshield_platform.*`.

## Request / data flow (dashboard audit)

```
operator ──▶ dashboard (api/dashboard/dist) ──▶ FastAPI (api/app)
                                          │
                                          ├─ auth (static token and/or JWT)
                                          │    role gates: viewer/operator/
                                          │    compliance/admin
                                          ├─ registry.open(store) → connectors/*
                                          ├─ orchestrator.run_full_audit
                                          │     ├─ scan/          (uses vecshield.classify)
                                          │     ├─ posture/       network/TLS/CVE
                                          │     ├─ integrity/     poisoning checks
                                          │     ├─ access/        RBAC / keys / isolation
                                          │     └─ compliance/    fingerprint,
                                          │                        allow-list,
                                          │                        suppression,
                                          │                        policy eval
                                          └─ history.save_job     (local storage)
```

All persistence (config store, scan history, evidence bundles, runtime alerts,
and audit logs) is local to the deployment. There is no hosted VecShield
service for any of it to be sent to.

When served with `--state-dir`, durable runtime state is organized under:

- `sqlite/history.db` for scan history, DSARs, findings, and async jobs.
- `sqlite/alerts.db` for runtime alerts.
- `audit/audit.jsonl` for the hash-chained audit log.

SQLite `-wal` and `-shm` files remain beside their database files in the
`sqlite/` directory.

Runtime query monitoring writes alerts to a local alert store and exposes them
through API endpoints under `/runtime/alerts*`.

Health/readiness/ops endpoints are first-class deployment surfaces:

- `/healthz` basic service health.
- `/livez` process liveness.
- `/readyz` dependency readiness (registry/history/alert store).
- `/metrics` Prometheus exposition for operations and findings.

## Scheduled audits

`vecshield-platform schedule` runs `orchestrator.run_full_audit` over every
registered store on an interval, or once (`--once`) under an external scheduler
(cron / Kubernetes CronJob). Results persist to the local scan history.

## Tenant isolation

`access/isolation.py` verifies tenant isolation per collection on the
configured tenant field. Where the connector can enumerate chunks and run a
filtered `query()`, it reads every chunk's tenant, then queries every stored
chunk's own vector under every *other* tenant's filter (untagged chunks under
every tenant's), plus a canary filter for a tenant that does not exist, a
full-view query per tenant, and one unfiltered query. A chunk is at distance
zero from its own vector, so if any other tenant's filter admitted it, that
query would return it: the sweep shows, chunk by chunk, that the store enforces
the filter for the stored corpus, independent of the store's result cap.

The outcome is `passed`/complete only when enumeration was whole and every
chunk-tenant pair was queried; any bleed is `failed` (CRITICAL, with chunk ids
and tenant names as evidence, never content). A sweep larger than
`VECSHIELD_ISOLATION_QUERY_BUDGET` (default 10,000 queries per collection) runs
a deterministic subset, is labelled `sampled`, and is never complete. A
collection holding one tenant, or no tenant field and no other tenant-like
field, is `not_applicable` (passed, complete). Two tenants sharing a
collection remain HIGH ("convention-only") even when the filter is verified,
because isolation still depends on every application query carrying it.

The check does not observe the application's own retrieval path, other
credentials or APIs, chunks written after enumeration, or whether each
chunk's tenant value is correct. See
[ADR 0001](adr/0001-exhaustive-tenant-isolation.md).

## Regulatory content

Detection and regulatory judgement are separate layers, and the boundary is
deliberate: a rule that matches is an observation, never a conclusion.

```
compliance/sources.py    maintained source records (issuer, section, edition,
                         dates, lifecycle, licence) — the citation of record
compliance/criteria.py   the evaluation contract: applicability, technical
                         result, evidence sufficiency, and reviewer conclusion
                         held as four separate fields
compliance/packs.py      the shipped draft criterion pack
compliance/content_review.py
                         ContentReview records (a qualified reviewer's sign-off
                         on VecShield's mapping) and the derived per-criterion
                         and per-pack lifecycle
compliance/pack_history.py
                         digests of earlier packs; generates the migration
                         note that says which reviewer decisions go stale
api/templates.py         detection rules, each referencing source records and
                         declaring what it detects and cannot establish
```

Rules the layer enforces rather than documents:

- A source record reports `lifecycle`, `legal_status` (in force, applies
  later, proposed, vacated, superseded, guidance), per-provision dates,
  licence and `reproduction` policy, and how far its locator was checked
  during research (`citation_check`: primary source, secondary sources only,
  or unverified). `verified` is true only when a build fetched and hashed the
  provision text; none has yet.
- Lifecycle states from `regulatory_reviewed` on are never declared. A
  criterion reaches `regulatory_reviewed` only through a `ContentReview` whose
  stored digest is the criterion's current digest, and the pack's lifecycle is
  its least-advanced criterion's. No content review ships, so every criterion
  and the pack are `draft`. A content review is about VecShield's content and
  is kept separate from a deployment's `ReviewerDecision` about its own store.
- A stored reviewer decision is bound to the pack version and the criterion
  digest. When the pack version moves, a decision is carried forward only if
  the criterion is unchanged since the pack it was recorded under; the list
  for the current move is `docs/compliance/pack-draft-4-migration.md`.
- Licensed standards (PCI DSS, AICPA TSC) are `link_only`: referenced by
  locator, link and a few words of our own. Their text and headings are not
  reproduced.
- Attribution is looked up from source records, so renaming a template cannot
  change its citation, and a broken reference surfaces as unresolved.
- Only a named reviewer moves a criterion to `satisfied_for_scope`. A clean
  scan with unconfirmed applicability, partial coverage, or missing evidence
  never reaches it.

Endpoints: `GET /compliance/criteria[?framework=]` publishes the pack (with
its derived lifecycle, coverage gaps and tracked proposals) and its limits; `POST /stores/{id}/criteria` evaluates it against a *frozen* audit
snapshot, taking applicability answers, evidence states, and reviewer decisions
from the caller.

## Extending

- New connector → `connectors/<kind>.py` implementing the `Connector` contract,
  registered in `connectors/__init__.py`.
- New posture/integrity/access check → add to the respective engine; the
  orchestrator aggregates findings by category.
