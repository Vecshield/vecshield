# Platform capabilities

A reference for what the `vecshield_platform` server does, module by module.
The detection library (`vecshield`) is described in
[`library/README.md`](library/README.md); this page covers the server that runs
on top of it.

## Console & API (`api/`)
- FastAPI service with a bundled web console (`api/dashboard/`).
- Store registry + persistent config store (register stores, define policies,
  alerting, allow-list rules, and suppressions).
- Endpoints for scans, audits, history, ingest gate/redact, DSAR, DPIA,
  runtime alerts, and admin control-plane operations.
- Authn/authz supports static bearer tokens plus JWT validation with API roles
  (`viewer`, `operator`, `compliance`, `admin`).
- API hardening knobs: CORS, request body caps, fixed-window rate limiting.
- Operational endpoints: `/healthz`, `/livez`, `/readyz`, `/metrics`.
- `vecshield-platform serve --config ./vecshield.json`

### Schema Explorer (`GET /stores/{store_id}/schema`)

Returns the full metadata schema for a store, sampled across collections:

| Parameter | Default | Description |
|---|---|---|
| `sample_chunks` | 200 | Max chunks sampled per collection for field statistics (0 = structure only) |
| `max_values` | 10 | Max distinct top-values returned per field |

Response includes collection count, total vectors, per-collection metadata
fields with coverage/types/top-values/examples, cross-collection field
aggregation, connector capabilities, and a per-collection error list.

Any role can read it, so every metadata value it returns (top values,
examples, collection metadata) is masked the way the masked chunk view masks
it: a value whose own key names identifying data (`email`, `ssn`,
`customer_id`, …) is masked whole, including inside arrays and nested
objects, and anything the deployment's classifier detects elsewhere is
masked in place, before the 140-character preview is cut. Values that mask
alike are counted together. The response carries `values_masked: true`.
Field names (keys) are shown as they are, as in the masked chunk view. Raw
values go through the audited reveal path.

The console's Schema Explorer panel exposes all of this with a live field
filter, sortable columns, coverage bars, expandable value lists, cross-
collection field badges, and a configurable sample-size control.

## Connectors (`connectors/`)
Chroma, pgvector, Pinecone, Qdrant, Weaviate, Milvus, Redis, OpenSearch,
MongoDB, OpenAI vector store, Azure AI Search, Bedrock KB, Vertex AI. Install
per-connector extras (e.g. `vecshield[pgvector]`).

## Vector-DB posture (`posture/`)
- Network exposure (public bind, open ports).
- Transport encryption / TLS checks.
- Cryptographic posture at the data plane: TLS on the live session and (opt-in)
  plaintext refusal, database-native encryption at rest where the store exposes
  it, field-level encryption, how sensitive values and PAN are represented,
  and (opt-in) what a retrieval client reads back. Mapped to the six frameworks
  without a score; see `docs/crypto_posture.md`.
- Dependency CVE scan via OSV.dev (`--offline` for air-gapped).
- `vecshield-platform posture ...` / `cve-scan`

## Runtime monitoring (`runtime/`)
- Query monitoring with bulk-volume, enumeration, collection-sweep, and
  rate-baseline detectors; pluggable sinks (console, webhook, in-memory).
- Persistent alert sink + alert store for runtime alerts exposed via API.
- Ingest monitor for pipeline-side PII alerting.
- `vecshield-platform monitor-replay --events events.jsonl`

## Access control (`access/`)
- RBAC diff, API-key auditor (stale / over-privileged keys), tenant-isolation
  prober (cross-tenant bleed).
- `vecshield-platform audit-keys` / `probe-isolation`

## RAG integrity (`integrity/`)
- Prompt-injection detection, provenance coverage, embedding anomaly detection.
- `vecshield-platform scan-integrity ...`

## Remediation (`remediation.py`, `actions.py`, `execution.py`)
- Every finding kind has its own catalogue (`GET /admin/findings/{id}/remediation`,
  the console's **Fix this**), split honestly in two:
  - **Executable** — VecShield performs it through a capability the store's
    connector declares, via `stage → review → approve (second person) →
    execute → read-back`. Kinds: label, tag for exclusion, redact, quarantine a
    collection, delete (gated shut), flag for review, tag unverified provenance,
    assign a missing tenant (the value is part of the approval), move chunks to
    `vecshield_quarantine` (write + delete), and copy each tenant into its own
    collection (write + collection_create).
  - **Guided** — a store-specific procedure with the finding's values filled in
    (the exact server setting, the key id, the package and fixed version, the
    tenant filter), for changes no connector can make. Marking one done
    (`.../remediation/attest`) records a claim; a re-scan
    (`.../remediation/verify`) re-runs the check behind the finding, read-only,
    and is the only thing that verifies it. A resolved re-scan moves a case
    awaiting verification to `verified`, naming the run.
- Conditions ("chunks with no tenant_id") become selectors, resolved against the
  store at staging into a concrete list the approval covers. Values written to
  the store (review reasons, provenance tags, tenant field) are recomputed or
  checked server-side, never taken from the client as sent.
- `VECSHIELD_SAFE_MODE` still blocks every execution; every stage, approval,
  execution, refusal, attestation and re-scan is in the audit log.

## Compliance (`compliance/`)
- DPIA (GDPR Art. 35) generation, DSAR workflow across all stores, erasure
  impact + execution + verification, tamper-evident audit log, policy engine,
  fingerprinting, allow-listing, suppression management, HTML report templates.
- `vecshield-platform dsar` / `pia` / `erasure` / `verify-erasure`

## Orchestration & operations
- `orchestrator.py` — full audit across every engine.
- `discovery.py` — network discovery of vector-store instances.
- `history.py` — local scan-history persistence (including finding
  fingerprints and suppression flags).
- `validation.py` — live connector-contract validation.
- `schedule` — recurring audits (long-lived or `--once` for cron/CronJob).

## Engineering hygiene
- CI workflow for lint (`ruff`), type-check (`mypy`), tests, and coverage.
- Coverage floor and integration-test marker wiring in `pyproject.toml`.
- Container-backed integration-test scaffolding in `tests/integration/`
  (nightly/manual CI lane).

## Deployment tooling
- [`../Dockerfile`](../Dockerfile), [`../helm/`](../helm/),
  [`../terraform/`](../terraform/).

## Taken from the `vecshield` library
PII/PHI/PCI/secret detection, the ingest gate, training-dataset scanning, local
data-source readers, and the shared data model — imported from `vecshield.*`.
The import only goes this way: the library does not depend on the server.
