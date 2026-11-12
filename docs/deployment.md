# Deployment

The VecShield server runs entirely inside your environment. This guide covers
the three supported modes. In every mode, your data (chunks, embeddings,
findings, audit logs, reports) stays in infrastructure you control.

## Prerequisites

- Python 3.10+ (for bare-metal) or a container runtime.
- Access from the deployment to the vector stores you want to govern.
- The `vecshield` distribution, which contains both the `vecshield` library and
  the `vecshield_platform` server. Install it with the extras for the stores
  you connect to:

```bash
pip install "vecshield[chroma]"
pip install "vecshield[chroma,pgvector,qdrant]"
```

One distribution provides both console scripts: `vecshield` (library CLI) and
`vecshield-platform` (server CLI).

## Mode 1 — Self-hosted Docker

```bash
docker build -t vecshield-platform:0.0.1 .
docker run --rm -p 8088:8088 \
  -e VECSHIELD_INITIAL_ADMIN_PASSWORD="$(openssl rand -base64 18)" \
  -e CUSTOMER_API_TOKEN="$(openssl rand -hex 24)" \
  -v "$PWD/data:/data" \
  vecshield-platform:0.0.1 \
  serve --config /data/vecshield.json --state-dir /data/state \
  --host 0.0.0.0 --port 8088
```

Sign in to the console as `admin` with the initial password (it must be
changed at first sign-in); the API token is for automation. See
[Sign-in and API authentication](#sign-in-and-api-authentication) and
[`../Dockerfile`](../Dockerfile).

## Mode 2 — Kubernetes / Helm

```bash
helm install vecshield ./helm \
  --set image.repository=<your-registry>/vecshield-platform \
  --set image.tag=0.0.1 \
  --set auth.token=<bearer-token>
```

The chart deploys the API/console `Deployment` + `Service` and an optional
`CronJob` that runs `vecshield-platform schedule --once` for scheduled audits.
See [`../helm/`](../helm/).

## Mode 3 — Infrastructure as code (Terraform)

[`../terraform/`](../terraform/) contains an example module skeleton for
provisioning the compute, network, and secrets the deployment needs in your
cloud account. Treat it as a starting point to adapt to your landing zone.

## Air-gapped deployment

For fully disconnected environments:

1. Mirror the `vecshield` distribution and all connector dependencies into your
   internal package index / registry.
2. Disable any outbound features (e.g. the OSV.dev CVE lookup runs with
   `--offline` / `--no-cve`).
3. Provide a local CVE feed if you want posture CVE coverage offline. The
   server-vulnerability checks work offline from the advisory snapshot bundled
   with the release; audits report its age, and treat a feed older than 30 days
   as incomplete coverage.

Adapt these controls to your organization's air-gap operating procedures,
artifact-trust chain, and change-management requirements.

## Configuration & secrets

- **Authentication:** see [Sign-in and API authentication](#sign-in-and-api-authentication)
  below. Never run the API unauthenticated on a non-localhost bind.
- **Config store:** `--config` points at a JSON file holding registered stores
  and policies.
- **State directory:** `--state-dir` (or `VECSHIELD_STATE_DIR`) keeps runtime
  state under one directory: `sqlite/history.db`, `sqlite/alerts.db`,
  `sqlite/users.db`, and `audit/audit.jsonl`. SQLite WAL/SHM sidecars stay beside their DB files.
  Omitting `--state-dir` preserves the legacy paths beside the config file.
  **One server per state directory:** the server holds an exclusive lock on
  `audit/audit.jsonl`, and a second server on the same directory refuses to
  start. The Helm chart enforces `replicaCount: 1` with a `Recreate` rollout.
  File locks may not hold on some network filesystems, so keep state on
  local or block storage.
- **Connector credentials:** inject via environment/secret manager, least
  privilege. Secret references support `*_env` and `*_file` keys.
- **Plaintext-secret guard:** set `VECSHIELD_REJECT_PLAINTEXT_SECRETS=1` to
  fail config writes that contain direct secret values.
- **NER models:** installed at image build or with
  `vecshield-platform nlp install --default` (never downloaded at scan
  time); see [NLP models](nlp_models.md) for the build arguments, air-gapped
  wheelhouse and verification. The default image ships `en_core_web_trf` with
  `VECSHIELD_NLP_MODE=required`; `docker build --target slim` ships
  `en_core_web_lg` without PyTorch. Size pods for the model: 2.2-3.2 GB of
  memory for `trf` (plan on requests of 2 CPU / 3 GiB and a 4 GiB limit),
  about 1-1.3 GB for `lg`. `serve` loads the model in the background at start;
  detection status reads `loading`, then `ready`. A cold first load has taken
  up to 40 s, so allow at least 60 s of start-up before liveness checks act.
- **Upgrading from an image without NLP, or from the hftrf default:** rebuild
  the image. Names, addresses and organisations are then detected, so expect
  more PII findings on unchanged data; the change comes from detection, and
  each run records the model that produced it (`stats.detection`).

### Sign-in and API authentication

`serve` turns on **local accounts** by default (design: [ADR 0002](adr/0002-local-accounts-and-sessions.md)).

- **First sign-in.** On first start, with no accounts yet, VecShield creates one
  account, `admin` (role `admin`), with the password `admin`, and logs a
  warning. That account must choose a new password at first sign-in; until it
  does, every API call made with its session answers `403 password change
  required`. Only an admin can create further accounts. To avoid ever exposing
  `admin`/`admin`, set `VECSHIELD_INITIAL_ADMIN_PASSWORD` before the first
  start; it still has to be changed at first sign-in, and it must pass the
  password policy (12+ characters, not a common password) or `serve` refuses
  to start. Bound beyond localhost (any `--host` other than a loopback
  address, as in the container), `serve` also refuses a first start without
  the variable, and a restart while `admin` still has the password `admin`.
  To recover from the last case, start once on `127.0.0.1` and change the
  password. On localhost the startup banner says when the default password is
  still in effect. Upgrading: a Helm release whose initial-password Secret
  fails the policy, or whose volume still holds `admin`/`admin`, now fails to
  start until that is fixed.
- **Accounts database.** `<state-dir>/sqlite/users.db` (legacy layout:
  `<config>.users.db`), created owner-only (`0600`). Passwords are stored as
  salted scrypt hashes; session tokens only as SHA-256 digests. Back it up with
  the rest of the state directory. Accounts are disabled, never deleted, so
  the audit trail stays attributable.
- **Roles.** `viewer`, `operator`, `compliance`, `admin` (admin implies all;
  operator and compliance imply viewer). Role changes take effect on the
  account's next request. The last enabled admin cannot be demoted or
  disabled, and nobody can disable their own account.
- **Password policy.** At least 12 and at most 256 characters, not the
  username, not a very common password.
- **Lockout.** Five consecutive wrong passwords lock the account for 15
  minutes (`429`). Tunable with `VECSHIELD_LOGIN_MAX_ATTEMPTS` and
  `VECSHIELD_LOGIN_LOCKOUT_MINUTES`.
- **Sessions.** An HttpOnly, `SameSite=Strict`, `Path=/` cookie named
  `vecshield_session`. It expires after 60 idle minutes
  (`VECSHIELD_SESSION_IDLE_MINUTES`) and at most 12 hours after sign-in
  (`VECSHIELD_SESSION_MAX_HOURS`). The cookie is marked `Secure` when the
  request arrives over HTTPS; behind a TLS-terminating proxy that forwards plain
  HTTP, set `VECSHIELD_COOKIE_SECURE=1`. Changing a password signs the account
  out of its other sessions; an admin password reset or disabling an account
  signs it out everywhere.
- **CSRF.** Requests authenticated by the cookie that change state (anything
  other than GET/HEAD/OPTIONS) must carry `X-VecShield-CSRF: 1`, which the
  console sends and a cross-site form cannot. Bearer-authenticated requests are
  exempt.
- **Automation.** Static bearer tokens (`--token`/`CUSTOMER_API_TOKEN`,
  `--admin-token`/`VECSHIELD_ADMIN_TOKEN`) and HS256 JWTs (`--jwt-secret`,
  `--jwt-audience`, `--jwt-issuer` or the matching `VECSHIELD_JWT_*` variables)
  keep working alongside sign-in for scripts and CI. A request with a valid
  bearer credential is authenticated by it; otherwise the session cookie is
  used. Asymmetric OIDC (RS256/JWKS) is not supported yet.
- **Turning sign-in off.** `--no-login` or `VECSHIELD_LOGIN=off`. With no bearer
  token or JWT secret configured either, the API is unauthenticated and `serve`
  refuses to bind anything but localhost.
- **Audit.** Sign-in, failed sign-in, sign-out, password change, account
  creation, account change and password reset are written to the audit log
  (`auth.login`, `auth.login_failed`, `auth.logout`, `auth.password_changed`,
  `user.created`, `user.updated`, `user.password_reset`). Passwords are never
  logged; a failed sign-in for a name that does not exist is recorded as
  `unknown`.

### Writes to your vector stores

VecShield reads your stores. The one exception is a **staged action plan**: a
set of changes proposed from findings, frozen, reviewed as a diff, approved by a
named person, and only then carried out.

**Writes are blocked by default.** `VECSHIELD_SAFE_MODE` is on unless you set it
to `0`, and while it is on the server will suggest, stage, show a diff and
accept an approval, but will not touch a store. A deployment that never
considers this setting cannot be written to.

- `VECSHIELD_SAFE_MODE=0` — permit execution. Every execution record states that
  safe mode was off when it ran.
- Check the current setting with `vecshield-platform actions safe-mode`, or
  `GET /actions/safe-mode`.

What can be executed, and what cannot:

| Action | Executable today | Why |
|---|---|---|
| Tag chunks for exclusion | Yes | Reversible; sets a metadata field, alters no content |
| Quarantine a collection | Yes | Reversible; sets a metadata field on the collection |
| Redact the matched spans in the stored text | Yes, where every detector behind the finding is measured at `possible` | Reversible; the original is copied to a quarantine collection first. **The vector is not changed** — see below |
| Delete chunks | No | Built, but needs every detector behind it measured at `likely`, and none is |

**Redaction does not re-embed, and cannot.** VecShield does not have the model
your collection was embedded with. Asking the store to embed a replacement
would fail on a locked-down deployment or — worse — succeed with the store's
default model and write a vector in a different space from every neighbour it
has. So a redaction replaces the stored text, copies the original (text and
vector) to a `vecshield_originals` collection marked quarantined, carries the
existing vector over unchanged, and sets `vecshield_needs_reembed` on the
chunk for the pipeline that owns the model. Until that pipeline re-embeds it,
the vector still encodes the original text. The verification record says all
of this every time.

Delete is the case worth understanding, because it is built and still unavailable.
An irreversible action requires every detector behind the finding to have earned
a `likely` confidence class on the benchmark — a measured precision whose *lower*
bound clears 0.90. On the shipped corpus the strongest measured class is
`possible`, so nothing can propose a delete. That is not a setting you can
change: the way to open it is to grow the benchmark corpus until the evidence
supports the claim. `GET /actions/safe-mode` reports the current state per
action, and the console shows the same table.

The rules the write path enforces, none of which can be turned off:

- An approval is scoped to one plan's hash. Re-staging needs a fresh approval,
  and there are no standing approvals or auto-apply rules.
- The person who staged a plan cannot approve it.
- A plan staged against a store that has since changed is refused, not
  re-resolved.
- Execution stops at the first failure rather than carrying on.
- A plan that has run cannot run again.

**What tagging does and does not do.** Marking a chunk sets
`vecshield_excluded` in its metadata, merged into whatever is already there.
Nothing is removed, and **nothing stops being retrieved** unless your retrieval
layer filters on that field. VecShield reports the write; making it take effect
is a change in your application. Verification says the same thing in the record
it produces.

Useful API hardening options:

- `--cors-origin` / `VECSHIELD_CORS_ORIGINS`. List the console's origins
  explicitly. A `*` entry is served without credentials, so browsers do not
  send the session cookie cross-origin; only bearer-token callers work there.
- `--max-body-mb` / `VECSHIELD_MAX_BODY_BYTES`
- `--rate-limit` + `--rate-window` / `VECSHIELD_RATE_LIMIT`. A caller gets a
  bucket of its own only with a bearer credential that validates; everything
  else, and every sign-in attempt, counts against the client IP.
- `VECSHIELD_JWT_MAX_LIFETIME` (seconds): refuse JWTs whose `exp` lies further
  than this past their `iat`. JWTs must always carry `exp` and a subject.
- `--log-level` and `--log-format` (text/json)

## The bundled detection library

The detection library ships inside the image: `vecshield/` is part of this
repository and is installed by the same `pip install .` as the server. There is
no separate fetch at build time, which is what makes an air-gapped build
straightforward — the image needs no access to a code host, only to a package
index for the third-party dependencies.

```bash
docker build -t vecshield-platform:0.0.1 .
```

The running service reports the library version it is detecting with at
`/version`. The field is still named `detection_version`, from the time the two
packages were released separately.

Operational endpoints exposed by the API service:

- `/healthz`, `/livez`, `/readyz`
- `/metrics` (Prometheus format)

## CI, quality gates, and integration tests

- Repository CI runs lint (`ruff`), type-check (`mypy`, advisory), tests, and
  coverage on a Python version matrix.
- Container-backed integration tests are marked `integration` and excluded from
  default `pytest` runs (`-m 'not integration'`).
- The integration lane is intended for nightly/manual execution and requires a
  Docker daemon.

## Data residency

Nothing leaves your environment by default. Telemetry is off. Support bundles
are redacted. See [`../SECURITY.md`](../SECURITY.md).

### Outbound connections (egress)

The only scheduled outbound traffic is the **server advisory feed** used by the
database-server vulnerability and end-of-life checks, and it is **off by
default**. Until an admin turns it on, audits read the snapshot bundled with the
release (or the last copy refreshed into the state directory).

| Host | Used for |
| --- | --- |
| `api.osv.dev` | OSV advisories for Qdrant, Weaviate, Milvus, Chroma, OpenSearch, pgvector |
| `api.github.com` | Vendor GitHub security advisories (Redis, Milvus, ...) |
| `services.nvd.nist.gov` | NVD CVE records by CPE |
| `www.postgresql.org` | PostgreSQL security page and per-CVE pages |
| `www.cisa.gov` | CISA Known Exploited Vulnerabilities catalogue |
| `endoflife.date` | Published end-of-life schedules |

All requests are HTTPS GETs (OSV queries are POSTs of a package name) to these
fixed endpoints; nothing about your stores, findings or data is sent. Allow
these hosts on your egress proxy only if you enable updates.

- **Manual refresh:** an admin runs `POST /admin/vulnfeed/refresh` (a
  background job, at most once per 10 minutes) or
  `vecshield-platform vulnfeed refresh --state-dir DIR`.
- **Auto-update:** an admin sets `PUT /admin/vulnfeed/settings`
  `{"auto_update": true, "interval_hours": 24}` (minimum 6 hours). The audit log
  records who enabled it as consent to the egress above. The server checks every
  15 minutes whether a refresh is due and waits an hour after a failed attempt.
  Set `VECSHIELD_VULNFEED_SCHEDULER=off` to keep the scheduler from starting at
  all.
- **Tokens (optional, for higher rate limits):** `VECSHIELD_GITHUB_TOKEN` and
  `VECSHIELD_NVD_API_KEY` in the server's environment, or secret *references*
  saved with the settings (`github_token_env` / `github_token_file`,
  `nvd_api_key_env` / `nvd_api_key_file`). Token values are never stored in the
  config or returned by the API.
- The feed is written to `<state-dir>/vulnfeed/` (beside the config file when
  the server runs without `--state-dir`).

Other outbound features are explicit per run: the OSV.dev lookup for client
libraries (`--cve-offline` / `offline=true` to skip) and connections to the
vector stores and model endpoints you register.
