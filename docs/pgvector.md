# Auditing a pgvector store

This page covers four things:

- what VecShield checks on a PostgreSQL + pgvector store;
- which role to audit with;
- what each check needs to read;
- how to read a result VecShield could not observe.

The rules and their sources live in
`vecshield_platform/posture/data/pg_hardening_rules.json`. Every rule names
the condition it fires on, its severity, and a verbatim quote from the
PostgreSQL, pgaudit or pgvector documentation.

## What is checked

| Check | What it reads | Fires on |
|---|---|---|
| `authentication` | `system_user` (PostgreSQL 16+), then libpq's own password flag | A session the server admitted without authenticating it (`trust`): CRITICAL on a public endpoint, HIGH otherwise |
| `network_exposure` | The host in the DSN, including keyword DSNs (`host=… dbname=…`) | A public address |
| `transport_encryption`, `transport_tls_enforcement` | `pg_stat_ssl`; `pg_hba_file_rules` | A plaintext session; `host` rules that accept non-local clients without TLS |
| `server_vulnerability`, `server_support_status` | The **installed package** version (`pg_available_extensions.default_version`), then `pg_extension.extversion` | pgvector advisories, including CVE-2026-3172 (fixed 0.8.2) and CVE-2026-103484 (fixed 0.8.7). Also a LOW note when the extension's SQL objects lag the package (`ALTER EXTENSION vector UPDATE`) |
| `server_hardening` | An allowlisted `pg_settings` snapshot; `pg_hba_file_rules`; `pg_extension`; members of `pg_read_all_stats` | The rules below |
| `access_grants` | `pg_roles`, `pg_auth_members` (via `pg_has_role`), `pg_class`, `pg_policy`, `has_table_privilege`, `has_schema_privilege`, `pg_proc`, each table's HNSW/IVFFlat index, `pg_db_role_setting` | The rules below |
| `tenant_isolation` | The tenant-filtered queries themselves, through the column's own index operator | Leaks across tenants. Since phase 3, also a LOW availability finding for a shared table on an HNSW/IVFFlat index with iterative scans off (see below) |

### `server_hardening` rules

| Severity | Rule |
|---|---|
| CRITICAL | A non-loopback `pg_hba.conf` line uses `trust` |
| HIGH | `ssl = off` while `listen_addresses` names a non-loopback address |
| MEDIUM | `password_encryption = md5`; non-local `md5` or `password` hba lines; `log_statement = mod` or `all` (the log then records chunk text and embeddings); pgaudit logging `read`/`write` with `pgaudit.log_parameter = on`; non-superuser login roles that can read every role's statement text through `pg_stat_statements` |
| LOW | `ssl_min_protocol_version` below TLSv1.2; pgaudit not loaded |

### `access_grants` rules

The rules that judge the retrieval role apply to the role your RAG
application connects as.

| Severity | Rule |
|---|---|
| CRITICAL | The retrieval role is a superuser, or a member of one. It has BYPASSRLS (or is a member of a role that has it) while a vector table relies on row security |
| HIGH | The retrieval role owns an RLS table without `FORCE ROW LEVEL SECURITY`. It holds INSERT, UPDATE, DELETE or TRUNCATE on a vector table. It has CREATEROLE. Separately, PUBLIC can SELECT a vector table that has row security off |
| MEDIUM | PUBLIC can CREATE in the vector extension's schema or a schema on the search path |
| LOW | VecShield itself audited as a superuser or BYPASSRLS role (see below). Separately, a table that relies on row security is searched through an HNSW/IVFFlat index with iterative scans off, so its searches can come back short. Nothing leaks |

`access_model()` also records two facts that no rule judges yet:

- SECURITY DEFINER functions the retrieval role can execute, with their owners;
- the number of LEAKPROOF pgvector functions (pgvector marks none LEAKPROOF).

## Approximate indexes, filters and short results

pgvector applies a `WHERE` filter, and row-level security, to the rows an HNSW
or IVFFlat index returns. HNSW returns `hnsw.ef_search` candidates per scan,
40 by default. A tenant's filtered search can therefore return fewer rows than
it asked for, or none, when other tenants' rows fill the scan. This is lost
recall, not a leak.

To tell lost recall from an isolation failure, the isolation probe works like
this:

- **It searches the way your application does.** It uses the distance
  operator of the column's index (`<=>`, `<->`, `<#>` or `<+>`), so its
  queries take the same index path.
- **It asks again when a view comes back short.** When a tenant's filtered
  view is short, it repeats that query once with iterative index scans on:
  `hnsw.iterative_scan = strict_order` or `ivfflat.iterative_scan =
  relaxed_order`. The setting applies only inside a read-only transaction
  (`SET LOCAL`), so nothing persists.
- **It classifies the retry:**
  - whole → `recall_loss`, and the tenant is judged on the retried rows;
  - still short → `still_short`, and the result stays partial;
  - another tenant's row appears → `leak`, which is reported like any other
    leak.

The result's coverage records the index, its type and metric, the
`hnsw.*` / `ivfflat.*` settings and the retry outcomes under `ann_index`.

The effective `iterative_scan` comes from one of two places:

- the declared retrieval role's own `ALTER ROLE … SET` value, when it has one;
- otherwise, the value VecShield's session sees.

When the effective setting is `off`, the shared collection gets a LOW finding.
A table that relies on row security gets one too, under `access_grants`. The
fix is `ALTER ROLE <app role> SET hnsw.iterative_scan = strict_order`, on
pgvector 0.8.0 or later. Don't fix short results by retrieving as a role that
bypasses row security; that trades lost recall for a leak.

## Declare the retrieval role

Least privilege is about the role the application reads as, which VecShield
cannot guess. Declare that role by name. Never give its password. You can
declare it in any of these places:

- CLI: `--retrieval-role rag_reader`
- Store configuration (`conn`): `"retrieval_role": "rag_reader"`
- Console: Stores → the pgvector store → **Retrieval role**

When no retrieval role is declared, VecShield judges the role it connected as.
In that case it:

- labels those findings "assumed retrieval role";
- caps them at MEDIUM;
- leaves `access_grants` **inconclusive**.

A role that does not exist in the database is named in the result. It is
never treated as clean.

## The role to audit with

Audit with a dedicated, least-privileged role:

```sql
CREATE ROLE vecshield_auditor LOGIN PASSWORD '<from your secret store>';

-- Settings (pg_read_all_settings) and statistics (pg_read_all_stats).
GRANT pg_monitor TO vecshield_auditor;

-- Reading the chunks, for classification and the isolation probe.
GRANT USAGE ON SCHEMA public TO vecshield_auditor;
GRANT SELECT ON public.docs TO vecshield_auditor;   -- each vector table

-- Optional: let it read pg_hba.conf rules, which are superuser-only by
-- default. Check these grants against your PostgreSQL version.
GRANT SELECT ON pg_catalog.pg_hba_file_rules TO vecshield_auditor;
GRANT EXECUTE ON FUNCTION pg_catalog.pg_hba_file_rules() TO vecshield_auditor;
```

Authenticate it with `scram-sha-256`. With `password_encryption =
scram-sha-256` (the default since PostgreSQL 14), a new password is stored as
SCRAM.

**The trade-off with row security.** Row security applies to this role too.
On a table whose policies do not admit it, the role reads no rows. The
classification scan and the tenant-isolation probe then see only what the
policies allow. You have two options:

- give the auditor a policy that admits it;
- audit as a BYPASSRLS role.

If you audit as a BYPASSRLS role or a superuser, VecShield reports a LOW
`privileged_auditor` finding. Isolation results from that run show every row,
not what an application role sees.

`pg_monitor` includes `pg_read_all_stats`. The `pg_stat_statements` rule
therefore leaves out the auditing role itself.

## What each read needs

| Read | Needs | Without it |
|---|---|---|
| `pg_roles`, `pg_class`, `pg_policy`, `pg_extension`, `pg_available_extensions` | Any login role | (always readable) |
| `has_table_privilege`, `has_schema_privilege`, `pg_has_role` | Any login role | (always callable) |
| `system_user` | PostgreSQL 16+ | Below 16, only "a password was required" can be observed |
| `pg_index`, `pg_db_role_setting`, `current_setting('hnsw.*')` | Any login role | (always readable). Iterative scans need pgvector 0.8.0+ |
| `ssl`, `listen_addresses`, `password_encryption`, `ssl_min_protocol_version` | Any login role | The rule is not evaluated |
| `shared_preload_libraries`, `pgaudit.*` and other superuser-only settings | `pg_read_all_settings` (in `pg_monitor`) | The pgaudit rules are not evaluated |
| `pg_hba_file_rules` | Superuser, or the grants above | The hba rules are not evaluated, and TLS enforcement is not observable |
| Rows of a vector table | SELECT on it, and a row-security policy that admits the role | The table is listed as unreadable, never as empty |

## Reading the results

- **Not observable / not evaluated is not a pass.** If a read was refused,
  VecShield names the rule and the privilege it needed. For `access_grants`,
  the outcome is `unsupported` or `inconclusive` with
  `access_state: not_observable` or `not_verified`. For `server_hardening`,
  the rule is listed under `rules_not_evaluated`. In either case the check is
  never `passed` and never `failed`.
- **Failed** means a HIGH or CRITICAL rule fired on something VecShield read.
- **Inconclusive with findings** means only MEDIUM or LOW weaknesses were
  observed. Their weight depends on which roles connect.
- **`pg_hba_file_rules` shows the file on disk.** A pending reload can differ
  from the rules the server has loaded.
- **Connection poolers.** PgBouncer and similar poolers authenticate clients
  themselves. `system_user` describes the pooler's connection to the server,
  not your application's connection to the pooler.

## Compliance mapping

`access_grants` is cited by these criteria:

- `HIPAA-164-312-A1-ACCESS-CONTROL-01`
- `HIPAA-164-308-A4-ACCESS-MGMT-01`
- `GDPR-SECURITY-32-01`

Connectors that cannot report roles and grants record the check as not
observable. These criteria then read inconclusive for those stores rather than
passed.

`server_hardening` has **no regulatory mapping** in the pack. It bundles
independent settings, so a criterion would fail on whichever rule fired.
`compliance/store_controls_basis.py` lists the obligations those settings
bear on, as supporting context only.
