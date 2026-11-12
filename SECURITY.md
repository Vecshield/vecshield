# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through
[GitHub's private vulnerability reporting](https://github.com/vecshield/vecshield/security/advisories/new)
rather than opening a public issue.

Useful things to include: the version or commit, how to reproduce it, and what
an attacker gains. We will acknowledge the report, agree a disclosure timeline
with you, and credit you in the advisory unless you prefer otherwise.

### Supported versions

VecShield is pre-1.0. Fixes land on `main` and in the next release; there are
no long-term support branches yet.

### Scope

In scope: authentication and authorization bypass, privilege escalation across
the `viewer` / `operator` / `compliance` / `admin` roles, separation-of-duties
bypass, unmasking of chunk values outside the audited reveal path, audit-log
tampering, secret disclosure in logs, reports or diagnostics, and SSRF through
connector or webhook configuration.

Out of scope: detector false negatives and false positives. Those are
correctness bugs — [open an issue](https://github.com/vecshield/vecshield/issues).
Known coverage gaps are documented in
[`docs/detection_limitations.md`](docs/detection_limitations.md).

## Data custody

VecShield runs in your environment. Chunks, embeddings, findings, audit logs
and reports stay in infrastructure you control. There is no managed backend and
telemetry is off by default. The only outbound request any engine makes is to a
vulnerability feed for CVE matching, which you can disable.

## Deployment hardening

- Bind the API to a private network and front it with your own authentication
  and TLS. `serve` refuses to bind beyond loopback without auth configured, and
  refuses while the bootstrap admin still has its default password.
- Configure auth explicitly: a static token
  (`LOCAL_ADMIN_TOKEN` / `CUSTOMER_API_TOKEN`), JWT validation
  (`VECSHIELD_JWT_SECRET`, `VECSHIELD_JWT_AUDIENCE`, `VECSHIELD_JWT_ISSUER`),
  or local accounts.
- Use least-privilege roles. `viewer` reads (reports, logs, masked views) and
  starts nothing. `operator` runs assessments that write results. `compliance`
  previews erasure, opens and executes DSARs, and stages, approves and executes
  plans. `admin` implies every role and alone may scan a server-side datasource
  or erase a subject directly.
- Deletion obeys `VECSHIELD_SAFE_MODE` for every role and, except for an admin,
  needs a second person: whoever opened a DSAR cannot also execute it unless
  separation of duties is turned off.
- Give connector credentials the least privilege that still lets the checks
  read what they need — see [`docs/pgvector.md`](docs/pgvector.md) for a worked
  example.
- Prefer secret references (`*_env` / `*_file`) over plaintext config values,
  and consider enforcing it with `VECSHIELD_REJECT_PLAINTEXT_SECRETS=1`.
- Enable request hardening as needed: CORS allow-list, body-size caps, rate
  limiting.
- Store the audit log on append-only, customer-controlled storage. It is
  hash-chained, so tampering is detectable, but only durable storage makes it
  recoverable.
- Scrape `/metrics` and monitor `/readyz`.

## How VecShield handles sensitive data it finds

- Detected spans are stored as **masked previews, never raw values**.
- Unmasking goes through `reveal.py`, which is role-gated and audit-logged.
- Diagnostic bundles are redacted by default. Review one before sharing it
  outside your environment.

## Suppression governance

False positives are handled with allow-list rules and time-boxed suppressions.
Suppressions are fingerprint-based, require an owner, reason and expiry, and
are recorded in evidence. Suppressed findings stay visible for audit, and
sensitive findings have stricter TTL limits. Suppressing a finding is a
decision with a name on it, not a delete.

See [`docs/deployment.md`](docs/deployment.md) for the full deployment guide.
