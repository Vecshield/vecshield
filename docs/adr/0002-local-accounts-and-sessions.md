# ADR 0002: Local accounts and console sessions

Status: accepted (2026-09-28)

## Context

The API authenticated callers with static bearer tokens (an admin token and an
optional read-only token) or HS256 JWTs from an identity provider. With none
configured, authentication was off and every caller was a synthetic `admin`,
which `serve` allowed only on localhost.

That left the console without a sign-in of its own. A deployment without an
identity provider had two choices: share one static token among everyone, so
the audit log could not say who approved a plan or revealed a value, and
separation of duties could not tell two people apart; or run open on
localhost. The product requirement is a console that starts with one
administrator, `admin` with password `admin`, who can create further users.

Browser sessions add a threat that bearer tokens do not have. A cookie is sent
automatically, so a page on another site can make the browser send a
state-changing request with the user's session (CSRF).

## Decision

1. **Local accounts** live in a SQLite store (`vecshield_platform/api/users.py`,
   `<state-dir>/sqlite/users.db`, created `0600` before SQLite opens it so its
   WAL/SHM sidecars inherit the mode). Accounts have a username (lowercase,
   `^[a-z0-9][a-z0-9._@-]{1,63}$`), one or more of the existing roles,
   a disabled flag, and a must-change-password flag. They are disabled, never
   deleted, so audit entries stay attributable.
2. **Passwords** are hashed with stdlib `hashlib.scrypt` (n=2^14, r=8, p=1,
   16-byte salt, 32-byte key), encoded `scrypt$n$r$p$salt$hash`, compared with
   `hmac.compare_digest`. A sign-in for an unknown name still runs one scrypt.
   New passwords need 12 to 256 characters, must differ from the username, and
   must not be in a small denylist.
3. **Bootstrap.** When the accounts table is empty, the store creates `admin`
   (role admin) with password `admin`, or `VECSHIELD_INITIAL_ADMIN_PASSWORD`
   when set, flagged must-change-password, and logs a warning. `serve` prints
   whether the default password is still in effect, and refuses to bind beyond
   localhost while it would be or still is (see Consequences).
4. **Forced change.** A session whose account must change its password gets
   `403 password change required` from every protected endpoint. Only
   `/auth/session`, `/auth/password`, and `/auth/logout` still work.
5. **Sessions.** Sign-in issues `secrets.token_urlsafe(32)` in an HttpOnly,
   `SameSite=Strict`, `Path=/` cookie (`vecshield_session`), `Secure` over HTTPS
   or with `VECSHIELD_COOKIE_SECURE=1`. Only the token's SHA-256 is stored.
   Sessions end after 60 idle minutes or 12 hours (both configurable); the last
   use is written at most once a minute. A password change revokes the
   account's other sessions; an administrative reset or disabling revokes all
   of them. Roles and the disabled flag are read from the store on every
   request, so changes apply immediately.
6. **CSRF.** A cookie-authenticated request with an unsafe method must carry
   `X-VecShield-CSRF: 1`. A cross-site form cannot set a custom header, and a
   cross-origin script cannot send one without a CORS preflight the server
   does not grant (unless an operator lists that origin). `SameSite=Strict` is
   a second layer. Bearer-authenticated requests are exempt, as they are not
   sent automatically. Sign-in itself is not header-gated: it carries no
   session yet, and FastAPI accepts its body only as `application/json`,
   which a cross-site form cannot send.
7. **Lockout.** Five consecutive wrong passwords lock an account for 15 minutes
   (configurable). A wrong current password on `/auth/password` counts too, so
   a stolen session cannot be used to guess the password. Success resets the
   count.
8. **Coexistence.** Static tokens and JWTs keep working for automation. A valid
   bearer credential authenticates the request; otherwise the session cookie is
   tried. With accounts enabled the synthetic open admin is never used, the
   API reports `auth_enabled` and `login_enabled`, and separation of duties
   defaults to `required`. `serve` enables accounts by default; `--no-login`
   or `VECSHIELD_LOGIN=off` turns them off. `serve` allows a non-loopback bind
   when accounts are enabled, because every request then needs a credential.
9. **Audit.** `auth.login`, `auth.login_failed`, `auth.logout`,
   `auth.password_changed`, `user.created`, `user.updated`, and
   `user.password_reset` go to the hash-chained audit log. A failed sign-in is
   attributed to the account only if the account exists, otherwise to
   `unknown`, since the typed name may be a mistyped password. Passwords are
   never logged.

## Alternatives considered

- **OIDC-only sign-in (RS256/JWKS, authorization-code flow).** This is the right
  end state for organizations with an identity provider, but it needs an
  asymmetric-crypto dependency, an outbound path to the provider, and provider
  setup before anyone can sign in. It does not meet the requirement of a
  console that works from first start. It remains future work and would sit
  beside local accounts, not replace them.
- **Keep static tokens and paste them into the console.** This gives no
  per-person identity and no way to revoke one person's access without
  rotating everyone's.
- **Stateless signed session cookies (JWT in a cookie).** This needs no session
  table, but sessions cannot be revoked on password change, reset, or
  disabling without a deny-list, which is a session table by another name.
- **bcrypt or argon2.** Both are good choices but add a native dependency.
  scrypt is memory-hard and in the standard library. The encoding records its
  parameters, so the cost can be raised later without breaking existing
  hashes.
- **Double-submit CSRF token.** This is equivalent in strength for this
  same-origin console but needs a readable cookie and more client state. A
  fixed custom header is enough when the API is same-origin.

## Consequences

- Every audit entry made from the console names a person, and separation of
  duties can tell two people apart.
- A fresh deployment reachable over the network before anyone signs in would
  expose `admin`/`admin`, and whoever signed in first could claim the account.
  So `serve` bound beyond localhost refuses a first start without
  `VECSHIELD_INITIAL_ADMIN_PASSWORD`, and refuses a restart while `admin`
  still has the password `admin`. On any host the variable must pass the
  password policy, since the restart check only recognises `admin`.
  The Helm chart refuses to render without the variable's Secret. Loopback
  binds keep the default for local evaluation.
- The static admin token's subject is `admin`, the same name as the bootstrap
  account. Audit entries from the two are told apart only by context.
  Deployments that need a hard distinction should give the token holder a JWT
  with its own subject.
- A locked account answers `429` where an unknown name answers `401`, which
  shows that a locked name exists. Failures for unknown names do not lock
  anything. This is accepted: usernames are not secrets here, and the lockout
  is what limits guessing.
- The store is one SQLite file guarded by one process-wide lock, consistent
  with the single-writer expectation of `serve`. Several API replicas would
  need a shared store.
- Rate limiting still keys cookie-authenticated requests by client IP.

## Migration and reproduction impact

- Existing deployments that upgrade and run `serve` get accounts on the next
  start. The console asks for sign-in as `admin`/`admin` (or the configured
  initial password), and then for a new password. Scripts using bearer tokens
  or JWTs are unaffected. To keep the previous open or token-only behaviour,
  pass `--no-login` or set `VECSHIELD_LOGIN=off`.
- `create_app()` without `user_store` behaves as before, so embedded and test
  uses are unaffected. `Principal` gained two defaulted fields
  (`must_change_password`, `granted_roles`).
- The accounts database belongs in backups with the rest of the state
  directory. Deleting it recreates the bootstrap admin on the next start,
  which is also the documented recovery path when every admin password is
  lost. Audit entries from before the reset keep their original actor names.
