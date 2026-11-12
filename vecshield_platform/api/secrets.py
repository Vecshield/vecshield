"""Pluggable secret resolution for connector configuration.

Secrets (passwords, API keys, tokens, DSNs) must never be persisted in the
config file. The stored connector config instead references a secret indirectly
and it is resolved to its real value at connect time, by suffix:

  * ``<key>_env``  -> value of the named environment variable
  * ``<key>_file`` -> trimmed contents of the named file (Docker/K8s secret
    mounts, ``/run/secrets/vecshield/...``)

Example stored config::

    {"host": "db", "user": "svc", "password_env": "VECSHIELD_STORE_PG_PASSWORD"}
    {"api_key_file": "/run/secrets/vecshield/pinecone_key"}

**Reference allowlist (ADR 0003).** A store's connection config is written by
an admin and the resolved value is sent to a host of that admin's choosing
(``/admin/stores/test-connection``). Without limits, an admin could read any
environment variable or file the server can see, including the server's own
credentials. So a reference resolves only when it passes
:class:`SecretReferencePolicy`:

* ``*_env`` names must start with an allowed prefix (``VECSHIELD_SECRET_ENV_PREFIXES``,
  comma separated, default ``VECSHIELD_STORE_``) or be listed exactly in
  ``VECSHIELD_SECRET_ENV_ALLOW`` (comma separated; the migration path for
  existing names such as ``PG_PASSWORD``).
* ``*_file`` paths must be absolute and, after resolving symlinks and ``..``,
  lie under an allowed root (``VECSHIELD_SECRET_FILE_ROOTS``, comma separated,
  default ``/run/secrets/vecshield/``).
* Regardless of those settings, the server's own authentication and
  configuration variables and the platform's workload-identity token paths are
  always refused (:data:`ALWAYS_DENIED_ENV`, :func:`_env_always_denied`,
  :data:`ALWAYS_DENIED_FILE_ROOTS`).

The policy is checked before the variable or file is looked at, so a refused
reference reveals nothing about whether the target exists. Errors name the
reference and the rule, never a value.

Additional backends (e.g. a cloud secrets manager) can be added by registering a
resolver for a new suffix via :func:`register_resolver`. Resolution is applied
only in :func:`resolve_conn`, called by ``ConfigStore.build_registry`` — the
raw config on disk keeps only the indirect reference.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Callable, Dict, Optional

logger = logging.getLogger(__name__)


class SecretResolutionError(ValueError):
    """A referenced secret could not be resolved (missing env var / file)."""


class SecretReferenceDenied(SecretResolutionError):
    """A secret reference is outside what this deployment allows (ADR 0003)."""


#: Environment variables the server itself reads for authentication or
#: configuration. Never resolvable as a store secret, even when allowlisted.
ALWAYS_DENIED_ENV: frozenset[str] = frozenset({
    "CUSTOMER_API_TOKEN",
    "LOCAL_ADMIN_TOKEN",
    "VECSHIELD_ADMIN_TOKEN",
    "VECSHIELD_API_TOKEN",
    "VECSHIELD_JWT_SECRET",
    "VECSHIELD_INITIAL_ADMIN_PASSWORD",
    "VECSHIELD_OIDC_CLIENT_SECRET",
    "VECSHIELD_SCIM_TOKEN",
    "VECSHIELD_SCIM_TOKEN_SHA256",
    "VECSHIELD_SECRET_ENV_PREFIXES",
    "VECSHIELD_SECRET_ENV_ALLOW",
    "VECSHIELD_SECRET_FILE_ROOTS",
})

#: The namespace a store secret may use inside ``VECSHIELD_*``. Every other
#: ``VECSHIELD_*`` name belongs to the server's own configuration and is
#: refused (for example ``VECSHIELD_OIDC_*``, ``VECSHIELD_SCIM_*``,
#: ``VECSHIELD_JWT_*`` and any ``VECSHIELD_*PASSWORD*``), so widening the
#: prefix list to ``VECSHIELD_`` cannot expose them.
STORE_ENV_NAMESPACE = "VECSHIELD_STORE_"

#: Paths never readable as a store secret, even under an allowed root:
#: Kubernetes service-account and projected tokens, cloud workload-identity
#: tokens, and kernel pseudo-filesystems.
ALWAYS_DENIED_FILE_ROOTS: tuple[str, ...] = (
    "/var/run/secrets/kubernetes.io",
    "/run/secrets/kubernetes.io",
    "/var/run/secrets/eks.amazonaws.com",
    "/run/secrets/eks.amazonaws.com",
    "/var/run/secrets/azure",
    "/run/secrets/azure",
    "/var/run/secrets/tokens",
    "/run/secrets/tokens",
    "/proc",
    "/sys",
    "/dev",
)

DEFAULT_ENV_PREFIXES = ("VECSHIELD_STORE_",)
DEFAULT_FILE_ROOTS = ("/run/secrets/vecshield/",)

ENV_PREFIXES_VAR = "VECSHIELD_SECRET_ENV_PREFIXES"
ENV_ALLOW_VAR = "VECSHIELD_SECRET_ENV_ALLOW"
FILE_ROOTS_VAR = "VECSHIELD_SECRET_FILE_ROOTS"


def _csv(value: Optional[str]) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(part.strip() for part in value.split(",") if part.strip())


def _env_always_denied(name: str) -> bool:
    upper = name.upper()
    if upper in ALWAYS_DENIED_ENV:
        return True
    # The server's own configuration namespace, outside the store namespace.
    return upper.startswith("VECSHIELD_") and not upper.startswith(STORE_ENV_NAMESPACE)


def _under(path: str, root: str) -> bool:
    root = root.rstrip(os.sep) or os.sep
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:  # different drives (Windows)
        return False


@dataclass(frozen=True)
class SecretReferencePolicy:
    """Which ``*_env`` names and ``*_file`` paths may be resolved."""

    env_prefixes: tuple[str, ...] = DEFAULT_ENV_PREFIXES
    env_allow: frozenset[str] = frozenset()
    file_roots: tuple[str, ...] = DEFAULT_FILE_ROOTS

    @classmethod
    def from_env(cls, environ: Optional[dict] = None) -> "SecretReferencePolicy":
        env = os.environ if environ is None else environ
        prefixes = (_csv(env.get(ENV_PREFIXES_VAR))
                    if env.get(ENV_PREFIXES_VAR) is not None else DEFAULT_ENV_PREFIXES)
        roots = (_csv(env.get(FILE_ROOTS_VAR))
                 if env.get(FILE_ROOTS_VAR) is not None else DEFAULT_FILE_ROOTS)
        return cls(env_prefixes=prefixes,
                   env_allow=frozenset(_csv(env.get(ENV_ALLOW_VAR))),
                   file_roots=roots)

    def check_env(self, name: str, *, key: str = "") -> None:
        """Raise :class:`SecretReferenceDenied` unless ``name`` may be read."""
        label = f"{key}={name}" if key else name
        if not name:
            raise SecretReferenceDenied(f"secret reference {key or '*_env'} is empty")
        if _env_always_denied(name):
            raise SecretReferenceDenied(
                f"secret reference {label} refused: the server's own authentication "
                "and configuration variables can never be used as a store secret "
                f"(only {STORE_ENV_NAMESPACE}* names inside the VECSHIELD_ namespace)")
        if name in self.env_allow:
            return
        if any(name.startswith(p) for p in self.env_prefixes):
            return
        raise SecretReferenceDenied(
            f"secret reference {label} refused: environment variable names must start "
            f"with an allowed prefix ({', '.join(self.env_prefixes) or 'none configured'}; "
            f"{ENV_PREFIXES_VAR}) or be listed exactly in {ENV_ALLOW_VAR}")

    def check_file(self, path: str, *, key: str = "") -> str:
        """Return the resolved real path, or raise :class:`SecretReferenceDenied`."""
        label = f"{key}={path}" if key else path
        if not path or not os.path.isabs(path):
            raise SecretReferenceDenied(
                f"secret reference {label} refused: a secret file must be an absolute path")
        real = os.path.realpath(path)
        for denied in ALWAYS_DENIED_FILE_ROOTS:
            if _under(real, denied) or _under(os.path.normpath(path), denied):
                raise SecretReferenceDenied(
                    f"secret reference {label} refused: platform credential and "
                    "pseudo-filesystem paths can never be used as a store secret")
        roots = [os.path.realpath(r) for r in self.file_roots if r]
        if not any(_under(real, root) for root in roots):
            raise SecretReferenceDenied(
                f"secret reference {label} refused: secret files must resolve (after "
                "symlinks and '..') under an allowed root "
                f"({', '.join(self.file_roots) or 'none configured'}; {FILE_ROOTS_VAR})")
        return real


def current_policy() -> SecretReferencePolicy:
    """The policy from the current environment (read on each call)."""
    return SecretReferencePolicy.from_env()


def _resolve_env(env_name: str) -> str:
    current_policy().check_env(env_name)
    value = os.environ.get(env_name)
    if value is None:
        raise SecretResolutionError(f"environment variable not set: {env_name}")
    return value


def _resolve_file(path: str) -> str:
    real = current_policy().check_file(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        # Open the resolved path without following a final symlink, so a link
        # swapped in after the check cannot redirect the read.
        fd = os.open(real, flags)
        with os.fdopen(fd, "r", encoding="utf-8") as fh:
            # Trailing newlines are common in mounted secret files.
            return fh.read().strip()
    except OSError as exc:
        raise SecretResolutionError(
            f"secret file unreadable: {path} ({type(exc).__name__})") from exc


# suffix (including the leading underscore) -> resolver(reference) -> value
_RESOLVERS: Dict[str, Callable[[str], str]] = {
    "_env": _resolve_env,
    "_file": _resolve_file,
}

# Suffixes that mark a value as an indirect reference rather than a plaintext
# secret. Kept in sync with ``_RESOLVERS``.
REFERENCE_SUFFIXES = tuple(_RESOLVERS.keys())


def register_resolver(suffix: str, resolver: Callable[[str], str]) -> None:
    """Register a resolver for a config-key suffix (e.g. ``"_vault"``)."""
    if not suffix.startswith("_"):
        raise ValueError("secret-reference suffix must start with '_'")
    _RESOLVERS[suffix] = resolver
    global REFERENCE_SUFFIXES
    REFERENCE_SUFFIXES = tuple(_RESOLVERS.keys())


def is_reference_key(key: str) -> bool:
    """True if ``key`` is an indirect secret reference (``*_env`` / ``*_file``)."""
    return any(key.endswith(sfx) for sfx in _RESOLVERS)


def check_references(conn: dict, policy: Optional[SecretReferencePolicy] = None) -> None:
    """Refuse a connection whose ``*_env``/``*_file`` references break the policy.

    Only the policy is checked; whether the variable is set or the file exists
    is left to :func:`resolve_conn`, so this is safe to run at save time.
    """
    policy = policy or current_policy()
    for key, value in conn.items():
        if key.endswith("_env"):
            policy.check_env(str(value), key=key)
        elif key.endswith("_file"):
            policy.check_file(str(value), key=key)


def reference_names(conn: dict) -> dict[str, str]:
    """The indirect references in ``conn``, as ``{key: env name or path}``.

    For the audit log: says *which* variable or file a store reads its secret
    from, never the secret. Sorted for a stable hash-chained entry.
    """
    return {k: str(conn[k]) for k in sorted(conn) if is_reference_key(k)}


def resolve_conn(conn: dict) -> dict:
    """Return a copy of ``conn`` with reference keys resolved to real values.

    A ``<base>_env`` / ``<base>_file`` key is replaced by ``<base>`` carrying the
    resolved value. Raises :class:`SecretResolutionError` if a reference cannot
    be resolved (fail closed — never connect with a missing credential), and
    its subclass :class:`SecretReferenceDenied` if the reference is outside the
    allowlist (ADR 0003).
    """
    policy = current_policy()
    resolved = dict(conn)
    for key in list(resolved.keys()):
        for suffix, resolver in _RESOLVERS.items():
            if key.endswith(suffix):
                base = key[: -len(suffix)]
                # Checked here too (the built-in resolvers re-check) so the
                # refusal names the config key as well as the reference.
                check_references({key: resolved[key]}, policy)
                resolved[base] = resolver(str(resolved[key]))
                resolved.pop(key)
                break
    return resolved
