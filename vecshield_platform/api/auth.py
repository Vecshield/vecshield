"""Pluggable authentication & RBAC for the VecShield API (improvement plan 1.1).

Two authentication backends are supported out of the box:

* **Static bearer token** (unchanged, for local/dev and simple deployments): an
  ``admin`` token and an optional read-only token.
* **JWT bearer** (for OIDC providers issuing HS256 tokens — Okta/Entra/Auth0/
  Keycloak with a shared signing secret): validates signature, ``exp``/``nbf``,
  ``iss``/``aud``, and extracts a real subject and roles claim. ``exp`` and the
  subject claim are required: a token that never expires, or one that names
  nobody, is refused. An optional maximum lifetime
  (``VECSHIELD_JWT_MAX_LIFETIME`` seconds) also refuses long-lived tokens.

A third, **local-account session** (:class:`SessionAuthenticator`, backed by
:mod:`vecshield_platform.api.users`), serves the browser console: a user signs
in with a username and password and receives an HttpOnly session cookie.

All produce a :class:`Principal` carrying the authenticated *subject* (threaded
into the audit log so evidence is attributable) and a set of *roles*.

RBAC roles form a hierarchy: ``admin`` implies every role, ``compliance`` and
``operator`` each imply ``viewer``. Endpoints gate on a required role; a static
admin token therefore keeps full access (backward compatible), while a JWT can
carry a narrower role (e.g. a compliance officer who may run DSAR/erasure but
not manage stores).

Note on algorithms: only symmetric HS256 is implemented here because the target
environment has no asymmetric-crypto dependency. RS256/JWKS validation (the
common OIDC default) is a documented future extension that would plug in behind
the same :class:`Authenticator` protocol.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Iterable, Optional, Protocol


# --------------------------------------------------------------------------- #
# Roles                                                                       #
# --------------------------------------------------------------------------- #

VIEWER = "viewer"
OPERATOR = "operator"
COMPLIANCE = "compliance"
ADMIN = "admin"

#: All roles that can be assigned, most→least privileged is not implied here;
#: privilege is expressed via _IMPLIES below.
ALL_ROLES = (VIEWER, OPERATOR, COMPLIANCE, ADMIN)

#: Each granted role implies (grants) this set of effective roles.
_IMPLIES: dict[str, frozenset[str]] = {
    ADMIN: frozenset({ADMIN, COMPLIANCE, OPERATOR, VIEWER}),
    COMPLIANCE: frozenset({COMPLIANCE, VIEWER}),
    OPERATOR: frozenset({OPERATOR, VIEWER}),
    VIEWER: frozenset({VIEWER}),
}


def expand_roles(roles: Iterable[str]) -> frozenset[str]:
    """Expand granted roles into the full set of effective roles they imply."""
    out: set[str] = set()
    for r in roles:
        out |= _IMPLIES.get(r, {r})
    return frozenset(out)


def normalize_roles(raw: object) -> set[str]:
    """Parse a roles claim (list, space- or comma-delimited string) into known
    roles. Unknown role names are ignored so an external IdP can't smuggle in a
    privilege VecShield doesn't recognize."""
    if raw is None:
        return set()
    if isinstance(raw, str):
        tokens = [t for chunk in raw.split(",") for t in chunk.split()]
    elif isinstance(raw, (list, tuple, set)):
        tokens = [str(t) for t in raw]
    else:
        return set()
    return {t.lower() for t in tokens if t.lower() in ALL_ROLES}


# --------------------------------------------------------------------------- #
# Principal                                                                   #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Principal:
    """An authenticated caller. ``roles`` are already expanded (see
    :func:`expand_roles`), so :meth:`has_role` is a plain membership test."""

    subject: str
    roles: frozenset[str]
    source: str = "static"
    #: Set for a local-account session whose password must be changed before
    #: anything else is allowed (bootstrap admin, administrative reset).
    must_change_password: bool = False
    #: The roles as granted, before expansion; empty means "same as roles".
    granted_roles: frozenset[str] = frozenset()

    def has_role(self, role: str) -> bool:
        return role in self.roles

    @property
    def granted(self) -> frozenset[str]:
        """Roles as granted (``admin``), as opposed to effective (all four)."""
        return self.granted_roles or self.roles


# --------------------------------------------------------------------------- #
# Errors & helpers                                                            #
# --------------------------------------------------------------------------- #

class AuthError(Exception):
    """A credential was presented but is invalid (bad signature, expired, ...)."""


def extract_bearer(authorization: Optional[str]) -> Optional[str]:
    """Return the token from an ``Authorization: Bearer <token>`` header."""
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme != "Bearer" or not token:
        return None
    return token


def _b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def decode_jwt_hs256(
    token: str,
    secret: str,
    *,
    audience: Optional[str] = None,
    issuer: Optional[str] = None,
    leeway: float = 60.0,
    now: Optional[float] = None,
    require_exp: bool = True,
    max_lifetime_s: Optional[float] = None,
) -> dict:
    """Verify an HS256 JWT and return its claims, or raise :class:`AuthError`.

    Validates the signature (constant-time), ``exp``/``nbf`` (with ``leeway``
    seconds of clock skew), and — when provided — ``iss`` and ``aud``. ``exp``
    is required unless ``require_exp`` is false: a bearer credential with no
    expiry is valid forever once leaked. With ``max_lifetime_s``, a token whose
    ``exp`` lies further than that past its ``iat`` (or past now, without
    ``iat``) is refused.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise AuthError("malformed JWT")
    header_b64, payload_b64, sig_b64 = parts
    try:
        header = json.loads(_b64url_decode(header_b64))
    except Exception as e:
        raise AuthError("malformed JWT header") from e
    alg = header.get("alg")
    if alg != "HS256":
        raise AuthError(f"unsupported JWT alg: {alg!r} (only HS256 supported)")

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    expected_sig = hmac.new(secret.encode("utf-8"), signing_input,
                            hashlib.sha256).digest()
    try:
        actual_sig = _b64url_decode(sig_b64)
    except Exception as e:
        raise AuthError("malformed JWT signature") from e
    if not hmac.compare_digest(expected_sig, actual_sig):
        raise AuthError("bad JWT signature")

    try:
        claims = json.loads(_b64url_decode(payload_b64))
    except Exception as e:
        raise AuthError("malformed JWT payload") from e
    if not isinstance(claims, dict):
        raise AuthError("malformed JWT payload")

    t = time.time() if now is None else now
    exp = claims.get("exp")
    if exp is None:
        if require_exp:
            raise AuthError("JWT has no exp claim")
    else:
        try:
            exp = float(exp)
        except (TypeError, ValueError) as e:
            raise AuthError("malformed JWT exp claim") from e
        if t > exp + leeway:
            raise AuthError("JWT expired")
        if max_lifetime_s is not None:
            iat = claims.get("iat")
            try:
                start = float(iat) if iat is not None else t
            except (TypeError, ValueError) as e:
                raise AuthError("malformed JWT iat claim") from e
            if exp - start > max_lifetime_s + leeway:
                raise AuthError("JWT lifetime exceeds the configured maximum")
    nbf = claims.get("nbf")
    if nbf is not None and t + leeway < float(nbf):
        raise AuthError("JWT not yet valid")
    if issuer is not None and claims.get("iss") != issuer:
        raise AuthError("bad JWT issuer")
    if audience is not None:
        aud = claims.get("aud")
        auds = aud if isinstance(aud, list) else [aud]
        if audience not in auds:
            raise AuthError("bad JWT audience")
    return claims


# --------------------------------------------------------------------------- #
# Authenticators                                                              #
# --------------------------------------------------------------------------- #

class Authenticator(Protocol):
    def authenticate(self, authorization: Optional[str]) -> Optional[Principal]:
        """Return a Principal on success, ``None`` if the credential isn't for
        this backend, or raise :class:`AuthError` for a definitive rejection."""
        ...


class StaticTokenAuthenticator:
    """Validates a static admin/read bearer token (constant-time)."""

    def __init__(self, admin_token: Optional[str], read_token: Optional[str] = None):
        self._admin_token = admin_token
        self._read_token = read_token

    def authenticate(self, authorization: Optional[str]) -> Optional[Principal]:
        token = extract_bearer(authorization)
        if token is None:
            return None
        if self._admin_token and hmac.compare_digest(token, self._admin_token):
            return Principal("admin", expand_roles({ADMIN}), source="static",
                             granted_roles=frozenset({ADMIN}))
        if self._read_token and hmac.compare_digest(token, self._read_token):
            return Principal("reader", expand_roles({VIEWER}), source="static",
                             granted_roles=frozenset({VIEWER}))
        return None


class JWTAuthenticator:
    """Validates HS256 JWT bearer tokens issued by an OIDC provider."""

    def __init__(
        self,
        secret: str,
        *,
        audience: Optional[str] = None,
        issuer: Optional[str] = None,
        roles_claim: str = "roles",
        subject_claim: str = "sub",
        leeway: float = 60.0,
        default_roles: Iterable[str] = (VIEWER,),
        max_lifetime_s: Optional[float] = None,
    ):
        if not secret:
            raise ValueError("JWTAuthenticator requires a non-empty secret")
        self._max_lifetime_s = max_lifetime_s
        self._secret = secret
        self._audience = audience
        self._issuer = issuer
        self._roles_claim = roles_claim
        self._subject_claim = subject_claim
        self._leeway = leeway
        self._default_roles = tuple(default_roles)

    def authenticate(self, authorization: Optional[str]) -> Optional[Principal]:
        token = extract_bearer(authorization)
        # Only handle things that look like a JWT; let other backends try the
        # rest (e.g. an opaque static token).
        if token is None or token.count(".") != 2:
            return None
        claims = decode_jwt_hs256(
            token, self._secret, audience=self._audience, issuer=self._issuer,
            leeway=self._leeway, require_exp=True, max_lifetime_s=self._max_lifetime_s,
        )
        raw_subject = claims.get(self._subject_claim)
        if (isinstance(raw_subject, bool) or not isinstance(raw_subject, (str, int))
                or not str(raw_subject).strip()):
            # Every JWT caller used to become "jwt-user", so the audit log
            # could not tell two of them apart.
            raise AuthError(f"JWT has no {self._subject_claim!r} claim")
        subject = str(raw_subject).strip()
        roles = normalize_roles(claims.get(self._roles_claim)) or set(self._default_roles)
        return Principal(subject, expand_roles(roles), source="jwt",
                         granted_roles=frozenset(roles))


class CompositeAuthenticator:
    """Tries each backend in order; first to return a Principal wins."""

    def __init__(self, authenticators: Iterable[Authenticator]):
        self._authenticators = list(authenticators)

    def authenticate(self, authorization: Optional[str]) -> Optional[Principal]:
        for backend in self._authenticators:
            principal = backend.authenticate(authorization)  # may raise AuthError
            if principal is not None:
                return principal
        return None


class SessionUser(Protocol):
    @property
    def username(self) -> str: ...

    @property
    def roles(self) -> tuple[str, ...]: ...

    @property
    def must_change_password(self) -> bool: ...


class SessionResolver(Protocol):
    def resolve_session(self, token: Optional[str]) -> Optional[SessionUser]:
        ...


class SessionAuthenticator:
    """Resolves a browser session cookie issued by a local-account sign-in.

    Kept separate from the bearer :class:`Authenticator` chain on purpose: a
    cookie is sent by the browser automatically, so the API applies CSRF
    checks to it that bearer credentials do not need.
    """

    def __init__(self, store: SessionResolver):
        self._store = store

    def authenticate_session(self, token: Optional[str]) -> Optional[Principal]:
        if not token:
            return None
        user = self._store.resolve_session(token)
        if user is None:
            return None
        granted = frozenset(user.roles)
        return Principal(user.username, expand_roles(granted), source="session",
                         must_change_password=bool(user.must_change_password),
                         granted_roles=granted)
