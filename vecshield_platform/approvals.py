"""Who may approve what they themselves proposed.

Two places in the product refuse to let one person both propose and authorize:
an action plan (``execution.approve``) and a risk exception
(``/compliance/exceptions/{id}/approve``). The rule is right for a team and
unsatisfiable for a person: with authentication disabled every caller is the
synthetic ``admin``, so nothing staged can ever be approved, and a one-person
deployment is stuck the same way with a real token.

This module makes the rule a stated deployment policy rather than a constant.
Three modes, in order of strictness:

* ``required`` — the approver must be a different subject. The default whenever
  real authentication is configured.
* ``admin_may_self_approve`` — a principal holding ``admin`` may approve their
  own proposal; anyone else still needs a second person. The default when
  authentication is disabled, because then the rule cannot be met at all.
* ``off`` — anyone with the approving role may self-approve. For test rigs.

Whatever the mode, a self-approval is recorded as one: the approval record,
the audit event, and the console all say ``self_approved``. Relaxing the rule
never hides that it was relaxed.

Irreversible operations are excepted from ``admin_may_self_approve``: a delete
still needs a second person unless the mode is ``off``. A deployment that
cannot produce a second person for a permanent deletion should not be running
one from here.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Iterable

#: Environment override, read after the explicit setting and before the default.
SEPARATION_ENV = "VECSHIELD_SEPARATION_OF_DUTIES"

REQUIRED = "required"
ADMIN_MAY_SELF_APPROVE = "admin_may_self_approve"
OFF = "off"
MODES = (REQUIRED, ADMIN_MAY_SELF_APPROVE, OFF)

#: The role whose holders may self-approve under ``admin_may_self_approve``.
#: Kept as a string so this module does not import the API's auth layer.
ADMIN_ROLE = "admin"


class SeparationError(ValueError):
    """A configured mode this module does not know."""


@dataclass(frozen=True)
class SeparationOfDuties:
    """The deployment's rule, resolved once and passed to every approval."""

    mode: str
    #: Why this mode is in force: "configured", "environment", or "default".
    source: str = "configured"

    def __post_init__(self) -> None:
        if self.mode not in MODES:
            raise SeparationError(
                f"unknown separation-of-duties mode '{self.mode}'; "
                f"expected one of {', '.join(MODES)}")

    @classmethod
    def resolve(cls, configured: str | None = None, *,
                auth_enabled: bool) -> "SeparationOfDuties":
        """Explicit setting, then the environment, then a default that fits
        the deployment: strict when there are real identities, workable when
        every caller is the same synthetic admin."""
        if configured:
            return cls(configured.strip().lower(), source="configured")
        from_env = os.environ.get(SEPARATION_ENV, "").strip().lower()
        if from_env:
            return cls(from_env, source="environment")
        return cls(REQUIRED if auth_enabled else ADMIN_MAY_SELF_APPROVE, source="default")

    def allows_self_approval(self, roles: Iterable[str], *,
                             irreversible: bool = False) -> bool:
        """Whether ``roles`` may approve something they themselves proposed."""
        if self.mode == OFF:
            return True
        if self.mode == ADMIN_MAY_SELF_APPROVE:
            return ADMIN_ROLE in set(roles) and not irreversible
        return False

    def refusal(self, *, proposer: str, what: str = "this plan",
                irreversible: bool = False) -> str:
        """The sentence a refused self-approval carries."""
        if self.mode == ADMIN_MAY_SELF_APPROVE and irreversible:
            return (f"{proposer} proposed {what} and cannot also approve it: it "
                    "contains an irreversible operation, and a permanent change to "
                    "customer data needs a second person even where an admin may "
                    "otherwise self-approve.")
        if self.mode == ADMIN_MAY_SELF_APPROVE:
            return (f"{proposer} proposed {what} and cannot also approve it. On this "
                    "deployment only an admin may self-approve.")
        return (f"{proposer} proposed {what} and cannot also approve it. A second "
                "person has to authorize a change to customer data.")

    def to_dict(self) -> dict:
        return {
            "separation_of_duties": self.mode,
            "source": self.source,
            "variable": SEPARATION_ENV,
            "self_approval": {
                REQUIRED: "never",
                ADMIN_MAY_SELF_APPROVE: "admins, except for irreversible operations",
                OFF: "anyone holding the approving role",
            }[self.mode],
            "note": {
                REQUIRED: "A plan or exception is approved by someone other than the "
                          "person who proposed it.",
                ADMIN_MAY_SELF_APPROVE: "An admin may approve their own plan or exception. "
                                        "Every such approval is recorded as self-approved.",
                OFF: "Separation of duties is off. Every self-approval is still recorded "
                     "as one. This setting is for test rigs.",
            }[self.mode],
        }


#: The rule the product applied before this module existed, kept as the
#: value callers get when they pass nothing.
STRICT = SeparationOfDuties(REQUIRED, source="default")
