"""gideon.core.auth — Public API for GIDEON v0.5 Trust & Authorization.

This package provides the deterministic local authorization policy engine.
All future GIDEON tools and subsystems that perform privileged actions must
consult this policy before proceeding.

Classes
-------
DevicePrincipal
    Immutable value object identifying the entity requesting an action.
    Contains a ``device_id`` and an optional ``PublicIdentity`` reference.
    Never contains private key material.

Permission
    Immutable, hashable value object naming a specific action/capability
    (e.g. ``Permission("filesystem.read")``).  Every permission must be
    explicitly named; wildcards are not supported.

AuthorizationRequest
    Immutable value object pairing a ``DevicePrincipal`` with a
    ``Permission`` and optional read-only context metadata.

AuthorizationDecision
    Immutable result of a policy check.  Contains only plain scalar
    values — safe to log, serialize, and transmit.  Never contains
    private key material.

AuthorizationPolicy
    Deterministic in-memory policy engine.  Default is DENY.
    Supports explicit allow, explicit deny (which overrides allow),
    revoke, and clear.  No I/O, networking, threads, or background tasks.

Reason constants
----------------
REASON_EXPLICITLY_DENIED
    Decision reason when an explicit deny is recorded.
REASON_EXPLICITLY_ALLOWED
    Decision reason when an explicit allow is recorded (and no deny).
REASON_NO_EXPLICIT_ALLOW
    Decision reason for all other cases (default DENY).
"""

from gideon.core.auth.models import (
    AuthorizationDecision,
    AuthorizationRequest,
    DevicePrincipal,
    Permission,
)
from gideon.core.auth.policy import (
    REASON_EXPLICITLY_ALLOWED,
    REASON_EXPLICITLY_DENIED,
    REASON_NO_EXPLICIT_ALLOW,
    AuthorizationPolicy,
)

__all__ = [
    # Value objects
    "DevicePrincipal",
    "Permission",
    "AuthorizationRequest",
    "AuthorizationDecision",
    # Policy engine
    "AuthorizationPolicy",
    # Reason constants
    "REASON_EXPLICITLY_ALLOWED",
    "REASON_EXPLICITLY_DENIED",
    "REASON_NO_EXPLICIT_ALLOW",
]
