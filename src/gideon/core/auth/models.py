"""gideon.core.auth.models — Immutable value objects for authorization.

Design notes
------------
All types in this module are frozen dataclasses (immutable value objects).
They carry only the data needed for authorization decisions; none of them
store private key material, tokens, credentials, or secrets.

``DevicePrincipal``
    Identifies *who* is requesting an action.  Holds a ``device_id`` and
    an optional ``PublicIdentity`` reference for additional context.
    Private cryptographic keys are deliberately excluded.

``Permission``
    Names *what* action is being requested.  A structured string such as
    ``"filesystem.read"`` or ``"browser.control"``.  Permissions are
    immutable, hashable, and comparable.

``AuthorizationRequest``
    Pairs a principal with a permission and optional read-only context
    metadata.  The context is snapshotted into a ``MappingProxyType`` at
    construction time so that later mutations to the caller's dict cannot
    affect the request, and so that the authorization layer cannot
    accidentally mutate it.

``AuthorizationDecision``
    The result of a policy check.  Contains only plain scalar values safe
    for logging, serialization, and transmission.  Never contains private
    key material, tokens, or object references to mutable state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping

from gideon.core.identity.identity import PublicIdentity


# ---------------------------------------------------------------------------
# Permission — immutable, hashable permission name
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Permission:
    """An immutable, hashable representation of a named permission.

    Permissions are structured dot-separated strings that name a specific
    action or capability, for example::

        Permission("filesystem.read")
        Permission("browser.control")
        Permission("system.command")

    The policy engine accepts permission strings so that future subsystems
    can define their own permissions without modifying this module.

    Attributes
    ----------
    name:
        The permission identifier string.  Must be a non-empty string.
        No wildcard characters are interpreted; every permission must be
        explicitly named.

    Raises
    ------
    TypeError
        If *name* is not a ``str``.
    ValueError
        If *name* is empty, whitespace-only, or contains ``'*'``.
        Wildcard permissions (``"*"``, ``"filesystem.*"``, ``"*.control"``,
        etc.) are explicitly rejected; every permission must be named
        exactly.
    """

    name: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str):
            raise TypeError(
                f"Permission.name must be a str; got {type(self.name).__name__!r}"
            )
        if not self.name or not self.name.strip():
            raise ValueError("Permission.name must not be empty or whitespace-only")
        if "*" in self.name:
            raise ValueError(
                f"Permission.name must not contain '*'; "
                f"wildcard permissions are not supported: {self.name!r}"
            )

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return f"Permission({self.name!r})"


# ---------------------------------------------------------------------------
# DevicePrincipal — immutable principal identifying a device
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DevicePrincipal:
    """An immutable principal representing a device requesting an action.

    The principal carries a ``device_id`` that uniquely identifies the
    requesting device, and an optional ``public_identity`` reference that
    provides additional cryptographic context without exposing any private
    key material.

    .. important::
        Possession of a ``DevicePrincipal`` does NOT imply any permissions.
        All authorization decisions must be made by the policy engine.

    Attributes
    ----------
    device_id:
        Unique identifier for the requesting device.  Must be non-empty.
    public_identity:
        Optional :class:`~gideon.core.identity.identity.PublicIdentity`
        providing public cryptographic context.  Contains no private keys.

    Raises
    ------
    TypeError
        If *device_id* is not a ``str``, or if *public_identity* is
        provided but is not a ``PublicIdentity`` instance.
    ValueError
        If *device_id* is empty or whitespace-only, or if *public_identity*
        is provided and ``public_identity.device_id != device_id``.
    """

    device_id: str
    public_identity: PublicIdentity | None = field(default=None)

    def __post_init__(self) -> None:
        if not isinstance(self.device_id, str):
            raise TypeError(
                f"DevicePrincipal.device_id must be a str; "
                f"got {type(self.device_id).__name__!r}"
            )
        if not self.device_id or not self.device_id.strip():
            raise ValueError("DevicePrincipal.device_id must not be empty or whitespace-only")
        if self.public_identity is not None and not isinstance(
            self.public_identity, PublicIdentity
        ):
            raise TypeError(
                f"DevicePrincipal.public_identity must be a PublicIdentity or None; "
                f"got {type(self.public_identity).__name__!r}"
            )
        if (
            self.public_identity is not None
            and self.public_identity.device_id != self.device_id
        ):
            raise ValueError(
                f"DevicePrincipal.device_id {self.device_id!r} does not match "
                f"public_identity.device_id {self.public_identity.device_id!r}"
            )

    def __repr__(self) -> str:
        # Intentionally omits public_key_hex from public_identity to keep repr
        # concise; device_id plus algorithm/version is enough for identification.
        if self.public_identity is not None:
            identity_repr = (
                f"PublicIdentity(device_id={self.public_identity.device_id!r}, "
                f"algorithm={self.public_identity.algorithm!r}, "
                f"version={self.public_identity.version!r})"
            )
        else:
            identity_repr = "None"
        return (
            f"DevicePrincipal("
            f"device_id={self.device_id!r}, "
            f"public_identity={identity_repr})"
        )


# ---------------------------------------------------------------------------
# AuthorizationRequest — immutable request value object
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthorizationRequest:
    """An immutable value object pairing a principal with a permission.

    The optional *context* metadata is snapshotted into an immutable
    :class:`~types.MappingProxyType` at construction time.  This means:

    - Mutations to the caller's original dict after construction do not
      affect the request.
    - The authorization layer cannot accidentally mutate the context.

    Attributes
    ----------
    principal:
        The :class:`DevicePrincipal` making the request.
    permission:
        The :class:`Permission` being requested.
    context:
        Read-only key/value metadata for logging or future policy hints.
        Always a :class:`~types.MappingProxyType`; never ``None``.

    Raises
    ------
    TypeError
        If *principal* is not a ``DevicePrincipal``, *permission* is not
        a ``Permission``, or *context* is not a ``Mapping``.
    """

    principal: DevicePrincipal
    permission: Permission
    context: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.principal, DevicePrincipal):
            raise TypeError(
                f"AuthorizationRequest.principal must be a DevicePrincipal; "
                f"got {type(self.principal).__name__!r}"
            )
        if not isinstance(self.permission, Permission):
            raise TypeError(
                f"AuthorizationRequest.permission must be a Permission; "
                f"got {type(self.permission).__name__!r}"
            )
        if not isinstance(self.context, Mapping):
            raise TypeError(
                f"AuthorizationRequest.context must be a Mapping; "
                f"got {type(self.context).__name__!r}"
            )
        # Snapshot the context into an immutable proxy.  We copy even if the
        # caller already supplied a MappingProxyType so that this request owns
        # an independent snapshot.
        object.__setattr__(
            self, "context", MappingProxyType(dict(self.context))
        )


# ---------------------------------------------------------------------------
# AuthorizationDecision — immutable, loggable decision result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthorizationDecision:
    """An immutable result from a policy check.

    Contains only plain scalar values; never holds references to mutable
    objects, private keys, tokens, credentials, or secrets.  Safe to log,
    serialize, and transmit.

    Attributes
    ----------
    allowed:
        ``True`` if the action is permitted; ``False`` otherwise.
    reason:
        Human-readable explanation of the decision (e.g.
        ``"Explicitly allowed"`` or ``"No explicit allow found"``).
    device_id:
        Identifier of the requesting device, copied from the principal.
    permission:
        The permission name string that was checked.
    policy_version:
        The version counter of the policy at decision time.  Monotonically
        increasing with every policy mutation.

    Raises
    ------
    TypeError
        If any field is not the expected scalar type.
    ValueError
        If *reason* is empty, *device_id* is empty, *permission* is empty,
        or *policy_version* is negative.
    """

    allowed: bool
    reason: str
    device_id: str
    permission: str
    policy_version: int

    def __post_init__(self) -> None:
        if not isinstance(self.allowed, bool):
            raise TypeError(
                f"AuthorizationDecision.allowed must be bool; "
                f"got {type(self.allowed).__name__!r}"
            )
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise ValueError("AuthorizationDecision.reason must be a non-empty string")
        if not isinstance(self.device_id, str) or not self.device_id.strip():
            raise ValueError("AuthorizationDecision.device_id must be a non-empty string")
        if not isinstance(self.permission, str) or not self.permission.strip():
            raise ValueError("AuthorizationDecision.permission must be a non-empty string")
        if not isinstance(self.policy_version, int) or self.policy_version < 0:
            raise ValueError(
                "AuthorizationDecision.policy_version must be a non-negative integer"
            )

    def __repr__(self) -> str:
        # Explicitly list every field — future additions must be reviewed.
        # This repr intentionally contains no private key material.
        return (
            f"AuthorizationDecision("
            f"allowed={self.allowed!r}, "
            f"reason={self.reason!r}, "
            f"device_id={self.device_id!r}, "
            f"permission={self.permission!r}, "
            f"policy_version={self.policy_version!r})"
        )
