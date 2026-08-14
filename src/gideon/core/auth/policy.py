"""gideon.core.auth.policy — Deterministic in-memory authorization policy.

Design notes
------------
``AuthorizationPolicy`` is a pure in-memory, synchronous, deterministic
policy engine with no I/O, networking, threads, or background tasks.

Security invariants
~~~~~~~~~~~~~~~~~~~
1. **Default DENY** — every access decision defaults to denied unless an
   explicit allow is present.
2. **Explicit ALLOW required** — no permission is granted without a
   corresponding ``allow()`` call.
3. **DENY overrides ALLOW** — if a device has both an allow and a deny for
   the same permission, the deny wins unconditionally.
4. **No implicit trust** — a device's mere existence or identity does not
   grant any permissions.
5. **No wildcard permissions** — every permission must be explicitly named
   and explicitly allowed; wildcards (``*``, ``filesystem.*``) are not
   interpreted.

Isolation
~~~~~~~~~
- The policy never mutates the ``DevicePrincipal``, ``AuthorizationRequest``,
  ``Permission``, or context metadata passed to it.
- Internal collections (``_allows``, ``_denies``) are never returned by
  reference; no public getter exposes them.
- All public mutating methods (``allow``, ``deny``, ``revoke``, ``clear``)
  increment the internal ``_version`` counter so that decisions are
  traceable to the policy state at check time.
"""

from __future__ import annotations

from gideon.core.auth.models import (
    AuthorizationDecision,
    AuthorizationRequest,
    Permission,
)

# ---------------------------------------------------------------------------
# Reason strings (constants so tests can import and assert against them)
# ---------------------------------------------------------------------------

REASON_EXPLICITLY_DENIED: str = "Explicitly denied"
REASON_EXPLICITLY_ALLOWED: str = "Explicitly allowed"
REASON_NO_EXPLICIT_ALLOW: str = "No explicit allow found"


class AuthorizationPolicy:
    """Deterministic in-memory authorization policy.

    All operations are synchronous, pure, and side-effect-free with
    respect to any external system.  No I/O, networking, threads, or
    background tasks are involved.

    Usage example::

        policy = AuthorizationPolicy()
        policy.allow("device-abc", "filesystem.read")

        request = AuthorizationRequest(
            principal=DevicePrincipal(device_id="device-abc"),
            permission=Permission("filesystem.read"),
        )
        decision = policy.check(request)
        assert decision.allowed is True

    Security guarantee: default is DENY.  A freshly created policy
    denies every request until an explicit ``allow()`` is recorded.
    """

    def __init__(self) -> None:
        # device_id -> set of permission name strings that are explicitly allowed.
        self._allows: dict[str, set[str]] = {}
        # device_id -> set of permission name strings that are explicitly denied.
        self._denies: dict[str, set[str]] = {}
        # Monotonically increasing version; increments on every mutation.
        self._version: int = 0

    # ------------------------------------------------------------------
    # Mutation API
    # ------------------------------------------------------------------

    def allow(self, device_id: str, permission: str | Permission) -> None:
        """Record an explicit allow for *device_id* / *permission*.

        If the same pair is already allowed, this is a no-op (but the
        version is still incremented to maintain monotonic traceability).

        Parameters
        ----------
        device_id:
            Identifier of the device to grant the permission to.
        permission:
            A :class:`Permission` instance or a permission name string.

        Raises
        ------
        TypeError
            If *device_id* is not a ``str`` or *permission* is not a
            ``str`` or :class:`Permission`.
        ValueError
            If *device_id* or the resolved permission name is empty.
        """
        device_id = _validate_device_id(device_id)
        perm_name = _resolve_permission(permission)
        self._allows.setdefault(device_id, set()).add(perm_name)
        self._version += 1

    def deny(self, device_id: str, permission: str | Permission) -> None:
        """Record an explicit deny for *device_id* / *permission*.

        An explicit deny overrides any existing allow for the same pair.
        The explicit allow (if any) is **not** removed — both entries may
        coexist, and the deny always wins during ``check()``.

        Parameters
        ----------
        device_id:
            Identifier of the device to deny.
        permission:
            A :class:`Permission` instance or a permission name string.

        Raises
        ------
        TypeError
            If *device_id* is not a ``str`` or *permission* is not a
            ``str`` or :class:`Permission`.
        ValueError
            If *device_id* or the resolved permission name is empty.
        """
        device_id = _validate_device_id(device_id)
        perm_name = _resolve_permission(permission)
        self._denies.setdefault(device_id, set()).add(perm_name)
        self._version += 1

    def revoke(self, device_id: str, permission: str | Permission) -> None:
        """Remove an explicit allow for *device_id* / *permission*.

        Revoking restores the default-DENY behaviour for this pair; it does
        **not** add an explicit deny.  Use :meth:`deny` for that.

        If the pair was not explicitly allowed, this is a no-op (but the
        version is still incremented).

        Parameters
        ----------
        device_id:
            Identifier of the device.
        permission:
            A :class:`Permission` instance or a permission name string.

        Raises
        ------
        TypeError
            If *device_id* is not a ``str`` or *permission* is not a
            ``str`` or :class:`Permission`.
        ValueError
            If *device_id* or the resolved permission name is empty.
        """
        device_id = _validate_device_id(device_id)
        perm_name = _resolve_permission(permission)
        device_allows = self._allows.get(device_id)
        if device_allows is not None:
            device_allows.discard(perm_name)
            # Clean up the empty set to keep internal state tidy.
            if not device_allows:
                del self._allows[device_id]
        self._version += 1

    def clear(self) -> None:
        """Remove all allows and denies from the policy.

        After ``clear()``, every access check returns a default DENY.
        The version counter is incremented.
        """
        self._allows.clear()
        self._denies.clear()
        self._version += 1

    # ------------------------------------------------------------------
    # Check API
    # ------------------------------------------------------------------

    def check(self, request: AuthorizationRequest) -> AuthorizationDecision:
        """Evaluate *request* against the current policy and return a decision.

        Decision logic (in priority order):

        1. Explicit DENY wins over everything.
        2. Explicit ALLOW — if present and no deny exists.
        3. Default DENY — all other cases (unknown device, unknown
           permission, or no explicit allow).

        The policy never mutates *request*, *request.principal*,
        *request.permission*, or *request.context*.

        Parameters
        ----------
        request:
            The :class:`AuthorizationRequest` to evaluate.

        Returns
        -------
        AuthorizationDecision
            An immutable decision object.  The ``policy_version`` field
            reflects the version of the policy at the moment the check
            was performed.

        Raises
        ------
        TypeError
            If *request* is not an :class:`AuthorizationRequest`.
        """
        if not isinstance(request, AuthorizationRequest):
            raise TypeError(
                f"request must be an AuthorizationRequest; "
                f"got {type(request).__name__!r}"
            )

        device_id: str = request.principal.device_id
        perm_name: str = request.permission.name
        version: int = self._version

        # --- Priority 1: Explicit DENY wins unconditionally ---
        device_denies = self._denies.get(device_id)
        if device_denies and perm_name in device_denies:
            return AuthorizationDecision(
                allowed=False,
                reason=REASON_EXPLICITLY_DENIED,
                device_id=device_id,
                permission=perm_name,
                policy_version=version,
            )

        # --- Priority 2: Explicit ALLOW (only if no deny above) ---
        device_allows = self._allows.get(device_id)
        if device_allows and perm_name in device_allows:
            return AuthorizationDecision(
                allowed=True,
                reason=REASON_EXPLICITLY_ALLOWED,
                device_id=device_id,
                permission=perm_name,
                policy_version=version,
            )

        # --- Priority 3: Default DENY ---
        return AuthorizationDecision(
            allowed=False,
            reason=REASON_NO_EXPLICIT_ALLOW,
            device_id=device_id,
            permission=perm_name,
            policy_version=version,
        )

    # ------------------------------------------------------------------
    # Introspection (read-only, defensive copies)
    # ------------------------------------------------------------------

    @property
    def version(self) -> int:
        """Current policy version.  Increments on every mutation."""
        return self._version


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _validate_device_id(device_id: str) -> str:
    """Validate and return *device_id*; raise on bad input."""
    if not isinstance(device_id, str):
        raise TypeError(
            f"device_id must be a str; got {type(device_id).__name__!r}"
        )
    if not device_id or not device_id.strip():
        raise ValueError("device_id must not be empty or whitespace-only")
    return device_id


def _resolve_permission(permission: str | Permission) -> str:
    """Extract the permission name string from a ``str`` or ``Permission``."""
    if isinstance(permission, Permission):
        return permission.name
    if isinstance(permission, str):
        if not permission or not permission.strip():
            raise ValueError("permission name must not be empty or whitespace-only")
        return permission
    raise TypeError(
        f"permission must be a str or Permission; "
        f"got {type(permission).__name__!r}"
    )
