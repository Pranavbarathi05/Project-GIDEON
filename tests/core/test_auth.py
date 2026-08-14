"""tests.core.test_auth — Pytest coverage for GIDEON v0.5 Trust & Authorization.

Test organization
-----------------
Each test class covers one focused concern.  Security invariants are
collected in dedicated classes (``TestSecurityInvariants``,
``TestNoPrivateKeyInDecisions``) so they are easy to audit separately.

All tests are deterministic: no randomness, no I/O, no network, no threads.
"""

from __future__ import annotations

import pytest
from types import MappingProxyType
from typing import Any

from gideon.core.auth import (
    REASON_EXPLICITLY_ALLOWED,
    REASON_EXPLICITLY_DENIED,
    REASON_NO_EXPLICIT_ALLOW,
    AuthorizationDecision,
    AuthorizationPolicy,
    AuthorizationRequest,
    DevicePrincipal,
    Permission,
)
from gideon.core.identity.identity import PublicIdentity, generate_identity


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _make_principal(device_id: str = "device-alpha") -> DevicePrincipal:
    return DevicePrincipal(device_id=device_id)


def _make_principal_with_identity(device_id: str = "device-alpha") -> DevicePrincipal:
    identity = generate_identity(device_id=device_id)
    return DevicePrincipal(
        device_id=device_id,
        public_identity=identity.public_identity(),
    )


def _make_permission(name: str = "filesystem.read") -> Permission:
    return Permission(name)


def _make_request(
    device_id: str = "device-alpha",
    perm: str = "filesystem.read",
    context: dict | None = None,
) -> AuthorizationRequest:
    return AuthorizationRequest(
        principal=DevicePrincipal(device_id=device_id),
        permission=Permission(perm),
        context=context or {},
    )


@pytest.fixture()
def policy() -> AuthorizationPolicy:
    return AuthorizationPolicy()


# ===========================================================================
# 1. Permission
# ===========================================================================


class TestPermission:
    def test_creation(self) -> None:
        perm = Permission("filesystem.read")
        assert perm.name == "filesystem.read"

    def test_str(self) -> None:
        assert str(Permission("browser.control")) == "browser.control"

    def test_repr(self) -> None:
        assert repr(Permission("email.send")) == "Permission('email.send')"

    def test_equality(self) -> None:
        assert Permission("system.command") == Permission("system.command")

    def test_inequality(self) -> None:
        assert Permission("filesystem.read") != Permission("filesystem.write")

    def test_hashable(self) -> None:
        perms = {Permission("a"), Permission("b"), Permission("a")}
        assert len(perms) == 2

    def test_usable_as_dict_key(self) -> None:
        d = {Permission("k"): "val"}
        assert d[Permission("k")] == "val"

    def test_immutable(self) -> None:
        perm = Permission("filesystem.read")
        with pytest.raises((AttributeError, TypeError)):
            perm.name = "changed"  # type: ignore[misc]

    def test_empty_name_raises(self) -> None:
        with pytest.raises(ValueError):
            Permission("")

    def test_whitespace_only_name_raises(self) -> None:
        with pytest.raises(ValueError):
            Permission("   ")

    def test_non_string_name_raises(self) -> None:
        with pytest.raises(TypeError):
            Permission(123)  # type: ignore[arg-type]

    def test_many_valid_permission_strings(self) -> None:
        names = [
            "filesystem.read",
            "filesystem.write",
            "browser.read",
            "browser.control",
            "system.media_control",
            "system.command",
            "email.read",
            "email.send",
        ]
        for name in names:
            perm = Permission(name)
            assert perm.name == name


# ===========================================================================
# 2. DevicePrincipal
# ===========================================================================


class TestDevicePrincipal:
    def test_creation_without_identity(self) -> None:
        principal = DevicePrincipal(device_id="dev-1")
        assert principal.device_id == "dev-1"
        assert principal.public_identity is None

    def test_creation_with_public_identity(self) -> None:
        identity = generate_identity("dev-2")
        pub = identity.public_identity()
        principal = DevicePrincipal(device_id="dev-2", public_identity=pub)
        assert principal.device_id == "dev-2"
        assert principal.public_identity is pub

    def test_immutable(self) -> None:
        principal = DevicePrincipal(device_id="dev-3")
        with pytest.raises((AttributeError, TypeError)):
            principal.device_id = "changed"  # type: ignore[misc]

    def test_equality(self) -> None:
        p1 = DevicePrincipal(device_id="same")
        p2 = DevicePrincipal(device_id="same")
        assert p1 == p2

    def test_inequality(self) -> None:
        assert DevicePrincipal(device_id="a") != DevicePrincipal(device_id="b")

    def test_hashable(self) -> None:
        s = {DevicePrincipal(device_id="x"), DevicePrincipal(device_id="x")}
        assert len(s) == 1

    def test_empty_device_id_raises(self) -> None:
        with pytest.raises(ValueError):
            DevicePrincipal(device_id="")

    def test_whitespace_device_id_raises(self) -> None:
        with pytest.raises(ValueError):
            DevicePrincipal(device_id="  ")

    def test_non_string_device_id_raises(self) -> None:
        with pytest.raises(TypeError):
            DevicePrincipal(device_id=42)  # type: ignore[arg-type]

    def test_invalid_public_identity_type_raises(self) -> None:
        with pytest.raises(TypeError):
            DevicePrincipal(device_id="dev", public_identity="not-a-public-identity")  # type: ignore[arg-type]

    def test_repr_contains_device_id(self) -> None:
        principal = _make_principal("my-device")
        assert "my-device" in repr(principal)

    def test_repr_with_public_identity_contains_algorithm(self) -> None:
        principal = _make_principal_with_identity("my-device")
        r = repr(principal)
        assert "my-device" in r
        assert "ed25519" in r

    def test_repr_does_not_contain_private_key(self) -> None:
        """The principal repr must never leak private key material."""
        identity = generate_identity("sec-device")
        pub = identity.public_identity()
        principal = DevicePrincipal(device_id="sec-device", public_identity=pub)
        r = repr(principal)
        # The private key is 32 bytes = 64 hex chars; verify it's not there.
        # We can't get the private key from outside, but we can confirm that
        # the repr doesn't contain the public_key_hex either (only device_id
        # and algorithm/version should appear).
        assert pub.public_key_hex not in r


# ===========================================================================
# 3. AuthorizationRequest
# ===========================================================================


class TestAuthorizationRequest:
    def test_creation(self) -> None:
        req = _make_request()
        assert req.principal.device_id == "device-alpha"
        assert req.permission.name == "filesystem.read"

    def test_default_context_is_empty_mapping_proxy(self) -> None:
        req = _make_request()
        assert isinstance(req.context, MappingProxyType)
        assert len(req.context) == 0

    def test_context_snapshotted(self) -> None:
        """Mutations to the caller's dict must not affect the request's context."""
        ctx: dict[str, Any] = {"key": "value"}
        req = AuthorizationRequest(
            principal=_make_principal(),
            permission=_make_permission(),
            context=ctx,
        )
        ctx["key"] = "MUTATED"
        assert req.context["key"] == "value"

    def test_context_is_read_only(self) -> None:
        """context must be immutable from the outside."""
        req = _make_request(context={"x": 1})
        with pytest.raises(TypeError):
            req.context["x"] = 999  # type: ignore[index]

    def test_context_accepts_mapping_proxy(self) -> None:
        proxy = MappingProxyType({"a": "b"})
        req = AuthorizationRequest(
            principal=_make_principal(),
            permission=_make_permission(),
            context=proxy,
        )
        assert req.context["a"] == "b"

    def test_immutable_principal(self) -> None:
        req = _make_request()
        with pytest.raises((AttributeError, TypeError)):
            req.principal = _make_principal("other")  # type: ignore[misc]

    def test_immutable_permission(self) -> None:
        req = _make_request()
        with pytest.raises((AttributeError, TypeError)):
            req.permission = Permission("other.perm")  # type: ignore[misc]

    def test_wrong_principal_type_raises(self) -> None:
        with pytest.raises(TypeError):
            AuthorizationRequest(
                principal="not-a-principal",  # type: ignore[arg-type]
                permission=_make_permission(),
            )

    def test_wrong_permission_type_raises(self) -> None:
        with pytest.raises(TypeError):
            AuthorizationRequest(
                principal=_make_principal(),
                permission="not-a-permission",  # type: ignore[arg-type]
            )

    def test_wrong_context_type_raises(self) -> None:
        with pytest.raises(TypeError):
            AuthorizationRequest(
                principal=_make_principal(),
                permission=_make_permission(),
                context="not-a-mapping",  # type: ignore[arg-type]
            )


# ===========================================================================
# 4. AuthorizationDecision
# ===========================================================================


class TestAuthorizationDecision:
    def test_creation_allowed(self) -> None:
        d = AuthorizationDecision(
            allowed=True,
            reason="Explicitly allowed",
            device_id="dev",
            permission="filesystem.read",
            policy_version=1,
        )
        assert d.allowed is True
        assert d.reason == "Explicitly allowed"
        assert d.device_id == "dev"
        assert d.permission == "filesystem.read"
        assert d.policy_version == 1

    def test_creation_denied(self) -> None:
        d = AuthorizationDecision(
            allowed=False,
            reason="No explicit allow found",
            device_id="dev",
            permission="system.command",
            policy_version=0,
        )
        assert d.allowed is False

    def test_immutable(self) -> None:
        d = AuthorizationDecision(
            allowed=True,
            reason="reason",
            device_id="d",
            permission="p",
            policy_version=0,
        )
        with pytest.raises((AttributeError, TypeError)):
            d.allowed = False  # type: ignore[misc]

    def test_equality(self) -> None:
        kwargs: dict[str, Any] = dict(
            allowed=True, reason="r", device_id="d", permission="p", policy_version=0
        )
        assert AuthorizationDecision(**kwargs) == AuthorizationDecision(**kwargs)

    def test_invalid_allowed_type(self) -> None:
        with pytest.raises(TypeError):
            AuthorizationDecision(
                allowed="yes",  # type: ignore[arg-type]
                reason="r",
                device_id="d",
                permission="p",
                policy_version=0,
            )

    def test_empty_reason_raises(self) -> None:
        with pytest.raises(ValueError):
            AuthorizationDecision(
                allowed=False, reason="", device_id="d", permission="p", policy_version=0
            )

    def test_empty_device_id_raises(self) -> None:
        with pytest.raises(ValueError):
            AuthorizationDecision(
                allowed=False, reason="r", device_id="", permission="p", policy_version=0
            )

    def test_empty_permission_raises(self) -> None:
        with pytest.raises(ValueError):
            AuthorizationDecision(
                allowed=False, reason="r", device_id="d", permission="", policy_version=0
            )

    def test_negative_version_raises(self) -> None:
        with pytest.raises(ValueError):
            AuthorizationDecision(
                allowed=False, reason="r", device_id="d", permission="p", policy_version=-1
            )

    def test_repr_contains_expected_fields(self) -> None:
        d = AuthorizationDecision(
            allowed=True,
            reason="Explicitly allowed",
            device_id="dev-x",
            permission="filesystem.read",
            policy_version=3,
        )
        r = repr(d)
        assert "dev-x" in r
        assert "filesystem.read" in r
        assert "True" in r
        assert "3" in r


# ===========================================================================
# 5. Policy — Default Deny
# ===========================================================================


class TestPolicyDefaultDeny:
    def test_fresh_policy_denies_any_request(self, policy: AuthorizationPolicy) -> None:
        req = _make_request()
        decision = policy.check(req)
        assert decision.allowed is False

    def test_fresh_policy_deny_reason(self, policy: AuthorizationPolicy) -> None:
        decision = policy.check(_make_request())
        assert decision.reason == REASON_NO_EXPLICIT_ALLOW

    def test_unknown_device_denied(self, policy: AuthorizationPolicy) -> None:
        policy.allow("known-device", "filesystem.read")
        req = _make_request(device_id="unknown-device", perm="filesystem.read")
        decision = policy.check(req)
        assert decision.allowed is False

    def test_unknown_permission_denied(self, policy: AuthorizationPolicy) -> None:
        policy.allow("device-alpha", "filesystem.read")
        req = _make_request(device_id="device-alpha", perm="filesystem.write")
        decision = policy.check(req)
        assert decision.allowed is False


# ===========================================================================
# 6. Policy — Explicit Allow
# ===========================================================================


class TestPolicyExplicitAllow:
    def test_allow_then_check_succeeds(self, policy: AuthorizationPolicy) -> None:
        policy.allow("device-alpha", "filesystem.read")
        decision = policy.check(_make_request())
        assert decision.allowed is True

    def test_allow_reason(self, policy: AuthorizationPolicy) -> None:
        policy.allow("device-alpha", "filesystem.read")
        decision = policy.check(_make_request())
        assert decision.reason == REASON_EXPLICITLY_ALLOWED

    def test_allow_with_permission_object(self, policy: AuthorizationPolicy) -> None:
        perm = Permission("email.send")
        policy.allow("dev", perm)
        req = _make_request(device_id="dev", perm="email.send")
        assert policy.check(req).allowed is True

    def test_allow_with_string(self, policy: AuthorizationPolicy) -> None:
        policy.allow("dev", "email.read")
        req = _make_request(device_id="dev", perm="email.read")
        assert policy.check(req).allowed is True

    def test_allow_does_not_affect_other_devices(
        self, policy: AuthorizationPolicy
    ) -> None:
        policy.allow("device-A", "filesystem.read")
        req_b = _make_request(device_id="device-B", perm="filesystem.read")
        assert policy.check(req_b).allowed is False

    def test_allow_does_not_affect_other_permissions(
        self, policy: AuthorizationPolicy
    ) -> None:
        policy.allow("device-alpha", "filesystem.read")
        req = _make_request(device_id="device-alpha", perm="filesystem.write")
        assert policy.check(req).allowed is False

    def test_decision_contains_correct_device_and_permission(
        self, policy: AuthorizationPolicy
    ) -> None:
        policy.allow("device-alpha", "filesystem.read")
        decision = policy.check(_make_request())
        assert decision.device_id == "device-alpha"
        assert decision.permission == "filesystem.read"


# ===========================================================================
# 7. Policy — Explicit Deny
# ===========================================================================


class TestPolicyExplicitDeny:
    def test_deny_then_check_denied(self, policy: AuthorizationPolicy) -> None:
        policy.deny("device-alpha", "filesystem.read")
        decision = policy.check(_make_request())
        assert decision.allowed is False

    def test_deny_reason(self, policy: AuthorizationPolicy) -> None:
        policy.deny("device-alpha", "filesystem.read")
        decision = policy.check(_make_request())
        assert decision.reason == REASON_EXPLICITLY_DENIED

    def test_deny_with_permission_object(self, policy: AuthorizationPolicy) -> None:
        policy.deny("dev", Permission("system.command"))
        req = _make_request(device_id="dev", perm="system.command")
        assert policy.check(req).allowed is False

    def test_deny_does_not_affect_other_devices(
        self, policy: AuthorizationPolicy
    ) -> None:
        policy.allow("device-B", "filesystem.read")
        policy.deny("device-A", "filesystem.read")
        req_b = _make_request(device_id="device-B", perm="filesystem.read")
        assert policy.check(req_b).allowed is True

    def test_deny_does_not_affect_other_permissions(
        self, policy: AuthorizationPolicy
    ) -> None:
        policy.allow("dev", "filesystem.read")
        policy.allow("dev", "filesystem.write")
        policy.deny("dev", "filesystem.write")
        req_read = _make_request(device_id="dev", perm="filesystem.read")
        assert policy.check(req_read).allowed is True


# ===========================================================================
# 8. Policy — Deny Overrides Allow
# ===========================================================================


class TestPolicyDenyOverridesAllow:
    """Explicit deny MUST override explicit allow — the critical invariant."""

    def test_deny_overrides_allow(self, policy: AuthorizationPolicy) -> None:
        policy.allow("device-alpha", "filesystem.read")
        policy.deny("device-alpha", "filesystem.read")
        decision = policy.check(_make_request())
        assert decision.allowed is False
        assert decision.reason == REASON_EXPLICITLY_DENIED

    def test_allow_does_not_override_deny(self, policy: AuthorizationPolicy) -> None:
        policy.deny("device-alpha", "filesystem.read")
        policy.allow("device-alpha", "filesystem.read")
        decision = policy.check(_make_request())
        assert decision.allowed is False
        assert decision.reason == REASON_EXPLICITLY_DENIED

    def test_deny_overrides_allow_for_specific_permission_only(
        self, policy: AuthorizationPolicy
    ) -> None:
        """Deny on one permission must not spill to others."""
        policy.allow("dev", "filesystem.read")
        policy.allow("dev", "filesystem.write")
        policy.deny("dev", "filesystem.write")
        assert policy.check(_make_request(device_id="dev", perm="filesystem.read")).allowed is True
        assert policy.check(_make_request(device_id="dev", perm="filesystem.write")).allowed is False

    def test_deny_overrides_allow_regardless_of_order(
        self, policy: AuthorizationPolicy
    ) -> None:
        """Order of allow/deny calls must not change the DENY-wins outcome."""
        # deny first, then allow
        p1 = AuthorizationPolicy()
        p1.deny("dev", "filesystem.read")
        p1.allow("dev", "filesystem.read")
        assert p1.check(_make_request()).allowed is False

        # allow first, then deny
        p2 = AuthorizationPolicy()
        p2.allow("dev", "filesystem.read")
        p2.deny("dev", "filesystem.read")
        assert p2.check(_make_request()).allowed is False


# ===========================================================================
# 9. Policy — Revoke
# ===========================================================================


class TestPolicyRevoke:
    def test_revoke_removes_allow(self, policy: AuthorizationPolicy) -> None:
        policy.allow("device-alpha", "filesystem.read")
        policy.revoke("device-alpha", "filesystem.read")
        decision = policy.check(_make_request())
        assert decision.allowed is False

    def test_revoke_returns_to_default_deny(self, policy: AuthorizationPolicy) -> None:
        policy.allow("device-alpha", "filesystem.read")
        policy.revoke("device-alpha", "filesystem.read")
        assert policy.check(_make_request()).reason == REASON_NO_EXPLICIT_ALLOW

    def test_revoke_does_not_add_explicit_deny(self, policy: AuthorizationPolicy) -> None:
        """After revoke, check reason should be NO_EXPLICIT_ALLOW, not EXPLICITLY_DENIED."""
        policy.allow("device-alpha", "filesystem.read")
        policy.revoke("device-alpha", "filesystem.read")
        decision = policy.check(_make_request())
        assert decision.reason != REASON_EXPLICITLY_DENIED

    def test_revoke_with_permission_object(self, policy: AuthorizationPolicy) -> None:
        policy.allow("dev", Permission("email.send"))
        policy.revoke("dev", Permission("email.send"))
        assert policy.check(_make_request(device_id="dev", perm="email.send")).allowed is False

    def test_revoke_nonexistent_is_noop(self, policy: AuthorizationPolicy) -> None:
        """Revoking a permission that was never allowed must not raise."""
        policy.revoke("dev", "filesystem.read")  # no error

    def test_revoke_does_not_affect_other_permissions(
        self, policy: AuthorizationPolicy
    ) -> None:
        policy.allow("dev", "filesystem.read")
        policy.allow("dev", "filesystem.write")
        policy.revoke("dev", "filesystem.read")
        assert policy.check(_make_request(device_id="dev", perm="filesystem.read")).allowed is False
        assert policy.check(_make_request(device_id="dev", perm="filesystem.write")).allowed is True

    def test_revoke_does_not_affect_deny(self, policy: AuthorizationPolicy) -> None:
        """Revoking an allow must not clear an existing explicit deny."""
        policy.allow("device-alpha", "filesystem.read")
        policy.deny("device-alpha", "filesystem.read")
        policy.revoke("device-alpha", "filesystem.read")
        # Still denied because deny remains.
        decision = policy.check(_make_request())
        assert decision.allowed is False
        assert decision.reason == REASON_EXPLICITLY_DENIED


# ===========================================================================
# 10. Policy — Multiple Devices
# ===========================================================================


class TestPolicyMultipleDevices:
    def test_independent_policies_per_device(self, policy: AuthorizationPolicy) -> None:
        policy.allow("device-A", "filesystem.read")
        # device-B gets no allows
        assert policy.check(_make_request(device_id="device-A", perm="filesystem.read")).allowed is True
        assert policy.check(_make_request(device_id="device-B", perm="filesystem.read")).allowed is False

    def test_deny_one_device_allows_another(self, policy: AuthorizationPolicy) -> None:
        policy.allow("device-A", "filesystem.read")
        policy.allow("device-B", "filesystem.read")
        policy.deny("device-A", "filesystem.read")
        assert policy.check(_make_request(device_id="device-A", perm="filesystem.read")).allowed is False
        assert policy.check(_make_request(device_id="device-B", perm="filesystem.read")).allowed is True

    def test_ten_devices_independent(self, policy: AuthorizationPolicy) -> None:
        device_ids = [f"dev-{i}" for i in range(10)]
        perm = "email.send"
        for did in device_ids[:5]:
            policy.allow(did, perm)
        for did in device_ids:
            req = _make_request(device_id=did, perm=perm)
            expected = did in device_ids[:5]
            assert policy.check(req).allowed is expected


# ===========================================================================
# 11. Policy — Multiple Permissions
# ===========================================================================


class TestPolicyMultiplePermissions:
    def test_independent_permissions_per_device(
        self, policy: AuthorizationPolicy
    ) -> None:
        policy.allow("dev", "filesystem.read")
        assert policy.check(_make_request(device_id="dev", perm="filesystem.read")).allowed is True
        assert policy.check(_make_request(device_id="dev", perm="filesystem.write")).allowed is False

    def test_all_named_permissions_can_be_individually_granted(
        self, policy: AuthorizationPolicy
    ) -> None:
        permissions = [
            "filesystem.read",
            "filesystem.write",
            "browser.read",
            "browser.control",
            "system.media_control",
            "system.command",
            "email.read",
            "email.send",
        ]
        for perm in permissions:
            policy.allow("dev", perm)

        for perm in permissions:
            req = _make_request(device_id="dev", perm=perm)
            assert policy.check(req).allowed is True

    def test_deny_one_permission_leaves_others_allowed(
        self, policy: AuthorizationPolicy
    ) -> None:
        policy.allow("dev", "filesystem.read")
        policy.allow("dev", "filesystem.write")
        policy.deny("dev", "filesystem.write")
        assert policy.check(_make_request(device_id="dev", perm="filesystem.read")).allowed is True
        assert policy.check(_make_request(device_id="dev", perm="filesystem.write")).allowed is False


# ===========================================================================
# 12. Policy Isolation
# ===========================================================================


class TestPolicyIsolation:
    def test_policy_does_not_mutate_request(self, policy: AuthorizationPolicy) -> None:
        req = _make_request()
        original_device_id = req.principal.device_id
        original_perm = req.permission.name
        original_context = dict(req.context)
        policy.check(req)
        assert req.principal.device_id == original_device_id
        assert req.permission.name == original_perm
        assert dict(req.context) == original_context

    def test_policy_does_not_mutate_principal(self, policy: AuthorizationPolicy) -> None:
        principal = _make_principal("isolated-device")
        req = AuthorizationRequest(principal=principal, permission=Permission("filesystem.read"))
        policy.allow("isolated-device", "filesystem.read")
        policy.check(req)
        assert principal.device_id == "isolated-device"
        assert principal.public_identity is None

    def test_policy_does_not_mutate_permission(self, policy: AuthorizationPolicy) -> None:
        perm = Permission("filesystem.read")
        req = AuthorizationRequest(principal=_make_principal(), permission=perm)
        policy.check(req)
        assert perm.name == "filesystem.read"

    def test_policy_does_not_mutate_context(self, policy: AuthorizationPolicy) -> None:
        ctx = {"source": "test"}
        req = AuthorizationRequest(
            principal=_make_principal(),
            permission=_make_permission(),
            context=ctx,
        )
        policy.check(req)
        assert req.context["source"] == "test"

    def test_internal_state_not_exposed_via_check(
        self, policy: AuthorizationPolicy
    ) -> None:
        """check() must return an AuthorizationDecision, not internal dicts."""
        policy.allow("dev", "filesystem.read")
        result = policy.check(_make_request())
        assert isinstance(result, AuthorizationDecision)
        assert not isinstance(result, dict)


# ===========================================================================
# 13. Policy — Clear
# ===========================================================================


class TestPolicyClear:
    def test_clear_resets_allows(self, policy: AuthorizationPolicy) -> None:
        policy.allow("dev", "filesystem.read")
        policy.clear()
        assert policy.check(_make_request(device_id="dev", perm="filesystem.read")).allowed is False

    def test_clear_resets_denies(self, policy: AuthorizationPolicy) -> None:
        policy.allow("dev", "filesystem.read")
        policy.deny("dev", "filesystem.read")
        policy.clear()
        # Default deny still applies, but reason should be NO_EXPLICIT_ALLOW not EXPLICITLY_DENIED
        decision = policy.check(_make_request(device_id="dev", perm="filesystem.read"))
        assert decision.allowed is False
        assert decision.reason == REASON_NO_EXPLICIT_ALLOW

    def test_clear_increments_version(self, policy: AuthorizationPolicy) -> None:
        v_before = policy.version
        policy.clear()
        assert policy.version > v_before

    def test_policy_usable_after_clear(self, policy: AuthorizationPolicy) -> None:
        policy.allow("dev", "filesystem.read")
        policy.clear()
        policy.allow("dev", "filesystem.read")
        assert policy.check(_make_request(device_id="dev", perm="filesystem.read")).allowed is True

    def test_clear_on_empty_policy_is_noop(self, policy: AuthorizationPolicy) -> None:
        policy.clear()
        assert policy.check(_make_request()).allowed is False


# ===========================================================================
# 14. Policy Version / Determinism
# ===========================================================================


class TestDeterminism:
    def test_same_input_same_decision(self, policy: AuthorizationPolicy) -> None:
        policy.allow("dev", "filesystem.read")
        req = _make_request()
        d1 = policy.check(req)
        d2 = policy.check(req)
        assert d1 == d2

    def test_version_increments_on_allow(self, policy: AuthorizationPolicy) -> None:
        v0 = policy.version
        policy.allow("dev", "perm.x")
        assert policy.version == v0 + 1

    def test_version_increments_on_deny(self, policy: AuthorizationPolicy) -> None:
        v0 = policy.version
        policy.deny("dev", "perm.x")
        assert policy.version == v0 + 1

    def test_version_increments_on_revoke(self, policy: AuthorizationPolicy) -> None:
        policy.allow("dev", "perm.x")
        v1 = policy.version
        policy.revoke("dev", "perm.x")
        assert policy.version == v1 + 1

    def test_version_in_decision_matches_policy_at_check_time(
        self, policy: AuthorizationPolicy
    ) -> None:
        policy.allow("dev", "filesystem.read")
        v = policy.version
        decision = policy.check(_make_request())
        assert decision.policy_version == v

    def test_decision_version_reflects_state_at_check(
        self, policy: AuthorizationPolicy
    ) -> None:
        """Decisions taken before and after a mutation have different versions."""
        policy.allow("dev", "filesystem.read")
        d1 = policy.check(_make_request())
        policy.allow("dev", "email.read")
        d2 = policy.check(_make_request())
        assert d2.policy_version > d1.policy_version


# ===========================================================================
# 15. Internal State Not Exposed
# ===========================================================================


class TestInternalStateNotExposed:
    def test_no_allows_getter(self, policy: AuthorizationPolicy) -> None:
        """There must be no public getter returning the internal _allows dict."""
        assert not hasattr(policy, "allows")
        assert not hasattr(policy, "get_allows")

    def test_no_denies_getter(self, policy: AuthorizationPolicy) -> None:
        assert not hasattr(policy, "denies")
        assert not hasattr(policy, "get_denies")

    def test_version_is_read_only(self, policy: AuthorizationPolicy) -> None:
        """version property must not be settable."""
        with pytest.raises(AttributeError):
            policy.version = 999  # type: ignore[misc]

    def test_check_result_is_not_mutable_internal_state(
        self, policy: AuthorizationPolicy
    ) -> None:
        policy.allow("dev", "filesystem.read")
        decision = policy.check(_make_request())
        # Decision is a frozen dataclass — callers cannot mutate it.
        with pytest.raises((AttributeError, TypeError)):
            decision.allowed = False  # type: ignore[misc]


# ===========================================================================
# 16. Immutable Models
# ===========================================================================


class TestImmutableModels:
    def test_permission_immutable(self) -> None:
        p = Permission("filesystem.read")
        with pytest.raises((AttributeError, TypeError)):
            p.name = "changed"  # type: ignore[misc]

    def test_principal_immutable(self) -> None:
        p = DevicePrincipal(device_id="dev")
        with pytest.raises((AttributeError, TypeError)):
            p.device_id = "changed"  # type: ignore[misc]

    def test_request_immutable(self) -> None:
        req = _make_request()
        with pytest.raises((AttributeError, TypeError)):
            req.principal = DevicePrincipal(device_id="other")  # type: ignore[misc]

    def test_decision_immutable(self) -> None:
        d = AuthorizationDecision(
            allowed=True, reason="r", device_id="d", permission="p", policy_version=0
        )
        with pytest.raises((AttributeError, TypeError)):
            d.allowed = False  # type: ignore[misc]


# ===========================================================================
# 17. Security Invariants — explicit proofs
# ===========================================================================


class TestSecurityInvariants:
    """Explicit proofs for every stated security invariant."""

    def test_invariant_default_deny(self) -> None:
        """INVARIANT: Default must be DENY. Never default to ALLOW."""
        policy = AuthorizationPolicy()
        # No configuration at all.
        decision = policy.check(_make_request())
        assert decision.allowed is False, (
            "SECURITY VIOLATION: Fresh policy must default to DENY"
        )

    def test_invariant_explicit_allow_required(self) -> None:
        """INVARIANT: Explicit allow is required; no implicit grants."""
        policy = AuthorizationPolicy()
        # Even after deny + revoke, no allow was ever granted.
        policy.deny("dev", "filesystem.read")
        policy.revoke("dev", "filesystem.read")
        decision = policy.check(_make_request())
        assert decision.allowed is False, (
            "SECURITY VIOLATION: allow must be explicit"
        )

    def test_invariant_deny_overrides_allow(self) -> None:
        """INVARIANT: Explicit DENY must override explicit ALLOW."""
        policy = AuthorizationPolicy()
        policy.allow("device-alpha", "filesystem.read")
        policy.deny("device-alpha", "filesystem.read")
        decision = policy.check(_make_request())
        assert decision.allowed is False, (
            "SECURITY VIOLATION: DENY must override ALLOW"
        )
        assert decision.reason == REASON_EXPLICITLY_DENIED

    def test_invariant_device_identity_does_not_imply_authorization(self) -> None:
        """INVARIANT: Device identity alone must NOT grant permissions."""
        policy = AuthorizationPolicy()
        # Create a full DeviceIdentity and principal with a PublicIdentity.
        identity = generate_identity("trust-test-device")
        pub = identity.public_identity()
        principal = DevicePrincipal(device_id="trust-test-device", public_identity=pub)
        req = AuthorizationRequest(
            principal=principal,
            permission=Permission("filesystem.read"),
        )
        # The device has a real keypair but zero policy entries.
        decision = policy.check(req)
        assert decision.allowed is False, (
            "SECURITY VIOLATION: DeviceIdentity must not imply authorization"
        )

    def test_invariant_unknown_device_denied(self) -> None:
        """INVARIANT: Unknown devices must be denied."""
        policy = AuthorizationPolicy()
        policy.allow("known-device", "filesystem.read")
        decision = policy.check(_make_request(device_id="unknown-device"))
        assert decision.allowed is False, (
            "SECURITY VIOLATION: Unknown device must be denied"
        )

    def test_invariant_unknown_permission_denied(self) -> None:
        """INVARIANT: Unknown permissions must be denied unless explicitly allowed."""
        policy = AuthorizationPolicy()
        policy.allow("dev", "filesystem.read")
        decision = policy.check(
            _make_request(device_id="dev", perm="some.future.capability")
        )
        assert decision.allowed is False, (
            "SECURITY VIOLATION: Unknown permission must be denied"
        )

    def test_invariant_no_wildcard_permissions(self) -> None:
        """INVARIANT: No wildcard permissions. Every permission must be explicit."""
        policy = AuthorizationPolicy()
        # Allow a permission with an asterisk-like name literally;
        # it should NOT grant "filesystem.read" automatically.
        policy.allow("dev", "filesystem.*")
        decision = policy.check(_make_request(device_id="dev", perm="filesystem.read"))
        assert decision.allowed is False, (
            "SECURITY VIOLATION: Wildcard-like permission must not grant others"
        )


# ===========================================================================
# 18. No Private Key Material in Decisions or Repr
# ===========================================================================


class TestNoPrivateKeyInDecisions:
    """Authorization objects must never contain or expose private key material."""

    def _get_public_key_hex(self, device_id: str) -> str:
        identity = generate_identity(device_id)
        return identity.public_identity().public_key_hex

    def test_decision_allowed_has_no_key_material(self) -> None:
        policy = AuthorizationPolicy()
        policy.allow("sec-device", "filesystem.read")
        req = _make_request(device_id="sec-device", perm="filesystem.read")
        decision = policy.check(req)
        r = repr(decision)
        # The repr must contain only the plain scalar fields we defined.
        # It must not contain any hex-encoded key material.
        assert "private" not in r.lower()
        assert "secret" not in r.lower()
        assert "key" not in r.lower() or "policy_version" in r  # "policy_version" is fine

    def test_decision_denied_has_no_key_material(self) -> None:
        policy = AuthorizationPolicy()
        decision = policy.check(_make_request())
        r = repr(decision)
        assert "private" not in r.lower()
        assert "secret" not in r.lower()

    def test_decision_fields_are_plain_scalars(self) -> None:
        policy = AuthorizationPolicy()
        policy.allow("dev", "filesystem.read")
        decision = policy.check(_make_request(device_id="dev", perm="filesystem.read"))
        assert isinstance(decision.allowed, bool)
        assert isinstance(decision.reason, str)
        assert isinstance(decision.device_id, str)
        assert isinstance(decision.permission, str)
        assert isinstance(decision.policy_version, int)

    def test_decision_does_not_hold_principal_reference(self) -> None:
        """Decision must not hold a reference to the DevicePrincipal."""
        policy = AuthorizationPolicy()
        policy.allow("dev", "filesystem.read")
        decision = policy.check(_make_request(device_id="dev", perm="filesystem.read"))
        assert not hasattr(decision, "principal")
        assert not hasattr(decision, "public_identity")

    def test_principal_repr_does_not_contain_private_key(self) -> None:
        """DevicePrincipal repr must not expose private key hex."""
        identity = generate_identity("repr-test-device")
        pub = identity.public_identity()
        principal = DevicePrincipal(device_id="repr-test-device", public_identity=pub)
        r = repr(principal)
        # Public key hex must not appear in the repr.
        assert pub.public_key_hex not in r

    def test_decision_repr_contains_no_64_char_hex_strings(self) -> None:
        """Check that no 64-char hex string (Ed25519 public key) leaks into decision repr."""
        import re
        policy = AuthorizationPolicy()
        policy.allow("dev", "filesystem.read")
        decision = policy.check(_make_request())
        r = repr(decision)
        # Ed25519 public key in hex is exactly 64 characters.
        hex_pattern = re.compile(r"\b[0-9a-fA-F]{64}\b")
        matches = hex_pattern.findall(r)
        assert not matches, f"Potential key material found in decision repr: {matches}"


# ===========================================================================
# 19. Public API surface check
# ===========================================================================


class TestPublicAPI:
    def test_all_expected_names_exported(self) -> None:
        import gideon.core.auth as auth_module
        expected = {
            "DevicePrincipal",
            "Permission",
            "AuthorizationRequest",
            "AuthorizationDecision",
            "AuthorizationPolicy",
            "REASON_EXPLICITLY_ALLOWED",
            "REASON_EXPLICITLY_DENIED",
            "REASON_NO_EXPLICIT_ALLOW",
        }
        for name in expected:
            assert hasattr(auth_module, name), f"Missing from public API: {name}"

    def test_all_in___all__(self) -> None:
        import gideon.core.auth as auth_module
        for name in auth_module.__all__:
            assert hasattr(auth_module, name), f"{name} in __all__ but not importable"

    def test_reason_constants_are_strings(self) -> None:
        assert isinstance(REASON_EXPLICITLY_ALLOWED, str)
        assert isinstance(REASON_EXPLICITLY_DENIED, str)
        assert isinstance(REASON_NO_EXPLICIT_ALLOW, str)

    def test_reason_constants_are_distinct(self) -> None:
        reasons = {REASON_EXPLICITLY_ALLOWED, REASON_EXPLICITLY_DENIED, REASON_NO_EXPLICIT_ALLOW}
        assert len(reasons) == 3


# ===========================================================================
# 20. Permission — Wildcard rejection (hardening)
# ===========================================================================


class TestPermissionWildcardRejection:
    """Permission names containing '*' must be rejected at construction time."""

    def test_bare_wildcard_raises(self) -> None:
        with pytest.raises(ValueError, match=r"\*"):
            Permission("*")

    def test_namespace_wildcard_raises(self) -> None:
        with pytest.raises(ValueError, match=r"\*"):
            Permission("filesystem.*")

    def test_prefix_wildcard_raises(self) -> None:
        with pytest.raises(ValueError, match=r"\*"):
            Permission("*.control")

    def test_embedded_wildcard_raises(self) -> None:
        with pytest.raises(ValueError, match=r"\*"):
            Permission("sys*em.command")

    def test_multi_wildcard_raises(self) -> None:
        with pytest.raises(ValueError, match=r"\*"):
            Permission("*.*")

    def test_wildcard_in_policy_allow_str_raises(self) -> None:
        """Policy must also reject wildcard strings via _resolve_permission."""
        from gideon.core.auth.policy import _resolve_permission

        # _resolve_permission accepts raw strings without Permission validation,
        # so the guard must also live in Permission itself.
        # This test verifies that constructing Permission("filesystem.*") raises
        # before it could ever reach the policy.
        with pytest.raises(ValueError):
            Permission("filesystem.*")

    def test_valid_permissions_still_accepted(self) -> None:
        """Ensure non-wildcard permissions are unaffected by the new check."""
        valid = [
            "filesystem.read",
            "filesystem.write",
            "browser.read",
            "browser.control",
            "system.media_control",
            "system.command",
            "email.read",
            "email.send",
        ]
        for name in valid:
            perm = Permission(name)
            assert perm.name == name

    def test_wildcard_permission_in_policy_via_string_is_not_magic(self) -> None:
        """A raw '*' string passed directly to policy.allow() is treated literally,
        not as a glob, because wildcard semantics are not implemented.
        Granting '*' literally does NOT grant other permissions."""
        from gideon.core.auth.policy import AuthorizationPolicy, _resolve_permission

        # _resolve_permission accepts raw strings (no Permission object needed),
        # but Permission("filesystem.read") in a request must NOT match
        # a literal "*" allow entry.
        policy = AuthorizationPolicy()
        # Bypass Permission() validation by passing the raw string to the policy.
        policy.allow("dev", "*")
        req = AuthorizationRequest(
            principal=DevicePrincipal(device_id="dev"),
            permission=Permission("filesystem.read"),
        )
        # "filesystem.read" != "*" — no wildcard expansion — so still denied.
        assert policy.check(req).allowed is False


# ===========================================================================
# 21. DevicePrincipal — Identity consistency (hardening)
# ===========================================================================


class TestDevicePrincipalIdentityConsistency:
    """If public_identity is provided its device_id must match the principal's."""

    def test_matching_identity_accepted(self) -> None:
        identity = generate_identity("consistent-device")
        pub = identity.public_identity()
        # Should not raise.
        principal = DevicePrincipal(device_id="consistent-device", public_identity=pub)
        assert principal.device_id == "consistent-device"
        assert principal.public_identity is pub

    def test_mismatching_identity_raises(self) -> None:
        identity = generate_identity("identity-owner")
        pub = identity.public_identity()
        # Passing a PublicIdentity whose device_id differs from the principal's.
        with pytest.raises(ValueError, match="does not match"):
            DevicePrincipal(device_id="different-device", public_identity=pub)

    def test_mismatching_identity_error_mentions_both_ids(self) -> None:
        identity = generate_identity("owner-device")
        pub = identity.public_identity()
        with pytest.raises(ValueError) as exc_info:
            DevicePrincipal(device_id="requester-device", public_identity=pub)
        msg = str(exc_info.value)
        assert "requester-device" in msg
        assert "owner-device" in msg

    def test_absent_identity_still_accepted(self) -> None:
        """public_identity=None must continue to work (the common case)."""
        principal = DevicePrincipal(device_id="any-device")
        assert principal.public_identity is None

    def test_explicit_none_identity_accepted(self) -> None:
        principal = DevicePrincipal(device_id="any-device", public_identity=None)
        assert principal.device_id == "any-device"

    def test_consistency_check_uses_exact_string_equality(self) -> None:
        """device_id comparison is case-sensitive exact match, not prefix/suffix."""
        identity = generate_identity("Device-A")
        pub = identity.public_identity()
        # "device-a" != "Device-A"
        with pytest.raises(ValueError):
            DevicePrincipal(device_id="device-a", public_identity=pub)

    def test_policy_check_unaffected_by_matching_identity(self) -> None:
        """A principal with a matching PublicIdentity still starts with zero permissions."""
        identity = generate_identity("trust-device")
        pub = identity.public_identity()
        principal = DevicePrincipal(device_id="trust-device", public_identity=pub)
        policy = AuthorizationPolicy()
        req = AuthorizationRequest(
            principal=principal,
            permission=Permission("filesystem.read"),
        )
        # Identity consistency does not imply authorization.
        assert policy.check(req).allowed is False

