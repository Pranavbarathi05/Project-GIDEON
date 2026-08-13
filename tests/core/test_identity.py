"""Unit tests for gideon.core.identity (DeviceIdentity, PublicIdentity)."""

from __future__ import annotations

import pytest

from gideon.core.identity import DeviceIdentity, PublicIdentity, generate_identity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MESSAGE = b"hello gideon"
OTHER_MESSAGE = b"different message"


# ---------------------------------------------------------------------------
# Identity generation
# ---------------------------------------------------------------------------


class TestIdentityGeneration:
    def test_generate_identity_returns_device_identity(self):
        identity = generate_identity()
        assert isinstance(identity, DeviceIdentity)

    def test_auto_generated_device_id_is_nonempty_string(self):
        identity = generate_identity()
        assert isinstance(identity.device_id, str)
        assert len(identity.device_id) > 0

    def test_unique_device_ids(self):
        ids = {generate_identity().device_id for _ in range(500)}
        assert len(ids) == 500

    def test_explicit_device_id_preserved(self):
        identity = generate_identity(device_id="gideon-node-001")
        assert identity.device_id == "gideon-node-001"

    def test_two_identities_have_different_public_keys(self):
        a = generate_identity()
        b = generate_identity()
        assert a.public_key_bytes != b.public_key_bytes

    def test_public_key_bytes_is_32_bytes(self):
        identity = generate_identity()
        assert isinstance(identity.public_key_bytes, bytes)
        assert len(identity.public_key_bytes) == 32

    def test_algorithm_constant(self):
        assert DeviceIdentity.ALGORITHM == "ed25519"

    def test_version_constant(self):
        assert isinstance(DeviceIdentity.VERSION, int)
        assert DeviceIdentity.VERSION >= 1


# ---------------------------------------------------------------------------
# Public identity serialization
# ---------------------------------------------------------------------------


class TestPublicIdentitySerialization:
    def test_public_identity_returns_public_identity_instance(self):
        pub = generate_identity().public_identity()
        assert isinstance(pub, PublicIdentity)

    def test_public_identity_has_device_id(self):
        identity = generate_identity(device_id="node-42")
        assert identity.public_identity().device_id == "node-42"

    def test_public_identity_has_algorithm(self):
        pub = generate_identity().public_identity()
        assert pub.algorithm == "ed25519"

    def test_public_identity_has_version(self):
        pub = generate_identity().public_identity()
        assert isinstance(pub.version, int)

    def test_public_identity_has_public_key_hex(self):
        pub = generate_identity().public_identity()
        assert isinstance(pub.public_key_hex, str)
        # Raw Ed25519 public key is 32 bytes → 64 hex chars
        assert len(pub.public_key_hex) == 64

    def test_public_key_hex_is_valid_hex(self):
        pub = generate_identity().public_identity()
        # Should not raise
        int(pub.public_key_hex, 16)

    def test_to_dict_contains_required_keys(self):
        d = generate_identity().public_identity().to_dict()
        assert set(d.keys()) == {"device_id", "public_key", "algorithm", "version"}

    def test_to_dict_values_are_correct(self):
        identity = generate_identity(device_id="serial-007")
        pub = identity.public_identity()
        d = pub.to_dict()
        assert d["device_id"] == "serial-007"
        assert d["public_key"] == pub.public_key_hex
        assert d["algorithm"] == "ed25519"
        assert isinstance(d["version"], int)

    def test_to_dict_is_deterministic(self):
        """The same PublicIdentity must always produce the same dict."""
        identity = generate_identity()
        pub = identity.public_identity()
        assert pub.to_dict() == pub.to_dict()

    def test_public_identity_is_deterministic(self):
        """Calling public_identity() twice on the same DeviceIdentity must
        return equal objects."""
        identity = generate_identity()
        assert identity.public_identity() == identity.public_identity()

    def test_public_identity_is_frozen(self):
        """PublicIdentity must be immutable."""
        pub = generate_identity().public_identity()
        with pytest.raises((AttributeError, TypeError)):
            pub.device_id = "hacked"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------


class TestSigning:
    def test_sign_returns_bytes(self):
        sig = generate_identity().sign(MESSAGE)
        assert isinstance(sig, bytes)

    def test_signature_is_64_bytes(self):
        """Ed25519 always produces a 64-byte signature."""
        sig = generate_identity().sign(MESSAGE)
        assert len(sig) == 64

    def test_sign_accepts_empty_bytes(self):
        sig = generate_identity().sign(b"")
        assert isinstance(sig, bytes)
        assert len(sig) == 64

    def test_sign_accepts_bytearray(self):
        sig = generate_identity().sign(bytearray(b"test"))
        assert len(sig) == 64

    def test_sign_non_bytes_raises_type_error(self):
        with pytest.raises(TypeError):
            generate_identity().sign("not bytes")  # type: ignore[arg-type]

    def test_repeated_signing_same_message_produces_same_signature(self):
        """Ed25519 is deterministic — same key + same message → same signature."""
        identity = generate_identity()
        assert identity.sign(MESSAGE) == identity.sign(MESSAGE)

    def test_different_messages_produce_different_signatures(self):
        identity = generate_identity()
        assert identity.sign(MESSAGE) != identity.sign(OTHER_MESSAGE)

    def test_different_identities_produce_different_signatures(self):
        sig_a = generate_identity().sign(MESSAGE)
        sig_b = generate_identity().sign(MESSAGE)
        assert sig_a != sig_b


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


class TestVerification:
    def test_verify_own_signature_returns_true(self):
        identity = generate_identity()
        sig = identity.sign(MESSAGE)
        assert identity.verify(MESSAGE, sig) is True

    def test_verify_returns_bool(self):
        identity = generate_identity()
        sig = identity.sign(MESSAGE)
        result = identity.verify(MESSAGE, sig)
        assert isinstance(result, bool)

    def test_verify_modified_message_returns_false(self):
        identity = generate_identity()
        sig = identity.sign(MESSAGE)
        assert identity.verify(b"tampered", sig) is False

    def test_verify_different_signature_returns_false(self):
        identity = generate_identity()
        sig_a = identity.sign(MESSAGE)
        sig_b = identity.sign(OTHER_MESSAGE)
        assert identity.verify(MESSAGE, sig_b) is False
        assert identity.verify(OTHER_MESSAGE, sig_a) is False

    def test_two_identities_cannot_cross_verify(self):
        """A signature made by identity A must not verify under identity B's
        public key, and vice versa."""
        a = generate_identity()
        b = generate_identity()
        sig_a = a.sign(MESSAGE)
        sig_b = b.sign(MESSAGE)
        assert b.verify(MESSAGE, sig_a) is False
        assert a.verify(MESSAGE, sig_b) is False

    def test_malformed_signature_returns_false_not_raises(self):
        """Malformed signatures (garbage bytes) must return False, not raise."""
        identity = generate_identity()
        assert identity.verify(MESSAGE, b"garbage") is False

    def test_empty_signature_returns_false(self):
        identity = generate_identity()
        assert identity.verify(MESSAGE, b"") is False

    def test_wrong_length_signature_returns_false(self):
        identity = generate_identity()
        # Ed25519 expects 64 bytes; 63 and 65 are invalid lengths
        assert identity.verify(MESSAGE, b"\x00" * 63) is False
        assert identity.verify(MESSAGE, b"\x00" * 65) is False

    def test_all_zeros_signature_returns_false(self):
        identity = generate_identity()
        assert identity.verify(MESSAGE, b"\x00" * 64) is False

    def test_verify_non_bytes_message_returns_false(self):
        identity = generate_identity()
        sig = identity.sign(MESSAGE)
        assert identity.verify("not bytes", sig) is False  # type: ignore[arg-type]

    def test_verify_non_bytes_signature_returns_false(self):
        identity = generate_identity()
        assert identity.verify(MESSAGE, "not bytes") is False  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Private key protection
# ---------------------------------------------------------------------------


class TestPrivateKeyProtection:
    def test_private_key_not_in_repr(self):
        identity = generate_identity()
        r = repr(identity)
        assert "private" not in r.lower()
        assert "secret" not in r.lower()

    def test_private_key_not_in_str(self):
        identity = generate_identity()
        s = str(identity)
        assert "private" not in s.lower()
        assert "secret" not in s.lower()

    def test_repr_contains_device_id(self):
        identity = generate_identity(device_id="repr-test-id")
        assert "repr-test-id" in repr(identity)

    def test_repr_contains_algorithm(self):
        identity = generate_identity()
        assert "ed25519" in repr(identity)

    def test_private_key_not_in_public_identity_dict(self):
        identity = generate_identity()
        d = identity.public_identity().to_dict()
        serialized = str(d).lower()
        assert "private" not in serialized
        assert "secret" not in serialized

    def test_no_public_private_key_attribute(self):
        """There must be no attribute simply named 'private_key' accessible."""
        identity = generate_identity()
        assert not hasattr(identity, "private_key")

    def test_no_public_attribute_named_secret_or_private(self):
        """No public attribute name should hint at private key exposure."""
        identity = generate_identity()
        public_attrs = [a for a in dir(identity) if not a.startswith("_")]
        suspicious = [
            a for a in public_attrs
            if "private" in a.lower() or "secret" in a.lower()
        ]
        assert suspicious == []

    def test_public_identity_repr_safe(self):
        pub = generate_identity().public_identity()
        r = repr(pub)
        assert "private" not in r.lower()
        assert "secret" not in r.lower()

    def test_public_identity_dict_no_private_key_field(self):
        d = generate_identity().public_identity().to_dict()
        for key in d:
            assert "private" not in key.lower()
            assert "secret" not in key.lower()


# ---------------------------------------------------------------------------
# Repeated signing / verifying (robustness)
# ---------------------------------------------------------------------------


class TestRobustness:
    def test_repeated_sign_verify_cycles(self):
        """Sign and verify many messages in a tight loop; must never fail."""
        identity = generate_identity()
        messages = [f"message-{i}".encode() for i in range(100)]
        for msg in messages:
            sig = identity.sign(msg)
            assert identity.verify(msg, sig) is True
            # Cross-check: adjacent messages must not verify with wrong sig
            assert identity.verify(msg + b"x", sig) is False

    def test_multiple_identities_independent(self):
        """Each identity is independently valid and non-interfering."""
        identities = [generate_identity() for _ in range(10)]
        for identity in identities:
            sig = identity.sign(MESSAGE)
            # Own verification succeeds
            assert identity.verify(MESSAGE, sig) is True
            # All other identities reject the signature
            for other in identities:
                if other is not identity:
                    assert other.verify(MESSAGE, sig) is False


# ---------------------------------------------------------------------------
# PublicIdentity JSON serialization
# ---------------------------------------------------------------------------


class TestPublicIdentityJson:
    def test_to_json_returns_string(self):
        pub = generate_identity().public_identity()
        assert isinstance(pub.to_json(), str)

    def test_to_json_is_valid_json(self):
        import json
        pub = generate_identity().public_identity()
        parsed = json.loads(pub.to_json())
        assert isinstance(parsed, dict)

    def test_to_json_contains_required_keys(self):
        import json
        d = json.loads(generate_identity().public_identity().to_json())
        assert set(d.keys()) == {"device_id", "public_key", "algorithm", "version"}

    def test_to_json_values_match_to_dict(self):
        import json
        pub = generate_identity().public_identity()
        parsed = json.loads(pub.to_json())
        expected = pub.to_dict()
        assert parsed["device_id"] == expected["device_id"]
        assert parsed["public_key"] == expected["public_key"]
        assert parsed["algorithm"] == expected["algorithm"]
        assert parsed["version"] == expected["version"]

    def test_to_json_is_deterministic(self):
        """Repeated calls on the same PublicIdentity must produce identical text."""
        pub = generate_identity().public_identity()
        assert pub.to_json() == pub.to_json()

    def test_to_json_same_identity_same_bytes(self):
        """The same PublicIdentity always serializes to the same byte sequence."""
        identity = generate_identity()
        pub = identity.public_identity()
        j1 = pub.to_json()
        j2 = pub.to_json()
        assert j1 == j2
        assert j1.encode() == j2.encode()

    def test_to_json_keys_are_sorted(self):
        """Keys must be in alphabetical order for canonical output."""
        import json
        pub = generate_identity().public_identity()
        raw = pub.to_json()
        parsed = json.loads(raw)
        expected = json.dumps(parsed, sort_keys=True, separators=(",", ":"))
        assert raw == expected

    def test_to_json_uses_compact_separators(self):
        """The JSON must not contain spaces after colons or commas."""
        raw = generate_identity().public_identity().to_json()
        assert ": " not in raw
        assert ", " not in raw

    def test_to_json_no_private_key_material(self):
        """JSON output must not contain words hinting at private key."""
        raw = generate_identity().public_identity().to_json().lower()
        assert "private" not in raw
        assert "secret" not in raw


# ---------------------------------------------------------------------------
# Keypair consistency
# ---------------------------------------------------------------------------


class TestKeypairConsistency:
    def test_mismatched_keypair_raises_value_error(self):
        """Regression: constructing DeviceIdentity with a private key from one
        keypair and the public key from a different keypair must be rejected
        immediately with a clear ValueError."""
        from gideon.core.identity import crypto as _crypto

        priv_a, _pub_a = _crypto.generate_keypair()
        _priv_b, pub_b = _crypto.generate_keypair()

        with pytest.raises(ValueError, match="keypair"):
            DeviceIdentity(
                device_id="mismatch-test",
                private_key=priv_a,
                public_key=pub_b,
            )

    def test_matched_keypair_is_accepted(self):
        """A correctly matched keypair must be accepted without error."""
        from gideon.core.identity import crypto as _crypto

        priv, pub = _crypto.generate_keypair()
        identity = DeviceIdentity(
            device_id="match-test",
            private_key=priv,
            public_key=pub,
        )
        assert identity.device_id == "match-test"

    def test_mismatch_error_does_not_expose_key_bytes(self):
        """The ValueError message must not contain raw private key bytes."""
        from gideon.core.identity import crypto as _crypto

        priv_a, _pub_a = _crypto.generate_keypair()
        _priv_b, pub_b = _crypto.generate_keypair()

        with pytest.raises(ValueError) as exc_info:
            DeviceIdentity(
                device_id="mismatch-leak-test",
                private_key=priv_a,
                public_key=pub_b,
            )
        # The raw public key bytes of B must not appear verbatim in the error
        pub_b_hex = _crypto.public_key_to_bytes(pub_b).hex()
        assert pub_b_hex not in str(exc_info.value)

