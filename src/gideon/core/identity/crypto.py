"""gideon.core.identity.crypto — Ed25519 primitives via PyCA cryptography.

This module is a thin, stateless wrapper around the `cryptography` library's
Ed25519 implementation.  All cryptographic work is delegated to OpenSSL via
the PyCA `cryptography` package; no custom algorithms are implemented here.

Signing invariants
------------------
- Ed25519 produces 64-byte deterministic signatures.
- Public keys are 32 bytes (raw encoding).
- ``verify()`` always returns a ``bool`` and never raises on bad input.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a fresh Ed25519 keypair using a CSPRNG.

    Returns
    -------
    tuple[Ed25519PrivateKey, Ed25519PublicKey]
        A ``(private_key, public_key)`` pair.  The private key must be
        kept local; the public key may be freely shared.
    """
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def sign(private_key: Ed25519PrivateKey, message: bytes) -> bytes:
    """Sign *message* with *private_key*.

    Parameters
    ----------
    private_key:
        An Ed25519 private key.
    message:
        Arbitrary bytes to sign.

    Returns
    -------
    bytes
        A 64-byte Ed25519 signature.  Ed25519 signing is deterministic:
        the same key and message always produce the same signature.
    """
    return private_key.sign(message)


def verify(
    public_key: Ed25519PublicKey,
    message: bytes,
    signature: bytes,
) -> bool:
    """Verify *signature* over *message* with *public_key*.

    Returns ``True`` if the signature is valid, ``False`` for any other
    outcome including malformed or wrong-length signatures.  This
    function never raises; it absorbs all exceptions so that callers
    always receive a safe boolean result.

    Parameters
    ----------
    public_key:
        The Ed25519 public key to verify against.
    message:
        The original message bytes.
    signature:
        The candidate signature bytes.

    Returns
    -------
    bool
        ``True`` iff the signature is a valid Ed25519 signature over
        *message* made with the private key corresponding to *public_key*.
    """
    try:
        public_key.verify(signature, message)
        return True
    except Exception:
        # InvalidSignature for wrong-but-well-formed sigs;
        # ValueError / others for malformed input (wrong length, etc.).
        # We absorb all exceptions to give callers a safe bool.
        return False


def public_key_to_bytes(public_key: Ed25519PublicKey) -> bytes:
    """Serialize *public_key* to its raw 32-byte form.

    This is the canonical, compact encoding used for storage and
    transmission.  It contains no private key material.
    """
    return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def public_key_from_bytes(data: bytes) -> Ed25519PublicKey:
    """Reconstruct an ``Ed25519PublicKey`` from its raw 32-byte encoding.

    Parameters
    ----------
    data:
        Exactly 32 raw bytes produced by :func:`public_key_to_bytes`.

    Returns
    -------
    Ed25519PublicKey

    Raises
    ------
    ValueError
        If *data* is not a valid 32-byte Ed25519 public key.
    """
    return Ed25519PublicKey.from_public_bytes(data)
