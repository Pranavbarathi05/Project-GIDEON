"""gideon.core.identity.identity — DeviceIdentity and PublicIdentity.

Design notes
------------
Private key material is treated as an internal implementation detail of
:class:`DeviceIdentity`.  It is intentionally excluded from every public
surface of the class: ``__repr__``, ``__str__``, ``public_identity()``,
and the resulting :meth:`PublicIdentity.to_dict` / :meth:`PublicIdentity.to_json`.

Note on Python name-mangling
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The private key is stored as ``self.__private_key``, which Python rewrites
to ``self._DeviceIdentity__private_key`` at compile time.  This is a
*software-engineering* convention that prevents accidental access via a
simple ``identity.private_key`` attribute lookup; it is **not** a
cryptographic access control mechanism.  Determined callers can still
reach the attribute via its mangled name.  The goal is to make
accidental exposure unlikely, not to enforce cryptographic isolation.

The ``PublicIdentity`` value object is frozen (``@dataclass(frozen=True)``)
and contains only the fields needed to identify and verify a device:

  - ``device_id``      — same unique identifier as the parent ``DeviceIdentity``
  - ``public_key_hex`` — hex-encoded raw 32-byte Ed25519 public key
  - ``algorithm``      — ``"ed25519"``
  - ``version``        — integer schema version (currently ``1``)
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import Any

from gideon.core.identity import crypto as _crypto


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ALGORITHM: str = "ed25519"
_VERSION: int = 1


# ---------------------------------------------------------------------------
# PublicIdentity — safe, serializable value object
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PublicIdentity:
    """The public-only, serializable view of a :class:`DeviceIdentity`.

    This object is safe to share, log, or transmit.  It contains no
    private key material.

    Attributes
    ----------
    device_id:
        The same unique identifier used by the parent DeviceIdentity.
    public_key_hex:
        Hex-encoded raw 32-byte Ed25519 public key (64 hex characters).
    algorithm:
        Signing algorithm identifier.  Always ``"ed25519"``.
    version:
        Schema version integer for forward-compatibility.
    """

    device_id: str
    public_key_hex: str
    algorithm: str
    version: int

    def to_dict(self) -> dict[str, Any]:
        """Return a deterministic dict containing only public information.

        The mapping is stable: the same ``PublicIdentity`` always produces
        the same dict (keys in insertion order, values are plain scalars).
        Contains no private key material.
        """
        return {
            "device_id": self.device_id,
            "public_key": self.public_key_hex,
            "algorithm": self.algorithm,
            "version": self.version,
        }

    def to_json(self) -> str:
        """Return a deterministic JSON string containing only public information.

        The output is canonical: keys are sorted alphabetically and
        compact separators ``(",", ":")`` are used so that the same
        ``PublicIdentity`` always produces the identical byte sequence.
        Contains no private key material.

        Returns
        -------
        str
            A compact, deterministic JSON string with the fields
            ``algorithm``, ``device_id``, ``public_key``, and ``version``.
        """
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    def __repr__(self) -> str:
        # Explicit repr — omits public_key_hex to keep repr concise;
        # device_id alone is enough to identify the device in logs.
        return (
            f"PublicIdentity("
            f"device_id={self.device_id!r}, "
            f"algorithm={self.algorithm!r}, "
            f"version={self.version!r})"
        )


# ---------------------------------------------------------------------------
# DeviceIdentity — full identity with keypair
# ---------------------------------------------------------------------------


class DeviceIdentity:
    """Complete device identity: a unique ID and an Ed25519 signing keypair.

    The private key is held internally and is never exposed through any
    public attribute, ``repr``, ``str``, or serialization method.

    Obtain instances via :func:`generate_identity` rather than constructing
    directly.
    """

    ALGORITHM: str = _ALGORITHM
    VERSION: int = _VERSION

    def __init__(
        self,
        device_id: str,
        private_key: Any,   # Ed25519PrivateKey — typed loosely to avoid
        public_key: Any,    # importing cryptography types at module level
    ) -> None:
        if not device_id or not str(device_id).strip():
            raise ValueError("device_id must not be empty")

        # --- Keypair consistency check ---
        # Sign a fixed probe message with the private key and verify it
        # with the supplied public key.  This rejects mismatched keypairs
        # immediately at construction time rather than allowing an identity
        # whose sign() and verify() would never agree to be used silently.
        _probe = b"gideon.identity.keypair-consistency-probe"
        _probe_sig = _crypto.sign(private_key, _probe)
        if not _crypto.verify(public_key, _probe, _probe_sig):
            raise ValueError(
                "private_key and public_key do not form a valid Ed25519 keypair: "
                "a message signed with the private key cannot be verified with "
                "the public key."
            )

        self._device_id: str = device_id
        # The private key is stored as a name-mangled attribute
        # (``_DeviceIdentity__private_key``) as a software-engineering
        # convention to prevent accidental public access.  See the module
        # docstring for the exact security guarantees this does and does
        # not provide.
        self.__private_key = private_key
        self._public_key = public_key
        # Pre-compute and cache the raw public key bytes so that
        # public_identity() and public_key_bytes are zero-cost.
        self._public_key_bytes: bytes = _crypto.public_key_to_bytes(public_key)

    # ------------------------------------------------------------------
    # Public read-only properties
    # ------------------------------------------------------------------

    @property
    def device_id(self) -> str:
        """Unique device identifier."""
        return self._device_id

    @property
    def public_key_bytes(self) -> bytes:
        """Raw 32-byte Ed25519 public key.  Safe to share."""
        return self._public_key_bytes

    # ------------------------------------------------------------------
    # Cryptographic operations
    # ------------------------------------------------------------------

    def sign(self, message: bytes) -> bytes:
        """Sign *message* with this identity's private key.

        Parameters
        ----------
        message:
            Arbitrary bytes to sign.

        Returns
        -------
        bytes
            A 64-byte Ed25519 signature.  Signing is deterministic: the
            same key and message always produce the same signature.

        Raises
        ------
        TypeError
            If *message* is not ``bytes`` or ``bytearray``.
        """
        if not isinstance(message, (bytes, bytearray)):
            raise TypeError(
                f"message must be bytes or bytearray; "
                f"got {type(message).__name__!r}"
            )
        return _crypto.sign(self.__private_key, bytes(message))

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify *signature* over *message* using this identity's public key.

        Returns ``True`` if valid, ``False`` for any invalid or malformed
        input.  Never raises; malformed inputs return ``False``.

        Parameters
        ----------
        message:
            The original message bytes.
        signature:
            The candidate 64-byte Ed25519 signature.

        Returns
        -------
        bool
        """
        if not isinstance(message, (bytes, bytearray)):
            return False
        if not isinstance(signature, (bytes, bytearray)):
            return False
        return _crypto.verify(self._public_key, bytes(message), bytes(signature))

    # ------------------------------------------------------------------
    # Public identity serialization
    # ------------------------------------------------------------------

    def public_identity(self) -> PublicIdentity:
        """Return the public-only, serializable view of this identity.

        The returned :class:`PublicIdentity` contains no private key
        material and is safe to share, log, or transmit.

        Returns
        -------
        PublicIdentity
            A frozen value object with ``device_id``, ``public_key_hex``,
            ``algorithm``, and ``version``.
        """
        return PublicIdentity(
            device_id=self._device_id,
            public_key_hex=self._public_key_bytes.hex(),
            algorithm=self.ALGORITHM,
            version=self.VERSION,
        )

    # ------------------------------------------------------------------
    # Safe string representations — no private key material
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        # Intentionally omits private key material.
        return (
            f"DeviceIdentity("
            f"device_id={self._device_id!r}, "
            f"algorithm={self.ALGORITHM!r})"
        )

    def __str__(self) -> str:
        return self.__repr__()


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def generate_identity(device_id: str | None = None) -> DeviceIdentity:
    """Generate a new :class:`DeviceIdentity` with a fresh Ed25519 keypair.

    ``device_id`` is generated automatically (UUID4) when not supplied.
    No network credentials, secrets beyond the keypair, or persistent
    state are created.

    Parameters
    ----------
    device_id:
        Optional explicit identifier.  A UUID4 string is used when
        ``None``.

    Returns
    -------
    DeviceIdentity
        A complete identity backed by a freshly generated private key.
    """
    resolved_id = device_id if device_id is not None else str(uuid.uuid4())
    private_key, public_key = _crypto.generate_keypair()
    return DeviceIdentity(
        device_id=resolved_id,
        private_key=private_key,
        public_key=public_key,
    )
