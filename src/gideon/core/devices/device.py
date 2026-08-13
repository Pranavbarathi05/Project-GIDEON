"""gideon.core.devices.device — Immutable Device dataclass and factory."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping


class DeviceStatus(Enum):
    """Lifecycle status of a registered device."""

    ONLINE = "online"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Device:
    """An immutable record representing a device known to GIDEON.

    Attributes
    ----------
    device_id:
        Globally-unique identifier for this device.
    name:
        Human-readable label (e.g. ``"Living Room Sensor"``).
    device_type:
        Category string (e.g. ``"sensor"``, ``"actuator"``).
    status:
        Current :class:`DeviceStatus` value.
    capabilities:
        Immutable frozenset of capability strings the device advertises
        (e.g. ``frozenset({"temperature", "humidity"})``).
    last_seen:
        UTC-aware :class:`~datetime.datetime` of the most recent
        observation, or ``None`` if the device has never been seen.
    metadata:
        Arbitrary read-only key/value pairs exposed as a
        :class:`~types.MappingProxyType`.
    """

    device_id: str
    name: str
    device_type: str
    status: DeviceStatus
    capabilities: frozenset[str]
    last_seen: datetime | None
    metadata: Mapping[str, Any]

    def __post_init__(self) -> None:
        # --- device_id ---
        if not self.device_id or not self.device_id.strip():
            raise ValueError("device_id must not be empty")

        # --- name ---
        if not self.name or not self.name.strip():
            raise ValueError("name must not be empty")

        # --- device_type ---
        if not self.device_type or not self.device_type.strip():
            raise ValueError("device_type must not be empty")

        # --- status ---
        if not isinstance(self.status, DeviceStatus):
            raise TypeError(
                f"status must be a DeviceStatus instance; "
                f"got {type(self.status).__name__!r}"
            )

        # --- capabilities: accept a plain set/list/tuple and freeze it ---
        if isinstance(self.capabilities, frozenset):
            pass  # already frozen — nothing to do
        elif isinstance(self.capabilities, (set, list, tuple)):
            object.__setattr__(self, "capabilities", frozenset(self.capabilities))
        else:
            raise TypeError(
                "capabilities must be a set, list, tuple, or frozenset; "
                f"got {type(self.capabilities).__name__!r}"
            )

        # --- last_seen: must be UTC-aware if provided ---
        if self.last_seen is not None:
            if self.last_seen.tzinfo is None:
                raise ValueError(
                    "last_seen must be timezone-aware and in UTC, "
                    "but got a naive datetime"
                )
            from datetime import timedelta

            if self.last_seen.utcoffset() != timedelta(0):
                raise ValueError(
                    "last_seen must be in UTC (offset == 0), "
                    f"but got offset {self.last_seen.utcoffset()!r}"
                )

        # --- metadata: accept any Mapping and always snapshot it ---
        # We copy unconditionally — even an existing MappingProxyType — so
        # that this Device owns an independent snapshot and cannot be
        # affected by later mutations to whatever mapping the caller held.
        if isinstance(self.metadata, Mapping):
            object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))
        else:
            raise TypeError(
                "metadata must be a Mapping; "
                f"got {type(self.metadata).__name__!r}"
            )


def create_device(
    name: str,
    device_type: str,
    *,
    device_id: str | None = None,
    status: DeviceStatus = DeviceStatus.UNKNOWN,
    capabilities: set[str] | frozenset[str] | list[str] | tuple[str, ...] | None = None,
    last_seen: datetime | None = None,
    metadata: dict[str, Any] | None = None,
) -> Device:
    """Factory that builds a fully-populated :class:`Device`.

    ``device_id`` is generated automatically when omitted.
    ``last_seen`` defaults to ``None`` (device has not yet been observed).
    No network credentials or secrets are generated.

    Parameters
    ----------
    name:
        Human-readable label for the device.
    device_type:
        Category string, e.g. ``"sensor"``.
    device_id:
        Optional explicit identifier.  A UUID4 string is used when not
        supplied.
    status:
        Initial :class:`DeviceStatus`.  Defaults to ``UNKNOWN``.
    capabilities:
        Collection of capability strings.  Defaults to an empty set.
    last_seen:
        UTC-aware datetime of most recent observation.  Defaults to
        ``None``.
    metadata:
        Arbitrary key/value pairs.  The dict is *copied* before being
        frozen so that mutations to the caller's original dict after
        this call do not affect the Device.  Defaults to ``{}``.

    Returns
    -------
    Device
        A frozen :class:`Device` instance.
    """
    return Device(
        device_id=device_id if device_id is not None else str(uuid.uuid4()),
        name=name,
        device_type=device_type,
        status=status,
        capabilities=frozenset(capabilities) if capabilities is not None else frozenset(),
        last_seen=last_seen,
        # Defensive copy so caller mutations don't affect the Device.
        metadata=dict(metadata) if metadata is not None else {},
    )
