"""gideon.core.devices.registry — In-memory DeviceRegistry."""

from __future__ import annotations

from datetime import datetime, timezone

from gideon.core.devices.device import Device, DeviceStatus


class DeviceNotFoundError(KeyError):
    """Raised when an operation targets a device_id not in the registry."""

    def __init__(self, device_id: str) -> None:
        super().__init__(device_id)
        self.device_id = device_id

    def __str__(self) -> str:
        return f"Device not found: {self.device_id!r}"


class DeviceAlreadyRegisteredError(ValueError):
    """Raised when registering a device_id that already exists."""

    def __init__(self, device_id: str) -> None:
        super().__init__(device_id)
        self.device_id = device_id

    def __str__(self) -> str:
        return f"Device already registered: {self.device_id!r}"


class DeviceRegistry:
    """In-memory registry of devices known to GIDEON.

    All operations are synchronous and deterministic.
    No threads, background tasks, or I/O are involved.

    Typical usage::

        registry = DeviceRegistry()
        device = create_device("Lamp", "actuator", capabilities={"switch"})
        registry.register(device)

        found = registry.get(device.device_id)
        switches = registry.find_by_capability("switch")
    """

    def __init__(self) -> None:
        # Internal store: device_id -> Device.
        # Never exposed directly; all public methods return copies or
        # new collections so that callers cannot mutate internal state.
        self._store: dict[str, Device] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, device: Device) -> None:
        """Add *device* to the registry.

        Raises
        ------
        DeviceAlreadyRegisteredError
            If a device with the same ``device_id`` is already registered.
        TypeError
            If *device* is not a :class:`Device` instance.
        """
        if not isinstance(device, Device):
            raise TypeError(
                f"device must be a Device instance; "
                f"got {type(device).__name__!r}"
            )
        if device.device_id in self._store:
            raise DeviceAlreadyRegisteredError(device.device_id)
        self._store[device.device_id] = device

    def unregister(self, device_id: str) -> Device:
        """Remove the device identified by *device_id* from the registry.

        Parameters
        ----------
        device_id:
            Identifier of the device to remove.

        Returns
        -------
        Device
            The removed device record.

        Raises
        ------
        DeviceNotFoundError
            If no device with *device_id* exists.
        """
        if device_id not in self._store:
            raise DeviceNotFoundError(device_id)
        return self._store.pop(device_id)

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------

    def get(self, device_id: str) -> Device | None:
        """Return the device for *device_id*, or ``None`` if not found."""
        return self._store.get(device_id)

    def list_devices(self) -> list[Device]:
        """Return a snapshot of all registered devices.

        The returned list is a *new* list; mutations to it do not affect
        the registry's internal state.  Device order is insertion order
        (CPython 3.7+ dict guarantee).
        """
        return list(self._store.values())

    def find_by_capability(self, capability: str) -> list[Device]:
        """Return devices that advertise *capability* in their capability set.

        Parameters
        ----------
        capability:
            Exact capability string to match (case-sensitive).

        Returns
        -------
        list[Device]
            All registered devices whose ``capabilities`` frozenset
            contains *capability*.  An empty list if none match.
        """
        return [d for d in self._store.values() if capability in d.capabilities]

    # ------------------------------------------------------------------
    # Mutation helpers
    # ------------------------------------------------------------------

    def update_status(self, device_id: str, status: DeviceStatus) -> Device:
        """Replace a device's status and return the updated device.

        Because :class:`Device` is frozen, this creates a new Device
        instance via :func:`dataclasses.replace` and stores it in place
        of the old record.

        Parameters
        ----------
        device_id:
            Target device.
        status:
            New :class:`DeviceStatus` value.

        Returns
        -------
        Device
            The updated (new) device record.

        Raises
        ------
        DeviceNotFoundError
            If no device with *device_id* exists.
        """
        import dataclasses

        existing = self._require(device_id)
        updated = dataclasses.replace(existing, status=status)
        self._store[device_id] = updated
        return updated

    def mark_seen(self, device_id: str) -> Device:
        """Record the current UTC time as the device's ``last_seen`` timestamp.

        Parameters
        ----------
        device_id:
            Target device.

        Returns
        -------
        Device
            The updated device record with a fresh ``last_seen``.

        Raises
        ------
        DeviceNotFoundError
            If no device with *device_id* exists.
        """
        import dataclasses

        existing = self._require(device_id)
        updated = dataclasses.replace(
            existing, last_seen=datetime.now(tz=timezone.utc)
        )
        self._store[device_id] = updated
        return updated

    def clear(self) -> None:
        """Remove all devices from the registry."""
        self._store.clear()

    # ------------------------------------------------------------------
    # Convenience properties
    # ------------------------------------------------------------------

    def __len__(self) -> int:
        """Return the number of registered devices."""
        return len(self._store)

    def __contains__(self, device_id: object) -> bool:
        """Support ``device_id in registry`` membership checks."""
        return device_id in self._store

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _require(self, device_id: str) -> Device:
        """Return the device or raise :class:`DeviceNotFoundError`."""
        device = self._store.get(device_id)
        if device is None:
            raise DeviceNotFoundError(device_id)
        return device
