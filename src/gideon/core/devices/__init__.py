"""gideon.core.devices — Public API for the GIDEON Device Registry."""

from gideon.core.devices.device import Device, DeviceStatus, create_device
from gideon.core.devices.registry import (
    DeviceAlreadyRegisteredError,
    DeviceNotFoundError,
    DeviceRegistry,
)

__all__ = [
    # Core types
    "Device",
    "DeviceStatus",
    "DeviceRegistry",
    # Factory
    "create_device",
    # Exceptions
    "DeviceAlreadyRegisteredError",
    "DeviceNotFoundError",
]
