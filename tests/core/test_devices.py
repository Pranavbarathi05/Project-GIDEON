"""Unit tests for gideon.core.devices (Device, DeviceRegistry)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import MappingProxyType

import pytest

from gideon.core.devices import (
    Device,
    DeviceAlreadyRegisteredError,
    DeviceNotFoundError,
    DeviceRegistry,
    DeviceStatus,
    create_device,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_device(**kwargs) -> Device:
    """Convenience wrapper around create_device with sensible defaults."""
    kwargs.setdefault("name", "Test Device")
    kwargs.setdefault("device_type", "sensor")
    return create_device(**kwargs)


# ---------------------------------------------------------------------------
# Device creation
# ---------------------------------------------------------------------------

class TestDeviceCreation:
    def test_create_device_returns_device(self):
        d = make_device()
        assert isinstance(d, Device)

    def test_create_device_sets_name_and_type(self):
        d = create_device("My Lamp", "actuator")
        assert d.name == "My Lamp"
        assert d.device_type == "actuator"

    def test_default_status_is_unknown(self):
        d = make_device()
        assert d.status is DeviceStatus.UNKNOWN

    def test_explicit_status_online(self):
        d = make_device(status=DeviceStatus.ONLINE)
        assert d.status is DeviceStatus.ONLINE

    def test_explicit_status_offline(self):
        d = make_device(status=DeviceStatus.OFFLINE)
        assert d.status is DeviceStatus.OFFLINE

    def test_default_last_seen_is_none(self):
        d = make_device()
        assert d.last_seen is None

    def test_explicit_last_seen_accepted(self):
        ts = datetime(2025, 1, 1, tzinfo=timezone.utc)
        d = make_device(last_seen=ts)
        assert d.last_seen == ts

    def test_default_capabilities_are_empty(self):
        d = make_device()
        assert d.capabilities == frozenset()

    def test_default_metadata_is_empty(self):
        d = make_device()
        assert d.metadata == {}


# ---------------------------------------------------------------------------
# Generated IDs
# ---------------------------------------------------------------------------

class TestGeneratedIds:
    def test_auto_generated_id_is_nonempty_string(self):
        d = make_device()
        assert isinstance(d.device_id, str)
        assert len(d.device_id) > 0

    def test_auto_generated_ids_are_unique(self):
        ids = {make_device().device_id for _ in range(500)}
        assert len(ids) == 500


# ---------------------------------------------------------------------------
# Explicit IDs
# ---------------------------------------------------------------------------

class TestExplicitIds:
    def test_explicit_id_is_preserved(self):
        d = create_device("Lamp", "actuator", device_id="lamp-001")
        assert d.device_id == "lamp-001"

    def test_different_explicit_ids_produce_different_devices(self):
        d1 = create_device("A", "sensor", device_id="aaa")
        d2 = create_device("B", "sensor", device_id="bbb")
        assert d1.device_id != d2.device_id


# ---------------------------------------------------------------------------
# Immutable capabilities
# ---------------------------------------------------------------------------

class TestImmutableCapabilities:
    def test_capabilities_stored_as_frozenset(self):
        d = make_device(capabilities={"temp", "humidity"})
        assert isinstance(d.capabilities, frozenset)

    def test_capabilities_not_mutable(self):
        d = make_device(capabilities={"temp"})
        with pytest.raises((AttributeError, TypeError)):
            d.capabilities.add("pressure")  # type: ignore[attr-defined]

    def test_caller_set_mutation_does_not_affect_device(self):
        caps = {"temp"}
        d = create_device("Sensor", "sensor", capabilities=caps)
        caps.add("humidity")
        assert "humidity" not in d.capabilities

    def test_capabilities_from_list(self):
        d = make_device(capabilities=["a", "b", "c"])
        assert isinstance(d.capabilities, frozenset)
        assert d.capabilities == frozenset({"a", "b", "c"})

    def test_capabilities_from_tuple(self):
        d = make_device(capabilities=("x", "y"))
        assert d.capabilities == frozenset({"x", "y"})


# ---------------------------------------------------------------------------
# Immutable metadata
# ---------------------------------------------------------------------------

class TestImmutableMetadata:
    def test_metadata_exposed_as_mapping_proxy(self):
        d = make_device(metadata={"zone": "kitchen"})
        assert isinstance(d.metadata, MappingProxyType)

    def test_metadata_not_mutable_via_device(self):
        d = make_device(metadata={"zone": "kitchen"})
        with pytest.raises(TypeError):
            d.metadata["zone"] = "bedroom"  # type: ignore[index]

    def test_caller_dict_mutation_does_not_affect_metadata(self):
        m = {"zone": "kitchen"}
        d = create_device("S", "sensor", metadata=m)
        m["zone"] = "bedroom"
        assert d.metadata["zone"] == "kitchen"

    def test_metadata_values_readable(self):
        d = make_device(metadata={"floor": 2, "room": "office"})
        assert d.metadata["floor"] == 2
        assert d.metadata["room"] == "office"

    def test_proxy_backed_by_mutable_dict_cannot_affect_device(self):
        """Regression: passing a MappingProxyType wrapping a mutable dict must
        not allow later mutations of that underlying dict to change the Device's
        metadata (i.e. Device always owns an independent snapshot)."""
        backing = {"zone": "kitchen"}
        proxy = MappingProxyType(backing)
        # Pass the proxy directly to the Device constructor
        d = Device(
            device_id="reg-001",
            name="Reg Test",
            device_type="sensor",
            status=DeviceStatus.UNKNOWN,
            capabilities=frozenset(),
            last_seen=None,
            metadata=proxy,
        )
        # Now mutate the original backing dict
        backing["zone"] = "bedroom"
        # The Device must be unaffected because it copied the proxy's contents
        assert d.metadata["zone"] == "kitchen"


# ---------------------------------------------------------------------------
# All status values
# ---------------------------------------------------------------------------

class TestAllStatusValues:
    def test_status_online(self):
        assert DeviceStatus.ONLINE.value == "online"

    def test_status_offline(self):
        assert DeviceStatus.OFFLINE.value == "offline"

    def test_status_unknown(self):
        assert DeviceStatus.UNKNOWN.value == "unknown"

    def test_all_three_statuses_exist(self):
        statuses = {s.value for s in DeviceStatus}
        assert statuses == {"online", "offline", "unknown"}


# ---------------------------------------------------------------------------
# Device immutability (field-level)
# ---------------------------------------------------------------------------

class TestDeviceImmutability:
    def test_device_id_not_reassignable(self):
        d = make_device()
        with pytest.raises((AttributeError, TypeError)):
            d.device_id = "new-id"  # type: ignore[misc]

    def test_name_not_reassignable(self):
        d = make_device()
        with pytest.raises((AttributeError, TypeError)):
            d.name = "new-name"  # type: ignore[misc]

    def test_status_not_reassignable(self):
        d = make_device()
        with pytest.raises((AttributeError, TypeError)):
            d.status = DeviceStatus.ONLINE  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Registry — registration
# ---------------------------------------------------------------------------

class TestRegistryRegistration:
    def test_register_adds_device(self):
        reg = DeviceRegistry()
        d = make_device()
        reg.register(d)
        assert len(reg) == 1

    def test_register_makes_device_retrievable(self):
        reg = DeviceRegistry()
        d = make_device()
        reg.register(d)
        assert reg.get(d.device_id) is d

    def test_register_non_device_raises_type_error(self):
        reg = DeviceRegistry()
        with pytest.raises(TypeError):
            reg.register("not-a-device")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Registry — duplicate registration
# ---------------------------------------------------------------------------

class TestRegistryDuplicateRegistration:
    def test_duplicate_raises_device_already_registered(self):
        reg = DeviceRegistry()
        d = make_device(device_id="dup-001")
        reg.register(d)
        with pytest.raises(DeviceAlreadyRegisteredError):
            reg.register(d)

    def test_duplicate_does_not_silently_replace(self):
        reg = DeviceRegistry()
        d1 = create_device("Original", "sensor", device_id="dup-002")
        d2 = create_device("Replacement", "actuator", device_id="dup-002")
        reg.register(d1)
        with pytest.raises(DeviceAlreadyRegisteredError):
            reg.register(d2)
        # The original must still be there
        assert reg.get("dup-002") is d1

    def test_duplicate_error_contains_device_id(self):
        reg = DeviceRegistry()
        d = make_device(device_id="dup-003")
        reg.register(d)
        with pytest.raises(DeviceAlreadyRegisteredError) as exc_info:
            reg.register(d)
        assert "dup-003" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Registry — retrieval
# ---------------------------------------------------------------------------

class TestRegistryRetrieval:
    def test_get_returns_correct_device(self):
        reg = DeviceRegistry()
        d = make_device()
        reg.register(d)
        assert reg.get(d.device_id) is d

    def test_contains_after_register(self):
        reg = DeviceRegistry()
        d = make_device()
        reg.register(d)
        assert d.device_id in reg


# ---------------------------------------------------------------------------
# Registry — unknown retrieval
# ---------------------------------------------------------------------------

class TestRegistryUnknownRetrieval:
    def test_get_unknown_returns_none(self):
        reg = DeviceRegistry()
        assert reg.get("nonexistent-id") is None

    def test_contains_unknown_is_false(self):
        reg = DeviceRegistry()
        assert "nonexistent-id" not in reg


# ---------------------------------------------------------------------------
# Registry — listing
# ---------------------------------------------------------------------------

class TestRegistryListing:
    def test_list_devices_empty_by_default(self):
        reg = DeviceRegistry()
        assert reg.list_devices() == []

    def test_list_devices_returns_all(self):
        reg = DeviceRegistry()
        d1 = make_device()
        d2 = make_device()
        reg.register(d1)
        reg.register(d2)
        listed = reg.list_devices()
        assert len(listed) == 2
        assert d1 in listed
        assert d2 in listed

    def test_list_devices_returns_new_list(self):
        """Mutating the returned list must not affect the registry."""
        reg = DeviceRegistry()
        d = make_device()
        reg.register(d)
        snapshot = reg.list_devices()
        snapshot.clear()
        assert len(reg) == 1

    def test_list_devices_insertion_order_preserved(self):
        reg = DeviceRegistry()
        ids = [f"dev-{i}" for i in range(10)]
        devices = [create_device(f"D{i}", "sensor", device_id=ids[i]) for i in range(10)]
        for dev in devices:
            reg.register(dev)
        listed_ids = [d.device_id for d in reg.list_devices()]
        assert listed_ids == ids


# ---------------------------------------------------------------------------
# Registry — capability lookup
# ---------------------------------------------------------------------------

class TestRegistryCapabilityLookup:
    def test_find_by_capability_returns_matching(self):
        reg = DeviceRegistry()
        d1 = make_device(capabilities={"temperature"})
        d2 = make_device(capabilities={"humidity"})
        reg.register(d1)
        reg.register(d2)
        result = reg.find_by_capability("temperature")
        assert d1 in result
        assert d2 not in result

    def test_find_by_capability_empty_when_none_match(self):
        reg = DeviceRegistry()
        d = make_device(capabilities={"pressure"})
        reg.register(d)
        assert reg.find_by_capability("temperature") == []

    def test_find_by_capability_multiple_results(self):
        reg = DeviceRegistry()
        d1 = make_device(capabilities={"switch", "dimmer"})
        d2 = make_device(capabilities={"switch"})
        d3 = make_device(capabilities={"camera"})
        reg.register(d1)
        reg.register(d2)
        reg.register(d3)
        result = reg.find_by_capability("switch")
        assert len(result) == 2
        assert d1 in result
        assert d2 in result
        assert d3 not in result

    def test_find_by_capability_case_sensitive(self):
        reg = DeviceRegistry()
        d = make_device(capabilities={"Temperature"})
        reg.register(d)
        assert reg.find_by_capability("temperature") == []
        assert reg.find_by_capability("Temperature") == [d]


# ---------------------------------------------------------------------------
# Registry — status updates
# ---------------------------------------------------------------------------

class TestRegistryStatusUpdates:
    def test_update_status_changes_status(self):
        reg = DeviceRegistry()
        d = make_device(status=DeviceStatus.OFFLINE)
        reg.register(d)
        updated = reg.update_status(d.device_id, DeviceStatus.ONLINE)
        assert updated.status is DeviceStatus.ONLINE

    def test_update_status_reflects_in_registry(self):
        reg = DeviceRegistry()
        d = make_device()
        reg.register(d)
        reg.update_status(d.device_id, DeviceStatus.ONLINE)
        assert reg.get(d.device_id).status is DeviceStatus.ONLINE  # type: ignore[union-attr]

    def test_update_status_unknown_device_raises(self):
        reg = DeviceRegistry()
        with pytest.raises(DeviceNotFoundError):
            reg.update_status("ghost-id", DeviceStatus.ONLINE)

    def test_update_status_error_contains_device_id(self):
        reg = DeviceRegistry()
        with pytest.raises(DeviceNotFoundError) as exc_info:
            reg.update_status("ghost-id-123", DeviceStatus.ONLINE)
        assert "ghost-id-123" in str(exc_info.value)

    def test_update_status_all_values(self):
        reg = DeviceRegistry()
        d = make_device()
        reg.register(d)
        for status in DeviceStatus:
            reg.update_status(d.device_id, status)
            assert reg.get(d.device_id).status is status  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# Registry — mark_seen
# ---------------------------------------------------------------------------

class TestRegistryMarkSeen:
    def test_mark_seen_sets_last_seen(self):
        reg = DeviceRegistry()
        d = make_device()
        assert d.last_seen is None
        reg.register(d)
        before = datetime.now(tz=timezone.utc)
        reg.mark_seen(d.device_id)
        after = datetime.now(tz=timezone.utc)
        seen = reg.get(d.device_id).last_seen  # type: ignore[union-attr]
        assert seen is not None
        assert before <= seen <= after

    def test_mark_seen_timestamp_is_utc_aware(self):
        reg = DeviceRegistry()
        d = make_device()
        reg.register(d)
        reg.mark_seen(d.device_id)
        seen = reg.get(d.device_id).last_seen  # type: ignore[union-attr]
        assert seen is not None
        assert seen.tzinfo is not None
        assert seen.utcoffset() == timedelta(0)

    def test_mark_seen_unknown_device_raises(self):
        reg = DeviceRegistry()
        with pytest.raises(DeviceNotFoundError):
            reg.mark_seen("ghost-id")

    def test_mark_seen_updates_registry(self):
        reg = DeviceRegistry()
        d = make_device()
        reg.register(d)
        updated = reg.mark_seen(d.device_id)
        assert reg.get(d.device_id) is updated


# ---------------------------------------------------------------------------
# Registry — unregister
# ---------------------------------------------------------------------------

class TestRegistryUnregister:
    def test_unregister_removes_device(self):
        reg = DeviceRegistry()
        d = make_device()
        reg.register(d)
        reg.unregister(d.device_id)
        assert reg.get(d.device_id) is None

    def test_unregister_returns_removed_device(self):
        reg = DeviceRegistry()
        d = make_device()
        reg.register(d)
        removed = reg.unregister(d.device_id)
        assert removed is d

    def test_unregister_decrements_count(self):
        reg = DeviceRegistry()
        d = make_device()
        reg.register(d)
        assert len(reg) == 1
        reg.unregister(d.device_id)
        assert len(reg) == 0

    def test_unregister_unknown_raises(self):
        reg = DeviceRegistry()
        with pytest.raises(DeviceNotFoundError):
            reg.unregister("nonexistent-id")


# ---------------------------------------------------------------------------
# Registry — clear
# ---------------------------------------------------------------------------

class TestRegistryClear:
    def test_clear_removes_all_devices(self):
        reg = DeviceRegistry()
        for i in range(5):
            reg.register(make_device())
        reg.clear()
        assert len(reg) == 0
        assert reg.list_devices() == []

    def test_clear_on_empty_registry_is_safe(self):
        reg = DeviceRegistry()
        reg.clear()  # must not raise
        assert len(reg) == 0


# ---------------------------------------------------------------------------
# Registry — unknown-device error handling
# ---------------------------------------------------------------------------

class TestRegistryUnknownDeviceErrors:
    def test_update_status_raises_device_not_found(self):
        reg = DeviceRegistry()
        with pytest.raises(DeviceNotFoundError):
            reg.update_status("no-such-id", DeviceStatus.ONLINE)

    def test_mark_seen_raises_device_not_found(self):
        reg = DeviceRegistry()
        with pytest.raises(DeviceNotFoundError):
            reg.mark_seen("no-such-id")

    def test_unregister_raises_device_not_found(self):
        reg = DeviceRegistry()
        with pytest.raises(DeviceNotFoundError):
            reg.unregister("no-such-id")

    def test_device_not_found_error_is_key_error_subclass(self):
        """DeviceNotFoundError should be catchable as KeyError."""
        reg = DeviceRegistry()
        with pytest.raises(KeyError):
            reg.unregister("no-such-id")

    def test_device_already_registered_error_is_value_error_subclass(self):
        """DeviceAlreadyRegisteredError should be catchable as ValueError."""
        reg = DeviceRegistry()
        d = make_device(device_id="already-001")
        reg.register(d)
        with pytest.raises(ValueError):
            reg.register(d)
