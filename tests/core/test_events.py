"""Unit tests for gideon.core.events (Event, EventBus)."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from types import MappingProxyType

import pytest

from gideon.core.events import (
    AsyncHandler,
    Event,
    EventBus,
    EventBusShutdownError,
    create_event,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(coro):  # type: ignore[no-untyped-def]
    """Run a coroutine synchronously (no pytest-asyncio needed)."""
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Event creation
# ---------------------------------------------------------------------------

class TestEventCreation:
    def test_create_event_returns_event(self):
        event = create_event("system.started", source="test")
        assert isinstance(event, Event)

    def test_create_event_sets_type_and_source(self):
        event = create_event("system.started", source="core.boot")
        assert event.event_type == "system.started"
        assert event.source == "core.boot"

    def test_create_event_default_payload_is_empty_dict(self):
        event = create_event("system.started", source="test")
        assert event.payload == {}

    def test_create_event_accepts_payload(self):
        event = create_event("sensor.data", source="sensor", payload={"temp": 22.5})
        assert event.payload["temp"] == 22.5

    def test_create_event_timestamp_is_utc(self):
        event = create_event("system.started", source="test")
        assert event.timestamp.tzinfo is not None
        # utcoffset must be exactly zero — not just any aware timezone
        assert event.timestamp.utcoffset() == timedelta(0)

    def test_event_is_immutable(self):
        event = create_event("system.started", source="test")
        with pytest.raises((AttributeError, TypeError)):
            event.event_type = "other"  # type: ignore[misc]

    def test_direct_construction_validates_empty_event_type(self):
        with pytest.raises(ValueError, match="event_type"):
            Event(
                event_id="x",
                event_type="",
                timestamp=datetime.now(tz=timezone.utc),
                source="test",
                payload={},
            )

    def test_direct_construction_validates_empty_source(self):
        with pytest.raises(ValueError, match="source"):
            Event(
                event_id="x",
                event_type="system.started",
                timestamp=datetime.now(tz=timezone.utc),
                source="",
                payload={},
            )

    def test_direct_construction_validates_naive_timestamp(self):
        with pytest.raises(ValueError, match="UTC"):
            Event(
                event_id="x",
                event_type="system.started",
                timestamp=datetime.now(),  # naive — no tzinfo
                source="test",
                payload={},
            )

    def test_direct_construction_validates_payload_type(self):
        with pytest.raises(TypeError, match="payload"):
            Event(
                event_id="x",
                event_type="system.started",
                timestamp=datetime.now(tz=timezone.utc),
                source="test",
                payload="not-a-dict",  # type: ignore[arg-type]
            )


# ---------------------------------------------------------------------------
# Event immutability (regression tests — would fail on the old implementation)
# ---------------------------------------------------------------------------

class TestEventImmutability:
    def test_payload_is_read_only(self):
        """Mutating the payload through an Event instance must raise."""
        event = create_event("x", source="test", payload={"k": 1})
        with pytest.raises(TypeError):
            event.payload["k"] = 99  # type: ignore[index]

    def test_payload_add_key_raises(self):
        """Adding a new key to the payload through the Event must raise."""
        event = create_event("x", source="test")
        with pytest.raises(TypeError):
            event.payload["new"] = "value"  # type: ignore[index]

    def test_payload_exposed_as_mapping_proxy(self):
        """payload must not be a plain mutable dict — it must be the
        read-only MappingProxyType wrapper."""
        event = create_event("x", source="test", payload={"a": 1})
        assert isinstance(event.payload, MappingProxyType)
        assert not isinstance(event.payload, dict)

    def test_payload_values_still_readable(self):
        """Read access must work exactly as before."""
        event = create_event("x", source="test", payload={"temp": 22.5, "unit": "C"})
        assert event.payload["temp"] == 22.5
        assert event.payload["unit"] == "C"
        assert len(event.payload) == 2
        assert set(event.payload.keys()) == {"temp", "unit"}

    def test_caller_dict_mutation_does_not_affect_payload(self):
        """Mutating the caller's original dict after create_event must
        not change the Event's payload (defensive copy)."""
        original = {"k": 1}
        event = create_event("x", source="test", payload=original)
        original["k"] = 999  # mutate the caller's dict
        assert event.payload["k"] == 1  # Event must be unaffected

    def test_non_utc_aware_timestamp_rejected(self):
        """An aware timestamp that is NOT UTC must be rejected."""
        non_utc = datetime(2024, 1, 1, 12, 0, tzinfo=timezone(timedelta(hours=5, minutes=30)))
        with pytest.raises(ValueError, match="UTC"):
            Event(
                event_id="x",
                event_type="system.started",
                timestamp=non_utc,
                source="test",
                payload={},
            )

    def test_utc_timestamp_accepted(self):
        """An explicitly UTC-aware timestamp must be accepted."""
        utc_ts = datetime(2024, 6, 1, 0, 0, tzinfo=timezone.utc)
        event = Event(
            event_id="x",
            event_type="system.started",
            timestamp=utc_ts,
            source="test",
            payload={},
        )
        assert event.timestamp == utc_ts


# ---------------------------------------------------------------------------
# Unique event IDs
# ---------------------------------------------------------------------------

class TestUniqueEventIds:
    def test_ids_are_unique(self):
        ids = {create_event("x", source="test").event_id for _ in range(1_000)}
        assert len(ids) == 1_000

    def test_id_is_nonempty_string(self):
        event = create_event("x", source="test")
        assert isinstance(event.event_id, str)
        assert len(event.event_id) > 0


# ---------------------------------------------------------------------------
# Subscription
# ---------------------------------------------------------------------------

class TestSubscription:
    def test_subscribe_and_receive(self):
        bus = EventBus()
        received: list[Event] = []

        async def handler(event: Event) -> None:
            received.append(event)

        bus.subscribe("system.started", handler)
        event = create_event("system.started", source="test")
        run(bus.publish(event))

        assert len(received) == 1
        assert received[0] is event

    def test_subscribe_non_async_raises(self):
        bus = EventBus()

        def sync_handler(event: Event) -> None:  # type: ignore[return]
            pass

        with pytest.raises(TypeError, match="async"):
            bus.subscribe("system.started", sync_handler)  # type: ignore[arg-type]

    def test_subscribe_non_callable_raises(self):
        bus = EventBus()
        with pytest.raises(TypeError):
            bus.subscribe("system.started", "not-a-function")  # type: ignore[arg-type]

    def test_subscriber_count(self):
        bus = EventBus()

        async def h1(e: Event) -> None: ...
        async def h2(e: Event) -> None: ...

        bus.subscribe("x", h1)
        bus.subscribe("x", h2)
        assert bus.subscriber_count("x") == 2

    def test_no_delivery_for_unrelated_type(self):
        bus = EventBus()
        received: list[Event] = []

        async def handler(event: Event) -> None:
            received.append(event)

        bus.subscribe("system.started", handler)
        run(bus.publish(create_event("system.stopped", source="test")))
        assert received == []


# ---------------------------------------------------------------------------
# Unsubscription
# ---------------------------------------------------------------------------

class TestUnsubscription:
    def test_unsubscribe_stops_delivery(self):
        bus = EventBus()
        received: list[Event] = []

        async def handler(event: Event) -> None:
            received.append(event)

        bus.subscribe("x", handler)
        bus.unsubscribe("x", handler)
        run(bus.publish(create_event("x", source="test")))
        assert received == []

    def test_unsubscribe_unknown_handler_raises(self):
        bus = EventBus()

        async def handler(event: Event) -> None: ...

        with pytest.raises(ValueError):
            bus.unsubscribe("x", handler)

    def test_unsubscribe_removes_only_one_registration(self):
        """When the same handler is registered twice, only the first copy
        is removed per unsubscribe call."""
        bus = EventBus()
        received: list[Event] = []

        async def handler(event: Event) -> None:
            received.append(event)

        bus.subscribe("x", handler)
        bus.subscribe("x", handler)
        bus.unsubscribe("x", handler)  # removes first registration

        run(bus.publish(create_event("x", source="test")))
        assert len(received) == 1  # second registration still active


# ---------------------------------------------------------------------------
# Multiple subscribers
# ---------------------------------------------------------------------------

class TestMultipleSubscribers:
    def test_all_subscribers_receive_event(self):
        bus = EventBus()
        log: list[str] = []

        async def h1(event: Event) -> None:
            log.append("h1")

        async def h2(event: Event) -> None:
            log.append("h2")

        async def h3(event: Event) -> None:
            log.append("h3")

        bus.subscribe("x", h1)
        bus.subscribe("x", h2)
        bus.subscribe("x", h3)

        run(bus.publish(create_event("x", source="test")))
        assert sorted(log) == ["h1", "h2", "h3"]


# ---------------------------------------------------------------------------
# Subscription order
# ---------------------------------------------------------------------------

class TestSubscriptionOrder:
    def test_handlers_called_in_subscription_order(self):
        bus = EventBus()
        order: list[int] = []

        async def h1(event: Event) -> None:
            order.append(1)

        async def h2(event: Event) -> None:
            order.append(2)

        async def h3(event: Event) -> None:
            order.append(3)

        bus.subscribe("x", h1)
        bus.subscribe("x", h2)
        bus.subscribe("x", h3)

        run(bus.publish(create_event("x", source="test")))
        assert order == [1, 2, 3]


# ---------------------------------------------------------------------------
# Handler failure isolation
# ---------------------------------------------------------------------------

class TestHandlerFailureIsolation:
    def test_failing_handler_does_not_prevent_others(self):
        bus = EventBus()
        called: list[str] = []

        async def good_before(event: Event) -> None:
            called.append("before")

        async def bad(event: Event) -> None:
            raise RuntimeError("boom")

        async def good_after(event: Event) -> None:
            called.append("after")

        bus.subscribe("x", good_before)
        bus.subscribe("x", bad)
        bus.subscribe("x", good_after)

        # Should not raise; the bad handler's exception is swallowed & logged.
        run(bus.publish(create_event("x", source="test")))

        assert called == ["before", "after"]

    def test_failing_handler_exception_is_logged(self, caplog):
        import logging

        bus = EventBus()

        async def bad(event: Event) -> None:
            raise ValueError("handler-error")

        bus.subscribe("x", bad)

        with caplog.at_level(logging.ERROR, logger="gideon.core.events.bus"):
            run(bus.publish(create_event("x", source="test")))

        assert any("handler-error" in record.message or
                   "handler-error" in str(record.exc_info)
                   for record in caplog.records)


# ---------------------------------------------------------------------------
# Publishing after shutdown
# ---------------------------------------------------------------------------

class TestShutdown:
    def test_publish_after_shutdown_raises(self):
        bus = EventBus()

        async def workflow() -> None:
            await bus.shutdown()
            await bus.publish(create_event("x", source="test"))

        with pytest.raises(EventBusShutdownError):
            run(workflow())

    def test_shutdown_is_idempotent(self):
        bus = EventBus()

        async def workflow() -> None:
            await bus.shutdown()
            await bus.shutdown()  # must not raise

        run(workflow())  # no exception expected
        assert bus.is_shut_down

    def test_shutdown_clears_subscribers(self):
        bus = EventBus()

        async def handler(event: Event) -> None: ...

        bus.subscribe("x", handler)

        async def workflow() -> None:
            await bus.shutdown()

        run(workflow())
        assert bus.subscriber_count("x") == 0
