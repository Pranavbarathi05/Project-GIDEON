"""gideon.core.events.event — Immutable Event dataclass and factory."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import Any, Mapping


@dataclass(frozen=True)
class Event:
    """An immutable event that travels through the GIDEON event bus.

    Attributes
    ----------
    event_id:   Globally-unique identifier (UUID4 string).
    event_type: Dot-namespaced string that identifies the kind of event,
                e.g. ``"system.started"`` or ``"sensor.motion.detected"``.
    timestamp:  UTC datetime at which the event was created.
                Must be timezone-aware *and* in UTC (offset == 0).
    source:     Logical name of the component that emitted the event.
    payload:    Arbitrary key/value data carried by the event, exposed as
                a read-only :class:`~types.MappingProxyType` so that
                callers cannot mutate it through the Event instance.
                Values must be JSON-serialisable by convention.
    """

    event_id: str
    event_type: str
    timestamp: datetime
    source: str
    # Public type is the read-only view; the raw dict is never exposed.
    payload: Mapping[str, Any]

    def __post_init__(self) -> None:
        # --- event_type ---
        if not self.event_type:
            raise ValueError("event_type must not be empty")

        # --- source ---
        if not self.source:
            raise ValueError("source must not be empty")

        # --- timestamp: must be UTC (timezone-aware with zero offset) ---
        if self.timestamp.tzinfo is None:
            raise ValueError(
                "timestamp must be timezone-aware and in UTC, "
                "but got a naive datetime"
            )
        offset = self.timestamp.utcoffset()
        if offset != timedelta(0):
            raise ValueError(
                f"timestamp must be in UTC (offset == 0), "
                f"but got offset {offset!r}"
            )

        # --- payload: accept a plain dict and freeze it immediately ---
        if not isinstance(self.payload, dict):
            raise TypeError(
                "payload must be a plain dict; "
                f"got {type(self.payload).__name__!r}"
            )
        # Bypass the frozen-field guard to swap the raw dict for its
        # read-only proxy.  This is the standard pattern for frozen
        # dataclasses that need to normalise a field in __post_init__.
        object.__setattr__(self, "payload", MappingProxyType(self.payload))


def create_event(
    event_type: str,
    source: str,
    payload: dict[str, Any] | None = None,
) -> Event:
    """Factory that builds a fully-populated :class:`Event`.

    Callers only need to supply *event_type*, *source*, and an optional
    *payload*.  ``event_id`` and ``timestamp`` are generated automatically.

    Parameters
    ----------
    event_type:
        Dot-namespaced event identifier, e.g. ``"system.started"``.
    source:
        Logical name of the emitting component.
    payload:
        Optional dictionary of event data.  Defaults to ``{}``.
        The dict is copied before being frozen so that mutations to the
        caller's original dict after this call do not affect the Event.

    Returns
    -------
    Event
        A frozen :class:`Event` instance ready for publication.
    """
    return Event(
        event_id=str(uuid.uuid4()),
        event_type=event_type,
        timestamp=datetime.now(tz=timezone.utc),
        source=source,
        # Copy so that the caller retaining a reference to the original dict
        # cannot indirectly mutate the payload after construction.
        payload=dict(payload) if payload is not None else {},
    )
