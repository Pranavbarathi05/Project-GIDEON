"""gideon.core.events — Public API for the GIDEON in-process event bus."""

from gideon.core.events.bus import AsyncHandler, EventBus, EventBusShutdownError
from gideon.core.events.event import Event, create_event

__all__ = [
    # Core types
    "Event",
    "EventBus",
    # Factory
    "create_event",
    # Exceptions
    "EventBusShutdownError",
    # Type alias (useful for type annotations by callers)
    "AsyncHandler",
]
