"""gideon.core.events.bus — Asynchronous in-process EventBus."""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from typing import Awaitable, Callable

from gideon.core.events.event import Event

logger = logging.getLogger(__name__)

# Type alias for an async handler callable.
AsyncHandler = Callable[[Event], Awaitable[None]]


class EventBusShutdownError(RuntimeError):
    """Raised when :meth:`EventBus.publish` is called after shutdown."""


class EventBus:
    """In-process, asynchronous publish-subscribe event bus.

    Usage
    -----
    .. code-block:: python

        bus = EventBus()

        async def on_started(event: Event) -> None:
            print("received:", event.event_type)

        bus.subscribe("system.started", on_started)

        event = create_event("system.started", source="core")
        await bus.publish(event)

        await bus.shutdown()

    Design notes
    ------------
    * Handlers are stored in insertion-order lists so dispatch order is
      deterministic (requirement 7).
    * Each handler is awaited sequentially.  A handler that raises an
      exception is logged and skipped; remaining handlers still run
      (requirement 6).
    * No background threads or tasks are created (requirement 9).
    * The bus itself has no I/O or network dependencies; it is purely
      in-process (requirement 8).
    """

    def __init__(self) -> None:
        # event_type → ordered list of handlers (preserves subscription order)
        self._subscribers: defaultdict[str, list[AsyncHandler]] = defaultdict(list)
        self._is_shut_down: bool = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def subscribe(self, event_type: str, handler: AsyncHandler) -> None:
        """Register *handler* to receive events of *event_type*.

        The same handler may be registered multiple times; each
        registration results in an additional call per published event.

        Parameters
        ----------
        event_type:
            The event type string to listen for.
        handler:
            An async callable that accepts a single :class:`Event` argument.
        """
        if not callable(handler):
            raise TypeError("handler must be callable")
        if not asyncio.iscoroutinefunction(handler):
            raise TypeError("handler must be an async (coroutine) function")
        self._subscribers[event_type].append(handler)
        logger.debug("subscribed %r to %r", handler, event_type)

    def unsubscribe(self, event_type: str, handler: AsyncHandler) -> None:
        """Remove the *first* registration of *handler* for *event_type*.

        If *handler* is not subscribed to *event_type*, a :class:`ValueError`
        is raised (mirrors ``list.remove`` semantics).

        Parameters
        ----------
        event_type:
            The event type the handler was registered under.
        handler:
            The handler to remove.
        """
        try:
            self._subscribers[event_type].remove(handler)
        except ValueError:
            raise ValueError(
                f"{handler!r} is not subscribed to event type {event_type!r}"
            ) from None
        logger.debug("unsubscribed %r from %r", handler, event_type)

    async def publish(self, event: Event) -> None:
        """Dispatch *event* to all handlers subscribed to its event type.

        Handlers are called in subscription order.  If a handler raises
        an exception it is caught, logged, and dispatch continues with
        the next handler.

        Parameters
        ----------
        event:
            The :class:`Event` to publish.

        Raises
        ------
        EventBusShutdownError
            If :meth:`shutdown` has already been called.
        """
        if self._is_shut_down:
            raise EventBusShutdownError(
                "EventBus has been shut down; cannot publish new events."
            )

        # Take a snapshot so that mutations during dispatch don't affect
        # the current delivery.
        handlers = list(self._subscribers.get(event.event_type, []))

        for handler in handlers:
            try:
                await handler(event)
            except Exception:  # noqa: BLE001
                logger.exception(
                    "Handler %r raised an exception for event %r (id=%s); "
                    "continuing dispatch.",
                    handler,
                    event.event_type,
                    event.event_id,
                )

    async def shutdown(self) -> None:
        """Shut down the bus.

        After this call, :meth:`publish` will raise
        :class:`EventBusShutdownError`.  Calling ``shutdown`` on an
        already-shut-down bus is a no-op.
        """
        if self._is_shut_down:
            return
        self._is_shut_down = True
        self._subscribers.clear()
        logger.info("EventBus shut down.")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @property
    def is_shut_down(self) -> bool:
        """``True`` after :meth:`shutdown` has been called."""
        return self._is_shut_down

    def subscriber_count(self, event_type: str) -> int:
        """Return the number of handlers registered for *event_type*."""
        return len(self._subscribers.get(event_type, []))
