"""
CyberDefense EventBus
=====================
Lightweight in-process async pub-sub bus for decoupled internal event broadcasting.
"""

import asyncio
from collections import defaultdict
import logging
from typing import Any, Callable, Coroutine

logger = logging.getLogger("cyberdefense.event_bus")


class EventBus:
    """Lightweight in-process async pub-sub bus."""

    def __init__(self):
        self._subscribers: dict[str, list[Callable[[Any], Coroutine[Any, Any, None]]]] = defaultdict(list)

    def subscribe(self, topic: str, callback: Callable[[Any], Coroutine[Any, Any, None]]) -> None:
        """Register an async callback for a specific topic."""
        self._subscribers[topic].append(callback)
        logger.debug(f"Subscribed to topic '{topic}' (total: {len(self._subscribers[topic])})")

    def unsubscribe(self, topic: str, callback: Callable[[Any], Coroutine[Any, Any, None]]) -> None:
        """Remove a callback from a topic."""
        if topic in self._subscribers and callback in self._subscribers[topic]:
            self._subscribers[topic].remove(callback)

    async def publish(self, topic: str, data: Any) -> None:
        """Publish an event to all topic subscribers concurrently."""
        callbacks = self._subscribers.get(topic, [])
        if not callbacks:
            return

        tasks = [asyncio.create_task(self._safe_execute(cb, data)) for cb in callbacks]
        await asyncio.gather(*tasks, return_exceptions=True)

    @staticmethod
    async def _safe_execute(callback: Callable[[Any], Coroutine[Any, Any, None]], data: Any) -> None:
        try:
            await callback(data)
        except Exception as e:
            logger.error(f"Error executing event bus callback: {e}", exc_info=True)


# Global singleton instance
bus = EventBus()
