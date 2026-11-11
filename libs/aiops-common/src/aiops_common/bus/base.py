"""Event bus abstraction. Kafka in every real deployment, in-memory for unit/e2e tests."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import Protocol

from aiops_common.cloudevents import CloudEvent

Handler = Callable[[CloudEvent], Awaitable[None]]


class PermanentError(Exception):
    """Raised by a handler for poison messages: skip retries, go straight to the DLQ."""


@dataclass
class Subscription:
    topics: Sequence[str]
    group: str
    handler: Handler
    max_retries: int = 3


@dataclass
class DeadLetter:
    original_topic: str
    event: CloudEvent
    error: str
    attempts: int
    headers: dict[str, str] = field(default_factory=dict)


class EventBus(Protocol):
    async def start(self) -> None: ...

    async def stop(self) -> None: ...

    async def publish(self, topic: str, event: CloudEvent) -> None: ...

    def subscribe(self, sub: Subscription) -> None: ...

    async def run(self) -> None:
        """Consume until ``stop()``; commits offsets only after handler success or DLQ."""
        ...

    def ready(self) -> bool: ...
