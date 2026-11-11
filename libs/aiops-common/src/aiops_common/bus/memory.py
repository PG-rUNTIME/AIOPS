"""Deterministic in-memory bus for unit and end-to-end tests.

Semantics mirror the Kafka bus: per-(group, topic) cursors, at-least-once
delivery, retries then DLQ. ``run_until_idle`` pumps messages until no
subscriber has anything left to read.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict

from aiops_common.bus.base import DeadLetter, PermanentError, Subscription
from aiops_common.bus.handling import handle_with_retries
from aiops_common.cloudevents import CloudEvent
from aiops_common.contracts.registry import Topics


class InMemoryBus:
    def __init__(self, *, validate: bool = True) -> None:
        self.log: dict[str, list[CloudEvent]] = defaultdict(list)
        self.dead_letters: list[DeadLetter] = []
        self._subs: list[Subscription] = []
        self._cursors: dict[tuple[str, str], int] = defaultdict(int)
        self._stopping = asyncio.Event()
        self._validate = validate
        self._started = False

    async def start(self) -> None:
        self._started = True

    async def stop(self) -> None:
        self._stopping.set()

    def ready(self) -> bool:
        return self._started

    async def publish(self, topic: str, event: CloudEvent) -> None:
        if self._validate and not topic.endswith(".dlq"):
            from aiops_common.contracts.schemas import validate_event

            validate_event(event.model_dump(mode="json", exclude_none=True))
        self.log[topic].append(event)

    def subscribe(self, sub: Subscription) -> None:
        self._subs.append(sub)

    async def _deliver_once(self) -> int:
        delivered = 0
        for sub in self._subs:
            for topic in sub.topics:
                cur = (sub.group, topic)
                while self._cursors[cur] < len(self.log[topic]):
                    ev = self.log[topic][self._cursors[cur]]
                    dl = await handle_with_retries(sub, topic, ev, base_delay=0.0)
                    if dl is not None:
                        self.dead_letters.append(dl)
                        self.log[Topics.dlq(topic)].append(ev)
                    self._cursors[cur] += 1
                    delivered += 1
        return delivered

    async def run_until_idle(self, max_rounds: int = 1000) -> None:
        for _ in range(max_rounds):
            if await self._deliver_once() == 0:
                return
        raise RuntimeError("bus did not go idle")

    async def run(self) -> None:
        while not self._stopping.is_set():
            if await self._deliver_once() == 0:
                await asyncio.sleep(0.01)


__all__ = ["InMemoryBus", "PermanentError"]
