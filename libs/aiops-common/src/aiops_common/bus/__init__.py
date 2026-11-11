"""Event bus: Kafka (prod) and in-memory (tests) behind one protocol."""

from __future__ import annotations

from aiops_common.bus.base import EventBus, Handler, PermanentError, Subscription
from aiops_common.bus.memory import InMemoryBus
from aiops_common.config import KafkaSettings


def make_bus(settings: KafkaSettings) -> EventBus:
    if settings.backend == "memory":
        return InMemoryBus()
    from aiops_common.bus.kafka import KafkaBus

    return KafkaBus(settings)


__all__ = ["EventBus", "Handler", "InMemoryBus", "PermanentError", "Subscription", "make_bus"]
