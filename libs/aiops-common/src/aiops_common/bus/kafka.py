"""Kafka bus on aiokafka: idempotent producer, manual commits, per-consumer DLQ.

Delivery guarantee: at-least-once. Offsets are committed only after every
message in a fetched batch was handled or dead-lettered, so a crash replays
the batch; downstream idempotency (deterministic incident_key + outbox)
turns that into effectively-once side effects.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer, TopicPartition
from pydantic import ValidationError

from aiops_common.bus.base import DeadLetter, Subscription
from aiops_common.bus.handling import handle_with_retries
from aiops_common.cloudevents import CloudEvent
from aiops_common.config import KafkaSettings
from aiops_common.contracts.registry import Topics

log = logging.getLogger("aiops.kafka")


def _common_kwargs(s: KafkaSettings) -> dict[str, Any]:
    kw: dict[str, Any] = {
        "bootstrap_servers": s.bootstrap_servers,
        "client_id": s.client_id,
        "security_protocol": s.security_protocol,
    }
    if s.sasl_mechanism:
        kw |= {
            "sasl_mechanism": s.sasl_mechanism,
            "sasl_plain_username": s.sasl_username,
            "sasl_plain_password": s.sasl_password.get_secret_value() if s.sasl_password else None,
        }
    return kw


class KafkaBus:
    def __init__(self, settings: KafkaSettings) -> None:
        self._s = settings
        self._producer: AIOKafkaProducer | None = None
        self._consumers: list[tuple[AIOKafkaConsumer, Subscription]] = []
        self._subs: list[Subscription] = []
        self._stopping = asyncio.Event()
        self._ready = False

    def subscribe(self, sub: Subscription) -> None:
        self._subs.append(sub)

    async def start(self) -> None:
        self._producer = AIOKafkaProducer(
            **_common_kwargs(self._s),
            acks="all",
            enable_idempotence=True,
            linger_ms=self._s.linger_ms,
            compression_type=self._s.compression_type,
        )
        await self._producer.start()
        for sub in self._subs:
            c = AIOKafkaConsumer(
                *sub.topics,
                **_common_kwargs(self._s),
                group_id=sub.group,
                enable_auto_commit=False,
                auto_offset_reset="earliest",
                max_poll_records=self._s.max_poll_records,
                isolation_level="read_committed",
            )
            await c.start()
            self._consumers.append((c, sub))
        self._ready = True

    def ready(self) -> bool:
        return self._ready and not self._stopping.is_set()

    async def publish(self, topic: str, event: CloudEvent) -> None:
        assert self._producer is not None, "bus not started"
        await self._producer.send_and_wait(
            topic, value=event.to_bytes(), key=event.partitionkey.encode()
        )

    async def _dead_letter(self, dl: DeadLetter) -> None:
        assert self._producer is not None
        await self._producer.send_and_wait(
            Topics.dlq(dl.original_topic),
            value=dl.event.to_bytes(),
            key=dl.event.partitionkey.encode(),
            headers=[(k, v.encode()) for k, v in dl.headers.items()],
        )

    async def _consume(self, consumer: AIOKafkaConsumer, sub: Subscription) -> None:
        while not self._stopping.is_set():
            batch = await consumer.getmany(timeout_ms=500)
            if not batch:
                continue
            offsets: dict[TopicPartition, int] = {}
            for tp, records in batch.items():
                for rec in records:
                    try:
                        ev = CloudEvent.from_bytes(rec.value)
                    except (ValidationError, ValueError) as e:
                        log.error("undecodable message", extra={"topic": tp.topic, "error": str(e)})
                        assert self._producer is not None
                        await self._producer.send_and_wait(
                            Topics.dlq(tp.topic),
                            value=rec.value,
                            key=rec.key,
                            headers=[("x-error", f"decode: {e}"[:500].encode())],
                        )
                    else:
                        dl = await handle_with_retries(sub, tp.topic, ev)
                        if dl is not None:
                            await self._dead_letter(dl)
                    offsets[tp] = rec.offset + 1
            await consumer.commit(offsets)

    async def run(self) -> None:
        await asyncio.gather(*(self._consume(c, s) for c, s in self._consumers))

    async def stop(self) -> None:
        """Graceful: stop fetching, let the in-flight batch finish and commit, then close."""
        self._stopping.set()
        await asyncio.sleep(0)
        for c, _ in self._consumers:
            await c.stop()
        if self._producer is not None:
            await self._producer.stop()
        self._ready = False
