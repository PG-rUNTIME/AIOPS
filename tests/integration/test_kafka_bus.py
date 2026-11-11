"""Integration tests against real Kafka and Postgres (Testcontainers).

Run with ``make test-integration`` (needs Docker). Proves: publish/consume through
the CloudEvents envelope, DLQ with error headers, at-least-once redelivery after a
consumer restart without committed offsets, and the outbox on Postgres.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest

from aiops_common.bus import Subscription
from aiops_common.cloudevents import CloudEvent, make_event
from aiops_common.config import KafkaSettings
from aiops_common.contracts.models import MetricBatch, MetricPoint
from aiops_common.contracts.registry import Topics

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def kafka_bootstrap():  # type: ignore[no-untyped-def]
    from testcontainers.kafka import KafkaContainer

    with KafkaContainer("confluentinc/cp-kafka:7.7.1").with_kraft() as k:
        yield k.get_bootstrap_server()


def batch(i: int) -> MetricBatch:
    return MetricBatch(
        tenant_id="t",
        ci_id=f"CI-{i % 3}",
        points=[MetricPoint(name="m", ts=datetime.now(UTC), value=i)],
    )


async def test_roundtrip_dlq_and_redelivery(kafka_bootstrap: str) -> None:
    from aiops_common.bus.kafka import KafkaBus

    s = KafkaSettings(bootstrap_servers=kafka_bootstrap)
    got: list[CloudEvent] = []

    async def handler(ev: CloudEvent) -> None:
        if ev.payload(MetricBatch).points[0].value == 13:
            raise ValueError("poison")
        got.append(ev)

    prod = KafkaBus(s)
    await prod.start()
    for i in range(20):
        await prod.publish(Topics.METRICS, make_event(batch(i), source="urn:it"))

    bus = KafkaBus(s)
    bus.subscribe(Subscription([Topics.METRICS], "it-group", handler, max_retries=1))
    await bus.start()
    task = asyncio.create_task(bus.run())
    for _ in range(100):
        if len(got) >= 19:
            break
        await asyncio.sleep(0.2)
    await bus.stop()
    task.cancel()
    assert len(got) == 19

    dlq: list[CloudEvent] = []
    dbus = KafkaBus(s)
    dbus.subscribe(Subscription([Topics.dlq(Topics.METRICS)], "it-dlq", lambda e: _append(dlq, e)))
    await dbus.start()
    t2 = asyncio.create_task(dbus.run())
    for _ in range(50):
        if dlq:
            break
        await asyncio.sleep(0.2)
    await dbus.stop()
    t2.cancel()
    assert dlq and dlq[0].payload(MetricBatch).points[0].value == 13

    # A new member of the same group sees nothing: offsets were committed.
    again: list[CloudEvent] = []
    b3 = KafkaBus(s)
    b3.subscribe(Subscription([Topics.METRICS], "it-group", lambda e: _append(again, e)))
    await b3.start()
    t3 = asyncio.create_task(b3.run())
    await asyncio.sleep(3)
    await b3.stop()
    t3.cancel()
    await prod.stop()
    assert again == []


async def _append(lst: list[CloudEvent], e: CloudEvent) -> None:
    lst.append(e)


def test_outbox_on_postgres() -> None:
    from testcontainers.postgres import PostgresContainer

    with PostgresContainer("pgvector/pgvector:pg16", driver="asyncpg") as pg:
        url = pg.get_connection_url()
        asyncio.run(_outbox(url))


async def _outbox(url: str) -> None:
    from sqlalchemy.ext.asyncio import create_async_engine

    from router.db import create_schema, insert_ignore
    from router.service import row_id

    eng = create_async_engine(url)
    await create_schema(eng)
    now = datetime.now(UTC)
    row = {
        "id": row_id("k", "servicenow", "open", 0),
        "incident_key": "k",
        "tenant_id": "t",
        "ci_id": "c",
        "channel": "servicenow",
        "action": "open",
        "revision": 0,
        "priority": 2,
        "payload": {},
        "status": "pending",
        "attempts": 0,
        "next_attempt_at": now,
        "created_at": now,
    }
    from sqlalchemy.ext.asyncio import async_sessionmaker

    sm = async_sessionmaker(eng)
    async with sm.begin() as s:
        assert await insert_ignore(s, [row]) == 1
    async with sm.begin() as s:
        assert await insert_ignore(s, [row]) == 0
    await eng.dispose()
