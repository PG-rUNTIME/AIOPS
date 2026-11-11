"""Entry point: ``correlator``."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

from aiops_common.bus import Subscription, make_bus
from aiops_common.config import ServiceSettings
from aiops_common.contracts.registry import Topics
from aiops_common.runner import Worker
from correlator.core import Correlator, CorrelatorConfig
from correlator.store import EpisodeStore, MemoryEpisodeStore, SqlEpisodeStore


class Settings(ServiceSettings):
    service_name: str = "correlator"
    consumer_group: str = "correlator"
    database_url: str | None = None  # postgresql+asyncpg://... ; memory if unset
    tick_seconds: float = 5.0
    grafana_url: str = "http://localhost:3000"
    settle_seconds: float = 20
    suppress_seconds: float = 1800


def main() -> None:
    s = Settings()
    bus = make_bus(s.kafka)
    store: EpisodeStore = MemoryEpisodeStore()
    startup: list[Callable[[], Awaitable[None]]] = []
    if s.database_url:
        from sqlalchemy.ext.asyncio import create_async_engine

        sql = SqlEpisodeStore(create_async_engine(s.database_url, pool_pre_ping=True))
        startup.append(sql.create_schema)
        store = sql
    corr = Correlator(
        bus,
        store,
        CorrelatorConfig(
            grafana_url=s.grafana_url,
            settle_seconds=s.settle_seconds,
            suppress_seconds=s.suppress_seconds,
        ),
    )
    bus.subscribe(Subscription([Topics.SIGNALS, Topics.CHANGES], s.consumer_group, corr.on_event))

    async def ticker(stop: asyncio.Event) -> None:
        while not stop.is_set():
            await corr.tick(datetime.now(UTC))
            await asyncio.sleep(s.tick_seconds)

    asyncio.run(Worker(s, bus, background=[ticker], on_startup=startup).serve())


if __name__ == "__main__":
    main()
