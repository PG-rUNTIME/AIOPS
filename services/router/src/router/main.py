"""Entry point: ``router`` (consumer + outbox dispatcher in one process)."""

from __future__ import annotations

import asyncio

import httpx
from sqlalchemy.ext.asyncio import create_async_engine

from aiops_common.bus import Subscription, make_bus
from aiops_common.config import ServiceSettings
from aiops_common.contracts.registry import Topics
from aiops_common.runner import Worker
from router.channels import AdapterRegistry, load_channels
from router.db import create_schema
from router.rules import load_rules
from router.service import Dispatcher, Router


class Settings(ServiceSettings):
    service_name: str = "router"
    consumer_group: str = "router"
    database_url: str = "sqlite+aiosqlite:///./router.db"
    channels_file: str | None = "/app/config/router/channels.yaml"
    rules_file: str | None = "/app/config/router/rules.yaml"
    mirror_to_keep: bool = False
    dispatch_interval_seconds: float = 1.0
    create_schema: bool = True


def main() -> None:
    s = Settings()
    engine = create_async_engine(s.database_url, pool_pre_ping=True)
    bus = make_bus(s.kafka)
    router = Router(engine, load_rules(s.rules_file), s.mirror_to_keep)
    disp = Dispatcher(
        engine, AdapterRegistry(load_channels(s.channels_file), httpx.AsyncClient(timeout=10)), bus
    )
    bus.subscribe(Subscription([Topics.VERDICTS], s.consumer_group, router.on_event))

    async def dispatch(stop: asyncio.Event) -> None:
        while not stop.is_set():
            await disp.run_once()
            await asyncio.sleep(s.dispatch_interval_seconds)

    async def startup() -> None:
        if s.create_schema:  # dev convenience; prod runs `alembic upgrade head` as an init job
            await create_schema(engine)

    asyncio.run(
        Worker(
            s, bus, background=[dispatch], on_startup=[startup], on_shutdown=[engine.dispose]
        ).serve()
    )


if __name__ == "__main__":
    main()
