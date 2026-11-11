"""Process lifecycle for worker services: bus + ops HTTP server + graceful SIGTERM.

On SIGTERM/SIGINT: readiness flips to 503, consumers stop fetching, the
in-flight batch finishes and offsets are committed, then the process exits.
Everything must complete inside ``shutdown_grace_seconds`` (< 30 s).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
from collections.abc import Awaitable, Callable, Coroutine
from dataclasses import dataclass, field
from typing import Any

import uvicorn
from fastapi import FastAPI

from aiops_common.bus import EventBus
from aiops_common.config import ServiceSettings
from aiops_common.http import ops_app
from aiops_common.logging import setup_logging
from aiops_common.telemetry import setup_tracing

log = logging.getLogger("aiops.runner")


@dataclass
class Worker:
    settings: ServiceSettings
    bus: EventBus
    app: FastAPI | None = None
    background: list[Callable[[asyncio.Event], Coroutine[Any, Any, None]]] = field(
        default_factory=list
    )
    on_shutdown: list[Callable[[], Awaitable[None]]] = field(default_factory=list)
    on_startup: list[Callable[[], Awaitable[None]]] = field(default_factory=list)
    _stop: asyncio.Event = field(default_factory=asyncio.Event)

    def ready(self) -> bool:
        return not self._stop.is_set() and self.bus.ready()

    async def serve(self) -> None:
        s = self.settings
        setup_logging(s.service_name, s.log_level)
        setup_tracing(s.service_name, s.service_version, s.otel_exporter_otlp_endpoint)
        app = self.app or ops_app(self.ready, s.service_name)
        server = uvicorn.Server(
            uvicorn.Config(app, host=s.http_host, port=s.http_port, log_config=None, lifespan="on")
        )
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, self._stop.set)

        for cb in self.on_startup:
            await cb()
        await self.bus.start()
        log.info("service started", extra={"port": s.http_port})
        tasks = [
            asyncio.create_task(self.bus.run(), name="bus"),
            asyncio.create_task(server.serve(), name="http"),
            *(
                asyncio.create_task(bg(self._stop), name=f"bg{i}")
                for i, bg in enumerate(self.background)
            ),
        ]
        stop_wait = asyncio.create_task(self._stop.wait())
        done, _ = await asyncio.wait([stop_wait, *tasks], return_when=asyncio.FIRST_COMPLETED)
        for t in done:
            if t is not stop_wait and t.exception():
                log.error("task crashed", extra={"task": t.get_name()}, exc_info=t.exception())
        self._stop.set()
        log.info("shutting down")
        try:
            async with asyncio.timeout(s.shutdown_grace_seconds):
                await self.bus.stop()
                for cb in self.on_shutdown:
                    await cb()
        except TimeoutError:
            log.error("graceful shutdown timed out")
        server.should_exit = True  # let uvicorn finish its lifespan instead of cancelling it
        http_task = tasks[1]
        with contextlib.suppress(TimeoutError, Exception):
            async with asyncio.timeout(5):
                await http_task
        for t in tasks:
            if not t.done():
                t.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await t
        log.info("stopped")
