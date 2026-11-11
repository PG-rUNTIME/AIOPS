"""Entry point: ``feedback-service`` (HTTP API + verdict consumer)."""

from __future__ import annotations

import asyncio
import json

from pydantic import SecretStr
from sqlalchemy.ext.asyncio import create_async_engine

from aiops_common.bus import Subscription, make_bus
from aiops_common.config import ServiceSettings
from aiops_common.contracts.registry import Topics
from aiops_common.runner import Worker
from feedback_service.app import FeedbackService, create_app


class Settings(ServiceSettings):
    service_name: str = "feedback-service"
    consumer_group: str = "feedback-service"
    database_url: str = "sqlite+aiosqlite:///./feedback.db"
    webhook_secrets: SecretStr = SecretStr("{}")  # JSON {"tenant": "secret"} injected from Vault


def main() -> None:
    s = Settings()
    engine = create_async_engine(s.database_url, pool_pre_ping=True)
    bus = make_bus(s.kafka)
    svc = FeedbackService(engine, bus, json.loads(s.webhook_secrets.get_secret_value()))
    bus.subscribe(Subscription([Topics.VERDICTS], s.consumer_group, svc.on_event))
    w = Worker(
        s, bus, on_startup=[svc.create_schema, svc.refresh_metrics], on_shutdown=[engine.dispose]
    )
    w.app = create_app(svc, w.ready)
    asyncio.run(w.serve())


if __name__ == "__main__":
    main()
