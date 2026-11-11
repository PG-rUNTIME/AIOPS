"""Entry point: ``control-plane-api``."""

from __future__ import annotations

import asyncio

import uvicorn
from sqlalchemy.ext.asyncio import create_async_engine

from aiops_common.config import ServiceSettings
from aiops_common.logging import setup_logging
from control_plane.app import create_app
from control_plane.auth import Authenticator, AuthSettings
from control_plane.db import Base
from control_plane.remediation import (
    AnsibleRunnerExecutor,
    DryRunExecutor,
    Executor,
    allowed_playbooks,
)


class Settings(ServiceSettings):
    service_name: str = "control-plane-api"
    database_url: str = "sqlite+aiosqlite:///./control-plane.db"
    auth: AuthSettings = AuthSettings()
    playbooks_dir: str = "/app/config/remediation/playbooks"
    executor: str = "dry_run"  # dry_run | ansible
    create_schema: bool = True  # dev; prod runs `alembic upgrade head`
    ansible_private_data_dir: str = "/runner"


def main() -> None:
    s = Settings()
    setup_logging(s.service_name, s.log_level)
    engine = create_async_engine(s.database_url, pool_pre_ping=True)
    if s.create_schema:

        async def init() -> None:
            async with engine.begin() as c:
                await c.run_sync(Base.metadata.create_all)
            await engine.dispose()

        asyncio.run(init())
    ex: Executor = (
        DryRunExecutor()
        if s.executor == "dry_run"
        else AnsibleRunnerExecutor(s.ansible_private_data_dir)
    )
    app = create_app(
        engine, Authenticator(s.auth, s.environment), ex, allowed_playbooks(s.playbooks_dir)
    )
    uvicorn.run(app, host=s.http_host, port=s.http_port, log_config=None)


if __name__ == "__main__":
    main()
