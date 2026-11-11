"""Entry point: ``control-plane-api``."""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
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
    create_schema: bool = False  # prod runs `alembic upgrade head`; dev opts in
    feedback_url: str | None = "http://feedback-service:8080"
    console_dir: str = "/app/console"
    brand_dir: str = "/app/brand"
    # OIDC for the console (authorization code + PKCE); empty = paste a token (dev)
    console_oidc_issuer: str | None = None
    console_oidc_client_id: str | None = None
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
    oidc = (
        {"issuer": s.console_oidc_issuer, "client_id": s.console_oidc_client_id}
        if s.console_oidc_issuer and s.console_oidc_client_id
        else None
    )
    app = create_app(
        engine,
        Authenticator(s.auth, s.environment),
        ex,
        allowed_playbooks(s.playbooks_dir),
        feedback=httpx.AsyncClient(base_url=s.feedback_url, timeout=10) if s.feedback_url else None,
        console_dir=Path(s.console_dir),
        brand_dir=Path(s.brand_dir),
        console_config={"environment": s.environment, "oidc": oidc},
    )
    uvicorn.run(app, host=s.http_host, port=s.http_port, log_config=None)


if __name__ == "__main__":
    main()
