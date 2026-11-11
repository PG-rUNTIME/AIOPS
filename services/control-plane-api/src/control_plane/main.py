"""Entry point: ``control-plane-api``."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
from pathlib import Path

import httpx
import uvicorn
from pydantic import SecretStr
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

from aiops_common.config import ServiceSettings
from aiops_common.logging import setup_logging
from control_plane import passwords
from control_plane.app import create_app
from control_plane.auth import Authenticator, AuthSettings
from control_plane.db import Base, User
from control_plane.poller import Poller
from control_plane.remediation import (
    AnsibleRunnerExecutor,
    DryRunExecutor,
    Executor,
    allowed_playbooks,
)
from control_plane.secretbox import SecretBox


class Settings(ServiceSettings):
    service_name: str = "control-plane-api"
    database_url: str = "sqlite+aiosqlite:///./control-plane.db"
    auth: AuthSettings = AuthSettings()
    playbooks_dir: str = "/app/config/remediation/playbooks"
    executor: str = "dry_run"  # dry_run | ansible
    create_schema: bool = False  # prod runs `alembic upgrade head`; dev opts in
    feedback_url: str | None = "http://feedback-service:8080"
    # the platform's own metric store, for the incident chart (sources are read via connections)
    vm_url: str | None = "http://victoriametrics:8428"
    console_dir: str = "/app/console"
    brand_dir: str = "/app/brand"
    # OIDC for the console (authorization code + PKCE); empty = paste a token (dev)
    console_oidc_issuer: str | None = None
    console_oidc_client_id: str | None = None
    ansible_private_data_dir: str = "/runner"
    # Fernet key for encrypting data-source credentials: `python -m control_plane.secretbox`
    secrets_key: SecretStr | None = None
    # shared secret the agent presents to read data through registered connections
    internal_token: SecretStr | None = None
    # pull host metrics from sources with "feed failure detection" on, into the ingest-gateway
    poller_enabled: bool = False
    poller_interval_seconds: float = 60.0
    ingest_url: str = "http://ingest-gateway:8080"
    poller_ingest_keys: SecretStr | None = None  # JSON {"tenant": "<plaintext ingest key>"}
    # local auth: seeds the first platform admin when the users table is empty
    bootstrap_admin_username: str | None = None
    bootstrap_admin_password: SecretStr | None = None


async def bootstrap_admin(
    engine: AsyncEngine, username: str | None, password: SecretStr | None
) -> None:
    """Create the first platform admin if (and only if) there are no users yet."""
    log = logging.getLogger("control-plane")
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with sessions.begin() as s:
        if (await s.execute(select(func.count()).select_from(User))).scalar_one():
            return
        if not username or password is None:
            log.warning(
                "no users exist: set AIOPS_BOOTSTRAP_ADMIN_USERNAME and "
                "AIOPS_BOOTSTRAP_ADMIN_PASSWORD to create the first admin"
            )
            return
        name = username.strip().lower()
        problem = passwords.check_policy(password.get_secret_value(), name)
        if problem:
            raise RuntimeError(f"bootstrap admin password rejected: {problem}")
        t = datetime.now(UTC)
        s.add(
            User(
                username=name,
                password_hash=passwords.hash_password(password.get_secret_value()),
                role="admin",
                tenants=["*"],
                display_name="Administrator",
                disabled=False,
                failed_attempts=0,
                created_at=t,
                password_changed_at=t,
            )
        )
    log.info("created first platform admin", extra={"username": name})


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
    if s.auth.mode == "local":

        async def seed() -> None:
            try:
                await bootstrap_admin(
                    engine, s.bootstrap_admin_username, s.bootstrap_admin_password
                )
            finally:  # the pool must not outlive this temporary event loop
                await engine.dispose()

        asyncio.run(seed())
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
    box = SecretBox(s.secrets_key.get_secret_value()) if s.secrets_key else None
    poller = (
        Poller(
            async_sessionmaker(engine, expire_on_commit=False),
            box,
            s.ingest_url,
            json.loads(s.poller_ingest_keys.get_secret_value()) if s.poller_ingest_keys else {},
            s.poller_interval_seconds,
        )
        if s.poller_enabled
        else None
    )
    app = create_app(
        engine,
        Authenticator(s.auth, s.environment),
        ex,
        allowed_playbooks(s.playbooks_dir),
        feedback=httpx.AsyncClient(base_url=s.feedback_url, timeout=10) if s.feedback_url else None,
        secrets=box,
        internal_token=s.internal_token.get_secret_value() if s.internal_token else None,
        poller=poller,
        vm=httpx.AsyncClient(base_url=s.vm_url, timeout=10) if s.vm_url else None,
        console_dir=Path(s.console_dir),
        brand_dir=Path(s.brand_dir),
        console_config={
            "environment": s.environment,
            "version": s.service_version,
            "oidc": oidc,
            "auth": "oidc" if oidc else s.auth.mode,
        },
    )
    uvicorn.run(app, host=s.http_host, port=s.http_port, log_config=None)


if __name__ == "__main__":
    main()
