"""Alembic environment: run as a Kubernetes Job / init container before rollout."""

from __future__ import annotations

import os

from alembic import context
from sqlalchemy import create_engine

TARGET = "control_plane"


def _url() -> str:
    url = os.environ["AIOPS_DATABASE_URL"]
    return url.replace("+asyncpg", "+psycopg").replace("+aiosqlite", "")


def run() -> None:
    engine = create_engine(_url())
    with engine.connect() as conn:
        context.configure(connection=conn, target_metadata=None, transaction_per_migration=True)
        with context.begin_transaction():
            context.run_migrations()


run()
