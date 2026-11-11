"""Transactional outbox. Row id = hash(incident_key, channel, action, revision): inserting
the same delivery twice is a no-op, so replays and retries never duplicate tickets."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Index, Integer, String, Text
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class OutboxRow(Base):
    __tablename__ = "router_outbox"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    incident_key: Mapped[str] = mapped_column(String(128), index=True)
    tenant_id: Mapped[str] = mapped_column(String(64))
    ci_id: Mapped[str] = mapped_column(String(128))
    channel: Mapped[str] = mapped_column(String(32))
    action: Mapped[str] = mapped_column(String(16))
    revision: Mapped[int] = mapped_column(Integer, default=0)
    priority: Mapped[int] = mapped_column(Integer, default=3)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending|sent|failed
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    external_ref: Mapped[str | None] = mapped_column(String(128), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (Index("ix_outbox_due", "status", "next_attempt_at"),)


async def create_schema(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def insert_ignore(session: AsyncSession, rows: list[dict[str, Any]]) -> int:
    """INSERT ... ON CONFLICT DO NOTHING on Postgres and SQLite. Returns rows inserted."""
    if not rows:
        return 0
    dialect = session.bind.dialect.name if session.bind else "postgresql"
    ins = (postgresql.insert if dialect == "postgresql" else sqlite.insert)(OutboxRow)
    res = await session.execute(ins.values(rows).on_conflict_do_nothing(index_elements=["id"]))
    return int(getattr(res, "rowcount", 0) or 0)
