"""Episode state behind a store, so correlator replicas stay stateless.

``MemoryEpisodeStore`` for tests/dev; ``SqlEpisodeStore`` (Postgres in prod)
survives restarts and consumer-group rebalances, which is what keeps
suppression — and therefore "no duplicate tickets" — correct across failover.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Protocol

from pydantic import BaseModel, Field
from sqlalchemy import DateTime, String, Text, delete, select
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from aiops_common.contracts.models import Signal


class Episode(BaseModel):
    tenant_id: str
    ci_id: str
    service: str
    incident_key: str
    signals: list[Signal] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    emitted_at: datetime | None = None
    resolved_at: datetime | None = None
    suppressed: int = 0
    emitted_eta: bool = False
    updates: int = 0


class EpisodeStore(Protocol):
    async def get(self, tenant_id: str, ci_id: str) -> Episode | None: ...
    async def put(self, ep: Episode) -> None: ...
    async def delete(self, tenant_id: str, ci_id: str) -> None: ...
    async def all(self) -> list[Episode]: ...


class MemoryEpisodeStore:
    def __init__(self) -> None:
        self._d: dict[tuple[str, str], Episode] = {}

    async def get(self, tenant_id: str, ci_id: str) -> Episode | None:
        ep = self._d.get((tenant_id, ci_id))
        return ep.model_copy(deep=True) if ep else None

    async def put(self, ep: Episode) -> None:
        self._d[(ep.tenant_id, ep.ci_id)] = ep.model_copy(deep=True)

    async def delete(self, tenant_id: str, ci_id: str) -> None:
        self._d.pop((tenant_id, ci_id), None)

    async def all(self) -> list[Episode]:
        return [e.model_copy(deep=True) for e in self._d.values()]


class _Base(DeclarativeBase):
    pass


class EpisodeRow(_Base):
    __tablename__ = "correlator_episodes"
    tenant_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    ci_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    incident_key: Mapped[str] = mapped_column(String(128))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    doc: Mapped[str] = mapped_column(Text)


class SqlEpisodeStore:
    """Upsert-by-primary-key store. Rows are keyed by the Kafka partition key."""

    def __init__(self, engine: AsyncEngine) -> None:
        self.engine = engine
        self.sessions = async_sessionmaker(engine, expire_on_commit=False)

    async def create_schema(self) -> None:
        async with self.engine.begin() as conn:
            await conn.run_sync(_Base.metadata.create_all)

    async def get(self, tenant_id: str, ci_id: str) -> Episode | None:
        async with self.sessions() as s:
            row = await s.get(EpisodeRow, (tenant_id, ci_id))
            return Episode.model_validate(json.loads(row.doc)) if row else None

    async def put(self, ep: Episode) -> None:
        async with self.sessions.begin() as s:
            await s.merge(
                EpisodeRow(
                    tenant_id=ep.tenant_id,
                    ci_id=ep.ci_id,
                    incident_key=ep.incident_key,
                    last_seen=ep.last_seen,
                    doc=ep.model_dump_json(),
                )
            )

    async def delete(self, tenant_id: str, ci_id: str) -> None:
        async with self.sessions.begin() as s:
            await s.execute(
                delete(EpisodeRow).where(
                    EpisodeRow.tenant_id == tenant_id, EpisodeRow.ci_id == ci_id
                )
            )

    async def all(self) -> list[Episode]:
        async with self.sessions() as s:
            rows = (await s.execute(select(EpisodeRow))).scalars().all()
            return [Episode.model_validate(json.loads(r.doc)) for r in rows]
