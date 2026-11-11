"""Control-plane schema. Every tenant-owned table carries ``tenant_id`` and, on
Postgres, a row-level-security policy keyed on ``current_setting('app.tenant_id')``
(see alembic/versions/0001_initial.py)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "cp_tenants"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class User(Base):
    """Local console account (``local`` auth mode). Not tenant-scoped: ``tenants`` is the
    list of tenant ids the user may access, or ``["*"]`` for a platform user."""

    __tablename__ = "cp_users"
    username: Mapped[str] = mapped_column(String(64), primary_key=True)
    password_hash: Mapped[str] = mapped_column(String(300))
    role: Mapped[str] = mapped_column(String(16))  # viewer|operator|approver|admin
    tenants: Mapped[list[str]] = mapped_column(JSON, default=list)
    display_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    password_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ConfigItem(Base):
    __tablename__ = "cp_cis"
    tenant_id: Mapped[str] = mapped_column(ForeignKey("cp_tenants.id"), primary_key=True)
    ci_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    service: Mapped[str] = mapped_column(String(128))
    owner_team: Mapped[str | None] = mapped_column(String(128), nullable=True)
    sn_sys_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class Connection(Base):
    """A data source (logs, metrics, traces, dashboards) this tenant's incidents are built from."""

    __tablename__ = "cp_connections"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("cp_tenants.id"), index=True)
    name: Mapped[str] = mapped_column(String(100))
    kind: Mapped[str] = mapped_column(String(32))
    url: Mapped[str] = mapped_column(String(500))
    auth_type: Mapped[str] = mapped_column(String(16), default="none")
    username: Mapped[str | None] = mapped_column(String(200), nullable=True)
    header_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    secret_enc: Mapped[str | None] = mapped_column(Text, nullable=True)  # Fernet token
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    extra: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    last_test_ok: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    last_test_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_test_message: Mapped[str | None] = mapped_column(String(300), nullable=True)
    created_by: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class IncidentActivity(Base):
    """Human workflow on an incident: acknowledge, assign, notes, resolve. Append-only."""

    __tablename__ = "cp_incident_activity"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("cp_tenants.id"), index=True)
    incident_key: Mapped[str] = mapped_column(String(128), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    actor: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(16))  # ack|assign|note|resolve|reopen
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class RoutingRules(Base):
    __tablename__ = "cp_routing_rules"
    tenant_id: Mapped[str] = mapped_column(ForeignKey("cp_tenants.id"), primary_key=True)
    rules: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    updated_by: Mapped[str] = mapped_column(String(200))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Runbook(Base):
    __tablename__ = "cp_runbooks"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), default="*")  # "*" = global
    title: Mapped[str] = mapped_column(String(200))
    failure_types: Mapped[list[str]] = mapped_column(JSON)
    url: Mapped[str | None] = mapped_column(String(500), nullable=True)


class Threshold(Base):
    __tablename__ = "cp_thresholds"
    tenant_id: Mapped[str] = mapped_column(ForeignKey("cp_tenants.id"), primary_key=True)
    failure_type: Mapped[str] = mapped_column(String(64), primary_key=True)
    threshold: Mapped[float] = mapped_column(Float)
    forecast_quantile: Mapped[str] = mapped_column(String(8), default="p90")
    horizon_minutes: Mapped[float] = mapped_column(Float, default=15)
    min_confidence: Mapped[float] = mapped_column(Float, default=0.5)


class ThresholdProposal(Base):
    __tablename__ = "cp_threshold_proposals"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    failure_type: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(16), default="open")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ModelConfig(Base):
    __tablename__ = "cp_model_configs"
    tenant_id: Mapped[str] = mapped_column(ForeignKey("cp_tenants.id"), primary_key=True)
    provider: Mapped[str] = mapped_column(String(32))
    model: Mapped[str] = mapped_column(String(128))
    base_url: Mapped[str] = mapped_column(String(500))
    tokens_per_day: Mapped[int] = mapped_column(Integer, default=500_000)
    max_inflight: Mapped[int] = mapped_column(Integer, default=2)
    data_residency_approved_hosted: Mapped[bool] = mapped_column(default=False)


class RemediationPolicy(Base):
    __tablename__ = "cp_remediation_policies"
    tenant_id: Mapped[str] = mapped_column(ForeignKey("cp_tenants.id"), primary_key=True)
    failure_type: Mapped[str] = mapped_column(String(64), primary_key=True)
    mode: Mapped[str] = mapped_column(String(16), default="recommend_only")  # | one_click


class Remediation(Base):
    __tablename__ = "cp_remediations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("cp_tenants.id"), index=True)
    incident_key: Mapped[str] = mapped_column(String(128))
    failure_type: Mapped[str] = mapped_column(String(64))
    playbook: Mapped[str] = mapped_column(String(128))
    params: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(16))  # proposed|approved|rejected|executed|failed
    requested_by: Mapped[str] = mapped_column(String(200))
    approved_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AuditLog(Base):
    """Append-only. The app role has INSERT/SELECT only on this table in prod."""

    __tablename__ = "cp_audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    actor: Mapped[str] = mapped_column(String(200))
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(200))
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


TENANT_TABLES = [
    t.__tablename__
    for t in (
        ConfigItem,
        Connection,
        IncidentActivity,
        RoutingRules,
        Threshold,
        ThresholdProposal,
        ModelConfig,
        RemediationPolicy,
        Remediation,
        AuditLog,
    )
]


@asynccontextmanager
async def tenant_session(
    sessions: async_sessionmaker[AsyncSession], tenant: str
) -> AsyncIterator[AsyncSession]:
    """Transaction with ``app.tenant_id`` set, so Postgres RLS enforces isolation."""
    async with sessions.begin() as s:
        if s.bind is not None and s.bind.dialect.name == "postgresql":
            await s.execute(text("SELECT set_config('app.tenant_id', :t, true)"), {"t": tenant})
        yield s
