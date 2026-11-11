"""Router: verdict → outbox rows (one transaction) → dispatcher delivers with retries.

Degraded modes:
* ServiceNow down → rows stay pending with backoff (buffered); after
  ``alert_after_attempts`` a one-off "ServiceNow unreachable" chat + email
  notice is queued for the tenant.
* A channel not configured for a tenant → row marked failed (non-retryable),
  visible in metrics; other channels still deliver.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from prometheus_client import Counter, Gauge
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from aiops_common.bus import EventBus
from aiops_common.cloudevents import CloudEvent, make_event
from aiops_common.contracts.models import (
    Channel,
    Notification,
    NotificationAction,
    Verdict,
    VerdictStatus,
)
from aiops_common.contracts.registry import Topics
from aiops_common.ids import stable_id
from aiops_common.logging import bind_context
from aiops_common.resilience import CircuitOpenError, backoff_delay
from router.adapters import Adapter, DeliveryError
from router.db import OutboxRow, insert_ignore
from router.render import payload
from router.rules import DEFAULT_RULES, RoutingRule, decide

log = logging.getLogger(__name__)
SOURCE = "urn:aiops:router"

ENQUEUED = Counter("aiops_router_enqueued_total", "Outbox rows created", ["channel", "action"])
DELIVERED = Counter("aiops_router_delivered_total", "Deliveries", ["channel", "outcome"])
PENDING = Gauge("aiops_router_outbox_pending", "Pending outbox rows")

CLEARABLE = {Channel.SERVICENOW.value, Channel.KEEP.value, Channel.CHAT.value}


def row_id(incident_key: str, channel: str, action: str, revision: int) -> str:
    return stable_id(incident_key, channel, action, str(revision), prefix="ob-")


@dataclass
class Router:
    engine: AsyncEngine
    rules: dict[str, list[RoutingRule]] = field(default_factory=dict)
    mirror_to_keep: bool = False
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)

    def __post_init__(self) -> None:
        self.sessions = async_sessionmaker(self.engine, expire_on_commit=False)

    def _rules_for(self, tenant: str) -> list[RoutingRule]:
        return self.rules.get(tenant) or self.rules.get("*") or DEFAULT_RULES

    async def on_event(self, ev: CloudEvent) -> None:
        v = ev.payload(Verdict)
        with bind_context(incident_key=v.incident_key, tenant_id=v.tenant_id):
            await self.route(v)

    def _row(
        self, v: Verdict, channel: str, action: str, priority: int, rev: int, body: dict[str, Any]
    ) -> dict[str, Any]:
        now = self.clock()
        return {
            "id": row_id(v.incident_key, channel, action, rev),
            "incident_key": v.incident_key,
            "tenant_id": v.tenant_id,
            "ci_id": v.ci_id,
            "channel": channel,
            "action": action,
            "revision": rev,
            "priority": priority,
            "payload": body,
            "status": "pending",
            "attempts": 0,
            "next_attempt_at": now,
            "created_at": now,
        }

    async def route(self, v: Verdict) -> int:
        body = payload(v)
        rows: list[dict[str, Any]] = []
        async with self.sessions.begin() as s:
            if v.status is VerdictStatus.RESOLVED:
                opened = (
                    (
                        await s.execute(
                            select(OutboxRow).where(
                                OutboxRow.incident_key == v.incident_key,
                                OutboxRow.action == "open",
                                OutboxRow.status == "sent",
                            )
                        )
                    )
                    .scalars()
                    .all()
                )
                for ch in sorted({o.channel for o in opened} & CLEARABLE):
                    prio = max(o.priority for o in opened if o.channel == ch)
                    rows.append(self._row(v, ch, "clear", prio, 0, body))
            else:
                decision = decide(v, self._rules_for(v.tenant_id))
                rev = 1 if v.candidate.is_update else 0
                for a in decision.actions:
                    rows.append(self._row(v, a.channel.value, "open", a.priority, rev, body))
                if self.mirror_to_keep and any(
                    a.channel is Channel.SERVICENOW for a in decision.actions
                ):
                    rows.append(
                        self._row(
                            v,
                            Channel.KEEP.value,
                            "open",
                            min(a.priority for a in decision.actions),
                            rev,
                            body,
                        )
                    )
                log.info(
                    "routed",
                    extra={
                        "rule": decision.rule,
                        "status": v.status.value,
                        "channels": [a.channel.value for a in decision.actions],
                    },
                )
            n = await insert_ignore(s, rows)
        for r in rows:
            ENQUEUED.labels(r["channel"], r["action"]).inc()
        return n


AdapterResolver = Callable[[str, str], Adapter | None]  # (tenant, channel) -> adapter


@dataclass
class Dispatcher:
    engine: AsyncEngine
    adapters: AdapterResolver
    bus: EventBus | None = None
    batch_size: int = 50
    max_attempts: int = 60
    alert_after_attempts: int = 3
    base_backoff: float = 2.0
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)

    def __post_init__(self) -> None:
        self.sessions = async_sessionmaker(self.engine, expire_on_commit=False)

    async def run_once(self) -> int:
        """Deliver due rows. Uses SKIP LOCKED on Postgres so replicas share the work."""
        now = self.clock()
        delivered = 0
        async with self.sessions.begin() as s:
            due = (
                (
                    await s.execute(
                        select(OutboxRow)
                        .where(OutboxRow.status == "pending", OutboxRow.next_attempt_at <= now)
                        .order_by(OutboxRow.priority, OutboxRow.created_at)
                        .limit(self.batch_size)
                        .with_for_update(skip_locked=True)
                    )
                )
                .scalars()
                .all()
            )
            followups: list[dict[str, Any]] = []
            for row in due:
                ok = await self._deliver(row, now, followups)
                delivered += int(ok)
            if followups:
                await insert_ignore(s, followups)
            pending = (
                await s.execute(select(OutboxRow.id).where(OutboxRow.status == "pending"))
            ).all()
            PENDING.set(len(pending))
        return delivered

    async def _deliver(
        self, row: OutboxRow, now: datetime, followups: list[dict[str, Any]]
    ) -> bool:
        adapter = self.adapters(row.tenant_id, row.channel)
        row.attempts += 1
        try:
            if adapter is None:
                raise DeliveryError(
                    f"channel {row.channel} not configured for tenant", retryable=False
                )
            ref = await adapter.send(row)
        except (DeliveryError, CircuitOpenError, OSError, Exception) as e:
            retryable = getattr(e, "retryable", True)
            row.last_error = f"{type(e).__name__}: {e}"[:1000]
            if not retryable or row.attempts >= self.max_attempts:
                row.status = "failed"
                DELIVERED.labels(row.channel, "failed").inc()
                await self._notify(row)
            else:
                delay = max(1.0, backoff_delay(row.attempts, base=self.base_backoff, cap=300))
                row.next_attempt_at = now + timedelta(seconds=delay)
                DELIVERED.labels(row.channel, "retry").inc()
            if (
                row.channel == Channel.SERVICENOW.value
                and row.attempts == self.alert_after_attempts
            ):
                followups += self._itsm_down_notice(row, now)
            log.warning(
                "delivery failed",
                extra={"channel": row.channel, "attempts": row.attempts, "error": row.last_error},
            )
            return False
        row.status, row.external_ref, row.sent_at = "sent", ref, now
        DELIVERED.labels(row.channel, "sent").inc()
        await self._notify(row)
        return True

    def _itsm_down_notice(self, row: OutboxRow, now: datetime) -> list[dict[str, Any]]:
        p = dict(row.payload)
        p["title"] = f"[AIOps] ServiceNow unreachable — buffering: {p['title']}"
        p["description"] = (
            f"ServiceNow delivery failing ({row.last_error}). The ticket is buffered "
            f"in the outbox and will be retried.\n\n{p['description']}"
        )[:4000]
        return [
            {
                "id": row_id(row.incident_key, ch, "itsm_down", 0),
                "incident_key": row.incident_key,
                "tenant_id": row.tenant_id,
                "ci_id": row.ci_id,
                "channel": ch,
                "action": "open",
                "revision": 0,
                "priority": row.priority,
                "payload": p,
                "status": "pending",
                "attempts": 0,
                "next_attempt_at": now,
                "created_at": now,
            }
            for ch in (Channel.CHAT.value, Channel.EMAIL.value)
        ]

    async def _notify(self, row: OutboxRow) -> None:
        if self.bus is None:
            return
        n = Notification(
            notification_id=row.id,
            incident_key=row.incident_key,
            tenant_id=row.tenant_id,
            ci_id=row.ci_id,
            channel=Channel(row.channel),
            action=NotificationAction.CLEAR if row.action == "clear" else NotificationAction.OPEN,
            priority=row.priority,
            status="sent" if row.status == "sent" else "failed",
            external_ref=row.external_ref,
        )
        await self.bus.publish(
            Topics.OUTBOX, make_event(n, source=SOURCE, event_id=f"{row.id}-{row.status}")
        )
