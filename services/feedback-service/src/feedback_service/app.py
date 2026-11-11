"""Feedback service: outcome labels in, precision / recall / lead-time KPIs out.

Inputs
* ``POST /v1/webhooks/servicenow`` — called by a ServiceNow business rule when an
  AIOps ticket closes. Authenticated with HMAC-SHA256 of the raw body in
  ``X-AIOps-Signature`` (shared secret per tenant).
* ``POST /v1/webhooks/chat`` — one-click rating from Teams/Slack.
* ``POST /v1/outcomes`` — generic API (e.g. a "missed incident" recorded by an SRE).
* Kafka ``incidents.verdict`` — what was predicted, when, and with what ETA.

Outputs: ``feedback.outcomes`` events, ``/v1/kpis`` JSON and Prometheus gauges.
"""

from __future__ import annotations

import hashlib
import hmac
import statistics
from collections import defaultdict
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from prometheus_client import Gauge
from pydantic import BaseModel
from sqlalchemy import DateTime, Float, String, Text, select
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from aiops_common.bus import EventBus
from aiops_common.cloudevents import CloudEvent, make_event
from aiops_common.contracts.models import FeedbackOutcome, Outcome, Verdict, VerdictStatus
from aiops_common.contracts.registry import Topics
from aiops_common.http import ops_router

SOURCE = "urn:aiops:feedback-service"
PRECISION = Gauge(
    "aiops_kpi_precision", "Share of alerts that were real", ["tenant", "failure_type"]
)
RECALL = Gauge(
    "aiops_kpi_recall", "Share of incidents warned about in advance", ["tenant", "failure_type"]
)
LEAD = Gauge(
    "aiops_kpi_median_lead_time_minutes", "Median minutes of warning", ["tenant", "failure_type"]
)
COUNT = Gauge(
    "aiops_kpi_labelled_total", "Labelled outcomes", ["tenant", "failure_type", "outcome"]
)


class Base(DeclarativeBase):
    pass


class Prediction(Base):
    __tablename__ = "feedback_predictions"
    incident_key: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    ci_id: Mapped[str] = mapped_column(String(128))
    failure_type: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16))
    predicted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    eta_minutes: Mapped[float | None] = mapped_column(Float, nullable=True)


class Label(Base):
    __tablename__ = "feedback_labels"
    incident_key: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    failure_type: Mapped[str] = mapped_column(String(64))
    outcome: Mapped[str] = mapped_column(String(32))
    actual_root_cause: Mapped[str | None] = mapped_column(Text, nullable=True)
    lead_time_minutes: Mapped[float | None] = mapped_column(Float, nullable=True)
    source: Mapped[str] = mapped_column(String(16))
    labelled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ServiceNowCloseout(BaseModel):
    """Payload sent by the ServiceNow business rule (see docs/runbooks/servicenow-setup.md)."""

    tenant_id: str
    correlation_id: str  # = incident_key (Table API) or message_key (EM)
    number: str | None = None
    close_code: str | None = None
    u_aiops_outcome: Outcome
    u_actual_root_cause: str | None = None
    u_failure_occurred_at: datetime | None = None  # when the failure actually happened, if it did
    failure_type: str | None = None


class ChatRating(BaseModel):
    tenant_id: str
    incident_key: str
    useful: bool
    rating: int | None = None


class KPI(BaseModel):
    tenant_id: str
    failure_type: str
    true_positives: int
    false_positives: int
    missed: int
    precision: float | None
    recall: float | None
    median_lead_time_minutes: float | None


def compute_kpis(labels: list[Label]) -> list[KPI]:
    groups: dict[tuple[str, str], list[Label]] = defaultdict(list)
    for lb in labels:
        groups[(lb.tenant_id, lb.failure_type)].append(lb)
    out = []
    for (tenant, ft), ls in sorted(groups.items()):
        tp = sum(1 for x in ls if x.outcome == Outcome.TRUE_POSITIVE)
        fp = sum(1 for x in ls if x.outcome == Outcome.FALSE_POSITIVE)
        missed = sum(1 for x in ls if x.outcome == Outcome.MISSED)
        leads = [
            x.lead_time_minutes
            for x in ls
            if x.outcome == Outcome.TRUE_POSITIVE and x.lead_time_minutes is not None
        ]
        out.append(
            KPI(
                tenant_id=tenant,
                failure_type=ft,
                true_positives=tp,
                false_positives=fp,
                missed=missed,
                precision=round(tp / (tp + fp), 3) if tp + fp else None,
                recall=round(tp / (tp + missed), 3) if tp + missed else None,
                median_lead_time_minutes=round(statistics.median(leads), 1) if leads else None,
            )
        )
    return out


class FeedbackService:
    def __init__(
        self,
        engine: AsyncEngine,
        bus: EventBus | None,
        secrets: dict[str, str],
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.engine, self.bus, self.secrets, self.clock = engine, bus, secrets, clock
        self.sessions = async_sessionmaker(engine, expire_on_commit=False)

    async def create_schema(self) -> None:
        async with self.engine.begin() as c:
            await c.run_sync(Base.metadata.create_all)

    async def on_event(self, ev: CloudEvent) -> None:
        v = ev.payload(Verdict)
        if v.status in (VerdictStatus.RESOLVED, VerdictStatus.NOISE) or v.candidate.is_update:
            return
        async with self.sessions.begin() as s:
            if await s.get(Prediction, v.incident_key) is None:
                s.add(
                    Prediction(
                        incident_key=v.incident_key,
                        tenant_id=v.tenant_id,
                        ci_id=v.ci_id,
                        failure_type=v.predicted_failure.split(" ")[0],
                        status=v.status.value,
                        predicted_at=v.candidate.first_seen,
                        eta_minutes=v.eta_minutes,
                    )
                )

    async def record(self, fo: FeedbackOutcome) -> None:
        async with self.sessions.begin() as s:
            existing = await s.get(Label, fo.incident_key)
            row = existing or Label(incident_key=fo.incident_key)
            row.tenant_id, row.failure_type, row.outcome = (
                fo.tenant_id,
                fo.failure_type,
                fo.outcome.value,
            )
            row.actual_root_cause, row.lead_time_minutes = (
                fo.actual_root_cause,
                fo.lead_time_minutes,
            )
            row.source, row.labelled_at = fo.source, fo.ts
            if existing is None:
                s.add(row)
        if self.bus is not None:
            await self.bus.publish(
                Topics.FEEDBACK,
                make_event(fo, source=SOURCE, event_id=f"fb-{fo.incident_key}-{fo.outcome}"),
            )
        await self.refresh_metrics()

    async def kpis(self, tenant: str | None = None) -> list[KPI]:
        async with self.sessions() as s:
            q = select(Label)
            if tenant:
                q = q.where(Label.tenant_id == tenant)
            return compute_kpis(list((await s.execute(q)).scalars().all()))

    async def refresh_metrics(self) -> None:
        for k in await self.kpis():
            for g, val in (
                (PRECISION, k.precision),
                (RECALL, k.recall),
                (LEAD, k.median_lead_time_minutes),
            ):
                if val is not None:
                    g.labels(k.tenant_id, k.failure_type).set(val)
            COUNT.labels(k.tenant_id, k.failure_type, "tp").set(k.true_positives)
            COUNT.labels(k.tenant_id, k.failure_type, "fp").set(k.false_positives)
            COUNT.labels(k.tenant_id, k.failure_type, "missed").set(k.missed)

    async def from_servicenow(self, c: ServiceNowCloseout) -> FeedbackOutcome:
        async with self.sessions() as s:
            pred = await s.get(Prediction, c.correlation_id)
        lead = None
        if pred and c.u_failure_occurred_at and c.u_aiops_outcome == Outcome.TRUE_POSITIVE:
            occurred = c.u_failure_occurred_at.replace(tzinfo=c.u_failure_occurred_at.tzinfo or UTC)
            predicted = pred.predicted_at.replace(tzinfo=pred.predicted_at.tzinfo or UTC)
            lead = max(0.0, (occurred - predicted).total_seconds() / 60)
        elif pred and c.u_aiops_outcome == Outcome.TRUE_POSITIVE:
            lead = pred.eta_minutes
        fo = FeedbackOutcome(
            incident_key=c.correlation_id,
            tenant_id=c.tenant_id,
            ci_id=pred.ci_id if pred else None,
            failure_type=c.failure_type or (pred.failure_type if pred else "unknown"),
            outcome=c.u_aiops_outcome,
            actual_root_cause=c.u_actual_root_cause,
            lead_time_minutes=lead,
            source="servicenow",
            ts=self.clock(),
        )
        await self.record(fo)
        return fo

    def verify(self, tenant: str, body: bytes, signature: str | None) -> None:
        secret = self.secrets.get(tenant)
        if not secret:
            raise HTTPException(403, "tenant has no webhook secret configured")
        expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        if not signature or not hmac.compare_digest(expected, signature.removeprefix("sha256=")):
            raise HTTPException(401, "bad signature")


def create_app(svc: FeedbackService, ready: Callable[[], bool] = lambda: True) -> FastAPI:
    app = FastAPI(title="feedback-service", version="0.1.0")
    app.include_router(ops_router(ready))

    @app.post("/v1/webhooks/servicenow", response_model=FeedbackOutcome)
    async def sn_webhook(
        request: Request, x_aiops_signature: str | None = Header(default=None)
    ) -> FeedbackOutcome:
        raw = await request.body()
        c = ServiceNowCloseout.model_validate_json(raw)
        svc.verify(c.tenant_id, raw, x_aiops_signature)
        return await svc.from_servicenow(c)

    @app.post("/v1/webhooks/chat", response_model=FeedbackOutcome)
    async def chat_webhook(
        request: Request, x_aiops_signature: str | None = Header(default=None)
    ) -> FeedbackOutcome:
        raw = await request.body()
        r = ChatRating.model_validate_json(raw)
        svc.verify(r.tenant_id, raw, x_aiops_signature)
        async with svc.sessions() as s:
            pred = await s.get(Prediction, r.incident_key)
        fo = FeedbackOutcome(
            incident_key=r.incident_key,
            tenant_id=r.tenant_id,
            ci_id=pred.ci_id if pred else None,
            failure_type=pred.failure_type if pred else "unknown",
            outcome=Outcome.TRUE_POSITIVE if r.useful else Outcome.FALSE_POSITIVE,
            source="chat",
            rating=r.rating,
            ts=svc.clock(),
        )
        await svc.record(fo)
        return fo

    @app.post("/v1/outcomes", response_model=FeedbackOutcome, status_code=201)
    async def post_outcome(fo: FeedbackOutcome) -> FeedbackOutcome:
        await svc.record(fo)
        return fo

    @app.get("/v1/kpis", response_model=list[KPI])
    async def get_kpis(tenant_id: str | None = None) -> list[KPI]:
        return await svc.kpis(tenant_id)

    @app.get("/v1/predictions/{incident_key}")
    async def get_prediction(incident_key: str) -> dict[str, Any]:
        async with svc.sessions() as s:
            p = await s.get(Prediction, incident_key)
        if p is None:
            raise HTTPException(404)
        return {
            "incident_key": p.incident_key,
            "failure_type": p.failure_type,
            "predicted_at": p.predicted_at,
            "eta_minutes": p.eta_minutes,
            "status": p.status,
        }

    return app
