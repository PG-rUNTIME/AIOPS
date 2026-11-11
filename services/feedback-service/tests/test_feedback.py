from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta

import httpx
from sqlalchemy.ext.asyncio import create_async_engine

from aiops_common.bus import InMemoryBus
from aiops_common.cloudevents import make_event
from aiops_common.contracts.models import (
    CandidateIncident,
    DetectorKind,
    FeedbackOutcome,
    Outcome,
    Signal,
    Verdict,
    VerdictStatus,
)
from aiops_common.contracts.registry import Topics
from feedback_service.app import KPI, FeedbackService, create_app
from feedback_service.tuning import propose

T0 = datetime(2026, 11, 11, 8, 0, tzinfo=UTC)
SECRET = "s3cret"


def verdict(key: str, ft: str = "disk_full") -> Verdict:
    s = Signal(
        signal_id="s",
        tenant_id="t",
        ci_id="CI-1",
        service="db",
        detector=DetectorKind.TREND,
        failure_type=ft,
        metric="m",
        value=1,
        score=0.9,
        ts=T0,
    )
    c = CandidateIncident(
        incident_key=key,
        tenant_id="t",
        ci_id="CI-1",
        service="db",
        signals=[s],
        predicted_failure=ft,
        eta_minutes=12,
        confidence=0.9,
        first_seen=T0,
        last_seen=T0,
    )
    return Verdict(
        incident_key=key,
        tenant_id="t",
        ci_id="CI-1",
        status=VerdictStatus.VERIFIED,
        is_incident=True,
        confidence=0.9,
        predicted_failure=ft,
        eta_minutes=12,
        root_cause="r",
        model_id="m",
        prompt_version="v",
        candidate=c,
    )


def sign(body: bytes) -> str:
    return "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()


async def test_feedback_loop_end_to_end() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    bus = InMemoryBus()
    svc = FeedbackService(engine, bus, {"t": SECRET}, clock=lambda: T0)
    await svc.create_schema()
    for i in range(3):
        await svc.on_event(make_event(verdict(f"inc-{i:020d}"), source="urn:test"))
    app = create_app(svc)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://x") as c:
        body = json.dumps(
            {
                "tenant_id": "t",
                "correlation_id": "inc-" + "0" * 20,
                "u_aiops_outcome": "true_positive",
                "u_actual_root_cause": "WAL",
                "u_failure_occurred_at": (T0 + timedelta(minutes=14)).isoformat(),
            }
        ).encode()
        assert (
            await c.post(
                "/v1/webhooks/servicenow", content=body, headers={"X-AIOps-Signature": "sha256=bad"}
            )
        ).status_code == 401
        r = await c.post(
            "/v1/webhooks/servicenow", content=body, headers={"X-AIOps-Signature": sign(body)}
        )
        assert r.status_code == 200 and r.json()["lead_time_minutes"] == 14
        body2 = json.dumps(
            {"tenant_id": "t", "incident_key": f"inc-{1:020d}", "useful": False}
        ).encode()
        r = await c.post(
            "/v1/webhooks/chat", content=body2, headers={"X-AIOps-Signature": sign(body2)}
        )
        assert r.json()["outcome"] == "false_positive"
        missed = FeedbackOutcome(
            incident_key="manual-1",
            tenant_id="t",
            failure_type="disk_full",
            outcome=Outcome.MISSED,
            ts=T0,
        )
        assert (
            await c.post(
                "/v1/outcomes",
                content=missed.model_dump_json(),
                headers={"content-type": "application/json"},
            )
        ).status_code == 201
        kpis = (await c.get("/v1/kpis", params={"tenant_id": "t"})).json()
        assert kpis[0]["precision"] == 0.5 and kpis[0]["recall"] == 0.5
        assert kpis[0]["median_lead_time_minutes"] == 14
        assert (await c.get(f"/v1/predictions/inc-{2:020d}")).json()["eta_minutes"] == 12
        assert (await c.get("/v1/predictions/nope")).status_code == 404
        bad_tenant = json.dumps({"tenant_id": "zz", "incident_key": "k", "useful": True}).encode()
        assert (await c.post("/v1/webhooks/chat", content=bad_tenant)).status_code == 403
    assert len(bus.log[Topics.FEEDBACK]) == 3


def test_tuning_proposals() -> None:
    def k(ft: str, tp: int, fp: int, missed: int, p: float | None, r: float | None) -> KPI:
        return KPI(
            tenant_id="t",
            failure_type=ft,
            true_positives=tp,
            false_positives=fp,
            missed=missed,
            precision=p,
            recall=r,
            median_lead_time_minutes=None,
        )

    props = propose(
        [
            k("a", 5, 10, 0, 0.33, 1.0),
            k("b", 10, 0, 6, 1.0, 0.62),
            k("c", 1, 1, 0, 0.5, 1.0),
            k("d", 20, 1, 1, 0.95, 0.95),
        ]
    )
    assert [(p.failure_type, p.change) for p in props] == [("a", "tighten"), ("b", "loosen")]
