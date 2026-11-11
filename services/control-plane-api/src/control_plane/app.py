"""Control-plane API (OpenAPI 3.1 via FastAPI)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from aiops_common.http import ops_router
from control_plane import db
from control_plane.auth import Authenticator, Principal, principal_dep, require
from control_plane.remediation import Executor


# --------------------------------------------------------------------------- schemas
class TenantIn(BaseModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    name: str


class TenantOut(TenantIn):
    created_at: datetime


class CIIn(BaseModel):
    ci_id: str
    name: str
    service: str
    owner_team: str | None = None
    sn_sys_id: str | None = None
    attributes: dict[str, Any] = {}


class RulesIn(BaseModel):
    rules: list[dict[str, Any]]


class ThresholdIn(BaseModel):
    threshold: float
    forecast_quantile: Literal["p10", "p50", "p90"] = "p90"
    horizon_minutes: float = Field(15, gt=0, le=1440)
    min_confidence: float = Field(0.5, ge=0, le=1)


class ModelConfigIn(BaseModel):
    provider: Literal["openai", "holmes", "none"]
    model: str
    base_url: str
    tokens_per_day: int = Field(500_000, ge=0)
    max_inflight: int = Field(2, ge=1, le=50)
    data_residency_approved_hosted: bool = False


class ProposalIn(BaseModel):
    tenant_id: str
    failure_type: str
    change: str
    forecast_quantile: str | None = None
    min_confidence_delta: float = 0
    horizon_minutes_delta: float = 0
    reason: str


class RemediationIn(BaseModel):
    incident_key: str
    failure_type: str
    playbook: str
    params: dict[str, str | int | float | bool] = {}


class RemediationOut(BaseModel):
    id: int
    tenant_id: str
    incident_key: str
    failure_type: str
    playbook: str
    params: dict[str, Any]
    status: str
    mode: str
    requested_by: str
    approved_by: str | None
    result: str | None


class PolicyIn(BaseModel):
    mode: Literal["recommend_only", "one_click"]


class AuditOut(BaseModel):
    ts: datetime
    actor: str
    action: str
    target: str
    detail: dict[str, Any]


def create_app(
    engine: AsyncEngine,
    auth: Authenticator,
    executor: Executor,
    playbooks: set[str],
    ready: Callable[[], bool] = lambda: True,
) -> FastAPI:
    app = FastAPI(
        title="AIOps control-plane API",
        version="0.1.0",
        description="Tenants, CIs, routing rules, runbooks, thresholds, model config and "
        "approval-gated remediation. OAuth2/OIDC bearer tokens; RBAC roles "
        "viewer < operator < approver < admin.",
    )
    app.include_router(ops_router(ready))
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    current = principal_dep(auth)
    viewer, operator = require("viewer", current), require("operator", current)
    approver, admin = require("approver", current), require("admin", current)

    def now() -> datetime:
        return datetime.now(UTC)

    async def audit(
        s: Any,
        p: Principal,
        tenant: str,
        action: str,
        target: str,
        detail: dict[str, Any] | None = None,
    ) -> None:
        s.add(
            db.AuditLog(
                ts=now(),
                actor=p.sub,
                tenant_id=tenant,
                action=action,
                target=target,
                detail=detail or {},
            )
        )

    # ------------------------------------------------------------------ tenants
    @app.post("/v1/tenants", response_model=TenantOut, status_code=201, tags=["tenants"])
    async def create_tenant(t: TenantIn, p: Principal = Depends(admin)) -> TenantOut:
        if "*" not in p.tenants:
            raise HTTPException(403, "platform admin required")
        async with sessions.begin() as s:
            if await s.get(db.Tenant, t.id):
                raise HTTPException(409, "tenant exists")
            row = db.Tenant(id=t.id, name=t.name, created_at=now())
            s.add(row)
            await audit(s, p, t.id, "tenant.create", t.id)
        return TenantOut(id=row.id, name=row.name, created_at=row.created_at)

    @app.get("/v1/tenants", response_model=list[TenantOut], tags=["tenants"])
    async def list_tenants(p: Principal = Depends(viewer)) -> list[TenantOut]:
        async with sessions() as s:
            rows = (await s.execute(select(db.Tenant))).scalars().all()
        return [
            TenantOut(id=r.id, name=r.name, created_at=r.created_at)
            for r in rows
            if p.can_access(r.id)
        ]

    async def _tenant_exists(tenant_id: str) -> None:
        async with sessions() as s:
            if not await s.get(db.Tenant, tenant_id):
                raise HTTPException(404, "tenant not found")

    # ------------------------------------------------------------------ CIs
    @app.put("/v1/tenants/{tenant_id}/cis/{ci_id}", response_model=CIIn, tags=["cmdb"])
    async def upsert_ci(
        tenant_id: str, ci_id: str, ci: CIIn, p: Principal = Depends(operator)
    ) -> CIIn:
        if ci.ci_id != ci_id:
            raise HTTPException(422, "ci_id mismatch")
        await _tenant_exists(tenant_id)
        async with db.tenant_session(sessions, tenant_id) as s:
            await s.merge(db.ConfigItem(tenant_id=tenant_id, **ci.model_dump()))
            await audit(s, p, tenant_id, "ci.upsert", ci_id)
        return ci

    @app.get("/v1/tenants/{tenant_id}/cis", response_model=list[CIIn], tags=["cmdb"])
    async def list_cis(tenant_id: str, p: Principal = Depends(viewer)) -> list[CIIn]:
        async with db.tenant_session(sessions, tenant_id) as s:
            rows = (
                await s.execute(select(db.ConfigItem).where(db.ConfigItem.tenant_id == tenant_id))
            ).scalars()
            return [
                CIIn(
                    ci_id=r.ci_id,
                    name=r.name,
                    service=r.service,
                    owner_team=r.owner_team,
                    sn_sys_id=r.sn_sys_id,
                    attributes=r.attributes,
                )
                for r in rows
            ]

    # ------------------------------------------------------------------ routing rules
    @app.put("/v1/tenants/{tenant_id}/routing-rules", response_model=RulesIn, tags=["routing"])
    async def put_rules(tenant_id: str, body: RulesIn, p: Principal = Depends(admin)) -> RulesIn:
        from aiops_common.routing import RoutingRule  # same model the router uses

        try:
            [RoutingRule.model_validate(r) for r in body.rules]
        except ValueError as e:
            raise HTTPException(422, str(e)) from e
        await _tenant_exists(tenant_id)
        async with db.tenant_session(sessions, tenant_id) as s:
            await s.merge(
                db.RoutingRules(
                    tenant_id=tenant_id, rules=body.rules, updated_by=p.sub, updated_at=now()
                )
            )
            await audit(s, p, tenant_id, "routing.update", tenant_id, {"n": len(body.rules)})
        return body

    @app.get("/v1/tenants/{tenant_id}/routing-rules", response_model=RulesIn, tags=["routing"])
    async def get_rules(tenant_id: str, p: Principal = Depends(viewer)) -> RulesIn:
        async with db.tenant_session(sessions, tenant_id) as s:
            row = await s.get(db.RoutingRules, tenant_id)
        if row is None:
            raise HTTPException(404, "tenant uses default rules")
        return RulesIn(rules=row.rules)

    # ------------------------------------------------------------------ thresholds
    @app.put(
        "/v1/tenants/{tenant_id}/thresholds/{failure_type}",
        response_model=ThresholdIn,
        tags=["detection"],
    )
    async def put_threshold(
        tenant_id: str, failure_type: str, t: ThresholdIn, p: Principal = Depends(admin)
    ) -> ThresholdIn:
        await _tenant_exists(tenant_id)
        async with db.tenant_session(sessions, tenant_id) as s:
            await s.merge(
                db.Threshold(tenant_id=tenant_id, failure_type=failure_type, **t.model_dump())
            )
            await audit(s, p, tenant_id, "threshold.update", failure_type, t.model_dump())
        return t

    @app.post("/v1/thresholds/proposals", status_code=202, tags=["detection"])
    async def post_proposal(prop: ProposalIn, p: Principal = Depends(operator)) -> dict[str, str]:
        if not p.can_access(prop.tenant_id):
            raise HTTPException(403, "no access to tenant")
        async with db.tenant_session(sessions, prop.tenant_id) as s:
            s.add(
                db.ThresholdProposal(
                    tenant_id=prop.tenant_id,
                    failure_type=prop.failure_type,
                    payload=prop.model_dump(),
                    created_at=now(),
                )
            )
            await audit(
                s, p, prop.tenant_id, "threshold.propose", prop.failure_type, prop.model_dump()
            )
        return {"status": "recorded"}

    # ------------------------------------------------------------------ model config
    @app.put("/v1/tenants/{tenant_id}/model-config", response_model=ModelConfigIn, tags=["ai"])
    async def put_model(
        tenant_id: str, m: ModelConfigIn, p: Principal = Depends(admin)
    ) -> ModelConfigIn:
        hosted = not any(
            h in m.base_url for h in ("localhost", "vllm", "ollama", ".svc", "10.", "192.168.")
        )
        if m.provider == "openai" and hosted and not m.data_residency_approved_hosted:
            raise HTTPException(
                422,
                "hosted LLM requires data_residency_approved_hosted=true "
                "(client's written approval, redacted summaries only)",
            )
        await _tenant_exists(tenant_id)
        async with db.tenant_session(sessions, tenant_id) as s:
            await s.merge(db.ModelConfig(tenant_id=tenant_id, **m.model_dump()))
            await audit(s, p, tenant_id, "model.update", m.model, {"base_url": m.base_url})
        return m

    # ------------------------------------------------------------------ remediation
    async def _mode(s: Any, tenant: str, failure_type: str) -> str:
        pol = await s.get(db.RemediationPolicy, (tenant, failure_type))
        return pol.mode if pol else "recommend_only"

    def _out(r: db.Remediation, mode: str) -> RemediationOut:
        return RemediationOut(
            id=r.id,
            tenant_id=r.tenant_id,
            incident_key=r.incident_key,
            failure_type=r.failure_type,
            playbook=r.playbook,
            params=r.params,
            status=r.status,
            mode=mode,
            requested_by=r.requested_by,
            approved_by=r.approved_by,
            result=r.result,
        )

    @app.put(
        "/v1/tenants/{tenant_id}/remediation-policies/{failure_type}",
        response_model=PolicyIn,
        tags=["remediation"],
    )
    async def put_policy(
        tenant_id: str, failure_type: str, pol: PolicyIn, p: Principal = Depends(admin)
    ) -> PolicyIn:
        await _tenant_exists(tenant_id)
        async with db.tenant_session(sessions, tenant_id) as s:
            await s.merge(
                db.RemediationPolicy(tenant_id=tenant_id, failure_type=failure_type, mode=pol.mode)
            )
            await audit(s, p, tenant_id, "remediation.policy", failure_type, {"mode": pol.mode})
        return pol

    @app.post(
        "/v1/tenants/{tenant_id}/remediations",
        response_model=RemediationOut,
        status_code=201,
        tags=["remediation"],
    )
    async def propose(
        tenant_id: str, body: RemediationIn, p: Principal = Depends(operator)
    ) -> RemediationOut:
        if body.playbook not in playbooks:
            raise HTTPException(422, f"playbook not allow-listed: {sorted(playbooks)}")
        await _tenant_exists(tenant_id)
        async with db.tenant_session(sessions, tenant_id) as s:
            r = db.Remediation(
                tenant_id=tenant_id,
                incident_key=body.incident_key,
                failure_type=body.failure_type,
                playbook=body.playbook,
                params=body.params,
                status="proposed",
                requested_by=p.sub,
                created_at=now(),
            )
            s.add(r)
            await s.flush()
            await audit(s, p, tenant_id, "remediation.propose", str(r.id), body.model_dump())
            return _out(r, await _mode(s, tenant_id, body.failure_type))

    async def _load(s: Any, tenant_id: str, rid: int) -> db.Remediation:
        r = await s.get(db.Remediation, rid)
        if r is None or r.tenant_id != tenant_id:
            raise HTTPException(404, "remediation not found")
        return r  # type: ignore[no-any-return]

    @app.post(
        "/v1/tenants/{tenant_id}/remediations/{rid}/approve",
        response_model=RemediationOut,
        tags=["remediation"],
    )
    async def approve(tenant_id: str, rid: int, p: Principal = Depends(approver)) -> RemediationOut:
        async with db.tenant_session(sessions, tenant_id) as s:
            r = await _load(s, tenant_id, rid)
            if r.status != "proposed":
                raise HTTPException(409, f"cannot approve in status {r.status}")
            if r.requested_by == p.sub:
                raise HTTPException(403, "four-eyes rule: requester cannot approve")
            r.status, r.approved_by, r.approved_at = "approved", p.sub, now()
            await audit(s, p, tenant_id, "remediation.approve", str(rid))
            return _out(r, await _mode(s, tenant_id, r.failure_type))

    @app.post(
        "/v1/tenants/{tenant_id}/remediations/{rid}/reject",
        response_model=RemediationOut,
        tags=["remediation"],
    )
    async def reject(tenant_id: str, rid: int, p: Principal = Depends(approver)) -> RemediationOut:
        async with db.tenant_session(sessions, tenant_id) as s:
            r = await _load(s, tenant_id, rid)
            if r.status != "proposed":
                raise HTTPException(409, f"cannot reject in status {r.status}")
            r.status = "rejected"
            await audit(s, p, tenant_id, "remediation.reject", str(rid))
            return _out(r, await _mode(s, tenant_id, r.failure_type))

    async def _deny(p: Principal, tenant_id: str, rid: int, why: str, msg: str) -> None:
        # Committed in its own transaction so the denial survives the error response.
        async with db.tenant_session(sessions, tenant_id) as s:
            await audit(s, p, tenant_id, "remediation.execute.denied", str(rid), {"why": why})
        raise HTTPException(409, msg)

    @app.post(
        "/v1/tenants/{tenant_id}/remediations/{rid}/execute",
        response_model=RemediationOut,
        tags=["remediation"],
    )
    async def execute(tenant_id: str, rid: int, p: Principal = Depends(operator)) -> RemediationOut:
        async with db.tenant_session(sessions, tenant_id) as s:
            r = await _load(s, tenant_id, rid)
            mode = await _mode(s, tenant_id, r.failure_type)
            status, approved_by = r.status, r.approved_by
        if mode != "one_click":
            await _deny(
                p,
                tenant_id,
                rid,
                "recommend_only",
                "failure type is recommend-only; apply the fix manually",
            )
        if status != "approved" or not approved_by:
            await _deny(p, tenant_id, rid, status, f"remediation not approved (status {status})")
        async with db.tenant_session(sessions, tenant_id) as s:
            r = await _load(s, tenant_id, rid)
            if r.status != "approved":  # re-check under the write transaction (no double run)
                raise HTTPException(409, f"remediation not approved (status {r.status})")
            r.status = "executing"
        async with db.tenant_session(sessions, tenant_id) as s:
            r = await _load(s, tenant_id, rid)
            res = await executor.run(r.playbook, dict(r.params))
            r.status = "executed" if res.ok else "failed"
            r.executed_at, r.result = now(), res.output[:4000]
            await audit(
                s,
                p,
                tenant_id,
                "remediation.execute",
                str(rid),
                {"ok": res.ok, "playbook": r.playbook, "approved_by": r.approved_by},
            )
            return _out(r, mode)

    @app.get("/v1/tenants/{tenant_id}/audit", response_model=list[AuditOut], tags=["audit"])
    async def get_audit(
        tenant_id: str, limit: int = 100, p: Principal = Depends(viewer)
    ) -> list[AuditOut]:
        async with db.tenant_session(sessions, tenant_id) as s:
            rows = (
                await s.execute(
                    select(db.AuditLog)
                    .where(db.AuditLog.tenant_id == tenant_id)
                    .order_by(db.AuditLog.id.desc())
                    .limit(min(limit, 1000))
                )
            ).scalars()
            return [
                AuditOut(ts=r.ts, actor=r.actor, action=r.action, target=r.target, detail=r.detail)
                for r in rows
            ]

    return app
