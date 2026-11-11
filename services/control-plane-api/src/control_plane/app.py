"""Control-plane API (OpenAPI 3.1 via FastAPI)."""

from __future__ import annotations

import asyncio
import hmac
import logging
import uuid
from collections.abc import Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from aiops_common.http import ops_router
from control_plane import connections as conn
from control_plane import datasource_query as dq
from control_plane import db, passwords
from control_plane import incidents as inc
from control_plane.auth import (
    Authenticator,
    Principal,
    principal_dep,
    require,
    session_token,
)
from control_plane.poller import Poller
from control_plane.remediation import Executor
from control_plane.secretbox import SecretBox

log = logging.getLogger("control-plane")


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
    tokens_per_day: int = Field(2_000_000, ge=0)
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


class OutcomeIn(BaseModel):
    outcome: Literal["true_positive", "false_positive"]
    actual_root_cause: str | None = Field(None, max_length=2000)


class MeOut(BaseModel):
    sub: str
    roles: list[str]
    tenants: list[str]


USERNAME_RE = r"^[a-z0-9][a-z0-9._-]{2,63}$"
MAX_FAILED_LOGINS = 5
LOCKOUT = timedelta(minutes=15)


class LoginIn(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)


class LoginOut(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - OAuth token type, not a secret
    expires_in: int
    user: MeOut


class UserIn(BaseModel):
    username: str = Field(pattern=USERNAME_RE)
    password: str = Field(max_length=256)
    role: Literal["viewer", "operator", "approver", "admin"]
    tenants: list[str] = Field(min_length=1, max_length=100)
    display_name: str | None = Field(None, max_length=200)


class UserPatch(BaseModel):
    role: Literal["viewer", "operator", "approver", "admin"] | None = None
    tenants: list[str] | None = Field(None, min_length=1, max_length=100)
    display_name: str | None = Field(None, max_length=200)
    disabled: bool | None = None
    unlock: bool = False


class UserOut(BaseModel):
    username: str
    display_name: str | None
    role: str
    tenants: list[str]
    disabled: bool
    locked: bool
    last_login: datetime | None
    created_at: datetime


class PasswordResetIn(BaseModel):
    new_password: str = Field(max_length=256)


class PasswordChangeIn(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)


class ConnectionIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    kind: str
    url: str = Field(max_length=500)
    auth_type: conn.AuthType = "none"
    username: str | None = Field(None, max_length=200)
    header_name: str | None = Field(None, pattern=r"^[A-Za-z0-9-]{1,100}$")
    secret: str | None = Field(None, max_length=4096)  # write-only; None keeps, "" clears
    verify_tls: bool = True
    enabled: bool = True
    extra: dict[str, str] = Field(default_factory=dict, max_length=10)


class ConnectionTestIn(ConnectionIn):
    id: str | None = None  # reuse the stored secret of this connection when no secret is given


class ConnectionOut(BaseModel):
    id: str
    name: str
    kind: str
    category: str
    url: str
    auth_type: str
    username: str | None
    header_name: str | None
    has_secret: bool
    verify_tls: bool
    enabled: bool
    extra: dict[str, str]
    last_test_ok: bool | None
    last_test_at: datetime | None
    last_test_message: str | None
    created_by: str
    created_at: datetime
    updated_at: datetime


class TestResultOut(BaseModel):
    ok: bool
    message: str
    status_code: int | None
    latency_ms: int | None
    tested_at: datetime


class KindOut(BaseModel):
    id: str
    label: str
    category: str
    example_url: str
    hint: str
    extra_fields: list[dict[str, str]]
    bool_fields: list[dict[str, str]]


class DataSourceOut(BaseModel):
    id: str
    name: str
    kind: str
    category: str
    ops: list[str]


class DataQueryIn(BaseModel):
    op: Literal["instant", "range", "logs", "dashboards"]
    query: str = Field(max_length=dq.MAX_QUERY_CHARS)
    minutes: int = Field(30, ge=1, le=dq.MAX_MINUTES)


def _aware(ts: datetime | None) -> datetime | None:
    return ts if ts is None or ts.tzinfo else ts.replace(tzinfo=UTC)


def create_app(
    engine: AsyncEngine,
    auth: Authenticator,
    executor: Executor,
    playbooks: set[str],
    ready: Callable[[], bool] = lambda: True,
    feedback: httpx.AsyncClient | None = None,
    console_dir: Path | None = None,
    console_config: dict[str, Any] | None = None,
    brand_dir: Path | None = None,
    secrets: SecretBox | None = None,
    internal_token: str | None = None,
    poller: Poller | None = None,
    vm: httpx.AsyncClient | None = None,
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_: FastAPI) -> Any:
        stop = asyncio.Event()
        task = asyncio.create_task(poller.run(stop)) if poller else None
        try:
            yield
        finally:
            stop.set()
            if task:
                await task

    app = FastAPI(
        lifespan=lifespan,
        title="AIOps control-plane API",
        version="0.1.0",
        description="Tenants, CIs, routing rules, runbooks, thresholds, model config and "
        "approval-gated remediation. OAuth2/OIDC bearer tokens; RBAC roles "
        "viewer < operator < approver < admin.",
    )
    app.include_router(ops_router(ready))
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    base_current = principal_dep(auth)
    local = auth.s.mode == "local"
    unauthorised = {"WWW-Authenticate": "Bearer"}

    async def local_current(p: Principal = Depends(base_current)) -> Principal:
        """Local mode: role/tenants come from the database, so changes apply immediately."""
        async with sessions() as s:
            u = await s.get(db.User, p.sub)
        if u is None or u.disabled:
            raise HTTPException(401, "account disabled or removed", headers=unauthorised)
        changed = _aware(u.password_changed_at)
        if changed and p.issued_at < int(changed.timestamp()):
            raise HTTPException(401, "password changed; sign in again", headers=unauthorised)
        return Principal(u.username, frozenset([u.role]), frozenset(u.tenants), p.issued_at)

    current = local_current if local else base_current
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

    # ------------------------------------------------------------------ connections
    def _conn_out(c: db.Connection) -> ConnectionOut:
        return ConnectionOut(
            id=c.id,
            name=c.name,
            kind=c.kind,
            category=conn.KIND_BY_ID[c.kind].category if c.kind in conn.KIND_BY_ID else "other",
            url=c.url,
            auth_type=c.auth_type,
            username=c.username,
            header_name=c.header_name,
            has_secret=bool(c.secret_enc),
            verify_tls=c.verify_tls,
            enabled=c.enabled,
            extra={k: str(v) for k, v in (c.extra or {}).items()},
            last_test_ok=c.last_test_ok,
            last_test_at=c.last_test_at,
            last_test_message=c.last_test_message,
            created_by=c.created_by,
            created_at=c.created_at,
            updated_at=c.updated_at,
        )

    def _validate_conn(b: ConnectionIn) -> str:
        if b.kind not in conn.KIND_BY_ID:
            raise HTTPException(422, f"unknown connection type: {b.kind}")
        try:
            url = conn.normalise_url(b.url)
        except conn.UrlRejected as e:
            raise HTTPException(422, str(e)) from e
        if b.auth_type == "header" and not b.header_name:
            raise HTTPException(422, "a header name is required for header authentication")
        if b.auth_type == "basic" and not b.username:
            raise HTTPException(422, "a username is required for basic authentication")
        spec = conn.KIND_BY_ID[b.kind]
        allowed = {k for k, _ in spec.extra_fields} | {k for k, _ in spec.bool_fields}
        if set(b.extra) - allowed:
            raise HTTPException(422, "unsupported option for this connection type")
        for k, _ in spec.bool_fields:
            if k in b.extra and b.extra[k] not in ("true", "false"):
                raise HTTPException(422, f"{k} must be true or false")
        return url

    def _encrypt(secret: str) -> str:
        if secrets is None:
            raise HTTPException(
                503, "Credential storage is not configured (set AIOPS_SECRETS_KEY)."
            )
        return secrets.encrypt(secret)

    def _decrypt(row: db.Connection | None) -> str | None:
        if row is None or not row.secret_enc or secrets is None:
            return None
        try:
            return secrets.decrypt(row.secret_enc)
        except ValueError as e:
            raise HTTPException(409, "stored credential cannot be decrypted; re-enter it") from e

    def _apply(row: db.Connection, b: ConnectionIn, url: str) -> None:
        row.name, row.kind, row.url, row.auth_type = b.name.strip(), b.kind, url, b.auth_type
        row.username = b.username if b.auth_type == "basic" else None
        row.header_name = b.header_name if b.auth_type == "header" else None
        row.verify_tls, row.enabled = b.verify_tls, b.enabled
        row.extra = {k: v for k, v in b.extra.items() if v}
        if b.auth_type == "none":
            row.secret_enc = None
        elif b.secret:
            row.secret_enc = _encrypt(b.secret)
        elif b.secret == "":
            row.secret_enc = None

    async def _run_test(b: ConnectionIn, url: str, secret: str | None) -> TestResultOut:
        res = await conn.probe(
            kind=b.kind,
            url=url,
            auth_type=b.auth_type,
            username=b.username,
            secret=secret,
            header_name=b.header_name,
            verify_tls=b.verify_tls,
            extra=b.extra,
        )
        return TestResultOut(
            ok=res.ok,
            message=res.message,
            status_code=res.status_code,
            latency_ms=res.latency_ms,
            tested_at=now(),
        )

    @app.get("/v1/connection-kinds", response_model=list[KindOut], tags=["connections"])
    async def connection_kinds(_: Principal = Depends(current)) -> list[KindOut]:
        return [
            KindOut(
                id=k.id,
                label=k.label,
                category=k.category,
                example_url=k.example_url,
                hint=k.hint,
                extra_fields=[{"key": a, "label": b} for a, b in k.extra_fields],
                bool_fields=[{"key": a, "label": b} for a, b in k.bool_fields],
            )
            for k in conn.KINDS
        ]

    @app.get(
        "/v1/tenants/{tenant_id}/connections",
        response_model=list[ConnectionOut],
        tags=["connections"],
    )
    async def list_connections(
        tenant_id: str, p: Principal = Depends(viewer)
    ) -> list[ConnectionOut]:
        async with db.tenant_session(sessions, tenant_id) as s:
            rows = (
                await s.execute(
                    select(db.Connection)
                    .where(db.Connection.tenant_id == tenant_id)
                    .order_by(db.Connection.name)
                )
            ).scalars()
            return [_conn_out(r) for r in rows]

    @app.post(
        "/v1/tenants/{tenant_id}/connections",
        response_model=ConnectionOut,
        status_code=201,
        tags=["connections"],
    )
    async def create_connection(
        tenant_id: str, body: ConnectionIn, p: Principal = Depends(admin)
    ) -> ConnectionOut:
        await _tenant_exists(tenant_id)
        url = _validate_conn(body)
        t = now()
        row = db.Connection(
            id=uuid.uuid4().hex,
            tenant_id=tenant_id,
            created_by=p.sub,
            created_at=t,
            updated_at=t,
        )
        _apply(row, body, url)
        async with db.tenant_session(sessions, tenant_id) as s:
            s.add(row)
            await audit(
                s, p, tenant_id, "connection.create", row.id, {"name": row.name, "kind": row.kind}
            )
            return _conn_out(row)

    @app.put(
        "/v1/tenants/{tenant_id}/connections/{conn_id}",
        response_model=ConnectionOut,
        tags=["connections"],
    )
    async def update_connection(
        tenant_id: str, conn_id: str, body: ConnectionIn, p: Principal = Depends(admin)
    ) -> ConnectionOut:
        url = _validate_conn(body)
        async with db.tenant_session(sessions, tenant_id) as s:
            row = await s.get(db.Connection, conn_id)
            if row is None or row.tenant_id != tenant_id:
                raise HTTPException(404, "connection not found")
            _apply(row, body, url)
            row.updated_at = now()
            row.last_test_ok = row.last_test_at = row.last_test_message = None  # stale after edit
            await audit(
                s, p, tenant_id, "connection.update", row.id, {"name": row.name, "kind": row.kind}
            )
            return _conn_out(row)

    @app.delete(
        "/v1/tenants/{tenant_id}/connections/{conn_id}", status_code=204, tags=["connections"]
    )
    async def delete_connection(
        tenant_id: str, conn_id: str, p: Principal = Depends(admin)
    ) -> None:
        async with db.tenant_session(sessions, tenant_id) as s:
            row = await s.get(db.Connection, conn_id)
            if row is None or row.tenant_id != tenant_id:
                raise HTTPException(404, "connection not found")
            name = row.name
            await s.delete(row)
            await audit(s, p, tenant_id, "connection.delete", conn_id, {"name": name})

    @app.post(
        "/v1/tenants/{tenant_id}/connections/test",
        response_model=TestResultOut,
        tags=["connections"],
    )
    async def test_unsaved(
        tenant_id: str, body: ConnectionTestIn, p: Principal = Depends(admin)
    ) -> TestResultOut:
        url = _validate_conn(body)
        secret = body.secret
        if not secret and body.id and body.auth_type != "none":
            async with db.tenant_session(sessions, tenant_id) as s:
                existing = await s.get(db.Connection, body.id)
                if existing is not None and existing.tenant_id == tenant_id:
                    secret = _decrypt(existing)
        return await _run_test(body, url, secret)

    @app.post(
        "/v1/tenants/{tenant_id}/connections/{conn_id}/test",
        response_model=TestResultOut,
        tags=["connections"],
    )
    async def test_saved(
        tenant_id: str, conn_id: str, p: Principal = Depends(operator)
    ) -> TestResultOut:
        async with db.tenant_session(sessions, tenant_id) as s:
            row = await s.get(db.Connection, conn_id)
            if row is None or row.tenant_id != tenant_id:
                raise HTTPException(404, "connection not found")
            snapshot = ConnectionIn(
                name=row.name,
                kind=row.kind,
                url=row.url,
                auth_type=row.auth_type,
                username=row.username,
                header_name=row.header_name,
                verify_tls=row.verify_tls,
                extra={k: str(v) for k, v in (row.extra or {}).items()},
            )
            secret = _decrypt(row)
        result = await _run_test(snapshot, row.url, secret)  # network I/O outside the transaction
        async with db.tenant_session(sessions, tenant_id) as s:
            row2 = await s.get(db.Connection, conn_id)
            if row2 is not None:
                row2.last_test_ok, row2.last_test_at = result.ok, result.tested_at
                row2.last_test_message = result.message[:300]
                await audit(s, p, tenant_id, "connection.test", conn_id, {"ok": result.ok})
        return result

    # ------------------------------------------------------------------ internal: agent data access
    async def internal_only(x_internal_token: str | None = Header(None)) -> None:
        if not internal_token:
            raise HTTPException(404, "not found")
        if not x_internal_token or not hmac.compare_digest(x_internal_token, internal_token):
            raise HTTPException(401, "invalid internal token")

    @app.get(
        "/internal/v1/tenants/{tenant_id}/data-sources",
        response_model=list[DataSourceOut],
        include_in_schema=False,
    )
    async def internal_sources(
        tenant_id: str, _: None = Depends(internal_only)
    ) -> list[DataSourceOut]:
        async with db.tenant_session(sessions, tenant_id) as s:
            rows = (
                await s.execute(
                    select(db.Connection)
                    .where(db.Connection.tenant_id == tenant_id, db.Connection.enabled.is_(True))
                    .order_by(db.Connection.name)
                )
            ).scalars()
            return [
                DataSourceOut(
                    id=c.id,
                    name=c.name,
                    kind=c.kind,
                    category=conn.KIND_BY_ID[c.kind].category,
                    ops=sorted(dq.OPS[c.kind]),
                )
                for c in rows
                if c.kind in dq.OPS
            ]

    @app.post(
        "/internal/v1/tenants/{tenant_id}/data-sources/{source_id}/query",
        include_in_schema=False,
    )
    async def internal_query(
        tenant_id: str, source_id: str, body: DataQueryIn, _: None = Depends(internal_only)
    ) -> dict[str, str]:
        async with db.tenant_session(sessions, tenant_id) as s:
            row = await s.get(db.Connection, source_id)
            if row is None or row.tenant_id != tenant_id or not row.enabled:
                raise HTTPException(404, "data source not found")
            row_name = row.name
            target = dq.Target(
                row.kind,
                row.url,
                row.auth_type,
                row.username,
                row.header_name,
                _decrypt(row),
                row.verify_tls,
                {k: str(v) for k, v in (row.extra or {}).items()},
            )
        log.info(
            "data source query",
            extra={
                "tenant": tenant_id,
                "source": row_name,
                "kind": target.kind,
                "op": body.op,
                "query": body.query[:200],
            },
        )
        try:
            return {"text": await dq.run(target, body.op, body.query, body.minutes)}
        except dq.QueryError as e:
            raise HTTPException(e.status, e.message) from e

    # ------------------------------------------------------------------ local accounts
    def _user_out(u: db.User) -> UserOut:
        locked = _aware(u.locked_until)
        return UserOut(
            username=u.username,
            display_name=u.display_name,
            role=u.role,
            tenants=list(u.tenants),
            disabled=u.disabled,
            locked=bool(locked and locked > now()),
            last_login=u.last_login,
            created_at=u.created_at,
        )

    def _issue(u: db.User) -> LoginOut:
        ttl = auth.s.session_ttl_seconds
        assert auth.s.session_secret is not None
        tok = session_token(
            auth.s.session_secret.get_secret_value(),
            u.username,
            u.role,
            list(u.tenants),
            ttl,
            auth.s.audience,
        )
        return LoginOut(
            access_token=tok,
            expires_in=ttl,
            user=MeOut(sub=u.username, roles=[u.role], tenants=sorted(u.tenants)),
        )

    def _require_local() -> None:
        if not local:
            raise HTTPException(404, "local accounts are not enabled")

    def _manageable(p: Principal, tenants: list[str]) -> bool:
        if "*" in p.tenants:
            return True
        return "*" not in tenants and set(tenants) <= set(p.tenants)

    async def _check_tenants(s: Any, tenants: list[str]) -> None:
        for t in set(tenants) - {"*"}:
            if not await s.get(db.Tenant, t):
                raise HTTPException(422, f"unknown tenant: {t}")

    async def _other_platform_admin(s: Any, username: str) -> bool:
        rows = (await s.execute(select(db.User))).scalars().all()
        return any(
            r.username != username and r.role == "admin" and not r.disabled and "*" in r.tenants
            for r in rows
        )

    def _is_platform_admin(u: db.User) -> bool:
        return u.role == "admin" and not u.disabled and "*" in u.tenants

    def _policy(password: str, username: str) -> None:
        problem = passwords.check_policy(password, username)
        if problem:
            raise HTTPException(422, problem)

    @app.post("/v1/auth/login", response_model=LoginOut, tags=["auth"])
    async def login(body: LoginIn) -> LoginOut:
        _require_local()
        username = body.username.strip().lower()
        bad = HTTPException(401, "Invalid username or password.")
        failure: HTTPException | None = None
        out: LoginOut | None = None
        async with db.tenant_session(sessions, "*") as s:
            u = await s.get(db.User, username)
            t = now()
            if u is None:
                passwords.verify_password(body.password, passwords.DUMMY_HASH)
                failure = bad
            else:
                locked = _aware(u.locked_until)
                ok = passwords.verify_password(body.password, u.password_hash)
                if locked and locked > t:
                    failure = HTTPException(429, "Account temporarily locked. Try again later.")
                elif not ok or u.disabled:
                    failure = bad
                    if not ok:
                        u.failed_attempts += 1
                        if u.failed_attempts >= MAX_FAILED_LOGINS:
                            u.locked_until, u.failed_attempts = t + LOCKOUT, 0
                else:
                    u.failed_attempts, u.locked_until, u.last_login = 0, None, t
                    out = _issue(u)
                who = Principal(username, frozenset(), frozenset())
                await audit(s, who, "*", "auth.login" if out else "auth.login_failed", username)
        if failure is not None:
            raise failure
        assert out is not None
        return out

    @app.post("/v1/auth/change-password", response_model=LoginOut, tags=["auth"])
    async def change_password(body: PasswordChangeIn, p: Principal = Depends(current)) -> LoginOut:
        _require_local()
        _policy(body.new_password, p.sub)
        async with db.tenant_session(sessions, "*") as s:
            u = await s.get(db.User, p.sub)
            assert u is not None
            if not passwords.verify_password(body.current_password, u.password_hash):
                raise HTTPException(403, "Current password is incorrect.")
            u.password_hash = passwords.hash_password(body.new_password)
            u.password_changed_at = now()
            await audit(s, p, "*", "user.password_change", u.username)
            await s.flush()
            return _issue(u)

    @app.get("/v1/users", response_model=list[UserOut], tags=["users"])
    async def list_users(p: Principal = Depends(admin)) -> list[UserOut]:
        _require_local()
        async with sessions() as s:
            rows = (await s.execute(select(db.User).order_by(db.User.username))).scalars().all()
        return [_user_out(u) for u in rows if _manageable(p, list(u.tenants))]

    @app.post("/v1/users", response_model=UserOut, status_code=201, tags=["users"])
    async def create_user(body: UserIn, p: Principal = Depends(admin)) -> UserOut:
        _require_local()
        if not _manageable(p, body.tenants):
            raise HTTPException(403, "you can only grant access to your own tenants")
        _policy(body.password, body.username)
        async with db.tenant_session(sessions, "*") as s:
            if await s.get(db.User, body.username):
                raise HTTPException(409, "username already exists")
            await _check_tenants(s, body.tenants)
            t = now()
            u = db.User(
                username=body.username,
                password_hash=passwords.hash_password(body.password),
                role=body.role,
                tenants=sorted(set(body.tenants)),
                display_name=body.display_name,
                disabled=False,
                failed_attempts=0,
                created_at=t,
                password_changed_at=t,
            )
            s.add(u)
            await audit(
                s, p, "*", "user.create", u.username, {"role": u.role, "tenants": u.tenants}
            )
            return _user_out(u)

    @app.patch("/v1/users/{username}", response_model=UserOut, tags=["users"])
    async def update_user(username: str, body: UserPatch, p: Principal = Depends(admin)) -> UserOut:
        _require_local()
        async with db.tenant_session(sessions, "*") as s:
            u = await s.get(db.User, username)
            if u is None or not _manageable(p, list(u.tenants)):
                raise HTTPException(404, "user not found")
            if username == p.sub and (
                body.disabled or body.role not in (None, u.role) or body.tenants is not None
            ):
                raise HTTPException(409, "you cannot disable or change the access of yourself")
            was_platform_admin = _is_platform_admin(u)
            if body.tenants is not None:
                if not _manageable(p, body.tenants):
                    raise HTTPException(403, "you can only grant access to your own tenants")
                await _check_tenants(s, body.tenants)
                u.tenants = sorted(set(body.tenants))
            if body.role is not None:
                u.role = body.role
            if body.display_name is not None:
                u.display_name = body.display_name
            if body.disabled is not None:
                u.disabled = body.disabled
            if body.unlock:
                u.locked_until, u.failed_attempts = None, 0
            if (
                was_platform_admin
                and not _is_platform_admin(u)
                and not await _other_platform_admin(s, username)
            ):
                raise HTTPException(409, "at least one enabled platform admin must remain")
            await audit(
                s,
                p,
                "*",
                "user.update",
                username,
                body.model_dump(exclude_none=True, exclude_defaults=True),
            )
            return _user_out(u)

    @app.post("/v1/users/{username}/password", status_code=204, tags=["users"])
    async def reset_password(
        username: str, body: PasswordResetIn, p: Principal = Depends(admin)
    ) -> None:
        _require_local()
        _policy(body.new_password, username)
        async with db.tenant_session(sessions, "*") as s:
            u = await s.get(db.User, username)
            if u is None or not _manageable(p, list(u.tenants)):
                raise HTTPException(404, "user not found")
            u.password_hash = passwords.hash_password(body.new_password)
            u.password_changed_at = now()
            u.locked_until, u.failed_attempts = None, 0
            await audit(s, p, "*", "user.password_reset", username)

    @app.delete("/v1/users/{username}", status_code=204, tags=["users"])
    async def delete_user(username: str, p: Principal = Depends(admin)) -> None:
        _require_local()
        if username == p.sub:
            raise HTTPException(409, "you cannot delete yourself")
        async with db.tenant_session(sessions, "*") as s:
            u = await s.get(db.User, username)
            if u is None or not _manageable(p, list(u.tenants)):
                raise HTTPException(404, "user not found")
            if _is_platform_admin(u) and not await _other_platform_admin(s, username):
                raise HTTPException(409, "at least one enabled platform admin must remain")
            await s.delete(u)
            await audit(s, p, "*", "user.delete", username)

    # ------------------------------------------------------------------ console support
    @app.get("/v1/me", response_model=MeOut, tags=["console"])
    async def me(p: Principal = Depends(current)) -> MeOut:
        return MeOut(sub=p.sub, roles=sorted(p.roles), tenants=sorted(p.tenants))

    @app.get("/v1/tenants/{tenant_id}/playbooks", response_model=list[str], tags=["remediation"])
    async def list_playbooks(tenant_id: str, p: Principal = Depends(viewer)) -> list[str]:
        return sorted(playbooks)

    @app.get(
        "/v1/tenants/{tenant_id}/remediations",
        response_model=list[RemediationOut],
        tags=["remediation"],
    )
    async def list_remediations(
        tenant_id: str, p: Principal = Depends(viewer)
    ) -> list[RemediationOut]:
        async with db.tenant_session(sessions, tenant_id) as s:
            rows = (
                (
                    await s.execute(
                        select(db.Remediation)
                        .where(db.Remediation.tenant_id == tenant_id)
                        .order_by(db.Remediation.id.desc())
                        .limit(200)
                    )
                )
                .scalars()
                .all()
            )
            return [_out(r, await _mode(s, tenant_id, r.failure_type)) for r in rows]

    async def _feedback(method: str, path: str, **kw: Any) -> Any:
        if feedback is None:
            raise HTTPException(503, "feedback service not configured")
        try:
            r = await feedback.request(method, path, **kw)
        except httpx.HTTPError as e:
            raise HTTPException(502, f"feedback service unreachable: {type(e).__name__}") from e
        if r.status_code >= 400:
            raise HTTPException(502, f"feedback service returned {r.status_code}")
        return r.json()

    inc.install(
        app,
        inc.Deps(
            sessions=sessions,
            viewer=viewer,
            operator=operator,
            now=now,
            audit=audit,
            feedback=_feedback,
            decrypt=_decrypt,
            vm=vm,
        ),
    )

    @app.get("/v1/tenants/{tenant_id}/kpis", tags=["console"])
    async def tenant_kpis(tenant_id: str, p: Principal = Depends(viewer)) -> Any:
        return await _feedback("GET", "/v1/kpis", params={"tenant_id": tenant_id})

    @app.post("/v1/tenants/{tenant_id}/incidents/{incident_key}/outcome", tags=["console"])
    async def label_incident(
        tenant_id: str, incident_key: str, body: OutcomeIn, p: Principal = Depends(operator)
    ) -> Any:
        pred = await _feedback("GET", f"/v1/predictions/{incident_key}")
        doc = {
            "incident_key": incident_key,
            "tenant_id": tenant_id,
            "failure_type": pred["failure_type"],
            "outcome": body.outcome,
            "actual_root_cause": body.actual_root_cause,
            "source": "api",
        }
        out = await _feedback("POST", "/v1/outcomes", json=doc)
        async with db.tenant_session(sessions, tenant_id) as s:
            await audit(s, p, tenant_id, "incident.label", incident_key, {"outcome": body.outcome})
        return out

    if console_dir is not None and console_dir.is_dir():
        cfg = console_config or {}

        @app.get("/console/config.json", include_in_schema=False)
        async def console_cfg() -> dict[str, Any]:
            return cfg

        if brand_dir is not None and brand_dir.is_dir():  # must precede the /console mount
            app.mount("/console/brand", StaticFiles(directory=brand_dir), name="brand")
        app.mount("/console", StaticFiles(directory=console_dir, html=True), name="console")

    return app
