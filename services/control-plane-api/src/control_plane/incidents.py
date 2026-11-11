"""Incident workflow and the investigation view.

* Workflow (acknowledge, assign, notes, resolve, reopen) is stored here, append-only, and
  audited. The prediction itself (what/when/why) stays in the feedback service.
* The workspace endpoint merges both with the remediation requests for the incident.
* The series endpoint returns the metric behind the primary signal so the page can draw it
  against its threshold; it reads from the registered source the signal came from, or from the
  platform's built-in metric store.
"""

from __future__ import annotations

import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx
from fastapi import Depends, FastAPI
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from control_plane import datasource_query as dq
from control_plane import db
from control_plane.auth import Principal

Dep = Callable[..., Awaitable[Principal]]
WORKFLOW_KINDS = ("ack", "assign", "resolve", "reopen")
_PREDICT = re.compile(r"^predict_linear\(\((.*)\)\[\d+[smh]:\d+[smh]\], \d+\)$", re.S)


class NoteIn(BaseModel):
    text: str = Field(min_length=1, max_length=2000)


class AssignIn(BaseModel):
    assignee: str | None = Field(None, max_length=64)  # None unassigns


class ResolveIn(BaseModel):
    resolution: str | None = Field(None, max_length=2000)


@dataclass
class Deps:
    sessions: async_sessionmaker[Any]
    viewer: Dep
    operator: Dep
    now: Callable[[], datetime]
    audit: Callable[..., Awaitable[None]]
    feedback: Callable[..., Awaitable[Any]]
    decrypt: Callable[[db.Connection], str | None]
    vm: httpx.AsyncClient | None = None


def _iso(ts: datetime) -> str:
    return (ts if ts.tzinfo else ts.replace(tzinfo=UTC)).astimezone(UTC).isoformat()


def workflow_of(acts: list[db.IncidentActivity]) -> dict[str, Any]:
    """Fold the activity log into the current workflow state."""
    w: dict[str, Any] = {
        "state": "new",
        "assignee": None,
        "acknowledged_by": None,
        "acknowledged_at": None,
        "resolved_by": None,
        "resolved_at": None,
        "resolution": None,
    }
    for a in acts:
        if a.kind == "ack" and w["state"] != "resolved":
            w.update(state="acknowledged", acknowledged_by=a.actor, acknowledged_at=_iso(a.ts))
        elif a.kind == "assign":
            w["assignee"] = (a.detail or {}).get("assignee")
            if w["state"] == "new":
                w.update(state="acknowledged", acknowledged_by=a.actor, acknowledged_at=_iso(a.ts))
        elif a.kind == "resolve":
            w.update(
                state="resolved",
                resolved_by=a.actor,
                resolved_at=_iso(a.ts),
                resolution=(a.detail or {}).get("resolution"),
            )
        elif a.kind == "reopen":
            w.update(
                state="acknowledged" if w["acknowledged_by"] else "new",
                resolved_by=None,
                resolved_at=None,
                resolution=None,
            )
    return w


def base_query(q: str) -> str:
    """The detector's trend signals wrap the series in predict_linear: unwrap it for charting."""
    m = _PREDICT.match(q.strip())
    return m.group(1) if m else q


def primary_signal(detail: dict[str, Any] | None) -> dict[str, Any] | None:
    sigs = [s for s in (detail or {}).get("signals", []) if s.get("metric") and s.get("query")]
    if not sigs:
        return None
    # prefer the signal that carries an ETA, then the highest score
    best: dict[str, Any] = max(
        sigs, key=lambda s: (s.get("eta_minutes") is not None, s.get("score", 0))
    )
    return best


def _points(text: str) -> list[list[float]]:
    import json

    try:
        result = json.loads(text)["data"]["result"]
        values = result[0]["values"] if result else []
        return [[float(t), float(v)] for t, v in values if v not in ("NaN", "+Inf", "-Inf")]
    except (KeyError, ValueError, TypeError, IndexError):
        return []


def install(app: FastAPI, d: Deps) -> None:
    base = "/v1/tenants/{tenant_id}/incidents"

    async def _acts(s: Any, tenant: str, key: str | None = None) -> list[db.IncidentActivity]:
        q = select(db.IncidentActivity).where(db.IncidentActivity.tenant_id == tenant)
        if key is not None:
            q = q.where(db.IncidentActivity.incident_key == key)
        rows = (
            await s.execute(q.order_by(db.IncidentActivity.ts, db.IncidentActivity.id))
        ).scalars()
        return list(rows)

    async def _incident(tenant: str, key: str) -> dict[str, Any]:
        found: dict[str, Any] = await d.feedback(
            "GET", f"/v1/incidents/{key}", params={"tenant_id": tenant}
        )
        return found

    @app.get(base, tags=["console"])
    async def list_incidents(tenant_id: str, p: Principal = Depends(d.viewer)) -> Any:
        rows: list[dict[str, Any]] = await d.feedback(
            "GET", "/v1/incidents", params={"tenant_id": tenant_id, "limit": 200}
        )
        async with db.tenant_session(d.sessions, tenant_id) as s:
            acts = await _acts(s, tenant_id)
        by: dict[str, list[db.IncidentActivity]] = {}
        for a in acts:
            if a.kind in WORKFLOW_KINDS:
                by.setdefault(a.incident_key, []).append(a)
        for r in rows:
            r["workflow"] = workflow_of(by.get(r["incident_key"], []))
        return rows

    @app.get(base + "/{incident_key}", tags=["console"])
    async def workspace(tenant_id: str, incident_key: str, p: Principal = Depends(d.viewer)) -> Any:
        found = await _incident(tenant_id, incident_key)
        async with db.tenant_session(d.sessions, tenant_id) as s:
            acts = await _acts(s, tenant_id, incident_key)
            rems = (
                await s.execute(
                    select(db.Remediation)
                    .where(
                        db.Remediation.tenant_id == tenant_id,
                        db.Remediation.incident_key == incident_key,
                    )
                    .order_by(db.Remediation.created_at)
                )
            ).scalars()
            remediations = [
                {
                    "id": r.id,
                    "playbook": r.playbook,
                    "status": r.status,
                    "requested_by": r.requested_by,
                    "approved_by": r.approved_by,
                    "result": r.result,
                    "created_at": _iso(r.created_at),
                }
                for r in rems
            ]
        activity = [
            {"ts": _iso(a.ts), "actor": a.actor, "kind": a.kind, "detail": a.detail or {}}
            for a in acts
        ]
        return {
            "incident": found["view"],
            "detail": found.get("detail"),
            "workflow": workflow_of([a for a in acts if a.kind in WORKFLOW_KINDS]),
            "activity": activity,
            "remediations": remediations,
        }

    @app.get(base + "/{incident_key}/series", tags=["console"])
    async def series(
        tenant_id: str, incident_key: str, minutes: int = 90, p: Principal = Depends(d.viewer)
    ) -> Any:
        minutes = max(10, min(minutes, 360))
        found = await _incident(tenant_id, incident_key)
        sig = primary_signal(found.get("detail"))
        if sig is None:
            return {"available": False, "reason": "This incident has no metric signal to chart."}
        query = base_query(sig["query"])
        source = (sig.get("labels") or {}).get("source")
        text: str | None = None
        label = "Built-in metric store"
        if source:
            # series polled from a registered source: identify the host by its instance label
            query = re.sub(r'source="[^"]*"', f'instance="{found["view"]["ci_id"]}"', query)
            async with db.tenant_session(d.sessions, tenant_id) as s:
                conn = (
                    await s.execute(
                        select(db.Connection).where(
                            db.Connection.tenant_id == tenant_id, db.Connection.name == source
                        )
                    )
                ).scalar_one_or_none()
                target = (
                    dq.Target(
                        conn.kind,
                        conn.url,
                        conn.auth_type,
                        conn.username,
                        conn.header_name,
                        d.decrypt(conn),
                        conn.verify_tls,
                        {k: str(v) for k, v in (conn.extra or {}).items()},
                    )
                    if conn is not None and conn.enabled
                    else None
                )
            if target is None:
                return {"available": False, "reason": f"Source '{source}' is no longer available."}
            label = source
            try:
                text = await dq.run(target, "range", query, minutes)
            except dq.QueryError as e:
                return {"available": False, "reason": e.message}
        elif d.vm is not None:
            end = time.time()
            try:
                r = await d.vm.get(
                    "/api/v1/query_range",
                    params={"query": query, "start": end - minutes * 60, "end": end, "step": 60},
                )
                text = r.text if r.status_code < 400 else None
            except httpx.HTTPError:
                text = None
        pts = _points(text) if text else []
        if not pts:
            return {"available": False, "reason": "No data points were found for this series."}
        fc = sig.get("forecast")
        return {
            "available": True,
            "metric": sig["metric"],
            "query": query,
            "source": label,
            "threshold": sig.get("threshold"),
            "points": pts,
            "now": time.time(),
            "eta_minutes": found["view"].get("eta_minutes"),
            "forecast": fc,
            "signal_ts": sig.get("ts"),
            "failure_type": sig.get("failure_type"),
        }

    # ------------------------------------------------------------------ workflow actions
    async def _act(
        tenant: str, key: str, p: Principal, kind: str, detail: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        await _incident(tenant, key)  # 404 if it does not exist for this tenant
        async with db.tenant_session(d.sessions, tenant) as s:
            s.add(
                db.IncidentActivity(
                    tenant_id=tenant,
                    incident_key=key,
                    ts=d.now(),
                    actor=p.sub,
                    kind=kind,
                    detail=detail or {},
                )
            )
            await d.audit(s, p, tenant, f"incident.{kind}", key, detail)
            await s.flush()
            acts = await _acts(s, tenant, key)
        return workflow_of([a for a in acts if a.kind in WORKFLOW_KINDS])

    @app.post(base + "/{incident_key}/ack", tags=["console"])
    async def ack(tenant_id: str, incident_key: str, p: Principal = Depends(d.operator)) -> Any:
        return await _act(tenant_id, incident_key, p, "ack")

    @app.post(base + "/{incident_key}/assign", tags=["console"])
    async def assign(
        tenant_id: str, incident_key: str, body: AssignIn, p: Principal = Depends(d.operator)
    ) -> Any:
        return await _act(tenant_id, incident_key, p, "assign", {"assignee": body.assignee})

    @app.post(base + "/{incident_key}/notes", tags=["console"])
    async def note(
        tenant_id: str, incident_key: str, body: NoteIn, p: Principal = Depends(d.operator)
    ) -> Any:
        return await _act(tenant_id, incident_key, p, "note", {"text": body.text})

    @app.post(base + "/{incident_key}/resolve", tags=["console"])
    async def resolve(
        tenant_id: str, incident_key: str, body: ResolveIn, p: Principal = Depends(d.operator)
    ) -> Any:
        return await _act(tenant_id, incident_key, p, "resolve", {"resolution": body.resolution})

    @app.post(base + "/{incident_key}/reopen", tags=["console"])
    async def reopen(tenant_id: str, incident_key: str, p: Principal = Depends(d.operator)) -> Any:
        return await _act(tenant_id, incident_key, p, "reopen")

    @app.get("/v1/tenants/{tenant_id}/assignees", tags=["console"])
    async def assignees(tenant_id: str, p: Principal = Depends(d.operator)) -> Any:
        async with d.sessions() as s:
            users = (await s.execute(select(db.User).where(db.User.disabled.is_(False)))).scalars()
            return [
                {"username": u.username, "display_name": u.display_name, "role": u.role}
                for u in users
                if u.role != "viewer" and ("*" in u.tenants or tenant_id in u.tenants)
            ]
