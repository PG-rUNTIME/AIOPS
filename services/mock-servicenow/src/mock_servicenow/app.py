"""Mock ServiceNow for dev and tests: Event Management jsonv2 + incident Table API.

Mimics "event rule auto-creates an incident" for severities 1-3 (one incident
per ``message_key``) and resolves it on a severity-0 Clear. Failure injection:
``POST /mock/fail?count=3&status=503`` makes the next N calls fail;
``POST /mock/em?enabled=false`` makes jsonv2 return 403 (EM not licensed).
"""

from __future__ import annotations

import itertools
import json
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response


def create_app() -> FastAPI:
    app = FastAPI(title="mock-servicenow")
    state: dict[str, Any] = {
        "events": [],
        "incidents": {},
        "fail": 0,
        "fail_status": 503,
        "em_enabled": True,
    }
    seq = itertools.count(1)

    def maybe_fail() -> None:
        if state["fail"] > 0:
            state["fail"] -= 1
            raise HTTPException(state["fail_status"], "injected failure")

    def new_incident(fields: dict[str, Any]) -> dict[str, Any]:
        n = next(seq)
        inc = {
            "sys_id": f"sys{n:06d}",
            "number": f"INC{n:07d}",
            "state": "1",
            "work_notes": [],
            **fields,
        }
        state["incidents"][inc["sys_id"]] = inc
        return inc

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/global/em/jsonv2")
    async def em(request: Request) -> dict[str, Any]:
        maybe_fail()
        if not state["em_enabled"]:
            raise HTTPException(403, "User Not Authorized")
        body = await request.json()
        for rec in body.get("records", []):
            if isinstance(rec.get("additional_info"), str):
                json.loads(rec["additional_info"])  # must be valid JSON
            state["events"].append(rec)
            key = rec.get("message_key")
            existing = next(
                (i for i in state["incidents"].values() if i.get("correlation_id") == key), None
            )
            sev = str(rec.get("severity"))
            if sev in {"1", "2", "3"} and existing is None:
                new_incident(
                    {
                        "short_description": rec.get("description", "")[:160],
                        "description": rec.get("description"),
                        "cmdb_ci": rec.get("node"),
                        "correlation_id": key,
                        "severity": sev,
                        "source": "em",
                    }
                )
            elif sev == "0" and existing is not None:
                existing["state"] = "6"
        return {
            "result": {
                "Default Bulk Endpoint": f"{len(body.get('records', []))} events were inserted"
            }
        }

    @app.get("/api/now/table/incident")
    async def list_incidents(sysparm_query: str = "", sysparm_limit: int = 100) -> dict[str, Any]:
        maybe_fail()
        rows = list(state["incidents"].values())
        if sysparm_query.startswith("correlation_id="):
            key = sysparm_query.split("=", 1)[1]
            rows = [r for r in rows if r.get("correlation_id") == key]
        return {"result": rows[:sysparm_limit]}

    @app.post("/api/now/table/incident", status_code=201)
    async def create_incident(request: Request) -> dict[str, Any]:
        maybe_fail()
        return {"result": new_incident({**(await request.json()), "source": "table"})}

    @app.patch("/api/now/table/incident/{sys_id}")
    async def patch_incident(sys_id: str, request: Request) -> dict[str, Any]:
        maybe_fail()
        inc = state["incidents"].get(sys_id)
        if inc is None:
            raise HTTPException(404, "not found")
        body = await request.json()
        if "work_notes" in body:
            inc["work_notes"].append(body.pop("work_notes"))
        inc.update(body)
        return {"result": inc}

    @app.get("/mock/state")
    async def dump() -> dict[str, Any]:
        return {"events": state["events"], "incidents": list(state["incidents"].values())}

    @app.post("/mock/fail")
    async def fail(count: int = 1, status: int = 503) -> dict[str, int]:
        state["fail"], state["fail_status"] = count, status
        return {"fail": count}

    @app.post("/mock/em")
    async def em_toggle(enabled: bool = True) -> dict[str, bool]:
        state["em_enabled"] = enabled
        return {"em_enabled": enabled}

    @app.post("/mock/reset")
    async def reset() -> Response:
        state.update(events=[], incidents={}, fail=0, em_enabled=True)
        return Response(status_code=204)

    app.state.mock = state
    return app
