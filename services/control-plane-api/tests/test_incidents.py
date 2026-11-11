"""Incident workflow, the investigation workspace and the chart series."""

from __future__ import annotations

import json
import time

import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import create_async_engine

from control_plane import datasource_query as dq
from control_plane import db
from control_plane.app import create_app
from control_plane.auth import Authenticator, AuthSettings, dev_token
from control_plane.incidents import base_query, primary_signal, workflow_of
from control_plane.remediation import DryRunExecutor

SECRET = "dev-secret-for-tests-only-0123456789"
KEY = "inc-0123456789abcdef"


def tok(sub: str, role: str, tenants: list[str]) -> dict[str, str]:
    return {"Authorization": f"Bearer {dev_token(SECRET, sub, [role], tenants)}"}


ADMIN, OPER, OPER2 = (
    tok("root", "admin", ["*"]),
    tok("olga", "operator", ["bank"]),
    tok("omar", "operator", ["bank"]),
)
VIEW, OTHER = tok("vi", "viewer", ["bank"]), tok("eve", "operator", ["other"])

SIGNALS = [
    {"signal_id": "a", "metric": "m", "query": "up", "score": 0.5, "eta_minutes": None},
    {
        "signal_id": "b",
        "metric": "1 - avail / size",
        "query": 'predict_linear((1 - avail{ci_id="X"} / size{ci_id="X"})[15m:15s], 900)',
        "score": 0.9,
        "eta_minutes": 12.0,
        "threshold": 0.98,
        "forecast": {"p10": 0.9, "p50": 0.95, "p90": 0.99},
        "labels": {},
        "ts": "2026-11-11T10:00:00Z",
    },
]


CURRENT: dict[str, object] = {"signals": SIGNALS, "ci": "X"}


def feedback_handler(req: httpx.Request) -> httpx.Response:
    if req.url.path == "/v1/incidents":
        return httpx.Response(200, json=[{"incident_key": KEY, "ci_id": "X", "tenant_id": "bank"}])
    if req.url.path == f"/v1/incidents/{KEY}" and req.url.params["tenant_id"] == "bank":
        view = {
            "incident_key": KEY,
            "ci_id": CURRENT["ci"],
            "tenant_id": "bank",
            "eta_minutes": 12.0,
        }
        detail = {"signals": CURRENT["signals"], "events": []}
        return httpx.Response(200, json={"view": view, "detail": detail})
    return httpx.Response(404, json={"detail": "nope"})


def vm_handler(req: httpx.Request) -> httpx.Response:
    assert "predict_linear" not in req.url.params["query"]  # the chart plots the series itself
    now = time.time()
    values = [[now - 60 * i, str(0.5 + 0.01 * (30 - i))] for i in range(30, 0, -1)]
    return httpx.Response(200, json={"data": {"result": [{"metric": {}, "values": values}]}})


@pytest.fixture
async def env():  # type: ignore[no-untyped-def]
    CURRENT.update(signals=SIGNALS, ci="X")
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as c:
        await c.run_sync(db.Base.metadata.create_all)
    auth = Authenticator(AuthSettings(mode="dev", dev_secret=SecretStr(SECRET)), "dev")
    fb = httpx.AsyncClient(transport=httpx.MockTransport(feedback_handler), base_url="http://fb")
    vm = httpx.AsyncClient(transport=httpx.MockTransport(vm_handler), base_url="http://vm")
    app = create_app(engine, auth, DryRunExecutor(), {"clean_tmp.yml"}, feedback=fb, vm=vm)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://x") as c:
        for t in ("bank", "other"):
            await c.post("/v1/tenants", json={"id": t, "name": t}, headers=ADMIN)
        yield c
    await engine.dispose()


def test_helpers() -> None:
    assert base_query("predict_linear((a / b)[15m:15s], 900)") == "a / b"
    assert base_query("up") == "up"
    assert primary_signal({"signals": SIGNALS})["signal_id"] == "b"  # type: ignore[index]
    assert primary_signal({"signals": []}) is None and primary_signal(None) is None
    assert workflow_of([])["state"] == "new"


async def test_workflow_lifecycle_and_audit(env) -> None:  # type: ignore[no-untyped-def]
    c = env
    base = f"/v1/tenants/bank/incidents/{KEY}"
    assert (await c.get("/v1/tenants/bank/incidents", headers=VIEW)).json()[0]["workflow"][
        "state"
    ] == "new"
    w = (await c.post(f"{base}/ack", headers=OPER)).json()
    assert w["state"] == "acknowledged" and w["acknowledged_by"] == "olga"
    w = (await c.post(f"{base}/assign", json={"assignee": "omar"}, headers=OPER)).json()
    assert w["assignee"] == "omar" and w["state"] == "acknowledged"
    assert (
        await c.post(f"{base}/notes", json={"text": "Looking at logs"}, headers=OPER2)
    ).status_code == 200
    w = (await c.post(f"{base}/resolve", json={"resolution": "Cleared tmp"}, headers=OPER2)).json()
    assert (
        w["state"] == "resolved" and w["resolved_by"] == "omar" and w["resolution"] == "Cleared tmp"
    )
    assert (await c.get("/v1/tenants/bank/incidents", headers=VIEW)).json()[0]["workflow"][
        "state"
    ] == "resolved"
    w = (await c.post(f"{base}/reopen", headers=OPER)).json()
    assert w["state"] == "acknowledged" and w["resolved_by"] is None
    # the workspace shows everything in order, and every action is in the audit log
    ws = (await c.get(base, headers=VIEW)).json()
    assert [a["kind"] for a in ws["activity"]] == ["ack", "assign", "note", "resolve", "reopen"]
    assert ws["activity"][2]["detail"]["text"] == "Looking at logs"
    actions = [a["action"] for a in (await c.get("/v1/tenants/bank/audit", headers=VIEW)).json()]
    assert {
        "incident.ack",
        "incident.assign",
        "incident.note",
        "incident.resolve",
        "incident.reopen",
    } <= set(actions)


async def test_permissions_and_isolation(env) -> None:  # type: ignore[no-untyped-def]
    c = env
    base = f"/v1/tenants/bank/incidents/{KEY}"
    for verb in ("ack", "reopen"):
        assert (await c.post(f"{base}/{verb}", headers=VIEW)).status_code == 403
    assert (await c.post(f"{base}/notes", json={"text": "x"}, headers=VIEW)).status_code == 403
    assert (await c.post(f"{base}/ack", headers=OTHER)).status_code == 403  # wrong tenant
    assert (await c.get(base, headers=OTHER)).status_code == 403
    assert (
        await c.post("/v1/tenants/bank/incidents/nope/ack", headers=OPER)
    ).status_code == 502  # unknown incident
    assert (await c.post(f"{base}/notes", json={"text": ""}, headers=OPER)).status_code == 422
    assert (
        await c.post(f"{base}/notes", json={"text": "x" * 2001}, headers=OPER)
    ).status_code == 422
    # a tenant admin of another tenant cannot read this incident through their own path either
    assert (await c.get(f"/v1/tenants/other/incidents/{KEY}", headers=OTHER)).status_code == 502


async def test_series_uses_the_unwrapped_query_and_reports_gaps(env) -> None:  # type: ignore[no-untyped-def]
    c = env
    r = (await c.get(f"/v1/tenants/bank/incidents/{KEY}/series", headers=VIEW)).json()
    assert r["available"] and r["threshold"] == 0.98 and len(r["points"]) == 30
    assert r["eta_minutes"] == 12.0 and r["source"] == "Built-in metric store"
    assert "predict_linear" not in r["query"]


async def test_series_from_a_registered_source_and_when_it_is_gone(env, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    c = env
    src = dict(
        SIGNALS[1], labels={"source": "Prod Prom"}, query='avail{mountpoint="/",source="Prod Prom"}'
    )
    CURRENT.update(signals=[src], ci="host1:9100")
    seen: list[tuple[str, str]] = []

    async def fake_run(t, op, query, minutes=30, **kw):  # type: ignore[no-untyped-def]
        seen.append((t.url, query))
        now = time.time()
        return json.dumps({"data": {"result": [{"values": [[now - 60, "0.5"], [now, "0.6"]]}]}})

    monkeypatch.setattr(dq, "run", fake_run)
    url = f"/v1/tenants/bank/incidents/{KEY}/series"
    # the source is not registered (any more): say so instead of failing
    r = (await c.get(url, headers=VIEW)).json()
    assert r["available"] is False and "no longer available" in r["reason"]
    cid = (
        await c.post(
            "/v1/tenants/bank/connections",
            json={"name": "Prod Prom", "kind": "prometheus", "url": "http://10.0.0.5:9090"},
            headers=ADMIN,
        )
    ).json()["id"]
    r = (await c.get(url, headers=VIEW)).json()
    assert r["available"] and r["source"] == "Prod Prom" and len(r["points"]) == 2
    # the polled host is identified by its instance label, and the source label is not sent upstream
    assert seen == [("http://10.0.0.5:9090", 'avail{mountpoint="/",instance="host1:9100"}')]
    body = {
        "name": "Prod Prom",
        "kind": "prometheus",
        "url": "http://10.0.0.5:9090",
        "enabled": False,
    }
    await c.put(f"/v1/tenants/bank/connections/{cid}", json=body, headers=ADMIN)
    assert (await c.get(url, headers=VIEW)).json()["available"] is False


async def test_series_when_the_incident_has_no_metric_signal(env) -> None:  # type: ignore[no-untyped-def]
    c = env
    CURRENT.update(signals=[{"signal_id": "log", "template": "oom", "metric": None}])
    r = (await c.get(f"/v1/tenants/bank/incidents/{KEY}/series", headers=VIEW)).json()
    assert r["available"] is False and "no metric signal" in r["reason"]


async def test_assignees_lists_people_who_can_act_on_the_tenant(env) -> None:  # type: ignore[no-untyped-def]
    c = env
    assert (await c.get("/v1/tenants/bank/assignees", headers=VIEW)).status_code == 403
    assert (
        await c.get("/v1/tenants/bank/assignees", headers=OPER)
    ).json() == []  # dev mode: no local users
