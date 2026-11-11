from __future__ import annotations

import httpx

from mock_servicenow.app import create_app


async def test_mock_servicenow_flows() -> None:
    app = create_app()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://x") as c:
        rec = {
            "node": "CI-1",
            "severity": "2",
            "message_key": "k1",
            "description": "d",
            "additional_info": "{}",
        }
        assert (await c.post("/api/global/em/jsonv2", json={"records": [rec]})).status_code == 200
        assert (await c.post("/api/global/em/jsonv2", json={"records": [rec]})).status_code == 200
        st = (await c.get("/mock/state")).json()
        assert len(st["incidents"]) == 1
        await c.post("/api/global/em/jsonv2", json={"records": [rec | {"severity": "0"}]})
        assert (await c.get("/mock/state")).json()["incidents"][0]["state"] == "6"
        await c.post("/mock/fail", params={"count": 1})
        assert (await c.get("/api/now/table/incident")).status_code == 503
        await c.post("/mock/em", params={"enabled": False})
        assert (await c.post("/api/global/em/jsonv2", json={"records": []})).status_code == 403
        r = await c.post(
            "/api/now/table/incident", json={"short_description": "x", "correlation_id": "k2"}
        )
        sys_id = r.json()["result"]["sys_id"]
        assert (
            await c.get("/api/now/table/incident", params={"sysparm_query": "correlation_id=k2"})
        ).json()["result"]
        assert (
            await c.patch(f"/api/now/table/incident/{sys_id}", json={"work_notes": "n"})
        ).status_code == 200
        assert (await c.patch("/api/now/table/incident/nope", json={})).status_code == 404
        assert (await c.post("/mock/reset")).status_code == 204
        assert (await c.get("/healthz")).status_code == 200
