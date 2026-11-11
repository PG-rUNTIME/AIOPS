from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from chaos_sim.main import Settings, build
from chaos_sim.scenarios import DEMO_HOSTS, SCENARIOS, Scenario, sample

T0 = datetime(2026, 11, 11, 8, 0, tzinfo=UTC)


@pytest.mark.parametrize("name", SCENARIOS)
def test_scenarios_progress_to_failure(name: str) -> None:
    host = DEMO_HOSTS[4] if name == "interface_flap" else DEMO_HOSTS[0]
    sc = Scenario(name, host, T0, fail_after_s=600)
    rng = random.Random(0)
    mb, _ = sample(host, T0 + timedelta(seconds=599), sc, rng)
    vals = {p.name: p.value for p in mb.points}
    if name == "disk_fill":
        assert vals["node_filesystem_avail_bytes"] < 0.01 * host.disk_size
    if name == "memory_leak":
        assert vals["node_memory_MemAvailable_bytes"] < 0.01 * host.mem_total
    assert sc.progress(T0 + timedelta(hours=1)) == 1.0
    with pytest.raises(ValueError):
        Scenario("nope", host, T0)


async def test_api() -> None:
    app, sim = build(Settings(tenant_id="acme", ingest_url=None, loki_url=None))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://x") as c:
        assert (
            await c.post("/scenarios/disk_fill", params={"ci_id": "CI-CORE-DB-01"})
        ).status_code == 200
        assert (await c.post("/scenarios/nope")).status_code == 404
        assert (await c.post("/scenarios/disk_fill", params={"ci_id": "X"})).status_code == 404
        await sim.tick()
        text = (await c.get("/metrics")).text
        assert 'node_filesystem_avail_bytes{ci_id="CI-CORE-DB-01"' in text
        assert 'tenant_id="acme"' in text  # reports as the configured tenant
        assert (await c.delete("/scenarios")).json()["status"] == "stopped"
        assert (await c.get("/healthz")).status_code == 200
        assert (await c.get("/readyz")).status_code == 200
