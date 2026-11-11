"""Dev-only service: simulates demo hosts in real time and injects failures on demand.

* ``GET /metrics``  – Prometheus exposition of every simulated series (scraped by
  Alloy into VictoriaMetrics, so vmalert ``predict_linear`` rules see them).
* pushes MetricBatch/LogBatch JSON to ingest-gateway every tick.
* pushes log lines to Loki's push API so they are queryable by the agent.
* ``POST /scenarios/{name}?ci_id=..&fail_in_minutes=..`` starts a scenario.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random
from datetime import UTC, datetime

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Response

from aiops_common.config import ServiceSettings
from aiops_common.logging import setup_logging
from chaos_sim.scenarios import SCENARIOS, Scenario, hosts_for, sample

log = logging.getLogger("chaos-sim")


class Settings(ServiceSettings):
    service_name: str = "chaos-sim"
    tenant_id: str  # the tenant the simulated estate reports as (AIOPS_TENANT_ID)
    tick_seconds: float = 15.0
    ingest_url: str | None = "http://ingest-gateway:8080"
    ingest_api_key: str | None = None
    loki_url: str | None = "http://loki:3100"


class Sim:
    def __init__(self, s: Settings) -> None:
        self.s = s
        self.hosts = hosts_for(s.tenant_id)
        self.rng = random.Random(42)
        self.active: Scenario | None = None
        self.last: dict[str, dict[str, float]] = {}
        self.http = httpx.AsyncClient(timeout=5)

    def _check(self, r: httpx.Response, ci_id: str) -> None:
        if r.status_code >= 300:  # never drop telemetry silently
            log.warning("ingest rejected push", extra={"status": r.status_code, "ci_id": ci_id})

    async def tick(self) -> None:
        now = datetime.now(UTC)
        for h in self.hosts:
            mb, lb = sample(h, now, self.active, self.rng)
            self.last[h.ci_id] = {p.name: p.value for p in mb.points}
            headers = {"X-AIOps-Tenant": h.tenant_id, "Content-Type": "application/json"}
            if self.s.ingest_api_key:
                headers["Authorization"] = f"Bearer {self.s.ingest_api_key}"
            with contextlib.suppress(httpx.HTTPError):
                if self.s.ingest_url:
                    r = await self.http.post(
                        f"{self.s.ingest_url}/v1/aiops/metrics",
                        content=mb.model_dump_json(),
                        headers=headers,
                    )
                    self._check(r, h.ci_id)
                    if lb:
                        r = await self.http.post(
                            f"{self.s.ingest_url}/v1/aiops/logs",
                            content=lb.model_dump_json(),
                            headers=headers,
                        )
                        self._check(r, h.ci_id)
                if lb and self.s.loki_url:
                    await self.http.post(
                        f"{self.s.loki_url}/loki/api/v1/push",
                        headers={"X-Scope-OrgID": h.tenant_id},
                        json={
                            "streams": [
                                {
                                    "stream": {
                                        "ci_id": h.ci_id,
                                        "service": h.service,
                                        "job": "chaos-sim",
                                    },
                                    "values": [
                                        [str(int(r.ts.timestamp() * 1e9)), f"{r.severity} {r.body}"]
                                        for r in lb.records
                                    ],
                                }
                            ]
                        },
                    )
        if self.active and now > self.active.fail_at:
            log.info("scenario reached failure point", extra={"scenario": self.active.name})

    def exposition(self) -> str:
        lines = []
        hosts = {h.ci_id: h for h in self.hosts}
        for ci, metrics in self.last.items():
            h = hosts[ci]
            for name, v in metrics.items():
                extra = ',mountpoint="/"' if name.startswith("node_filesystem") else ""
                lines.append(
                    f'{name}{{ci_id="{ci}",service="{h.service}",'
                    f'tenant_id="{h.tenant_id}"{extra}}} {v}'
                )
        return "\n".join(lines) + "\n"


def build(s: Settings) -> tuple[FastAPI, Sim]:
    sim = Sim(s)
    app = FastAPI(title="chaos-sim")

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz() -> dict[str, str]:
        return {"status": "ready"}

    @app.get("/metrics")
    async def metrics() -> Response:
        return Response(sim.exposition(), media_type="text/plain; version=0.0.4")

    @app.post("/scenarios/{name}")
    async def start(
        name: str, ci_id: str = "CI-CORE-DB-01", fail_in_minutes: float = 20
    ) -> dict[str, str]:
        if name not in SCENARIOS:
            raise HTTPException(404, f"scenario must be one of {SCENARIOS}")
        host = next((h for h in sim.hosts if h.ci_id == ci_id), None)
        if host is None:
            raise HTTPException(404, "unknown ci_id")
        sim.active = Scenario(name, host, datetime.now(UTC), fail_after_s=fail_in_minutes * 60)
        return {"scenario": name, "ci_id": ci_id, "fail_at": sim.active.fail_at.isoformat()}

    @app.delete("/scenarios")
    async def stop() -> dict[str, str]:
        sim.active = None
        return {"status": "stopped"}

    return app, sim


async def _run(s: Settings) -> None:
    app, sim = build(s)
    server = uvicorn.Server(
        uvicorn.Config(app, host=s.http_host, port=s.http_port, log_config=None)
    )

    async def loop() -> None:
        while not server.should_exit:
            await sim.tick()
            await asyncio.sleep(s.tick_seconds)

    await asyncio.gather(server.serve(), loop())


def main() -> None:
    s = Settings()
    setup_logging(s.service_name, s.log_level)
    asyncio.run(_run(s))


if __name__ == "__main__":
    main()
