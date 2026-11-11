"""In-process pipeline harness with a simulated clock.

Wires every custom service on the in-memory bus, a fake OpenAI-compatible
LLM + fake VictoriaMetrics behind ``httpx.MockTransport`` (so the real tool
loop and evidence check run), and the router delivering to the mock
ServiceNow ASGI app through the real ServiceNow adapter.
"""

from __future__ import annotations

import json
import random
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from agent_gateway.investigators import OpenAIToolLoopInvestigator
from agent_gateway.runbooks import KeywordRetriever, load_past_incidents, load_runbooks
from agent_gateway.service import AgentGateway
from agent_gateway.tools import ToolBackends
from aiops_common.bus import InMemoryBus, Subscription
from aiops_common.cloudevents import make_event
from aiops_common.contracts.models import CandidateIncident, Verdict
from aiops_common.contracts.registry import Topics
from aiops_common.resilience import CircuitBreaker
from chaos_sim.scenarios import DEMO_HOSTS, Scenario, sample
from correlator.core import Correlator
from detector_workers.worker import DetectorWorker
from mock_servicenow.app import create_app
from router.adapters import ServiceNowAdapter, ServiceNowConfig
from router.db import create_schema
from router.service import Dispatcher, Router

ROOT = Path(__file__).resolve().parents[2]
RUNBOOKS = ROOT / "config" / "runbooks"
FAILURE_RUNBOOK = {
    "disk_full": "RB-DISK-001",
    "memory_exhaustion": "RB-MEM-001",
    "cpu_saturation": "RB-CPU-001",
    "connection_pool_exhaustion": "RB-DBPOOL-001",
    "interface_flap": "RB-NET-001",
    "error_spike": "RB-ERR-001",
}


@dataclass
class FakeLLM:
    """OpenAI Chat Completions + VictoriaMetrics instant query, deterministic."""

    mode: str = "good"  # good | hallucinate | garbage | down
    calls: int = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "/api/v1/query" in url:
            q = request.url.params.get("query", "")
            ci = re.search(r'ci_id="([^"]+)"', q)
            return httpx.Response(
                200,
                json={
                    "status": "success",
                    "data": {
                        "resultType": "vector",
                        "result": [
                            {
                                "metric": {"ci_id": ci.group(1) if ci else "?"},
                                "value": [1731300000, "0.9731"],
                            }
                        ],
                    },
                },
            )
        if "/loki/" in url:
            return httpx.Response(200, json={"data": {"result": []}})
        if url.endswith("/chat/completions"):
            self.calls += 1
            if self.mode == "down":
                return httpx.Response(503, json={"error": "overloaded"})
            body = json.loads(request.content)
            msgs = body["messages"]
            user = next(m["content"] for m in msgs if m["role"] == "user")
            brief = json.loads(
                user.split("CANDIDATE INCIDENT:\n", 1)[1].split("\n\nRELEVANT", 1)[0]
            )
            query = next(
                (
                    s["query"]
                    for s in brief["signals"]
                    if s["query"] and s["detector"] != "log_template"
                ),
                brief["signals"][0]["query"],
            )
            ft = brief["predicted_failure"].split(" ")[0]
            has_tool_result = any(m["role"] == "tool" for m in msgs)
            if "tools" in body and not has_tool_result and self.mode != "garbage":
                return httpx.Response(
                    200,
                    json={
                        "choices": [
                            {
                                "message": {
                                    "role": "assistant",
                                    "content": None,
                                    "tool_calls": [
                                        {
                                            "id": "t1",
                                            "type": "function",
                                            "function": {
                                                "name": "prometheus_query",
                                                "arguments": json.dumps({"query": query}),
                                            },
                                        }
                                    ],
                                }
                            }
                        ],
                        "usage": {"total_tokens": 900},
                    },
                )
            if self.mode == "garbage":
                content = "I think the disk is probably fine, no JSON for you."
            else:
                cited = query if self.mode == "good" else 'rate(made_up_metric{ci_id="X"}[5m])'
                content = json.dumps(
                    {
                        "is_incident": True,
                        "confidence": 0.88,
                        "predicted_failure": ft,
                        "eta_minutes": brief["eta_minutes"],
                        "root_cause": f"{ft} on {brief['ci_id']}: steady growth towards threshold.",
                        "evidence": [
                            {"query": cited, "excerpt": f"ci_id {brief['ci_id']} value 0.9731"}
                        ],
                        "recommended_actions": [
                            "Follow the runbook",
                            "Open a change if capacity is needed",
                        ],
                        "runbook_ref": FAILURE_RUNBOOK.get(ft),
                    }
                )
            return httpx.Response(
                200,
                json={
                    "choices": [{"message": {"role": "assistant", "content": content}}],
                    "usage": {"total_tokens": 400},
                },
            )
        return httpx.Response(404)


@dataclass
class Pipeline:
    llm_mode: str = "good"
    start: datetime = field(default_factory=lambda: datetime(2026, 11, 11, 6, 0, tzinfo=UTC))
    bus: InMemoryBus = field(default_factory=InMemoryBus)
    now: datetime = field(init=False)

    async def setup(self) -> None:
        self.now = self.start
        self.fake = FakeLLM(self.llm_mode)
        llm_http = httpx.AsyncClient(transport=httpx.MockTransport(self.fake.handler))
        self.sn_app = create_app()
        sn_http = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.sn_app), base_url="http://sn"
        )
        self.engine: AsyncEngine = create_async_engine("sqlite+aiosqlite:///:memory:")
        await create_schema(self.engine)

        self.detector = DetectorWorker(self.bus, clock=lambda: self.now.timestamp())
        self.correlator = Correlator(self.bus)
        runbooks = load_runbooks(RUNBOOKS)
        self.agent = AgentGateway(
            self.bus,
            OpenAIToolLoopInvestigator("http://llm/v1", "fake-model", None, llm_http),
            KeywordRetriever(runbooks, load_past_incidents(RUNBOOKS / "past_incidents.yaml")),
            runbooks,
            backends=ToolBackends("http://vm", "http://loki"),
            http=llm_http,
            breaker=CircuitBreaker("llm", failure_threshold=100),
        )
        self.router = Router(self.engine, clock=lambda: self.now)
        sn = ServiceNowAdapter(
            ServiceNowConfig(instance_url="http://sn", username="u", password="p"),  # type: ignore[arg-type]
            sn_http,
            CircuitBreaker("sn", failure_threshold=1000, reset_after=0),
        )
        self.dispatcher = Dispatcher(
            self.engine,
            lambda t, ch: sn if ch == "servicenow" else _Sink(ch),
            self.bus,
            clock=lambda: self.now,
            base_backoff=1.0,
        )
        b = self.bus
        b.subscribe(Subscription([Topics.METRICS, Topics.LOGS], "detector", self.detector.on_event))
        b.subscribe(
            Subscription([Topics.SIGNALS, Topics.CHANGES], "correlator", self.correlator.on_event)
        )
        b.subscribe(Subscription([Topics.CANDIDATES], "agent", self.agent.on_event, max_retries=0))
        b.subscribe(Subscription([Topics.VERDICTS], "router", self.router.on_event))

    async def step(self, scenario: Scenario | None, rng: random.Random) -> None:
        for h in DEMO_HOSTS:
            mb, lb = sample(h, self.now, scenario, rng)
            await self.bus.publish(Topics.METRICS, make_event(mb, source="urn:test"))
            if lb:
                await self.bus.publish(Topics.LOGS, make_event(lb, source="urn:test"))
        await self.bus.run_until_idle()
        await self.correlator.tick(self.now)
        await self.bus.run_until_idle()
        await self.dispatcher.run_once()
        self.now += timedelta(seconds=15)

    async def run(self, scenario: Scenario, until: datetime, seed: int = 3) -> None:
        rng = random.Random(seed)
        while self.now < until:
            await self.step(scenario, rng)

    @property
    def sn_state(self) -> dict[str, Any]:
        return self.sn_app.state.mock  # type: ignore[no-any-return]

    @property
    def sn(self) -> dict[str, Any]:
        st = self.sn_state
        return {"events": st["events"], "incidents": list(st["incidents"].values())}

    async def ticket_sent_at(self) -> list[datetime]:
        """Simulated time at which each ServiceNow open delivery succeeded."""
        from sqlalchemy import select

        from router.db import OutboxRow

        async with self.engine.connect() as c:
            rows = (
                (
                    await c.execute(
                        select(OutboxRow.sent_at).where(
                            OutboxRow.channel == "servicenow",
                            OutboxRow.action == "open",
                            OutboxRow.status == "sent",
                        )
                    )
                )
                .scalars()
                .all()
            )
        return [r.replace(tzinfo=UTC) if r.tzinfo is None else r for r in rows if r]

    def candidates(self) -> list[CandidateIncident]:
        return [e.payload(CandidateIncident) for e in self.bus.log[Topics.CANDIDATES]]

    def verdicts(self) -> list[Verdict]:
        return [e.payload(Verdict) for e in self.bus.log[Topics.VERDICTS]]


@dataclass
class _Sink:
    channel: str
    name: str = "sink"
    sent: list[str] = field(default_factory=list)

    async def send(self, row: Any) -> str:
        self.sent.append(row.id)
        return f"{self.channel}:ok"
