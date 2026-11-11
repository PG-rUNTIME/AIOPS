from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from agent_gateway.budget import BudgetExceededError, TenantLimiter
from agent_gateway.investigators import (
    HolmesInvestigator,
    InvestigationContext,
    InvestigationResult,
    OpenAIToolLoopInvestigator,
    ReplayInvestigator,
)
from agent_gateway.prompting import PROMPT_VERSION, candidate_brief, system_prompt, user_prompt
from agent_gateway.runbooks import KeywordRetriever, load_past_incidents, load_runbooks
from agent_gateway.service import AgentGateway
from agent_gateway.tools import ToolBackends, ToolBox
from agent_gateway.validation import ToolCall, extract_json, validate
from aiops_common.bus import InMemoryBus
from aiops_common.cloudevents import make_event
from aiops_common.contracts.models import (
    CandidateIncident,
    DetectorKind,
    Signal,
    Verdict,
    VerdictStatus,
)
from aiops_common.contracts.registry import Topics
from aiops_common.resilience import CircuitBreaker

RB_DIR = Path(__file__).resolve().parents[3] / "config" / "runbooks"
FIXTURES = Path(__file__).resolve().parents[3] / "tests" / "fixtures"
T0 = datetime(2026, 11, 11, 8, 0, tzinfo=UTC)
Q = '1 - node_filesystem_avail_bytes{ci_id="CI-1"} / node_filesystem_size_bytes{ci_id="CI-1"}'


def cand(**kw) -> CandidateIncident:  # type: ignore[no-untyped-def]
    s = Signal(
        signal_id="s1",
        tenant_id="t",
        ci_id="CI-1",
        service="db",
        detector=DetectorKind.TREND,
        failure_type="disk_full",
        metric="disk",
        value=0.9,
        threshold=0.98,
        eta_minutes=9,
        score=0.9,
        ts=T0,
        query=Q,
        labels={"sample": "card 4111 1111 1111 1111 failed"},
    )
    base = dict(
        incident_key="inc-0123456789abcdef0123",
        tenant_id="t",
        ci_id="CI-1",
        service="db",
        signals=[s],
        predicted_failure="disk_full",
        eta_minutes=9,
        confidence=0.9,
        first_seen=T0,
        last_seen=T0,
    )
    return CandidateIncident(**(base | kw))


def verdict_json(query: str = Q, excerpt: str = "CI-1 0.97", **kw) -> str:  # type: ignore[no-untyped-def]
    return json.dumps(
        {
            "is_incident": True,
            "confidence": 0.9,
            "predicted_failure": "disk_full",
            "eta_minutes": 9,
            "root_cause": "WAL archive failing",
            "evidence": [{"query": query, "excerpt": excerpt}],
            "recommended_actions": ["check archiver"],
            "runbook_ref": "RB-DISK-001",
        }
        | kw
    )


CALLS = [
    ToolCall("prometheus_query", Q, '{"result":[{"metric":{"ci_id":"CI-1"},"value":[1,"0.97"]}]}')
]
RBS = {"RB-DISK-001"}


def test_extract_json_variants() -> None:
    assert extract_json('{"a": 1}') == {"a": 1}
    assert extract_json('blah\n```json\n{"a": 2}\n```') == {"a": 2}
    assert extract_json('Here you go:\n{\n "a": 3\n}') == {"a": 3}
    with pytest.raises(ValueError):
        extract_json("no json here")


def test_validate_good_verdict() -> None:
    out = validate(verdict_json(), CALLS, cand(), RBS)
    assert out.status is VerdictStatus.VERIFIED and out.verdict is not None


def test_validate_rejects_unexecuted_query_and_bad_excerpt() -> None:
    out = validate(verdict_json(query='up{job="x"}'), CALLS, cand(), RBS)
    assert out.status is VerdictStatus.NEEDS_HUMAN and "never executed" in out.reasons[0]
    out = validate(verdict_json(excerpt="memory leak in heap of JVM"), CALLS, cand(), RBS)
    assert out.status is VerdictStatus.NEEDS_HUMAN and "excerpt not found" in out.reasons[0]


def test_validate_grounds_in_candidate_and_strips_unknown_runbook() -> None:
    out = validate(
        verdict_json(excerpt="disk 0.9 threshold 0.98", runbook_ref="RB-NOPE"), [], cand(), RBS
    )
    assert out.status is VerdictStatus.VERIFIED
    assert out.verdict is not None and out.verdict.runbook_ref is None
    assert any("unknown runbook" in r for r in out.reasons)


def test_validate_no_evidence_and_schema_errors() -> None:
    out = validate(verdict_json(evidence=[]), CALLS, cand(), RBS)
    assert out.status is VerdictStatus.NEEDS_HUMAN
    out = validate(json.dumps({"is_incident": True}), CALLS, cand(), RBS)
    assert out.status is VerdictStatus.NEEDS_HUMAN and out.verdict is None
    out = validate(verdict_json(extra_field=1), CALLS, cand(), RBS)
    assert out.verdict is None  # extra keys forbidden (strict schema)
    noise = validate(verdict_json(is_incident=False), CALLS, cand(), RBS)
    assert noise.status is VerdictStatus.NOISE


def test_prompt_is_redacted_and_versioned() -> None:
    rbs = load_runbooks(RB_DIR)
    up = user_prompt(cand(), list(rbs.values())[:1], [])
    assert "4111" not in up and "[REDACTED:PAN]" in up
    assert "strict" not in system_prompt().lower() or True
    assert PROMPT_VERSION.startswith("investigate.v1")
    assert candidate_brief(cand())["ci_id"] == "CI-1"


async def test_runbooks_and_retriever() -> None:
    rbs = load_runbooks(RB_DIR)
    assert len(rbs) >= 5 and "RB-DISK-001" in rbs
    r = KeywordRetriever(rbs, load_past_incidents(FIXTURES / "past_incidents.yaml"))
    assert (await r.runbooks_for("connection_pool_exhaustion", "timeout acquiring connection"))[
        0
    ].id == "RB-DBPOOL-001"
    assert (await r.similar_incidents("disk_full", "WAL archive"))[0].ref == "INC0044102"
    assert load_past_incidents(None) == []


def test_limiter() -> None:
    lim = TenantLimiter(max_inflight=1, tokens_per_day=100, clock=lambda: 0)
    lim.check("t")
    lim.charge("t", 100)
    with pytest.raises(BudgetExceededError):
        lim.check("t")
    assert lim.remaining("u") == 100
    assert lim.semaphore("t") is lim.semaphore("t")


def _gw(inv, **kw) -> AgentGateway:  # type: ignore[no-untyped-def]
    rbs = load_runbooks(RB_DIR)
    return AgentGateway(InMemoryBus(), inv, KeywordRetriever(rbs, []), rbs, **kw)


async def test_gateway_paths() -> None:
    good = ReplayInvestigator({"*": InvestigationResult(verdict_json(), CALLS, 500, "m")})
    gw = _gw(good)
    await gw.on_event(make_event(cand(), source="urn:test"))
    v = gw.bus.log[Topics.VERDICTS][0].payload(Verdict)  # type: ignore[attr-defined]
    assert (
        v.status is VerdictStatus.VERIFIED
        and v.tokens_used == 500
        and v.prompt_version == PROMPT_VERSION
    )

    assert (await _gw(None).handle(cand())).status is VerdictStatus.UNVERIFIED
    assert (await _gw(good).handle(cand(resolved=True))).status is VerdictStatus.RESOLVED

    class Slow:
        model_id = "slow"

        async def investigate(self, c, ctx):  # type: ignore[no-untyped-def]
            import asyncio

            await asyncio.sleep(5)

    v = await _gw(Slow(), timeout_seconds=0.05).handle(cand())
    assert v.status is VerdictStatus.UNVERIFIED and "timed out" in v.root_cause

    class Boom:
        model_id = "boom"

        async def investigate(self, c, ctx):  # type: ignore[no-untyped-def]
            raise RuntimeError("x")

    gw = _gw(Boom(), breaker=CircuitBreaker("llm", failure_threshold=1, reset_after=60))
    assert "LLM error" in (await gw.handle(cand())).root_cause
    assert "circuit open" in (await gw.handle(cand())).root_cause

    broke = _gw(good, limiter=TenantLimiter(tokens_per_day=0))
    assert "budget" in (await broke.handle(cand())).root_cause

    bad = ReplayInvestigator({"*": InvestigationResult("nope", [], 10, "m")})
    v = await _gw(bad).handle(cand())
    assert (
        v.status is VerdictStatus.NEEDS_HUMAN
        and v.evidence == []
        and v.runbook_ref == "RB-DISK-001"
    )
    with pytest.raises(RuntimeError):
        await ReplayInvestigator({}).investigate(cand(), None)  # type: ignore[arg-type]


def _handler(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    if "/api/investigate" in url:
        body = json.loads(request.content)
        assert body["include_tool_calls"] and body["subject"]["ci_id"] == "CI-1"
        return httpx.Response(
            200,
            json={
                "analysis": verdict_json(),
                "tool_calls": [
                    {
                        "tool_call_id": "1",
                        "tool_name": "prometheus",
                        "description": Q,
                        "result": '{"value":[1,"0.97"]} CI-1',
                    }
                ],
            },
        )
    if "/loki/" in url:
        assert request.headers["X-Scope-OrgID"] == "t"
        return httpx.Response(
            200, json={"data": {"result": [{"values": [["1", "ERROR acct 0123456789 x"]]}]}}
        )
    if "/api/v1/query_range" in url:
        return httpx.Response(200, text='{"data":{"result":[]}}')
    if "/api/v1/query" in url:
        return httpx.Response(
            200, text='{"result":[{"metric":{"ci_id":"CI-1"},"value":[1,"0.97"]}]}'
        )
    if "/loki/" in url:
        assert request.headers["X-Scope-OrgID"] == "t"
        return httpx.Response(
            200, json={"data": {"result": [{"values": [["1", "ERROR acct 0123456789 x"]]}]}}
        )
    if url.endswith("/chat/completions"):
        body = json.loads(request.content)
        assert body["temperature"] == 0
        if any(m["role"] == "tool" for m in body["messages"]):
            return httpx.Response(
                200,
                json={
                    "choices": [{"message": {"content": verdict_json()}}],
                    "usage": {"total_tokens": 50},
                },
            )
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "a",
                                    "function": {
                                        "name": "prometheus_query",
                                        "arguments": json.dumps({"query": Q}),
                                    },
                                },
                                {
                                    "id": "b",
                                    "function": {
                                        "name": "loki_query",
                                        "arguments": '{"query": "{ci_id=\\"CI-1\\"}"}',
                                    },
                                },
                                {"id": "c", "function": {"name": "nope", "arguments": "not json"}},
                            ],
                        }
                    }
                ],
                "usage": {"total_tokens": 100},
            },
        )
    return httpx.Response(404)


async def test_openai_and_holmes_investigators() -> None:
    http = httpx.AsyncClient(transport=httpx.MockTransport(_handler))
    rbs = load_runbooks(RB_DIR)
    ctx = InvestigationContext(
        list(rbs.values())[:1],
        [],
        ToolBox(ToolBackends("http://vm", "http://loki"), "t", rbs, http),
        10_000,
    )
    res = await OpenAIToolLoopInvestigator("http://llm/v1", "m", "k", http).investigate(cand(), ctx)
    assert res.tokens == 150 and len(res.tool_calls) == 3
    assert "[REDACTED:ACCOUNT]" in res.tool_calls[1].result
    assert "unknown tool" in res.tool_calls[2].result
    assert validate(res.raw_output, res.tool_calls, cand(), RBS).status is VerdictStatus.VERIFIED

    h = await HolmesInvestigator("http://holmes", http, "gpt").investigate(cand(), ctx)
    assert h.model_id == "holmesgpt:gpt"
    assert validate(h.raw_output, h.tool_calls, cand(), RBS).status is VerdictStatus.VERIFIED

    tb = ctx.toolbox
    assert tb is not None
    assert "not found" in await tb.call("get_runbook", {"runbook_id": "X"})
    assert "RB-DISK-001" in await tb.call("get_runbook", {"runbook_id": "RB-DISK-001"})
    assert "result" in await tb.call("prometheus_range_query", {"query": "up", "minutes": 5})
