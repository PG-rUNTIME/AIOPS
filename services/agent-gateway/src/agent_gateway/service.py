"""Agent gateway: candidate → bounded, validated investigation → Verdict."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field

import httpx
from prometheus_client import Counter, Histogram

from agent_gateway.budget import INFLIGHT, BudgetExceededError, TenantLimiter
from agent_gateway.investigators import InvestigationContext, Investigator
from agent_gateway.prompting import PROMPT_VERSION
from agent_gateway.runbooks import Retriever, Runbook
from agent_gateway.tools import ToolBackends, ToolBox
from agent_gateway.validation import validate
from aiops_common.bus import EventBus
from aiops_common.cloudevents import CloudEvent, make_event
from aiops_common.contracts.models import CandidateIncident, Verdict, VerdictStatus
from aiops_common.contracts.registry import Topics
from aiops_common.ids import stable_id
from aiops_common.logging import bind_context
from aiops_common.resilience import CircuitBreaker, CircuitOpenError

log = logging.getLogger(__name__)
SOURCE = "urn:aiops:agent-gateway"

VERDICTS = Counter("aiops_verdicts_total", "Verdicts by status", ["status"])
LATENCY = Histogram(
    "aiops_verdict_latency_seconds",
    "Candidate → verdict latency",
    buckets=(1, 5, 10, 20, 30, 45, 60, 90, 120),
)


@dataclass
class AgentGateway:
    bus: EventBus
    investigator: Investigator | None
    retriever: Retriever
    runbooks: dict[str, Runbook]
    limiter: TenantLimiter = field(default_factory=TenantLimiter)
    backends: ToolBackends = field(default_factory=ToolBackends)
    timeout_seconds: float = 90.0
    breaker: CircuitBreaker = field(
        default_factory=lambda: CircuitBreaker("llm", failure_threshold=3)
    )
    http: httpx.AsyncClient = field(default_factory=lambda: httpx.AsyncClient(timeout=15))
    toolbox_factory: Callable[[str], ToolBox] | None = None  # evals inject recorded tools

    async def on_event(self, ev: CloudEvent) -> None:
        cand = ev.payload(CandidateIncident)
        with bind_context(incident_key=cand.incident_key, tenant_id=cand.tenant_id):
            verdict = await self.handle(cand)
        VERDICTS.labels(verdict.status.value).inc()
        LATENCY.observe(verdict.latency_ms / 1000)
        await self.bus.publish(
            Topics.VERDICTS,
            make_event(
                verdict, source=SOURCE, event_id=stable_id(cand.incident_key, ev.id, prefix="vrd-")
            ),
        )

    def _fallback(
        self,
        c: CandidateIncident,
        status: VerdictStatus,
        reasons: list[str],
        t0: float,
        model_id: str = "none",
        tokens: int = 0,
    ) -> Verdict:
        """Degraded verdict built ONLY from detector facts; no LLM claims are carried over."""
        rb = next(
            (
                r.id
                for r in self.runbooks.values()
                if c.predicted_failure.split(" ")[0] in r.failure_types
            ),
            None,
        )
        return Verdict(
            incident_key=c.incident_key,
            tenant_id=c.tenant_id,
            ci_id=c.ci_id,
            status=status,
            is_incident=status is not VerdictStatus.RESOLVED,
            confidence=c.confidence,
            predicted_failure=c.predicted_failure,
            eta_minutes=c.eta_minutes,
            root_cause=(
                "Risk has passed; detectors are quiet."
                if status is VerdictStatus.RESOLVED
                else "Not verified by the AI agent: " + "; ".join(reasons)[:1500]
            ),
            evidence=[],
            recommended_actions=[],
            runbook_ref=rb,
            model_id=model_id,
            prompt_version=PROMPT_VERSION,
            downgrade_reasons=reasons,
            latency_ms=int((time.perf_counter() - t0) * 1000),
            tokens_used=tokens,
            candidate=c,
        )

    async def handle(self, c: CandidateIncident) -> Verdict:
        t0 = time.perf_counter()
        if c.resolved:
            return self._fallback(c, VerdictStatus.RESOLVED, [], t0)
        if self.investigator is None:
            return self._fallback(c, VerdictStatus.UNVERIFIED, ["LLM disabled"], t0)
        try:
            self.limiter.check(c.tenant_id)
        except BudgetExceededError as e:
            return self._fallback(c, VerdictStatus.UNVERIFIED, [str(e)], t0)

        ft = c.predicted_failure.split(" ")[0]
        text = " ".join(
            filter(None, [c.predicted_failure, *(s.template or s.metric or "" for s in c.signals)])
        )
        ctx = InvestigationContext(
            runbooks=await self.retriever.runbooks_for(ft, text),
            similar=await self.retriever.similar_incidents(ft, text),
            toolbox=(
                self.toolbox_factory(c.tenant_id)
                if self.toolbox_factory
                else ToolBox(self.backends, c.tenant_id, self.runbooks, self.http)
            ),
            max_tokens_remaining=self.limiter.remaining(c.tenant_id),
        )
        sem = self.limiter.semaphore(c.tenant_id)
        inv = self.investigator
        try:
            async with sem:
                INFLIGHT.labels(c.tenant_id).inc()
                try:
                    async with asyncio.timeout(self.timeout_seconds):
                        result = await self.breaker.call(lambda: inv.investigate(c, ctx))
                finally:
                    INFLIGHT.labels(c.tenant_id).dec()
        except TimeoutError:
            return self._fallback(
                c,
                VerdictStatus.UNVERIFIED,
                [f"LLM timed out after {self.timeout_seconds}s"],
                t0,
                inv.model_id,
            )
        except CircuitOpenError:
            return self._fallback(
                c, VerdictStatus.UNVERIFIED, ["LLM circuit open"], t0, inv.model_id
            )
        except Exception as e:
            log.warning("investigation failed", extra={"error": str(e)})
            return self._fallback(
                c, VerdictStatus.UNVERIFIED, [f"LLM error: {type(e).__name__}"], t0, inv.model_id
            )

        self.limiter.charge(c.tenant_id, result.tokens)
        out = validate(result.raw_output, result.tool_calls, c, set(self.runbooks))
        if out.verdict is None or out.status is VerdictStatus.NEEDS_HUMAN:
            return self._fallback(
                c, VerdictStatus.NEEDS_HUMAN, out.reasons, t0, result.model_id, result.tokens
            )
        v = out.verdict
        return Verdict(
            **v.model_dump(),
            incident_key=c.incident_key,
            tenant_id=c.tenant_id,
            ci_id=c.ci_id,
            status=out.status,
            model_id=result.model_id,
            prompt_version=PROMPT_VERSION,
            downgrade_reasons=out.reasons,
            latency_ms=int((time.perf_counter() - t0) * 1000),
            tokens_used=result.tokens,
            candidate=c,
        )
