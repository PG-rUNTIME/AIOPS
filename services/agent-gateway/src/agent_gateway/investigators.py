"""LLM investigators behind one interface.

* ``OpenAIToolLoopInvestigator`` — any OpenAI-compatible Chat Completions
  endpoint (vLLM serving Qwen, Ollama, OpenAI, or a hosted gateway). The
  gateway runs the read-only tools itself, so the evidence check sees exactly
  what was executed.
* ``HolmesInvestigator`` — HolmesGPT HTTP server ``POST /api/investigate``
  (fields per the HolmesGPT HTTP API reference: source, title, description,
  subject, context, include_tool_calls; response: analysis, tool_calls[]).
* ``ReplayInvestigator`` — recorded outputs, for tests and the eval suite.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

from agent_gateway.prompting import system_prompt, user_prompt
from agent_gateway.runbooks import PastIncident, Runbook
from agent_gateway.tools import TOOL_SPECS, ToolBox
from agent_gateway.validation import ToolCall
from aiops_common.contracts.models import CandidateIncident

log = logging.getLogger(__name__)


@dataclass
class InvestigationResult:
    raw_output: str
    tool_calls: list[ToolCall]
    tokens: int
    model_id: str


@dataclass
class InvestigationContext:
    runbooks: list[Runbook]
    similar: list[PastIncident]
    toolbox: ToolBox | None
    max_tokens_remaining: int


class Investigator(Protocol):
    @property
    def model_id(self) -> str: ...

    async def investigate(
        self, c: CandidateIncident, ctx: InvestigationContext
    ) -> InvestigationResult: ...


@dataclass
class OpenAIToolLoopInvestigator:
    base_url: str
    model: str
    api_key: str | None
    client: httpx.AsyncClient
    max_steps: int = 6
    max_output_tokens: int = 1500
    json_mode: bool = True
    extra_headers: dict[str, str] = field(default_factory=dict)

    @property
    def model_id(self) -> str:
        return self.model

    async def _chat(self, messages: list[dict[str, Any]], tools: bool) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": 0,
            "max_tokens": self.max_output_tokens,
        }
        if tools:
            body["tools"] = TOOL_SPECS
            body["tool_choice"] = "auto"
        elif self.json_mode:
            body["response_format"] = {"type": "json_object"}
        headers = dict(self.extra_headers)
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        r = await self.client.post(
            f"{self.base_url.rstrip('/')}/chat/completions", json=body, headers=headers
        )
        r.raise_for_status()
        data: dict[str, Any] = r.json()
        return data

    async def investigate(
        self, c: CandidateIncident, ctx: InvestigationContext
    ) -> InvestigationResult:
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system_prompt()},
            {"role": "user", "content": user_prompt(c, ctx.runbooks, ctx.similar)},
        ]
        calls: list[ToolCall] = []
        tokens = 0
        for step in range(self.max_steps):
            last = step == self.max_steps - 1 or tokens >= ctx.max_tokens_remaining
            data = await self._chat(messages, tools=not last and ctx.toolbox is not None)
            tokens += int(data.get("usage", {}).get("total_tokens", 0))
            msg = data["choices"][0]["message"]
            tcs = msg.get("tool_calls") or []
            if not tcs:
                return InvestigationResult(msg.get("content") or "", calls, tokens, self.model)
            messages.append({"role": "assistant", "content": msg.get("content"), "tool_calls": tcs})
            for tc in tcs:
                fn = tc["function"]["name"]
                try:
                    args = json.loads(tc["function"].get("arguments") or "{}")
                except json.JSONDecodeError:
                    args = {}
                assert ctx.toolbox is not None
                result = await ctx.toolbox.call(fn, args)
                calls.append(
                    ToolCall(fn, args.get("query") or args.get("runbook_id"), result, args)
                )
                messages.append({"role": "tool", "tool_call_id": tc["id"], "content": result})
        messages.append({"role": "user", "content": "Return the final JSON verdict now."})
        data = await self._chat(messages, tools=False)
        tokens += int(data.get("usage", {}).get("total_tokens", 0))
        return InvestigationResult(
            data["choices"][0]["message"].get("content") or "", calls, tokens, self.model
        )


@dataclass
class HolmesInvestigator:
    base_url: str
    client: httpx.AsyncClient
    model: str | None = None

    @property
    def model_id(self) -> str:
        return f"holmesgpt:{self.model or 'default'}"

    async def investigate(
        self, c: CandidateIncident, ctx: InvestigationContext
    ) -> InvestigationResult:
        body: dict[str, Any] = {
            "source": "aiops-platform",
            "title": f"[{c.tenant_id}] {c.predicted_failure} predicted on {c.ci_id}",
            "description": system_prompt() + "\n\n" + user_prompt(c, ctx.runbooks, ctx.similar),
            "subject": {"ci_id": c.ci_id, "service": c.service, "tenant_id": c.tenant_id},
            "context": {"incident_key": c.incident_key},
            "include_tool_calls": True,
        }
        if self.model:
            body["model"] = self.model
        r = await self.client.post(f"{self.base_url.rstrip('/')}/api/investigate", json=body)
        r.raise_for_status()
        data = r.json()
        calls = [
            ToolCall(
                str(t.get("tool_name", "")),
                str(t.get("description") or ""),
                str(t.get("result") or "")[:8000],
            )
            for t in data.get("tool_calls") or []
        ]
        return InvestigationResult(str(data.get("analysis", "")), calls, 0, self.model_id)


@dataclass
class ReplayInvestigator:
    """Returns recorded outputs keyed by incident_key (or ``*`` for any)."""

    recordings: dict[str, InvestigationResult]
    model_id: str = "replay"

    async def investigate(
        self, c: CandidateIncident, ctx: InvestigationContext
    ) -> InvestigationResult:
        rec = self.recordings.get(c.incident_key) or self.recordings.get("*")
        if rec is None:
            raise RuntimeError(f"no recording for {c.incident_key}")
        return rec
