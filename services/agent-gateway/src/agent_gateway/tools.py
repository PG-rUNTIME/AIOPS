"""Read-only investigation tools exposed to the LLM (OpenAI tool-calling format).

Every tool is a GET-style query. Results are PII-redacted and truncated before
they reach the model. Tenant isolation: VictoriaMetrics cluster path
``/select/<accountID>/prometheus`` and Loki ``X-Scope-OrgID``.
"""

from __future__ import annotations

import json
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import httpx

from agent_gateway.runbooks import Runbook
from aiops_common.redaction import redact_str

MAX_RESULT_CHARS = 4000

TOOL_SPECS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "prometheus_query",
            "description": "Run an instant PromQL query against VictoriaMetrics. Read-only.",
            "parameters": {
                "type": "object",
                "properties": {"query": {"type": "string", "description": "PromQL expression"}},
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "prometheus_range_query",
            "description": "Run a PromQL range query over the last N minutes (step 60s).",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "minutes": {"type": "integer", "minimum": 1, "maximum": 360},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "loki_query",
            "description": "Run a LogQL query over the last N minutes; returns at most 50 lines.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": 'LogQL, e.g. {ci_id="X"} |= "error"',
                    },
                    "minutes": {"type": "integer", "minimum": 1, "maximum": 360},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_runbook",
            "description": "Fetch the full text of a runbook by id.",
            "parameters": {
                "type": "object",
                "properties": {"runbook_id": {"type": "string"}},
                "required": ["runbook_id"],
            },
        },
    },
]


@dataclass
class ToolBackends:
    vm_url: str = (
        "http://victoriametrics:8428"  # single-node; cluster: .../select/{tenant}/prometheus
    )
    loki_url: str = "http://loki:3100"
    vm_tenant_path: bool = False


ToolFn = Callable[[dict[str, Any]], Awaitable[str]]


def _clip(s: str) -> str:
    s = redact_str(s)
    return s if len(s) <= MAX_RESULT_CHARS else s[:MAX_RESULT_CHARS] + "…[truncated]"


class ToolBox:
    def __init__(
        self,
        backends: ToolBackends,
        tenant: str,
        runbooks: dict[str, Runbook],
        client: httpx.AsyncClient,
    ) -> None:
        self.b, self.tenant, self.runbooks, self.http = backends, tenant, runbooks, client

    def _vm(self) -> str:
        base = self.b.vm_url.rstrip("/")
        return f"{base}/select/{self.tenant}/prometheus" if self.b.vm_tenant_path else base

    async def prometheus_query(self, args: dict[str, Any]) -> str:
        r = await self.http.get(f"{self._vm()}/api/v1/query", params={"query": args["query"]})
        return _clip(r.text)

    async def prometheus_range_query(self, args: dict[str, Any]) -> str:
        end = time.time()
        start = end - 60 * int(args.get("minutes", 30))
        r = await self.http.get(
            f"{self._vm()}/api/v1/query_range",
            params={"query": args["query"], "start": start, "end": end, "step": 60},
        )
        return _clip(r.text)

    async def loki_query(self, args: dict[str, Any]) -> str:
        end = time.time_ns()
        start = end - int(args.get("minutes", 30)) * 60 * 10**9
        r = await self.http.get(
            f"{self.b.loki_url.rstrip('/')}/loki/api/v1/query_range",
            params={"query": args["query"], "start": start, "end": end, "limit": 50},
            headers={"X-Scope-OrgID": self.tenant},
        )
        try:
            data = r.json()["data"]["result"]
            lines = [v[1] for stream in data for v in stream["values"]]
            return _clip("\n".join(lines) or "(no lines)")
        except (KeyError, ValueError, TypeError):
            return _clip(r.text)

    async def get_runbook(self, args: dict[str, Any]) -> str:
        rb = self.runbooks.get(str(args.get("runbook_id")))
        return _clip(f"# {rb.id} {rb.title}\n{rb.body}") if rb else "runbook not found"

    async def call(self, name: str, args: dict[str, Any]) -> str:
        fn: ToolFn | None = getattr(self, name, None) if name in _ALLOWED else None
        if fn is None:
            return json.dumps({"error": f"unknown tool {name}"})
        try:
            return await fn(args)
        except (httpx.HTTPError, KeyError) as e:
            return json.dumps({"error": f"{type(e).__name__}: {e}"})


_ALLOWED = {t["function"]["name"] for t in TOOL_SPECS}
