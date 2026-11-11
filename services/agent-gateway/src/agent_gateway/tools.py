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

from agent_gateway.datasources import DataSources
from agent_gateway.runbooks import Runbook
from aiops_common.redaction import redact_str

MAX_RESULT_CHARS = 4000

SOURCE_PROP = {
    "type": "string",
    "description": (
        "Name of a registered data source (see list_data_sources). "
        "Omit to use the platform's built-in store."
    ),
}

TOOL_SPECS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "prometheus_query",
            "description": "Run an instant PromQL query against VictoriaMetrics. Read-only.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "PromQL expression"},
                    "source": SOURCE_PROP,
                },
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
                    "source": SOURCE_PROP,
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
                    "source": SOURCE_PROP,
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_data_sources",
            "description": "List the log, metric and dashboard systems registered for this tenant.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "logs_query",
            "description": (
                "Search logs in a registered log source (Loki LogQL, VictoriaLogs LogsQL or "
                "Elasticsearch/OpenSearch query-string syntax) over the last N minutes; "
                "at most 50 lines."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "source": {"type": "string", "description": "Registered log source name."},
                    "query": {"type": "string"},
                    "minutes": {"type": "integer", "minimum": 1, "maximum": 360},
                },
                "required": ["source", "query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "dashboard_search",
            "description": "Find dashboards by title in a registered Grafana source.",
            "parameters": {
                "type": "object",
                "properties": {
                    "source": {"type": "string", "description": "Registered Grafana source name."},
                    "query": {"type": "string", "description": "Title text; empty lists recent."},
                },
                "required": ["source", "query"],
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
        sources: DataSources | None = None,
    ) -> None:
        self.b, self.tenant, self.runbooks, self.http = backends, tenant, runbooks, client
        self.sources = sources

    async def _source(self, args: dict[str, Any], op: str) -> dict[str, Any] | str | None:
        """Resolve ``args['source']``: a source row, an error string, or None if not requested."""
        name = args.get("source")
        if not name:
            return None
        if self.sources is None:
            return json.dumps({"error": "no registered data sources are available"})
        rows = await self.sources.list(self.tenant)
        usable = [r for r in rows if op in r["ops"]]
        for r in usable:
            if str(name).lower() in (r["name"].lower(), r["id"]):
                return r
        names = ", ".join(r["name"] for r in usable) or "none"
        return json.dumps({"error": f"unknown source '{name}' for this query; available: {names}"})

    async def _via(self, args: dict[str, Any], op: str, query: str, minutes: int) -> str | None:
        src = await self._source(args, op)
        if src is None:
            return None
        if isinstance(src, str):
            return src
        assert self.sources is not None
        return _clip(await self.sources.query(self.tenant, src["id"], op, query, minutes))

    def _vm(self) -> str:
        base = self.b.vm_url.rstrip("/")
        return f"{base}/select/{self.tenant}/prometheus" if self.b.vm_tenant_path else base

    async def list_data_sources(self, args: dict[str, Any]) -> str:
        if self.sources is None:
            return "No registered data sources. Use the built-in tools without `source`."
        rows = await self.sources.list(self.tenant)
        if not rows:
            return "No registered data sources. Use the built-in tools without `source`."
        return _clip(
            "\n".join(
                f"{r['name']} | {r['kind']} | {r['category']} | ops: {', '.join(r['ops'])}"
                for r in rows
            )
        )

    async def logs_query(self, args: dict[str, Any]) -> str:
        out = await self._via(args, "logs", str(args["query"]), int(args.get("minutes", 30)))
        return out or json.dumps({"error": "source is required"})

    async def dashboard_search(self, args: dict[str, Any]) -> str:
        out = await self._via(args, "dashboards", str(args["query"]), 1)
        return out or json.dumps({"error": "source is required"})

    async def prometheus_query(self, args: dict[str, Any]) -> str:
        routed = await self._via(args, "instant", str(args["query"]), 1)
        if routed is not None:
            return routed
        r = await self.http.get(f"{self._vm()}/api/v1/query", params={"query": args["query"]})
        return _clip(r.text)

    async def prometheus_range_query(self, args: dict[str, Any]) -> str:
        routed = await self._via(args, "range", str(args["query"]), int(args.get("minutes", 30)))
        if routed is not None:
            return routed
        end = time.time()
        start = end - 60 * int(args.get("minutes", 30))
        r = await self.http.get(
            f"{self._vm()}/api/v1/query_range",
            params={"query": args["query"], "start": start, "end": end, "step": 60},
        )
        return _clip(r.text)

    async def loki_query(self, args: dict[str, Any]) -> str:
        routed = await self._via(args, "logs", str(args["query"]), int(args.get("minutes", 30)))
        if routed is not None:
            return routed
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
