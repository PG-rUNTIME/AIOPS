"""LLM eval harness over recorded incidents (``evals/incidents/*.json``).

Modes
* replay (default, CI on every change): the recorded model output and tool
  results go through the real agent-gateway path (validation, evidence check,
  runbook registry, fallback). Catches prompt/runbook/validator regressions.
* live (``AIOPS_EVAL_LIVE=1``): the configured LLM investigates each incident
  at temperature 0; tools return the *recorded* telemetry, so results are
  comparable run to run. Uses AIOPS_LLM__BASE_URL / AIOPS_LLM__API_KEY / AIOPS_LLM__MODEL.

Scoring per incident: status matches; for verified incidents the root cause
mentions at least one expected keyword and the runbook_ref matches.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from agent_gateway.investigators import (
    InvestigationResult,
    Investigator,
    OpenAIToolLoopInvestigator,
    ReplayInvestigator,
)
from agent_gateway.runbooks import KeywordRetriever, load_past_incidents, load_runbooks
from agent_gateway.service import AgentGateway
from agent_gateway.tools import ToolBackends, ToolBox
from agent_gateway.validation import ToolCall
from aiops_common.bus import InMemoryBus
from aiops_common.contracts.models import CandidateIncident, Verdict

ROOT = Path(__file__).resolve().parents[1]
INCIDENTS = ROOT / "evals" / "incidents"
RUNBOOKS = ROOT / "config" / "runbooks"
PASS_THRESHOLD = 0.8


def _norm(q: str) -> str:
    return re.sub(r"\s+", "", q).lower()


class RecordedToolBox(ToolBox):
    """Serves recorded tool results; anything not recorded returns 'no data'."""

    def __init__(self, recorded: list[dict[str, str]], runbooks: Any) -> None:
        super().__init__(ToolBackends(), "eval", runbooks, httpx.AsyncClient())
        self.recorded = recorded

    async def call(self, name: str, args: dict[str, Any]) -> str:
        if name == "get_runbook":
            return await self.get_runbook(args)
        q = _norm(str(args.get("query", "")))
        for r in self.recorded:
            if r["name"].split("_")[0] == name.split("_")[0] and _norm(r["query"]) == q:
                return r["result"]
        return '{"status":"success","data":{"result":[]}}  (no data recorded for this query)'


@dataclass
class EvalResult:
    id: str
    passed: bool
    status: str
    expected_status: str
    reasons: list[str]
    root_cause: str


def load_cases() -> list[dict[str, Any]]:
    return [json.loads(p.read_text()) for p in sorted(INCIDENTS.glob("*.json"))]


def score(case: dict[str, Any], v: Verdict) -> EvalResult:
    exp = case["expected"]
    reasons: list[str] = []
    if v.status.value != exp["status"]:
        reasons.append(f"status {v.status.value} != {exp['status']}")
    rc = v.root_cause.lower()
    kws = exp["root_cause_keywords"]
    if exp["status"] in ("verified", "noise") and kws and not any(k.lower() in rc for k in kws):
        reasons.append(f"root cause lacks any of {kws}")
    if exp["status"] == "verified" and exp["runbook_ref"] and v.runbook_ref != exp["runbook_ref"]:
        reasons.append(f"runbook {v.runbook_ref} != {exp['runbook_ref']}")
    return EvalResult(case["id"], not reasons, v.status.value, exp["status"], reasons, v.root_cause)


def live_investigator() -> Investigator:  # pragma: no cover - needs an LLM
    return OpenAIToolLoopInvestigator(
        base_url=os.environ["AIOPS_LLM__BASE_URL"],
        model=os.environ["AIOPS_LLM__MODEL"],
        api_key=os.environ.get("AIOPS_LLM__API_KEY"),
        client=httpx.AsyncClient(timeout=120),
    )


async def run_case(case: dict[str, Any], live: bool = False) -> EvalResult:
    runbooks = load_runbooks(RUNBOOKS)
    cand = CandidateIncident.model_validate(case["candidate"])
    tools = case["tool_results"]
    if live:  # pragma: no cover
        inv: Investigator = live_investigator()
    else:
        calls = [ToolCall(t["name"], t["query"], t["result"]) for t in tools]
        rec = case["recorded"]
        inv = ReplayInvestigator(
            {"*": InvestigationResult(rec["raw_output"], calls, 0, rec["model_id"])}
        )
    gw = AgentGateway(
        InMemoryBus(),
        inv,
        KeywordRetriever(runbooks, load_past_incidents(RUNBOOKS / "past_incidents.yaml")),
        runbooks,
        toolbox_factory=lambda _t: RecordedToolBox(tools, runbooks),
        timeout_seconds=120,
    )
    return score(case, await gw.handle(cand))


async def run_all(live: bool = False) -> tuple[float, list[EvalResult]]:
    results = [await run_case(c, live) for c in load_cases()]
    rate = sum(r.passed for r in results) / len(results)
    return rate, results
