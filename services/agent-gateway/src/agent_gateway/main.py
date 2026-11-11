"""Entry point: ``agent-gateway``.

LLM selection (one OpenAI-compatible interface, chosen by config):

    AIOPS_LLM__PROVIDER=openai   AIOPS_LLM__BASE_URL=http://vllm:8000/v1        # self-hosted vLLM
    AIOPS_LLM__PROVIDER=openai   AIOPS_LLM__BASE_URL=http://ollama:11434/v1     # CPU laptop
    AIOPS_LLM__PROVIDER=openai   AIOPS_LLM__BASE_URL=https://api.openai.com/v1  # hosted
    AIOPS_LLM__PROVIDER=holmes   AIOPS_LLM__HOLMES_URL=http://holmesgpt:5050
    AIOPS_LLM__PROVIDER=none     # degraded mode: every candidate forwarded "unverified"
"""

from __future__ import annotations

import asyncio
from typing import Literal

import httpx
from pydantic import BaseModel, SecretStr

from agent_gateway.budget import TenantLimiter
from agent_gateway.investigators import HolmesInvestigator, Investigator, OpenAIToolLoopInvestigator
from agent_gateway.runbooks import (
    KeywordRetriever,
    PgVectorRetriever,
    Retriever,
    load_past_incidents,
    load_runbooks,
)
from agent_gateway.service import AgentGateway
from agent_gateway.tools import ToolBackends
from aiops_common.bus import Subscription, make_bus
from aiops_common.config import ServiceSettings
from aiops_common.contracts.registry import Topics
from aiops_common.runner import Worker


class LLMSettings(BaseModel):
    provider: Literal["openai", "holmes", "none"] = "openai"
    base_url: str = "http://ollama:11434/v1"
    api_key: SecretStr | None = None
    model: str = "qwen3:8b"
    holmes_url: str = "http://holmesgpt:5050"
    timeout_seconds: float = 90.0
    max_steps: int = 6
    json_mode: bool = True
    embed_model: str | None = None  # enables pgvector RAG when set with rag_dsn


class Settings(ServiceSettings):
    service_name: str = "agent-gateway"
    consumer_group: str = "agent-gateway"
    llm: LLMSettings = LLMSettings()
    runbooks_dir: str = "/app/config/runbooks"
    past_incidents_file: str | None = "/app/config/runbooks/past_incidents.yaml"
    rag_dsn: str | None = None
    vm_url: str = "http://victoriametrics:8428"
    vm_tenant_path: bool = False
    loki_url: str = "http://loki:3100"
    max_inflight_per_tenant: int = 2
    tokens_per_tenant_per_day: int = 500_000


def build(s: Settings) -> AgentGateway:
    bus = make_bus(s.kafka)
    http = httpx.AsyncClient(timeout=httpx.Timeout(s.llm.timeout_seconds, connect=5))
    investigator: Investigator | None = None
    key = s.llm.api_key.get_secret_value() if s.llm.api_key else None
    if s.llm.provider == "openai":
        investigator = OpenAIToolLoopInvestigator(
            s.llm.base_url,
            s.llm.model,
            key,
            http,
            max_steps=s.llm.max_steps,
            json_mode=s.llm.json_mode,
        )
    elif s.llm.provider == "holmes":
        investigator = HolmesInvestigator(s.llm.holmes_url, http, s.llm.model)
    runbooks = load_runbooks(s.runbooks_dir)
    retriever: Retriever = KeywordRetriever(runbooks, load_past_incidents(s.past_incidents_file))
    if s.rag_dsn and s.llm.embed_model:
        retriever = PgVectorRetriever(s.rag_dsn, s.llm.base_url, s.llm.embed_model, key)
    gw = AgentGateway(
        bus,
        investigator,
        retriever,
        runbooks,
        limiter=TenantLimiter(s.max_inflight_per_tenant, s.tokens_per_tenant_per_day),
        backends=ToolBackends(s.vm_url, s.loki_url, s.vm_tenant_path),
        timeout_seconds=min(90.0, s.llm.timeout_seconds),
    )
    bus.subscribe(Subscription([Topics.CANDIDATES], s.consumer_group, gw.on_event, max_retries=1))
    return gw


def main() -> None:
    s = Settings()
    gw = build(s)
    asyncio.run(Worker(s, gw.bus).serve())


if __name__ == "__main__":
    main()
