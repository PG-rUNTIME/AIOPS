# ADR-0007: Agent gateway — one OpenAI-compatible interface, HolmesGPT as an adapter, strict evidence policy

- Status: accepted · Date: 2026-11-11

## Context
The stack names HolmesGPT. Its HTTP API (`POST /api/investigate` with `source, title,
description, subject, context, include_tool_calls` → `analysis, tool_calls[]`) is documented,
but its tool-call records describe *what* ran in free text, which makes strict evidence
checking weaker, and its server image/entrypoint could not be verified here.

## Decision
- `Investigator` protocol with three adapters: `OpenAIToolLoopInvestigator` (**default**: any
  OpenAI-compatible endpoint — vLLM/Qwen, Ollama, OpenAI, Anthropic's OpenAI-compatible API),
  `HolmesInvestigator` (`AIOPS_LLM__PROVIDER=holmes`), `ReplayInvestigator` (tests/evals).
- In the default adapter the **gateway executes the read-only tools itself** (PromQL instant/
  range, LogQL, runbook fetch), so the evidence check sees exactly what ran.
- Guardrails: temperature 0, ≤ 90 s timeout, circuit breaker, per-tenant in-flight semaphore
  and daily token budget, PII redaction of prompts and tool results, strict `LLMVerdict`
  schema (`extra="forbid"`).
- Evidence policy: every evidence item must reference a query/log_ref that was executed (or is
  on the candidate's own signals) and ≥ 50 % of its excerpt tokens must appear in that result.
  Unknown runbook refs are stripped. Any failure → `needs_human`, and the LLM's claims are
  **not** forwarded (the ticket carries detector facts only). LLM down / over budget →
  `unverified` (degraded mode still tickets).
- Prompts are versioned files (`prompts/investigate.v1.md`, `PROMPT_VERSION`) stamped on every verdict.

## Consequences
HolmesGPT remains a first-class option for teams that want its toolsets/MCP integrations;
switching is configuration only. Deviation from "HolmesGPT is *the* agent": recorded here.
