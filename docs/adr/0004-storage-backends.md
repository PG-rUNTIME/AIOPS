# ADR-0004: VictoriaMetrics, Loki, Tempo, PostgreSQL + pgvector, MinIO

- Status: accepted · Date: 2026-11-11

## Decision
As in the stack table. Single-node VictoriaMetrics, single-binary Loki (auth enabled, so
`X-Scope-OrgID` tenancy is exercised even in dev), local Tempo in Compose; cluster/simple-
scalable modes in prod via upstream charts. The agent's Loki access is behind
`agent_gateway.tools.ToolBox`, so VictoriaLogs can replace Loki without touching the agent.

## Consequences
Raw metrics 30 d retention in dev; prod adds downsampling and 13-month retention for seasonal baselines.
