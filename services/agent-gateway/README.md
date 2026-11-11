# agent-gateway

Bounded, validated LLM investigation of candidate incidents.

| | |
|---|---|
| Run | `uv run agent-gateway` (or the `agent-gateway` image) |
| Test | `uv run pytest services/agent-gateway` |
| Config | environment variables `AIOPS_*` — see `Settings` in `src/*/main.py`; nested keys use `__` (e.g. `AIOPS_KAFKA__BOOTSTRAP_SERVERS`) |
| Health | `/healthz` (liveness), `/readyz` (readiness), `/metrics` (Prometheus) on port 8080 |

Design notes: see the module docstrings and `docs/architecture.md`.
