# control-plane-api

Tenants, CIs, routing rules, runbooks, thresholds, remediation approvals.

| | |
|---|---|
| Run | `uv run control-plane-api` (or the `control-plane-api` image) |
| Test | `uv run pytest services/control-plane-api` |
| Config | environment variables `AIOPS_*` — see `Settings` in `src/*/main.py`; nested keys use `__` (e.g. `AIOPS_KAFKA__BOOTSTRAP_SERVERS`) |
| Health | `/healthz` (liveness), `/readyz` (readiness), `/metrics` (Prometheus) on port 8080 |

Design notes: see the module docstrings and `docs/architecture.md`.
