# feedback-service

Outcome labels and precision/recall/lead-time KPIs.

| | |
|---|---|
| Run | `uv run feedback-service` (or the `feedback-service` image) |
| Test | `uv run pytest services/feedback-service` |
| Config | environment variables `AIOPS_*` — see `Settings` in `src/*/main.py`; nested keys use `__` (e.g. `AIOPS_KAFKA__BOOTSTRAP_SERVERS`) |
| Health | `/healthz` (liveness), `/readyz` (readiness), `/metrics` (Prometheus) on port 8080 |

Design notes: see the module docstrings and `docs/architecture.md`.
