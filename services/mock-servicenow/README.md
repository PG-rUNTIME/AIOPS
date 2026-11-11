# mock-servicenow

Dev/test mock of ServiceNow Event Management and Table APIs.

| | |
|---|---|
| Run | `uv run mock-servicenow` (or the `mock-servicenow` image) |
| Test | `uv run pytest services/mock-servicenow` |
| Config | environment variables `AIOPS_*` — see `Settings` in `src/*/main.py`; nested keys use `__` (e.g. `AIOPS_KAFKA__BOOTSTRAP_SERVERS`) |
| Health | `/healthz` (liveness), `/readyz` (readiness), `/metrics` (Prometheus) on port 8080 |

Design notes: see the module docstrings and `docs/architecture.md`.
