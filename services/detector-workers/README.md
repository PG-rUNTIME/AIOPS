# detector-workers

Forecasting, anomaly and log-template detectors.

| | |
|---|---|
| Run | `uv run detector-workers` (or the `detector-workers` image) |
| Test | `uv run pytest services/detector-workers` |
| Config | environment variables `AIOPS_*` — see `Settings` in `src/*/main.py`; nested keys use `__` (e.g. `AIOPS_KAFKA__BOOTSTRAP_SERVERS`) |
| Health | `/healthz` (liveness), `/readyz` (readiness), `/metrics` (Prometheus) on port 8080 |

Design notes: see the module docstrings and `docs/architecture.md`.
