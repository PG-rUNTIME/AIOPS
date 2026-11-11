# chaos-sim

Dev-only failure simulator.

| | |
|---|---|
| Run | `uv run chaos-sim` (or the `chaos-sim` image) |
| Test | `uv run pytest services/chaos-sim` |
| Config | environment variables `AIOPS_*` — see `Settings` in `src/*/main.py`; nested keys use `__` (e.g. `AIOPS_KAFKA__BOOTSTRAP_SERVERS`) |
| Health | `/healthz` (liveness), `/readyz` (readiness), `/metrics` (Prometheus) on port 8080 |

Design notes: see the module docstrings and `docs/architecture.md`.
