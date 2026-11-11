# correlator

Groups signals per CI into candidate incidents.

| | |
|---|---|
| Run | `uv run correlator` (or the `correlator` image) |
| Test | `uv run pytest services/correlator` |
| Config | environment variables `AIOPS_*` — see `Settings` in `src/*/main.py`; nested keys use `__` (e.g. `AIOPS_KAFKA__BOOTSTRAP_SERVERS`) |
| Health | `/healthz` (liveness), `/readyz` (readiness), `/metrics` (Prometheus) on port 8080 |

Design notes: see the module docstrings and `docs/architecture.md`.
