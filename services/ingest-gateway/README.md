# ingest-gateway

OTLP/HTTP JSON entry point: tenant auth, PII redaction, Kafka publish.

| | |
|---|---|
| Run | `uv run ingest-gateway` (or the `ingest-gateway` image) |
| Test | `uv run pytest services/ingest-gateway` |
| Config | environment variables `AIOPS_*` — see `Settings` in `src/*/main.py`; nested keys use `__` (e.g. `AIOPS_KAFKA__BOOTSTRAP_SERVERS`) |
| Health | `/healthz` (liveness), `/readyz` (readiness), `/metrics` (Prometheus) on port 8080 |

Design notes: see the module docstrings and `docs/architecture.md`.
