<!-- Replace your-org/aiops-platform with the real GitHub slug once the repo is pushed. -->
<h1 align="center">Predictive AIOps platform</h1>

<p align="center">
  <a href="https://github.com/your-org/aiops-platform/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/your-org/aiops-platform/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="tests" src="https://img.shields.io/badge/tests-107%20passing-brightgreen">
  <img alt="coverage" src="https://img.shields.io/badge/coverage-92%25-brightgreen">
  <img alt="LLM evals" src="https://img.shields.io/badge/LLM%20evals-10%2F10-8a2be2">
  <img alt="mypy" src="https://img.shields.io/badge/mypy-strict-1f5082">
  <a href="https://github.com/astral-sh/ruff"><img alt="ruff" src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json"></a>
  <a href="https://github.com/astral-sh/uv"><img alt="uv" src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json"></a>
</p>
<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/python-3.12-3776AB?logo=python&logoColor=white">
  <img alt="Kafka" src="https://img.shields.io/badge/Apache%20Kafka-KRaft-231F20?logo=apachekafka&logoColor=white">
  <img alt="OpenTelemetry" src="https://img.shields.io/badge/OpenTelemetry-OTLP-425CC7?logo=opentelemetry&logoColor=white">
  <img alt="CloudEvents" src="https://img.shields.io/badge/CloudEvents-1.0-0d6efd">
  <img alt="AsyncAPI" src="https://img.shields.io/badge/AsyncAPI-3.0-6c3fc8">
  <img alt="Docker" src="https://img.shields.io/badge/docker-compose-2496ED?logo=docker&logoColor=white">
  <img alt="Helm" src="https://img.shields.io/badge/helm-charts-0F1689?logo=helm&logoColor=white">
  <a href="https://www.conventionalcommits.org"><img alt="Conventional Commits" src="https://img.shields.io/badge/Conventional%20Commits-1.0.0-FE5196?logo=conventionalcommits&logoColor=white"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-blue"></a>
</p>

<p align="center">
  <img src="docs/media/demo.gif" alt="A real disk-fill run: the anomaly detector fires at 0:45, a verified ServiceNow ticket opens at 2:45, the trend detector predicts 'full in 14.7 min' at 9:45 and updates the same ticket, and the disk fills at 20:00 — 17 minutes after the ticket." width="880">
  <br><sub>A real disk-fill run through the pipeline (<code>make demo-media</code> regenerates it) · <a href="docs/media/demo.mp4">MP4 version</a></sub>
</p>

Collects metrics, logs and traces; **predicts failures 5–15 minutes ahead**; investigates
candidates with an LLM agent; opens a ServiceNow ticket (or Teams/Slack/e-mail) with root cause,
evidence and the recommended fix. Self-hostable, multi-tenant, data-residency-safe.

> Cheap detectors watch everything; the LLM investigates only candidate incidents.

## Quick start

```bash
cp .env.example .env        # set an LLM: hosted key, vLLM (GPU) or the default Ollama
make up                     # core + observability + chaos (+ ai) profiles, waits for healthy
make demo-disk-fill         # watch Grafana (localhost:3000) and mock ServiceNow (localhost:8085/mock/state)
make test                   # lint, mypy --strict, unit + e2e (coverage ≥ 80 %), evals, contracts
```

Plug in your LLM by setting `AIOPS_LLM__BASE_URL`, `AIOPS_LLM__MODEL` and `AIOPS_LLM__API_KEY`
(any OpenAI-compatible endpoint), or `AIOPS_LLM__PROVIDER=holmes` for HolmesGPT.

## Layout

| Path | What |
|---|---|
| `libs/aiops-common` | contracts (Pydantic → JSON Schema), CloudEvents, Kafka bus + DLQ, retry/circuit breaker, JSON logging, OTel, PII redaction, routing rules |
| `services/*` | ingest-gateway, detector-workers, correlator, agent-gateway, router, feedback-service, control-plane-api, chaos-sim, mock-servicenow |
| `contracts/` | JSON Schemas (v1), `asyncapi.yaml`, OpenAPI 3.1 per HTTP service — generated, CI-checked |
| `config/` | OTel Collector, Alloy, vmalert `predict_linear` rules, Grafana dashboards, runbooks, Keep workflow, router channels, remediation playbooks |
| `deploy/compose` · `deploy/docker` · `deploy/helm` · `deploy/argocd` | dev stack · image · charts · GitOps |
| `evals/` | recorded incidents + harness (replay in CI, live with your LLM) |
| `tests/e2e` · `tests/integration` | in-process chaos → ticket pipeline · Testcontainers Kafka/Postgres |
| `docs/` | `architecture.md`, `adr/`, `runbooks/`, `demos/` |

## Milestone status

| Milestone | Status |
|---|---|
| M0 Foundations | ✅ done — CI pipeline defined; contracts validated in tests |
| M1 Observe | ✅ built — Compose stack, dashboards, `predict_linear` rules, chaos scenarios. The "`make up` in < 5 min" check has not been run (see below) |
| M2 Detect | ✅ e2e-proven: one candidate per scenario, duplicate suppression |
| M3 Investigate | ✅ agent gateway, 8 runbooks, evals 10/10 (replay); live evals need your key |
| M4 Act | ✅ outbox, ServiceNow EM + Table, Keep, chat, e-mail, Clear; no duplicates under replay/outage |
| M5 Learn | ✅ feedback KPIs, tuning proposals, four-eyes remediation with audit |
| M6 Production | 🟡 scaffolding only: Helm service + umbrella charts (PDB, NetworkPolicy, KEDA, ESO, ServiceMonitor), Argo CD app-of-apps. Data-plane apps, backups and load/failover tests remain |

See `docs/architecture.md` → *Verified vs unverified third-party APIs* before going live.
