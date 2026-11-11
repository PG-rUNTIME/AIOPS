# Architecture (as built)

This document describes what is in the repository today. The design rationale lives in
`AIOps_Platform_Architecture.docx` and the ADRs in `adr/`.

## Data flow

```
 hosts/devices/apps
   │  Alloy (scrape 15 s, logs)      OTel SDKs ──► OTel Collector (memory_limiter → redact → batch)
   │        │ remote_write                         │            │              │
   │        ▼                                      ▼            ▼              ▼
   │   VictoriaMetrics ◄────────────────── prometheusremotewrite  Loki (OTLP)    Tempo
   │        ▲  vmalert predict_linear rules → Alertmanager → Keep (optional)
   │        │
   └──► ingest-gateway  (tenant API key, PII redaction, OTLP/JSON → CloudEvents)
            │ telemetry.metrics / telemetry.logs      key = tenant_id:ci_id
            ▼
       detector-workers  trend (predict_linear twin) · forecast (Chronos-2 | stat, p90 crossing)
            │            anomaly (robust/seasonal z gate → Isolation Forest) · Drain3 templates
            │ signals.detected
            ▼
       correlator        episode per CI · 5-min window · 30-min suppression · change events
            │            ETA upgrade (once) · resolved after 15 quiet min · state in Postgres
            │ incidents.candidate
            ▼
       agent-gateway     runbooks + similar incidents (keyword | pgvector) → LLM tool loop
            │            (PromQL/LogQL read-only, redacted) · ≤90 s · budgets · strict JSON
            │            evidence check → verified | noise | needs_human | unverified | resolved
            │ incidents.verdict
            ├──────────────► feedback-service (predictions; ServiceNow/chat close-outs → KPIs)
            ▼
       router            routing rules (tenant overridable) → outbox (Postgres, idempotent)
            │            dispatcher: ServiceNow EM → Table fallback · Keep · Teams/Slack · e-mail
            │ notifications.outbox                     Clear events on resolve
            ▼
       ServiceNow / chat / e-mail
```

`control-plane-api` also serves the operator console (`ui/console`, `/console`) and proxies the
feedback service's incident and KPI views to it with RBAC. It holds tenants, CIs, routing rules, thresholds (and tuning proposals from
`feedback_service.tuning`), model config and the approval-gated remediation flow with audit log.

## Services

| Service | Consumes → produces | State | Scales on |
|---|---|---|---|
| ingest-gateway | HTTP → `telemetry.metrics`, `telemetry.logs` | none | HPA (CPU) |
| detector-workers | telemetry → `signals.detected` | per-partition windows (rebuilt from stream), Drain3 snapshot | KEDA lag |
| correlator | signals, `changes.events` → `incidents.candidate` | episodes in Postgres | KEDA lag |
| agent-gateway | candidates → `incidents.verdict` | none (budgets in memory per replica) | KEDA lag, concurrency |
| router | verdicts → outbox → channels, `notifications.outbox` | outbox in Postgres | KEDA lag |
| feedback-service | verdicts + webhooks → `feedback.outcomes`, KPI gauges | Postgres | HPA |
| control-plane-api | HTTP | Postgres (RLS) | HPA |
| chaos-sim, mock-servicenow | dev only | memory | — |

## Latency budget (target signal → ticket < 2 min)

| Hop | Design value |
|---|---|
| scrape → detector | 15 s scrape + < 1 s ingest/Kafka |
| detector scoring | every point (15 s), slowed to ≤ 240 s only under lag (load shedding) |
| signal → candidate | 20 s settle (120 s for anomaly-only) |
| candidate → verdict | ≤ 90 s hard timeout, else `unverified` |
| verdict → ticket | dispatcher tick 1 s |

The in-process e2e tests prove the logic; the p95 numbers must be measured with the load tests in M6.

## Verified vs unverified third-party APIs

| Integration | Status |
|---|---|
| ServiceNow EM `jsonv2`, Table API | Verified against ServiceNow docs; exercised against `mock-servicenow` |
| HolmesGPT `/api/investigate` | Request/response fields from the HolmesGPT HTTP API reference; server image not verified (set `HOLMES_IMAGE`) |
| Keep `POST /alerts/event/{provider_type}` + `X-API-KEY` | Verified from Keep API reference; body fields and workflow provider keys must be checked against your Keep version |
| Chronos-2 `Chronos2Pipeline.predict_df` | From the model card; output column names handled defensively |
| Drain3 `TemplateMiner`, `MaskingInstruction`, `PersistenceHandler` | Verified against the installed package |
| Alloy components, OTel Collector config keys, vmalert flags | Written from upstream docs; validated only by `docker compose config`, not by running the binaries in this environment |
