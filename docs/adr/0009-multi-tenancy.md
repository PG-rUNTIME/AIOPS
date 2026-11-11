# ADR-0009: Multi-tenancy — tenant on every message, RLS in Postgres, backend tenant headers

- Status: accepted · Date: 2026-11-11

## Decision
- `tenant_id` is a required field on every payload and the `tenantid` CloudEvents attribute;
  partition keys start with it.
- Ingest authenticates the tenant with a per-tenant API key (stored as SHA-256) and refuses
  batches whose `tenant_id` differs from the authenticated one.
- Postgres row-level security on every tenant table (`app.tenant_id` set per transaction via
  `set_config(..., true)`; migration `0001` enables + forces RLS). The app also filters by tenant.
- Loki `X-Scope-OrgID`, VictoriaMetrics cluster `/select/<accountID>/prometheus` in prod.
- Per-tenant LLM concurrency/token budgets, routing rules, channels and ServiceNow instances.

## Open
Per-tenant Kafka topics (architecture doc, MSP model) are not implemented; shared topics with
tenant-prefixed keys are used. Revisit when a tenant needs physical isolation.
