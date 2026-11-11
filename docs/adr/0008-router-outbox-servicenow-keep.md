# ADR-0008: Router with a transactional outbox; ServiceNow EM first, Table API fallback; Keep optional

- Status: accepted · Date: 2026-11-11

## Decision
- Router writes delivery rows in **one transaction** (`router_outbox`, id =
  hash(incident_key, channel, action, revision), `INSERT … ON CONFLICT DO NOTHING`). A
  dispatcher loop (`FOR UPDATE SKIP LOCKED`, so replicas share work) delivers with backoff.
- ServiceNow: `POST /api/global/em/jsonv2` (`records[]`, `message_key = incident_key`,
  `severity` 1–5, `0` = Clear, `additional_info` as a JSON *string*). On a non-retryable 4xx
  (EM not licensed / role missing) fall back to `POST /api/now/table/incident` with
  `correlation_id = incident_key` (looked up first → no duplicates; updates add work notes).
  Description capped at 4,000 characters.
- ServiceNow down: rows stay pending (buffered); after 3 failed attempts a one-off
  "ServiceNow unreachable" chat + e-mail notice is queued.
- Keep: adapter for `POST /alerts/event/{provider_type}` with `X-API-KEY` (Keep API reference).
  **Deviation:** the router talks to ServiceNow directly by default; Keep is an optional mirror
  (`AIOPS_MIRROR_TO_KEEP=true`) or can own delivery via `config/keep/workflows/`. Reason: the
  outbox guarantees (idempotency, buffering, Clear) must hold even if Keep is absent, and Keep's
  post-acquisition roadmap is a watch item in the architecture document. Keep body fields and
  workflow provider keys must be verified against the deployed Keep version.

## Consequences
"No duplicate tickets under retry and broker restart" is proven by e2e tests (replay of all
verdicts and candidates + injected ServiceNow outage → exactly one incident, one message_key).
