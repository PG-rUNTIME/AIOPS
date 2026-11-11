# ServiceNow unreachable

Symptoms: `aiops_router_outbox_pending` rising, `aiops_circuit_open{name=~"servicenow:.*"} == 1`,
chat/e-mail notices "ServiceNow unreachable — buffering".

Nothing is lost: rows stay `pending` in `router_outbox` and retry with backoff (up to 60 attempts).
1. `SELECT channel, status, count(*), max(attempts), max(last_error) FROM router_outbox GROUP BY 1,2;`
2. 401/403 → credentials/role (`evt_mgmt_integration`) — fix the Vault secret; ESO refreshes hourly
   (force: annotate the ExternalSecret). 404 on jsonv2 → EM not licensed: set `mode: table`.
3. Rows marked `failed` (non-retryable) can be re-queued:
   `UPDATE router_outbox SET status='pending', attempts=0, next_attempt_at=now() WHERE status='failed' AND channel='servicenow';`
   Re-queuing is safe: the Table adapter looks up `correlation_id` and EM dedupes on `message_key`.
