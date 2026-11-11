# ADR-0010: PII redaction in two layers

- Status: accepted · Date: 2026-11-11

## Decision
1. OTel Collector `transform` processor (`replace_pattern` on log bodies) before storage.
2. `aiops_common.redaction` in ingest-gateway (log bodies + attributes) and agent-gateway
   (prompts and every tool result) — Luhn-checked PANs, IBANs, keyword-anchored account
   numbers/NIN/BVN, Zimbabwe and South-African national IDs, e-mail, MSISDN.
Redaction counts are exported as `aiops_ingest_redactions_total{rule}`.

## Consequences
Hosted LLMs are allowed only for tenants whose model config sets
`data_residency_approved_hosted=true` (enforced by the control plane).
