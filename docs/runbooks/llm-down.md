# LLM unavailable or over budget

Degraded mode is automatic: candidates are still ticketed, marked **UNVERIFIED**, with detector evidence.
1. `aiops_verdicts_total{status="unverified"}` rising? Check agent-gateway logs for `LLM error` / `timed out`.
2. Self-hosted: `kubectl -n aiops-llm logs deploy/vllm`; GPU OOM → lower `--max-model-len`.
3. Hosted: provider status page; rotate the key in Vault if 401.
4. Budget: `aiops_agent_tokens_used_today{tenant}` vs the tenant's `tokens_per_day` (control plane).
5. The breaker half-opens after 30 s; no restart needed once the backend recovers.
