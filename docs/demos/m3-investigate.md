# M3 demo — investigate

```bash
make evals                                  # replay: ≥ 80 % of recorded incidents pass (currently 10/10)
AIOPS_EVAL_LIVE=1 AIOPS_LLM__BASE_URL=... AIOPS_LLM__MODEL=... AIOPS_LLM__API_KEY=... make evals
uv run pytest tests/e2e -k "hallucinated or garbage or llm_down" -v
```
Acceptance: invalid or evidence-free output becomes `needs_human` with no LLM claims in the ticket.
