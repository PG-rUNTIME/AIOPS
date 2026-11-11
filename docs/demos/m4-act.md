# M4 demo — act

```bash
uv run pytest tests/e2e -v -k "ticket or duplicate or clear"
make up && make demo-disk-fill
curl -s localhost:8085/mock/state | jq '.incidents[] | {number, cmdb_ci, short_description}'
```
Acceptance: one incident per scenario before the simulated failure; replaying all verdicts and
candidates during a ServiceNow outage still leaves exactly one incident; Clear (severity 0) resolves it.
