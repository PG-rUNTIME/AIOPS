# M2 demo — detect

```bash
make test-e2e   # each of the six chaos scenarios → exactly one opening CandidateIncident, right ci_id, ETA, evidence
uv run pytest services/correlator -v -k "storm or replay"   # duplicate suppression
```
Live: after `make demo-disk-fill`, watch `aiops_candidates_emitted_total` on *AIOps / Platform services*.
