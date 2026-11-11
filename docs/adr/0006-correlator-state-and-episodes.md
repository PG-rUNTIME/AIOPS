# ADR-0006: Correlator episodes in a store; deterministic incident keys

- Status: accepted · Date: 2026-11-11

## Decision
- One **episode** per (tenant, CI): signals in a 5-minute window group into one candidate;
  later signals are absorbed (suppressed) for 30 minutes after the last signal.
- Emission: after 20 s settle, immediately at confidence ≥ 0.9; anomaly-only groups wait 120 s
  for a predictive signal. If an episode was emitted without an ETA, **one** `is_update`
  re-emission carries the first ETA (same `incident_key`) so ticket priority can be raised.
- After 15 quiet minutes a `resolved` candidate is emitted → router sends Clear events.
- `incident_key = hash(tenant, ci, first signal id)`; signal ids are themselves deterministic
  (series + timestamp), so replays reproduce the same key.
- Episode state lives behind `EpisodeStore`: Postgres (`SqlEpisodeStore`) in deployments so
  rebalances/restarts keep suppression; in-memory for tests.

## Consequences
"Exactly one candidate per scenario" means exactly one *opening* candidate per incident key,
plus at most one ETA upgrade — asserted by the e2e tests.
