---
id: RB-LAT-001
title: Latency degradation
failure_types: [latency_degradation]
---
## Confirm
- p99 latency trend; traces in Tempo for the slowest spans and their dependency.
## Likely causes
1. Slow downstream (database, external API); GC pauses; noisy neighbour.
## Safe actions
1. Identify the slowest span in traces; check that dependency's runbook.
2. Scale out if CPU-bound; enable circuit breaker towards slow upstream.
