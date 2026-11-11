---
id: RB-MEM-001
title: Memory leak / memory exhaustion
failure_types: [memory_exhaustion]
---
## Confirm
- `1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes` rising steadily with no plateau.
- Logs: `OutOfMemoryError`, `oom-kill`, `cannot allocate memory`.
## Likely causes
1. Application memory leak introduced by the most recent deploy (check recent changes first).
2. Unbounded cache or connection objects; JVM heap sized above container limit.
## Safe actions
1. Capture a heap dump / `pmap` before restarting (evidence for the developers).
2. Rolling restart of the affected instance behind the load balancer.
3. If a deploy in the last 24h correlates, propose a rollback via change request.
