---
id: RB-CPU-001
title: CPU saturation
failure_types: [cpu_saturation]
---
## Confirm
- `node_cpu_utilisation{ci_id="<ci>"}` above 0.9 and rising; check run-queue / load average.
## Likely causes
1. Traffic peak (month-end, salary day, promotions) — compare with the same hour last week.
2. Hot loop or regex backtracking after a deploy; runaway batch job.
## Safe actions
1. Scale out stateless instances (HPA / add node to pool).
2. Identify top processes (`top -o %CPU`); pause non-critical batch jobs.
