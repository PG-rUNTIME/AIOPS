---
id: RB-ERR-001
title: Error-log spike / new error template
failure_types: [error_spike]
---
## Confirm
- Count of the new template per minute vs baseline; affected services and upstreams.
## Likely causes
1. Upstream dependency failure (payment switch, card network, core banking).
2. Bad deploy or config push in the last hour.
## Safe actions
1. Identify the upstream from the log template (host/IP) and check its health dashboard.
2. If a change correlates, roll back via the change process.
