---
id: RB-DBPOOL-001
title: Database connection-pool exhaustion
failure_types: [connection_pool_exhaustion]
---
## Confirm
- `db_pool_connections_in_use / db_pool_connections_max` approaching 1.
- Logs: `Connection is not available, timeout acquiring connection`, `too many connections`.
## Likely causes
1. Slow queries holding connections (lock contention, missing index after migration).
2. Connection leak in application code (connections not returned).
3. Pool size too small for current traffic.
## Safe actions
1. Check `pg_stat_activity` for long-running / idle-in-transaction sessions.
2. Terminate idle-in-transaction sessions older than 10 minutes (with DBA approval).
3. Temporarily raise pool size within the DB's max_connections budget.
