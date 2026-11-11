---
id: RB-DISK-001
title: Filesystem filling up
failure_types: [disk_full]
---
## Confirm
- `1 - node_filesystem_avail_bytes{ci_id="<ci>"} / node_filesystem_size_bytes{ci_id="<ci>"}` trend over 1h.
- Logs: `{ci_id="<ci>"} |~ "(?i)no space left|disk full"`.
## Likely causes
1. Runaway application or audit logs (log rotation broken after a deploy).
2. Database WAL / archive not being shipped (check replication and archive_command).
3. Core dumps or temp files from a crashing batch job.
## Safe actions
1. Identify the top directories: `du -xh --max-depth=2 / | sort -h | tail`.
2. Rotate/compress logs; clear `/tmp` and application temp volumes older than 24h.
3. For PostgreSQL: verify `pg_stat_archiver`; never delete WAL files by hand.
4. Expand the volume if growth is legitimate (raise a change request).
## Escalate
Storage team if growth > 5%/h after cleanup.
