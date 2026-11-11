# M1 demo — observe

```bash
make up                                   # < 5 min on a laptop (first build longer)
docker compose --env-file .env -f deploy/compose/docker-compose.yml ps   # all healthy
open http://localhost:3000                # AIOps / CI overview → tenant demo-bank, pick a CI
make demo-disk-fill                       # CI-CORE-DB-01 fills in 20 minutes
open http://localhost:8880/vmalert/alerts # DiskWillFillIn15m fires several minutes before full
```
Acceptance: dashboards show the five demo hosts; `DiskWillFillIn15m` is firing while
`aiops:disk_used_ratio{ci_id="CI-CORE-DB-01"}` is still below 1.
