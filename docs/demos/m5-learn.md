# M5 demo — learn

```bash
uv run pytest services/feedback-service services/control-plane-api -v
TOKEN=$(make -s token)
curl -s -H "Authorization: Bearer $TOKEN" localhost:8084/v1/tenants/demo-bank/audit | jq
curl -s localhost:8083/v1/kpis | jq          # precision / recall / median lead time per failure type
```
Acceptance: KPIs per failure type; an approved one-click fix executes and is audit-logged; a
recommend-only or unapproved fix returns 409 and the denial is audit-logged.
