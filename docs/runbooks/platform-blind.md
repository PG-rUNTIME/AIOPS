# The platform may be blind (dead-man's switch silent)

1. Check `vmalert` (`/api/v1/alerts`) and Alertmanager are up; the heartbeat rule is `vector(1)`.
2. `up{job="aiops"}` — which services are down? `kubectl -n aiops get pods`.
3. If VictoriaMetrics is down nothing evaluates: restore vmstorage/vmselect first.
4. Tell the NOC monitoring is degraded until the heartbeat returns (it is routed outside the platform on purpose).
