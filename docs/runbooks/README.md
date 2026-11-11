# Operator runbooks (platform failure modes)

| Alert | Runbook |
|---|---|
| `DeadMansSwitch` stops arriving at the external monitor | [platform-blind.md](platform-blind.md) |
| `AIOpsOutboxBacklog`, "ServiceNow unreachable" notices | [servicenow-down.md](servicenow-down.md) |
| `AIOpsLLMCircuitOpen`, verdicts mostly `unverified` | [llm-down.md](llm-down.md) |
| `AIOpsDeadLettersGrowing` | [dlq.md](dlq.md) |
| `AIOpsDetectorLagging` | [detector-lag.md](detector-lag.md) |
| Kafka broker loss | [kafka.md](kafka.md) |
| Setting up ServiceNow (EM, roles, close-out webhook) | [servicenow-setup.md](servicenow-setup.md) |

Failure-type runbooks used by the AI agent (disk, memory, pool, network…) are in `config/runbooks/`.
