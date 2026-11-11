# Dead-letter topics growing

Each `<topic>.dlq` message carries headers `x-error`, `x-attempts`, `x-group`.
1. Inspect: `kafka-console-consumer.sh --topic signals.detected.dlq --property print.headers=true --max-messages 5`
2. `permanent: ...` = schema/validation problem → fix the producer; do not replay as-is.
3. Transient (timeouts) → after the dependency is healthy, replay by producing the DLQ messages back to
   the source topic (idempotent consumers make replays safe).
