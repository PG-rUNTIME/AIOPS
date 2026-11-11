# Kafka broker loss

RF 3 / `min.insync.replicas=2` tolerates one broker. Producers use `acks=all` + idempotence.
1. `kubectl -n aiops get kafka,pods -l strimzi.io/cluster=aiops` — let Strimzi reschedule.
2. Under-replicated partitions should return to 0 within minutes after the pod is back.
3. Consumers resume from committed offsets; at-least-once replays are absorbed by deterministic ids and the outbox.
