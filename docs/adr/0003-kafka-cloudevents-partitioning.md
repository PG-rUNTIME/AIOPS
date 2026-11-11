# ADR-0003: Kafka (KRaft) with CloudEvents envelopes, partitioned by tenant_id:ci_id

- Status: accepted · Date: 2026-11-11

## Decision
- Apache Kafka 3.9 in KRaft mode (no ZooKeeper); `apache/kafka` image in dev, Strimzi in prod
  (3 brokers, RF 3, `min.insync.replicas=2`).
- Every message is a CloudEvents 1.0 structured JSON envelope with extensions `tenantid` and
  `partitionkey` (the CloudEvents partitioning extension). `dataschema` points at the
  versioned JSON Schema in `contracts/jsonschema/<name>/v<N>.json`.
- Kafka key = `tenant_id:ci_id`, so one CI's signals stay ordered on one partition and the
  correlator's per-CI state is partition-local.
- Delivery is at-least-once: manual commits after the whole fetched batch is handled or
  dead-lettered. Idempotency downstream (deterministic ids, outbox) gives effectively-once effects.
- Each consumer retries with exponential backoff + full jitter, then writes to `<topic>.dlq`
  with `x-error`, `x-attempts`, `x-group` headers. `PermanentError` skips retries.
- Producers are idempotent (`enable_idempotence`, `acks=all`).

## Alternatives
Redpanda (fine for dev; BSL licence noted in the architecture doc), NATS JetStream (no
Kafka ecosystem/KEDA scaler parity).
