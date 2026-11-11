#!/bin/bash
# Create every topic (+ .dlq) with the partition key scheme tenant_id:ci_id.
# Dev: 6 partitions, RF 1. Prod (Helm/Strimzi): 24+ partitions, RF 3, min.insync.replicas 2.
set -euo pipefail
BS=${BOOTSTRAP:-kafka:9092}
P=${PARTITIONS:-6}
for t in telemetry.metrics telemetry.logs changes.events signals.detected incidents.candidate \
         incidents.verdict notifications.outbox feedback.outcomes; do
  for name in "$t" "$t.dlq"; do
    /opt/kafka/bin/kafka-topics.sh --bootstrap-server "$BS" --create --if-not-exists \
      --topic "$name" --partitions "$P" --replication-factor "${RF:-1}" \
      --config retention.ms=$([[ $name == *.dlq ]] && echo 1209600000 || echo 604800000)
  done
done
/opt/kafka/bin/kafka-topics.sh --bootstrap-server "$BS" --list
