# Argo CD applications

| Wave | App | Source (pin versions when you adopt) |
|---|---|---|
| 0 | `strimzi` + `Kafka` CR (3 brokers KRaft, RF 3, min ISR 2) | strimzi-kafka-operator chart |
| 0 | `cloudnative-pg` + `Cluster` (primary + streaming replica, PITR to MinIO) | cloudnative-pg chart |
| 0 | `victoria-metrics-cluster` (vminsert/vmselect/vmstorage ×3) | victoria-metrics-cluster chart |
| 0 | `loki` (simple-scalable, S3 backend) and `tempo-distributed` | grafana charts |
| 0 | `minio` (or the client's S3) · `external-secrets` + Vault `ClusterSecretStore` · `keda` | upstream charts |
| 5 | `opentelemetry-collector`, `alloy` (DaemonSet), `grafana`, `vmalert` | upstream charts + `config/` |
| 10 | `aiops-platform` (this repo, `deploy/helm/aiops-platform`) | `aiops-platform.yaml` |

Only `aiops-platform.yaml` is committed today; the data-plane Applications are part of M6.
