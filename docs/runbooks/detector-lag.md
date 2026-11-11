# Detector workers lagging

`aiops_detector_event_lag_seconds` > 60 s or KEDA at max replicas.
1. Workers already shed load: `aiops_detector_score_interval_seconds` rises (scores less often, no data dropped).
2. Raise `keda.maxReplicas` (partitions bound parallelism: replicas ≤ partitions of `telemetry.metrics`).
3. If Chronos-2 is the bottleneck, check CPU throttling; batch size and `AIOPS_FORECASTER=stat` for
   low-value metric families are the release valves.
