# ADR-0005: Chronos-2 as the forecaster, behind an interface with a statistical fallback

- Status: accepted · Date: 2026-11-11

## Context
Chronos-2 (`Chronos2Pipeline.predict_df`, model `amazon/chronos-2`, per the model card) is
the stack choice. It pulls in torch and model weights (~GBs with CUDA wheels), which is heavy
for laptops and unit tests, and its output column names are not documented on the model card.

## Decision
- `detector_workers.forecast.Forecaster` protocol. `Chronos2Forecaster` is the **default in
  Helm/prod** (`AIOPS_FORECASTER=chronos2`, image built with `EXTRAS=chronos`).
- `StatForecaster` (least-squares trend + horizon-widening Gaussian quantiles) is used in tests,
  by default in Compose (laptop footprint), and as the automatic fallback if Chronos-2 fails to load.
- Raise on the **upper quantile** crossing the threshold inside the horizon (p90 rising, p10 falling).
- Quantile column names are read defensively (`"0.1"` or `0.1`); this is isolated in one method.

## Consequences
Deviation: Compose defaults to `stat` — set `DETECTOR_EXTRAS=chronos AIOPS_FORECASTER=chronos2`
in `.env` to run Chronos-2 locally. A benchmark of series/s per vCPU for both is an M6 load-test item.
