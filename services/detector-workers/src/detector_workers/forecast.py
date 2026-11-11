"""Forecasters behind one interface.

* ``Chronos2Forecaster`` — the default in deployed images (Chronos-2, zero-shot,
  CPU). Uses ``Chronos2Pipeline.predict_df`` as documented on the
  amazon/chronos-2 model card. Requires the ``chronos`` extra (torch).
* ``StatForecaster`` — dependency-free linear-trend forecaster with
  horizon-widening Gaussian quantiles. Used in tests, on tiny edge sites and
  as the automatic fallback if Chronos-2 cannot load.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from typing import Any, Protocol

import numpy as np
import numpy.typing as npt

log = logging.getLogger(__name__)

FloatArray = npt.NDArray[np.float64]
Z90 = 1.2815515655446004  # standard normal 90th percentile


@dataclass(frozen=True)
class Forecast:
    p10: FloatArray
    p50: FloatArray
    p90: FloatArray
    step_seconds: float

    def quantile(self, name: str) -> FloatArray:
        arr: FloatArray = getattr(self, name)
        return arr


class Forecaster(Protocol):
    name: str

    def forecast(self, values: FloatArray, step_seconds: float, horizon_steps: int) -> Forecast: ...


def linear_fit(values: FloatArray) -> tuple[float, float, float]:
    """Least squares y = a + b*x on x = 0..n-1. Returns (intercept, slope, residual_std)."""
    n = len(values)
    x = np.arange(n, dtype=np.float64)
    b, a = np.polyfit(x, values, 1)
    resid = values - (a + b * x)
    std = float(np.std(resid, ddof=2)) if n > 2 else 0.0
    return float(a), float(b), std


class StatForecaster:
    name = "stat-linear"

    def forecast(self, values: FloatArray, step_seconds: float, horizon_steps: int) -> Forecast:
        a, b, std = linear_fit(values)
        n = len(values)
        h = np.arange(1, horizon_steps + 1, dtype=np.float64)
        p50 = a + b * (n - 1 + h)
        width = Z90 * max(std, 1e-9) * np.sqrt(1 + h / max(n, 1))
        return Forecast(p10=p50 - width, p50=p50, p90=p50 + width, step_seconds=step_seconds)


class Chronos2Forecaster:  # pragma: no cover - needs torch + model weights
    name = "chronos-2"

    def __init__(self, model_id: str = "amazon/chronos-2", device: str = "cpu") -> None:
        from chronos import Chronos2Pipeline

        self._pipe: Any = Chronos2Pipeline.from_pretrained(model_id, device_map=device)

    def forecast(self, values: FloatArray, step_seconds: float, horizon_steps: int) -> Forecast:
        import pandas as pd

        ts = pd.date_range(
            end=pd.Timestamp.now(tz="UTC"),
            periods=len(values),
            freq=pd.Timedelta(seconds=step_seconds),
        )
        ctx = pd.DataFrame({"id": "s", "timestamp": ts, "target": values})
        pred = self._pipe.predict_df(
            ctx,
            prediction_length=horizon_steps,
            quantile_levels=[0.1, 0.5, 0.9],
            id_column="id",
            timestamp_column="timestamp",
            target="target",
        )

        # Quantile columns are named by level; tolerate "0.1" or 0.1 keys.
        def col(q: float) -> FloatArray:
            for key in (str(q), q):
                if key in pred.columns:
                    return np.asarray(pred[key], dtype=np.float64)
            raise KeyError(f"quantile column {q} missing: {list(pred.columns)}")

        return Forecast(col(0.1), col(0.5), col(0.9), step_seconds)


def make_forecaster(kind: str, model_id: str = "amazon/chronos-2") -> Forecaster:
    if kind == "chronos2":
        try:
            return Chronos2Forecaster(model_id)
        except Exception as e:  # pragma: no cover
            log.error(
                "Chronos-2 unavailable, falling back to stat forecaster", extra={"error": str(e)}
            )
    return StatForecaster()


def first_crossing(arr: FloatArray, threshold: float, rising: bool) -> int | None:
    hits = np.nonzero(arr >= threshold if rising else arr <= threshold)[0]
    return int(hits[0]) if len(hits) else None


def safe_float(x: float) -> float:
    return x if math.isfinite(x) else 0.0
