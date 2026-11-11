"""Metric detectors: trend extrapolation, quantile forecast crossing, anomaly ensemble."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime

import numpy as np
from sklearn.ensemble import IsolationForest

from detector_workers.forecast import FloatArray, Forecaster, first_crossing, linear_fit
from detector_workers.rules import SeriesRule


@dataclass
class SeriesWindow:
    maxlen: int = 240  # 1 h at 15 s
    ts: deque[float] = field(default_factory=deque)
    values: deque[float] = field(default_factory=deque)

    def add(self, t: datetime, v: float) -> None:
        epoch = t.timestamp()
        if self.ts and epoch <= self.ts[-1]:
            return  # drop duplicates / out-of-order (replays are idempotent)
        self.ts.append(epoch)
        self.values.append(v)
        while len(self.ts) > self.maxlen:
            self.ts.popleft()
            self.values.popleft()

    def __len__(self) -> int:
        return len(self.ts)

    def array(self, last: int | None = None) -> FloatArray:
        vals = list(self.values)[-last:] if last else list(self.values)
        return np.asarray(vals, dtype=np.float64)

    def step_seconds(self) -> float:
        if len(self.ts) < 2:
            return 15.0
        return float(np.median(np.diff(np.asarray(self.ts)))) or 15.0


@dataclass(frozen=True)
class Detection:
    detector: str
    value: float
    score: float
    eta_minutes: float | None = None
    p10: float | None = None
    p50: float | None = None
    p90: float | None = None
    detail: str = ""


def _clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))


class TrendDetector:
    """Least-squares extrapolation — the streaming twin of PromQL ``predict_linear``."""

    def __init__(self, window_minutes: float = 15.0, min_r2: float = 0.6) -> None:
        self.window_minutes = window_minutes
        self.min_r2 = min_r2

    def evaluate(self, w: SeriesWindow, rule: SeriesRule) -> Detection | None:
        if len(w) < rule.min_points:
            return None
        step = w.step_seconds()
        n = max(rule.min_points, int(self.window_minutes * 60 / step))
        y = w.array(n)
        a, b, std = linear_fit(y)
        current = a + b * (len(y) - 1)
        rising = rule.direction == "rising"
        if (current >= rule.threshold) if rising else (current <= rule.threshold):
            return Detection("trend", current, 0.95, eta_minutes=0.0, detail="threshold breached")
        if (b <= 0) if rising else (b >= 0):
            return None
        ss_tot = float(np.sum((y - y.mean()) ** 2)) or 1e-12
        r2 = 1 - (std**2 * (len(y) - 2)) / ss_tot if len(y) > 2 else 0.0
        if r2 < self.min_r2:
            return None
        eta_min = (rule.threshold - current) / b * step / 60.0
        if not 0 <= eta_min <= rule.horizon_minutes:
            return None
        score = _clamp(r2 * (1.0 - 0.4 * eta_min / rule.horizon_minutes))
        return Detection(
            "trend",
            current,
            score,
            eta_minutes=round(eta_min, 2),
            detail=f"slope={b:.4g}/step r2={r2:.2f}",
        )


class ForecastDetector:
    """Raise when the chosen *upper* quantile crosses the threshold inside the horizon."""

    def __init__(self, forecaster: Forecaster) -> None:
        self.forecaster = forecaster

    def evaluate(self, w: SeriesWindow, rule: SeriesRule) -> Detection | None:
        if len(w) < rule.min_points:
            return None
        step = w.step_seconds()
        horizon_steps = max(1, int(rule.horizon_minutes * 60 / step))
        y = w.array()
        fc = self.forecaster.forecast(y, step, horizon_steps)
        rising = rule.direction == "rising"
        q = rule.forecast_quantile if rising else "p10"
        idx = first_crossing(fc.quantile(q), rule.threshold, rising)
        if idx is None:
            return None
        median_idx = first_crossing(fc.p50, rule.threshold, rising)
        eta = (idx + 1) * step / 60.0
        score = 0.85 if median_idx is not None else 0.6
        return Detection(
            "forecast",
            float(y[-1]),
            score,
            eta_minutes=round(eta, 2),
            p10=float(fc.p10[idx]),
            p50=float(fc.p50[idx]),
            p90=float(fc.p90[idx]),
            detail=f"{self.forecaster.name} {q} crosses at +{eta:.1f}m",
        )


@dataclass
class _SeasonalBucket:
    n: int = 0
    mean: float = 0.0
    m2: float = 0.0

    def update(self, x: float) -> None:
        self.n += 1
        d = x - self.mean
        self.mean += d / self.n
        self.m2 += d * (x - self.mean)

    @property
    def std(self) -> float:
        return float(np.sqrt(self.m2 / (self.n - 1))) if self.n > 1 else 0.0


class SeasonalBaseline:
    """Online mean/std per hour-of-week (Welford). Becomes active once a bucket has history."""

    def __init__(self, min_obs: int = 30) -> None:
        self.buckets: dict[int, _SeasonalBucket] = {}
        self.min_obs = min_obs

    @staticmethod
    def bucket(t: float) -> int:
        dt = datetime.fromtimestamp(t)
        return dt.weekday() * 24 + dt.hour

    def zscore(self, t: float, x: float) -> float | None:
        b = self.buckets.get(self.bucket(t))
        if b is None or b.n < self.min_obs or b.std == 0:
            return None
        return (x - b.mean) / b.std

    def update(self, t: float, x: float) -> None:
        self.buckets.setdefault(self.bucket(t), _SeasonalBucket()).update(x)


@dataclass
class _AnomalyState:
    model: IsolationForest | None = None
    fitted_at: int = 0
    seasonal: SeasonalBaseline = field(default_factory=SeasonalBaseline)


class AnomalyDetector:
    """Isolation Forest on (value, delta) ensembled with a robust/seasonal z-score.

    Both must agree on the latest ``confirm`` points, which keeps false
    positives low on noisy series.
    """

    def __init__(self, z_threshold: float = 4.0, confirm: int = 3, refit_every: int = 20) -> None:
        self.z_threshold = z_threshold
        self.confirm = confirm
        self.refit_every = refit_every
        self._state: dict[str, _AnomalyState] = {}

    def evaluate(self, key: str, w: SeriesWindow, rule: SeriesRule) -> Detection | None:
        st = self._state.setdefault(key, _AnomalyState())
        st.seasonal.update(w.ts[-1], w.values[-1])
        if not rule.anomaly or len(w) < max(32, rule.min_points):
            return None
        y = w.array()
        hist = y[: -self.confirm]
        med = float(np.median(hist))
        mad = float(np.median(np.abs(hist - med))) * 1.4826 or float(np.std(hist)) or 1e-9
        z_robust = (y[-self.confirm :] - med) / mad
        z_season = st.seasonal.zscore(w.ts[-1], float(y[-1]))
        z_last = z_season if z_season is not None else float(z_robust[-1])
        # Cheap gate first: the forest only runs on series that already look odd.
        if not ((np.abs(z_robust) > self.z_threshold).all() and abs(z_last) > self.z_threshold):
            return None
        feats = np.column_stack([y, np.concatenate([[0.0], np.diff(y)])])
        if st.model is None or len(w) - st.fitted_at >= self.refit_every:
            st.model = IsolationForest(n_estimators=50, contamination="auto", random_state=0)
            st.model.fit(feats[: -self.confirm])
            st.fitted_at = len(w)
        if_scores = st.model.decision_function(feats[-self.confirm :])
        if (if_scores < 0).all():
            score = _clamp(0.5 + min(abs(z_last), 20) / 40)
            return Detection(
                "anomaly",
                float(y[-1]),
                score,
                detail=f"z={z_last:.1f} iforest={float(if_scores[-1]):.3f}",
            )
        return None
