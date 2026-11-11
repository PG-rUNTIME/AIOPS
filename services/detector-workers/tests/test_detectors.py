from __future__ import annotations

from datetime import UTC, datetime, timedelta

import numpy as np

from aiops_common.bus import InMemoryBus
from aiops_common.contracts.models import LogBatch, LogRecord, Signal
from aiops_common.contracts.registry import Topics
from detector_workers.detectors import (
    AnomalyDetector,
    ForecastDetector,
    SeriesWindow,
    TrendDetector,
)
from detector_workers.forecast import StatForecaster, first_crossing, linear_fit, make_forecaster
from detector_workers.logs import LogTemplateDetector
from detector_workers.rules import DEFAULT_RULES, SeriesRule, load_rules
from detector_workers.worker import AdaptiveInterval, DetectorWorker, promql_for

T0 = datetime(2026, 11, 11, 8, 0, tzinfo=UTC)
RULE = SeriesRule(failure_type="disk_full", metric="m", threshold=0.95, horizon_minutes=15)


def window(values: list[float], step: int = 15) -> SeriesWindow:
    w = SeriesWindow()
    for i, v in enumerate(values):
        w.add(T0 + timedelta(seconds=step * i), v)
    return w


def test_window_drops_out_of_order_and_bounds() -> None:
    w = SeriesWindow(maxlen=3)
    for i in range(5):
        w.add(T0 + timedelta(seconds=15 * i), float(i))
    w.add(T0, 99.0)
    assert list(w.values) == [2.0, 3.0, 4.0]
    assert w.step_seconds() == 15


def test_linear_fit_and_crossing() -> None:
    a, b, std = linear_fit(np.arange(10, dtype=float) * 2 + 1)
    assert abs(a - 1) < 1e-9 and abs(b - 2) < 1e-9 and std < 1e-6
    assert first_crossing(np.array([0.1, 0.5, 0.9]), 0.5, rising=True) == 1
    assert first_crossing(np.array([0.9, 0.5]), 0.4, rising=False) is None


def test_trend_predicts_eta_like_predict_linear() -> None:
    # 0.80 rising 0.002 per 15 s step → 0.95 in 75 steps = 18.75 min (beyond 15 min horizon)
    vals = [0.80 + 0.002 * i for i in range(40)]
    d = TrendDetector().evaluate(window(vals), RULE)
    # last fitted ≈ 0.878 → (0.95-0.878)/0.002 = 36 steps = 9 min
    assert d is not None and d.eta_minutes is not None and 8 < d.eta_minutes < 10
    assert TrendDetector().evaluate(window([0.5] * 40), RULE) is None
    assert TrendDetector().evaluate(window(vals[:5]), RULE) is None
    breached = TrendDetector().evaluate(window([0.96] * 20), RULE)
    assert breached is not None and breached.eta_minutes == 0


def test_trend_falling_direction() -> None:
    rule = RULE.model_copy(update={"direction": "falling", "threshold": 0.1})
    d = TrendDetector().evaluate(window([0.4 - 0.004 * i for i in range(40)]), rule)
    assert d is not None and d.eta_minutes is not None


def test_forecast_uses_upper_quantile() -> None:
    rng = np.random.default_rng(0)
    vals = list(0.85 + 0.0008 * np.arange(60) + rng.normal(0, 0.002, 60))
    d = ForecastDetector(StatForecaster()).evaluate(window(vals), RULE)
    assert d is not None and d.p90 is not None and d.p50 is not None and d.p90 >= d.p50
    assert d.eta_minutes is not None and d.eta_minutes <= RULE.horizon_minutes
    assert ForecastDetector(StatForecaster()).evaluate(window([0.5] * 60), RULE) is None
    assert make_forecaster("stat").name == "stat-linear"


def test_anomaly_needs_both_models() -> None:
    rng = np.random.default_rng(1)
    base = list(0.3 + rng.normal(0, 0.01, 80))
    det = AnomalyDetector()
    assert det.evaluate("k", window(base), RULE) is None
    spiked = [*base, 0.95, 0.96, 0.97]
    d = det.evaluate("k2", window(spiked), RULE)
    assert d is not None and d.detector == "anomaly"
    assert det.evaluate("k3", window(base[:10]), RULE) is None


def test_log_detector_new_template_and_spike() -> None:
    det = LogTemplateDetector(DEFAULT_RULES)
    assert det.observe("t", "c", T0, "INFO", "healthcheck ok in 5ms") is None
    d = det.observe("t", "c", T0, "ERROR", "write /data: no space left on device")
    assert d is not None and d.failure_type == "disk_full" and d.reason == "new error template"
    # spike of an unclassified error template
    det2 = LogTemplateDetector(DEFAULT_RULES)
    for m in range(5):
        for _ in range(2):
            det2.observe("t", "c", T0 + timedelta(minutes=m), "ERROR", "upstream 502 from 10.0.0.9")
    hits = [
        det2.observe("t", "c", T0 + timedelta(minutes=6), "ERROR", f"upstream 502 from 10.0.0.{i}")
        for i in range(30)
    ]
    spike = [h for h in hits if h]
    assert len(spike) == 1 and spike[0].failure_type == "error_spike"


def test_promql_rendering() -> None:
    r = DEFAULT_RULES.series[0]
    q = promql_for(r, (("ci_id", "CI-1"), ("mountpoint", "/")))
    assert q.startswith('1 - node_filesystem_avail_bytes{ci_id="CI-1"')
    assert "node_filesystem_size_bytes" in q


def test_adaptive_interval_sheds_load() -> None:
    a = AdaptiveInterval()
    a.observe_lag(100)
    a.observe_lag(100)
    assert a.current == 60
    a.observe_lag(0)
    assert a.current == 30


async def test_worker_emits_log_signal() -> None:
    bus = InMemoryBus()
    w = DetectorWorker(bus, clock=lambda: T0.timestamp())
    await w.on_logs(
        LogBatch(
            tenant_id="t",
            ci_id="c",
            records=[
                LogRecord(
                    ts=T0, severity="ERROR", body="java.lang.OutOfMemoryError: Java heap space"
                )
            ],
        )
    )
    sig = bus.log[Topics.SIGNALS][0].payload(Signal)
    assert sig.failure_type == "memory_exhaustion" and sig.query and 'ci_id="c"' in sig.query


def test_rules_yaml(tmp_path) -> None:  # type: ignore[no-untyped-def]
    import yaml

    p = tmp_path / "r.yaml"
    p.write_text(yaml.safe_dump(DEFAULT_RULES.model_dump()))
    assert load_rules(str(p)) == DEFAULT_RULES
    assert load_rules(None) is DEFAULT_RULES
