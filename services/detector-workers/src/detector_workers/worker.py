"""Consume telemetry, run detectors, publish ``signals.detected``."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from prometheus_client import Counter, Gauge

from aiops_common.bus import EventBus
from aiops_common.cloudevents import CloudEvent, make_event
from aiops_common.contracts.models import (
    DetectorKind,
    ForecastQuantiles,
    LogBatch,
    MetricBatch,
    Signal,
)
from aiops_common.contracts.registry import Topics
from aiops_common.ids import stable_id
from detector_workers.detectors import (
    AnomalyDetector,
    Detection,
    ForecastDetector,
    SeriesWindow,
    TrendDetector,
)
from detector_workers.forecast import Forecaster, StatForecaster
from detector_workers.logs import LogTemplateDetector
from detector_workers.rules import DEFAULT_RULES, RuleSet, SeriesRule

log = logging.getLogger(__name__)
SOURCE = "urn:aiops:detector-workers"

SIGNALS = Counter("aiops_signals_emitted_total", "Signals emitted", ["detector", "failure_type"])
SERIES = Gauge("aiops_detector_series_tracked", "Series held in memory")
LAG = Gauge("aiops_detector_event_lag_seconds", "Now minus event time of last batch")
INTERVAL = Gauge(
    "aiops_detector_score_interval_seconds", "Current scoring interval (load shedding)"
)

LabelKey = tuple[tuple[str, str], ...]


def _labels_key(labels: dict[str, str]) -> LabelKey:
    return tuple(sorted((k, v) for k, v in labels.items() if k not in {"__name__", "tenant_id"}))


def _selector(metric: str, labels: LabelKey) -> str:
    inner = ",".join(f'{k}="{v}"' for k, v in labels)
    return f"{metric}{{{inner}}}"


def promql_for(rule: SeriesRule, labels: LabelKey) -> str:
    num = _selector(rule.metric, labels)
    if rule.transform == "identity":
        return num
    den = _selector(rule.denominator or "", labels)
    expr = f"{num} / {den}"
    return f"1 - {expr}" if rule.transform == "one_minus_ratio" else expr


@dataclass
class AdaptiveInterval:
    """Load shedding: score less often when lagging instead of dropping data."""

    min_s: float = 15.0
    max_s: float = 240.0
    current: float = 15.0
    high_lag: float = 30.0
    low_lag: float = 5.0

    def observe_lag(self, lag: float) -> None:
        if lag > self.high_lag:
            self.current = min(self.max_s, self.current * 2)
        elif lag < self.low_lag:
            self.current = max(self.min_s, self.current / 2)
        INTERVAL.set(self.current)


@dataclass
class _Series:
    window: SeriesWindow
    rule: SeriesRule
    labels: LabelKey
    service: str
    last_scored: float = 0.0


@dataclass
class DetectorWorker:
    bus: EventBus
    rules: RuleSet = field(default_factory=lambda: DEFAULT_RULES)
    forecaster: Forecaster = field(default_factory=StatForecaster)
    cooldown_seconds: float = 60.0
    shed: AdaptiveInterval = field(default_factory=AdaptiveInterval)
    clock: Callable[[], float] = time.time  # injectable for tests
    series: dict[tuple[str, str, str, LabelKey], _Series] = field(default_factory=dict)
    _denoms: dict[tuple[str, str, str, LabelKey], float] = field(default_factory=dict)
    _last_emit: dict[tuple[str, str], float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.trend = TrendDetector()
        self.fcst = ForecastDetector(self.forecaster)
        self.anomaly = AnomalyDetector()
        self.logs = LogTemplateDetector(self.rules)
        self._by_metric: dict[str, list[SeriesRule]] = {}
        self._denom_names = {r.denominator for r in self.rules.series if r.denominator}
        for r in self.rules.series:
            self._by_metric.setdefault(r.metric, []).append(r)

    # ------------------------------------------------------------------ handlers
    async def on_event(self, ev: CloudEvent) -> None:
        if ev.type.startswith("io.aiops.telemetry.metrics"):
            await self.on_metrics(ev.payload(MetricBatch))
        elif ev.type.startswith("io.aiops.telemetry.logs"):
            await self.on_logs(ev.payload(LogBatch))

    async def on_metrics(self, batch: MetricBatch) -> None:
        now = self.clock()
        latest = max(p.ts for p in batch.points).timestamp()
        LAG.set(max(0.0, now - latest))
        self.shed.observe_lag(now - latest)
        # Denominators first so ratio rules can use same-batch values.
        for p in batch.points:
            if p.name in self._denom_names:
                self._denoms[(batch.tenant_id, batch.ci_id, p.name, _labels_key(p.labels))] = (
                    p.value
                )
        touched: set[tuple[str, str, str, LabelKey]] = set()
        for p in batch.points:
            for rule in self._by_metric.get(p.name, []):
                lk = _labels_key(p.labels)
                value = p.value
                if rule.denominator:
                    den = self._denoms.get((batch.tenant_id, batch.ci_id, rule.denominator, lk))
                    if not den:
                        continue
                    ratio = p.value / den
                    value = 1 - ratio if rule.transform == "one_minus_ratio" else ratio
                key = (batch.tenant_id, batch.ci_id, rule.series_name, lk)
                s = self.series.get(key)
                if s is None:
                    s = self.series[key] = _Series(SeriesWindow(), rule, lk, batch.service)
                s.window.add(p.ts, value)
                touched.add(key)
        SERIES.set(len(self.series))
        for key in touched:
            await self._score(key, self.series[key])

    async def _score(self, key: tuple[str, str, str, LabelKey], s: _Series) -> None:
        t_last = s.window.ts[-1]
        if t_last - s.last_scored < self.shed.current:
            return
        s.last_scored = t_last
        tenant, ci, series_name, _ = key
        skey = "|".join([tenant, ci, series_name, repr(s.labels)])
        dets: list[Detection | None] = [
            self.trend.evaluate(s.window, s.rule),
            self.fcst.evaluate(s.window, s.rule),
            self.anomaly.evaluate(skey, s.window, s.rule),
        ]
        for d in dets:
            if d is not None:
                await self._emit_metric_signal(tenant, ci, s, d, t_last)

    def _cooldown_ok(self, key: str, t: float) -> bool:
        last = self._last_emit.get((key, ""))
        if last is not None and t - last < self.cooldown_seconds:
            return False
        self._last_emit[(key, "")] = t
        return True

    async def _emit_metric_signal(
        self, tenant: str, ci: str, s: _Series, d: Detection, t: float
    ) -> None:
        rule = s.rule
        skey = f"{tenant}|{ci}|{rule.series_name}|{s.labels}|{d.detector}"
        if not self._cooldown_ok(skey, t):
            return
        base_q = promql_for(rule, s.labels)
        if d.detector == "trend":
            horizon_s = int(rule.horizon_minutes * 60)
            query = f"predict_linear(({base_q})[15m:15s], {horizon_s})"
        else:
            query = base_q
        ts = datetime.fromtimestamp(t, UTC)
        sig = Signal(
            signal_id=stable_id(skey, str(int(t)), prefix="sig-"),
            tenant_id=tenant,
            ci_id=ci,
            service=s.service,
            detector=DetectorKind(d.detector),
            failure_type=rule.failure_type,
            metric=rule.series_name,
            value=round(d.value, 6),
            threshold=rule.threshold,
            forecast=ForecastQuantiles(p10=d.p10, p50=d.p50, p90=d.p90)
            if d.p50 is not None
            else None,
            eta_minutes=d.eta_minutes,
            score=round(d.score, 3),
            ts=ts,
            query=query,
            labels={k: v for k, v in s.labels} | {"detail": d.detail},
        )
        await self._publish(sig)

    async def on_logs(self, batch: LogBatch) -> None:
        for rec in batch.records:
            det = self.logs.observe(batch.tenant_id, batch.ci_id, rec.ts, rec.severity, rec.body)
            if det is None:
                continue
            logql = f'{{ci_id="{batch.ci_id}"}} |~ "(?i){_logql_escape(det.sample[:60])}"'
            sig = Signal(
                signal_id=stable_id(
                    batch.tenant_id,
                    batch.ci_id,
                    str(det.template_id),
                    str(int(rec.ts.timestamp() // 60)),
                    prefix="sig-",
                ),
                tenant_id=batch.tenant_id,
                ci_id=batch.ci_id,
                service=batch.service,
                detector=DetectorKind.LOG_TEMPLATE,
                failure_type=det.failure_type,
                template=det.template,
                value=float(det.count),
                threshold=det.baseline,
                score=det.score,
                ts=rec.ts,
                query=logql,
                labels={
                    "reason": det.reason,
                    "template_id": str(det.template_id),
                    "sample": det.sample,
                },
            )
            await self._publish(sig)

    async def _publish(self, sig: Signal) -> None:
        SIGNALS.labels(sig.detector.value, sig.failure_type).inc()
        await self.bus.publish(
            Topics.SIGNALS, make_event(sig, source=SOURCE, event_id=sig.signal_id)
        )


def _logql_escape(s: str) -> str:
    out = []
    for ch in s:
        if ch.isalnum() or ch in " _-:/":
            out.append(ch)
        else:
            out.append(".")
    return "".join(out)
