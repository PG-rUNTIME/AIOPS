"""Correlation: signals → one CandidateIncident per CI episode.

Rules (from the architecture document, §4.3):
* group by ``tenant_id`` + ``ci_id`` inside a 5-minute window;
* one episode per CI: later signals are absorbed (suppressed) for 30 minutes
  after the last signal, so a failing database is one candidate, not 40 alerts;
* attach change events seen for the CI in the 2 hours before the episode;
* a candidate is emitted once the group has settled (``settle_seconds``) or is
  already high-confidence; a ``resolved`` candidate follows after a quiet period.
"""

from __future__ import annotations

import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from urllib.parse import urlencode

from prometheus_client import Counter

from aiops_common.bus import EventBus
from aiops_common.cloudevents import CloudEvent, make_event
from aiops_common.contracts.models import (
    CandidateIncident,
    ChangeEvent,
    DetectorKind,
    Signal,
)
from aiops_common.contracts.registry import Topics
from aiops_common.ids import stable_id
from correlator.store import Episode, EpisodeStore, MemoryEpisodeStore

log = logging.getLogger(__name__)
SOURCE = "urn:aiops:correlator"

CANDIDATES = Counter(
    "aiops_candidates_emitted_total", "Candidates emitted", ["failure_type", "kind"]
)
SUPPRESSED = Counter("aiops_signals_suppressed_total", "Signals absorbed by an active episode")

PREDICTIVE = {DetectorKind.TREND, DetectorKind.FORECAST}
FAILURE_PRIORITY = {  # tie-breaker when several failure types compete
    "disk_full": 5,
    "memory_exhaustion": 5,
    "connection_pool_exhaustion": 5,
    "cpu_saturation": 4,
    "interface_flap": 4,
    "tls_certificate_expiry": 4,
    "latency_degradation": 3,
    "error_spike": 1,
}


@dataclass
class CorrelatorConfig:
    window_seconds: float = 300
    settle_seconds: float = 20
    anomaly_hold_seconds: float = 120  # anomaly-only groups wait for a predictive signal
    suppress_seconds: float = 1800
    clear_after_seconds: float = 900
    change_lookback_seconds: float = 7200
    min_confidence: float = 0.5
    immediate_confidence: float = 0.9
    grafana_url: str = "http://localhost:3000"


def combined_confidence(signals: list[Signal]) -> float:
    """Noisy-OR over the best score per detector kind, capped at 0.99."""
    best: dict[DetectorKind, float] = {}
    for s in signals:
        best[s.detector] = max(best.get(s.detector, 0.0), s.score)
    p = 1.0
    for v in best.values():
        p *= 1 - v
    return round(min(0.99, 1 - p), 3)


def dominant_failure(signals: list[Signal]) -> str:
    agg: dict[str, float] = defaultdict(float)
    for s in signals:
        agg[s.failure_type] += s.score + (0.5 if s.detector in PREDICTIVE else 0)
    return max(agg, key=lambda f: (agg[f], FAILURE_PRIORITY.get(f, 2)))


def eta_of(signals: list[Signal], failure_type: str) -> float | None:
    etas = [
        s.eta_minutes
        for s in signals
        if s.eta_minutes is not None and s.failure_type == failure_type
    ]
    return min(etas) if etas else None


@dataclass
class Correlator:
    bus: EventBus
    store: EpisodeStore = field(default_factory=MemoryEpisodeStore)
    cfg: CorrelatorConfig = field(default_factory=CorrelatorConfig)
    changes: dict[tuple[str, str], deque[ChangeEvent]] = field(
        default_factory=lambda: defaultdict(lambda: deque(maxlen=50))
    )

    async def on_event(self, ev: CloudEvent) -> None:
        if ev.type.startswith("io.aiops.signal"):
            sig = ev.payload(Signal)
            await self.on_signal(sig)
        elif ev.type.startswith("io.aiops.changes"):
            ch = ev.payload(ChangeEvent)
            self.changes[(ch.tenant_id, ch.ci_id)].append(ch)

    async def on_signal(self, sig: Signal) -> None:
        now = sig.ts
        ep = await self.store.get(sig.tenant_id, sig.ci_id)
        if ep is not None and self._expired(ep, now):
            await self.store.delete(sig.tenant_id, sig.ci_id)
            ep = None
        if ep is None:
            ep = Episode(
                tenant_id=sig.tenant_id,
                ci_id=sig.ci_id,
                service=sig.service,
                incident_key=stable_id(sig.tenant_id, sig.ci_id, sig.signal_id, prefix="inc-"),
                first_seen=now,
                last_seen=now,
            )
        if any(s.signal_id == sig.signal_id for s in ep.signals):
            return  # replayed message: idempotent
        if ep.emitted_at is not None:
            ep.last_seen = max(ep.last_seen, now)
            ep.resolved_at = None
            if len(ep.signals) < 50:
                ep.signals.append(sig)
            # One upgrade: the first ETA for an episode that was emitted without one.
            if not ep.emitted_eta and ep.updates == 0 and sig.eta_minutes is not None:
                ep.updates, ep.emitted_eta = 1, True
                await self.store.put(ep)
                await self._publish(ep, resolved=False, update=True)
                return
            ep.suppressed += 1
            SUPPRESSED.inc()
            await self.store.put(ep)
            return
        if (now - ep.first_seen).total_seconds() <= self.cfg.window_seconds:
            ep.signals.append(sig)
        ep.last_seen = max(ep.last_seen, now)
        await self.store.put(ep)
        await self._maybe_emit(ep, now)

    def _expired(self, ep: Episode, now: datetime) -> bool:
        if ep.emitted_at is None:
            return (now - ep.first_seen).total_seconds() > self.cfg.window_seconds * 2
        return (now - ep.last_seen).total_seconds() > self.cfg.suppress_seconds

    async def _maybe_emit(self, ep: Episode, now: datetime) -> None:
        if ep.emitted_at is not None or not ep.signals:
            return
        conf = combined_confidence(ep.signals)
        age = (now - ep.first_seen).total_seconds()
        anomaly_only = all(s.detector is DetectorKind.ANOMALY for s in ep.signals)
        settled = age >= (
            self.cfg.anomaly_hold_seconds if anomaly_only else self.cfg.settle_seconds
        )
        if conf < self.cfg.min_confidence:
            return
        if not settled and (anomaly_only or conf < self.cfg.immediate_confidence):
            return
        ep.emitted_at = now
        ep.emitted_eta = any(s.eta_minutes is not None for s in ep.signals)
        await self.store.put(ep)
        await self._publish(ep, resolved=False)

    async def tick(self, now: datetime) -> None:
        """Periodic: emit settled groups, resolve quiet episodes, expire old ones."""
        for ep in await self.store.all():
            if ep.emitted_at is None:
                if self._expired(ep, now):
                    await self.store.delete(ep.tenant_id, ep.ci_id)
                else:
                    await self._maybe_emit(ep, now)
                continue
            quiet = (now - ep.last_seen).total_seconds()
            if ep.resolved_at is None and quiet >= self.cfg.clear_after_seconds:
                ep.resolved_at = now
                await self.store.put(ep)
                await self._publish(ep, resolved=True)
            elif self._expired(ep, now):
                await self.store.delete(ep.tenant_id, ep.ci_id)

    def _links(self, ep: Episode) -> list[str]:
        q = {
            "var-tenant": ep.tenant_id,
            "var-ci_id": ep.ci_id,
            "from": int((ep.first_seen - timedelta(minutes=30)).timestamp() * 1000),
            "to": int((ep.last_seen + timedelta(minutes=15)).timestamp() * 1000),
        }
        return [f"{self.cfg.grafana_url}/d/aiops-ci-overview/ci-overview?{urlencode(q)}"]

    async def _publish(self, ep: Episode, *, resolved: bool, update: bool = False) -> None:
        ft = dominant_failure(ep.signals)
        lo = ep.first_seen - timedelta(seconds=self.cfg.change_lookback_seconds)
        recent = [c for c in self.changes[(ep.tenant_id, ep.ci_id)] if lo <= c.ts <= ep.last_seen]
        eta = eta_of(ep.signals, ft)
        cand = CandidateIncident(
            incident_key=ep.incident_key,
            tenant_id=ep.tenant_id,
            ci_id=ep.ci_id,
            service=ep.service,
            signals=ep.signals[:20],
            predicted_failure=ft if eta is not None else f"{ft} (anomaly)",
            eta_minutes=eta,
            confidence=combined_confidence(ep.signals),
            recent_changes=recent[-10:],
            grafana_links=self._links(ep),
            first_seen=ep.first_seen,
            last_seen=ep.last_seen,
            resolved=resolved,
            is_update=update,
        )
        kind = "resolved" if resolved else "update" if update else "open"
        CANDIDATES.labels(ft, kind).inc()
        log.info(
            "candidate emitted",
            extra={
                "incident_key": ep.incident_key,
                "resolved": resolved,
                "failure_type": ft,
                "eta_minutes": eta,
            },
        )
        await self.bus.publish(
            Topics.CANDIDATES,
            make_event(cand, source=SOURCE, event_id=stable_id(ep.incident_key, kind)),
        )
