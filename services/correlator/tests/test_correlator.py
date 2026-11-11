from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from aiops_common.bus import InMemoryBus
from aiops_common.cloudevents import make_event
from aiops_common.contracts.models import (
    CandidateIncident,
    ChangeEvent,
    ChangeKind,
    DetectorKind,
    Signal,
)
from aiops_common.contracts.registry import Topics
from correlator.core import Correlator, CorrelatorConfig, combined_confidence, dominant_failure
from correlator.store import MemoryEpisodeStore, SqlEpisodeStore

T0 = datetime(2026, 11, 11, 8, 0, tzinfo=UTC)


def sig(
    i: int,
    det: DetectorKind = DetectorKind.TREND,
    ft: str = "disk_full",
    ci: str = "CI-1",
    eta: float | None = 12.0,
    score: float = 0.8,
    dt: float = 0,
) -> Signal:
    return Signal(
        signal_id=f"s{i}-{ci}",
        tenant_id="t",
        ci_id=ci,
        service="db",
        detector=det,
        failure_type=ft,
        metric="m",
        value=0.9,
        threshold=0.95,
        eta_minutes=eta,
        score=score,
        ts=T0 + timedelta(seconds=dt),
        query='m{ci_id="CI-1"}',
    )


def cands(bus: InMemoryBus) -> list[CandidateIncident]:
    return [e.payload(CandidateIncident) for e in bus.log[Topics.CANDIDATES]]


async def test_groups_and_suppresses_storm() -> None:
    bus = InMemoryBus()
    c = Correlator(bus)
    for i in range(40):  # 40 signals in 10 minutes → one candidate
        await c.on_signal(sig(i, dt=i * 15))
    out = cands(bus)
    assert len(out) == 1 and out[0].eta_minutes == 12.0 and out[0].confidence >= 0.8


async def test_replayed_signal_is_idempotent() -> None:
    bus = InMemoryBus()
    c = Correlator(bus, cfg=CorrelatorConfig(settle_seconds=60))
    s = sig(1)
    await c.on_signal(s)
    await c.on_signal(s)
    ep = await c.store.get("t", "CI-1")
    assert ep is not None and len(ep.signals) == 1


async def test_separate_cis_get_separate_candidates() -> None:
    bus = InMemoryBus()
    c = Correlator(bus)
    for ci in ("A", "B"):
        await c.on_signal(sig(1, ci=ci, score=0.95))
    assert {x.ci_id for x in cands(bus)} == {"A", "B"}


async def test_anomaly_only_waits_then_upgrades_with_eta() -> None:
    bus = InMemoryBus()
    c = Correlator(bus)
    await c.on_signal(sig(1, DetectorKind.ANOMALY, eta=None, score=0.7))
    await c.tick(T0 + timedelta(seconds=60))
    assert cands(bus) == []
    await c.tick(T0 + timedelta(seconds=130))
    assert len(cands(bus)) == 1 and cands(bus)[0].eta_minutes is None
    await c.on_signal(sig(2, eta=9.0, dt=200))
    out = cands(bus)
    assert len(out) == 2 and out[1].is_update and out[1].eta_minutes == 9.0
    assert out[0].incident_key == out[1].incident_key
    await c.on_signal(sig(3, eta=5.0, dt=230))
    assert len(cands(bus)) == 2  # only one upgrade


async def test_changes_attached_and_resolution() -> None:
    bus = InMemoryBus()
    c = Correlator(bus)
    ch = ChangeEvent(
        tenant_id="t",
        ci_id="CI-1",
        change_id="CHG001",
        kind=ChangeKind.DEPLOY,
        summary="release 4.12",
        ts=T0 - timedelta(minutes=30),
    )
    await c.on_event(make_event(ch, source="urn:test"))
    await c.on_event(make_event(sig(1, score=0.95), source="urn:test"))
    assert cands(bus)[0].recent_changes[0].change_id == "CHG001"
    await c.tick(T0 + timedelta(minutes=16))
    assert cands(bus)[-1].resolved
    await c.tick(T0 + timedelta(minutes=40))
    assert await c.store.get("t", "CI-1") is None


async def test_low_confidence_never_emits_and_expires() -> None:
    bus = InMemoryBus()
    c = Correlator(bus)
    await c.on_signal(sig(1, DetectorKind.LOG_TEMPLATE, eta=None, score=0.3))
    await c.tick(T0 + timedelta(minutes=3))
    assert cands(bus) == []
    await c.tick(T0 + timedelta(minutes=11))
    assert await c.store.get("t", "CI-1") is None


def test_confidence_and_dominance() -> None:
    s = [sig(1, score=0.5), sig(2, DetectorKind.ANOMALY, score=0.5, ft="cpu_saturation", eta=None)]
    assert combined_confidence(s) == 0.75
    assert dominant_failure(s) == "disk_full"


@pytest.mark.parametrize("kind", ["memory", "sql"])
async def test_stores(kind: str) -> None:
    from correlator.store import Episode

    if kind == "sql":
        store = SqlEpisodeStore(create_async_engine("sqlite+aiosqlite:///:memory:"))
        await store.create_schema()
    else:
        store = MemoryEpisodeStore()  # type: ignore[assignment]
    ep = Episode(
        tenant_id="t",
        ci_id="c",
        service="s",
        incident_key="inc-1234567890123456",
        signals=[sig(1)],
        first_seen=T0,
        last_seen=T0,
    )
    await store.put(ep)
    ep.suppressed = 3
    await store.put(ep)
    got = await store.get("t", "c")
    assert got is not None and got.suppressed == 3 and got.signals[0].signal_id == "s1-CI-1"
    assert len(await store.all()) == 1
    await store.delete("t", "c")
    assert await store.get("t", "c") is None


async def test_a_different_failure_on_a_reported_host_gets_its_own_incident() -> None:
    bus = InMemoryBus()
    c = Correlator(bus)
    for i in range(3):  # a disk problem is reported and then keeps signalling: suppressed
        await c.on_signal(sig(i, ft="disk_full", score=0.95, dt=i * 30))
    assert len(cands(bus)) == 1
    # a memory problem on the SAME host is not part of it: it must surface separately
    await c.on_signal(sig(10, ft="memory_exhaustion", score=0.95, dt=200))
    out = cands(bus)
    assert len(out) == 2 and out[0].incident_key != out[1].incident_key
    assert out[1].predicted_failure.startswith("memory_exhaustion") and out[1].ci_id == "CI-1"
    # further memory signals are absorbed by the memory episode, further disk ones by the disk one
    await c.on_signal(sig(11, ft="memory_exhaustion", score=0.95, dt=230))
    await c.on_signal(sig(12, ft="disk_full", score=0.95, dt=240))
    assert len(cands(bus)) == 2
    keys = {e.key for e in await c.store.all()}
    assert keys == {"CI-1", "CI-1|memory_exhaustion"}
    # each episode clears on its own when quiet
    await c.tick(T0 + timedelta(seconds=240 + 901))
    assert sum(1 for x in cands(bus) if x.resolved) == 2


async def test_sql_store_keeps_episodes_for_the_same_host_apart() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    store = SqlEpisodeStore(engine)
    await store.create_schema()
    base = dict(tenant_id="t", ci_id="CI-1", service="db", first_seen=T0, last_seen=T0)
    from correlator.store import Episode

    await store.put(Episode(incident_key="inc-a" * 4, **base))
    await store.put(Episode(incident_key="inc-b" * 4, scope="CI-1|memory_exhaustion", **base))
    assert (await store.get("t", "CI-1")).incident_key == "inc-a" * 4  # type: ignore[union-attr]
    assert (await store.get("t", "CI-1|memory_exhaustion")).incident_key == "inc-b" * 4  # type: ignore[union-attr]
    await store.delete("t", "CI-1|memory_exhaustion")
    assert await store.get("t", "CI-1|memory_exhaustion") is None and await store.get("t", "CI-1")
    await engine.dispose()
