"""End-to-end acceptance tests (M2 + M3 + M4) on the in-process pipeline."""

from __future__ import annotations

import random
from datetime import timedelta

import pytest

from aiops_common.contracts.models import VerdictStatus
from aiops_common.contracts.registry import Topics
from aiops_common.contracts.schemas import validate_event
from chaos_sim.scenarios import DEMO_HOSTS, SCENARIOS, Scenario
from tests.e2e.harness import Pipeline

pytestmark = pytest.mark.e2e
WARMUP = timedelta(minutes=15)


def host_for(name: str):
    return DEMO_HOSTS[4] if name == "interface_flap" else DEMO_HOSTS[0]


async def _run(
    name: str, llm: str = "good", extra: timedelta = timedelta(minutes=2)
) -> tuple[Pipeline, Scenario]:
    p = Pipeline(llm_mode=llm)
    await p.setup()
    sc = Scenario(name, host_for(name), p.start + WARMUP, fail_after_s=20 * 60)
    await p.run(sc, until=sc.fail_at + extra)
    return p, sc


@pytest.mark.parametrize("name", SCENARIOS)
async def test_each_scenario_yields_one_candidate_and_one_ticket_before_failure(name: str) -> None:
    p, sc = await _run(name)
    cands = [c for c in p.candidates() if not c.resolved]
    opens = [c for c in cands if not c.is_update]
    assert len(opens) == 1, [c.model_dump() for c in opens]
    assert len({c.incident_key for c in cands}) == 1
    assert len(cands) - len(opens) <= 1  # at most one ETA upgrade
    c = opens[0]
    assert c.ci_id == sc.host.ci_id
    assert c.tenant_id == sc.host.tenant_id
    assert c.signals and all(s.query for s in c.signals)
    assert c.first_seen < sc.fail_at

    incidents = p.sn["incidents"]
    assert len(incidents) == 1, incidents
    inc = incidents[0]
    assert inc["cmdb_ci"] == sc.host.ci_id
    sent = await p.ticket_sent_at()
    assert sent and min(sent) < sc.fail_at, "ticket must exist before the simulated failure"
    assert "Root cause" in inc["description"]


@pytest.mark.parametrize("name", ["disk_fill", "memory_leak", "connection_pool_exhaustion"])
async def test_gradual_failures_are_predicted_with_eta(name: str) -> None:
    p, sc = await _run(name)
    upd = [c for c in p.candidates() if c.eta_minutes is not None]
    assert upd, "a predictive signal with ETA must reach the candidate"
    lead = (sc.fail_at - upd[0].last_seen).total_seconds() / 60
    assert 5 <= lead <= 20, lead
    assert abs(upd[0].eta_minutes - lead) < 6  # ETA roughly right
    v = next(v for v in p.verdicts() if v.candidate.eta_minutes is not None)
    assert v.status is VerdictStatus.VERIFIED
    assert v.runbook_ref and v.evidence


async def test_every_message_on_every_topic_matches_its_schema() -> None:
    p, _ = await _run("connection_pool_exhaustion")
    n = 0
    for topic, events in p.bus.log.items():
        if topic.endswith(".dlq"):
            continue
        for ev in events:
            validate_event(ev.model_dump(mode="json", exclude_none=True))
            n += 1
    assert n > 100
    assert not p.bus.dead_letters


async def test_hallucinated_evidence_is_downgraded_not_forwarded() -> None:
    p, _ = await _run("disk_fill", llm="hallucinate")
    vs = p.verdicts()
    assert vs and all(v.status is VerdictStatus.NEEDS_HUMAN for v in vs)
    assert all(v.evidence == [] and v.recommended_actions == [] for v in vs)
    assert all("never executed" in " ".join(v.downgrade_reasons) for v in vs)


async def test_garbage_llm_output_is_downgraded() -> None:
    p, _ = await _run("memory_leak", llm="garbage")
    assert all(v.status is VerdictStatus.NEEDS_HUMAN for v in p.verdicts())
    assert any("invalid output" in r for v in p.verdicts() for r in v.downgrade_reasons)


async def test_llm_down_still_tickets_as_unverified() -> None:
    p, _ = await _run("disk_fill", llm="down")
    vs = p.verdicts()
    assert vs and all(v.status is VerdictStatus.UNVERIFIED for v in vs)
    assert len(p.sn["incidents"]) == 1
    assert "UNVERIFIED" in p.sn["incidents"][0]["description"]


async def test_no_duplicate_tickets_under_replay_and_servicenow_outage() -> None:
    p = Pipeline()
    await p.setup()
    sc = Scenario("disk_fill", DEMO_HOSTS[0], p.start + WARMUP, fail_after_s=20 * 60)
    p.sn_state["fail"] = 6  # ServiceNow down for the first deliveries
    await p.run(sc, until=sc.fail_at + timedelta(minutes=2))
    # Broker-restart style replay: every verdict and candidate delivered again.
    for ev in list(p.bus.log[Topics.VERDICTS]):
        await p.router.on_event(ev)
    for ev in list(p.bus.log[Topics.CANDIDATES]):
        await p.agent.on_event(ev)
    await p.bus.run_until_idle()
    for _ in range(40):
        p.now += timedelta(seconds=30)
        await p.dispatcher.run_once()
    assert len(p.sn["incidents"]) == 1
    keys = {e["message_key"] for e in p.sn["events"]}
    assert len(keys) == 1


async def test_clear_event_when_risk_passes() -> None:
    p = Pipeline()
    await p.setup()
    sc = Scenario("interface_flap", DEMO_HOSTS[4], p.start + WARMUP, fail_after_s=20 * 60)
    await p.run(sc, until=sc.start + timedelta(minutes=12))
    rng = random.Random(9)
    for _ in range(int(20 * 60 / 15)):  # 20 quiet minutes, no scenario
        await p.step(None, rng)
    assert any(c.resolved for c in p.candidates())
    sev = [e["severity"] for e in p.sn["events"]]
    assert sev[-1] == "0", sev
    assert p.sn["incidents"][0]["state"] == "6"
