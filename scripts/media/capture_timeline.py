"""Run a real disk-fill through the in-process pipeline and dump the demo timeline.

PYTHONPATH=. uv run python scripts/media/capture_timeline.py
"""

from __future__ import annotations

import asyncio
import json
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from aiops_common.contracts.models import CandidateIncident, Signal, Verdict
from aiops_common.contracts.registry import Topics
from chaos_sim.scenarios import DEMO_HOSTS, Scenario
from tests.e2e.harness import Pipeline

CI = "CI-CORE-DB-01"
OUT = Path(__file__).parent / "timeline.json"


async def main() -> None:
    p = Pipeline()
    await p.setup()
    sc = Scenario("disk_fill", DEMO_HOSTS[0], p.start + timedelta(minutes=10), fail_after_s=20 * 60)
    rng = random.Random(3)

    def rel(d: datetime) -> float:
        return (d - sc.start).total_seconds() / 60

    series: list[list[float]] = []
    while p.now < sc.fail_at + timedelta(minutes=1):
        t = p.now
        await p.step(sc, rng)
        mb = next(e.data for e in reversed(p.bus.log[Topics.METRICS]) if e.data["ci_id"] == CI)
        v = {x["name"]: x["value"] for x in mb["points"]}
        used = 1 - v["node_filesystem_avail_bytes"] / v["node_filesystem_size_bytes"]
        series.append([rel(t), used])

    sigs = [e.payload(Signal) for e in p.bus.log[Topics.SIGNALS] if e.data["ci_id"] == CI]
    first: dict[str, float] = {}
    for s in sigs:
        first.setdefault(s.detector.value, rel(s.ts))
    cands = [e.payload(CandidateIncident) for e in p.bus.log[Topics.CANDIDATES]]
    verdict = [e.payload(Verdict) for e in p.bus.log[Topics.VERDICTS]][-1]
    inc = p.sn["incidents"][0]
    doc: dict[str, Any] = {
        "series": series,
        "first_signal": first,
        "candidates": [[rel(c.last_seen), c.eta_minutes, c.is_update, c.confidence] for c in cands],
        "verdict": {
            "status": verdict.status.value,
            "root_cause": verdict.root_cause,
            "runbook": verdict.runbook_ref,
            "conf": verdict.confidence,
            "eta": verdict.eta_minutes,
        },
        "ticket": {"at": [rel(x) for x in await p.ticket_sent_at()], "number": inc["number"]},
        "fail_at": 20,
        "nsignals": len(sigs),
    }
    OUT.write_text(json.dumps(doc))
    print(f"wrote {OUT}: {len(sigs)} signals, ticket {inc['number']} at {doc['ticket']['at']}")


if __name__ == "__main__":
    asyncio.run(main())
