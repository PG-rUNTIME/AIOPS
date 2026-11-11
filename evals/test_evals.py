"""Eval gate: ≥80% of recorded incidents must pass. Runs in CI on prompt/runbook/model changes."""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from pathlib import Path

import pytest

from evals.harness import PASS_THRESHOLD, load_cases, run_all

pytestmark = pytest.mark.evals


async def test_eval_suite_meets_threshold() -> None:
    live = os.environ.get("AIOPS_EVAL_LIVE") == "1"
    rate, results = await run_all(live=live)
    report = {"live": live, "pass_rate": rate, "results": [asdict(r) for r in results]}
    Path(os.environ.get("AIOPS_EVAL_REPORT", "evals/report.json")).write_text(
        json.dumps(report, indent=2)
    )
    failed = [(r.id, r.reasons) for r in results if not r.passed]
    assert rate >= PASS_THRESHOLD, failed


def test_suite_covers_required_paths() -> None:
    cases = load_cases()
    statuses = {c["expected"]["status"] for c in cases}
    assert {"verified", "noise", "needs_human"} <= statuses
    assert len(cases) >= 10


async def test_hallucination_trap_is_never_forwarded() -> None:
    _, results = await run_all()
    trap = next(r for r in results if r.id == "hallucination-trap")
    assert trap.status == "needs_human"
    assert "Kubernetes" not in trap.root_cause
