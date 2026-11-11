"""Threshold tuning job: "tune before you retrain".

Reads KPIs per (tenant, failure_type) and proposes detector changes:
* precision below target → raise the confidence floor / use the median
  forecast quantile (fewer, surer alerts);
* recall below target → lower the confidence floor / use the upper quantile
  and lengthen the horizon (earlier, more alerts).

Proposals are written as JSON for review and, with ``--apply``, POSTed to the
control-plane ``/v1/thresholds/proposals`` endpoint. Never auto-applied to
production without the normal change process.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass

import httpx

from feedback_service.app import KPI

MIN_LABELS = 10


@dataclass(frozen=True)
class Proposal:
    tenant_id: str
    failure_type: str
    change: str
    forecast_quantile: str | None
    min_confidence_delta: float
    horizon_minutes_delta: float
    reason: str


def propose(
    kpis: list[KPI], precision_target: float = 0.7, recall_target: float = 0.8
) -> list[Proposal]:
    out: list[Proposal] = []
    for k in kpis:
        n = k.true_positives + k.false_positives + k.missed
        if n < MIN_LABELS:
            continue
        if k.precision is not None and k.precision < precision_target:
            out.append(
                Proposal(
                    k.tenant_id,
                    k.failure_type,
                    "tighten",
                    "p50",
                    +0.1,
                    0.0,
                    f"precision {k.precision:.2f} < {precision_target} over {n} labels",
                )
            )
        elif k.recall is not None and k.recall < recall_target:
            out.append(
                Proposal(
                    k.tenant_id,
                    k.failure_type,
                    "loosen",
                    "p90",
                    -0.05,
                    +5.0,
                    f"recall {k.recall:.2f} < {recall_target} over {n} labels",
                )
            )
    return out


def main() -> None:  # pragma: no cover - CLI wrapper
    ap = argparse.ArgumentParser()
    ap.add_argument("--feedback-url", default="http://feedback-service:8080")
    ap.add_argument("--control-plane-url", default="http://control-plane-api:8080")
    ap.add_argument("--token", default=None)
    ap.add_argument("--apply", action="store_true")
    a = ap.parse_args()
    kpis = [
        KPI.model_validate(k) for k in httpx.get(f"{a.feedback_url}/v1/kpis", timeout=10).json()
    ]
    props = propose(kpis)
    print(json.dumps([asdict(p) for p in props], indent=2))
    if a.apply and props:
        headers = {"Authorization": f"Bearer {a.token}"} if a.token else {}
        for p in props:
            httpx.post(
                f"{a.control_plane_url}/v1/thresholds/proposals",
                json=asdict(p),
                headers=headers,
                timeout=10,
            ).raise_for_status()


if __name__ == "__main__":  # pragma: no cover
    main()
