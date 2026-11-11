"""Seed the demo tenant through the API (dev only): ``python -m control_plane.seed``."""

from __future__ import annotations

import os
import sys

import httpx

from control_plane.auth import dev_token

TENANT = "demo-bank"
DEMO_CIS = [
    ("CI-CORE-DB-01", "Core banking PostgreSQL primary", "core-banking-db", "dba"),
    ("CI-PAY-API-01", "Payments API node 1", "payments-api", "payments"),
    ("CI-PAY-API-02", "Payments API node 2", "payments-api", "payments"),
    ("CI-MOBILE-GW-01", "Mobile banking gateway", "mobile-gateway", "digital"),
    ("CI-NET-RTR-HRE-01", "Harare WAN edge router", "wan-router", "network"),
]


def main() -> int:
    base = os.environ.get("AIOPS_CONTROL_PLANE_URL", "http://localhost:8084")
    secret = os.environ["AIOPS_AUTH__DEV_SECRET"]
    h = {"Authorization": f"Bearer {dev_token(secret, 'seed', ['admin'], ['*'])}"}
    with httpx.Client(base_url=base, headers=h, timeout=10) as c:
        r = c.post("/v1/tenants", json={"id": TENANT, "name": "Demo Bank (Zimbabwe)"})
        if r.status_code not in (201, 409):
            print(r.text, file=sys.stderr)
            return 1
        for ci, name, svc, team in DEMO_CIS:
            c.put(
                f"/v1/tenants/{TENANT}/cis/{ci}",
                json={"ci_id": ci, "name": name, "service": svc, "owner_team": team},
            ).raise_for_status()
        for ft, thr in (
            ("disk_full", 0.98),
            ("memory_exhaustion", 0.97),
            ("connection_pool_exhaustion", 1.0),
        ):
            c.put(
                f"/v1/tenants/{TENANT}/thresholds/{ft}", json={"threshold": thr}
            ).raise_for_status()
        c.put(
            f"/v1/tenants/{TENANT}/remediation-policies/disk_full", json={"mode": "one_click"}
        ).raise_for_status()
        c.put(
            f"/v1/tenants/{TENANT}/model-config",
            json={
                "provider": "openai",
                "model": os.environ.get("AIOPS_LLM__MODEL", "qwen3:8b"),
                "base_url": os.environ.get("AIOPS_LLM__BASE_URL", "http://ollama:11434/v1"),
                "data_residency_approved_hosted": True,
            },
        ).raise_for_status()
    print(f"seeded tenant {TENANT} with {len(DEMO_CIS)} CIs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
