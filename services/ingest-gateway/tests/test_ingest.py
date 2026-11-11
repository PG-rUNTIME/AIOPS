from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import httpx

from aiops_common.bus import InMemoryBus
from aiops_common.contracts.models import LogBatch, MetricBatch
from aiops_common.contracts.registry import Topics
from ingest_gateway.app import Ingest, create_app

KEY = "tenant-api-key"
H = {"X-AIOps-Tenant": "bank", "Authorization": f"Bearer {KEY}", "content-type": "application/json"}
NS = str(int(datetime(2026, 11, 11, tzinfo=UTC).timestamp() * 1e9))


def res(ci: str) -> dict:  # type: ignore[type-arg]
    return {
        "attributes": [
            {"key": "host.name", "value": {"stringValue": ci}},
            {"key": "service.name", "value": {"stringValue": "payments"}},
        ]
    }


async def test_otlp_json_and_auth() -> None:
    bus = InMemoryBus()
    app = create_app(Ingest(bus, {"bank": hashlib.sha256(KEY.encode()).hexdigest()}))
    metrics = {
        "resourceMetrics": [
            {
                "resource": res("CI-9"),
                "scopeMetrics": [
                    {
                        "metrics": [
                            {
                                "name": "node_cpu_utilisation",
                                "gauge": {"dataPoints": [{"asDouble": 0.5, "timeUnixNano": NS}]},
                            },
                            {
                                "name": "reqs",
                                "sum": {
                                    "dataPoints": [
                                        {
                                            "asInt": "7",
                                            "timeUnixNano": NS,
                                            "attributes": [
                                                {"key": "code", "value": {"intValue": "200"}}
                                            ],
                                        }
                                    ]
                                },
                            },
                            {"name": "hist", "histogram": {"dataPoints": []}},
                        ]
                    }
                ],
            },
            {"resource": {"attributes": []}, "scopeMetrics": []},
        ]
    }
    logs = {
        "resourceLogs": [
            {
                "resource": res("CI-9"),
                "scopeLogs": [
                    {
                        "logRecords": [
                            {
                                "timeUnixNano": NS,
                                "severityText": "ERROR",
                                "body": {
                                    "stringValue": "card 4111 1111 1111 1111 declined for acct no 0123456789"
                                },
                            }
                        ]
                    }
                ],
            }
        ]
    }
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://x") as c:
        assert (await c.post("/v1/metrics", json=metrics)).status_code == 401
        assert (
            await c.post("/v1/metrics", json=metrics, headers=H | {"Authorization": "Bearer no"})
        ).status_code == 403
        assert (
            await c.post(
                "/v1/metrics",
                content=b"\x00",
                headers=H | {"content-type": "application/x-protobuf"},
            )
        ).status_code == 415
        assert (await c.post("/v1/metrics", json=metrics, headers=H)).status_code == 200
        assert (await c.post("/v1/logs", json=logs, headers=H)).status_code == 200
        mb = MetricBatch(
            tenant_id="bank",
            ci_id="CI-1",
            points=[{"name": "x", "ts": datetime.now(UTC), "value": 1}],
        )  # type: ignore[list-item]
        assert (await c.post("/v1/aiops/metrics", content=mb.model_dump_json(), headers=H)).json()[
            "accepted"
        ] == 1
        other = mb.model_copy(update={"tenant_id": "other"})
        assert (
            await c.post("/v1/aiops/metrics", content=other.model_dump_json(), headers=H)
        ).status_code == 403
        lb = LogBatch(
            tenant_id="bank", ci_id="CI-1", records=[{"ts": datetime.now(UTC), "body": "a@b.co"}]
        )  # type: ignore[list-item]
        assert (
            await c.post("/v1/aiops/logs", content=lb.model_dump_json(), headers=H)
        ).status_code == 202
    m = bus.log[Topics.METRICS][0].payload(MetricBatch)
    assert m.ci_id == "CI-9" and len(m.points) == 2 and m.points[1].labels["code"] == "200"
    body = bus.log[Topics.LOGS][0].payload(LogBatch).records[0].body
    assert "4111" not in body and "[REDACTED:PAN]" in body and "[REDACTED:ACCOUNT]" in body
    assert "[REDACTED:EMAIL]" in bus.log[Topics.LOGS][1].payload(LogBatch).records[0].body
    assert bus.log[Topics.METRICS][0].partitionkey == "bank:CI-9"


async def test_auth_can_be_disabled_for_dev() -> None:
    ing = Ingest(InMemoryBus(), {}, require_auth=False)
    assert ing.tenant("x", None) == "x"
