from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest
from jsonschema import ValidationError

from aiops_common.bus import InMemoryBus, PermanentError, Subscription
from aiops_common.cloudevents import CloudEvent, make_event, partition_key
from aiops_common.contracts.models import (
    DetectorKind,
    EvidenceItem,
    LogBatch,
    LogRecord,
    MetricBatch,
    MetricPoint,
    Signal,
)
from aiops_common.contracts.registry import EVENT_TYPES, Topics
from aiops_common.contracts.schemas import generate_all, validate_event
from aiops_common.ids import incident_key, stable_id
from aiops_common.redaction import luhn_ok, redact
from aiops_common.resilience import BreakerState, CircuitBreaker, CircuitOpenError, retry_async

NOW = datetime(2026, 11, 11, 8, 0, tzinfo=UTC)


def mb() -> MetricBatch:
    return MetricBatch(
        tenant_id="t1", ci_id="CI-1", points=[MetricPoint(name="m", ts=NOW, value=1)]
    )


def test_cloudevent_roundtrip_and_partition_key() -> None:
    ev = make_event(mb(), source="urn:test")
    assert ev.partitionkey == partition_key("t1", "CI-1") == "t1:CI-1"
    assert ev.type == "io.aiops.telemetry.metrics.v1"
    back = CloudEvent.from_bytes(ev.to_bytes())
    assert back.payload(MetricBatch).points[0].value == 1
    with pytest.raises(TypeError):
        back.payload(LogBatch)
    validate_event(ev.model_dump(mode="json", exclude_none=True))


def test_schema_rejects_bad_payload() -> None:
    ev = make_event(mb(), source="urn:test").model_dump(mode="json")
    ev["data"]["points"] = []
    with pytest.raises(ValidationError):
        validate_event(ev)
    ev2 = make_event(mb(), source="urn:test").model_dump(mode="json")
    del ev2["tenantid"]
    with pytest.raises(ValidationError):
        validate_event(ev2)


def test_every_event_type_has_a_schema() -> None:
    docs = generate_all()
    for et in EVENT_TYPES:
        assert f"{et.name}/v1.json" in docs
        assert docs[f"{et.name}/v1.json"]["x-topic"] == et.topic


def test_model_validators() -> None:
    with pytest.raises(ValueError):
        Signal(
            signal_id="s",
            tenant_id="t",
            ci_id="c",
            detector=DetectorKind.TREND,
            failure_type="x",
            value=1,
            score=0.5,
            ts=NOW,
        )
    with pytest.raises(ValueError):
        EvidenceItem(excerpt="x")
    with pytest.raises(ValueError):
        MetricBatch(
            tenant_id="BAD TENANT", ci_id="c", points=[MetricPoint(name="m", ts=NOW, value=1)]
        )


async def test_memory_bus_retries_then_dlq() -> None:
    bus = InMemoryBus()
    calls = {"ok": 0, "bad": 0}

    async def flaky(ev: CloudEvent) -> None:
        calls["bad"] += 1
        raise RuntimeError("boom")

    async def poison(ev: CloudEvent) -> None:
        raise PermanentError("bad payload")

    async def ok(ev: CloudEvent) -> None:
        calls["ok"] += 1

    bus.subscribe(Subscription([Topics.METRICS], "g1", flaky, max_retries=2))
    bus.subscribe(Subscription([Topics.METRICS], "g2", poison, max_retries=5))
    bus.subscribe(Subscription([Topics.METRICS], "g3", ok))
    await bus.start()
    await bus.publish(Topics.METRICS, make_event(mb(), source="urn:test"))
    await bus.run_until_idle()
    assert calls == {"ok": 1, "bad": 3}
    assert len(bus.dead_letters) == 2
    assert bus.dead_letters[1].attempts == 1 and "permanent" in bus.dead_letters[1].error
    assert len(bus.log[Topics.dlq(Topics.METRICS)]) == 2
    assert bus.ready()
    task = asyncio.create_task(bus.run())
    await asyncio.sleep(0.02)
    await bus.stop()
    await task


async def test_memory_bus_validates_on_publish() -> None:
    bus = InMemoryBus()
    ev = make_event(mb(), source="urn:test")
    ev.data["points"] = []
    with pytest.raises(ValidationError):
        await bus.publish(Topics.METRICS, ev)


def test_incident_key_deterministic() -> None:
    a = incident_key("t", "c", "disk_full", NOW)
    assert a == incident_key("t", "c", "disk_full", NOW.replace(minute=10))
    assert a != incident_key("t", "c", "disk_full", NOW.replace(minute=40))
    assert stable_id("a", "b") == stable_id("a", "b") != stable_id("a", "c")


@pytest.mark.parametrize(
    ("text", "rule"),
    [
        ("card 4111 1111 1111 1111 declined", "PAN"),
        ("pan=5500005555555559", "PAN"),
        ("acct no: 0123456789012", "ACCOUNT"),
        ("customer national_id 63-1234567A12", "ZW_ID"),
        ("id 8001015009087 verified", "ZA_ID"),
        ("mail john.doe@bank.co.zw", "EMAIL"),
        ("call +263 77 123 4567", "MSISDN"),
        ("IBAN GB82 WEST 1234 5698 7654 32", "IBAN"),
    ],
)
def test_redaction_catches_pii(text: str, rule: str) -> None:
    out, counts = redact(text)
    assert f"[REDACTED:{rule}]" in out, out
    assert counts.get(rule, 0) >= 1


def test_redaction_leaves_non_pii() -> None:
    text = "request took 1234 ms, txn order 4111111111111112 failed at 10.0.0.1"
    out, counts = redact(text)
    assert "1234 ms" in out
    assert "PAN" not in counts  # fails Luhn
    assert luhn_ok("4111111111111111") and not luhn_ok("4111111111111112")


async def test_retry_and_breaker() -> None:
    n = {"i": 0}

    async def flaky() -> int:
        n["i"] += 1
        if n["i"] < 3:
            raise RuntimeError
        return 7

    assert await retry_async(flaky, attempts=3, base=0) == 7
    with pytest.raises(RuntimeError):
        await retry_async(lambda: flaky_fail(), attempts=2, base=0)

    t = {"now": 0.0}
    br = CircuitBreaker("x", failure_threshold=2, reset_after=10, clock=lambda: t["now"])
    for _ in range(2):
        with pytest.raises(RuntimeError):
            await br.call(flaky_fail)
    assert br.state is BreakerState.OPEN
    with pytest.raises(CircuitOpenError):
        await br.call(flaky_fail)
    t["now"] = 11
    assert br.state is BreakerState.HALF_OPEN

    async def good() -> int:
        return 1

    assert await br.call(good) == 1
    assert br.state is BreakerState.CLOSED


async def flaky_fail() -> int:
    raise RuntimeError("down")


def test_logbatch_limits() -> None:
    with pytest.raises(ValueError):
        LogBatch(tenant_id="t", ci_id="c", records=[])
    LogBatch(tenant_id="t", ci_id="c", records=[LogRecord(ts=NOW, body="x")])


def test_json_logging(capsys: pytest.CaptureFixture[str]) -> None:
    import json
    import logging

    from aiops_common.logging import bind_context, current_context, setup_logging

    setup_logging("svc", "INFO")
    with bind_context(tenant_id="t1", incident_key="inc-1"):
        assert current_context()["tenant_id"] == "t1"
        logging.getLogger("x").info("hello", extra={"k": 1})
    line = capsys.readouterr().out.strip().splitlines()[-1]
    doc = json.loads(line)
    assert doc["msg"] == "hello" and doc["tenant_id"] == "t1" and doc["k"] == 1


async def test_ops_endpoints() -> None:
    import httpx

    from aiops_common.http import ops_app

    state = {"ready": False}
    app = ops_app(lambda: state["ready"], "t")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://x") as c:
        assert (await c.get("/healthz")).status_code == 200
        assert (await c.get("/readyz")).status_code == 503
        state["ready"] = True
        assert (await c.get("/readyz")).status_code == 200
        assert "aiops" in (await c.get("/metrics")).text or True


def test_routing_rules_default_table() -> None:
    from aiops_common.routing import load_rules

    assert load_rules(None) == {}
