from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine

from aiops_common.contracts.models import (
    CandidateIncident,
    Channel,
    DetectorKind,
    EvidenceItem,
    Signal,
    Verdict,
    VerdictStatus,
)
from aiops_common.resilience import CircuitBreaker
from mock_servicenow.app import create_app
from router.adapters import (
    ChatAdapter,
    ChatConfig,
    DeliveryError,
    EmailAdapter,
    EmailConfig,
    KeepAdapter,
    KeepConfig,
    ServiceNowAdapter,
    ServiceNowConfig,
)
from router.channels import AdapterRegistry, load_channels
from router.db import OutboxRow, create_schema
from router.render import SN_DESCRIPTION_LIMIT, description
from router.rules import DEFAULT_RULES, RoutingRule, decide, load_rules
from router.service import Dispatcher, Router

T0 = datetime(2026, 11, 11, 8, 0, tzinfo=UTC)


def verdict(
    status: VerdictStatus = VerdictStatus.VERIFIED,
    eta: float | None = 10,
    conf: float = 0.9,
    is_incident: bool = True,
    **ckw,
) -> Verdict:  # type: ignore[no-untyped-def]
    s = Signal(
        signal_id="s",
        tenant_id="t",
        ci_id="CI-1",
        service="db",
        detector=DetectorKind.TREND,
        failure_type="disk_full",
        metric="m",
        value=0.9,
        score=0.9,
        ts=T0,
        query="m",
    )
    c = CandidateIncident(
        incident_key="inc-0123456789abcdef0123",
        tenant_id="t",
        ci_id="CI-1",
        service="db",
        signals=[s],
        predicted_failure="disk_full",
        eta_minutes=eta,
        confidence=conf,
        first_seen=T0,
        last_seen=T0,
        grafana_links=["http://grafana/d/x"],
        **ckw,
    )
    return Verdict(
        incident_key=c.incident_key,
        tenant_id="t",
        ci_id="CI-1",
        status=status,
        is_incident=is_incident,
        confidence=conf,
        predicted_failure="disk_full",
        eta_minutes=eta,
        root_cause="WAL archive failing",
        evidence=[EvidenceItem(query="m", excerpt="0.97")]
        if status is VerdictStatus.VERIFIED
        else [],
        recommended_actions=["fix archiver"],
        runbook_ref="RB-DISK-001",
        model_id="m",
        prompt_version="v",
        candidate=c,
    )


@pytest.mark.parametrize(
    ("v", "rule", "channels", "prio"),
    [
        (verdict(eta=10), "imminent-verified", {"servicenow", "chat"}, 2),
        (verdict(eta=3), "imminent-verified", {"servicenow", "chat"}, 1),
        (verdict(eta=40), "later-verified", {"servicenow", "email"}, 3),
        (verdict(eta=None), "verified-detected-now", {"servicenow", "chat"}, 2),
        (verdict(eta=None, conf=0.4), "unclear", {"chat"}, 4),
        (verdict(VerdictStatus.NOISE, is_incident=False), "noise", {"log_only"}, 5),
        (
            verdict(VerdictStatus.UNVERIFIED, eta=5),
            "unverified-imminent",
            {"servicenow", "chat"},
            2,
        ),
        (
            verdict(VerdictStatus.UNVERIFIED, eta=None, conf=0.7),
            "unverified",
            {"servicenow", "chat"},
            3,
        ),
        (
            verdict(VerdictStatus.NEEDS_HUMAN, eta=5),
            "needs-human-imminent",
            {"servicenow", "chat"},
            3,
        ),
        (verdict(VerdictStatus.NEEDS_HUMAN, eta=40), "unclear", {"chat"}, 4),
    ],
)
def test_routing_table(v: Verdict, rule: str, channels: set[str], prio: int) -> None:
    d = decide(v)
    assert d.rule == rule
    assert {a.channel.value for a in d.actions} == channels
    assert d.actions[0].priority == prio


def test_rules_from_yaml(tmp_path) -> None:  # type: ignore[no-untyped-def]
    import yaml

    p = tmp_path / "r.yaml"
    p.write_text(
        yaml.safe_dump({"t": [{"name": "all-chat", "match": {}, "actions": [{"channel": "chat"}]}]})
    )
    rules = load_rules(str(p))
    assert decide(verdict(), rules["t"]).rule == "all-chat"
    assert decide(verdict(), []).rule == "none"
    assert isinstance(DEFAULT_RULES[0], RoutingRule)


def test_description_limit() -> None:
    v = verdict()
    v.root_cause = "x" * 1999
    v.recommended_actions = ["y" * 900] * 5
    assert len(description(v)) <= SN_DESCRIPTION_LIMIT


@pytest.fixture
async def env():  # type: ignore[no-untyped-def]
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    await create_schema(engine)
    sn_app = create_app()
    http = httpx.AsyncClient(transport=httpx.ASGITransport(app=sn_app), base_url="http://sn")
    yield engine, sn_app.state.mock, http
    await engine.dispose()


def sn_adapter(http: httpx.AsyncClient, mode: str = "em_with_table_fallback") -> ServiceNowAdapter:
    return ServiceNowAdapter(
        ServiceNowConfig(
            instance_url="http://sn",
            mode=mode,
            username="u",
            password="p",
            resolve_state="6",
            close_code="Solved",
        ),  # type: ignore[arg-type]
        http,
        CircuitBreaker("sn", failure_threshold=100),
    )


class Sink:
    name = "sink"

    def __init__(self) -> None:
        self.rows: list[OutboxRow] = []

    async def send(self, row: OutboxRow) -> str:
        self.rows.append(row)
        return "ok"


async def test_outbox_idempotent_and_clear(env) -> None:  # type: ignore[no-untyped-def]
    engine, sn, http = env
    now = {"t": T0}
    router = Router(engine, clock=lambda: now["t"])
    chat = Sink()
    adapter = sn_adapter(http)
    disp = Dispatcher(
        engine, lambda t, ch: adapter if ch == "servicenow" else chat, clock=lambda: now["t"]
    )
    v = verdict()
    assert await router.route(v) == 2
    assert await router.route(v) == 0  # replay: nothing new
    assert await disp.run_once() == 2
    assert len(sn["incidents"]) == 1
    em = sn["events"][0]
    assert em["message_key"] == v.incident_key and em["severity"] == "2" and em["node"] == "CI-1"
    assert json.loads(em["additional_info"])["runbook_ref"] == "RB-DISK-001"
    await router.route(verdict(VerdictStatus.RESOLVED))
    assert await disp.run_once() == 2
    assert sn["events"][-1]["severity"] == "0"
    assert next(iter(sn["incidents"].values()))["state"] == "6"
    assert chat.rows[-1].action == "clear"


async def test_update_revision_and_keep_mirror(env) -> None:  # type: ignore[no-untyped-def]
    engine, _, _ = env
    router = Router(engine, mirror_to_keep=True, clock=lambda: T0)
    await router.route(verdict())
    await router.route(verdict(is_update=True))
    async with engine.connect() as c:
        rows = (await c.execute(select(OutboxRow.channel, OutboxRow.revision))).all()
    assert ("keep", 0) in rows and ("servicenow", 1) in rows and len(rows) == 6


async def test_table_fallback_when_em_not_licensed(env) -> None:  # type: ignore[no-untyped-def]
    engine, sn, http = env
    sn["em_enabled"] = False
    router, adapter = Router(engine, clock=lambda: T0), sn_adapter(http)
    disp = Dispatcher(
        engine, lambda t, ch: adapter if ch == "servicenow" else Sink(), clock=lambda: T0
    )
    await router.route(verdict())
    await disp.run_once()
    inc = next(iter(sn["incidents"].values()))
    assert inc["source"] == "table" and inc["correlation_id"] == "inc-0123456789abcdef0123"
    assert inc["impact"] == "1" and inc["urgency"] == "2"
    # second open for same key updates instead of creating
    row = OutboxRow(
        id="x",
        incident_key=inc["correlation_id"],
        tenant_id="t",
        ci_id="CI-1",
        channel="servicenow",
        action="open",
        revision=1,
        priority=2,
        payload=(await _payload(engine)),
        status="pending",
        attempts=0,
        next_attempt_at=T0,
        created_at=T0,
    )
    assert await adapter.send(row) == inc["number"]
    assert len(sn["incidents"]) == 1 and inc["work_notes"]


async def _payload(engine) -> dict:  # type: ignore[no-untyped-def,type-arg]
    async with engine.connect() as c:
        return (await c.execute(select(OutboxRow.payload))).scalars().first()  # type: ignore[no-any-return]


async def test_servicenow_outage_buffers_and_alerts(env) -> None:  # type: ignore[no-untyped-def]
    engine, sn, http = env
    now = {"t": T0}
    chat, email = Sink(), Sink()
    adapter = sn_adapter(http, mode="em")
    disp = Dispatcher(
        engine,
        lambda t, ch: {"servicenow": adapter, "chat": chat, "email": email}.get(ch),
        clock=lambda: now["t"],
        base_backoff=0.01,
    )
    await Router(engine, clock=lambda: now["t"]).route(verdict())
    sn["fail"] = 4
    for _ in range(8):
        await disp.run_once()
        now["t"] += timedelta(seconds=400)
    assert len(sn["incidents"]) == 1
    assert any("ServiceNow unreachable" in r.payload["title"] for r in chat.rows)
    assert any("ServiceNow unreachable" in r.payload["title"] for r in email.rows)


async def test_unconfigured_channel_fails_permanently(env) -> None:  # type: ignore[no-untyped-def]
    engine, _, _ = env
    disp = Dispatcher(engine, lambda t, ch: None, clock=lambda: T0)
    await Router(engine, clock=lambda: T0).route(verdict())
    await disp.run_once()
    async with engine.connect() as c:
        statuses = (await c.execute(select(OutboxRow.status))).scalars().all()
    assert set(statuses) == {"failed"}


async def test_keep_chat_email_bodies(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    seen: list[httpx.Request] = []

    def h(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(500 if "fail" in str(req.url) else 202, json={"key": "k"})

    http = httpx.AsyncClient(transport=httpx.MockTransport(h))
    br = CircuitBreaker("x", failure_threshold=100)
    row = OutboxRow(
        id="1",
        incident_key="inc-1",
        tenant_id="t",
        ci_id="CI-1",
        channel="keep",
        action="open",
        revision=0,
        priority=1,
        payload={
            "title": "T",
            "description": "D",
            "status": "verified",
            "service": "db",
            "failure_type": "disk_full",
            "confidence": 0.9,
            "eta_minutes": 5,
            "root_cause": "R",
            "recommended_actions": [],
            "runbook_ref": None,
            "grafana_links": ["http://g"],
            "model_id": "m",
            "prompt_version": "v",
        },
        status="pending",
        attempts=0,
        next_attempt_at=T0,
        created_at=T0,
    )
    await KeepAdapter(KeepConfig(url="http://keep", api_key="k"), http, br).send(row)  # type: ignore[arg-type]
    assert seen[-1].headers["X-API-KEY"] == "k" and "/alerts/event/webhook" in str(seen[-1].url)
    assert json.loads(seen[-1].content)["severity"] == "critical"
    await ChatAdapter(ChatConfig(kind="teams", webhook_url="http://teams"), http, br).send(row)  # type: ignore[arg-type]
    assert json.loads(seen[-1].content)["attachments"][0]["content"]["type"] == "AdaptiveCard"
    await ChatAdapter(ChatConfig(kind="slack", webhook_url="http://slack"), http, br).send(row)  # type: ignore[arg-type]
    assert "P1 T" in json.loads(seen[-1].content)["text"]
    with pytest.raises(DeliveryError):
        await ChatAdapter(ChatConfig(kind="slack", webhook_url="http://fail"), http, br).send(row)  # type: ignore[arg-type]

    sent: list[object] = []
    ea = EmailAdapter(EmailConfig(host="smtp", sender="a@b", recipients=["c@d"]), br)
    monkeypatch.setattr(ea, "_send_sync", lambda msg: sent.append(msg))
    assert await ea.send(row) == "email:sent"
    assert "[P1]" in sent[0]["Subject"]  # type: ignore[index]


def test_channels_yaml_env_expansion(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("SN_PW", "s3cret")
    p = tmp_path / "c.yaml"
    p.write_text(
        "t:\n  servicenow: {instance_url: 'http://sn', username: u, password: '${SN_PW}'}\n"
        "  chat: {kind: slack, webhook_url: 'http://s'}\n"
    )
    ch = load_channels(str(p))
    assert ch["t"].servicenow and ch["t"].servicenow.password.get_secret_value() == "s3cret"  # type: ignore[union-attr]
    reg = AdapterRegistry(ch, httpx.AsyncClient())
    assert reg("t", "servicenow") is reg("t", "servicenow")
    assert reg("t", "chat") is not None and reg("t", "email") is None
    assert reg("nobody", "chat") is None and reg("x", Channel.LOG_ONLY.value) is not None
    assert load_channels(None) == {}
