from __future__ import annotations

import httpx
import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from control_plane.app import create_app
from control_plane.auth import Authenticator, AuthSettings, dev_token
from control_plane.db import Base
from control_plane.remediation import DryRunExecutor, allowed_playbooks

SECRET = "dev-secret-for-tests-only-0123456789"


def tok(sub: str, roles: list[str], tenants: list[str]) -> dict[str, str]:
    return {"Authorization": f"Bearer {dev_token(SECRET, sub, roles, tenants)}"}


ADMIN = tok("root", ["admin"], ["*"])
T_ADMIN = tok("tadmin", ["admin"], ["bank"])
OPER = tok("alice", ["operator"], ["bank"])
APPR = tok("bob", ["approver"], ["bank"])
OTHER = tok("eve", ["admin"], ["other"])


@pytest.fixture
async def client():  # type: ignore[no-untyped-def]
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.create_all)
    ex = DryRunExecutor()
    auth = Authenticator(AuthSettings(mode="dev", dev_secret=SECRET), "dev")  # type: ignore[arg-type]
    app = create_app(engine, auth, ex, {"clean_tmp.yml", "restart_service.yml"})
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://x") as c:
        assert (
            await c.post("/v1/tenants", json={"id": "bank", "name": "Bank"}, headers=ADMIN)
        ).status_code == 201
        yield c, ex
    await engine.dispose()


async def test_auth_and_tenant_isolation(client) -> None:  # type: ignore[no-untyped-def]
    c, _ = client
    assert (await c.get("/v1/tenants")).status_code == 401
    assert (await c.get("/v1/tenants", headers={"Authorization": "Bearer junk"})).status_code == 401
    assert (
        await c.post("/v1/tenants", json={"id": "x", "name": "x"}, headers=T_ADMIN)
    ).status_code == 403
    assert (
        await c.post("/v1/tenants", json={"id": "bank", "name": "x"}, headers=ADMIN)
    ).status_code == 409
    assert [t["id"] for t in (await c.get("/v1/tenants", headers=OPER)).json()] == ["bank"]
    assert (await c.get("/v1/tenants", headers=OTHER)).json() == []
    ci = {"ci_id": "CI-1", "name": "db", "service": "core"}
    assert (await c.put("/v1/tenants/bank/cis/CI-1", json=ci, headers=OTHER)).status_code == 403
    assert (await c.put("/v1/tenants/bank/cis/CI-1", json=ci, headers=OPER)).status_code == 200
    assert (await c.put("/v1/tenants/bank/cis/CI-2", json=ci, headers=OPER)).status_code == 422
    assert (await c.get("/v1/tenants/bank/cis", headers=OPER)).json()[0]["ci_id"] == "CI-1"
    assert (await c.put("/v1/tenants/nope/cis/CI-1", json=ci, headers=ADMIN)).status_code == 404


async def test_rules_thresholds_models(client) -> None:  # type: ignore[no-untyped-def]
    c, _ = client
    rules = {"rules": [{"name": "r", "match": {}, "actions": [{"channel": "chat"}]}]}
    assert (await c.get("/v1/tenants/bank/routing-rules", headers=OPER)).status_code == 404
    assert (
        await c.put("/v1/tenants/bank/routing-rules", json=rules, headers=OPER)
    ).status_code == 403
    assert (
        await c.put("/v1/tenants/bank/routing-rules", json=rules, headers=T_ADMIN)
    ).status_code == 200
    assert (await c.get("/v1/tenants/bank/routing-rules", headers=OPER)).json() == rules
    bad = {"rules": [{"name": "r", "match": {}, "actions": [{"channel": "fax"}]}]}
    assert (
        await c.put("/v1/tenants/bank/routing-rules", json=bad, headers=T_ADMIN)
    ).status_code == 422
    assert (
        await c.put(
            "/v1/tenants/bank/thresholds/disk_full", json={"threshold": 0.97}, headers=T_ADMIN
        )
    ).status_code == 200
    prop = {"tenant_id": "bank", "failure_type": "disk_full", "change": "tighten", "reason": "x"}
    assert (await c.post("/v1/thresholds/proposals", json=prop, headers=OPER)).status_code == 202
    assert (
        await c.post("/v1/thresholds/proposals", json=prop | {"tenant_id": "zz"}, headers=OPER)
    ).status_code == 403
    hosted = {"provider": "openai", "model": "gpt", "base_url": "https://api.example.com/v1"}
    assert (
        await c.put("/v1/tenants/bank/model-config", json=hosted, headers=T_ADMIN)
    ).status_code == 422
    hosted["data_residency_approved_hosted"] = True  # type: ignore[assignment]
    assert (
        await c.put("/v1/tenants/bank/model-config", json=hosted, headers=T_ADMIN)
    ).status_code == 200
    local = {"provider": "openai", "model": "qwen", "base_url": "http://vllm:8000/v1"}
    assert (
        await c.put("/v1/tenants/bank/model-config", json=local, headers=T_ADMIN)
    ).status_code == 200


async def test_remediation_requires_approval_and_is_audited(client) -> None:  # type: ignore[no-untyped-def]
    c, ex = client
    base = "/v1/tenants/bank/remediations"
    body = {
        "incident_key": "inc-1",
        "failure_type": "disk_full",
        "playbook": "clean_tmp.yml",
        "params": {"ci_id": "CI-1"},
    }
    assert (
        await c.post(base, json=body | {"playbook": "rm_rf.yml"}, headers=OPER)
    ).status_code == 422
    r = (await c.post(base, json=body, headers=OPER)).json()
    assert r["status"] == "proposed" and r["mode"] == "recommend_only"
    rid = r["id"]
    # recommend-only: cannot run even if approved
    assert (await c.post(f"{base}/{rid}/execute", headers=OPER)).status_code == 409
    assert (
        await c.put(
            "/v1/tenants/bank/remediation-policies/disk_full",
            json={"mode": "one_click"},
            headers=T_ADMIN,
        )
    ).status_code == 200
    # unapproved cannot run
    assert (await c.post(f"{base}/{rid}/execute", headers=OPER)).status_code == 409
    assert ex.runs == []
    # operator cannot approve; requester cannot self-approve
    assert (await c.post(f"{base}/{rid}/approve", headers=OPER)).status_code == 403
    self_appr = tok("alice", ["approver"], ["bank"])
    assert (await c.post(f"{base}/{rid}/approve", headers=self_appr)).status_code == 403
    a = await c.post(f"{base}/{rid}/approve", headers=APPR)
    assert a.json()["status"] == "approved" and a.json()["approved_by"] == "bob"
    assert (await c.post(f"{base}/{rid}/approve", headers=APPR)).status_code == 409
    e = await c.post(f"{base}/{rid}/execute", headers=OPER)
    assert e.status_code == 200 and e.json()["status"] == "executed"
    assert ex.runs == [("clean_tmp.yml", {"ci_id": "CI-1"})]
    assert (await c.post(f"{base}/999/approve", headers=APPR)).status_code == 404
    r2 = (await c.post(base, json=body, headers=OPER)).json()
    assert (await c.post(f"{base}/{r2['id']}/reject", headers=APPR)).json()["status"] == "rejected"
    assert (await c.post(f"{base}/{r2['id']}/reject", headers=APPR)).status_code == 409
    audit = (await c.get("/v1/tenants/bank/audit", headers=OPER)).json()
    actions = [x["action"] for x in audit]
    assert "remediation.execute" in actions and "remediation.approve" in actions
    assert actions.count("remediation.execute.denied") == 2


def test_dev_mode_refused_in_prod_and_playbooks(tmp_path) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(RuntimeError):
        Authenticator(AuthSettings(mode="dev"), "prod")
    (tmp_path / "a.yml").write_text("-")
    assert allowed_playbooks(tmp_path) == {"a.yml"}


def test_role_claim_paths() -> None:
    import time

    import jwt

    a = Authenticator(
        AuthSettings(mode="dev", dev_secret=SECRET, roles_claim="realm_access.roles"), "dev"
    )  # type: ignore[arg-type]
    t = jwt.encode(
        {
            "sub": "k",
            "aud": "aiops-control-plane",
            "iat": int(time.time()),
            "exp": int(time.time()) + 60,
            "realm_access": {"roles": ["approver"]},
            "tenants": "bank",
        },
        SECRET,
        algorithm="HS256",
    )
    p = a.decode(t)
    assert p.has("operator") and not p.has("admin") and p.can_access("bank")


async def test_console_endpoints_proxy_feedback_with_rbac(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from datetime import UTC, datetime

    from aiops_common.cloudevents import make_event
    from aiops_common.contracts.models import (
        CandidateIncident,
        DetectorKind,
        Signal,
        Verdict,
        VerdictStatus,
    )
    from feedback_service.app import FeedbackService
    from feedback_service.app import create_app as fb_app

    t0 = datetime(2026, 11, 11, 8, 0, tzinfo=UTC)
    fe = create_async_engine("sqlite+aiosqlite:///:memory:")
    fb = FeedbackService(fe, None, {})
    await fb.create_schema()
    sig = Signal(
        signal_id="s",
        tenant_id="bank",
        ci_id="CI-1",
        service="db",
        detector=DetectorKind.TREND,
        failure_type="disk_full",
        metric="m",
        value=1,
        score=0.9,
        ts=t0,
    )
    cand = CandidateIncident(
        incident_key="inc-0123456789abcdef0123",
        tenant_id="bank",
        ci_id="CI-1",
        service="db",
        signals=[sig],
        predicted_failure="disk_full",
        eta_minutes=12,
        confidence=0.9,
        first_seen=t0,
        last_seen=t0,
    )
    v = Verdict(
        incident_key=cand.incident_key,
        tenant_id="bank",
        ci_id="CI-1",
        status=VerdictStatus.VERIFIED,
        is_incident=True,
        confidence=0.9,
        predicted_failure="disk_full",
        eta_minutes=12,
        root_cause="WAL archive failing",
        recommended_actions=["fix archiver"],
        runbook_ref="RB-DISK-001",
        model_id="m",
        prompt_version="v",
        candidate=cand,
    )
    await fb.on_event(make_event(v, source="urn:t"))
    fbc = httpx.AsyncClient(transport=httpx.ASGITransport(app=fb_app(fb)), base_url="http://fb")
    (tmp_path / "console").mkdir()
    (tmp_path / "console" / "index.html").write_text("<h1>console</h1>")
    (tmp_path / "brand").mkdir()
    (tmp_path / "brand" / "tokens.css").write_text(":root{}")
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.create_all)
    auth = Authenticator(AuthSettings(mode="dev", dev_secret=SECRET), "dev")  # type: ignore[arg-type]
    app = create_app(
        engine,
        auth,
        DryRunExecutor(),
        {"clean_tmp.yml"},
        feedback=fbc,
        console_dir=tmp_path / "console",
        console_config={"oidc": None},
        brand_dir=tmp_path / "brand",
    )
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://x") as c:
        await c.post("/v1/tenants", json={"id": "bank", "name": "Bank"}, headers=ADMIN)
        me = (await c.get("/v1/me", headers=OPER)).json()
        assert me == {"sub": "alice", "roles": ["operator"], "tenants": ["bank"]}
        assert (await c.get("/v1/tenants/bank/incidents", headers=OTHER)).status_code == 403
        inc = (await c.get("/v1/tenants/bank/incidents", headers=OPER)).json()
        assert inc[0]["root_cause"] == "WAL archive failing"
        assert inc[0]["predicted_at"].endswith(("Z", "+00:00"))
        viewer = tok("vic", ["viewer"], ["bank"])
        body = {"outcome": "true_positive"}
        url = f"/v1/tenants/bank/incidents/{cand.incident_key}/outcome"
        assert (await c.post(url, json=body, headers=viewer)).status_code == 403
        assert (await c.post(url, json=body, headers=OPER)).status_code == 200
        kpis = (await c.get("/v1/tenants/bank/kpis", headers=OPER)).json()
        assert kpis[0]["true_positives"] == 1
        assert (await c.get("/v1/tenants/bank/playbooks", headers=OPER)).json() == ["clean_tmp.yml"]
        assert (await c.get("/v1/tenants/bank/remediations", headers=OPER)).json() == []
        assert "console" in (await c.get("/console/")).text
        assert (await c.get("/console/config.json")).json() == {"oidc": None}
        assert (await c.get("/console/brand/tokens.css")).status_code == 200
        audit = [a["action"] for a in (await c.get("/v1/tenants/bank/audit", headers=OPER)).json()]
        assert "incident.label" in audit
    down = create_app(engine, auth, DryRunExecutor(), set(), feedback=None)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=down), base_url="http://x") as c:
        assert (await c.get("/v1/tenants/bank/incidents", headers=OPER)).status_code == 503
    await fbc.aclose()
    await engine.dispose()
    await fe.dispose()
