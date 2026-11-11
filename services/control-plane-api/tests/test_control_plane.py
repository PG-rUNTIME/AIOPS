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
    import jwt

    a = Authenticator(
        AuthSettings(mode="dev", dev_secret=SECRET, roles_claim="realm_access.roles"), "dev"
    )  # type: ignore[arg-type]
    t = jwt.encode(
        {
            "sub": "k",
            "aud": "aiops-control-plane",
            "realm_access": {"roles": ["approver"]},
            "tenants": "bank",
        },
        SECRET,
        algorithm="HS256",
    )
    p = a.decode(t)
    assert p.has("operator") and not p.has("admin") and p.can_access("bank")
