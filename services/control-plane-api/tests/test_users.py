"""Local username/password accounts: login, lockout, RBAC, revocation, last-admin safety."""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime, timedelta

import httpx
import jwt
import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from control_plane import db, passwords
from control_plane.app import create_app
from control_plane.auth import Authenticator, AuthSettings
from control_plane.main import bootstrap_admin
from control_plane.remediation import DryRunExecutor

SESSION_SECRET = "session-secret-for-tests-only-0123456789"
PW = "correct-horse-battery"
ROOT_PW = "Zebra-quartz-lantern-9"


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
async def env():  # type: ignore[no-untyped-def]
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as c:
        await c.run_sync(db.Base.metadata.create_all)
    from pydantic import SecretStr

    await bootstrap_admin(engine, "root", SecretStr(ROOT_PW))
    auth = Authenticator(
        AuthSettings(mode="local", session_secret=SecretStr(SESSION_SECRET)), "prod"
    )
    app = create_app(engine, auth, DryRunExecutor(), set())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://x") as c:

        async def login(user: str, pw: str) -> httpx.Response:
            return await c.post("/v1/auth/login", json={"username": user, "password": pw})

        root = (await login("root", ROOT_PW)).json()["access_token"]
        r = await c.post("/v1/tenants", json={"id": "bank", "name": "Bank"}, headers=bearer(root))
        assert r.status_code == 201
        yield c, login, bearer(root), engine
    await engine.dispose()


def new_user(name: str, role: str, tenants: list[str], pw: str = PW) -> dict[str, object]:
    return {"username": name, "password": pw, "role": role, "tenants": tenants}


def test_password_hashing_and_policy() -> None:
    h = passwords.hash_password(PW)
    assert passwords.verify_password(PW, h) and not passwords.verify_password("wrong", h)
    assert not passwords.verify_password(PW, "garbage")
    assert passwords.check_policy("short") and passwords.check_policy("aaaaaaaaaaaaaaaa")
    assert passwords.check_policy("alice-is-my-name", "alice")
    assert passwords.check_policy(PW, "alice") is None


async def test_bootstrap_only_when_empty(env) -> None:  # type: ignore[no-untyped-def]
    _, _, _, engine = env
    from pydantic import SecretStr

    await bootstrap_admin(engine, "second", SecretStr(PW + "-two"))
    async with async_sessionmaker(engine)() as s:
        assert await s.get(db.User, "second") is None
    eng2 = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with eng2.begin() as c:
        await c.run_sync(db.Base.metadata.create_all)
    with pytest.raises(RuntimeError, match="rejected"):
        await bootstrap_admin(eng2, "root", SecretStr("short"))


async def test_login_and_me(env) -> None:  # type: ignore[no-untyped-def]
    c, login, _, _ = env
    r = await login("ROOT", ROOT_PW)  # usernames are case-insensitive
    assert r.status_code == 200 and r.json()["user"]["roles"] == ["admin"]
    assert (await c.get("/v1/me", headers=bearer(r.json()["access_token"]))).json()["sub"] == "root"
    assert (await login("root", "nope")).status_code == 401
    assert (await login("ghost", "nope")).status_code == 401
    assert (await c.get("/v1/me")).status_code == 401


async def test_roles_are_enforced(env) -> None:  # type: ignore[no-untyped-def]
    c, login, admin, _ = env
    for name, role in (("vera", "viewer"), ("olga", "operator"), ("adam", "approver")):
        assert (
            await c.post("/v1/users", json=new_user(name, role, ["bank"]), headers=admin)
        ).status_code == 201
    v = bearer((await login("vera", PW)).json()["access_token"])
    o = bearer((await login("olga", PW)).json()["access_token"])
    ci = {"ci_id": "CI-1", "name": "db", "service": "core"}
    assert (await c.get("/v1/tenants", headers=v)).status_code == 200
    assert (await c.put("/v1/tenants/bank/cis/CI-1", json=ci, headers=v)).status_code == 403
    assert (await c.put("/v1/tenants/bank/cis/CI-1", json=ci, headers=o)).status_code == 200
    assert (await c.get("/v1/users", headers=o)).status_code == 403
    assert (
        await c.post("/v1/users", json=new_user("x" * 3, "viewer", ["bank"]), headers=v)
    ).status_code == 403


async def test_lockout_after_repeated_failures(env) -> None:  # type: ignore[no-untyped-def]
    c, login, admin, _ = env
    await c.post("/v1/users", json=new_user("vera", "viewer", ["bank"]), headers=admin)
    for _ in range(5):
        assert (await login("vera", "wrong-password-1")).status_code == 401
    assert (await login("vera", PW)).status_code == 429  # locked even with the right password
    users = {u["username"]: u for u in (await c.get("/v1/users", headers=admin)).json()}
    assert users["vera"]["locked"] is True
    r = await c.patch("/v1/users/vera", json={"unlock": True}, headers=admin)
    assert r.json()["locked"] is False
    assert (await login("vera", PW)).status_code == 200


async def test_disable_and_role_change_apply_immediately(env) -> None:  # type: ignore[no-untyped-def]
    c, login, admin, _ = env
    await c.post("/v1/users", json=new_user("olga", "operator", ["bank"]), headers=admin)
    o = bearer((await login("olga", PW)).json()["access_token"])
    ci = {"ci_id": "CI-1", "name": "db", "service": "core"}
    assert (await c.put("/v1/tenants/bank/cis/CI-1", json=ci, headers=o)).status_code == 200
    await c.patch("/v1/users/olga", json={"role": "viewer"}, headers=admin)
    assert (await c.put("/v1/tenants/bank/cis/CI-1", json=ci, headers=o)).status_code == 403
    await c.patch("/v1/users/olga", json={"disabled": True}, headers=admin)
    assert (await c.get("/v1/me", headers=o)).status_code == 401
    assert (await login("olga", PW)).status_code == 401


async def test_password_reset_and_change_revoke_old_tokens(env) -> None:  # type: ignore[no-untyped-def]
    c, login, admin, _ = env
    await c.post("/v1/users", json=new_user("vera", "viewer", ["bank"]), headers=admin)
    old = bearer((await login("vera", PW)).json()["access_token"])
    # backdate the password change so the next token's iat is not earlier than it (1s resolution)
    await asyncio.sleep(1.1)
    r = await c.post(
        "/v1/auth/change-password",
        json={"current_password": "bad", "new_password": PW + "2"},
        headers=old,
    )
    assert r.status_code == 403
    r = await c.post(
        "/v1/auth/change-password",
        json={"current_password": PW, "new_password": "short"},
        headers=old,
    )
    assert r.status_code == 422
    r = await c.post(
        "/v1/auth/change-password",
        json={"current_password": PW, "new_password": PW + "2"},
        headers=old,
    )
    assert r.status_code == 200
    assert (await c.get("/v1/me", headers=old)).status_code == 401
    assert (await c.get("/v1/me", headers=bearer(r.json()["access_token"]))).status_code == 200
    assert (await login("vera", PW + "2")).status_code == 200
    await asyncio.sleep(1.1)
    assert (
        await c.post("/v1/users/vera/password", json={"new_password": PW + "3"}, headers=admin)
    ).status_code == 204
    assert (await login("vera", PW + "2")).status_code == 401
    assert (await login("vera", PW + "3")).status_code == 200


async def test_tenant_admin_scope_and_validation(env) -> None:  # type: ignore[no-untyped-def]
    c, login, admin, _ = env
    await c.post("/v1/tenants", json={"id": "other", "name": "Other"}, headers=admin)
    await c.post("/v1/users", json=new_user("tadmin", "admin", ["bank"]), headers=admin)
    await c.post("/v1/users", json=new_user("outsider", "viewer", ["other"]), headers=admin)
    ta = bearer((await login("tadmin", PW)).json()["access_token"])
    assert (
        await c.post("/v1/users", json=new_user("newuser1", "viewer", ["bank"]), headers=ta)
    ).status_code == 201
    assert (
        await c.post("/v1/users", json=new_user("newuser2", "viewer", ["other"]), headers=ta)
    ).status_code == 403
    assert (
        await c.post("/v1/users", json=new_user("newuser3", "admin", ["*"]), headers=ta)
    ).status_code == 403
    assert {u["username"] for u in (await c.get("/v1/users", headers=ta)).json()} == {
        "tadmin",
        "newuser1",
    }
    assert (
        await c.patch("/v1/users/outsider", json={"disabled": True}, headers=ta)
    ).status_code == 404
    assert (
        await c.post("/v1/users", json=new_user("newuser4", "viewer", ["nope"]), headers=admin)
    ).status_code == 422
    assert (
        await c.post("/v1/users", json=new_user("newuser1", "viewer", ["bank"]), headers=admin)
    ).status_code == 409
    assert (
        await c.post(
            "/v1/users", json=new_user("newuser5", "viewer", ["bank"], "short"), headers=admin
        )
    ).status_code == 422
    assert (
        await c.post("/v1/users", json=new_user("Bad Name", "viewer", ["bank"]), headers=admin)
    ).status_code == 422


async def test_cannot_remove_last_platform_admin_or_self(env) -> None:  # type: ignore[no-untyped-def]
    c, login, admin, _ = env
    assert (
        await c.patch("/v1/users/root", json={"disabled": True}, headers=admin)
    ).status_code == 409
    assert (await c.delete("/v1/users/root", headers=admin)).status_code == 409
    await c.post("/v1/users", json=new_user("root2", "admin", ["*"]), headers=admin)
    r2 = bearer((await login("root2", PW)).json()["access_token"])
    # another platform admin exists now, so root may be demoted by root2 ...
    assert (await c.patch("/v1/users/root", json={"role": "viewer"}, headers=r2)).status_code == 200
    # ... but root2 is now the last one and cannot be removed
    assert (await c.delete("/v1/users/root2", headers=r2)).status_code == 409
    assert (
        await c.patch("/v1/users/root2", json={"role": "viewer"}, headers=r2)
    ).status_code == 409


async def test_forged_and_expired_tokens_rejected(env) -> None:  # type: ignore[no-untyped-def]
    c, _, _, _ = env
    now = int(time.time())
    claims = {
        "sub": "root",
        "roles": ["admin"],
        "tenants": ["*"],
        "aud": "aiops-control-plane",
        "iat": now,
    }
    forged = jwt.encode({**claims, "exp": now + 60}, "x" * 40, algorithm="HS256")
    assert (await c.get("/v1/me", headers=bearer(forged))).status_code == 401
    expired = jwt.encode({**claims, "exp": now - 10}, SESSION_SECRET, algorithm="HS256")
    assert (await c.get("/v1/me", headers=bearer(expired))).status_code == 401
    ghost = jwt.encode(
        {**claims, "sub": "ghost", "exp": now + 60}, SESSION_SECRET, algorithm="HS256"
    )
    assert (await c.get("/v1/me", headers=bearer(ghost))).status_code == 401  # no such account


def test_local_mode_requires_strong_secret() -> None:
    with pytest.raises(RuntimeError, match="SESSION_SECRET"):
        Authenticator(AuthSettings(mode="local"), "prod")
    _ = (datetime.now(UTC), timedelta(0))
