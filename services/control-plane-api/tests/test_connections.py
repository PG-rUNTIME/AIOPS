"""Data-source connections: CRUD, encryption at rest, RBAC, tenant isolation, SSRF guard."""

from __future__ import annotations

import httpx
import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from control_plane import connections as conn
from control_plane import db
from control_plane.app import create_app
from control_plane.auth import Authenticator, AuthSettings, dev_token
from control_plane.remediation import DryRunExecutor
from control_plane.secretbox import SecretBox

SECRET = "dev-secret-for-tests-only-0123456789"


def tok(sub: str, role: str, tenants: list[str]) -> dict[str, str]:
    return {"Authorization": f"Bearer {dev_token(SECRET, sub, [role], tenants)}"}


ADMIN = tok("root", "admin", ["*"])
T_ADMIN = tok("ta", "admin", ["bank"])
OPER = tok("op", "operator", ["bank"])
VIEW = tok("vi", "viewer", ["bank"])
OTHER = tok("eve", "admin", ["other"])
BODY = {
    "name": "Prod Loki",
    "kind": "loki",
    "url": "http://10.0.0.5:3100/",
    "auth_type": "bearer",
    "secret": "s3cr3t-token",
    "extra": {"org_id": "bank"},
}


@pytest.fixture
async def env():  # type: ignore[no-untyped-def]
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as c:
        await c.run_sync(db.Base.metadata.create_all)
    box = SecretBox(Fernet.generate_key().decode())
    auth = Authenticator(AuthSettings(mode="dev", dev_secret=SecretStr(SECRET)), "dev")
    app = create_app(engine, auth, DryRunExecutor(), set(), secrets=box)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://x") as c:
        for t in ("bank", "other"):
            assert (
                await c.post("/v1/tenants", json={"id": t, "name": t}, headers=ADMIN)
            ).status_code == 201
        yield c, engine, box
    await engine.dispose()


async def test_crud_hides_and_encrypts_secret(env) -> None:  # type: ignore[no-untyped-def]
    c, engine, box = env
    r = await c.post("/v1/tenants/bank/connections", json=BODY, headers=T_ADMIN)
    assert r.status_code == 201, r.text
    out = r.json()
    assert out["has_secret"] is True and "secret" not in out and "s3cr3t" not in r.text
    assert out["url"] == "http://10.0.0.5:3100" and out["category"] == "logs"
    async with async_sessionmaker(engine)() as s:
        row = (await s.execute(select(db.Connection))).scalar_one()
    assert row.secret_enc and "s3cr3t" not in row.secret_enc
    assert box.decrypt(row.secret_enc) == "s3cr3t-token"
    cid = out["id"]
    listed = (await c.get("/v1/tenants/bank/connections", headers=VIEW)).json()
    assert [x["id"] for x in listed] == [cid] and "secret" not in listed[0]
    # edit without a secret keeps it; empty string clears it
    r = await c.put(
        f"/v1/tenants/bank/connections/{cid}",
        json={**BODY, "name": "Renamed", "secret": None},
        headers=T_ADMIN,
    )
    assert r.json()["name"] == "Renamed" and r.json()["has_secret"] is True
    r = await c.put(
        f"/v1/tenants/bank/connections/{cid}", json={**BODY, "secret": ""}, headers=T_ADMIN
    )
    assert r.json()["has_secret"] is False
    assert (
        await c.delete(f"/v1/tenants/bank/connections/{cid}", headers=T_ADMIN)
    ).status_code == 204
    assert (
        await c.delete(f"/v1/tenants/bank/connections/{cid}", headers=T_ADMIN)
    ).status_code == 404
    assert (await c.get("/v1/tenants/bank/connections", headers=VIEW)).json() == []


async def test_rbac_and_tenant_isolation(env) -> None:  # type: ignore[no-untyped-def]
    c, _, _ = env
    assert (
        await c.post("/v1/tenants/bank/connections", json=BODY, headers=OPER)
    ).status_code == 403
    assert (
        await c.post("/v1/tenants/bank/connections", json=BODY, headers=OTHER)
    ).status_code == 403
    cid = (await c.post("/v1/tenants/bank/connections", json=BODY, headers=T_ADMIN)).json()["id"]
    assert (await c.get("/v1/tenants/bank/connections", headers=OTHER)).status_code == 403
    # a tenant admin cannot reach another tenant's connection through their own tenant path
    assert (
        await c.delete(f"/v1/tenants/other/connections/{cid}", headers=OTHER)
    ).status_code == 404
    assert (
        await c.put(f"/v1/tenants/other/connections/{cid}", json=BODY, headers=OTHER)
    ).status_code == 404
    assert (await c.get("/v1/tenants/other/connections", headers=OTHER)).json() == []
    assert (
        await c.post(f"/v1/tenants/bank/connections/{cid}/test", headers=VIEW)
    ).status_code == 403


async def test_validation(env) -> None:  # type: ignore[no-untyped-def]
    c, _, _ = env
    post = lambda **kw: c.post("/v1/tenants/bank/connections", json={**BODY, **kw}, headers=T_ADMIN)  # noqa: E731
    assert (await post(kind="nope")).status_code == 422
    assert (await post(url="ftp://x")).status_code == 422
    assert (await post(url="http://user:pw@host")).status_code == 422
    assert (await post(url="http://host/?q=1")).status_code == 422
    assert (await post(auth_type="basic", username=None)).status_code == 422
    assert (await post(auth_type="header", header_name=None)).status_code == 422
    assert (await post(extra={"bogus": "1"})).status_code == 422
    assert (
        await c.post("/v1/tenants/ghost/connections", json=BODY, headers=ADMIN)
    ).status_code == 404


async def test_secret_requires_configured_key() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as cx:
        await cx.run_sync(db.Base.metadata.create_all)
    auth = Authenticator(AuthSettings(mode="dev", dev_secret=SecretStr(SECRET)), "dev")
    app = create_app(engine, auth, DryRunExecutor(), set())  # no secrets box
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://x") as c:
        await c.post("/v1/tenants", json={"id": "bank", "name": "b"}, headers=ADMIN)
        assert (
            await c.post("/v1/tenants/bank/connections", json=BODY, headers=ADMIN)
        ).status_code == 503
        open_ = {**BODY, "auth_type": "none", "secret": None}
        assert (
            await c.post("/v1/tenants/bank/connections", json=open_, headers=ADMIN)
        ).status_code == 201
    await engine.dispose()


async def test_catalogue(env) -> None:  # type: ignore[no-untyped-def]
    c, _, _ = env
    kinds = (await c.get("/v1/connection-kinds", headers=VIEW)).json()
    ids = {k["id"] for k in kinds}
    assert {"loki", "elasticsearch", "prometheus", "grafana", "tempo", "custom"} <= ids
    assert (await c.get("/v1/connection-kinds")).status_code == 401


# ------------------------------------------------------------------ connectivity test + SSRF
@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8080",
        "http://localhost",
        "http://169.254.169.254/latest/meta-data",
        "http://[::1]/",
        "http://0.0.0.0",
        "http://[fe80::1]/",
    ],
)
async def test_probe_blocks_unsafe_hosts(url: str) -> None:
    r = await conn.probe(
        kind="custom",
        url=url,
        auth_type="none",
        username=None,
        secret=None,
        header_name=None,
        verify_tls=True,
        extra={},
    )
    assert not r.ok and "not allowed" in r.message


async def test_probe_rejects_bad_scheme_and_unknown_kind() -> None:
    base = dict(
        auth_type="none", username=None, secret=None, header_name=None, verify_tls=True, extra={}
    )
    assert not (await conn.probe(kind="custom", url="file:///etc/passwd", **base)).ok  # type: ignore[arg-type]
    assert "Unknown" in (await conn.probe(kind="zzz", url="http://10.0.0.1", **base)).message  # type: ignore[arg-type]


def _client(handler) -> httpx.AsyncClient:  # type: ignore[no-untyped-def]
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)


async def _probe(handler, **kw):  # type: ignore[no-untyped-def]
    args = dict(
        kind="loki",
        url="http://10.1.2.3:3100",
        auth_type="none",
        username=None,
        secret=None,
        header_name=None,
        verify_tls=True,
        extra={},
    )
    args.update(kw)
    return await conn.probe(client=_client(handler), **args)  # type: ignore[arg-type]


async def test_probe_outcomes() -> None:
    seen: dict[str, str] = {}

    def ok(req: httpx.Request) -> httpx.Response:
        seen.update(req.headers)
        return httpx.Response(200, json={"status": "success", "data": ["a", "b", "c"]})

    r = await _probe(ok, auth_type="bearer", secret="tkn", extra={"org_id": "acme"})
    assert r.ok and "3 labels" in r.message
    assert seen["authorization"] == "Bearer tkn" and seen["x-scope-orgid"] == "acme"
    assert not (await _probe(lambda q: httpx.Response(401), auth_type="bearer", secret="x")).ok
    assert "requires authentication" in (await _probe(lambda q: httpx.Response(403))).message
    assert "HTTP 500" in (await _probe(lambda q: httpx.Response(500))).message
    redirect = await _probe(
        lambda q: httpx.Response(302, headers={"location": "http://169.254.169.254"})
    )
    assert not redirect.ok and "redirected" in redirect.message  # never followed

    def boom(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    assert "Could not connect" in (await _probe(boom)).message
    es = await _probe(
        lambda q: httpx.Response(200, json={"cluster_name": "c1", "version": {"number": "8.9.0"}}),
        kind="elasticsearch",
    )
    assert es.ok and "8.9.0" in es.message and "c1" in es.message
    custom_path: list[str] = []
    await _probe(
        lambda q: (custom_path.append(q.url.path), httpx.Response(200))[1],
        kind="custom",
        extra={"test_path": "/healthz"},
    )
    assert custom_path == ["/healthz"]


async def test_endpoint_test_does_not_leak_or_persist_unsaved(env) -> None:  # type: ignore[no-untyped-def]
    c, _, _ = env
    r = await c.post(
        "/v1/tenants/bank/connections/test",
        json={**BODY, "url": "http://169.254.169.254"},
        headers=T_ADMIN,
    )
    assert r.status_code == 200 and r.json()["ok"] is False and "not allowed" in r.json()["message"]
    assert (await c.get("/v1/tenants/bank/connections", headers=VIEW)).json() == []
