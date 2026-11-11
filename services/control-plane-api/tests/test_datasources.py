"""Query gateway, internal endpoints and the metrics puller."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import httpx
import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from control_plane import datasource_query as dq
from control_plane import db
from control_plane.app import create_app
from control_plane.auth import Authenticator, AuthSettings, dev_token
from control_plane.poller import Poller, collect
from control_plane.remediation import DryRunExecutor
from control_plane.secretbox import SecretBox

SECRET = "dev-secret-for-tests-only-0123456789"
INTERNAL = {"X-Internal-Token": "internal-token-for-tests-0123456789"}
ADMIN = {"Authorization": f"Bearer {dev_token(SECRET, 'root', ['admin'], ['*'])}"}


def client_for(handler) -> httpx.AsyncClient:  # type: ignore[no-untyped-def]
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)


async def run(kind: str, op: str, handler, query: str = "q", **extra):  # type: ignore[no-untyped-def]
    t = dq.Target(kind, "http://10.1.2.3:9000", extra=extra)
    return await dq.run(t, op, query, 30, client=client_for(handler))


async def test_adapters_build_the_right_requests() -> None:
    seen: list[httpx.Request] = []

    def h(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        if "loki" in req.url.path:
            return httpx.Response(
                200, json={"data": {"result": [{"values": [["1", "disk full"], ["2", "retry"]]}]}}
            )
        if req.url.path.endswith("_search"):
            return httpx.Response(200, json={"hits": {"hits": [{"_source": {"msg": "boom"}}]}})
        if req.url.path == "/api/search":
            return httpx.Response(200, json=[{"title": "Node", "uid": "abc", "url": "/d/abc"}])
        return httpx.Response(200, json={"status": "success"})

    assert "success" in await run("prometheus", "instant", h)
    assert seen[-1].url.path == "/api/v1/query"
    await run("victoriametrics", "range", h)
    assert seen[-1].url.path == "/api/v1/query_range" and seen[-1].url.params["step"] == "60"
    assert await run("loki", "logs", h, org_id="acme") == "disk full\nretry"
    assert seen[-1].headers["x-scope-orgid"] == "acme"
    await run("victorialogs", "logs", h)
    assert seen[-1].url.path == "/select/logsql/query" and seen[-1].url.params["limit"] == "50"
    assert await run("elasticsearch", "logs", h, index_pattern="logs-*") == '{"msg":"boom"}'
    assert seen[-1].method == "POST" and seen[-1].url.path == "/logs-*/_search"
    assert "Node | uid=abc" in await run("grafana", "dashboards", h)


async def test_unsupported_and_unsafe_requests_are_refused() -> None:
    ok = lambda r: httpx.Response(200, json={})  # noqa: E731
    with pytest.raises(dq.QueryError) as e:
        await run("loki", "instant", ok)
    assert e.value.status == 422
    with pytest.raises(dq.QueryError):
        await run("tempo", "logs", ok)
    with pytest.raises(dq.QueryError):
        await dq.run(dq.Target("prometheus", "http://169.254.169.254"), "instant", "x")
    with pytest.raises(dq.QueryError):
        await dq.run(dq.Target("prometheus", "http://10.0.0.1"), "instant", "x" * 3000)


async def test_upstream_failures_are_mapped() -> None:
    for status, text in ((401, "rejected"), (500, "HTTP 500"), (302, "redirected")):
        with pytest.raises(dq.QueryError, match=text):
            await run("prometheus", "instant", lambda r, s=status: httpx.Response(s))

    def boom(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    with pytest.raises(dq.QueryError, match="could not be reached"):
        await run("prometheus", "instant", boom)


async def test_response_is_size_capped() -> None:
    big = lambda r: httpx.Response(200, content=b"x" * (dq.MAX_BYTES * 2))  # noqa: E731
    assert len(await run("prometheus", "instant", big)) == dq.MAX_BYTES


# ------------------------------------------------------------------ internal endpoints
@pytest.fixture
async def env(monkeypatch):  # type: ignore[no-untyped-def]
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as c:
        await c.run_sync(db.Base.metadata.create_all)
    box = SecretBox(Fernet.generate_key().decode())
    auth = Authenticator(AuthSettings(mode="dev", dev_secret=SecretStr(SECRET)), "dev")
    app = create_app(
        engine,
        auth,
        DryRunExecutor(),
        set(),
        secrets=box,
        internal_token=INTERNAL["X-Internal-Token"],
    )
    calls: list[tuple[dq.Target, str, str, int]] = []

    async def fake_run(t, op, query, minutes=30, **kw):  # type: ignore[no-untyped-def]
        calls.append((t, op, query, minutes))
        return "RESULT"

    monkeypatch.setattr(dq, "run", fake_run)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://x") as c:
        for t in ("bank", "other"):
            await c.post("/v1/tenants", json={"id": t, "name": t}, headers=ADMIN)
        body = {
            "name": "Prom",
            "kind": "prometheus",
            "url": "http://10.0.0.5:9090",
            "auth_type": "bearer",
            "secret": "tok-123",
        }
        cid = (await c.post("/v1/tenants/bank/connections", json=body, headers=ADMIN)).json()["id"]
        yield c, cid, calls, engine
    await engine.dispose()


async def test_internal_endpoints_require_the_token(env) -> None:  # type: ignore[no-untyped-def]
    c, cid, _, _ = env
    url = "/internal/v1/tenants/bank/data-sources"
    assert (await c.get(url)).status_code == 401
    assert (await c.get(url, headers={"X-Internal-Token": "nope"})).status_code == 401
    assert (await c.get(url, headers=ADMIN)).status_code == 401  # a user token is not enough
    rows = (await c.get(url, headers=INTERNAL)).json()
    assert rows == [
        {
            "id": cid,
            "name": "Prom",
            "kind": "prometheus",
            "category": "metrics",
            "ops": ["instant", "range"],
        }
    ]
    assert "tok-123" not in json.dumps(rows)
    assert "/internal/v1" not in json.dumps((await c.get("/openapi.json")).json()["paths"])


async def test_internal_endpoints_are_disabled_without_a_token() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    auth = Authenticator(AuthSettings(mode="dev", dev_secret=SecretStr(SECRET)), "dev")
    app = create_app(engine, auth, DryRunExecutor(), set())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://x") as c:
        assert (
            await c.get("/internal/v1/tenants/bank/data-sources", headers=INTERNAL)
        ).status_code == 404
    await engine.dispose()


async def test_query_uses_the_stored_secret_and_isolates_tenants(env) -> None:  # type: ignore[no-untyped-def]
    c, cid, calls, _ = env
    q = f"/internal/v1/tenants/bank/data-sources/{cid}/query"
    r = await c.post(q, json={"op": "instant", "query": "up", "minutes": 5}, headers=INTERNAL)
    assert (
        r.json() == {"text": "RESULT"}
        and calls[-1][0].secret == "tok-123"
        and calls[-1][1:] == ("instant", "up", 5)
    )
    # another tenant cannot reach it, and unknown ops / ids are rejected
    other = f"/internal/v1/tenants/other/data-sources/{cid}/query"
    assert (
        await c.post(other, json={"op": "instant", "query": "up"}, headers=INTERNAL)
    ).status_code == 404
    assert (
        await c.post(q, json={"op": "write", "query": "up"}, headers=INTERNAL)
    ).status_code == 422
    assert (
        await c.post(q.replace(cid, "nope"), json={"op": "instant", "query": "u"}, headers=INTERNAL)
    ).status_code == 404
    # disabling hides it
    body = {"name": "Prom", "kind": "prometheus", "url": "http://10.0.0.5:9090", "enabled": False}
    await c.put(f"/v1/tenants/bank/connections/{cid}", json=body, headers=ADMIN)
    assert (await c.get("/internal/v1/tenants/bank/data-sources", headers=INTERNAL)).json() == []
    assert (
        await c.post(q, json={"op": "instant", "query": "up"}, headers=INTERNAL)
    ).status_code == 404


async def test_ingest_option_is_validated(env) -> None:  # type: ignore[no-untyped-def]
    c, _, _, _ = env
    base = {"name": "P2", "kind": "prometheus", "url": "http://10.0.0.6:9090"}
    assert (
        await c.post(
            "/v1/tenants/bank/connections",
            json={**base, "extra": {"ingest": "true"}},
            headers=ADMIN,
        )
    ).status_code == 201
    assert (
        await c.post(
            "/v1/tenants/bank/connections",
            json={**base, "extra": {"ingest": "maybe"}},
            headers=ADMIN,
        )
    ).status_code == 422
    kinds = {k["id"]: k for k in (await c.get("/v1/connection-kinds", headers=ADMIN)).json()}
    assert (
        kinds["prometheus"]["bool_fields"][0]["key"] == "ingest"
        and not kinds["loki"]["bool_fields"]
    )


# ------------------------------------------------------------------ poller
def prom_handler(req: httpx.Request) -> httpx.Response:
    q = req.url.params["query"]
    ts = datetime.now(UTC).timestamp()

    def vec(metric: str, host: str, v: str, **lbl: str) -> dict[str, object]:
        return {"metric": {"instance": host, "job": "node", **lbl}, "value": [ts, v]}

    if q.startswith("node_filesystem_avail"):
        rows = [
            vec("a", "h1:9100", "20", mountpoint="/"),
            vec("a", "h2:9100", "NaN", mountpoint="/"),
        ]
    elif q.startswith("node_filesystem_size"):
        rows = [vec("s", "h1:9100", "100", mountpoint="/")]
    elif q.startswith("1 - avg"):
        rows = [vec("c", "h1:9100", "0.5")]
    else:
        rows = []
    return httpx.Response(200, json={"status": "success", "data": {"result": rows}})


async def test_collect_groups_points_per_host_and_drops_bad_values() -> None:
    out = await collect(
        dq.Target("prometheus", "http://10.1.1.1:9090"), "My Prom", client_for(prom_handler)
    )
    assert set(out) == {"h1:9100"}  # h2 only had a NaN
    names = {p.name for p in out["h1:9100"].points}
    assert names == {
        "node_filesystem_avail_bytes",
        "node_filesystem_size_bytes",
        "node_cpu_utilisation",
    }
    pt = next(p for p in out["h1:9100"].points if p.name.endswith("avail_bytes"))
    assert pt.labels == {"mountpoint": "/", "source": "My Prom"} and pt.value == 20.0
    assert out["h1:9100"].service == "node"


async def test_poller_posts_only_opted_in_sources_for_the_right_tenant(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as c:
        await c.run_sync(db.Base.metadata.create_all)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    now = datetime.now(UTC)
    async with sessions.begin() as s:
        s.add_all(
            [
                db.Tenant(id="bank", name="b", created_at=now),
                db.Tenant(id="nokey", name="n", created_at=now),
            ]
        )
        await s.flush()
        for tenant, name, ingest in (
            ("bank", "on", "true"),
            ("bank", "off", "false"),
            ("nokey", "x", "true"),
        ):
            s.add(
                db.Connection(
                    id=f"id-{name}",
                    tenant_id=tenant,
                    name=name,
                    kind="prometheus",
                    url="http://10.1.1.1:9090",
                    auth_type="none",
                    verify_tls=True,
                    enabled=True,
                    extra={"ingest": ingest},
                    created_by="t",
                    created_at=now,
                    updated_at=now,
                )
            )
    posted: list[httpx.Request] = []

    def ingest(req: httpx.Request) -> httpx.Response:
        posted.append(req)
        return httpx.Response(202, json={"accepted": 1})

    async def fake_run(t, op, query, minutes=30, **kw):  # type: ignore[no-untyped-def]
        return prom_handler(httpx.Request("GET", "http://x", params={"query": query})).text

    monkeypatch.setattr(dq, "run", fake_run)
    poller = Poller(
        sessions, None, "http://ingest:8080", {"bank": "k-bank"}, client=client_for(ingest)
    )
    assert await poller.poll_once() == {"bank": 1}
    assert len(posted) == 1
    req = posted[0]
    assert req.url.path == "/v1/aiops/metrics" and req.headers["authorization"] == "Bearer k-bank"
    assert req.headers["x-aiops-tenant"] == "bank"
    body = json.loads(req.content)
    assert body["tenant_id"] == "bank" and body["ci_id"] == "h1:9100"
    await engine.dispose()
