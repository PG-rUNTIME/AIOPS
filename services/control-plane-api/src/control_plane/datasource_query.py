"""Read-only queries against a tenant's registered connections.

The control plane runs these on behalf of the agent so credentials never leave it. Every call
re-checks the host (SSRF guard), refuses redirects, caps the response size and time, and only
supports a fixed set of read operations per system type.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from control_plane import connections as conn

MAX_BYTES = 256 * 1024
MAX_QUERY_CHARS = 2000
MAX_MINUTES = 360
TIMEOUT = httpx.Timeout(10.0, connect=5.0)

# system type -> operations it supports
OPS: dict[str, frozenset[str]] = {
    "prometheus": frozenset({"instant", "range"}),
    "victoriametrics": frozenset({"instant", "range"}),
    "loki": frozenset({"logs"}),
    "victorialogs": frozenset({"logs"}),
    "elasticsearch": frozenset({"logs"}),
    "opensearch": frozenset({"logs"}),
    "grafana": frozenset({"dashboards"}),
}


class QueryError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status, self.message = status, message


@dataclass(frozen=True)
class Target:
    kind: str
    url: str
    auth_type: str = "none"
    username: str | None = None
    header_name: str | None = None
    secret: str | None = None
    verify_tls: bool = True
    extra: dict[str, str] = field(default_factory=dict)


async def _send(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    auth: httpx.BasicAuth | None,
    params: dict[str, Any] | None = None,
    json_body: Any = None,
) -> str:
    try:
        async with client.stream(
            method, url, params=params, headers=headers, auth=auth, json=json_body
        ) as r:
            if 300 <= r.status_code < 400:
                raise QueryError(502, "the source redirected the request")
            if r.status_code in (401, 403):
                raise QueryError(502, "the source rejected the credentials")
            if r.status_code >= 400:
                raise QueryError(502, f"the source answered HTTP {r.status_code}")
            body = b""
            async for chunk in r.aiter_bytes():
                body += chunk
                if len(body) >= MAX_BYTES:
                    body = body[:MAX_BYTES]
                    break
            return body.decode("utf-8", "replace")
    except httpx.TimeoutException as e:
        raise QueryError(504, "the source timed out") from e
    except httpx.HTTPError as e:
        raise QueryError(502, "the source could not be reached") from e


def _lines_from_loki(text: str) -> str:
    try:
        streams = json.loads(text)["data"]["result"]
        out = [v[1] for st in streams for v in st["values"]]
    except (KeyError, ValueError, TypeError):
        return text
    return "\n".join(out) or "(no lines)"


def _lines_from_es(text: str) -> str:
    try:
        hits = json.loads(text)["hits"]["hits"]
    except (KeyError, ValueError, TypeError):
        return text
    return (
        "\n".join(json.dumps(h.get("_source", {}), separators=(",", ":")) for h in hits)
        or "(no lines)"
    )


def _dashboards(text: str) -> str:
    try:
        rows = json.loads(text)
    except ValueError:
        return text
    lines = [f"{r.get('title', '?')} | uid={r.get('uid', '?')} | {r.get('url', '')}" for r in rows]
    return "\n".join(lines) or "(no dashboards)"


async def run(
    t: Target,
    op: str,
    query: str,
    minutes: int = 30,
    *,
    client: httpx.AsyncClient | None = None,
) -> str:
    if op not in OPS.get(t.kind, frozenset()):
        raise QueryError(422, f"'{op}' is not supported by {t.kind}")
    if len(query) > MAX_QUERY_CHARS:
        raise QueryError(422, "query too long")
    minutes = max(1, min(int(minutes), MAX_MINUTES))
    try:
        base = conn.normalise_url(t.url)
        await conn.assert_safe_host(base)
    except conn.UrlRejected as e:
        raise QueryError(422, str(e)) from e
    headers, basic = conn.build_auth(t.auth_type, t.username, t.secret, t.header_name)
    own = client is None
    c = client or httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False, verify=t.verify_tls)
    kw: dict[str, Any] = {"headers": headers, "auth": basic}
    now = time.time()
    try:
        if t.kind in ("prometheus", "victoriametrics"):
            if op == "instant":
                return await _send(c, "GET", f"{base}/api/v1/query", params={"query": query}, **kw)
            params = {"query": query, "start": now - minutes * 60, "end": now, "step": 60}
            return await _send(c, "GET", f"{base}/api/v1/query_range", params=params, **kw)
        if t.kind == "loki":
            if t.extra.get("org_id"):
                headers["X-Scope-OrgID"] = t.extra["org_id"]
            p = {
                "query": query,
                "start": int((now - minutes * 60) * 1e9),
                "end": int(now * 1e9),
                "limit": 50,
            }
            return _lines_from_loki(
                await _send(c, "GET", f"{base}/loki/api/v1/query_range", params=p, **kw)
            )
        if t.kind == "victorialogs":
            p = {"query": query, "start": int(now - minutes * 60), "limit": 50}
            return await _send(c, "GET", f"{base}/select/logsql/query", params=p, **kw)
        if t.kind in ("elasticsearch", "opensearch"):
            index = t.extra.get("index_pattern") or "*"
            body = {
                "size": 50,
                "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
                "query": {
                    "bool": {
                        "must": [{"query_string": {"query": query}}],
                        "filter": [{"range": {"@timestamp": {"gte": f"now-{minutes}m"}}}],
                    }
                },
            }
            text = await _send(c, "POST", f"{base}/{index}/_search", json_body=body, **kw)
            return _lines_from_es(text)
        if t.kind == "grafana":
            p = {"query": query, "type": "dash-db", "limit": 20}
            return _dashboards(await _send(c, "GET", f"{base}/api/search", params=p, **kw))
        raise QueryError(422, f"{t.kind} cannot be queried")
    finally:
        if own:
            await c.aclose()
