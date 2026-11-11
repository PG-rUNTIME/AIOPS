"""Data-source connections: the catalogue of supported systems and a safe connectivity test.

The test makes an outbound request to a user-supplied URL, so it is guarded against SSRF:
http/https only, no embedded credentials, no redirects, and hostnames must not resolve to
loopback, link-local (cloud metadata), multicast or unspecified addresses. Private (RFC 1918)
ranges are allowed because internal log servers live there. Response bodies are never echoed.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx

Category = Literal["logs", "metrics", "traces", "dashboards", "other"]
AuthType = Literal["none", "basic", "bearer", "header"]


@dataclass(frozen=True)
class Kind:
    id: str
    label: str
    category: Category
    example_url: str
    test_path: str
    hint: str
    extra_fields: tuple[tuple[str, str], ...] = ()  # (key, label): text options
    bool_fields: tuple[tuple[str, str], ...] = ()  # (key, label): checkboxes, stored "true"/"false"


KINDS: tuple[Kind, ...] = (
    Kind(
        "loki",
        "Grafana Loki",
        "logs",
        "http://loki:3100",
        "/loki/api/v1/labels",
        "Log aggregation. Multi-tenant Loki needs the tenant (org) id.",
        (("org_id", "Tenant / org id (X-Scope-OrgID)"),),
    ),
    Kind(
        "elasticsearch",
        "Elasticsearch",
        "logs",
        "https://elastic.example.com:9200",
        "/",
        "Search and log store.",
        (("index_pattern", "Index pattern (e.g. logs-*)"),),
    ),
    Kind(
        "opensearch",
        "OpenSearch",
        "logs",
        "https://opensearch.example.com:9200",
        "/",
        "Search and log store.",
        (("index_pattern", "Index pattern (e.g. logs-*)"),),
    ),
    Kind(
        "victorialogs",
        "VictoriaLogs",
        "logs",
        "http://victorialogs:9428",
        "/health",
        "Log database from VictoriaMetrics.",
    ),
    Kind(
        "splunk",
        "Splunk",
        "logs",
        "https://splunk.example.com:8089",
        "/services/server/info?output_mode=json",
        "Management port (8089). Use a bearer token.",
    ),
    Kind(
        "prometheus",
        "Prometheus",
        "metrics",
        "http://prometheus:9090",
        "/api/v1/query?query=vector(1)",
        "Metrics store.",
        bool_fields=(
            ("ingest", "Feed this source into failure detection (pulls host metrics every minute)"),
        ),
    ),
    Kind(
        "victoriametrics",
        "VictoriaMetrics",
        "metrics",
        "http://victoriametrics:8428",
        "/api/v1/query?query=vector(1)",
        "Metrics store, Prometheus-compatible.",
        bool_fields=(
            ("ingest", "Feed this source into failure detection (pulls host metrics every minute)"),
        ),
    ),
    Kind(
        "tempo",
        "Grafana Tempo",
        "traces",
        "http://tempo:3200",
        "/ready",
        "Distributed tracing backend.",
    ),
    Kind(
        "grafana",
        "Grafana",
        "dashboards",
        "https://grafana.example.com",
        "/api/health",
        "Dashboards. Add a service-account token to verify access.",
    ),
    Kind(
        "custom",
        "Custom HTTP endpoint",
        "other",
        "https://service.example.com",
        "/",
        "Any HTTP service. Set the path to probe.",
        (("test_path", "Health path (e.g. /healthz)"),),
    ),
)
KIND_BY_ID = {k.id: k for k in KINDS}


class UrlRejected(ValueError):
    pass


def normalise_url(url: str) -> str:
    url = url.strip()
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise UrlRejected("URL must start with http:// or https:// and include a host.")
    if parts.username or parts.password:
        raise UrlRejected("Do not put credentials in the URL; use the authentication fields.")
    if parts.query or parts.fragment:
        raise UrlRejected("URL must not include a query string or fragment.")
    return url.rstrip("/")


def _blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return (
        ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved
    )


async def assert_safe_host(url: str) -> None:
    host = urlsplit(url).hostname or ""
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise UrlRejected(f"Host '{host}' could not be resolved.") from e
    for info in infos:
        if _blocked(ipaddress.ip_address(info[4][0])):
            raise UrlRejected("That address is not allowed (loopback, link-local or reserved).")


@dataclass
class TestResult:
    ok: bool
    message: str
    status_code: int | None = None
    latency_ms: int | None = None


def build_auth(
    auth_type: str, username: str | None, secret: str | None, header_name: str | None
) -> tuple[dict[str, str], httpx.BasicAuth | None]:
    headers: dict[str, str] = {}
    basic = None
    if auth_type == "bearer" and secret:
        headers["Authorization"] = f"Bearer {secret}"
    elif auth_type == "basic" and username is not None:
        basic = httpx.BasicAuth(username, secret or "")
    elif auth_type == "header" and header_name and secret:
        headers[header_name] = secret
    return headers, basic


def _describe(kind: str, status: int, body: Any) -> str:
    """A short, safe summary from known fields only: never the raw response."""
    d = body if isinstance(body, dict) else {}
    if kind in ("elasticsearch", "opensearch"):
        v = (d.get("version") or {}).get("number") if isinstance(d.get("version"), dict) else None
        return (
            f"{kind.title()} {v or ''} cluster '{d.get('cluster_name', '?')}' reachable.".replace(
                "  ", " "
            )
        )
    if kind == "loki":
        n = len(d["data"]) if isinstance(d.get("data"), list) else None
        return "Loki reachable" + (f"; {n} labels visible." if n is not None else ".")
    if kind in ("prometheus", "victoriametrics"):
        state = "OK" if d.get("status") == "success" else "responded"
        return f"{KIND_BY_ID[kind].label} reachable; query API {state}."
    if kind == "grafana":
        return f"Grafana {d.get('version', '')} reachable.".replace("  ", " ")
    if kind == "splunk":
        c = d.get("generator", {}) if isinstance(d.get("generator"), dict) else {}
        return f"Splunk {c.get('version', '')} reachable.".replace("  ", " ")
    return f"Reachable (HTTP {status})."


async def probe(
    *,
    kind: str,
    url: str,
    auth_type: str,
    username: str | None,
    secret: str | None,
    header_name: str | None,
    verify_tls: bool,
    extra: dict[str, str],
    client: httpx.AsyncClient | None = None,
) -> TestResult:
    spec = KIND_BY_ID.get(kind)
    if spec is None:
        return TestResult(False, "Unknown connection type.")
    try:
        base = normalise_url(url)
        await assert_safe_host(base)
    except UrlRejected as e:
        return TestResult(False, str(e))
    path = extra.get("test_path") or spec.test_path if kind == "custom" else spec.test_path
    if not path.startswith("/"):
        path = "/" + path
    headers, basic = build_auth(auth_type, username, secret, header_name)
    if kind == "loki" and extra.get("org_id"):
        headers["X-Scope-OrgID"] = extra["org_id"]
    own = client is None
    c = client or httpx.AsyncClient(timeout=8.0, follow_redirects=False, verify=verify_tls)
    t0 = time.perf_counter()
    try:
        r = await c.get(base + path, headers=headers, auth=basic)
    except httpx.ConnectTimeout:
        return TestResult(False, "Timed out connecting. Check the host, port and firewall.")
    except httpx.ReadTimeout:
        return TestResult(False, "Connected, but the server did not respond in time.")
    except httpx.ConnectError as e:
        reason = (
            "TLS certificate could not be verified."
            if "CERTIFICATE" in str(e).upper()
            else "Could not connect. Check the host, port and that the service is running."
        )
        return TestResult(False, reason)
    except httpx.HTTPError:
        return TestResult(False, "The request failed. Check the URL and TLS settings.")
    finally:
        if own:
            await c.aclose()
    ms = int((time.perf_counter() - t0) * 1000)
    if 300 <= r.status_code < 400:
        return TestResult(
            False, "The server redirected the request; use the final URL.", r.status_code, ms
        )
    if r.status_code in (401, 403):
        return TestResult(
            False,
            "Reachable, but the credentials were rejected."
            if auth_type != "none"
            else "Reachable, but it requires authentication.",
            r.status_code,
            ms,
        )
    if not r.is_success:
        return TestResult(False, f"The server answered HTTP {r.status_code}.", r.status_code, ms)
    try:
        body = r.json()
    except ValueError:
        body = None
    return TestResult(True, _describe(kind, r.status_code, body), r.status_code, ms)
