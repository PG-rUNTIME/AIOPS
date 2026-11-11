"""Pull host metrics from opted-in Prometheus-compatible connections into failure detection.

For each connection with ``ingest`` switched on, the standard node_exporter series the detectors
watch (disk, memory, CPU) are queried once a minute, grouped per host, and posted to the
ingest-gateway as that tenant. This turns a registered source into live telemetry.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import math
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from aiops_common.contracts.models import MetricBatch, MetricPoint
from control_plane import datasource_query as dq
from control_plane import db
from control_plane.secretbox import SecretBox

log = logging.getLogger("control-plane.poller")

FS = '{mountpoint="/",fstype!~"tmpfs|overlay|squashfs|ramfs"}'
# (series name the detectors expect, PromQL to fetch it, labels worth keeping)
NODE_QUERIES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("node_filesystem_avail_bytes", f"node_filesystem_avail_bytes{FS}", ("mountpoint",)),
    ("node_filesystem_size_bytes", f"node_filesystem_size_bytes{FS}", ("mountpoint",)),
    ("node_memory_MemAvailable_bytes", "node_memory_MemAvailable_bytes", ()),
    ("node_memory_MemTotal_bytes", "node_memory_MemTotal_bytes", ()),
    (
        "node_cpu_utilisation",
        '1 - avg by (instance, job) (rate(node_cpu_seconds_total{mode="idle"}[2m]))',
        (),
    ),
)
PROM_KINDS = ("prometheus", "victoriametrics")
MAX_HOSTS = 200


def _num(v: Any) -> float | None:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if math.isfinite(f) else None


async def collect(
    target: dq.Target, source: str, client: httpx.AsyncClient | None = None
) -> dict[str, MetricBatch]:
    """Query one source and return a MetricBatch per host (keyed by ``instance``)."""
    hosts: dict[str, dict[str, Any]] = {}
    for name, promql, keep in NODE_QUERIES:
        try:
            text = await dq.run(target, "instant", promql, client=client)
            rows = json.loads(text)["data"]["result"]
        except (dq.QueryError, ValueError, KeyError, TypeError) as e:
            log.warning(
                "poll query failed", extra={"source": source, "series": name, "err": str(e)}
            )
            continue
        for row in rows:
            m = row.get("metric", {})
            instance = m.get("instance")
            value = _num(row.get("value", [None, None])[1])
            if not instance or value is None or (len(hosts) >= MAX_HOSTS and instance not in hosts):
                continue
            h = hosts.setdefault(instance, {"service": m.get("job", "unknown"), "points": []})
            labels = {k: m[k] for k in keep if k in m} | {"source": source}
            ts = datetime.fromtimestamp(float(row["value"][0]), UTC)
            h["points"].append(MetricPoint(name=name, labels=labels, ts=ts, value=value))
    return {
        inst: MetricBatch(tenant_id="x", ci_id=inst, service=h["service"], points=h["points"])
        for inst, h in hosts.items()
        if h["points"]
    }


class Poller:
    def __init__(
        self,
        sessions: async_sessionmaker[Any],
        secrets: SecretBox | None,
        ingest_url: str,
        ingest_keys: dict[str, str],
        interval: float = 60.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.sessions, self.secrets = sessions, secrets
        self.ingest_url, self.keys, self.interval = ingest_url.rstrip("/"), ingest_keys, interval
        self.http = client or httpx.AsyncClient(timeout=10.0)

    async def _targets(self) -> list[tuple[str, str, dq.Target]]:
        out: list[tuple[str, str, dq.Target]] = []
        async with self.sessions() as s:
            tenants = (await s.execute(select(db.Tenant.id))).scalars().all()
        for tenant in tenants:
            async with db.tenant_session(self.sessions, tenant) as s:
                rows = (
                    await s.execute(
                        select(db.Connection).where(
                            db.Connection.tenant_id == tenant,
                            db.Connection.enabled.is_(True),
                            db.Connection.kind.in_(PROM_KINDS),
                        )
                    )
                ).scalars()
                for c in rows:
                    if str((c.extra or {}).get("ingest", "")).lower() != "true":
                        continue
                    secret = None
                    if c.secret_enc and self.secrets:
                        with contextlib.suppress(ValueError):
                            secret = self.secrets.decrypt(c.secret_enc)
                    out.append(
                        (
                            tenant,
                            c.name,
                            dq.Target(
                                c.kind,
                                c.url,
                                c.auth_type,
                                c.username,
                                c.header_name,
                                secret,
                                c.verify_tls,
                                {k: str(v) for k, v in (c.extra or {}).items()},
                            ),
                        )
                    )
        return out

    async def poll_once(self) -> dict[str, int]:
        sent: dict[str, int] = {}
        for tenant, name, target in await self._targets():
            key = self.keys.get(tenant)
            if not key:
                log.warning("no ingest key for tenant; skipping", extra={"tenant": tenant})
                continue
            try:
                batches = await collect(target, name)
            except Exception:
                log.exception("poll failed", extra={"tenant": tenant, "source": name})
                continue
            for inst, b in batches.items():
                b = b.model_copy(update={"tenant_id": tenant})
                try:
                    r = await self.http.post(
                        f"{self.ingest_url}/v1/aiops/metrics",
                        content=b.model_dump_json(),
                        headers={
                            "X-AIOps-Tenant": tenant,
                            "Authorization": f"Bearer {key}",
                            "Content-Type": "application/json",
                        },
                    )
                    if r.status_code >= 300:
                        log.warning(
                            "ingest rejected batch", extra={"status": r.status_code, "ci": inst}
                        )
                        continue
                    sent[tenant] = sent.get(tenant, 0) + 1
                except httpx.HTTPError:
                    log.warning("ingest unreachable", extra={"ci": inst})
        return sent

    async def run(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            try:
                sent = await self.poll_once()
                if sent:
                    log.info("polled sources", extra={"batches": sent})
            except Exception:
                log.exception("poll cycle failed")
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=self.interval)
