"""Ingest gateway: validate tenant, redact PII, enrich labels, publish to Kafka.

Endpoints
* ``POST /v1/metrics`` and ``POST /v1/logs`` — OTLP/HTTP with **JSON** encoding
  (``Content-Type: application/json``), as sent by the OTel Collector
  ``otlphttp`` exporter with ``encoding: json``. Protobuf is rejected with 415.
* ``POST /v1/aiops/metrics`` and ``/v1/aiops/logs`` — native MetricBatch / LogBatch.

Tenant: ``X-AIOps-Tenant`` (or ``X-Scope-OrgID``) + ``Authorization: Bearer <key>``;
keys are stored as SHA-256 hashes (``AIOPS_TENANT_KEYS='{"tenant": "<sha256>"}'``).
CI resolution: resource attribute ``ci_id`` → ``host.name`` → ``service.instance.id``.
"""

from __future__ import annotations

import hashlib
import hmac
from collections import defaultdict
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from prometheus_client import Counter

from aiops_common.bus import EventBus
from aiops_common.cloudevents import make_event
from aiops_common.contracts.models import LogBatch, LogRecord, MetricBatch, MetricPoint
from aiops_common.contracts.registry import Topics
from aiops_common.http import ops_router
from aiops_common.redaction import redact

SOURCE = "urn:aiops:ingest-gateway"
INGESTED = Counter("aiops_ingest_items_total", "Items ingested", ["tenant", "kind"])
REDACTED = Counter("aiops_ingest_redactions_total", "PII redactions", ["tenant", "rule"])
REJECTED = Counter("aiops_ingest_rejected_total", "Rejected requests", ["reason"])

MAX_BATCH = 5000


def _attrs(kvs: list[dict[str, Any]] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for kv in kvs or []:
        v = kv.get("value", {})
        val = next(iter(v.values()), "") if isinstance(v, dict) and v else ""
        out[str(kv.get("key"))] = str(val)
    return out


def _ts(nanos: str | int | None) -> datetime:
    return datetime.fromtimestamp(int(nanos or 0) / 1e9, UTC) if nanos else datetime.now(UTC)


def _ci(res: dict[str, str]) -> str | None:
    return res.get("ci_id") or res.get("host.name") or res.get("service.instance.id")


def otlp_metrics_to_batches(tenant: str, doc: dict[str, Any]) -> list[MetricBatch]:
    """Group points per CI. ``ci_id`` may be a resource attribute (OTel SDKs) or a
    datapoint label (Prometheus scrapes converted by Alloy/OTel ``prometheus`` receiver)."""
    groups: dict[tuple[str, str], list[MetricPoint]] = defaultdict(list)
    for rm in doc.get("resourceMetrics", []):
        res = _attrs(rm.get("resource", {}).get("attributes"))
        svc_default = res.get("service.name", "unknown")
        for sm in rm.get("scopeMetrics", []):
            for m in sm.get("metrics", []):
                data = m.get("gauge") or m.get("sum")
                if not data:
                    continue  # histograms/summaries: use derived gauges upstream
                for dp in data.get("dataPoints", []):
                    raw = dp.get("asDouble", dp.get("asInt"))
                    if raw is None:
                        continue
                    dpa = _attrs(dp.get("attributes"))
                    ci = dpa.get("ci_id") or _ci(res)
                    if not ci:
                        continue
                    svc = dpa.get("service") or svc_default
                    labels = dpa | {"ci_id": ci, "service": svc}
                    groups[(ci, svc)].append(
                        MetricPoint(
                            name=m["name"],
                            labels=labels,
                            ts=_ts(dp.get("timeUnixNano")),
                            value=float(raw),
                        )
                    )
    return [
        MetricBatch(tenant_id=tenant, ci_id=ci, service=svc, points=pts[i : i + MAX_BATCH])
        for (ci, svc), pts in groups.items()
        for i in range(0, len(pts), MAX_BATCH)
    ]


def otlp_logs_to_batches(tenant: str, doc: dict[str, Any]) -> list[LogBatch]:
    groups: dict[tuple[str, str], list[LogRecord]] = defaultdict(list)
    for rl in doc.get("resourceLogs", []):
        res = _attrs(rl.get("resource", {}).get("attributes"))
        ci = _ci(res)
        if not ci:
            continue
        svc = res.get("service.name", "unknown")
        for sl in rl.get("scopeLogs", []):
            for lr in sl.get("logRecords", []):
                body = lr.get("body", {})
                text = str(next(iter(body.values()), "")) if isinstance(body, dict) else str(body)
                groups[(ci, svc)].append(
                    LogRecord(
                        ts=_ts(lr.get("timeUnixNano") or lr.get("observedTimeUnixNano")),
                        severity=lr.get("severityText") or "INFO",
                        body=text[:16_384],
                        attributes=_attrs(lr.get("attributes")),
                    )
                )
    return [
        LogBatch(tenant_id=tenant, ci_id=ci, service=svc, records=recs)
        for (ci, svc), recs in groups.items()
    ]


class Ingest:
    def __init__(
        self, bus: EventBus, tenant_keys: dict[str, str], require_auth: bool = True
    ) -> None:
        self.bus, self.tenant_keys, self.require_auth = bus, tenant_keys, require_auth

    def tenant(self, tenant: str | None, authorization: str | None) -> str:
        if not tenant:
            REJECTED.labels("no_tenant").inc()
            raise HTTPException(401, "missing X-AIOps-Tenant header")
        if not self.require_auth:
            return tenant
        expected = self.tenant_keys.get(tenant)
        token = (authorization or "").removeprefix("Bearer ").strip()
        got = hashlib.sha256(token.encode()).hexdigest()
        if not expected or not token or not hmac.compare_digest(expected, got):
            REJECTED.labels("bad_key").inc()
            raise HTTPException(403, "invalid tenant credentials")
        return tenant

    def redact_logs(self, b: LogBatch) -> LogBatch:
        for r in b.records:
            r.body, counts = redact(r.body)
            r.attributes = {k: redact(v)[0] for k, v in r.attributes.items()}
            for rule, n in counts.items():
                REDACTED.labels(b.tenant_id, rule).inc(n)
        return b

    async def publish_metrics(self, batches: list[MetricBatch]) -> int:
        n = 0
        for b in batches:
            await self.bus.publish(Topics.METRICS, make_event(b, source=SOURCE))
            n += len(b.points)
            INGESTED.labels(b.tenant_id, "metric").inc(len(b.points))
        return n

    async def publish_logs(self, batches: list[LogBatch]) -> int:
        n = 0
        for b in batches:
            await self.bus.publish(Topics.LOGS, make_event(self.redact_logs(b), source=SOURCE))
            n += len(b.records)
            INGESTED.labels(b.tenant_id, "log").inc(len(b.records))
        return n


def create_app(ing: Ingest, ready: Callable[[], bool] = lambda: True) -> FastAPI:
    app = FastAPI(title="ingest-gateway", version="0.1.0")
    app.include_router(ops_router(ready))

    def _tenant(x_aiops_tenant: str | None, x_scope_orgid: str | None, auth: str | None) -> str:
        return ing.tenant(x_aiops_tenant or x_scope_orgid, auth)

    async def _json(request: Request) -> dict[str, Any]:
        if "json" not in request.headers.get("content-type", ""):
            raise HTTPException(415, "only OTLP/HTTP JSON encoding is supported")
        doc: dict[str, Any] = await request.json()
        return doc

    @app.post("/v1/metrics")
    async def otlp_metrics(
        request: Request,
        x_aiops_tenant: str | None = Header(None),
        x_scope_orgid: str | None = Header(None),
        authorization: str | None = Header(None),
    ) -> dict[str, Any]:
        t = _tenant(x_aiops_tenant, x_scope_orgid, authorization)
        await ing.publish_metrics(otlp_metrics_to_batches(t, await _json(request)))
        return {"partialSuccess": {}}

    @app.post("/v1/logs")
    async def otlp_logs(
        request: Request,
        x_aiops_tenant: str | None = Header(None),
        x_scope_orgid: str | None = Header(None),
        authorization: str | None = Header(None),
    ) -> dict[str, Any]:
        t = _tenant(x_aiops_tenant, x_scope_orgid, authorization)
        await ing.publish_logs(otlp_logs_to_batches(t, await _json(request)))
        return {"partialSuccess": {}}

    @app.post("/v1/aiops/metrics", status_code=202)
    async def native_metrics(
        batch: MetricBatch,
        x_aiops_tenant: str | None = Header(None),
        authorization: str | None = Header(None),
    ) -> dict[str, int]:
        t = _tenant(x_aiops_tenant, None, authorization)
        if batch.tenant_id != t:
            raise HTTPException(403, "tenant mismatch")
        return {"accepted": await ing.publish_metrics([batch])}

    @app.post("/v1/aiops/logs", status_code=202)
    async def native_logs(
        batch: LogBatch,
        x_aiops_tenant: str | None = Header(None),
        authorization: str | None = Header(None),
    ) -> dict[str, int]:
        t = _tenant(x_aiops_tenant, None, authorization)
        if batch.tenant_id != t:
            raise HTTPException(403, "tenant mismatch")
        return {"accepted": await ing.publish_logs([batch])}

    return app
