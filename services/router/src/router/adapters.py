"""Delivery adapters. Each takes an outbox row and returns an external reference.

ServiceNow:
* Event Management: ``POST /api/global/em/jsonv2`` with ``{"records": [...]}``
  (ServiceNow docs, "Pushing events to the instance using web service API").
  ``message_key`` = incident_key, so re-sends update the same alert and a
  severity ``0`` (Clear) event closes it. Requires role ``evt_mgmt_integration``.
* Table API fallback: ``POST /api/now/table/incident``; idempotent through
  ``correlation_id`` = incident_key (looked up before creating).
Keep: ``POST /alerts/event/{provider_type}`` with header ``X-API-KEY`` (Keep API
reference "receive event"). Body fields follow Keep's AlertDto; verify against
your Keep version — isolated here on purpose.
"""

from __future__ import annotations

import asyncio
import json
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Any, Literal, Protocol

import httpx
from pydantic import BaseModel, SecretStr

from aiops_common.resilience import CircuitBreaker
from router.db import OutboxRow


class DeliveryError(RuntimeError):
    def __init__(self, msg: str, *, retryable: bool = True) -> None:
        super().__init__(msg)
        self.retryable = retryable


class Adapter(Protocol):
    name: str

    async def send(self, row: OutboxRow) -> str: ...


def _check(r: httpx.Response) -> None:
    if r.status_code >= 500 or r.status_code == 429:
        raise DeliveryError(f"HTTP {r.status_code}: {r.text[:200]}")
    if r.status_code >= 400:
        raise DeliveryError(f"HTTP {r.status_code}: {r.text[:200]}", retryable=False)


# --------------------------------------------------------------------------- ServiceNow
class ServiceNowConfig(BaseModel):
    instance_url: str
    mode: Literal["em", "table", "em_with_table_fallback"] = "em_with_table_fallback"
    username: str | None = None
    password: SecretStr | None = None
    oauth_token: SecretStr | None = None
    event_source: str = "AIOps"
    assignment_group: str | None = None
    resolve_state: str | None = None  # e.g. "6" (Resolved); None → only add a work note on Clear
    close_code: str | None = None


# ServiceNow EM severities: 0 Clear, 1 Critical, 2 Major, 3 Minor, 4 Warning, 5 Info
EM_SEVERITY = {1: "1", 2: "2", 3: "3", 4: "4", 5: "5"}
# Table API: impact/urgency 1..3
TABLE_IMPACT_URGENCY = {1: ("1", "1"), 2: ("1", "2"), 3: ("2", "2"), 4: ("3", "3"), 5: ("3", "3")}


@dataclass
class ServiceNowAdapter:
    cfg: ServiceNowConfig
    client: httpx.AsyncClient
    breaker: CircuitBreaker
    name: str = "servicenow"

    def _auth(self) -> dict[str, Any]:
        if self.cfg.oauth_token:
            return {
                "headers": {"Authorization": f"Bearer {self.cfg.oauth_token.get_secret_value()}"}
            }
        if self.cfg.username and self.cfg.password:
            return {"auth": (self.cfg.username, self.cfg.password.get_secret_value())}
        return {}

    def _url(self, path: str) -> str:
        return f"{self.cfg.instance_url.rstrip('/')}{path}"

    async def send(self, row: OutboxRow) -> str:
        async def go() -> str:
            if self.cfg.mode == "table":
                return await self._table(row)
            try:
                return await self._em(row)
            except DeliveryError as e:
                if self.cfg.mode == "em_with_table_fallback" and not e.retryable:
                    return await self._table(row)  # EM not licensed / not permitted
                raise

        return await self.breaker.call(go)

    def em_record(self, row: OutboxRow) -> dict[str, Any]:
        p = row.payload
        clear = row.action == "clear"
        additional = {
            "tenant_id": row.tenant_id,
            "incident_key": row.incident_key,
            "status": p["status"],
            "confidence": p["confidence"],
            "eta_minutes": p["eta_minutes"],
            "recommended_actions": p["recommended_actions"],
            "runbook_ref": p["runbook_ref"],
            "grafana_links": p["grafana_links"],
            "model_id": p["model_id"],
            "prompt_version": p["prompt_version"],
        }
        return {
            "source": self.cfg.event_source,
            "event_class": f"AIOps predictive ({row.tenant_id})",
            "node": row.ci_id,
            "resource": p["service"],
            "metric_name": p["failure_type"],
            "type": p["failure_type"],
            "severity": "0" if clear else EM_SEVERITY[row.priority],
            "message_key": row.incident_key,
            "description": ("Risk cleared. " if clear else "") + p["description"],
            # additional_info as a JSON *string*: object values render as [object Object]
            "additional_info": json.dumps(additional),
        }

    async def _em(self, row: OutboxRow) -> str:
        r = await self.client.post(
            self._url("/api/global/em/jsonv2"),
            json={"records": [self.em_record(row)]},
            **self._auth(),
        )
        _check(r)
        return f"em:{row.incident_key}"

    async def _table(self, row: OutboxRow) -> str:
        p = row.payload
        q = {
            "sysparm_query": f"correlation_id={row.incident_key}",
            "sysparm_limit": "1",
            "sysparm_fields": "sys_id,number,state",
        }
        r = await self.client.get(self._url("/api/now/table/incident"), params=q, **self._auth())
        _check(r)
        existing = r.json().get("result") or []
        if existing:
            sys_id, number = existing[0]["sys_id"], existing[0]["number"]
            body: dict[str, Any] = {
                "work_notes": (
                    "AIOps: risk cleared."
                    if row.action == "clear"
                    else f"AIOps update:\n{p['description']}"
                )
            }
            if row.action == "clear" and self.cfg.resolve_state:
                body |= {
                    "state": self.cfg.resolve_state,
                    "close_code": self.cfg.close_code or "",
                    "close_notes": "Predicted failure did not materialise / risk passed (AIOps).",
                }
            r = await self.client.patch(
                self._url(f"/api/now/table/incident/{sys_id}"), json=body, **self._auth()
            )
            _check(r)
            return str(number)
        if row.action == "clear":
            return "noop:no-ticket"
        impact, urgency = TABLE_IMPACT_URGENCY[row.priority]
        body = {
            "short_description": p["title"],
            "description": p["description"],
            "cmdb_ci": row.ci_id,
            "impact": impact,
            "urgency": urgency,
            "correlation_id": row.incident_key,
            "correlation_display": "AIOps",
            "category": "Software" if row.channel != "network" else "Network",
        }
        if self.cfg.assignment_group:
            body["assignment_group"] = self.cfg.assignment_group
        r = await self.client.post(self._url("/api/now/table/incident"), json=body, **self._auth())
        _check(r)
        return str(r.json()["result"]["number"])


# --------------------------------------------------------------------------- Keep
class KeepConfig(BaseModel):
    url: str
    api_key: SecretStr
    provider_type: str = "webhook"


KEEP_SEVERITY = {1: "critical", 2: "high", 3: "warning", 4: "info", 5: "low"}


@dataclass
class KeepAdapter:
    cfg: KeepConfig
    client: httpx.AsyncClient
    breaker: CircuitBreaker
    name: str = "keep"

    async def send(self, row: OutboxRow) -> str:
        p = row.payload
        body = {
            "id": row.incident_key,
            "fingerprint": row.incident_key,
            "name": p["title"],
            "status": "resolved" if row.action == "clear" else "firing",
            "severity": KEEP_SEVERITY[row.priority],
            "service": p["service"],
            "source": ["aiops"],
            "description": p["description"][:2000],
            "message": p["root_cause"],
            "labels": {
                "tenant_id": row.tenant_id,
                "ci_id": row.ci_id,
                "failure_type": p["failure_type"],
                "status": p["status"],
            },
            "url": (p["grafana_links"] or [None])[0],
        }

        async def go() -> str:
            r = await self.client.post(
                f"{self.cfg.url.rstrip('/')}/alerts/event/{self.cfg.provider_type}",
                params={"fingerprint": row.incident_key},
                json=body,
                headers={"X-API-KEY": self.cfg.api_key.get_secret_value()},
            )
            _check(r)
            return f"keep:{row.incident_key}"

        return await self.breaker.call(go)


# --------------------------------------------------------------------------- chat
class ChatConfig(BaseModel):
    kind: Literal["slack", "teams"]
    webhook_url: SecretStr


@dataclass
class ChatAdapter:
    cfg: ChatConfig
    client: httpx.AsyncClient
    breaker: CircuitBreaker
    name: str = "chat"

    def body(self, row: OutboxRow) -> dict[str, Any]:
        p = row.payload
        head = ("✅ CLEARED: " if row.action == "clear" else f"P{row.priority} ") + p["title"]
        text = f"{head}\n{p['description'][:1500]}"
        if self.cfg.kind == "slack":
            return {"text": text}
        return {  # Teams incoming webhook / Workflows: Adaptive Card message
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "body": [
                            {"type": "TextBlock", "text": head, "weight": "Bolder", "wrap": True},
                            {"type": "TextBlock", "text": p["description"][:1500], "wrap": True},
                        ],
                        "actions": [
                            {"type": "Action.OpenUrl", "title": "Grafana", "url": u}
                            for u in p["grafana_links"][:1]
                        ],
                    },
                }
            ],
        }

    async def send(self, row: OutboxRow) -> str:
        async def go() -> str:
            r = await self.client.post(self.cfg.webhook_url.get_secret_value(), json=self.body(row))
            _check(r)
            return f"{self.cfg.kind}:ok"

        return await self.breaker.call(go)


# --------------------------------------------------------------------------- email
class EmailConfig(BaseModel):
    host: str
    port: int = 587
    starttls: bool = True
    username: str | None = None
    password: SecretStr | None = None
    sender: str
    recipients: list[str]


@dataclass
class EmailAdapter:
    cfg: EmailConfig
    breaker: CircuitBreaker
    name: str = "email"

    def _send_sync(self, msg: EmailMessage) -> None:
        with smtplib.SMTP(self.cfg.host, self.cfg.port, timeout=15) as s:
            if self.cfg.starttls:
                s.starttls()
            if self.cfg.username and self.cfg.password:
                s.login(self.cfg.username, self.cfg.password.get_secret_value())
            s.send_message(msg)

    async def send(self, row: OutboxRow) -> str:
        p = row.payload
        msg = EmailMessage()
        msg["Subject"] = ("[CLEARED] " if row.action == "clear" else f"[P{row.priority}] ") + p[
            "title"
        ]
        msg["From"], msg["To"] = self.cfg.sender, ", ".join(self.cfg.recipients)
        msg["X-AIOps-Incident-Key"] = row.incident_key
        msg.set_content(p["description"])

        async def go() -> str:
            try:
                await asyncio.to_thread(self._send_sync, msg)
            except (OSError, smtplib.SMTPException) as e:
                raise DeliveryError(f"smtp: {e}") from e
            return "email:sent"

        return await self.breaker.call(go)


@dataclass
class LogOnlyAdapter:
    name: str = "log_only"

    async def send(self, row: OutboxRow) -> str:
        return "logged"
