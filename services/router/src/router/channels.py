"""Per-tenant channel configuration from YAML with ``${ENV}`` secret references.

Secrets are never written in the file; they are injected as environment
variables (from Vault / External Secrets in Kubernetes, ``.env`` in dev).

    demo-bank:
      servicenow: {instance_url: "http://mock-servicenow:8080", mode: em_with_table_fallback,
                   username: aiops, password: "${SN_DEMO_PASSWORD}"}
      chat: {kind: slack, webhook_url: "${SLACK_WEBHOOK_DEMO}"}
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import httpx
import yaml
from pydantic import BaseModel

from aiops_common.resilience import CircuitBreaker
from router.adapters import (
    Adapter,
    ChatAdapter,
    ChatConfig,
    EmailAdapter,
    EmailConfig,
    KeepAdapter,
    KeepConfig,
    LogOnlyAdapter,
    ServiceNowAdapter,
    ServiceNowConfig,
)

_ENV = re.compile(r"\$\{([A-Z0-9_]+)\}")


class TenantChannels(BaseModel):
    servicenow: ServiceNowConfig | None = None
    keep: KeepConfig | None = None
    chat: ChatConfig | None = None
    email: EmailConfig | None = None


def _expand(obj: Any) -> Any:
    if isinstance(obj, str):
        return _ENV.sub(lambda m: os.environ.get(m.group(1), ""), obj)
    if isinstance(obj, dict):
        return {k: _expand(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_expand(v) for v in obj]
    return obj


def load_channels(path: str | None) -> dict[str, TenantChannels]:
    if not path or not Path(path).exists():
        return {}
    doc = _expand(yaml.safe_load(Path(path).read_text()) or {})
    return {t: TenantChannels.model_validate(c) for t, c in doc.items()}


class AdapterRegistry:
    def __init__(self, channels: dict[str, TenantChannels], client: httpx.AsyncClient) -> None:
        self.channels, self.client = channels, client
        self._cache: dict[tuple[str, str], Adapter] = {}

    def __call__(self, tenant: str, channel: str) -> Adapter | None:
        key = (tenant, channel)
        if key in self._cache:
            return self._cache[key]
        if channel == "log_only":
            self._cache[key] = LogOnlyAdapter()
            return self._cache[key]
        tc = self.channels.get(tenant) or self.channels.get("*")
        if tc is None:
            return None
        br = CircuitBreaker(f"{channel}:{tenant}", failure_threshold=5, reset_after=30)
        adapter: Adapter | None = None
        if channel == "servicenow" and tc.servicenow:
            adapter = ServiceNowAdapter(tc.servicenow, self.client, br)
        elif channel == "keep" and tc.keep:
            adapter = KeepAdapter(tc.keep, self.client, br)
        elif channel == "chat" and tc.chat:
            adapter = ChatAdapter(tc.chat, self.client, br)
        elif channel == "email" and tc.email:
            adapter = EmailAdapter(tc.email, br)
        if adapter is not None:
            self._cache[key] = adapter
        return adapter
