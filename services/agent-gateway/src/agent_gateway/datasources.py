"""Client for the control plane's internal data-source gateway.

The agent never sees credentials: it asks the control plane to run a read-only query against one
of the tenant's registered connections and gets text back.
"""

from __future__ import annotations

import time
from typing import Any

import httpx


class DataSources:
    def __init__(
        self, base_url: str, token: str, http: httpx.AsyncClient, ttl: float = 30.0
    ) -> None:
        self.base, self.http, self.ttl = base_url.rstrip("/"), http, ttl
        self._headers = {"X-Internal-Token": token}
        self._cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}

    async def list(self, tenant: str) -> list[dict[str, Any]]:
        hit = self._cache.get(tenant)
        if hit and time.monotonic() - hit[0] < self.ttl:
            return hit[1]
        r = await self.http.get(
            f"{self.base}/internal/v1/tenants/{tenant}/data-sources", headers=self._headers
        )
        r.raise_for_status()
        rows: list[dict[str, Any]] = r.json()
        self._cache[tenant] = (time.monotonic(), rows)
        return rows

    async def query(
        self, tenant: str, source_id: str, op: str, query: str, minutes: int = 30
    ) -> str:
        r = await self.http.post(
            f"{self.base}/internal/v1/tenants/{tenant}/data-sources/{source_id}/query",
            json={"op": op, "query": query, "minutes": minutes},
            headers=self._headers,
        )
        if r.status_code >= 400:
            try:
                detail = r.json().get("detail", r.text)
            except ValueError:
                detail = r.text
            return f'{{"error": "data source query failed: {str(detail)[:200]}"}}'
        text: str = r.json()["text"]
        return text
