"""Per-tenant concurrency limits and daily token budgets."""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field

from prometheus_client import Gauge

INFLIGHT = Gauge("aiops_agent_inflight", "In-flight investigations", ["tenant"])
TOKENS = Gauge("aiops_agent_tokens_used_today", "Tokens used in the current day", ["tenant"])


class BudgetExceededError(RuntimeError):
    pass


@dataclass
class TenantLimiter:
    max_inflight: int = 2
    tokens_per_day: int = 500_000
    clock: Callable[[], float] = time.time
    _sems: dict[str, asyncio.Semaphore] = field(default_factory=dict)
    _used: dict[tuple[str, int], int] = field(default_factory=lambda: defaultdict(int))

    def _day(self) -> int:
        return int(self.clock() // 86400)

    def semaphore(self, tenant: str) -> asyncio.Semaphore:
        if tenant not in self._sems:
            self._sems[tenant] = asyncio.Semaphore(self.max_inflight)
        return self._sems[tenant]

    def remaining(self, tenant: str) -> int:
        return self.tokens_per_day - self._used[(tenant, self._day())]

    def check(self, tenant: str) -> None:
        if self.remaining(tenant) <= 0:
            raise BudgetExceededError(f"tenant {tenant} token budget exhausted")

    def charge(self, tenant: str, tokens: int) -> None:
        self._used[(tenant, self._day())] += tokens
        TOKENS.labels(tenant).set(self._used[(tenant, self._day())])
