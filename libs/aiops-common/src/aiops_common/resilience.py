"""Retries with exponential backoff + full jitter, and a circuit breaker for external calls."""

from __future__ import annotations

import asyncio
import random
import time
from collections.abc import Awaitable, Callable
from enum import StrEnum
from typing import TypeVar

from prometheus_client import Gauge

T = TypeVar("T")

BREAKER_STATE = Gauge("aiops_circuit_open", "1 when the circuit is open", ["name"])


def backoff_delay(attempt: int, *, base: float = 0.5, cap: float = 30.0) -> float:
    """Full-jitter exponential backoff (AWS architecture blog)."""
    if base <= 0:
        return 0.0
    return random.uniform(0, min(cap, base * (2 ** (attempt - 1))))


async def sleep(seconds: float) -> None:
    if seconds > 0:
        await asyncio.sleep(seconds)


async def retry_async(
    fn: Callable[[], Awaitable[T]],
    *,
    attempts: int = 4,
    base: float = 0.5,
    cap: float = 10.0,
    retry_on: tuple[type[BaseException], ...] = (Exception,),
) -> T:
    for i in range(1, attempts + 1):
        try:
            return await fn()
        except retry_on:
            if i == attempts:
                raise
            await sleep(backoff_delay(i, base=base, cap=cap))
    raise AssertionError("unreachable")


class CircuitOpenError(RuntimeError):
    pass


class BreakerState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """Opens after ``failure_threshold`` consecutive failures; probes after ``reset_after`` s."""

    def __init__(
        self,
        name: str,
        *,
        failure_threshold: int = 5,
        reset_after: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.name = name
        self.failure_threshold = failure_threshold
        self.reset_after = reset_after
        self._clock = clock
        self._failures = 0
        self._opened_at: float | None = None

    @property
    def state(self) -> BreakerState:
        if self._opened_at is None:
            return BreakerState.CLOSED
        if self._clock() - self._opened_at >= self.reset_after:
            return BreakerState.HALF_OPEN
        return BreakerState.OPEN

    async def call(self, fn: Callable[[], Awaitable[T]]) -> T:
        if self.state is BreakerState.OPEN:
            raise CircuitOpenError(f"circuit {self.name} open")
        try:
            result = await fn()
        except Exception:
            self._failures += 1
            if self._failures >= self.failure_threshold or self.state is BreakerState.HALF_OPEN:
                self._opened_at = self._clock()
                BREAKER_STATE.labels(self.name).set(1)
            raise
        self._failures = 0
        self._opened_at = None
        BREAKER_STATE.labels(self.name).set(0)
        return result
