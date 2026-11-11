"""Deterministic failure scenarios. Pure functions of (scenario, elapsed seconds).

Used two ways: by the e2e test with a simulated clock, and by the dev
``chaos-sim`` service in real time (exposes /metrics and pushes to the
ingest-gateway and Loki).
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from aiops_common.contracts.models import LogBatch, LogRecord, MetricBatch, MetricPoint

GiB = 1024**3


@dataclass(frozen=True)
class Host:
    tenant_id: str
    ci_id: str
    service: str
    disk_size: float = 100 * GiB
    mem_total: float = 32 * GiB
    pool_max: float = 100.0
    kind: str = "server"  # server | network


DEMO_TENANT = "demo-bank"
DEMO_HOSTS: tuple[Host, ...] = (
    Host(DEMO_TENANT, "CI-CORE-DB-01", "core-banking-db"),
    Host(DEMO_TENANT, "CI-PAY-API-01", "payments-api"),
    Host(DEMO_TENANT, "CI-PAY-API-02", "payments-api"),
    Host(DEMO_TENANT, "CI-MOBILE-GW-01", "mobile-gateway"),
    Host(DEMO_TENANT, "CI-NET-RTR-HRE-01", "wan-router", kind="network"),
)

SCENARIOS = (
    "disk_fill",
    "memory_leak",
    "cpu_saturation",
    "connection_pool_exhaustion",
    "error_log_spike",
    "interface_flap",
)

FAILURE_TYPE = {
    "disk_fill": "disk_full",
    "memory_leak": "memory_exhaustion",
    "cpu_saturation": "cpu_saturation",
    "connection_pool_exhaustion": "connection_pool_exhaustion",
    "error_log_spike": "error_spike",
    "interface_flap": "interface_flap",
}


@dataclass
class Scenario:
    name: str
    host: Host
    start: datetime
    fail_after_s: float = 20 * 60  # failure happens 20 min after start
    seed: int = 7
    _rng: random.Random = field(init=False)

    def __post_init__(self) -> None:
        if self.name not in SCENARIOS:
            raise ValueError(f"unknown scenario {self.name}")
        self._rng = random.Random(self.seed)

    @property
    def fail_at(self) -> datetime:
        return self.start + timedelta(seconds=self.fail_after_s)

    @property
    def failure_type(self) -> str:
        return FAILURE_TYPE[self.name]

    def progress(self, t: datetime) -> float:
        """0 at start → 1 at failure time."""
        return max(0.0, min(1.0, (t - self.start).total_seconds() / self.fail_after_s))


def _noise(rng: random.Random, scale: float) -> float:
    return rng.gauss(0, scale)


def baseline_metrics(h: Host, t: datetime, rng: random.Random) -> dict[str, float]:
    day = math.sin(2 * math.pi * (t.hour * 3600 + t.minute * 60) / 86400)
    return {
        "node_filesystem_size_bytes": h.disk_size,
        "node_filesystem_avail_bytes": h.disk_size * (0.55 + _noise(rng, 0.0005)),
        "node_memory_MemTotal_bytes": h.mem_total,
        "node_memory_MemAvailable_bytes": h.mem_total * (0.6 + 0.02 * day + _noise(rng, 0.003)),
        "node_cpu_utilisation": max(0.0, 0.25 + 0.05 * day + _noise(rng, 0.02)),
        "db_pool_connections_max": h.pool_max,
        "db_pool_connections_in_use": max(0.0, 30 + _noise(rng, 2)),
        "http_server_request_duration_p99_seconds": max(0.01, 0.18 + _noise(rng, 0.01)),
    }


def sample(
    h: Host, t: datetime, scenario: Scenario | None, rng: random.Random
) -> tuple[MetricBatch, LogBatch | None]:
    m = baseline_metrics(h, t, rng)
    logs: list[LogRecord] = []
    if h.kind == "network":
        m = {"node_cpu_utilisation": m["node_cpu_utilisation"]}
    if scenario is not None and scenario.host.ci_id == h.ci_id:
        p = scenario.progress(t)
        n = scenario.name
        if n == "disk_fill":
            m["node_filesystem_avail_bytes"] = h.disk_size * max(
                0.0, 0.55 * (1 - p) + _noise(rng, 0.001)
            )
            if p >= 0.97:
                logs.append(
                    LogRecord(
                        ts=t,
                        severity="ERROR",
                        body="write /var/lib/postgresql/data: no space left on device",
                    )
                )
        elif n == "memory_leak":
            m["node_memory_MemAvailable_bytes"] = h.mem_total * max(
                0.0, 0.6 * (1 - p) + _noise(rng, 0.002)
            )
            if p >= 0.98:
                logs.append(
                    LogRecord(
                        ts=t, severity="ERROR", body="java.lang.OutOfMemoryError: Java heap space"
                    )
                )
        elif n == "cpu_saturation":
            m["node_cpu_utilisation"] = min(1.0, 0.25 + 0.78 * p + _noise(rng, 0.01))
        elif n == "connection_pool_exhaustion":
            m["db_pool_connections_in_use"] = min(h.pool_max, 30 + 72 * p + _noise(rng, 1))
            if p > 0.8:
                for _ in range(1 + int(10 * p)):
                    logs.append(
                        LogRecord(
                            ts=t,
                            severity="ERROR",
                            body=f"HikariPool-1 - Connection is not available, timeout acquiring "
                            f"connection after {rng.randint(29000, 30500)}ms",
                        )
                    )
        elif n == "error_log_spike" and p > 0.5:
            for _ in range(40):
                logs.append(
                    LogRecord(
                        ts=t,
                        severity="ERROR",
                        body=f"PaymentProcessor failed to settle txn {rng.randint(10**8, 10**9)}: "
                        "upstream 502 from switch "
                        f"10.20.{rng.randint(0, 255)}.{rng.randint(1, 254)}",
                    )
                )
        elif n == "interface_flap" and p > 0.3:
            state = "down" if rng.random() < 0.5 else "up"
            logs.append(
                LogRecord(
                    ts=t,
                    severity="ERROR" if state == "down" else "WARNING",
                    body=f"%LINK-3-UPDOWN: Interface GigabitEthernet0/{rng.randint(1, 4)}, "
                    f"changed state to {state}",
                )
            )
    if rng.random() < 0.3:
        logs.append(
            LogRecord(ts=t, severity="INFO", body=f"healthcheck ok in {rng.randint(1, 30)}ms")
        )
    labels = {"ci_id": h.ci_id, "service": h.service, "mountpoint": "/"}
    points = [
        MetricPoint(
            name=k,
            labels=labels
            if k.startswith("node_filesystem")
            else {"ci_id": h.ci_id, "service": h.service},
            ts=t,
            value=v,
        )
        for k, v in m.items()
    ]
    mb = MetricBatch(tenant_id=h.tenant_id, ci_id=h.ci_id, service=h.service, points=points)
    lb = (
        LogBatch(tenant_id=h.tenant_id, ci_id=h.ci_id, service=h.service, records=logs)
        if logs
        else None
    )
    return mb, lb
