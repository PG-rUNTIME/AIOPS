"""Detection rules: which series to watch, how to derive them, and when they fail.

Rules are data (YAML, ``AIOPS_RULES_FILE``); the defaults below cover the
failure families the platform ships with. Thresholds are tuned per tenant by
the feedback loop (see feedback_service.tuning).
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field


class SeriesRule(BaseModel):
    failure_type: str
    # Derivation: value = metric | metric/denominator | 1 - metric/denominator
    metric: str
    denominator: str | None = None
    transform: Literal["identity", "ratio", "one_minus_ratio"] = "identity"
    direction: Literal["rising", "falling"] = "rising"
    threshold: float
    horizon_minutes: float = 15.0
    forecast_quantile: Literal["p10", "p50", "p90"] = "p90"
    min_points: int = 12
    anomaly: bool = True
    unit: str = ""

    @property
    def series_name(self) -> str:
        if self.transform == "identity":
            return self.metric
        prefix = "1 - " if self.transform == "one_minus_ratio" else ""
        return f"{prefix}{self.metric} / {self.denominator}"


class LogRule(BaseModel):
    failure_type: str
    pattern: str = Field(description="Case-insensitive regex on the raw log line")


class RuleSet(BaseModel):
    series: list[SeriesRule]
    logs: list[LogRule]
    log_spike_factor: float = 5.0
    log_spike_min_count: int = 20
    log_new_error_template: bool = True


DEFAULT_RULES = RuleSet(
    series=[
        SeriesRule(
            failure_type="disk_full",
            metric="node_filesystem_avail_bytes",
            denominator="node_filesystem_size_bytes",
            transform="one_minus_ratio",
            threshold=0.98,
            unit="ratio",
        ),
        SeriesRule(
            failure_type="memory_exhaustion",
            metric="node_memory_MemAvailable_bytes",
            denominator="node_memory_MemTotal_bytes",
            transform="one_minus_ratio",
            threshold=0.97,
            unit="ratio",
        ),
        SeriesRule(
            failure_type="cpu_saturation",
            metric="node_cpu_utilisation",
            threshold=0.98,
            horizon_minutes=10,
            unit="ratio",
        ),
        SeriesRule(
            failure_type="connection_pool_exhaustion",
            metric="db_pool_connections_in_use",
            denominator="db_pool_connections_max",
            transform="ratio",
            threshold=1.0,
            unit="ratio",
        ),
        SeriesRule(
            failure_type="latency_degradation",
            metric="http_server_request_duration_p99_seconds",
            threshold=2.0,
            unit="s",
        ),
    ],
    logs=[
        LogRule(failure_type="disk_full", pattern=r"no space left on device|disk (is )?full"),
        LogRule(
            failure_type="memory_exhaustion",
            pattern=r"out ?of ?memory|oom[- ]?kill|cannot allocate",
        ),
        LogRule(
            failure_type="connection_pool_exhaustion",
            pattern=(
                r"(connection )?pool (is )?exhausted|too many connections"
                r"|timeout acquiring connection"
            ),
        ),
        LogRule(
            failure_type="interface_flap",
            pattern=(
                r"%LINK-3-UPDOWN|%LINEPROTO-5-UPDOWN"
                r"|link (state )?(changed to )?down|interface .* flap"
            ),
        ),
        LogRule(failure_type="tls_certificate_expiry", pattern=r"certificate (has )?expired|x509"),
    ],
)


def load_rules(path: str | None) -> RuleSet:
    if not path:
        return DEFAULT_RULES
    return RuleSet.model_validate(yaml.safe_load(Path(path).read_text()))
