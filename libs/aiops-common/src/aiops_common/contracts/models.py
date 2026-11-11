"""v1 data contracts. Every Kafka payload is one of these models.

JSON Schemas in ``contracts/jsonschema`` are generated from these models
(``make contracts``) and CI fails if the committed schemas drift.
Evolution rule: v1 may only gain *optional* fields. Anything else is v2.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

TenantId = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9_-]*$")]
CiId = Annotated[str, Field(min_length=1, max_length=128)]


def utcnow() -> datetime:
    return datetime.now(UTC)


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=False, populate_by_name=True)


# --------------------------------------------------------------------------- telemetry
class MetricPoint(_Base):
    name: str = Field(description="Metric name, e.g. node_filesystem_avail_bytes")
    labels: dict[str, str] = Field(default_factory=dict)
    ts: datetime
    value: float


class MetricBatch(_Base):
    """telemetry.metrics payload: points for ONE tenant + CI (one partition key)."""

    tenant_id: TenantId
    ci_id: CiId
    service: str = "unknown"
    points: list[MetricPoint] = Field(min_length=1)


class LogRecord(_Base):
    ts: datetime
    severity: str = "INFO"
    body: str = Field(max_length=16_384)
    attributes: dict[str, str] = Field(default_factory=dict)


class LogBatch(_Base):
    """telemetry.logs payload. Bodies are PII-redacted before they are published."""

    tenant_id: TenantId
    ci_id: CiId
    service: str = "unknown"
    records: list[LogRecord] = Field(min_length=1)


class ChangeKind(StrEnum):
    DEPLOY = "deploy"
    CONFIG = "config"
    INFRA = "infra"
    CHANGE_REQUEST = "change_request"


class ChangeEvent(_Base):
    """changes.events payload: deploys, config pushes, CRs."""

    tenant_id: TenantId
    ci_id: CiId
    change_id: str
    kind: ChangeKind
    summary: str = Field(max_length=1000)
    ts: datetime
    url: str | None = None


# --------------------------------------------------------------------------- detection
class DetectorKind(StrEnum):
    TREND = "trend"
    FORECAST = "forecast"
    ANOMALY = "anomaly"
    LOG_TEMPLATE = "log_template"


class ForecastQuantiles(_Base):
    p10: float
    p50: float
    p90: float


class Signal(_Base):
    """signals.detected payload: one detector firing on one series/template."""

    signal_id: str
    tenant_id: TenantId
    ci_id: CiId
    service: str = "unknown"
    detector: DetectorKind
    failure_type: str = Field(description="Failure family, e.g. disk_full, memory_exhaustion")
    metric: str | None = None
    template: str | None = None
    value: float
    threshold: float | None = None
    forecast: ForecastQuantiles | None = None
    eta_minutes: float | None = Field(default=None, ge=0)
    score: float = Field(ge=0.0, le=1.0, description="Detector confidence 0..1")
    ts: datetime
    query: str | None = Field(default=None, description="PromQL/LogQL that reproduces the signal")
    labels: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _metric_or_template(self) -> Signal:
        if self.metric is None and self.template is None:
            raise ValueError("signal needs metric or template")
        return self


# --------------------------------------------------------------------------- incidents
class CandidateIncident(_Base):
    """incidents.candidate payload: correlated signals for one CI."""

    incident_key: str = Field(min_length=16, max_length=128)
    tenant_id: TenantId
    ci_id: CiId
    service: str
    signals: list[Signal] = Field(min_length=1)
    predicted_failure: str
    eta_minutes: float | None = Field(default=None, ge=0)
    confidence: float = Field(ge=0.0, le=1.0)
    recent_changes: list[ChangeEvent] = Field(default_factory=list)
    grafana_links: list[str] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    is_update: bool = Field(default=False, description="True when re-emitted for a known episode")
    resolved: bool = Field(default=False, description="True when the risk has passed (send Clear)")

    @model_validator(mode="after")
    def _order(self) -> CandidateIncident:
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen must be >= first_seen")
        return self


class EvidenceItem(_Base):
    query: str | None = Field(default=None, description="PromQL/LogQL actually executed")
    log_ref: str | None = Field(default=None, description="Pointer to a log line")
    excerpt: str = Field(min_length=1, max_length=2000)

    @model_validator(mode="after")
    def _needs_ref(self) -> EvidenceItem:
        if not (self.query or self.log_ref):
            raise ValueError("evidence needs query or log_ref")
        return self


class LLMVerdict(_Base):
    """The STRICT JSON the LLM must return. Nothing else is accepted."""

    is_incident: bool
    confidence: float = Field(ge=0.0, le=1.0)
    predicted_failure: str = Field(max_length=200)
    eta_minutes: float | None = Field(default=None, ge=0)
    root_cause: str = Field(max_length=2000)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list, max_length=10)
    runbook_ref: str | None = None


class VerdictStatus(StrEnum):
    VERIFIED = "verified"  # LLM output valid and evidence-backed
    NEEDS_HUMAN = "needs_human"  # LLM output invalid / claims unsupported
    UNVERIFIED = "unverified"  # LLM unavailable: degraded mode
    NOISE = "noise"  # LLM says not an incident, with evidence
    RESOLVED = "resolved"  # risk passed; router sends Clear events


class ToolTrace(_Base):
    """One step of the investigation: a read-only tool the agent ran and what came back."""

    tool: str = Field(max_length=64)
    source: str | None = Field(default=None, max_length=100, description="Registered source used")
    query: str | None = Field(default=None, max_length=2000)
    thought: str | None = Field(default=None, max_length=400, description="Visible rationale")
    result_preview: str = Field(default="", max_length=600)
    ok: bool = True


class Verdict(LLMVerdict):
    """incidents.verdict payload: LLMVerdict + provenance + the candidate."""

    incident_key: str
    tenant_id: TenantId
    ci_id: CiId
    status: VerdictStatus
    model_id: str
    prompt_version: str
    downgrade_reasons: list[str] = Field(default_factory=list)
    latency_ms: int = 0
    tokens_used: int = 0
    tool_trace: list[ToolTrace] = Field(default_factory=list, max_length=40)
    candidate: CandidateIncident


# --------------------------------------------------------------------------- action
class Channel(StrEnum):
    SERVICENOW = "servicenow"
    KEEP = "keep"
    EMAIL = "email"
    CHAT = "chat"
    LOG_ONLY = "log_only"


class NotificationAction(StrEnum):
    OPEN = "open"
    CLEAR = "clear"


class Notification(_Base):
    """notifications.outbox payload: one delivery recorded by the router."""

    notification_id: str
    incident_key: str
    tenant_id: TenantId
    ci_id: CiId
    channel: Channel
    action: NotificationAction
    priority: Literal[1, 2, 3, 4, 5] = 3
    status: Literal["pending", "sent", "failed"] = "pending"
    external_ref: str | None = None
    ts: datetime = Field(default_factory=utcnow)


class Outcome(StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    MISSED = "missed"  # incident with no prior warning (recall)


class FeedbackOutcome(_Base):
    """feedback.outcomes payload."""

    incident_key: str
    tenant_id: TenantId
    ci_id: CiId | None = None
    failure_type: str
    outcome: Outcome
    actual_root_cause: str | None = None
    lead_time_minutes: float | None = None
    source: Literal["servicenow", "chat", "api"] = "api"
    rating: int | None = Field(default=None, ge=1, le=5)
    ts: datetime = Field(default_factory=utcnow)
