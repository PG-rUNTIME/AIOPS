"""Topic and event-type registry: the single source of truth for what flows where."""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import BaseModel

from aiops_common.contracts.models import (
    CandidateIncident,
    ChangeEvent,
    FeedbackOutcome,
    LogBatch,
    MetricBatch,
    Notification,
    Signal,
    Verdict,
)


class Topics:
    METRICS = "telemetry.metrics"
    LOGS = "telemetry.logs"
    CHANGES = "changes.events"
    SIGNALS = "signals.detected"
    CANDIDATES = "incidents.candidate"
    VERDICTS = "incidents.verdict"
    OUTBOX = "notifications.outbox"
    FEEDBACK = "feedback.outcomes"

    @staticmethod
    def dlq(topic: str) -> str:
        return f"{topic}.dlq"


@dataclass(frozen=True)
class EventType:
    name: str  # schema folder name
    ce_type: str  # CloudEvents `type`
    topic: str
    model: type[BaseModel]
    version: int = 1

    @property
    def dataschema(self) -> str:
        return f"https://schemas.aiops.local/{self.name}/v{self.version}.json"


EVENT_TYPES: tuple[EventType, ...] = (
    EventType("metric-batch", "io.aiops.telemetry.metrics.v1", Topics.METRICS, MetricBatch),
    EventType("log-batch", "io.aiops.telemetry.logs.v1", Topics.LOGS, LogBatch),
    EventType("change-event", "io.aiops.changes.event.v1", Topics.CHANGES, ChangeEvent),
    EventType("signal", "io.aiops.signal.detected.v1", Topics.SIGNALS, Signal),
    EventType(
        "candidate-incident", "io.aiops.incident.candidate.v1", Topics.CANDIDATES, CandidateIncident
    ),
    EventType("verdict", "io.aiops.incident.verdict.v1", Topics.VERDICTS, Verdict),
    EventType("notification", "io.aiops.notification.v1", Topics.OUTBOX, Notification),
    EventType("feedback-outcome", "io.aiops.feedback.outcome.v1", Topics.FEEDBACK, FeedbackOutcome),
)

BY_CE_TYPE: dict[str, EventType] = {e.ce_type: e for e in EVENT_TYPES}
BY_MODEL: dict[type[BaseModel], EventType] = {e.model: e for e in EVENT_TYPES}
ALL_TOPICS: tuple[str, ...] = tuple(sorted({e.topic for e in EVENT_TYPES}))
