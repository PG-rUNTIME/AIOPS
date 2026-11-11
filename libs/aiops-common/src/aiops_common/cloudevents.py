"""CloudEvents 1.0 structured-mode JSON envelope for every Kafka message."""

from __future__ import annotations

import builtins
import uuid
from datetime import datetime
from typing import Any, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from aiops_common.contracts.models import utcnow
from aiops_common.contracts.registry import BY_CE_TYPE, BY_MODEL

M = TypeVar("M", bound=BaseModel)


class CloudEvent(BaseModel):
    model_config = ConfigDict(extra="allow")

    specversion: Literal["1.0"] = "1.0"
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source: str
    type: str
    time: datetime = Field(default_factory=utcnow)
    datacontenttype: Literal["application/json"] = "application/json"
    dataschema: str
    tenantid: str
    partitionkey: str
    traceparent: str | None = None
    data: dict[str, Any]

    def payload(self, model: builtins.type[M]) -> M:
        """Parse ``data`` as ``model``; raises if the type does not match."""
        expected = BY_MODEL[model].ce_type
        if self.type != expected:
            raise TypeError(f"event type {self.type!r} is not {expected!r}")
        return model.model_validate(self.data)

    def to_bytes(self) -> bytes:
        return self.model_dump_json(exclude_none=True).encode()

    @classmethod
    def from_bytes(cls, raw: bytes) -> CloudEvent:
        return cls.model_validate_json(raw)


def partition_key(tenant_id: str, ci_id: str) -> str:
    """Partition key for every topic: keeps one CI's events ordered on one partition."""
    return f"{tenant_id}:{ci_id}"


def make_event(
    payload: BaseModel,
    *,
    source: str,
    event_id: str | None = None,
    traceparent: str | None = None,
) -> CloudEvent:
    et = BY_MODEL[type(payload)]
    tenant = str(getattr(payload, "tenant_id"))  # noqa: B009 - all payloads carry tenant_id
    ci = getattr(payload, "ci_id", None) or "_"
    return CloudEvent(
        id=event_id or str(uuid.uuid4()),
        source=source,
        type=et.ce_type,
        dataschema=et.dataschema,
        tenantid=tenant,
        partitionkey=partition_key(tenant, str(ci)),
        traceparent=traceparent,
        data=payload.model_dump(mode="json"),
    )


def topic_for(event: CloudEvent) -> str:
    return BY_CE_TYPE[event.type].topic
