"""Structured JSON logs to stdout with trace_id / tenant_id / incident_key context."""

from __future__ import annotations

import contextvars
import json
import logging
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

_ctx: contextvars.ContextVar[dict[str, str]] = contextvars.ContextVar("aiops_log_ctx", default={})  # noqa: B039

_RESERVED = set(vars(logging.LogRecord("", 0, "", 0, "", None, None))) | {"message", "asctime"}


@contextmanager
def bind_context(**kv: str | None) -> Iterator[None]:
    new = {**_ctx.get(), **{k: v for k, v in kv.items() if v is not None}}
    token = _ctx.set(new)
    try:
        yield
    finally:
        _ctx.reset(token)


def current_context() -> dict[str, str]:
    return dict(_ctx.get())


class JsonFormatter(logging.Formatter):
    def __init__(self, service: str) -> None:
        super().__init__()
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        doc: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "service": self.service,
            "logger": record.name,
            "msg": record.getMessage(),
            **_ctx.get(),
        }
        try:
            from opentelemetry import trace

            span = trace.get_current_span().get_span_context()
            if span.is_valid:
                doc["trace_id"] = f"{span.trace_id:032x}"
                doc["span_id"] = f"{span.span_id:016x}"
        except Exception:  # noqa: S110 - logging must never raise
            pass
        for k, v in vars(record).items():
            if k not in _RESERVED and not k.startswith("_"):
                doc[k] = v
        if record.exc_info:
            doc["exc"] = self.formatException(record.exc_info)
        return json.dumps(doc, default=str)


def setup_logging(service: str, level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter(service))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    for noisy in ("aiokafka", "httpx", "uvicorn.access"):
        logging.getLogger(noisy).setLevel("WARNING")
