"""Retry/DLQ policy shared by every bus implementation."""

from __future__ import annotations

import logging
import time

from prometheus_client import Counter, Histogram

from aiops_common.bus.base import DeadLetter, PermanentError, Subscription
from aiops_common.cloudevents import CloudEvent
from aiops_common.logging import bind_context
from aiops_common.resilience import backoff_delay, sleep

log = logging.getLogger("aiops.bus")

MESSAGES = Counter("aiops_messages_total", "Messages handled", ["group", "topic", "outcome"])
DURATION = Histogram(
    "aiops_handler_duration_seconds",
    "Handler latency",
    ["group", "topic"],
    buckets=(0.005, 0.01, 0.05, 0.1, 0.5, 1, 2, 5, 10, 30, 90),
)


async def handle_with_retries(
    sub: Subscription, topic: str, event: CloudEvent, *, base_delay: float = 0.5
) -> DeadLetter | None:
    """Run the handler with exponential backoff. Returns a DeadLetter if it gave up."""
    attempt = 0
    last_err = ""
    with bind_context(tenant_id=event.tenantid, event_id=event.id):
        while True:
            attempt += 1
            t0 = time.perf_counter()
            try:
                await sub.handler(event)
            except PermanentError as e:
                last_err = f"permanent: {e}"
                break
            except Exception as e:
                last_err = f"{type(e).__name__}: {e}"
                log.warning("handler failed", extra={"attempt": attempt, "error": last_err})
                if attempt > sub.max_retries:
                    break
                await sleep(backoff_delay(attempt, base=base_delay))
                continue
            else:
                MESSAGES.labels(sub.group, topic, "ok").inc()
                return None
            finally:
                DURATION.labels(sub.group, topic).observe(time.perf_counter() - t0)
        MESSAGES.labels(sub.group, topic, "dlq").inc()
        log.error("message dead-lettered", extra={"error": last_err, "topic": topic})
        return DeadLetter(
            original_topic=topic,
            event=event,
            error=last_err[:2000],
            attempts=attempt,
            headers={"x-error": last_err[:500], "x-attempts": str(attempt), "x-group": sub.group},
        )
