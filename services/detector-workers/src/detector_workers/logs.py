"""Drain3 log-template mining → per-template rate series → new/spiking error signals.

Drain3 state is persisted through ``StatePersistence`` (S3/MinIO in deployed
images, in-memory in tests) so a restarted worker keeps its template IDs.
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime

from drain3 import TemplateMiner
from drain3.masking import MaskingInstruction
from drain3.persistence_handler import PersistenceHandler
from drain3.template_miner_config import TemplateMinerConfig

from detector_workers.rules import RuleSet

log = logging.getLogger(__name__)

ERROR_WORDS = re.compile(
    r"(?i)\b(error|err|fatal|critical|crit|fail(ed|ure)?|exception|panic|down)\b"
)

MASKS = [
    MaskingInstruction(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b", "IP"),
    MaskingInstruction(r"\b0x[0-9a-fA-F]+\b", "HEX"),
    MaskingInstruction(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "UUID"),
    MaskingInstruction(r"\[REDACTED:[A-Z_]+\]", "PII"),
    MaskingInstruction(r"(?<![A-Za-z])[-+]?\d+(?:\.\d+)?(?:ms|s|%|[KMG]i?B)?(?![A-Za-z])", "NUM"),
]


class MemoryPersistence(PersistenceHandler):  # type: ignore[misc]
    def __init__(self) -> None:
        self.state: bytes | None = None

    def save_state(self, state: bytes) -> None:
        self.state = state

    def load_state(self) -> bytes | None:
        return self.state


class S3Persistence(PersistenceHandler):  # type: ignore[misc]  # pragma: no cover - needs MinIO
    """Drain3 snapshot in an S3 bucket, one object per tenant."""

    def __init__(self, client: object, bucket: str, key: str) -> None:
        self.client, self.bucket, self.key = client, bucket, key

    def save_state(self, state: bytes) -> None:
        self.client.put_object(Bucket=self.bucket, Key=self.key, Body=state)  # type: ignore[attr-defined]

    def load_state(self) -> bytes | None:
        try:
            obj = self.client.get_object(Bucket=self.bucket, Key=self.key)  # type: ignore[attr-defined]
            data: bytes = obj["Body"].read()
            return data
        except Exception:
            return None


def make_miner(persistence: PersistenceHandler | None = None) -> TemplateMiner:
    cfg = TemplateMinerConfig()
    cfg.masking_instructions = MASKS
    cfg.drain_sim_th = 0.4
    cfg.drain_depth = 4
    cfg.drain_max_clusters = 5000
    cfg.snapshot_interval_minutes = 5
    cfg.snapshot_compress_state = True
    return TemplateMiner(persistence_handler=persistence, config=cfg)


@dataclass(frozen=True)
class LogDetection:
    failure_type: str
    template: str
    template_id: int
    count: int
    baseline: float
    reason: str
    sample: str
    score: float


@dataclass
class _Rate:
    minute: int = -1
    count: int = 0
    ewma: float = 0.0
    minutes_seen: int = 0
    emitted_minute: int = -1


@dataclass
class LogTemplateDetector:
    rules: RuleSet
    miners: dict[str, TemplateMiner] = field(default_factory=dict)
    persistence_factory: type[PersistenceHandler] | None = MemoryPersistence
    _rates: dict[tuple[str, str, int], _Rate] = field(default_factory=lambda: defaultdict(_Rate))
    _compiled: list[tuple[str, re.Pattern[str]]] = field(default_factory=list)
    _created: dict[tuple[str, int], int] = field(default_factory=dict)  # template → minute created
    _new_alerted: set[tuple[str, str, int]] = field(default_factory=set)
    new_template_minutes: int = 15

    def __post_init__(self) -> None:
        self._compiled = [(r.failure_type, re.compile(r.pattern, re.I)) for r in self.rules.logs]

    def _miner(self, tenant: str) -> TemplateMiner:
        if tenant not in self.miners:
            p = self.persistence_factory() if self.persistence_factory else None
            self.miners[tenant] = make_miner(p)
        return self.miners[tenant]

    def classify(self, line: str) -> str | None:
        for ft, rx in self._compiled:
            if rx.search(line):
                return ft
        return None

    def observe(
        self, tenant: str, ci: str, ts: datetime, severity: str, line: str
    ) -> LogDetection | None:
        res = self._miner(tenant).add_log_message(line)
        tid = int(res["cluster_id"])
        template = str(res["template_mined"])
        minute = int(ts.timestamp() // 60)
        if res["change_type"] == "cluster_created":
            self._created[(tenant, tid)] = minute
        r = self._rates[(tenant, ci, tid)]
        if r.minute != minute:
            if r.minute >= 0:
                r.ewma = 0.3 * r.count + 0.7 * r.ewma if r.minutes_seen else float(r.count)
                r.minutes_seen += 1
            r.minute, r.count = minute, 0
        r.count += 1
        is_error = severity.upper() in {"ERROR", "FATAL", "CRITICAL"} or bool(
            ERROR_WORDS.search(line)
        )
        if not is_error or r.emitted_minute == minute:
            return None
        failure_type = self.classify(line)
        reason: str | None = None
        created = self._created.get((tenant, tid))
        is_new = created is not None and minute - created <= self.new_template_minutes
        if (
            is_new
            and self.rules.log_new_error_template
            and failure_type is not None
            and (tenant, ci, tid) not in self._new_alerted
        ):
            self._new_alerted.add((tenant, ci, tid))
            reason = "new error template"
        elif (
            r.count >= self.rules.log_spike_min_count
            and r.count >= self.rules.log_spike_factor * max(r.ewma, 1.0)
        ):
            reason = "error template spike"
        if reason is None:
            return None
        r.emitted_minute = minute
        score = 0.7 if failure_type else 0.5
        return LogDetection(
            failure_type=failure_type or "error_spike",
            template=template,
            template_id=tid,
            count=r.count,
            baseline=round(r.ewma, 2),
            reason=reason,
            sample=line[:500],
            score=score,
        )
