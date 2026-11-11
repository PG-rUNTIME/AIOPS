"""Deterministic identifiers. Same inputs → same key, on any replica, after any replay."""

from __future__ import annotations

import hashlib
from datetime import datetime

EPISODE_BUCKET_SECONDS = 30 * 60


def incident_key(tenant_id: str, ci_id: str, failure_type: str, episode_start: datetime) -> str:
    """Key for one incident episode. ``episode_start`` is floored to a 30-minute bucket."""
    bucket = int(episode_start.timestamp()) // EPISODE_BUCKET_SECONDS
    raw = f"{tenant_id}|{ci_id}|{failure_type}|{bucket}"
    return f"inc-{hashlib.sha256(raw.encode()).hexdigest()[:24]}"


def stable_id(*parts: str, prefix: str = "") -> str:
    h = hashlib.sha256("|".join(parts).encode()).hexdigest()[:24]
    return f"{prefix}{h}"
