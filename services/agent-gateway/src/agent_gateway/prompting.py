"""Versioned prompts. Bump PROMPT_VERSION whenever the template changes (CI runs evals)."""

from __future__ import annotations

import json
from importlib import resources

from agent_gateway.runbooks import PastIncident, Runbook
from aiops_common.contracts.models import CandidateIncident
from aiops_common.redaction import redact_str

PROMPT_VERSION = "investigate.v1.3.0"


def system_prompt() -> str:
    return resources.files("agent_gateway.prompts").joinpath("investigate.v1.md").read_text()


def candidate_brief(c: CandidateIncident) -> dict[str, object]:
    """Compact, redacted view of the candidate: what the LLM actually sees."""
    return {
        "incident_key": c.incident_key,
        "tenant_id": c.tenant_id,
        "ci_id": c.ci_id,
        "service": c.service,
        "predicted_failure": c.predicted_failure,
        "eta_minutes": c.eta_minutes,
        "detector_confidence": c.confidence,
        "window": [c.first_seen.isoformat(), c.last_seen.isoformat()],
        "signals": [
            {
                "detector": s.detector.value,
                "failure_type": s.failure_type,
                "metric": s.metric,
                "template": s.template,
                "value": s.value,
                "threshold": s.threshold,
                "eta_minutes": s.eta_minutes,
                "score": s.score,
                "forecast": s.forecast.model_dump() if s.forecast else None,
                "query": s.query,
                "ts": s.ts.isoformat(),
                "sample": s.labels.get("sample"),
                "source": s.labels.get("source"),
            }
            for s in c.signals[:12]
        ],
        "recent_changes": [ch.model_dump(mode="json") for ch in c.recent_changes],
    }


def user_prompt(c: CandidateIncident, runbooks: list[Runbook], similar: list[PastIncident]) -> str:
    parts = [
        "CANDIDATE INCIDENT:",
        json.dumps(candidate_brief(c), indent=1, default=str),
        "",
        "RELEVANT RUNBOOKS (use get_runbook for full text):",
        *[
            f"- {r.id}: {r.title} (failure types: {', '.join(r.failure_types)})\n  {r.body[:600]}"
            for r in runbooks
        ],
        "",
        "SIMILAR RESOLVED INCIDENTS:",
        *[
            f"- {i.ref} [{i.failure_type}] {i.summary} | root cause: {i.root_cause} | fix: {i.fix}"
            for i in similar
        ],
    ]
    return redact_str("\n".join(parts))
