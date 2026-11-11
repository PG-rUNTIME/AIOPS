"""Turn a verdict into ticket/message content that is useful on arrival."""

from __future__ import annotations

from typing import Any

from aiops_common.contracts.models import Verdict, VerdictStatus

SN_DESCRIPTION_LIMIT = 4000  # ServiceNow event description limit

BANNER = {
    VerdictStatus.VERIFIED: "AI-verified",
    VerdictStatus.UNVERIFIED: "UNVERIFIED — AI agent unavailable, detector evidence only",
    VerdictStatus.NEEDS_HUMAN: "NEEDS HUMAN REVIEW — AI analysis rejected by evidence check",
    VerdictStatus.NOISE: "Noise",
    VerdictStatus.RESOLVED: "Risk cleared",
}


def title(v: Verdict) -> str:
    eta = f" in ~{v.eta_minutes:.0f} min" if v.eta_minutes is not None else ""
    return f"[AIOps] {v.predicted_failure} predicted on {v.ci_id}{eta}"[:160]


def description(v: Verdict) -> str:
    c = v.candidate
    lines = [
        f"{BANNER[v.status]} | confidence {v.confidence:.2f} | incident_key {v.incident_key}",
        "",
        f"Root cause: {v.root_cause}",
    ]
    if v.evidence:
        lines += ["", "Evidence:"] + [
            f"- {e.query or e.log_ref}: {e.excerpt[:300]}" for e in v.evidence[:6]
        ]
    else:
        lines += ["", "Detector signals:"] + [
            f"- {s.detector.value} {s.metric or s.template}: value={s.value:g}"
            + (f" eta={s.eta_minutes:g}m" if s.eta_minutes is not None else "")
            + (f" [{s.query}]" if s.query else "")
            for s in c.signals[:6]
        ]
    if v.recommended_actions:
        lines += ["", "Recommended actions:"] + [
            f"{i}. {a}" for i, a in enumerate(v.recommended_actions, 1)
        ]
    if v.runbook_ref:
        lines += ["", f"Runbook: {v.runbook_ref}"]
    if c.recent_changes:
        lines += ["", "Recent changes:"] + [
            f"- {ch.ts:%Y-%m-%d %H:%M} {ch.kind.value} {ch.change_id}: {ch.summary[:120]}"
            for ch in c.recent_changes[:5]
        ]
    if v.downgrade_reasons:
        lines += ["", "Validation notes: " + "; ".join(v.downgrade_reasons)[:400]]
    lines += ["", *c.grafana_links[:2]]
    text = "\n".join(lines)
    return (
        text
        if len(text) <= SN_DESCRIPTION_LIMIT
        else text[: SN_DESCRIPTION_LIMIT - 15] + "\n…[truncated]"
    )


def payload(v: Verdict) -> dict[str, Any]:
    """Everything an adapter needs, stored in the outbox row (adapters stay pure)."""
    return {
        "title": title(v),
        "description": description(v),
        "status": v.status.value,
        "service": v.candidate.service,
        "failure_type": v.predicted_failure.split(" ")[0],
        "confidence": v.confidence,
        "eta_minutes": v.eta_minutes,
        "root_cause": v.root_cause,
        "recommended_actions": v.recommended_actions,
        "runbook_ref": v.runbook_ref,
        "grafana_links": v.candidate.grafana_links,
        "model_id": v.model_id,
        "prompt_version": v.prompt_version,
    }
