"""Strict-JSON parsing and the evidence check.

Policy: the LLM's verdict is only forwarded as ``verified``/``noise`` when it
parses against ``LLMVerdict`` *and* every evidence item is grounded in a tool
call that actually ran (or in the candidate's own signals). Anything else is
downgraded to ``needs_human`` and the LLM's claims are not forwarded.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from aiops_common.contracts.models import CandidateIncident, EvidenceItem, LLMVerdict, VerdictStatus


@dataclass(frozen=True)
class ToolCall:
    name: str
    query: str | None
    result: str
    args: dict[str, Any] = field(default_factory=dict)
    thought: str = ""  # the model's visible note before this call, if any


@dataclass
class ValidationOutcome:
    verdict: LLMVerdict | None
    status: VerdictStatus
    reasons: list[str]


_FENCE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.S)
_TOKEN = re.compile(r"[A-Za-z_]{3,}|\d+(?:\.\d+)?")


def extract_json(text: str) -> dict[str, Any]:
    """Accept bare JSON, fenced JSON, or the last top-level JSON object in prose."""
    text = text.strip()
    candidates = [text]
    candidates += _FENCE.findall(text)
    start = text.rfind("{\n") if "{\n" in text else text.find("{")
    if start >= 0:
        candidates.append(text[start : text.rfind("}") + 1])
    for c in candidates:
        try:
            doc = json.loads(c)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(doc, dict):
            return doc
    raise ValueError("no JSON object found in model output")


def _norm(s: str) -> str:
    return re.sub(r"\s+", "", s).lower()


def _grounded(excerpt: str, corpus: str) -> bool:
    toks = {t.lower() for t in _TOKEN.findall(excerpt)}
    if not toks:
        return False
    corpus_l = corpus.lower()
    hit = sum(1 for t in toks if t in corpus_l)
    return hit / len(toks) >= 0.5


def check_evidence(
    item: EvidenceItem, calls: list[ToolCall], candidate_text: str, candidate_queries: set[str]
) -> str | None:
    """Return None if grounded, otherwise a reason string."""
    ref = item.query or item.log_ref or ""
    nref = _norm(ref)
    matched = [c for c in calls if c.query and (_norm(c.query) == nref or nref in _norm(c.query))]
    if item.log_ref and not matched:
        matched = [c for c in calls if item.log_ref in c.result]
    if matched:
        if any(_grounded(item.excerpt, c.result) for c in matched):
            return None
        return f"excerpt not found in result of {ref[:80]!r}"
    if nref in candidate_queries or (item.log_ref and item.log_ref in candidate_text):
        return (
            None
            if _grounded(item.excerpt, candidate_text)
            else f"excerpt not found in candidate for {ref[:80]!r}"
        )
    return f"evidence {ref[:80]!r} was never executed"


def validate(
    raw_output: str,
    calls: list[ToolCall],
    candidate: CandidateIncident,
    known_runbooks: set[str],
) -> ValidationOutcome:
    reasons: list[str] = []
    try:
        verdict = LLMVerdict.model_validate(extract_json(raw_output))
    except (ValueError, ValidationError) as e:
        msg = str(e).splitlines()[0][:300]
        return ValidationOutcome(None, VerdictStatus.NEEDS_HUMAN, [f"invalid output: {msg}"])

    if verdict.runbook_ref and verdict.runbook_ref not in known_runbooks:
        reasons.append(f"unknown runbook_ref {verdict.runbook_ref!r} removed")
        verdict.runbook_ref = None

    cand_text = candidate.model_dump_json()
    cand_queries = {_norm(s.query) for s in candidate.signals if s.query}
    if not verdict.evidence:
        reasons.append("no evidence cited")
        return ValidationOutcome(verdict, VerdictStatus.NEEDS_HUMAN, reasons)
    bad = [r for e in verdict.evidence if (r := check_evidence(e, calls, cand_text, cand_queries))]
    if bad:
        return ValidationOutcome(verdict, VerdictStatus.NEEDS_HUMAN, reasons + bad)
    if verdict.is_incident and not verdict.recommended_actions:
        reasons.append("no recommended actions")
    status = VerdictStatus.VERIFIED if verdict.is_incident else VerdictStatus.NOISE
    return ValidationOutcome(verdict, status, reasons)
