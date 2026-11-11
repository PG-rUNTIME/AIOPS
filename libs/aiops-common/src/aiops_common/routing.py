"""Routing rules: verdict → channels + priority. First match wins.

Defaults implement the routing table in the architecture document (§4.5);
tenants override them with YAML from the control plane.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from aiops_common.contracts.models import Channel, Verdict, VerdictStatus


class Match(BaseModel):
    status_in: list[VerdictStatus] | None = None
    is_incident: bool | None = None
    min_confidence: float | None = None
    max_confidence: float | None = None
    eta_lt: float | None = None  # eta_minutes < x (requires an ETA)
    eta_gte: float | None = None  # eta_minutes >= x (requires an ETA)
    has_eta: bool | None = None

    def matches(self, v: Verdict) -> bool:
        eta = v.eta_minutes
        checks = [
            self.status_in is None or v.status in self.status_in,
            self.is_incident is None or v.is_incident == self.is_incident,
            self.min_confidence is None or v.confidence >= self.min_confidence,
            self.max_confidence is None or v.confidence < self.max_confidence,
            self.eta_lt is None or (eta is not None and eta < self.eta_lt),
            self.eta_gte is None or (eta is not None and eta >= self.eta_gte),
            self.has_eta is None or ((eta is not None) == self.has_eta),
        ]
        return all(checks)


class RouteAction(BaseModel):
    channel: Channel
    priority: int = Field(3, ge=1, le=5)
    priority_p1_if_eta_lte: float | None = None  # escalate to P1 when the ETA is this close


class RoutingRule(BaseModel):
    name: str
    match: Match
    actions: list[RouteAction]


class RouteDecision(BaseModel):
    rule: str
    actions: list[RouteAction]


S = VerdictStatus
DEFAULT_RULES: list[RoutingRule] = [
    RoutingRule(
        name="noise",
        match=Match(status_in=[S.NOISE]),
        actions=[RouteAction(channel=Channel.LOG_ONLY, priority=5)],
    ),
    RoutingRule(
        name="imminent-verified",
        match=Match(status_in=[S.VERIFIED], is_incident=True, min_confidence=0.7, eta_lt=15),
        actions=[
            RouteAction(channel=Channel.SERVICENOW, priority=2, priority_p1_if_eta_lte=5),
            RouteAction(channel=Channel.CHAT, priority=2),
        ],
    ),
    RoutingRule(
        name="later-verified",
        match=Match(status_in=[S.VERIFIED], is_incident=True, min_confidence=0.5, eta_gte=15),
        actions=[
            RouteAction(channel=Channel.SERVICENOW, priority=3),
            RouteAction(channel=Channel.EMAIL, priority=3),
        ],
    ),
    RoutingRule(
        name="verified-detected-now",
        match=Match(status_in=[S.VERIFIED], is_incident=True, min_confidence=0.7, has_eta=False),
        actions=[
            RouteAction(channel=Channel.SERVICENOW, priority=2),
            RouteAction(channel=Channel.CHAT, priority=2),
        ],
    ),
    RoutingRule(  # degraded mode: LLM down → still ticket, marked unverified
        name="unverified-imminent",
        match=Match(status_in=[S.UNVERIFIED], eta_lt=15),
        actions=[
            RouteAction(channel=Channel.SERVICENOW, priority=2),
            RouteAction(channel=Channel.CHAT, priority=2),
        ],
    ),
    RoutingRule(
        name="unverified",
        match=Match(status_in=[S.UNVERIFIED], min_confidence=0.6),
        actions=[
            RouteAction(channel=Channel.SERVICENOW, priority=3),
            RouteAction(channel=Channel.CHAT, priority=3),
        ],
    ),
    RoutingRule(  # invalid / evidence-free LLM output: humans decide; ticket only if imminent
        name="needs-human-imminent",
        match=Match(status_in=[S.NEEDS_HUMAN], eta_lt=15, min_confidence=0.7),
        actions=[
            RouteAction(channel=Channel.SERVICENOW, priority=3),
            RouteAction(channel=Channel.CHAT, priority=3),
        ],
    ),
    RoutingRule(
        name="unclear",
        match=Match(),  # anomaly, cause unclear → chat only
        actions=[RouteAction(channel=Channel.CHAT, priority=4)],
    ),
]


def decide(v: Verdict, rules: list[RoutingRule] = DEFAULT_RULES) -> RouteDecision:
    for r in rules:
        if r.match.matches(v):
            acts = []
            for a in r.actions:
                p = a.priority
                if (
                    a.priority_p1_if_eta_lte is not None
                    and v.eta_minutes is not None
                    and v.eta_minutes <= a.priority_p1_if_eta_lte
                ):
                    p = 1
                acts.append(RouteAction(channel=a.channel, priority=p))
            return RouteDecision(rule=r.name, actions=acts)
    return RouteDecision(rule="none", actions=[])


def load_rules(path: str | None) -> dict[str, list[RoutingRule]]:
    """YAML: ``{tenant_id: [rules...], "*": [...]}``. Missing tenants use defaults."""
    if not path or not Path(path).exists():
        return {}
    doc = yaml.safe_load(Path(path).read_text()) or {}
    return {t: [RoutingRule.model_validate(r) for r in rs] for t, rs in doc.items()}
