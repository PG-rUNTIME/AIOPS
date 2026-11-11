"""Routing rules live in aiops_common.routing (shared with the control plane)."""

from aiops_common.routing import (
    DEFAULT_RULES,
    Match,
    RouteAction,
    RouteDecision,
    RoutingRule,
    decide,
    load_rules,
)

__all__ = [
    "DEFAULT_RULES",
    "Match",
    "RouteAction",
    "RouteDecision",
    "RoutingRule",
    "decide",
    "load_rules",
]
