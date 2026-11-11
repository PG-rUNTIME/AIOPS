# ADR-0001: Record architecture decisions

- Status: accepted · Date: 2026-11-11

## Context
The build prompt requires every significant choice to be defensible and recorded.

## Decision
Lightweight ADRs (Nygard format) in `docs/adr/`, numbered, immutable once accepted (supersede, don't edit).
Every deviation from the stack table in the build prompt has an ADR.

## Consequences
Reviewers can trace why the code looks the way it does; ADR links go in PR descriptions.
