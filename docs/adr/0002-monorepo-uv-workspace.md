# ADR-0002: Monorepo with a uv workspace and one shared library

- Status: accepted · Date: 2026-11-11

## Context
Nine small services share contracts, Kafka helpers, telemetry and config. They must be
independently deployable yet change together when a contract changes.

## Decision
- One repo; each service is a uv workspace member under `services/<name>` with its own
  `pyproject.toml` and console script; shared code lives in `libs/aiops-common`.
- One `uv.lock` (with hashes) for the whole workspace; images install `--frozen --no-dev
  --no-editable --package <svc>` so each image only carries its own dependency closure.
- One parameterised Dockerfile (`deploy/docker/Dockerfile`, `--build-arg SERVICE=`).
- Routing-rule models live in the shared lib because both router and control plane validate them.

## Consequences
Atomic contract changes; a single lockfile means one Renovate stream. Services still get
SemVer independently via their own `version` and image tags.
