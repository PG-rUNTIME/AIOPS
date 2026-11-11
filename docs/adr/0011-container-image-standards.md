# ADR-0011: Container image standards

- Status: accepted · Date: 2026-11-11

## Decision
Multi-stage build on `python:3.12-slim-bookworm`; uv installs from the hashed lockfile with a
BuildKit cache mount; non-root UID 10001; shells removed from the final image; exec-form
HEALTHCHECK; OCI labels; read-only root FS + `cap_drop: ALL` + `no-new-privileges` in Compose and
the Helm chart; SIGTERM drains within 25 s (`terminationGracePeriodSeconds: 35`).
CI: buildx multi-arch (amd64/arm64) → Trivy (fail on fixable HIGH/CRITICAL) → Syft SPDX SBOM →
Cosign keyless sign + SBOM attestation; BuildKit provenance `mode=max` for SLSA L2.

## Deviation / open item
Distroless Python images ship Python 3.11, so the base is slim + shell removal instead.
Base images are referenced by tag in the committed Dockerfile; CI runs `scripts/pin-digests.sh`
before release builds and `check-digests.sh` fails unpinned builds; Renovate (`docker:pinDigests`)
should commit the digests on first run.
