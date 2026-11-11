#!/usr/bin/env bash
# CI gate for release builds: every base image must be referenced by digest.
set -euo pipefail
if grep -E '^ARG (PYTHON|UV)_IMAGE=' deploy/docker/Dockerfile | grep -vq '@sha256:'; then
  echo "Base images are not pinned by digest. Run scripts/pin-digests.sh." >&2
  exit 1
fi
