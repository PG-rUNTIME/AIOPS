#!/usr/bin/env bash
# Resolve base-image tags to digests and rewrite the Dockerfile ARG defaults.
# Run in CI before building release images (and Renovate keeps them fresh).
set -euo pipefail
f=deploy/docker/Dockerfile
for arg in PYTHON_IMAGE UV_IMAGE; do
  ref=$(grep -E "^ARG ${arg}=" "$f" | cut -d= -f2-)
  tag=${ref%@*}
  digest=$(docker buildx imagetools inspect "$tag" --format '{{json .Manifest}}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["digest"])')
  sed -i "s|^ARG ${arg}=.*|ARG ${arg}=${tag}@${digest}|" "$f"
  echo "${arg} -> ${tag}@${digest}"
done
