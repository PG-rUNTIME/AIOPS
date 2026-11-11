# syntax=docker/dockerfile:1.7
# One Dockerfile for every Python service:  docker build --build-arg SERVICE=router -f deploy/docker/Dockerfile .
#
# Base images are pinned by DIGEST in CI (scripts/pin-digests.sh rewrites the
# ARG defaults; Renovate keeps them current). Never build prod images from tags.
ARG PYTHON_IMAGE=python:3.12-slim-bookworm
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.5.11

FROM ${UV_IMAGE} AS uv

# ---------------------------------------------------------------- build stage
FROM ${PYTHON_IMAGE} AS build
ARG SERVICE
ARG EXTRAS=""
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /src
# Lockfile carries hashes for every wheel; --frozen refuses to re-resolve.
COPY pyproject.toml uv.lock .python-version ./
COPY libs/ libs/
COPY services/ services/
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable --package "${SERVICE}" \
      $(for e in ${EXTRAS}; do printf -- '--extra %s ' "$e"; done) \
 && ln -s "/opt/venv/bin/${SERVICE}" /opt/venv/bin/aiops-service

# ---------------------------------------------------------------- runtime stage
FROM ${PYTHON_IMAGE} AS runtime
ARG SERVICE
ARG VERSION=0.1.0
ARG REVISION=unknown
ARG CREATED=unknown
LABEL org.opencontainers.image.title="aiops-${SERVICE}" \
      org.opencontainers.image.source="https://github.com/your-org/aiops-platform" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.description="AIOps platform service: ${SERVICE}"

RUN groupadd --gid 10001 app \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin app \
 && rm -rf /var/lib/apt/lists/* /root/.cache

COPY --from=build /opt/venv /opt/venv
COPY --chown=0:0 config/ /app/config/

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    AIOPS_HTTP_PORT=8080 \
    HOME=/tmp

WORKDIR /app
USER 10001:10001
EXPOSE 8080
STOPSIGNAL SIGTERM
# Exec-form healthcheck: no shell needed. K8s uses /healthz + /readyz probes instead.
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status == 200 else 1)"]

# Remove shells last so nothing after this needs one (no interactive shell in prod).
USER 0
RUN rm -f /bin/sh /bin/bash /bin/dash /usr/bin/sh /usr/bin/bash /usr/bin/dash
USER 10001:10001
ENTRYPOINT ["/opt/venv/bin/aiops-service"]
