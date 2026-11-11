"""Operational HTTP endpoints shared by every service: /healthz, /readyz, /metrics."""

from __future__ import annotations

from collections.abc import Callable

from fastapi import APIRouter, FastAPI, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest


def ops_router(ready: Callable[[], bool]) -> APIRouter:
    r = APIRouter(tags=["ops"])

    @r.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @r.get("/readyz", include_in_schema=False)
    async def readyz(response: Response) -> dict[str, str]:
        if ready():
            return {"status": "ready"}
        response.status_code = 503
        return {"status": "not_ready"}

    @r.get("/metrics", include_in_schema=False)
    async def metrics() -> Response:
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    return r


def ops_app(ready: Callable[[], bool], title: str) -> FastAPI:
    app = FastAPI(title=title, docs_url=None, redoc_url=None, openapi_url=None)
    app.include_router(ops_router(ready))
    return app
