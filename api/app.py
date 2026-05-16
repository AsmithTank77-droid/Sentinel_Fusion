"""
api/app.py — FastAPI application factory.

Run with:
    uvicorn api.app:app --host 0.0.0.0 --port 8000

Or via the config-driven entrypoint:
    python -m api.run

Interactive docs:
    http://localhost:8000/api/docs    (Swagger UI)
    http://localhost:8000/api/redoc   (ReDoc)
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse

from fastapi.security import APIKeyHeader

from api.dependencies import init_dependencies, shutdown_dependencies, verify_api_key
from api.routes import alerts, cases, events, health, intel, pipeline, scores
from config.settings import get_settings

_AUTH = [Depends(verify_api_key)]

_API_PREFIX = "/api/v1"


@asynccontextmanager
async def _lifespan(app: FastAPI):
    cfg = get_settings()
    init_dependencies(db_path=str(cfg.db_path))
    yield
    shutdown_dependencies()


def create_app() -> FastAPI:
    cfg = get_settings()

    app = FastAPI(
        title="Sentinel Fusion",
        description=(
            "## SOC-Grade Detection & Correlation Engine\n\n"
            "Sentinel Fusion ingests multi-source security events (NRA scans, "
            "Windows event logs, simulated attacks), correlates them into attack "
            "chains, scores host and asset risk, and generates structured SOC "
            "reports — all through a single REST API.\n\n"
            "### Pipeline Stages\n"
            "Ingest → Normalize → Enrich → Correlate → Detect → Score → Timeline → Report\n\n"
            "### Quick Start\n"
            "`POST /api/v1/pipeline/run` with your event data to trigger the full pipeline."
        ),
        version=cfg.version,
        debug=cfg.debug,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        lifespan=_lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.cors_origins_list,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.exception_handler(ValueError)
    async def _value_error(request: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "Bad Request", "detail": str(exc), "code": 400},
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "Internal Server Error", "detail": str(exc), "code": 500},
        )

    app.include_router(health.router,   prefix=_API_PREFIX)                         # no auth — monitoring
    app.include_router(pipeline.router, prefix=_API_PREFIX, dependencies=_AUTH)
    app.include_router(events.router,   prefix=_API_PREFIX, dependencies=_AUTH)
    app.include_router(alerts.router,   prefix=_API_PREFIX, dependencies=_AUTH)
    app.include_router(cases.router,    prefix=_API_PREFIX, dependencies=_AUTH)
    app.include_router(scores.router,   prefix=_API_PREFIX, dependencies=_AUTH)
    app.include_router(intel.router,    prefix=_API_PREFIX, dependencies=_AUTH)

    _DASHBOARD = Path(__file__).parent.parent / "interface" / "dashboard" / "index.html"

    @app.get("/", include_in_schema=False)
    async def _root() -> RedirectResponse:
        return RedirectResponse(url="/dashboard")

    @app.get("/dashboard", include_in_schema=False)
    async def _dashboard() -> FileResponse:
        return FileResponse(_DASHBOARD, media_type="text/html")

    return app


app = create_app()
