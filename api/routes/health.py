"""
api/routes/health.py — Health check and platform summary endpoints.
"""

from __future__ import annotations

from fastapi import APIRouter

from api.dependencies import Store
from api.schemas.responses import HealthResponse, SummaryResponse

router = APIRouter(tags=["health"])

_VERSION = "1.0.0"


@router.get("/health", response_model=HealthResponse, summary="Liveness check")
def health(store: Store) -> HealthResponse:
    """Returns API status and platform-wide event/alert/case totals."""
    s = store.summary()
    return HealthResponse(
        status="ok",
        version=_VERSION,
        schema_version=s["schema_version"],
        total_events=s["total_events"],
        total_alerts=s["total_alerts"],
        total_cases=s["total_cases"],
        total_runs=s["total_runs"],
    )


@router.get("/status", response_model=SummaryResponse, summary="Platform statistics")
def status(store: Store) -> SummaryResponse:
    """Full platform statistics including alert/case breakdowns and top risk hosts."""
    return SummaryResponse(**store.summary())
