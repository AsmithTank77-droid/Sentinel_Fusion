"""
api/routes/pipeline.py — Pipeline execution and run history endpoints.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status

from api.dependencies import Orchestrator, Store
from api.schemas.requests import PipelineRunRequest, PurgeRequest
from api.schemas.responses import (
    PipelineRunResponse,
    PipelineRunSummaryResponse,
    PurgeResponse,
)
from core.pipeline.orchestrator import PipelineStageError

router = APIRouter(prefix="/pipeline", tags=["pipeline"])


@router.post(
    "/run",
    response_model=PipelineRunResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute the full 8-stage detection pipeline",
)
def run_pipeline(
    body: PipelineRunRequest,
    orchestrator: Orchestrator,
    store: Store,
) -> PipelineRunResponse:
    """
    Accepts multi-source event batches (nra / winlog / mock), runs the complete
    Sentinel Fusion pipeline, persists the results, and returns the run summary
    including scores, top alerts, and the full SOC report.
    """
    inputs: dict[str, list] = {}
    if body.nra:
        inputs["nra"] = body.nra
    if body.winlog:
        inputs["winlog"] = body.winlog
    if body.mock:
        inputs["mock"] = body.mock

    if not inputs:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one non-empty source list (nra, winlog, mock) is required.",
        )

    try:
        result = orchestrator.run(inputs)
    except PipelineStageError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Pipeline failed at stage '{exc.stage}': {exc.cause}",
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    run_id = store.persist_run(result)

    top_alerts = sorted(
        result["alerts"],
        key=lambda a: float(a.get("confidence", 0)),
        reverse=True,
    )[:5]

    return PipelineRunResponse(
        run_id=run_id,
        event_count=result["event_count"],
        alert_count=len(result["alerts"]),
        status="completed",
        trace=result["trace"],
        scores=result["scores"],
        top_alerts=top_alerts,
        report=result["report"],
    )


@router.get(
    "/runs",
    response_model=list[PipelineRunSummaryResponse],
    summary="List recent pipeline runs",
)
def list_runs(
    store: Store,
    limit: int = Query(20, ge=1, le=200, description="Max runs to return"),
) -> list[PipelineRunSummaryResponse]:
    """Returns the most recent pipeline runs, newest first."""
    runs = store.audit.get_recent_runs(limit=limit)
    return [
        PipelineRunSummaryResponse(
            id=r.id,
            run_id=r.run_id,
            event_count=r.event_count,
            alert_count=r.alert_count,
            status=r.status,
            started_at=r.started_at,
            completed_at=r.completed_at,
        )
        for r in runs
    ]


@router.get(
    "/runs/{run_id}",
    response_model=PipelineRunSummaryResponse,
    summary="Get a specific pipeline run",
)
def get_run(run_id: str, store: Store) -> PipelineRunSummaryResponse:
    run = store.audit.get_run(run_id)
    if run is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Run '{run_id}' not found.",
        )
    return PipelineRunSummaryResponse(
        id=run.id,
        run_id=run.run_id,
        event_count=run.event_count,
        alert_count=run.alert_count,
        status=run.status,
        started_at=run.started_at,
        completed_at=run.completed_at,
    )


@router.post(
    "/purge",
    response_model=PurgeResponse,
    summary="Purge events older than N days",
)
def purge_events(body: PurgeRequest, store: Store) -> PurgeResponse:
    """
    Enforce data retention. Deletes events older than `days` days.
    Alerts and cases are NOT purged — they require explicit analyst closure.
    """
    result = store.purge(days=body.days)
    return PurgeResponse(
        deleted_events=result.get("events", 0),
        retention_days=body.days,
    )
