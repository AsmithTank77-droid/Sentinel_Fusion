"""
api/routes/alerts.py — Alert query and lifecycle endpoints.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status

from api.dependencies import Store
from api.schemas.requests import AlertStatusUpdate
from api.schemas.responses import AlertResponse

router = APIRouter(prefix="/alerts", tags=["alerts"])


def _alert_response(a) -> AlertResponse:
    return AlertResponse(
        id=a.id,
        alert_hash=a.alert_hash,
        run_id=a.run_id,
        alert_type=a.alert_type,
        confidence=a.confidence,
        src_ip=a.src_ip,
        dst_ip=a.dst_ip,
        severity=a.severity,
        mitre_tactic=a.mitre_tactic,
        status=a.status,
        details=a.details,
        created_at=a.created_at,
        updated_at=a.updated_at,
    )


@router.get("", response_model=list[AlertResponse], summary="List alerts")
def list_alerts(
    store: Store,
    alert_status:   str | None = Query(None, alias="status", description="Filter by status"),
    min_confidence: float      = Query(0.0, ge=0.0, le=1.0, description="Minimum confidence"),
    limit:          int        = Query(50, ge=1, le=500, description="Max results"),
) -> list[AlertResponse]:
    """
    Returns alerts ordered by created_at descending. Optionally filter by status
    (open / investigating / contained / closed) and minimum confidence score.
    """
    if alert_status:
        try:
            alerts = store.alerts.get_by_status(alert_status)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    else:
        alerts = store.alerts.get_recent(limit=limit)

    if min_confidence > 0.0:
        alerts = [a for a in alerts if a.confidence >= min_confidence]

    return [_alert_response(a) for a in alerts[:limit]]


@router.get("/{alert_id}", response_model=AlertResponse, summary="Get alert by ID")
def get_alert(alert_id: int, store: Store) -> AlertResponse:
    alert = store.alerts.get_by_id(alert_id)
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id} not found.",
        )
    return _alert_response(alert)


@router.patch(
    "/{alert_id}/status",
    response_model=AlertResponse,
    summary="Update alert status",
)
def update_alert_status(
    alert_id: int,
    body: AlertStatusUpdate,
    store: Store,
) -> AlertResponse:
    """Advance alert through its lifecycle: open → investigating → contained → closed."""
    alert = store.alerts.get_by_id(alert_id)
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id} not found.",
        )
    store.alerts.update_status(alert_id, body.status)
    return _alert_response(store.alerts.get_by_id(alert_id))
