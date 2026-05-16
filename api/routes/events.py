"""
api/routes/events.py — Normalized event query endpoints.
"""

from __future__ import annotations

from fastapi import APIRouter, Query

from api.dependencies import Store
from api.schemas.responses import EventResponse

router = APIRouter(prefix="/events", tags=["events"])


def _event_response(e) -> EventResponse:
    return EventResponse(
        id=e.id,
        event_hash=e.event_hash,
        run_id=e.run_id,
        timestamp=e.timestamp,
        source_type=e.source_type,
        src_ip=e.src_ip,
        dst_ip=e.dst_ip,
        event_type=e.event_type,
        severity=e.severity,
        ingested_at=e.ingested_at,
    )


@router.get("", response_model=list[EventResponse], summary="Query normalized events")
def list_events(
    store: Store,
    run_id:     str | None = Query(None, description="Filter by pipeline run ID"),
    src_ip:     str | None = Query(None, description="Filter by source IP"),
    event_type: str | None = Query(None, description="Filter by event type"),
    limit:      int        = Query(100, ge=1, le=1000, description="Max results"),
) -> list[EventResponse]:
    """
    Query stored events. Filters are mutually exclusive and evaluated in priority
    order: run_id → src_ip → event_type → most recent N events.
    """
    if run_id:
        events = store.events.get_by_run(run_id)
    elif src_ip:
        events = store.events.get_by_src_ip(src_ip, limit=limit)
    elif event_type:
        events = store.events.get_by_event_type(event_type, limit=limit)
    else:
        events = store.events.get_recent(limit=limit)

    return [_event_response(e) for e in events[:limit]]
