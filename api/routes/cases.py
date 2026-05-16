"""
api/routes/cases.py — Incident case management endpoints.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status

from api.dependencies import Store
from api.schemas.requests import (
    AddNoteRequest,
    CaseAssignRequest,
    CaseStatusUpdate,
    CreateCaseRequest,
    LinkAlertRequest,
)
from api.schemas.responses import CaseNoteResponse, CaseResponse

router = APIRouter(prefix="/cases", tags=["cases"])


def _case_response(c) -> CaseResponse:
    return CaseResponse(
        id=c.id,
        case_ref=c.case_ref,
        title=c.title,
        severity=c.severity,
        status=c.status,
        assigned_to=c.assigned_to,
        created_at=c.created_at,
        updated_at=c.updated_at,
    )


def _note_response(n) -> CaseNoteResponse:
    return CaseNoteResponse(
        id=n.id,
        case_ref=n.case_ref,
        author=n.author,
        note=n.note,
        created_at=n.created_at,
    )


def _require_case(case_ref: str, store) -> None:
    if store.cases.get(case_ref) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_ref}' not found.",
        )


@router.get("", response_model=list[CaseResponse], summary="List cases")
def list_cases(
    store: Store,
    case_status: str | None = Query(None, alias="status", description="Filter by status"),
) -> list[CaseResponse]:
    """Returns all cases, optionally filtered by status (open / investigating / contained / closed)."""
    try:
        cases = store.cases.get_all(status=case_status)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return [_case_response(c) for c in cases]


@router.post(
    "",
    response_model=CaseResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create incident case",
)
def create_case(body: CreateCaseRequest, store: Store) -> CaseResponse:
    """Creates a new incident case with a sequential CASE-YYYY-NNNN reference."""
    case = store.cases.create(
        title=body.title,
        severity=body.severity,
        assigned_to=body.assigned_to,
    )
    return _case_response(case)


@router.get("/{case_ref}", response_model=CaseResponse, summary="Get case by reference")
def get_case(case_ref: str, store: Store) -> CaseResponse:
    case = store.cases.get(case_ref)
    if case is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_ref}' not found.",
        )
    return _case_response(case)


@router.patch(
    "/{case_ref}/status",
    response_model=CaseResponse,
    summary="Update case status",
)
def update_case_status(case_ref: str, body: CaseStatusUpdate, store: Store) -> CaseResponse:
    """Advance case through its lifecycle: open → investigating → contained → closed."""
    _require_case(case_ref, store)
    store.cases.update_status(case_ref, body.status)
    return _case_response(store.cases.get(case_ref))


@router.patch(
    "/{case_ref}/assign",
    response_model=CaseResponse,
    summary="Assign case to analyst",
)
def assign_case(case_ref: str, body: CaseAssignRequest, store: Store) -> CaseResponse:
    _require_case(case_ref, store)
    store.cases.assign(case_ref, body.assigned_to)
    return _case_response(store.cases.get(case_ref))


@router.post(
    "/{case_ref}/notes",
    response_model=CaseNoteResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add analyst note",
)
def add_note(case_ref: str, body: AddNoteRequest, store: Store) -> CaseNoteResponse:
    _require_case(case_ref, store)
    note = store.cases.add_note(case_ref, note=body.note, author=body.author)
    return _note_response(note)


@router.get(
    "/{case_ref}/notes",
    response_model=list[CaseNoteResponse],
    summary="Get case notes",
)
def get_notes(case_ref: str, store: Store) -> list[CaseNoteResponse]:
    _require_case(case_ref, store)
    return [_note_response(n) for n in store.cases.get_notes(case_ref)]


@router.post(
    "/{case_ref}/alerts",
    response_model=CaseResponse,
    summary="Link alert to case",
)
def link_alert(case_ref: str, body: LinkAlertRequest, store: Store) -> CaseResponse:
    """Links an existing alert to this case (idempotent — safe to call twice)."""
    _require_case(case_ref, store)
    alert = store.alerts.get_by_id(body.alert_id)
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert {body.alert_id} not found.",
        )
    store.cases.link_alert(case_ref, body.alert_id)
    return _case_response(store.cases.get(case_ref))
