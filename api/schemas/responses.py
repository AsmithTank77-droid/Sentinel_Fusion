"""
api/schemas/responses.py — Pydantic response models for all API endpoints.
"""

from __future__ import annotations

from typing import Any, Optional
from pydantic import BaseModel


class HealthResponse(BaseModel):
    status:         str
    version:        str
    schema_version: int
    total_events:   int
    total_alerts:   int
    total_cases:    int
    total_runs:     int


class PipelineRunResponse(BaseModel):
    run_id:       str
    event_count:  int
    alert_count:  int
    status:       str
    trace:        list[dict[str, Any]]
    scores:       dict[str, Any]
    top_alerts:   list[dict[str, Any]]
    report:       dict[str, Any]


class EventResponse(BaseModel):
    id:          Optional[int]
    event_hash:  str
    run_id:      str
    timestamp:   str
    source_type: str
    src_ip:      str
    dst_ip:      str
    event_type:  str
    severity:    int
    ingested_at: str


class AlertResponse(BaseModel):
    id:           Optional[int]
    alert_hash:   str
    run_id:       str
    alert_type:   str
    confidence:   float
    src_ip:       str
    dst_ip:       str
    severity:     int
    mitre_tactic: str
    status:       str
    details:      dict[str, Any]
    created_at:   str
    updated_at:   str


class CaseResponse(BaseModel):
    id:          Optional[int]
    case_ref:    str
    title:       str
    severity:    str
    status:      str
    assigned_to: str
    created_at:  str
    updated_at:  str


class CaseNoteResponse(BaseModel):
    id:         Optional[int]
    case_ref:   str
    author:     str
    note:       str
    created_at: str


class ScoreResponse(BaseModel):
    id:         Optional[int]
    run_id:     str
    score_type: str
    target:     str
    score:      float
    label:      str
    details:    dict[str, Any]
    scored_at:  str


class IntelResponse(BaseModel):
    ip:         str
    reputation: dict[str, Any]
    geo:        dict[str, Any]
    threats:    dict[str, Any]
    summary:    dict[str, Any]


class SummaryResponse(BaseModel):
    total_events:     int
    total_alerts:     int
    total_cases:      int
    total_runs:       int
    alerts_by_status: dict[str, int]
    cases_by_status:  dict[str, int]
    alerts_by_type:   dict[str, int]
    top_risk_hosts:   list[dict[str, Any]]
    schema_version:   int


class PurgeResponse(BaseModel):
    deleted_events: int
    retention_days: int


class PipelineRunSummaryResponse(BaseModel):
    id:           Optional[int]
    run_id:       str
    event_count:  int
    alert_count:  int
    status:       str
    started_at:   str
    completed_at: Optional[str] = None


class ErrorResponse(BaseModel):
    error:   str
    detail:  Optional[str] = None
    code:    int
