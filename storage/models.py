"""
storage/models.py — Dataclass models for all persisted entities.

These are plain Python dataclasses — no ORM, no magic.
They mirror the storage schema exactly and are used as the contract
between repositories and callers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class StoredEvent:
    event_hash:  str
    run_id:      str
    timestamp:   str
    source_type: str
    src_ip:      str
    dst_ip:      str
    event_type:  str
    severity:    int
    metadata:    dict
    ingested_at: str
    id:          Optional[int] = None


@dataclass
class StoredAlert:
    alert_hash:   str
    run_id:       str
    alert_type:   str
    confidence:   float
    src_ip:       str
    dst_ip:       str
    severity:     int
    mitre_tactic: str
    details:      dict
    created_at:   str
    updated_at:   str
    status:       str = "open"
    id:           Optional[int] = None


@dataclass
class StoredCase:
    case_ref:    str
    title:       str
    severity:    str
    status:      str
    assigned_to: str
    created_at:  str
    updated_at:  str
    id:          Optional[int] = None


@dataclass
class CaseNote:
    case_ref:   str
    note:       str
    author:     str
    created_at: str
    id:         Optional[int] = None


@dataclass
class StoredScore:
    run_id:     str
    score_type: str
    target:     str
    score:      float
    label:      str
    details:    dict
    scored_at:  str
    id:         Optional[int] = None


@dataclass
class AuditEntry:
    run_id:     str
    stage:      str
    action:     str
    detail:     str
    created_at: str
    id:         Optional[int] = None


@dataclass
class PipelineRun:
    run_id:       str
    event_count:  int
    alert_count:  int
    status:       str
    started_at:   str
    completed_at: Optional[str] = None
    id:           Optional[int] = None


# Valid status values — enforced at the repository layer
ALERT_STATUSES: frozenset[str] = frozenset({"open", "investigating", "contained", "closed"})
CASE_STATUSES:  frozenset[str] = frozenset({"open", "investigating", "contained", "closed"})
CASE_SEVERITIES: frozenset[str] = frozenset({"low", "medium", "high", "critical"})
RUN_STATUSES:   frozenset[str] = frozenset({"running", "completed", "failed"})
