"""
api/schemas/requests.py — Pydantic request models for all API endpoints.
"""

from __future__ import annotations

from typing import Any, Optional
from pydantic import BaseModel, Field, field_validator


class PipelineRunRequest(BaseModel):
    nra:    list[dict[str, Any]] = Field(default_factory=list, description="NRA / Nmap events")
    winlog: list[dict[str, Any]] = Field(default_factory=list, description="Windows event log records")
    mock:   list[dict[str, Any]] = Field(default_factory=list, description="Simulated / mock attack events")

    @field_validator("nra", "winlog", "mock", mode="before")
    @classmethod
    def must_be_list_of_dicts(cls, v: Any) -> list:
        if not isinstance(v, list):
            raise ValueError("Must be a list of event dicts")
        return v

    model_config = {
        "json_schema_extra": {
            "example": {
                "nra": [
                    {
                        "scanner_ip": "185.220.101.45",
                        "host": "10.0.0.5",
                        "scan_time": "2026-05-09T02:14:00Z",
                        "risk_level": "high",
                    }
                ],
                "winlog": [
                    {
                        "EventID": 4625,
                        "TimeCreated": "2026-05-09T02:15:00Z",
                        "IpAddress": "185.220.101.45",
                        "dst_ip": "10.0.0.5",
                    }
                ],
                "mock": [],
            }
        }
    }


class AlertStatusUpdate(BaseModel):
    status: str = Field(
        ...,
        description="New alert status",
        examples=["investigating"],
    )

    @field_validator("status")
    @classmethod
    def valid_status(cls, v: str) -> str:
        valid = {"open", "investigating", "contained", "closed"}
        if v not in valid:
            raise ValueError(f"status must be one of {sorted(valid)}")
        return v


class CreateCaseRequest(BaseModel):
    title:       str = Field(..., min_length=1, max_length=255, description="Case title")
    severity:    str = Field("medium", description="Case severity: low/medium/high/critical")
    assigned_to: str = Field("", description="Analyst email or name")

    @field_validator("severity")
    @classmethod
    def valid_severity(cls, v: str) -> str:
        valid = {"low", "medium", "high", "critical"}
        if v not in valid:
            raise ValueError(f"severity must be one of {sorted(valid)}")
        return v

    model_config = {
        "json_schema_extra": {
            "example": {
                "title": "SSH Brute Force — DC01",
                "severity": "high",
                "assigned_to": "analyst@company.com",
            }
        }
    }


class CaseStatusUpdate(BaseModel):
    status: str = Field(..., description="New case status")

    @field_validator("status")
    @classmethod
    def valid_status(cls, v: str) -> str:
        valid = {"open", "investigating", "contained", "closed"}
        if v not in valid:
            raise ValueError(f"status must be one of {sorted(valid)}")
        return v


class CaseAssignRequest(BaseModel):
    assigned_to: str = Field(..., min_length=1, description="Analyst name or email")


class AddNoteRequest(BaseModel):
    note:   str = Field(..., min_length=1, description="Analyst note text")
    author: str = Field("analyst", description="Note author")

    model_config = {
        "json_schema_extra": {
            "example": {
                "note": "Confirmed TOR exit node activity from Russian IP block. Escalating.",
                "author": "j.smith@company.com",
            }
        }
    }


class LinkAlertRequest(BaseModel):
    alert_id: int = Field(..., gt=0, description="Alert database ID to link to this case")


class PurgeRequest(BaseModel):
    days: int = Field(90, ge=1, le=3650, description="Delete events older than this many days")
