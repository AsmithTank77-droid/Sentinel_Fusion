"""
storage/repositories/audit.py — AuditRepository + RunRepository.

Tracks pipeline runs and per-stage audit log entries.
Provides complete execution history for every pipeline invocation.
"""

from __future__ import annotations

from datetime import datetime, timezone

from storage.database import Database
from storage.models import AuditEntry, PipelineRun, RUN_STATUSES


def _now() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class AuditRepository:
    """Read/write access to audit_log and runs tables."""

    def __init__(self, db: Database) -> None:
        self._db = db

    # ------------------------------------------------------------------
    # Pipeline runs
    # ------------------------------------------------------------------

    def start_run(self, run_id: str) -> PipelineRun:
        """Record the start of a new pipeline run."""
        now = _now()
        self._db.execute(
            """
            INSERT INTO runs
                (run_id, event_count, alert_count, status, started_at)
            VALUES (?, 0, 0, 'running', ?)
            """,
            (run_id, now),
        )
        return PipelineRun(
            run_id=run_id,
            event_count=0,
            alert_count=0,
            status="running",
            started_at=now,
        )

    def complete_run(
        self,
        run_id: str,
        event_count: int,
        alert_count: int,
        status: str = "completed",
    ) -> None:
        """Mark a run as completed (or failed) with final counts."""
        if status not in RUN_STATUSES:
            raise ValueError(f"Invalid run status {status!r}")
        self._db.execute(
            """
            UPDATE runs
            SET event_count = ?, alert_count = ?, status = ?, completed_at = ?
            WHERE run_id = ?
            """,
            (event_count, alert_count, status, _now(), run_id),
        )

    def get_run(self, run_id: str) -> PipelineRun | None:
        row = self._db.query_one(
            "SELECT * FROM runs WHERE run_id = ?", (run_id,)
        )
        return self._run_row(row) if row else None

    def get_recent_runs(self, limit: int = 20) -> list[PipelineRun]:
        rows = self._db.query(
            "SELECT * FROM runs ORDER BY started_at DESC LIMIT ?", (limit,)
        )
        return [self._run_row(r) for r in rows]

    def get_run_count(self) -> int:
        row = self._db.query_one("SELECT COUNT(*) FROM runs")
        return row[0] if row else 0

    # ------------------------------------------------------------------
    # Audit log
    # ------------------------------------------------------------------

    def log(
        self,
        run_id: str,
        stage: str,
        action: str,
        detail: str = "",
    ) -> AuditEntry:
        """Append an audit log entry for a pipeline stage action."""
        now = _now()
        self._db.execute(
            """
            INSERT INTO audit_log (run_id, stage, action, detail, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (run_id, stage, action, detail, now),
        )
        return AuditEntry(
            run_id=run_id,
            stage=stage,
            action=action,
            detail=detail,
            created_at=now,
        )

    def log_trace(self, run_id: str, trace: list[dict]) -> None:
        """
        Persist the orchestrator's trace list to the audit log.
        Each trace entry: {stage, status, count (optional)}.
        """
        for entry in trace:
            detail = f"count={entry['count']}" if "count" in entry else ""
            self.log(
                run_id=run_id,
                stage=entry.get("stage", "unknown"),
                action=entry.get("status", "ok"),
                detail=detail,
            )

    def get_run_log(self, run_id: str) -> list[AuditEntry]:
        rows = self._db.query(
            "SELECT * FROM audit_log WHERE run_id = ? ORDER BY created_at",
            (run_id,),
        )
        return [self._audit_row(r) for r in rows]

    def get_stage_log(self, stage: str, limit: int = 100) -> list[AuditEntry]:
        rows = self._db.query(
            """SELECT * FROM audit_log WHERE stage = ?
               ORDER BY created_at DESC LIMIT ?""",
            (stage, limit),
        )
        return [self._audit_row(r) for r in rows]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _run_row(row) -> PipelineRun:
        return PipelineRun(
            id=row["id"],
            run_id=row["run_id"],
            event_count=row["event_count"],
            alert_count=row["alert_count"],
            status=row["status"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
        )

    @staticmethod
    def _audit_row(row) -> AuditEntry:
        return AuditEntry(
            id=row["id"],
            run_id=row["run_id"],
            stage=row["stage"],
            action=row["action"],
            detail=row["detail"],
            created_at=row["created_at"],
        )
