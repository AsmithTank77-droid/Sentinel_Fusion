"""
storage/store.py — StorageLayer: unified facade over all repositories.

Single entry point for all persistence operations. Wires together
the Database connection and all repositories. Provides a clean
one-call interface for persisting a complete pipeline run result.

Usage:
    with StorageLayer("sentinel.db") as store:
        run_id = store.persist_run(pipeline_result)
        cases  = store.cases.get_all(status="open")
        alerts = store.alerts.get_open(min_confidence=0.7)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from storage.database import Database
from storage.repositories.alerts import AlertRepository
from storage.repositories.audit import AuditRepository
from storage.repositories.cases import CaseRepository
from storage.repositories.events import EventRepository
from storage.repositories.scores import ScoreRepository


def _generate_run_id() -> str:
    ts  = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%S")
    uid = uuid.uuid4().hex[:8]
    return f"run-{ts}-{uid}"


class StorageLayer:
    """
    Unified storage facade for Sentinel_Fusion.

    Repositories are accessible as attributes:
        store.events   — EventRepository
        store.alerts   — AlertRepository
        store.cases    — CaseRepository
        store.scores   — ScoreRepository
        store.audit    — AuditRepository

    High-level methods:
        persist_run(result)  — persist a complete orchestrator result
        purge(days)          — enforce retention policy
        summary()            — platform-wide statistics dict
    """

    def __init__(self, path: str = "sentinel.db") -> None:
        self._db     = Database(path)
        self.events  = EventRepository(self._db)
        self.alerts  = AlertRepository(self._db)
        self.cases   = CaseRepository(self._db)
        self.scores  = ScoreRepository(self._db)
        self.audit   = AuditRepository(self._db)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def connect(self) -> "StorageLayer":
        self._db.connect()
        return self

    def close(self) -> None:
        self._db.close()

    def __enter__(self) -> "StorageLayer":
        self.connect()
        return self

    def __exit__(self, *_) -> None:
        self.close()

    # ------------------------------------------------------------------
    # High-level operations
    # ------------------------------------------------------------------

    def persist_run(self, result: dict, run_id: str | None = None) -> str:
        """
        Persist a complete orchestrator pipeline result to storage.

        Accepts the dict returned by PipelineOrchestrator.run():
        {
            "event_count":       int,
            "normalized_events": list[dict],
            "alerts":            list[dict],
            "scores":            dict,
            "timeline":          list[dict],
            "report":            dict,
            "trace":             list[dict],
        }

        Returns the run_id used for this persist operation.
        """
        if run_id is None:
            run_id = _generate_run_id()

        normalized_events = result.get("normalized_events") or []
        alerts            = result.get("alerts") or []
        scores            = result.get("scores") or {}
        trace             = result.get("trace") or []

        # Record run start
        self.audit.start_run(run_id)

        # Persist events
        event_count = self.events.store_batch(normalized_events, run_id)

        # Persist alerts
        alert_count = self.alerts.store_batch(alerts, run_id)

        # Persist scores
        self.scores.store_run_scores(scores, run_id)

        # Persist pipeline trace to audit log
        self.audit.log_trace(run_id, trace)

        # Mark run complete
        self.audit.complete_run(
            run_id=run_id,
            event_count=event_count,
            alert_count=alert_count,
            status="completed",
        )

        return run_id

    def purge(self, days: int = 90) -> dict[str, int]:
        """
        Enforce data retention policy. Deletes events older than `days` days.
        Returns counts of deleted rows per table.

        Alerts and cases are NOT auto-purged — they require explicit
        analyst closure to preserve audit trail integrity.
        """
        if days < 1:
            raise ValueError(f"Retention period must be >= 1 day, got {days}")
        deleted_events = self.events.purge_before(days)
        return {"events": deleted_events}

    def summary(self) -> dict:
        """
        Return platform-wide statistics for dashboards and health checks.

        {
            "total_events":     int,
            "total_alerts":     int,
            "total_cases":      int,
            "total_runs":       int,
            "alerts_by_status": dict,
            "cases_by_status":  dict,
            "alerts_by_type":   dict,
            "top_risk_hosts":   list[dict],
            "schema_version":   int,
        }
        """
        top_hosts = self.scores.get_highest_risk_hosts(limit=5)

        return {
            "total_events":     self.events.count(),
            "total_alerts":     sum(self.alerts.count_by_status().values()),
            "total_cases":      sum(self.cases.count_by_status().values()),
            "total_runs":       self.audit.get_run_count(),
            "alerts_by_status": self.alerts.count_by_status(),
            "cases_by_status":  self.cases.count_by_status(),
            "alerts_by_type":   self.alerts.count_by_type(),
            "top_risk_hosts": [
                {
                    "target":    h.target,
                    "score":     h.score,
                    "label":     h.label,
                    "scored_at": h.scored_at,
                }
                for h in top_hosts
            ],
            "schema_version": self._db.schema_version,
        }

    @property
    def db(self) -> Database:
        return self._db
