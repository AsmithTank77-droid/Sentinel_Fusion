"""
storage/schema.py — SQLite schema definitions and versioned migrations.

Each entry in MIGRATIONS is a complete SQL batch for that version.
Migrations run in ascending order and are applied exactly once.
The schema_version table tracks what has been applied.
"""

from __future__ import annotations

CURRENT_VERSION = 1

# Each migration is a list of individual statements executed in order.
MIGRATIONS: dict[int, list[str]] = {
    1: [
        # Version tracking
        """
        CREATE TABLE IF NOT EXISTS schema_version (
            version    INTEGER PRIMARY KEY,
            applied_at TEXT    NOT NULL
        )
        """,

        # Pipeline runs — one row per orchestrator.run() call
        """
        CREATE TABLE IF NOT EXISTS runs (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id       TEXT    NOT NULL UNIQUE,
            event_count  INTEGER NOT NULL DEFAULT 0,
            alert_count  INTEGER NOT NULL DEFAULT 0,
            status       TEXT    NOT NULL DEFAULT 'running',
            started_at   TEXT    NOT NULL,
            completed_at TEXT
        )
        """,

        # Normalized events persisted after ingestion + normalization
        """
        CREATE TABLE IF NOT EXISTS events (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            event_hash   TEXT    NOT NULL UNIQUE,
            run_id       TEXT    NOT NULL,
            timestamp    TEXT    NOT NULL,
            source_type  TEXT    NOT NULL,
            src_ip       TEXT    NOT NULL DEFAULT '',
            dst_ip       TEXT    NOT NULL DEFAULT '',
            event_type   TEXT    NOT NULL,
            severity     INTEGER NOT NULL,
            metadata     TEXT    NOT NULL DEFAULT '{}',
            ingested_at  TEXT    NOT NULL
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_events_timestamp  ON events(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_events_src_ip     ON events(src_ip)",
        "CREATE INDEX IF NOT EXISTS idx_events_dst_ip     ON events(dst_ip)",
        "CREATE INDEX IF NOT EXISTS idx_events_run_id     ON events(run_id)",
        "CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type)",

        # Detection alerts
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_hash   TEXT    NOT NULL UNIQUE,
            run_id       TEXT    NOT NULL,
            alert_type   TEXT    NOT NULL,
            confidence   REAL    NOT NULL,
            src_ip       TEXT    NOT NULL DEFAULT '',
            dst_ip       TEXT    NOT NULL DEFAULT '',
            severity     INTEGER NOT NULL DEFAULT 0,
            mitre_tactic TEXT    NOT NULL DEFAULT '',
            details      TEXT    NOT NULL DEFAULT '{}',
            status       TEXT    NOT NULL DEFAULT 'open',
            created_at   TEXT    NOT NULL,
            updated_at   TEXT    NOT NULL
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_alerts_status     ON alerts(status)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_src_ip     ON alerts(src_ip)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_run_id     ON alerts(run_id)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_alert_type ON alerts(alert_type)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_confidence ON alerts(confidence)",

        # Incident cases — group related alerts into an investigation
        """
        CREATE TABLE IF NOT EXISTS cases (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            case_ref    TEXT    NOT NULL UNIQUE,
            title       TEXT    NOT NULL,
            severity    TEXT    NOT NULL DEFAULT 'medium',
            status      TEXT    NOT NULL DEFAULT 'open',
            assigned_to TEXT    NOT NULL DEFAULT '',
            created_at  TEXT    NOT NULL,
            updated_at  TEXT    NOT NULL
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_cases_status   ON cases(status)",
        "CREATE INDEX IF NOT EXISTS idx_cases_severity ON cases(severity)",

        # Many-to-many: cases ↔ alerts
        """
        CREATE TABLE IF NOT EXISTS case_alerts (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            case_ref  TEXT    NOT NULL,
            alert_id  INTEGER NOT NULL,
            linked_at TEXT    NOT NULL,
            UNIQUE(case_ref, alert_id)
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_case_alerts_case  ON case_alerts(case_ref)",
        "CREATE INDEX IF NOT EXISTS idx_case_alerts_alert ON case_alerts(alert_id)",

        # Analyst notes attached to cases
        """
        CREATE TABLE IF NOT EXISTS case_notes (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            case_ref   TEXT    NOT NULL,
            author     TEXT    NOT NULL DEFAULT 'analyst',
            note       TEXT    NOT NULL,
            created_at TEXT    NOT NULL
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_case_notes_case ON case_notes(case_ref)",

        # Risk scores per run — one row per (run_id, score_type, target)
        """
        CREATE TABLE IF NOT EXISTS scores (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id     TEXT    NOT NULL,
            score_type TEXT    NOT NULL,
            target     TEXT    NOT NULL,
            score      REAL    NOT NULL,
            label      TEXT    NOT NULL,
            details    TEXT    NOT NULL DEFAULT '{}',
            scored_at  TEXT    NOT NULL
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_scores_run_id     ON scores(run_id)",
        "CREATE INDEX IF NOT EXISTS idx_scores_target     ON scores(target)",
        "CREATE INDEX IF NOT EXISTS idx_scores_score_type ON scores(score_type)",

        # Pipeline stage audit log
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id     TEXT    NOT NULL,
            stage      TEXT    NOT NULL,
            action     TEXT    NOT NULL,
            detail     TEXT    NOT NULL DEFAULT '',
            created_at TEXT    NOT NULL
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_audit_run_id ON audit_log(run_id)",
        "CREATE INDEX IF NOT EXISTS idx_audit_stage  ON audit_log(stage)",
    ],
}
