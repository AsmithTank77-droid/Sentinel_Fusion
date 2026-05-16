"""
storage/repositories/alerts.py — AlertRepository.

Stores detection alerts with status lifecycle management.
Deduplicates by alert_hash — the same alert from the same run
is stored only once.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from storage.database import Database, DatabaseError
from storage.models import ALERT_STATUSES, StoredAlert


def _now() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hash_alert(alert: dict) -> str:
    """
    Deterministic 24-char hash. Keys that uniquely identify an alert instance.
    Includes window_start / timestamp so the same alert_type from different
    time windows produces different hashes.
    """
    key = (
        alert.get("alert_type", ""),
        alert.get("src_ip", ""),
        alert.get("dst_ip", ""),
        alert.get("window_start") or alert.get("timestamp") or
        alert.get("initial_login_ts") or
        (alert.get("timestamps") or [""])[0],
    )
    return hashlib.sha256(json.dumps(key).encode()).hexdigest()[:24]


class AlertRepository:
    """Read/write access to the alerts table."""

    def __init__(self, db: Database) -> None:
        self._db = db

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    def store(self, alert: dict, run_id: str) -> str | None:
        """
        Persist an alert dict.
        Returns alert_hash on success, None if already stored (idempotent).
        """
        alert_hash   = _hash_alert(alert)
        now          = _now()
        src_ip       = alert.get("src_ip") or alert.get("initial_src_ip") or ""
        dst_ip       = (alert.get("dst_ip") or alert.get("lateral_target")
                        or alert.get("pivot_host") or "")
        mitre_tactic = alert.get("mitre_tactic") or (
            alert.get("mitre_tactics") or [""]
        )[0]

        try:
            self._db.execute(
                """
                INSERT INTO alerts
                    (alert_hash, run_id, alert_type, confidence,
                     src_ip, dst_ip, severity, mitre_tactic,
                     details, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)
                """,
                (
                    alert_hash,
                    run_id,
                    alert.get("alert_type", "unknown"),
                    float(alert.get("confidence") or 0.0),
                    src_ip,
                    dst_ip,
                    int(alert.get("severity") or alert.get("max_severity") or 0),
                    mitre_tactic,
                    json.dumps(alert),
                    now,
                    now,
                ),
            )
            return alert_hash
        except Exception:
            return None  # duplicate

    def store_batch(self, alerts: list[dict], run_id: str) -> int:
        """Store a list of alerts. Returns count newly stored."""
        return sum(1 for a in alerts if self.store(a, run_id) is not None)

    def update_status(self, alert_id: int, status: str) -> None:
        """Update the lifecycle status of an alert."""
        if status not in ALERT_STATUSES:
            raise ValueError(
                f"Invalid status {status!r}. Must be one of {sorted(ALERT_STATUSES)!r}."
            )
        self._db.execute(
            "UPDATE alerts SET status = ?, updated_at = ? WHERE id = ?",
            (status, _now(), alert_id),
        )

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def get_by_run(self, run_id: str) -> list[StoredAlert]:
        rows = self._db.query(
            "SELECT * FROM alerts WHERE run_id = ? ORDER BY confidence DESC",
            (run_id,),
        )
        return [self._row_to_model(r) for r in rows]

    def get_open(self, min_confidence: float = 0.0) -> list[StoredAlert]:
        rows = self._db.query(
            """SELECT * FROM alerts
               WHERE status = 'open' AND confidence >= ?
               ORDER BY confidence DESC, created_at DESC""",
            (min_confidence,),
        )
        return [self._row_to_model(r) for r in rows]

    def get_by_status(self, status: str) -> list[StoredAlert]:
        if status not in ALERT_STATUSES:
            raise ValueError(f"Invalid status {status!r}")
        rows = self._db.query(
            "SELECT * FROM alerts WHERE status = ? ORDER BY created_at DESC",
            (status,),
        )
        return [self._row_to_model(r) for r in rows]

    def get_by_src_ip(self, src_ip: str) -> list[StoredAlert]:
        rows = self._db.query(
            "SELECT * FROM alerts WHERE src_ip = ? ORDER BY created_at DESC",
            (src_ip,),
        )
        return [self._row_to_model(r) for r in rows]

    def get_by_id(self, alert_id: int) -> StoredAlert | None:
        row = self._db.query_one(
            "SELECT * FROM alerts WHERE id = ?", (alert_id,)
        )
        return self._row_to_model(row) if row else None

    def get_recent(self, limit: int = 50) -> list[StoredAlert]:
        rows = self._db.query(
            "SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,)
        )
        return [self._row_to_model(r) for r in rows]

    def count_by_status(self) -> dict[str, int]:
        rows = self._db.query(
            "SELECT status, COUNT(*) AS cnt FROM alerts GROUP BY status"
        )
        return {r["status"]: r["cnt"] for r in rows}

    def count_by_type(self, run_id: str | None = None) -> dict[str, int]:
        if run_id:
            rows = self._db.query(
                """SELECT alert_type, COUNT(*) AS cnt FROM alerts
                   WHERE run_id = ? GROUP BY alert_type""",
                (run_id,),
            )
        else:
            rows = self._db.query(
                "SELECT alert_type, COUNT(*) AS cnt FROM alerts GROUP BY alert_type"
            )
        return {r["alert_type"]: r["cnt"] for r in rows}

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_model(row) -> StoredAlert:
        return StoredAlert(
            id=row["id"],
            alert_hash=row["alert_hash"],
            run_id=row["run_id"],
            alert_type=row["alert_type"],
            confidence=row["confidence"],
            src_ip=row["src_ip"],
            dst_ip=row["dst_ip"],
            severity=row["severity"],
            mitre_tactic=row["mitre_tactic"],
            details=json.loads(row["details"] or "{}"),
            status=row["status"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
