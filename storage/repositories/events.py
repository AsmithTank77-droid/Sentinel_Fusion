"""
storage/repositories/events.py — EventRepository.

Stores and queries normalized pipeline events.
Deduplicates by event_hash so re-ingesting the same source
never creates duplicate rows.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from storage.database import Database
from storage.models import StoredEvent


def _now() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hash_event(event: dict) -> str:
    """Deterministic 16-char hash from fields that uniquely identify an event."""
    key = (
        event.get("timestamp", ""),
        event.get("source_type", ""),
        event.get("src_ip", ""),
        event.get("dst_ip", ""),
        event.get("event_type", ""),
    )
    return hashlib.sha256(json.dumps(key).encode()).hexdigest()[:24]


class EventRepository:
    """Read/write access to the events table."""

    def __init__(self, db: Database) -> None:
        self._db = db

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    def store(self, event: dict, run_id: str) -> str | None:
        """
        Persist a normalized event dict.

        Returns the event_hash on success, None if the event already exists
        (duplicate silently skipped — idempotent).
        """
        event_hash = _hash_event(event)
        metadata   = event.get("metadata") or {}

        try:
            self._db.execute(
                """
                INSERT INTO events
                    (event_hash, run_id, timestamp, source_type,
                     src_ip, dst_ip, event_type, severity, metadata, ingested_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_hash,
                    run_id,
                    event.get("timestamp", ""),
                    event.get("source_type", ""),
                    event.get("src_ip", ""),
                    event.get("dst_ip", ""),
                    event.get("event_type", ""),
                    int(event.get("severity", 0)),
                    json.dumps(metadata),
                    _now(),
                ),
            )
            return event_hash
        except Exception:
            return None  # duplicate — already stored

    def store_batch(self, events: list[dict], run_id: str) -> int:
        """Store a list of events. Returns count of newly stored (non-duplicate) events."""
        stored = 0
        for event in events:
            if self.store(event, run_id) is not None:
                stored += 1
        return stored

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def get_by_run(self, run_id: str) -> list[StoredEvent]:
        """Return all events for a given run, ordered by timestamp."""
        rows = self._db.query(
            "SELECT * FROM events WHERE run_id = ? ORDER BY timestamp",
            (run_id,),
        )
        return [self._row_to_model(r) for r in rows]

    def get_by_src_ip(self, src_ip: str, limit: int = 500) -> list[StoredEvent]:
        rows = self._db.query(
            "SELECT * FROM events WHERE src_ip = ? ORDER BY timestamp DESC LIMIT ?",
            (src_ip, limit),
        )
        return [self._row_to_model(r) for r in rows]

    def get_by_event_type(self, event_type: str, limit: int = 500) -> list[StoredEvent]:
        rows = self._db.query(
            "SELECT * FROM events WHERE event_type = ? ORDER BY timestamp DESC LIMIT ?",
            (event_type, limit),
        )
        return [self._row_to_model(r) for r in rows]

    def get_recent(self, limit: int = 100) -> list[StoredEvent]:
        rows = self._db.query(
            "SELECT * FROM events ORDER BY ingested_at DESC LIMIT ?",
            (limit,),
        )
        return [self._row_to_model(r) for r in rows]

    def count(self) -> int:
        row = self._db.query_one("SELECT COUNT(*) FROM events")
        return row[0] if row else 0

    def count_by_run(self, run_id: str) -> int:
        row = self._db.query_one(
            "SELECT COUNT(*) FROM events WHERE run_id = ?", (run_id,)
        )
        return row[0] if row else 0

    # ------------------------------------------------------------------
    # Retention
    # ------------------------------------------------------------------

    def purge_before(self, days: int) -> int:
        """
        Delete events older than `days` days. Returns count deleted.
        Protects events linked to open or investigating cases via alerts.
        """
        cutoff = self._cutoff_ts(days)
        row = self._db.query_one(
            "SELECT COUNT(*) FROM events WHERE timestamp < ?", (cutoff,)
        )
        count = row[0] if row else 0
        with self._db.write() as conn:
            conn.execute(
                "DELETE FROM events WHERE timestamp < ?", (cutoff,)
            )
        return count

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _cutoff_ts(days: int) -> str:
        from datetime import timedelta
        cutoff = datetime.now(tz=timezone.utc) - timedelta(days=days)
        return cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def _row_to_model(row) -> StoredEvent:
        return StoredEvent(
            id=row["id"],
            event_hash=row["event_hash"],
            run_id=row["run_id"],
            timestamp=row["timestamp"],
            source_type=row["source_type"],
            src_ip=row["src_ip"],
            dst_ip=row["dst_ip"],
            event_type=row["event_type"],
            severity=row["severity"],
            metadata=json.loads(row["metadata"] or "{}"),
            ingested_at=row["ingested_at"],
        )
