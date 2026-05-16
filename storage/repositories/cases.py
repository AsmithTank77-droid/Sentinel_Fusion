"""
storage/repositories/cases.py — CaseRepository.

Manages security incident cases — groups of related alerts
under investigation. Supports full status lifecycle, analyst
notes, and alert linking.
"""

from __future__ import annotations

from datetime import datetime, timezone

from storage.database import Database
from storage.models import CASE_SEVERITIES, CASE_STATUSES, CaseNote, StoredCase


def _now() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _next_case_ref(db: Database) -> str:
    """Generate next sequential case reference: CASE-YYYY-NNNN."""
    year = datetime.now(tz=timezone.utc).year
    row  = db.query_one(
        "SELECT COUNT(*) FROM cases WHERE case_ref LIKE ?",
        (f"CASE-{year}-%",),
    )
    seq = (row[0] if row else 0) + 1
    return f"CASE-{year}-{seq:04d}"


class CaseRepository:
    """Read/write access to cases, case_alerts, and case_notes tables."""

    def __init__(self, db: Database) -> None:
        self._db = db

    # ------------------------------------------------------------------
    # Case lifecycle
    # ------------------------------------------------------------------

    def create(
        self,
        title: str,
        severity: str = "medium",
        assigned_to: str = "",
    ) -> StoredCase:
        """Create a new incident case. Returns the created StoredCase."""
        if severity not in CASE_SEVERITIES:
            raise ValueError(
                f"Invalid severity {severity!r}. "
                f"Must be one of {sorted(CASE_SEVERITIES)!r}."
            )
        now      = _now()
        case_ref = _next_case_ref(self._db)
        self._db.execute(
            """
            INSERT INTO cases
                (case_ref, title, severity, status, assigned_to, created_at, updated_at)
            VALUES (?, ?, ?, 'open', ?, ?, ?)
            """,
            (case_ref, title, severity, assigned_to, now, now),
        )
        return StoredCase(
            case_ref=case_ref,
            title=title,
            severity=severity,
            status="open",
            assigned_to=assigned_to,
            created_at=now,
            updated_at=now,
        )

    def update_status(self, case_ref: str, status: str) -> None:
        """Advance the case through its status workflow."""
        if status not in CASE_STATUSES:
            raise ValueError(
                f"Invalid status {status!r}. "
                f"Must be one of {sorted(CASE_STATUSES)!r}."
            )
        self._db.execute(
            "UPDATE cases SET status = ?, updated_at = ? WHERE case_ref = ?",
            (status, _now(), case_ref),
        )

    def assign(self, case_ref: str, analyst: str) -> None:
        """Assign a case to an analyst."""
        self._db.execute(
            "UPDATE cases SET assigned_to = ?, updated_at = ? WHERE case_ref = ?",
            (analyst, _now(), case_ref),
        )

    def update_severity(self, case_ref: str, severity: str) -> None:
        if severity not in CASE_SEVERITIES:
            raise ValueError(f"Invalid severity {severity!r}")
        self._db.execute(
            "UPDATE cases SET severity = ?, updated_at = ? WHERE case_ref = ?",
            (severity, _now(), case_ref),
        )

    # ------------------------------------------------------------------
    # Alert linking
    # ------------------------------------------------------------------

    def link_alert(self, case_ref: str, alert_id: int) -> bool:
        """
        Link an alert to a case.
        Returns True if linked, False if already linked (idempotent).
        """
        try:
            self._db.execute(
                """
                INSERT INTO case_alerts (case_ref, alert_id, linked_at)
                VALUES (?, ?, ?)
                """,
                (case_ref, alert_id, _now()),
            )
            self._db.execute(
                "UPDATE cases SET updated_at = ? WHERE case_ref = ?",
                (_now(), case_ref),
            )
            return True
        except Exception:
            return False  # already linked

    def unlink_alert(self, case_ref: str, alert_id: int) -> None:
        self._db.execute(
            "DELETE FROM case_alerts WHERE case_ref = ? AND alert_id = ?",
            (case_ref, alert_id),
        )

    def get_alert_ids(self, case_ref: str) -> list[int]:
        rows = self._db.query(
            "SELECT alert_id FROM case_alerts WHERE case_ref = ? ORDER BY linked_at",
            (case_ref,),
        )
        return [r["alert_id"] for r in rows]

    # ------------------------------------------------------------------
    # Notes
    # ------------------------------------------------------------------

    def add_note(self, case_ref: str, note: str, author: str = "analyst") -> CaseNote:
        """Append an analyst note to a case."""
        now = _now()
        self._db.execute(
            """
            INSERT INTO case_notes (case_ref, author, note, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (case_ref, author, note, now),
        )
        self._db.execute(
            "UPDATE cases SET updated_at = ? WHERE case_ref = ?",
            (now, case_ref),
        )
        return CaseNote(case_ref=case_ref, note=note, author=author, created_at=now)

    def get_notes(self, case_ref: str) -> list[CaseNote]:
        rows = self._db.query(
            "SELECT * FROM case_notes WHERE case_ref = ? ORDER BY created_at",
            (case_ref,),
        )
        return [
            CaseNote(
                id=r["id"],
                case_ref=r["case_ref"],
                author=r["author"],
                note=r["note"],
                created_at=r["created_at"],
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def get(self, case_ref: str) -> StoredCase | None:
        row = self._db.query_one(
            "SELECT * FROM cases WHERE case_ref = ?", (case_ref,)
        )
        return self._row_to_model(row) if row else None

    def get_all(self, status: str | None = None) -> list[StoredCase]:
        if status:
            if status not in CASE_STATUSES:
                raise ValueError(f"Invalid status {status!r}")
            rows = self._db.query(
                "SELECT * FROM cases WHERE status = ? ORDER BY updated_at DESC",
                (status,),
            )
        else:
            rows = self._db.query(
                "SELECT * FROM cases ORDER BY updated_at DESC"
            )
        return [self._row_to_model(r) for r in rows]

    def count_by_status(self) -> dict[str, int]:
        rows = self._db.query(
            "SELECT status, COUNT(*) AS cnt FROM cases GROUP BY status"
        )
        return {r["status"]: r["cnt"] for r in rows}

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_model(row) -> StoredCase:
        return StoredCase(
            id=row["id"],
            case_ref=row["case_ref"],
            title=row["title"],
            severity=row["severity"],
            status=row["status"],
            assigned_to=row["assigned_to"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
